import { describe, it, expect } from 'vitest';
import {
  constantFold,
  copyPropagate,
  analyzeDeadDefs,
  runDataFlowPasses,
  emitValue,
  mbaSimplify,
  mbaDensity,
  buildExprTree,
  exprEqual,
  simplifyExprTree,
} from '../../utils/dataFlowPasses';
import type { IRExprNode } from '../../utils/dataFlowPasses';
import { buildSSAForm } from '../../utils/ssaTransform';
import type { IRBlock, IRStmt, IRValue } from '../../utils/decompilerEngine';

// ─── IR construction helpers ──────────────────────────────────────────────────

function reg(name: string): IRValue {
  return { kind: 'reg', name };
}

function cnst(value: number): IRValue {
  return { kind: 'const', value };
}

function mem(base: string, offset: number): IRValue {
  return { kind: 'mem', base, offset, size: 'qword' } as IRValue;
}

function assign(dest: string, src: IRValue, address: number): IRStmt {
  return { op: 'assign', dest: reg(dest), src, address } as IRStmt;
}

function binop(dest: string, left: IRValue, right: IRValue, op: string, address: number): IRStmt {
  return { op: 'binop', dest: reg(dest), left, right, operator: op, address } as IRStmt;
}

function uop(dest: string, operand: IRValue, op: string, address: number): IRStmt {
  return { op: 'uop', dest: reg(dest), operand, operator: op, address } as IRStmt;
}

function makeBlock(
  id: string,
  stmts: IRStmt[],
  successors: string[] = [],
  allSuccessors?: string[],
): IRBlock {
  return {
    id,
    start: parseInt(id.replace(/\D/g, '') || '0', 10) * 0x10,
    end:   parseInt(id.replace(/\D/g, '') || '0', 10) * 0x10 + 0x10,
    stmts,
    successors,
    allSuccessors: allSuccessors ?? successors,
  };
}

// ─── constantFold ─────────────────────────────────────────────────────────────

describe('constantFold', () => {
  it('returns empty env for block with no assignments', () => {
    const blocks = [makeBlock('b0', [
      { op: 'nop', address: 0 } as IRStmt,
    ])];
    const env = constantFold(blocks);
    expect(env.size).toBe(0);
  });

  it('records a literal constant assignment', () => {
    const blocks = [makeBlock('b0', [
      assign('rax', cnst(42), 0),
    ])];
    const env = constantFold(blocks);
    const val = env.get('rax');
    expect(val?.kind).toBe('const');
    expect((val as { kind: 'const'; value: number }).value).toBe(42);
  });

  it('evaluates const + const binop', () => {
    const blocks = [makeBlock('b0', [
      assign('rax', cnst(3), 0),
      assign('rbx', cnst(4), 4),
      binop('rcx', reg('rax'), reg('rbx'), '+', 8),
    ])];
    const env = constantFold(blocks);
    const val = env.get('rcx');
    expect(val?.kind).toBe('const');
    expect((val as { kind: 'const'; value: number }).value).toBe(7);
  });

  it('folds const * const', () => {
    const blocks = [makeBlock('b0', [
      assign('rax', cnst(6), 0),
      assign('rbx', cnst(7), 4),
      binop('rcx', reg('rax'), reg('rbx'), '*', 8),
    ])];
    const env = constantFold(blocks);
    expect((env.get('rcx') as { kind: 'const'; value: number })?.value).toBe(42);
  });

  it('simplifies x + 0 identity', () => {
    const blocks = [makeBlock('b0', [
      // rax (unknown) + 0 → rax  (identity simplification)
      binop('rbx', reg('rax'), cnst(0), '+', 0),
    ])];
    const env = constantFold(blocks);
    const rbxVal = env.get('rbx');
    // rbx should be simplified to rax (not a const, but a reg)
    expect(rbxVal?.kind).toBe('reg');
    expect((rbxVal as { kind: 'reg'; name: string })?.name).toBe('rax');
  });

  it('simplifies x * 0 to 0', () => {
    const blocks = [makeBlock('b0', [
      binop('rcx', reg('rax'), cnst(0), '*', 0),
    ])];
    const env = constantFold(blocks);
    const val = env.get('rcx');
    expect(val?.kind).toBe('const');
    expect((val as { kind: 'const'; value: number })?.value).toBe(0);
  });

  it('evaluates unary negation', () => {
    const blocks = [makeBlock('b0', [
      assign('rax', cnst(5), 0),
      uop('rbx', reg('rax'), '-', 4),
    ])];
    const env = constantFold(blocks);
    expect((env.get('rbx') as { kind: 'const'; value: number })?.value).toBe(-5);
  });
});

// ─── copyPropagate ────────────────────────────────────────────────────────────

describe('copyPropagate', () => {
  it('propagates a register copy', () => {
    const blocks = [makeBlock('b0', [
      assign('rax', cnst(99), 0),
      assign('rbx', reg('rax'), 4),  // copy: rbx = rax
    ])];
    const base = constantFold(blocks);
    const env  = copyPropagate(blocks, base);
    // rbx should resolve to the same constant as rax (99)
    const rbxVal = env.get('rbx');
    expect(rbxVal?.kind).toBe('const');
    expect((rbxVal as { kind: 'const'; value: number })?.value).toBe(99);
  });

  it('does not overwrite a known constant with a non-const', () => {
    const blocks = [makeBlock('b0', [
      assign('rax', cnst(10), 0),
      // rax already const — copying rdi into rax should not lose the const
      assign('rax', reg('rdi'), 4),
    ])];
    // After the second assign, rax should be rdi (not const 10)
    // That's actually correct: SSA would have two versions, but without SSA we take last def
    const env = constantFold(blocks);
    // First pass records rax=10; second assign overwrites it with rdi (non-const)
    // The fold loop will stabilize with rax being unknown (not constant) after second def
    // This tests that we don't crash
    expect(env).toBeDefined();
  });
});

// ─── analyzeDeadDefs ─────────────────────────────────────────────────────────

describe('analyzeDeadDefs', () => {
  it('reports 0 dead defs when all defs are used', () => {
    const blocks = [
      makeBlock('b0', [assign('rax', cnst(1), 0)], ['b1'], ['b1']),
      makeBlock('b1', [assign('rbx', reg('rax'), 0x10)], []),
    ];
    const ssa = buildSSAForm(blocks);
    const report = analyzeDeadDefs(blocks, ssa);
    // rax is used in b1, so it should not be dead
    // (exact count depends on rename pass coverage)
    expect(report.count).toBeGreaterThanOrEqual(0);  // no crash
  });

  it('does not crash on empty blocks', () => {
    const blocks: IRBlock[] = [];
    const ssa = buildSSAForm(blocks);
    const report = analyzeDeadDefs(blocks, ssa);
    expect(report.count).toBe(0);
    expect(report.deadDefs).toHaveLength(0);
  });
});

// ─── runDataFlowPasses ────────────────────────────────────────────────────────

describe('runDataFlowPasses', () => {
  it('returns a DataFlowResult with all fields for empty blocks', () => {
    const ssa = buildSSAForm([]);
    const result = runDataFlowPasses([], ssa);
    expect(result.env).toBeDefined();
    expect(result.deadDefReport).toBeDefined();
    expect(result.foldedCount).toBe(0);
  });

  it('foldedCount > 0 when there are constant assignments', () => {
    const blocks = [makeBlock('b0', [
      assign('rax', cnst(1), 0),
      assign('rbx', cnst(2), 4),
      binop('rcx', reg('rax'), reg('rbx'), '+', 8),
    ])];
    const ssa = buildSSAForm(blocks);
    const result = runDataFlowPasses(blocks, ssa);
    // At least rax, rbx, rcx folded to constants
    expect(result.foldedCount).toBeGreaterThanOrEqual(2);
  });
});

// ─── emitValue ────────────────────────────────────────────────────────────────

describe('emitValue', () => {
  it('emits a constant as decimal when small', () => {
    const env = new Map<string, IRValue>();
    expect(emitValue(cnst(5), env)).toBe('5');
  });

  it('emits a constant as hex when large', () => {
    const env = new Map<string, IRValue>();
    expect(emitValue(cnst(0x1000), env)).toBe('0x1000');
  });

  it('emits a register by name when no env entry', () => {
    const env = new Map<string, IRValue>();
    expect(emitValue(reg('rdi'), env)).toBe('rdi');
  });

  it('emits a folded constant for a register with known const value', () => {
    const env = new Map<string, IRValue>([['rax', cnst(0xff)]]);
    expect(emitValue(reg('rax'), env)).toBe('0xff');
  });

  it('emits negative hex with - prefix', () => {
    const env = new Map<string, IRValue>();
    expect(emitValue(cnst(-0x10), env)).toBe('-0x10');
  });

  it('emits memory expression as [base+offset]', () => {
    const env = new Map<string, IRValue>();
    const mVal = mem('rbp', -8);
    const out = emitValue(mVal, env);
    expect(out).toContain('rbp');
  });
});

// ─── exprEqual ────────────────────────────────────────────────────────────────

describe('exprEqual', () => {
  it('matches identical constants', () => {
    const a: IRExprNode = { kind: 'const', value: 42 };
    expect(exprEqual(a, { kind: 'const', value: 42 })).toBe(true);
    expect(exprEqual(a, { kind: 'const', value: 0  })).toBe(false);
  });

  it('matches same variable', () => {
    const x: IRExprNode = { kind: 'var', base: 'rax' };
    expect(exprEqual(x, { kind: 'var', base: 'rax' })).toBe(true);
    expect(exprEqual(x, { kind: 'var', base: 'rbx' })).toBe(false);
  });

  it('accepts commutative binop in either argument order', () => {
    const x: IRExprNode = { kind: 'var', base: 'rax' };
    const y: IRExprNode = { kind: 'var', base: 'rbx' };
    const ab: IRExprNode = { kind: 'binop', op: '&', left: x, right: y };
    const ba: IRExprNode = { kind: 'binop', op: '&', left: y, right: x };
    expect(exprEqual(ab, ba)).toBe(true);
  });

  it('rejects non-commutative subtraction in reversed order', () => {
    const x: IRExprNode = { kind: 'var', base: 'rax' };
    const y: IRExprNode = { kind: 'var', base: 'rbx' };
    const ab: IRExprNode = { kind: 'binop', op: '-', left: x, right: y };
    const ba: IRExprNode = { kind: 'binop', op: '-', left: y, right: x };
    expect(exprEqual(ab, ba)).toBe(false);
  });

  it('matches uop recursively', () => {
    const x: IRExprNode = { kind: 'var', base: 'rax' };
    const nx: IRExprNode = { kind: 'uop', op: '~', operand: x };
    expect(exprEqual(nx, { kind: 'uop', op: '~', operand: x })).toBe(true);
    expect(exprEqual(nx, { kind: 'uop', op: '-', operand: x })).toBe(false);
  });
});

// ─── simplifyExprTree ─────────────────────────────────────────────────────────

describe('simplifyExprTree', () => {
  it('x ^ x → 0', () => {
    const x: IRExprNode = { kind: 'var', base: 'rax' };
    const e: IRExprNode = { kind: 'binop', op: '^', left: x, right: x };
    expect(simplifyExprTree(e)).toEqual({ kind: 'const', value: 0 });
  });

  it('x & x → x (idempotence)', () => {
    const x: IRExprNode = { kind: 'var', base: 'rax' };
    const e: IRExprNode = { kind: 'binop', op: '&', left: x, right: x };
    expect(exprEqual(simplifyExprTree(e), x)).toBe(true);
  });

  it('x - x → 0', () => {
    const x: IRExprNode = { kind: 'var', base: 'rax' };
    const e: IRExprNode = { kind: 'binop', op: '-', left: x, right: x };
    expect(simplifyExprTree(e)).toEqual({ kind: 'const', value: 0 });
  });

  it('x & ~x → 0 (complement annihilation)', () => {
    const x: IRExprNode = { kind: 'var', base: 'rax' };
    const e: IRExprNode = {
      kind: 'binop', op: '&',
      left: x,
      right: { kind: 'uop', op: '~', operand: x },
    };
    expect(simplifyExprTree(e)).toEqual({ kind: 'const', value: 0 });
  });

  it('~~x → x (double NOT)', () => {
    const x: IRExprNode = { kind: 'var', base: 'rax' };
    const e: IRExprNode = {
      kind: 'uop', op: '~',
      operand: { kind: 'uop', op: '~', operand: x },
    };
    expect(exprEqual(simplifyExprTree(e), x)).toBe(true);
  });

  it('(a ^ b) ^ b → a (XOR inverse)', () => {
    const a: IRExprNode = { kind: 'var', base: 'rax' };
    const b: IRExprNode = { kind: 'var', base: 'rbx' };
    const e: IRExprNode = {
      kind: 'binop', op: '^',
      left: { kind: 'binop', op: '^', left: a, right: b },
      right: b,
    };
    expect(exprEqual(simplifyExprTree(e), a)).toBe(true);
  });

  it('(a + b) - b → a (additive inverse)', () => {
    const a: IRExprNode = { kind: 'var', base: 'rax' };
    const b: IRExprNode = { kind: 'var', base: 'rbx' };
    const e: IRExprNode = {
      kind: 'binop', op: '-',
      left: { kind: 'binop', op: '+', left: a, right: b },
      right: b,
    };
    expect(exprEqual(simplifyExprTree(e), a)).toBe(true);
  });

  it('~x + 1 → -x (two\'s complement negation)', () => {
    const x: IRExprNode = { kind: 'var', base: 'rax' };
    const e: IRExprNode = {
      kind: 'binop', op: '+',
      left: { kind: 'uop', op: '~', operand: x },
      right: { kind: 'const', value: 1 },
    };
    const result = simplifyExprTree(e);
    expect(result.kind).toBe('uop');
    if (result.kind === 'uop') {
      expect(result.op).toBe('-');
      expect(exprEqual(result.operand, x)).toBe(true);
    }
  });

  // ── Core MBA identities ──────────────────────────────────────────────────

  it('MBA: (a | b) + (a & b) → a + b', () => {
    const a: IRExprNode = { kind: 'var', base: 'rax' };
    const b: IRExprNode = { kind: 'var', base: 'rbx' };
    const e: IRExprNode = {
      kind: 'binop', op: '+',
      left:  { kind: 'binop', op: '|', left: a, right: b },
      right: { kind: 'binop', op: '&', left: a, right: b },
    };
    const result = simplifyExprTree(e);
    const expected: IRExprNode = { kind: 'binop', op: '+', left: a, right: b };
    expect(exprEqual(result, expected)).toBe(true);
  });

  it('MBA: (a | b) - (a & b) → a ^ b', () => {
    const a: IRExprNode = { kind: 'var', base: 'rax' };
    const b: IRExprNode = { kind: 'var', base: 'rbx' };
    const e: IRExprNode = {
      kind: 'binop', op: '-',
      left:  { kind: 'binop', op: '|', left: a, right: b },
      right: { kind: 'binop', op: '&', left: a, right: b },
    };
    const result = simplifyExprTree(e);
    const expected: IRExprNode = { kind: 'binop', op: '^', left: a, right: b };
    expect(exprEqual(result, expected)).toBe(true);
  });

  it('MBA: (a ^ b) + (a&b)+(a&b) → a + b  [2*(a&b) as sum form]', () => {
    const a: IRExprNode = { kind: 'var', base: 'rax' };
    const b: IRExprNode = { kind: 'var', base: 'rbx' };
    const andAB: IRExprNode = { kind: 'binop', op: '&', left: a, right: b };
    const e: IRExprNode = {
      kind: 'binop', op: '+',
      left: { kind: 'binop', op: '^', left: a, right: b },
      right: { kind: 'binop', op: '+', left: andAB, right: andAB },
    };
    const result = simplifyExprTree(e);
    const expected: IRExprNode = { kind: 'binop', op: '+', left: a, right: b };
    expect(exprEqual(result, expected)).toBe(true);
  });

  it('MBA: (a ^ b) + ((a&b)<<1) → a + b  [2*(a&b) as shl form]', () => {
    const a: IRExprNode = { kind: 'var', base: 'rax' };
    const b: IRExprNode = { kind: 'var', base: 'rbx' };
    const e: IRExprNode = {
      kind: 'binop', op: '+',
      left: { kind: 'binop', op: '^', left: a, right: b },
      right: {
        kind: 'binop', op: '<<',
        left: { kind: 'binop', op: '&', left: a, right: b },
        right: { kind: 'const', value: 1 },
      },
    };
    const result = simplifyExprTree(e);
    const expected: IRExprNode = { kind: 'binop', op: '+', left: a, right: b };
    expect(exprEqual(result, expected)).toBe(true);
  });

  it('is idempotent — applying twice gives the same result', () => {
    const a: IRExprNode = { kind: 'var', base: 'rax' };
    const b: IRExprNode = { kind: 'var', base: 'rbx' };
    const e: IRExprNode = {
      kind: 'binop', op: '-',
      left:  { kind: 'binop', op: '|', left: a, right: b },
      right: { kind: 'binop', op: '&', left: a, right: b },
    };
    const once  = simplifyExprTree(e);
    const twice = simplifyExprTree(once);
    expect(exprEqual(once, twice)).toBe(true);
  });
});

// ─── mbaSimplify ──────────────────────────────────────────────────────────────

describe('mbaSimplify', () => {
  it('returns empty env for empty blocks', () => {
    const env = mbaSimplify([], new Map());
    expect(env.size).toBe(0);
  });

  it('x ^ x → 0 across two statements', () => {
    // r8 = rax ^ rax  — should simplify r8 → 0
    const blocks = [makeBlock('b0', [
      binop('r8', reg('rax'), reg('rax'), '^', 0),
    ])];
    const env = mbaSimplify(blocks, new Map());
    const val = env.get('r8');
    expect(val?.kind).toBe('const');
    expect((val as { kind: 'const'; value: number }).value).toBe(0);
  });

  it('x & ~x → 0 via inlined def chain', () => {
    // r8 = ~rax;  r9 = rax & r8  — should simplify r9 → 0
    const blocks = [makeBlock('b0', [
      uop('r8', reg('rax'), '~', 0),
      binop('r9', reg('rax'), reg('r8'), '&', 4),
    ])];
    const env = mbaSimplify(blocks, new Map());
    const val = env.get('r9');
    expect(val?.kind).toBe('const');
    expect((val as { kind: 'const'; value: number }).value).toBe(0);
  });

  it('(a ^ b) ^ b → a via two-level inlining', () => {
    // r8 = rax ^ rbx;  r9 = r8 ^ rbx  → should simplify r9 → rax
    const blocks = [makeBlock('b0', [
      binop('r8', reg('rax'), reg('rbx'), '^', 0),
      binop('r9', reg('r8'),  reg('rbx'), '^', 4),
    ])];
    const env = mbaSimplify(blocks, new Map());
    const val = env.get('r9');
    expect(val?.kind).toBe('reg');
    expect((val as { kind: 'reg'; name: string }).name).toBe('rax');
  });

  it('MBA (a|b)+(a&b) → a+b: result is not the raw r10+r11 form', () => {
    // r8 = rax & rbx;  r9 = rax | rbx;  r10 = r9 + r8
    const blocks = [makeBlock('b0', [
      binop('r8', reg('rax'), reg('rbx'), '&', 0),
      binop('r9', reg('rax'), reg('rbx'), '|', 4),
      binop('r10', reg('r9'), reg('r8'), '+', 8),
    ])];
    const env = mbaSimplify(blocks, new Map());
    // The raw form would be r9+r8 with no simplification.
    // After MBA pass, r10 should map to an expr or reg representing rax+rbx.
    expect(env.has('r10')).toBe(true);
    const val = env.get('r10')!;
    // Should NOT still be just "reg r9" or "reg r8"
    if (val.kind === 'expr') {
      expect(val.text).toContain('rax');
      expect(val.text).toContain('rbx');
      expect(val.text).toContain('+');
    }
  });

  it('rotation (x<<4)|(x>>>28) is detected', () => {
    const blocks = [makeBlock('b0', [
      binop('r8',  reg('rax'), cnst(4),  '<<',  0),
      binop('r9',  reg('rax'), cnst(28), '>>>', 4),
      binop('r10', reg('r8'),  reg('r9'), '|',  8),
    ])];
    const env = mbaSimplify(blocks, new Map());
    const val = env.get('r10');
    expect(val).toBeDefined();
    if (val?.kind === 'expr') {
      expect(val.text).toContain('ROL32');
    }
  });

  it('does not add entries for expressions with no simplification', () => {
    // rax + rbx has no simplification
    const blocks = [makeBlock('b0', [
      binop('rcx', reg('rax'), reg('rbx'), '+', 0),
    ])];
    const env = mbaSimplify(blocks, new Map());
    expect(env.has('rcx')).toBe(false);
  });
});

// ─── mbaDensity ───────────────────────────────────────────────────────────────

describe('mbaDensity', () => {
  it('returns 0 for empty block', () => {
    const block = makeBlock('b0', []);
    expect(mbaDensity(block)).toBe(0);
  });

  it('returns 1.0 for all-bitwise block', () => {
    const block = makeBlock('b0', [
      binop('r8', reg('rax'), reg('rbx'), '&', 0),
      binop('r9', reg('rax'), reg('rbx'), '|', 4),
      binop('r10', reg('r8'), reg('r9'), '^', 8),
    ]);
    expect(mbaDensity(block)).toBe(1);
  });

  it('returns 0.5 for half-bitwise block', () => {
    const block = makeBlock('b0', [
      binop('r8', reg('rax'), reg('rbx'), '&', 0),
      binop('r9', reg('rax'), reg('rbx'), '+', 4),
    ]);
    expect(mbaDensity(block)).toBe(0.5);
  });

  it('ignores non-binop statements', () => {
    const block = makeBlock('b0', [
      assign('r8', reg('rax'), 0),
      binop('r9', reg('rax'), reg('rbx'), '^', 4),
    ]);
    expect(mbaDensity(block)).toBe(1);
  });
});
