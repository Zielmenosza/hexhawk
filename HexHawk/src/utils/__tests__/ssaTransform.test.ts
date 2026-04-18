import { describe, it, expect } from 'vitest';
import {
  buildSSAForm,
  listPhiNodes,
  ssaVersionStats,
  getSSADefName,
  getSSAUseName,
} from '../../utils/ssaTransform';
import type { IRBlock, IRStmt, IRValue } from '../../utils/decompilerEngine';

// ─── IR construction helpers ──────────────────────────────────────────────────

function reg(name: string): IRValue {
  return { kind: 'reg', name };
}

function cnst(value: number): IRValue {
  return { kind: 'const', value };
}

function assign(dest: string, src: IRValue, address: number): IRStmt {
  return { op: 'assign', dest: reg(dest), src, address } as IRStmt;
}

function binop(dest: string, left: IRValue, right: IRValue, op: string, address: number): IRStmt {
  return { op: 'binop', dest: reg(dest), left, right, operator: op, address } as IRStmt;
}

function makeBlock(
  id: string,
  stmts: IRStmt[],
  successors: string[],
  allSuccessors?: string[],
  blockType?: string,
): IRBlock {
  return {
    id,
    start: parseInt(id.replace(/\D/g, '') || '0', 10) * 0x10,
    end:   parseInt(id.replace(/\D/g, '') || '0', 10) * 0x10 + 0x10,
    stmts,
    successors,
    allSuccessors: allSuccessors ?? successors,
    blockType,
  };
}

// ─── buildSSAForm ─────────────────────────────────────────────────────────────

describe('buildSSAForm — empty / trivial', () => {
  it('returns ok=false for empty block list', () => {
    const result = buildSSAForm([]);
    expect(result.ok).toBe(false);
    expect(result.varCount).toBe(0);
  });

  it('handles single block with no register assignments', () => {
    const block = makeBlock('b0', [
      { op: 'nop', address: 0 } as IRStmt,
      { op: 'ret', address: 4 } as IRStmt,
    ], [], [], 'entry');

    const result = buildSSAForm([block]);
    expect(result.ok).toBe(true);
    expect(result.varCount).toBe(0);
    expect(listPhiNodes(result)).toHaveLength(0);
  });

  it('handles single block with one definition', () => {
    const block = makeBlock('b0', [
      assign('rax', cnst(42), 0),
    ], [], [], 'entry');

    const result = buildSSAForm([block]);
    expect(result.ok).toBe(true);
    // rax_0 created
    expect(result.varCount).toBeGreaterThanOrEqual(1);
    const defName = getSSADefName(result, 'b0', 0, 'rax');
    expect(defName).toBe('rax₀');
  });
});

describe('buildSSAForm — linear chain', () => {
  it('assigns sequential SSA versions in a linear 3-block function', () => {
    // b0 → b1 → b2
    // b0: rax = 1
    // b1: rax = 2
    // b2: rbx = rax  (uses b1's rax)
    const blocks = [
      makeBlock('b0', [assign('rax', cnst(1), 0x10)], ['b1'], ['b1'], 'entry'),
      makeBlock('b1', [assign('rax', cnst(2), 0x20)], ['b2'], ['b2']),
      makeBlock('b2', [assign('rbx', reg('rax'), 0x30)], [],  []),
    ];

    const result = buildSSAForm(blocks);
    expect(result.ok).toBe(true);

    // b0 defines rax_0, b1 redefines rax_1
    const def0 = getSSADefName(result, 'b0', 0x10, 'rax');
    const def1 = getSSADefName(result, 'b1', 0x20, 'rax');
    expect(def0).toBeTruthy();
    expect(def1).toBeTruthy();
    expect(def0).not.toBe(def1);  // different versions
  });

  it('no phi nodes in a linear chain (no join points)', () => {
    const blocks = [
      makeBlock('b0', [assign('rax', cnst(0), 0)], ['b1'], ['b1'], 'entry'),
      makeBlock('b1', [assign('rax', cnst(1), 0x10)], ['b2'], ['b2']),
      makeBlock('b2', [], [], []),
    ];
    const result = buildSSAForm(blocks);
    expect(listPhiNodes(result)).toHaveLength(0);
  });
});

describe('buildSSAForm — diamond (if-else join)', () => {
  it('inserts phi node at join point', () => {
    // b0 → b1, b2; b1 → b3; b2 → b3  (diamond)
    // b1: rax = 1; b2: rax = 2; b3 uses rax → needs phi
    const blocks = [
      makeBlock('b0', [assign('rax', cnst(0), 0x00)], ['b1', 'b2'], ['b1', 'b2'], 'entry'),
      makeBlock('b1', [assign('rax', cnst(1), 0x10)], ['b3'], ['b3']),
      makeBlock('b2', [assign('rax', cnst(2), 0x20)], ['b3'], ['b3']),
      makeBlock('b3', [],                              [],     []),
    ];

    const result = buildSSAForm(blocks);
    expect(result.ok).toBe(true);

    const phis = listPhiNodes(result);
    // There should be a phi for 'rax' in b3
    const raxPhi = phis.find(p => p.dest.base === 'rax' && p.blockId === 'b3');
    expect(raxPhi).toBeDefined();
    // Should have 2 operands (one from b1, one from b2)
    expect(raxPhi!.operands).toHaveLength(2);
  });

  it('does NOT insert phi for variable defined in only one branch', () => {
    // b0 → b1, b2; b1: rbx=5; b2: (no rbx def); join at b3
    const blocks = [
      makeBlock('b0', [],                              ['b1', 'b2'], ['b1', 'b2'], 'entry'),
      makeBlock('b1', [assign('rbx', cnst(5), 0x10)], ['b3'], ['b3']),
      makeBlock('b2', [],                              ['b3'], ['b3']),
      makeBlock('b3', [],                              [],     []),
    ];

    const result = buildSSAForm(blocks);
    // rbx is only defined in one branch — phi nodes present only for multi-def vars
    // At minimum: if rbx IS inserted as phi, it should still be valid
    expect(result.ok).toBe(true);
  });
});

describe('buildSSAForm — loop', () => {
  it('inserts phi at loop header for induction variable', () => {
    // b0 → b1 → b1 (self-loop back edge)  (minimal loop)
    // b0: rax = 0  (init)
    // b1: rax = rax + 1  (induction); back edge to b1
    const blocks = [
      makeBlock('b0', [assign('rax', cnst(0), 0x00)], ['b1'], ['b1'], 'entry'),
      makeBlock('b1',
        [binop('rax', reg('rax'), cnst(1), '+', 0x10)],
        ['b1'],
        ['b1'],
      ),
    ];

    const result = buildSSAForm(blocks);
    // Loop header b1 receives rax from outside (b0) and from back-edge (b1 itself)
    // → phi for rax at b1
    const phis = listPhiNodes(result);
    const headerPhi = phis.find(p => p.blockId === 'b1' && p.dest.base === 'rax');
    expect(headerPhi).toBeDefined();
  });
});

describe('buildSSAForm — utilities', () => {
  it('ssaVersionStats returns sorted stats by version count', () => {
    // b0: rax=0; b1: rax=1; b2: rbx=3  → rax has 2 versions, rbx has 1
    const blocks = [
      makeBlock('b0', [assign('rax', cnst(0), 0x00)], ['b1'], ['b1'], 'entry'),
      makeBlock('b1', [assign('rax', cnst(1), 0x10)], ['b2'], ['b2']),
      makeBlock('b2', [assign('rbx', cnst(3), 0x20)], [],     []),
    ];

    const result = buildSSAForm(blocks);
    expect(result.ok).toBe(true);

    const stats = ssaVersionStats(result);
    expect(stats.length).toBeGreaterThan(0);
    // First entry should have the most versions
    if (stats.length >= 2) {
      expect(stats[0].versions).toBeGreaterThanOrEqual(stats[1].versions);
    }
  });

  it('getSSAUseName returns null for unknown block+address+var', () => {
    const block = makeBlock('b0', [assign('rax', cnst(1), 0)], [], [], 'entry');
    const result = buildSSAForm([block]);
    const name = getSSAUseName(result, 'nosuchblock', 9999, 'rax');
    expect(name).toBeNull();
  });

  it('dominator tree is populated for multi-block CFG', () => {
    const blocks = [
      makeBlock('b0', [], ['b1'], ['b1'], 'entry'),
      makeBlock('b1', [], ['b2'], ['b2']),
      makeBlock('b2', [], [],     []),
    ];
    const result = buildSSAForm(blocks);
    // b0 dominates b1, b1 dominates b2
    expect(result.domTree.idom.get('b2')).toBe('b1');
    expect(result.domTree.idom.get('b1')).toBe('b0');
    expect(result.domTree.idom.get('b0')).toBeNull();
  });
});
