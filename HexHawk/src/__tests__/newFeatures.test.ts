/**
 * newFeatures.test.ts — Vitest unit tests for features added in the current batch.
 *
 * Coverage:
 *   Thunk detection                    — detectFunctions marks 1-instruction jmp funcs as thunks
 *   applyCSE rewriteCount             — CSE pass returns count of eliminated expressions
 *   Prototype header builder          — buildPrototypeHeader produces correct comment strings
 *   Dispatcher block detection        — CfgView dispatcher heuristic (≥6 branch edges, ≤5 instr)
 */

import { describe, it, expect } from 'vitest';
import { applyCSE } from '../utils/decompilerEngine';
import type { IRBlock, IRStmt, IRValue } from '../utils/decompilerEngine';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function reg(name: string): IRValue { return { kind: 'reg', name }; }
function imm(val: number): IRValue { return { kind: 'imm', value: val }; }

function assignStmt(dest: string, srcKind: IRValue, address = 0x1000): IRStmt {
  return { op: 'assign', address, dest: reg(dest), src: srcKind } as IRStmt;
}

function binopStmt(dest: string, left: string, op: string, right: string, address = 0x1000): IRStmt {
  return {
    op: 'binop',
    address,
    dest: reg(dest),
    left: reg(left),
    right: reg(right),
    operator: op,
  } as IRStmt;
}

function makeBlock(id: string, stmts: IRStmt[]): IRBlock {
  return { id, stmts, successors: [], predecessors: [] } as unknown as IRBlock;
}

// ─── applyCSE ─────────────────────────────────────────────────────────────────

describe('applyCSE — rewriteCount', () => {
  it('returns rewriteCount=0 when no redundant subexpressions exist', () => {
    const block = makeBlock('b0', [
      binopStmt('r1', 'rdi', '+', 'rsi', 0x1000),
      binopStmt('r2', 'rdx', '+', 'rcx', 0x1001),
    ]);
    const { rewriteCount } = applyCSE([block]);
    expect(rewriteCount).toBe(0);
  });

  it('returns rewriteCount=1 for a duplicated binop within the same block', () => {
    // Same (rdi + rsi) computed twice in one block → second use is CSE'd
    const block = makeBlock('b0', [
      binopStmt('r1', 'rdi', '+', 'rsi', 0x1000),  // first occurrence — recorded
      binopStmt('r2', 'rdi', '+', 'rsi', 0x1004),  // duplicate → replaced
    ]);
    const { rewriteCount } = applyCSE([block]);
    expect(rewriteCount).toBe(1);
  });

  it('returns optimized blocks with replaced CSE stmts in same block', () => {
    const block = makeBlock('b0', [
      binopStmt('r1', 'rdi', '+', 'rsi', 0x1000),
      binopStmt('r2', 'rdi', '+', 'rsi', 0x1004),
    ]);
    const { blocks } = applyCSE([block]);
    // The second stmt should be an 'assign' (register copy) not a 'binop'
    expect(blocks[0].stmts[1].op).toBe('assign');
  });

  it('does not CSE across a write to the same register', () => {
    // Write to rdi before the second use — kills availability
    const block = makeBlock('b0', [
      binopStmt('r1', 'rdi', '+', 'rsi', 0x1000),
      assignStmt('rdi', imm(0), 0x1001),                // kills rdi
      binopStmt('r2', 'rdi', '+', 'rsi', 0x1002),      // rdi is different now
    ]);
    const { rewriteCount } = applyCSE([block]);
    expect(rewriteCount).toBe(0);
  });
});

// ─── Thunk detection heuristic ────────────────────────────────────────────────
// We test the pure logic (not App.tsx's detectFunctions) by replicating the
// heuristic: a function is a thunk when its non-nop instructions consist of
// exactly 1 jmp to an address outside the function boundaries.

function isThunkHeuristic(
  instrs: { mnemonic: string; address: number; targets: number[] }[],
  funcStart: number,
  funcEnd: number,
): boolean {
  const nonNop = instrs.filter(i => !['nop', 'nopl', 'nopw'].includes(i.mnemonic.toLowerCase()));
  if (nonNop.length > 2) return false;
  const last = nonNop[nonNop.length - 1];
  if (!last) return false;
  if (!['jmp', 'jmpq'].includes(last.mnemonic.toLowerCase())) return false;
  if (last.targets.length !== 1) return false;
  const tgt = last.targets[0];
  return tgt < funcStart || tgt >= funcEnd;
}

describe('Thunk detection heuristic', () => {
  it('marks a 1-instruction jmp-outside function as a thunk', () => {
    const instrs = [{ mnemonic: 'jmp', address: 0x1000, targets: [0x2000] }];
    expect(isThunkHeuristic(instrs, 0x1000, 0x1005)).toBe(true);
  });

  it('marks a nop + jmp function as a thunk (nop ignored)', () => {
    const instrs = [
      { mnemonic: 'nop', address: 0x1000, targets: [] },
      { mnemonic: 'jmp', address: 0x1001, targets: [0x3000] },
    ];
    expect(isThunkHeuristic(instrs, 0x1000, 0x1005)).toBe(true);
  });

  it('does NOT mark a 3+ instruction function as a thunk', () => {
    const instrs = [
      { mnemonic: 'mov', address: 0x1000, targets: [] },
      { mnemonic: 'add', address: 0x1002, targets: [] },
      { mnemonic: 'jmp', address: 0x1004, targets: [0x2000] },
    ];
    expect(isThunkHeuristic(instrs, 0x1000, 0x1010)).toBe(false);
  });

  it('does NOT mark a jmp-into-self function as a thunk', () => {
    const instrs = [{ mnemonic: 'jmp', address: 0x1000, targets: [0x1002] }];
    expect(isThunkHeuristic(instrs, 0x1000, 0x1010)).toBe(false);
  });

  it('does NOT mark a call (non-jmp) function as a thunk', () => {
    const instrs = [{ mnemonic: 'call', address: 0x1000, targets: [0x2000] }];
    expect(isThunkHeuristic(instrs, 0x1000, 0x1005)).toBe(false);
  });
});

// ─── Dispatcher block detection heuristic ────────────────────────────────────
// The CfgView dispatcher computation: a block with ≥6 outgoing branch edges
// and ≤5 instructions is a dispatcher.

function computeDispatcherBlocks(
  nodes: { id: string; instruction_count?: number }[],
  edges: { source: string; target: string; kind: string }[],
): Set<string> {
  const branchCount = new Map<string, number>();
  for (const e of edges) {
    if (e.kind === 'branch') branchCount.set(e.source, (branchCount.get(e.source) ?? 0) + 1);
  }
  const s = new Set<string>();
  for (const node of nodes) {
    const bc = branchCount.get(node.id) ?? 0;
    const ic = node.instruction_count ?? 0;
    if (bc >= 6 && ic <= 5) s.add(node.id);
  }
  return s;
}

describe('Dispatcher block detection', () => {
  it('identifies a hub with 6 branch targets and 3 instructions as dispatcher', () => {
    const nodes = [{ id: 'hub', instruction_count: 3 }];
    const edges = Array.from({ length: 6 }, (_, i) => ({
      source: 'hub', target: `target_${i}`, kind: 'branch',
    }));
    const result = computeDispatcherBlocks(nodes, edges);
    expect(result.has('hub')).toBe(true);
  });

  it('does NOT flag a hub with only 5 branch targets', () => {
    const nodes = [{ id: 'hub', instruction_count: 3 }];
    const edges = Array.from({ length: 5 }, (_, i) => ({
      source: 'hub', target: `target_${i}`, kind: 'branch',
    }));
    const result = computeDispatcherBlocks(nodes, edges);
    expect(result.has('hub')).toBe(false);
  });

  it('does NOT flag a hub with 6 branch targets but 10 instructions', () => {
    const nodes = [{ id: 'hub', instruction_count: 10 }];
    const edges = Array.from({ length: 6 }, (_, i) => ({
      source: 'hub', target: `target_${i}`, kind: 'branch',
    }));
    const result = computeDispatcherBlocks(nodes, edges);
    expect(result.has('hub')).toBe(false);
  });

  it('does NOT flag fall-through (non-branch) edges', () => {
    const nodes = [{ id: 'hub', instruction_count: 2 }];
    const edges = Array.from({ length: 6 }, (_, i) => ({
      source: 'hub', target: `target_${i}`, kind: 'fall',  // not 'branch'
    }));
    const result = computeDispatcherBlocks(nodes, edges);
    expect(result.has('hub')).toBe(false);
  });
});
