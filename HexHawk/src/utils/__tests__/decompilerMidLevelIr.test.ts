import { describe, expect, it } from 'vitest';
import {
  annotateReachingDefinitions,
  constantFoldDecompilerIr,
  eliminateDeadStores,
  runMidLevelIrPasses,
} from '../decompilerIr';
import type { DecompilerIrNode, DecompilerIrValue } from '../decompilerTypes';

const reg = (name: string): DecompilerIrValue => ({ kind: 'register', name });
const c = (value: number): DecompilerIrValue => ({ kind: 'constant', value, raw: String(value) });

const assign = (address: number, destination: string, source: DecompilerIrValue): DecompilerIrNode => ({
  kind: 'assignment',
  address,
  destination: reg(destination),
  source,
  confidence: 'high',
});

const add = (address: number, destination: string, left: DecompilerIrValue, right: DecompilerIrValue): DecompilerIrNode => ({
  kind: 'arithmetic',
  address,
  operator: '+',
  destination: reg(destination),
  left,
  right,
  confidence: 'high',
});

const ret = (address: number, value?: DecompilerIrValue): DecompilerIrNode => ({
  kind: 'return',
  address,
  value,
  confidence: 'high',
});

describe('GYRE mid-level IR tier', () => {
  it('constant folds tracked mov plus add constants into one constant node', () => {
    const [first, folded] = constantFoldDecompilerIr([
      assign(0x1000, 'rax', c(4)),
      add(0x1001, 'rax', reg('rax'), c(8)),
    ]);

    expect(first.kind).toBe('assignment');
    expect(folded.kind).toBe('assignment');
    if (folded.kind !== 'assignment') throw new Error('expected folded assignment');
    expect(folded.source).toEqual({ kind: 'constant', value: 12, raw: '12' });
  });

  it('does not fold non-constant operand pairs', () => {
    const [node] = constantFoldDecompilerIr([
      add(0x1000, 'rax', reg('rbx'), c(8)),
    ]);

    expect(node.kind).toBe('arithmetic');
  });

  it('eliminates unused assignments before function exit', () => {
    const optimized = eliminateDeadStores([
      assign(0x1000, 'rax', c(4)),
      ret(0x1001),
    ]);

    expect(optimized).toEqual([ret(0x1001)]);
  });

  it('keeps assignments used before exit', () => {
    const optimized = eliminateDeadStores([
      assign(0x1000, 'rax', c(4)),
      ret(0x1001, reg('rax')),
    ]);

    expect(optimized.map((node) => node.address)).toEqual([0x1000, 0x1001]);
  });

  it('records reaching definitions for a use across a branch merge', () => {
    const annotated = annotateReachingDefinitions([
      assign(0x1000, 'rax', c(1)),
      { kind: 'conditional-branch', address: 0x1001, condition: '==', target: 0x1004, fallthrough: 0x1002, confidence: 'medium' },
      assign(0x1002, 'rax', c(2)),
      { kind: 'side-effect-note', address: 0x1003, text: 'fallthrough', confidence: 'medium' },
      ret(0x1004, reg('rax')),
    ]);

    expect(annotated[4].reachingDefs?.rax).toEqual([0x1000, 0x1002]);
  });

  it('runs fold then DSE then reaching definitions in canonical order', () => {
    const optimized = runMidLevelIrPasses([
      assign(0x1000, 'rax', c(4)),
      add(0x1001, 'rax', reg('rax'), c(8)),
      ret(0x1002, reg('rax')),
    ]);

    expect(optimized).toHaveLength(2);
    expect(optimized[0].kind).toBe('assignment');
    expect(optimized[1].reachingDefs?.rax).toEqual([0x1001]);
  });
});
