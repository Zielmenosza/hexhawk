import { describe, expect, it } from 'vitest';
import { createStrikeQuerySurface, matchIL, type ILPattern } from '../strikeEngine';
import type { DecompilerIrNode } from '../decompilerTypes';

const nodes: DecompilerIrNode[] = [
  {
    kind: 'assignment',
    address: 0x1000,
    destination: { kind: 'register', name: 'rax' },
    source: { kind: 'constant', value: 1, raw: '1' },
    confidence: 'high',
  },
  {
    kind: 'assignment',
    address: 0x1004,
    destination: { kind: 'register', name: 'rbx' },
    source: { kind: 'memory', text: '[rsp + 8]' },
    confidence: 'high',
  },
  {
    kind: 'call',
    address: 0x1008,
    target: null,
    name: 'CreateFileW',
    args: [{ kind: 'register', name: 'rcx' }],
    confidence: 'medium',
    unresolved: true,
  },
];

describe('STRIKE IL opcode-tree pattern matching', () => {
  it('finds exact opcode matches for all call nodes', () => {
    const results = matchIL(nodes, { opcode: 'call' });

    expect(results).toHaveLength(1);
    expect(results[0].node.kind).toBe('call');
  });

  it('matches mov-to-register style assignments regardless of source', () => {
    const pattern: ILPattern = {
      opcode: 'assignment',
      operands: [{ opcode: 'register' }, { wildcard: true }],
    };

    const results = matchIL(nodes, pattern);

    expect(results).toHaveLength(2);
  });

  it('captures named wildcard bindings for matched subtrees', () => {
    const [result] = matchIL(nodes, {
      opcode: 'assignment',
      operands: [{ opcode: 'register' }, { wildcard: true, bind: 'source' }],
    });

    expect(result.bindings.source).toEqual({ kind: 'constant', value: 1, raw: '1' });
  });

  it('returns an empty array when no IL nodes match', () => {
    expect(matchIL(nodes, { opcode: 'return' })).toEqual([]);
  });

  it('exposes strike.matchIL(pattern) through a query surface', () => {
    const strike = createStrikeQuerySurface(nodes);

    expect(strike.matchIL({ opcode: 'call' })).toHaveLength(1);
  });
});
