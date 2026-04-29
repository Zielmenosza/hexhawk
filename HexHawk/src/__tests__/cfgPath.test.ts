import { describe, expect, it } from 'vitest';
import { findPathNodesAnyRoute } from '../utils/cfgPath';
import type { CfgGraph } from '../utils/cfgSignalExtractor';

function makeCfg(nodes: string[], edges: Array<[string, string]>): CfgGraph {
  return {
    nodes: nodes.map((id, idx) => ({ id, block_type: idx === 0 ? 'entry' : undefined })),
    edges: edges.map(([source, target]) => ({ source, target, kind: 'branch' })),
  };
}

describe('findPathNodesAnyRoute', () => {
  it('returns union of nodes on any route in a diamond', () => {
    const cfg = makeCfg(
      ['A', 'B', 'C', 'D'],
      [
        ['A', 'B'],
        ['A', 'C'],
        ['B', 'D'],
        ['C', 'D'],
      ],
    );

    const path = findPathNodesAnyRoute(cfg, 'A', 'D');
    expect(path).toEqual(new Set(['A', 'B', 'C', 'D']));
  });

  it('does not hang on back edges and excludes dead branches', () => {
    const cfg = makeCfg(
      ['entry', 'L1', 'L2', 'exit', 'dead'],
      [
        ['entry', 'L1'],
        ['L1', 'L2'],
        ['L2', 'L1'],   // back edge loop
        ['L2', 'exit'],
        ['entry', 'dead'],
      ],
    );

    const path = findPathNodesAnyRoute(cfg, 'entry', 'exit');
    expect(path.has('entry')).toBe(true);
    expect(path.has('L1')).toBe(true);
    expect(path.has('L2')).toBe(true);
    expect(path.has('exit')).toBe(true);
    expect(path.has('dead')).toBe(false);
  });

  it('returns empty set when no path exists', () => {
    const cfg = makeCfg(
      ['A', 'B', 'C'],
      [
        ['A', 'B'],
      ],
    );

    const path = findPathNodesAnyRoute(cfg, 'A', 'C');
    expect(path.size).toBe(0);
  });
});
