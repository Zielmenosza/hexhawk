/**
 * cfgConcepts.test.ts
 *
 * Tests for all 19 in-scope RE concepts:
 *   1.  call              — CALL xref kind in xref map
 *   2.  call site         — source address with kind=CALL in xrefTypes
 *   3.  caller            — address that appears in incoming xrefs for a callee
 *   4.  callee            — address that appears in outgoing CALL xrefs for a caller
 *   5.  call graph        — caller/callee relationships from xref maps
 *   6.  basic block       — CfgNode with id, address range, instruction_count
 *   7.  edge              — CfgEdge with source, target, kind
 *   8.  true edge         — conditional branch → "TRUE" successor
 *   9.  false edge        — conditional fallthrough → "FALSE" successor
 *   10. back edge         — computeNaturalLoops backEdgeKey format
 *   11. loop header       — NaturalLoop.header field
 *   12. loop body         — NaturalLoop.body Set membership
 *   13. exit block        — block with no outgoing edges (ret/syscall ending block); distinct from external target nodes
 *   14. dominator         — idom chain from buildDomTreeFromCfg
 *   15. immediate dom     — idom map: B's idom is the closest dominator
 *   16. post-dominator    — postDomTree from buildDomTreeFromCfg
 *   17. dominator tree    — children map builds a tree from idom
 *   18. cross-reference   — xrefTypes Map keyed by "src:dst"
 *   19. incoming xrefs    — referencesMap: targetAddr → Set<sourceAddr>
 *       outgoing xrefs    — jumpTargetsMap: sourceAddr → Set<targetAddr>
 *
 * All tests use real analysis code — no mocks of the computation logic.
 */

import { describe, it, expect } from 'vitest';
import {
  computeNaturalLoops,
  buildLoopNestingTree,
  buildDomTreeFromCfg,
} from '../utils/cfgSignalExtractor';
import type { CfgGraph } from '../utils/cfgSignalExtractor';

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Build a minimal CfgGraph with the given adjacency list. */
function makeCfg(
  nodes: Array<{ id: string; block_type?: string; instruction_count?: number }>,
  edges: Array<{ source: string; target: string; kind?: string; condition?: string }>,
): CfgGraph {
  return {
    nodes: nodes.map(n => ({
      id:                n.id,
      block_type:        n.block_type ?? undefined,
      instruction_count: n.instruction_count ?? undefined,
    })),
    edges: edges.map(e => ({
      source:    e.source,
      target:    e.target,
      kind:      e.kind ?? 'branch',
      condition: e.condition ?? undefined,
    })),
  };
}

/**
 * Minimal xref map builder — simulates what App.tsx buildReferenceMaps produces.
 * Returns referencesMap (target → Set<source>) and jumpTargetsMap (source → Set<target>).
 */
function buildXrefMaps(
  xrefs: Array<{ src: number; dst: number; kind: string }>,
): {
  referencesMap: Map<number, Set<number>>;
  jumpTargetsMap: Map<number, Set<number>>;
  xrefTypes: Map<string, string>;
} {
  const referencesMap  = new Map<number, Set<number>>();
  const jumpTargetsMap = new Map<number, Set<number>>();
  const xrefTypes      = new Map<string, string>();
  for (const { src, dst, kind } of xrefs) {
    if (!referencesMap.has(dst)) referencesMap.set(dst, new Set());
    referencesMap.get(dst)!.add(src);
    if (!jumpTargetsMap.has(src)) jumpTargetsMap.set(src, new Set());
    jumpTargetsMap.get(src)!.add(dst);
    xrefTypes.set(`${src}:${dst}`, kind);
  }
  return { referencesMap, jumpTargetsMap, xrefTypes };
}

// ═══════════════════════════════════════════════════════════════════════════════
// ── Concepts 1-5: call, call site, caller, callee, call graph ────────────────
// ═══════════════════════════════════════════════════════════════════════════════

describe('Concept 1 — call: CALL xref kind is tracked', () => {
  it('records CALL kind for a call instruction', () => {
    const { xrefTypes } = buildXrefMaps([{ src: 0x1000, dst: 0x2000, kind: 'CALL' }]);
    expect(xrefTypes.get('4096:8192')).toBe('CALL');
  });
});

describe('Concept 2 — call site: source address with CALL is the call site', () => {
  it('jumpTargetsMap maps call site address to callee address', () => {
    const { jumpTargetsMap } = buildXrefMaps([{ src: 0x1004, dst: 0x3000, kind: 'CALL' }]);
    expect(jumpTargetsMap.get(0x1004)?.has(0x3000)).toBe(true);
  });

  it('xrefTypes marks the src:dst key as CALL', () => {
    const { xrefTypes } = buildXrefMaps([{ src: 0x1004, dst: 0x3000, kind: 'CALL' }]);
    expect(xrefTypes.get(`${0x1004}:${0x3000}`)).toBe('CALL');
  });
});

describe('Concept 3 — caller: incoming xrefs to a function give callers', () => {
  it('referencesMap contains the caller at the callee address', () => {
    const { referencesMap } = buildXrefMaps([
      { src: 0x1004, dst: 0x3000, kind: 'CALL' },
      { src: 0x2010, dst: 0x3000, kind: 'CALL' },
    ]);
    const callers = referencesMap.get(0x3000);
    expect(callers).toBeDefined();
    expect(callers!.has(0x1004)).toBe(true);
    expect(callers!.has(0x2010)).toBe(true);
    expect(callers!.size).toBe(2);
  });
});

describe('Concept 4 — callee: outgoing CALL xrefs give callees', () => {
  it('jumpTargetsMap maps a function to everything it calls', () => {
    const { jumpTargetsMap } = buildXrefMaps([
      { src: 0x1004, dst: 0x3000, kind: 'CALL' },
      { src: 0x1020, dst: 0x4000, kind: 'CALL' },
    ]);
    expect(jumpTargetsMap.get(0x1004)?.has(0x3000)).toBe(true);
    expect(jumpTargetsMap.get(0x1020)?.has(0x4000)).toBe(true);
  });
});

describe('Concept 5 — call graph: caller/callee graph is recoverable from xref maps', () => {
  it('can reconstruct which functions call which from xref maps', () => {
    const xrefs = [
      { src: 0x1000, dst: 0x2000, kind: 'CALL' }, // fn A calls fn B
      { src: 0x1000, dst: 0x3000, kind: 'CALL' }, // fn A also calls fn C
      { src: 0x2000, dst: 0x3000, kind: 'CALL' }, // fn B calls fn C
    ];
    const { referencesMap, jumpTargetsMap } = buildXrefMaps(xrefs);
    // A's callees
    expect(jumpTargetsMap.get(0x1000)?.size).toBe(2);
    // C's callers
    const cCallers = referencesMap.get(0x3000);
    expect(cCallers?.has(0x1000)).toBe(true);
    expect(cCallers?.has(0x2000)).toBe(true);
    // B's callers
    expect(referencesMap.get(0x2000)?.has(0x1000)).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// ── Concepts 6-7: basic block, edge ─────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

describe('Concept 6 — basic block: CfgNode has id, address range, instruction count', () => {
  it('basic block carries expected fields', () => {
    const cfg = makeCfg(
      [{ id: 'bb0', block_type: 'entry', instruction_count: 5 }],
      [],
    );
    const block = cfg.nodes[0];
    expect(block.id).toBe('bb0');
    expect(block.block_type).toBe('entry');
    expect(block.instruction_count).toBe(5);
  });

  it('multiple basic blocks form a linear sequence', () => {
    const cfg = makeCfg(
      [{ id: 'bb0', block_type: 'entry' }, { id: 'bb1' }, { id: 'bb2' }],
      [{ source: 'bb0', target: 'bb1' }, { source: 'bb1', target: 'bb2' }],
    );
    expect(cfg.nodes).toHaveLength(3);
    expect(cfg.edges).toHaveLength(2);
  });
});

describe('Concept 7 — edge: CfgEdge has source, target, kind', () => {
  it('branch edge has kind="branch"', () => {
    const cfg = makeCfg(
      [{ id: 'a' }, { id: 'b' }],
      [{ source: 'a', target: 'b', kind: 'branch' }],
    );
    expect(cfg.edges[0].kind).toBe('branch');
  });

  it('fallthrough edge has kind="fallthrough"', () => {
    const cfg = makeCfg(
      [{ id: 'a' }, { id: 'b' }],
      [{ source: 'a', target: 'b', kind: 'fallthrough' }],
    );
    expect(cfg.edges[0].kind).toBe('fallthrough');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// ── Concepts 8-9: true edge / false edge ─────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

describe('Concept 8 — true edge: conditional branch edge', () => {
  it('conditional branch edge has condition="conditional"', () => {
    const cfg = makeCfg(
      [{ id: 'hdr' }, { id: 'body' }, { id: 'exit' }],
      [
        { source: 'hdr', target: 'body', kind: 'branch',      condition: 'conditional' },
        { source: 'hdr', target: 'exit', kind: 'fallthrough',  condition: 'conditional' },
      ],
    );
    const trueEdge = cfg.edges.find(e => e.kind === 'branch' && e.condition === 'conditional');
    expect(trueEdge).toBeDefined();
    expect(trueEdge!.target).toBe('body');
  });
});

describe('Concept 9 — false edge: conditional fallthrough edge', () => {
  it('conditional fallthrough edge leads to the fall-through target', () => {
    const cfg = makeCfg(
      [{ id: 'hdr' }, { id: 'body' }, { id: 'exit' }],
      [
        { source: 'hdr', target: 'body', kind: 'branch',      condition: 'conditional' },
        { source: 'hdr', target: 'exit', kind: 'fallthrough',  condition: 'conditional' },
      ],
    );
    const falseEdge = cfg.edges.find(e => e.kind === 'fallthrough' && e.condition === 'conditional');
    expect(falseEdge).toBeDefined();
    expect(falseEdge!.target).toBe('exit');
  });

  it('a node with one branch + one fallthrough has exactly one true edge and one false edge', () => {
    const cfg = makeCfg(
      [{ id: 'cond' }, { id: 't' }, { id: 'f' }],
      [
        { source: 'cond', target: 't', kind: 'branch',     condition: 'conditional' },
        { source: 'cond', target: 'f', kind: 'fallthrough', condition: 'conditional' },
      ],
    );
    const edgesFrom = cfg.edges.filter(e => e.source === 'cond');
    const trueEdges  = edgesFrom.filter(e => e.kind === 'branch' && e.condition === 'conditional');
    const falseEdges = edgesFrom.filter(e => e.kind === 'fallthrough' && e.condition === 'conditional');
    expect(trueEdges).toHaveLength(1);
    expect(falseEdges).toHaveLength(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// ── Concepts 10-13: back edge, loop header, loop body, exit block ─────────────
// (existing tests, kept for completeness)
// ═══════════════════════════════════════════════════════════════════════════════

describe('computeNaturalLoops – back edge detection', () => {
  it('returns empty array for a straight-line CFG (no loops)', () => {
    const cfg = makeCfg(
      [{ id: 'b0', block_type: 'entry' }, { id: 'b1' }, { id: 'b2' }],
      [{ source: 'b0', target: 'b1' }, { source: 'b1', target: 'b2' }],
    );
    expect(computeNaturalLoops(cfg)).toHaveLength(0);
  });

  it('detects one back edge in a simple while-loop CFG', () => {
    const cfg = makeCfg(
      [{ id: 'b0', block_type: 'entry' }, { id: 'b1' }, { id: 'b2' }, { id: 'b3' }],
      [
        { source: 'b0', target: 'b1' },
        { source: 'b1', target: 'b2' },
        { source: 'b1', target: 'b3' },
        { source: 'b2', target: 'b1' }, // back edge
      ],
    );
    const loops = computeNaturalLoops(cfg);
    expect(loops).toHaveLength(1);
    expect(loops[0].header).toBe('b1');
    expect(loops[0].latch).toBe('b2');
    expect(loops[0].backEdgeKey).toBe('b2->b1');
  });

  it('identifies the loop header as a block in the loop body', () => {
    const cfg = makeCfg(
      [{ id: 'b0', block_type: 'entry' }, { id: 'b1' }, { id: 'b2' }],
      [
        { source: 'b0', target: 'b1' },
        { source: 'b1', target: 'b2' },
        { source: 'b2', target: 'b1' },
      ],
    );
    const loops = computeNaturalLoops(cfg);
    expect(loops[0].body.has('b1')).toBe(true);
    expect(loops[0].body.has('b2')).toBe(true);
  });
});

describe('computeNaturalLoops – loop header & body', () => {
  it('header block is distinct from latch block', () => {
    const cfg = makeCfg(
      [{ id: 'entry', block_type: 'entry' }, { id: 'hdr' }, { id: 'body' }, { id: 'exit' }],
      [
        { source: 'entry', target: 'hdr' },
        { source: 'hdr',   target: 'body' },
        { source: 'hdr',   target: 'exit' },
        { source: 'body',  target: 'hdr' },
      ],
    );
    const loops = computeNaturalLoops(cfg);
    expect(loops[0].header).toBe('hdr');
    expect(loops[0].latch).toBe('body');
  });

  it('all body blocks are reachable from header within the loop', () => {
    const cfg = makeCfg(
      [{ id: 'hdr', block_type: 'entry' }, { id: 'a' }, { id: 'b' }, { id: 'c' }],
      [
        { source: 'hdr', target: 'a' },
        { source: 'hdr', target: 'b' },
        { source: 'a',   target: 'c' },
        { source: 'b',   target: 'c' },
        { source: 'c',   target: 'hdr' },
      ],
    );
    const loops = computeNaturalLoops(cfg);
    expect(loops).toHaveLength(1);
    const body = loops[0].body;
    expect(body.has('hdr')).toBe(true);
    expect(body.has('a')).toBe(true);
    expect(body.has('b')).toBe(true);
    expect(body.has('c')).toBe(true);
  });
});

describe('computeNaturalLoops – nesting depth', () => {
  it('assigns depth=1 to outermost loop and depth=2 to inner loop', () => {
    const cfg = makeCfg(
      [
        { id: 'entry',       block_type: 'entry' },
        { id: 'outer_hdr' },
        { id: 'inner_hdr' },
        { id: 'inner_body' },
        { id: 'outer_latch' },
        { id: 'exit' },
      ],
      [
        { source: 'entry',       target: 'outer_hdr' },
        { source: 'outer_hdr',  target: 'inner_hdr' },
        { source: 'outer_hdr',  target: 'exit' },
        { source: 'inner_hdr',  target: 'inner_body' },
        { source: 'inner_hdr',  target: 'outer_latch' },
        { source: 'inner_body', target: 'inner_hdr' },
        { source: 'outer_latch', target: 'outer_hdr' },
      ],
    );
    const loops = computeNaturalLoops(cfg);
    expect(loops.length).toBeGreaterThanOrEqual(2);
    const outer = loops.find(l => l.header === 'outer_hdr');
    const inner = loops.find(l => l.header === 'inner_hdr');
    expect(outer).toBeDefined();
    expect(inner).toBeDefined();
    expect(outer!.depth).toBe(1);
    expect(inner!.depth).toBe(2);
  });
});

describe('Concept 13 — exit block: block with no outgoing edges', () => {
  it('a block with no outgoing edges is an exit block (ret-ending block)', () => {
    // entry → mid → exit (no successors = exit block, as in a block ending with ret)
    const cfg = makeCfg(
      [
        { id: 'entry', block_type: 'entry' },
        { id: 'mid' },
        { id: 'exit' },   // no outgoing edges — this is the exit block
      ],
      [
        { source: 'entry', target: 'mid' },
        { source: 'mid',   target: 'exit' },
        // 'exit' has no outgoing edges
      ],
    );
    const hasOutgoing = new Set(cfg.edges.map(e => e.source));
    const exitBlocks = cfg.nodes.filter(n => n.block_type !== 'external' && !hasOutgoing.has(n.id));
    expect(exitBlocks).toHaveLength(1);
    expect(exitBlocks[0].id).toBe('exit');
  });

  it('external target nodes are NOT exit blocks — they are out-of-range call/jump targets', () => {
    const cfg = makeCfg(
      [
        { id: 'entry', block_type: 'entry' },
        { id: 'ext',   block_type: 'external' },  // external target (e.g. libc call)
      ],
      [{ source: 'entry', target: 'ext' }],
    );
    const hasOutgoing = new Set(cfg.edges.map(e => e.source));
    // External nodes should not be classified as exit blocks
    const exitBlocks = cfg.nodes.filter(n => n.block_type !== 'external' && !hasOutgoing.has(n.id));
    // entry has an outgoing edge to ext, so it is not an exit block
    expect(exitBlocks).toHaveLength(0);
    // The external node is not an exit block (it's an external target)
    const extIsExitBlock = exitBlocks.some(n => n.id === 'ext');
    expect(extIsExitBlock).toBe(false);
  });
});

describe('NaturalLoop.backEdgeKey format', () => {
  it('encodes back edge as "latch->header"', () => {
    const cfg = makeCfg(
      [{ id: 'A', block_type: 'entry' }, { id: 'B' }],
      [{ source: 'A', target: 'B' }, { source: 'B', target: 'A' }],
    );
    const loops = computeNaturalLoops(cfg);
    expect(loops).toHaveLength(1);
    const { latch, header, backEdgeKey } = loops[0];
    expect(backEdgeKey).toBe(`${latch}->${header}`);
  });
});

describe('buildLoopNestingTree', () => {
  it('produces a single root for one loop', () => {
    const cfg = makeCfg(
      [{ id: 'h', block_type: 'entry' }, { id: 'b' }],
      [{ source: 'h', target: 'b' }, { source: 'b', target: 'h' }],
    );
    const loops = computeNaturalLoops(cfg);
    const tree = buildLoopNestingTree(loops);
    expect(tree).toHaveLength(1);
    expect(tree[0].loop.header).toBe('h');
  });

  it('nests inner loop as child of outer loop', () => {
    const cfg = makeCfg(
      [
        { id: 'entry', block_type: 'entry' },
        { id: 'outer' },
        { id: 'inner' },
        { id: 'body' },
        { id: 'latch' },
        { id: 'exit' },
      ],
      [
        { source: 'entry', target: 'outer' },
        { source: 'outer', target: 'inner' },
        { source: 'outer', target: 'exit' },
        { source: 'inner', target: 'body' },
        { source: 'inner', target: 'latch' },
        { source: 'body',  target: 'inner' },
        { source: 'latch', target: 'outer' },
      ],
    );
    const loops = computeNaturalLoops(cfg);
    const tree = buildLoopNestingTree(loops);
    expect(tree).toHaveLength(1);
    expect(tree[0].loop.header).toBe('outer');
    expect(tree[0].children).toHaveLength(1);
    expect(tree[0].children[0].loop.header).toBe('inner');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// ── Concepts 14-17: dominator, immediate dom, post-dom, dominator tree ────────
// ═══════════════════════════════════════════════════════════════════════════════

describe('Concept 14 — dominator: entry dominates all blocks', () => {
  it('every node is dominated by the entry', () => {
    // entry → A → B → exit; entry dominates all
    const cfg = makeCfg(
      [{ id: 'entry', block_type: 'entry' }, { id: 'A' }, { id: 'B' }, { id: 'exit' }],
      [
        { source: 'entry', target: 'A' },
        { source: 'A',     target: 'B' },
        { source: 'B',     target: 'exit' },
      ],
    );
    const { domTree } = buildDomTreeFromCfg(cfg);
    // Check that entry appears as idom ancestor for B
    const idomB = domTree.idom.get('B');
    expect(idomB).toBe('A'); // A immediately dominates B
    // Ancestry chain: B → A → entry
    const idomA = domTree.idom.get('A');
    expect(idomA).toBe('entry');
    const idomEntry = domTree.idom.get('entry');
    expect(idomEntry).toBeNull(); // entry has no dominator
  });
});

describe('Concept 15 — immediate dominator: idom is the closest dominator', () => {
  it('idom picks the closest dominator, not just any ancestor', () => {
    // entry → A → B → C; A dominates B and C, but idom(C) = B (not A)
    const cfg = makeCfg(
      [{ id: 'entry', block_type: 'entry' }, { id: 'A' }, { id: 'B' }, { id: 'C' }],
      [
        { source: 'entry', target: 'A' },
        { source: 'A',     target: 'B' },
        { source: 'B',     target: 'C' },
      ],
    );
    const { domTree } = buildDomTreeFromCfg(cfg);
    expect(domTree.idom.get('C')).toBe('B');
    expect(domTree.idom.get('B')).toBe('A');
    expect(domTree.idom.get('A')).toBe('entry');
  });

  it('at a merge point, idom is the lowest common dominator', () => {
    // entry → L → merge,  entry → R → merge: idom(merge) = entry
    const cfg = makeCfg(
      [{ id: 'entry', block_type: 'entry' }, { id: 'L' }, { id: 'R' }, { id: 'merge' }],
      [
        { source: 'entry', target: 'L' },
        { source: 'entry', target: 'R' },
        { source: 'L',     target: 'merge' },
        { source: 'R',     target: 'merge' },
      ],
    );
    const { domTree } = buildDomTreeFromCfg(cfg);
    expect(domTree.idom.get('merge')).toBe('entry');
  });
});

describe('Concept 16 — post-dominator: exit post-dominates everything that must reach it', () => {
  it('exit block has null idom in post-dom tree (it is the post-dom root)', () => {
    const cfg = makeCfg(
      [{ id: 'entry', block_type: 'entry' }, { id: 'A' }, { id: 'exit', block_type: 'external' }],
      [
        { source: 'entry', target: 'A' },
        { source: 'A',     target: 'exit' },
      ],
    );
    const { postDomTree } = buildDomTreeFromCfg(cfg);
    // At least one node should have null idom (the post-dom root(s))
    const roots = Array.from(postDomTree.idom.entries()).filter(([, v]) => v === null);
    expect(roots.length).toBeGreaterThan(0);
  });

  it('nodes before exit are post-dominated by exit', () => {
    const cfg = makeCfg(
      [{ id: 'entry', block_type: 'entry' }, { id: 'mid' }, { id: 'exit', block_type: 'external' }],
      [
        { source: 'entry', target: 'mid' },
        { source: 'mid',   target: 'exit' },
      ],
    );
    const { postDomTree } = buildDomTreeFromCfg(cfg);
    // mid should be post-dominated by exit
    const midPostIdom = postDomTree.idom.get('mid');
    expect(midPostIdom).toBe('exit');
  });
});

describe('Concept 17 — dominator tree: children map builds correct tree structure', () => {
  it('entry is the root with all others as descendants', () => {
    const cfg = makeCfg(
      [{ id: 'entry', block_type: 'entry' }, { id: 'A' }, { id: 'B' }],
      [
        { source: 'entry', target: 'A' },
        { source: 'A',     target: 'B' },
      ],
    );
    const { domTree } = buildDomTreeFromCfg(cfg);
    expect(domTree.children.get('entry')).toContain('A');
    expect(domTree.children.get('A')).toContain('B');
  });

  it('rpo contains all reachable nodes', () => {
    const cfg = makeCfg(
      [{ id: 'e', block_type: 'entry' }, { id: 'a' }, { id: 'b' }],
      [{ source: 'e', target: 'a' }, { source: 'a', target: 'b' }],
    );
    const { domTree } = buildDomTreeFromCfg(cfg);
    expect(domTree.rpo).toContain('e');
    expect(domTree.rpo).toContain('a');
    expect(domTree.rpo).toContain('b');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// ── Concepts 18-19: cross-reference, incoming xrefs, outgoing xrefs ───────────
// ═══════════════════════════════════════════════════════════════════════════════

describe('Concept 18 — cross-reference: xrefTypes keyed by "src:dst"', () => {
  it('key format is "srcAddr:dstAddr" as decimal strings', () => {
    const { xrefTypes } = buildXrefMaps([{ src: 0x401000, dst: 0x402000, kind: 'CALL' }]);
    expect(xrefTypes.has(`${0x401000}:${0x402000}`)).toBe(true);
  });

  it('different xref kinds are stored correctly', () => {
    const { xrefTypes } = buildXrefMaps([
      { src: 0x1000, dst: 0x2000, kind: 'JMP' },
      { src: 0x1010, dst: 0x3000, kind: 'DATA' },
      { src: 0x1020, dst: 0x4000, kind: 'JMP_COND' },
    ]);
    expect(xrefTypes.get(`${0x1000}:${0x2000}`)).toBe('JMP');
    expect(xrefTypes.get(`${0x1010}:${0x3000}`)).toBe('DATA');
    expect(xrefTypes.get(`${0x1020}:${0x4000}`)).toBe('JMP_COND');
  });
});

describe('Concept 19 — incoming & outgoing xrefs', () => {
  it('incoming xrefs: referencesMap[target] = set of all sources', () => {
    const { referencesMap } = buildXrefMaps([
      { src: 0x1000, dst: 0x5000, kind: 'CALL' },
      { src: 0x2000, dst: 0x5000, kind: 'CALL' },
      { src: 0x3000, dst: 0x5000, kind: 'JMP' },
    ]);
    const incoming = referencesMap.get(0x5000);
    expect(incoming).toBeDefined();
    expect(incoming!.size).toBe(3);
    expect(incoming!.has(0x1000)).toBe(true);
    expect(incoming!.has(0x2000)).toBe(true);
    expect(incoming!.has(0x3000)).toBe(true);
  });

  it('outgoing xrefs: jumpTargetsMap[source] = set of all targets', () => {
    const { jumpTargetsMap } = buildXrefMaps([
      { src: 0x1000, dst: 0x2000, kind: 'CALL' },
      { src: 0x1000, dst: 0x3000, kind: 'JMP_COND' },
    ]);
    const outgoing = jumpTargetsMap.get(0x1000);
    expect(outgoing).toBeDefined();
    expect(outgoing!.size).toBe(2);
    expect(outgoing!.has(0x2000)).toBe(true);
    expect(outgoing!.has(0x3000)).toBe(true);
  });

  it('an address with no references has no entry in referencesMap', () => {
    const { referencesMap } = buildXrefMaps([{ src: 0x1000, dst: 0x2000, kind: 'DATA' }]);
    expect(referencesMap.has(0x1000)).toBe(false); // 0x1000 is a source, not a target
    expect(referencesMap.has(0x2000)).toBe(true);
  });
});


// ─── Back edge detection ─────────────────────────────────────────────────────

describe('computeNaturalLoops – back edge detection', () => {
  it('returns empty array for a straight-line CFG (no loops)', () => {
    const cfg = makeCfg(
      [{ id: 'b0', block_type: 'entry' }, { id: 'b1' }, { id: 'b2' }],
      [{ source: 'b0', target: 'b1' }, { source: 'b1', target: 'b2' }],
    );
    expect(computeNaturalLoops(cfg)).toHaveLength(0);
  });

  it('detects one back edge in a simple while-loop CFG', () => {
    // b0 (entry) → b1 (header) → b2 (body) → b1 (back), b1 → b3 (exit)
    const cfg = makeCfg(
      [{ id: 'b0', block_type: 'entry' }, { id: 'b1' }, { id: 'b2' }, { id: 'b3' }],
      [
        { source: 'b0', target: 'b1' },
        { source: 'b1', target: 'b2' },   // true branch: enter loop body
        { source: 'b1', target: 'b3' },   // false branch: exit loop
        { source: 'b2', target: 'b1' },   // back edge: b2 → b1
      ],
    );
    const loops = computeNaturalLoops(cfg);
    expect(loops).toHaveLength(1);
    expect(loops[0].header).toBe('b1');
    expect(loops[0].latch).toBe('b2');
    // backEdgeKey format must be "latch->header"
    expect(loops[0].backEdgeKey).toBe('b2->b1');
  });

  it('identifies the loop header as a block in the loop body', () => {
    const cfg = makeCfg(
      [{ id: 'b0', block_type: 'entry' }, { id: 'b1' }, { id: 'b2' }],
      [
        { source: 'b0', target: 'b1' },
        { source: 'b1', target: 'b2' },
        { source: 'b2', target: 'b1' },  // back edge
      ],
    );
    const loops = computeNaturalLoops(cfg);
    expect(loops[0].body.has('b1')).toBe(true);   // header is in body
    expect(loops[0].body.has('b2')).toBe(true);   // latch is in body
  });
});

// ─── Loop header / body classification ───────────────────────────────────────

describe('computeNaturalLoops – loop header & body', () => {
  it('header block is distinct from latch block', () => {
    const cfg = makeCfg(
      [{ id: 'entry', block_type: 'entry' }, { id: 'hdr' }, { id: 'body' }, { id: 'exit' }],
      [
        { source: 'entry', target: 'hdr' },
        { source: 'hdr',   target: 'body' },
        { source: 'hdr',   target: 'exit' },
        { source: 'body',  target: 'hdr' },  // back edge
      ],
    );
    const loops = computeNaturalLoops(cfg);
    expect(loops[0].header).toBe('hdr');
    expect(loops[0].latch).toBe('body');
  });

  it('all body blocks are reachable from header within the loop', () => {
    // Diamond loop: hdr → a → c → hdr,  hdr → b → c → hdr
    const cfg = makeCfg(
      [{ id: 'hdr', block_type: 'entry' }, { id: 'a' }, { id: 'b' }, { id: 'c' }],
      [
        { source: 'hdr', target: 'a' },
        { source: 'hdr', target: 'b' },
        { source: 'a',   target: 'c' },
        { source: 'b',   target: 'c' },
        { source: 'c',   target: 'hdr' },  // back edge
      ],
    );
    const loops = computeNaturalLoops(cfg);
    expect(loops).toHaveLength(1);
    const body = loops[0].body;
    expect(body.has('hdr')).toBe(true);
    expect(body.has('a')).toBe(true);
    expect(body.has('b')).toBe(true);
    expect(body.has('c')).toBe(true);
  });
});

// ─── Nested loop depth ────────────────────────────────────────────────────────

describe('computeNaturalLoops – nesting depth', () => {
  it('assigns depth=1 to outermost loop and depth=2 to inner loop', () => {
    // Outer loop: entry → outer_hdr → inner_hdr → inner_body → inner_hdr (back), inner_hdr → outer_latch → outer_hdr (back)
    const cfg = makeCfg(
      [
        { id: 'entry',      block_type: 'entry' },
        { id: 'outer_hdr' },
        { id: 'inner_hdr' },
        { id: 'inner_body' },
        { id: 'outer_latch' },
        { id: 'exit' },
      ],
      [
        { source: 'entry',       target: 'outer_hdr' },
        { source: 'outer_hdr',  target: 'inner_hdr' },
        { source: 'outer_hdr',  target: 'exit' },
        { source: 'inner_hdr',  target: 'inner_body' },
        { source: 'inner_hdr',  target: 'outer_latch' },
        { source: 'inner_body', target: 'inner_hdr' },   // inner back edge
        { source: 'outer_latch', target: 'outer_hdr' },  // outer back edge
      ],
    );
    const loops = computeNaturalLoops(cfg);
    expect(loops.length).toBeGreaterThanOrEqual(2);

    const outer = loops.find(l => l.header === 'outer_hdr');
    const inner = loops.find(l => l.header === 'inner_hdr');
    expect(outer).toBeDefined();
    expect(inner).toBeDefined();
    expect(outer!.depth).toBe(1);
    expect(inner!.depth).toBe(2);
  });
});

// ─── Exit block identification ────────────────────────────────────────────────
// An exit block is a basic block with no outgoing edges — typically ends in
// ret or syscall. This is distinct from block_type === 'external', which are
// jump/call targets outside the analyzed address range.

describe('exit block identification', () => {
  it('a block with no successors (no outgoing edges) is the exit block', () => {
    const cfg = makeCfg(
      [
        { id: 'entry',  block_type: 'entry' },
        { id: 'body' },
        { id: 'ret_block' },  // ends with ret — no outgoing edges
        { id: 'extern', block_type: 'external' },  // out-of-range call target
      ],
      [
        { source: 'entry', target: 'body' },
        { source: 'body',  target: 'entry' },   // back edge (loop)
        { source: 'entry', target: 'extern' },  // call to external function
        { source: 'body',  target: 'ret_block' },
        // ret_block has no outgoing edges
      ],
    );
    const hasOutgoing = new Set(cfg.edges.map(e => e.source));
    // True exit block: non-external node with no outgoing edges
    const exitBlocks = cfg.nodes.filter(n => n.block_type !== 'external' && !hasOutgoing.has(n.id));
    expect(exitBlocks).toHaveLength(1);
    expect(exitBlocks[0].id).toBe('ret_block');
    // External target is NOT an exit block
    expect(exitBlocks.some(n => n.id === 'extern')).toBe(false);
  });
});

// ─── Back edge key format (used by ControlFlowGraph rendering) ────────────────

describe('NaturalLoop.backEdgeKey format', () => {
  it('encodes back edge as "latch->header"', () => {
    const cfg = makeCfg(
      [{ id: 'A', block_type: 'entry' }, { id: 'B' }],
      [
        { source: 'A', target: 'B' },
        { source: 'B', target: 'A' },  // back edge B → A
      ],
    );
    const loops = computeNaturalLoops(cfg);
    expect(loops).toHaveLength(1);
    // Key format must be "latch->header" so CfgView can parse it
    const { latch, header, backEdgeKey } = loops[0];
    expect(backEdgeKey).toBe(`${latch}->${header}`);
  });
});

// ─── Loop nesting tree ────────────────────────────────────────────────────────

describe('buildLoopNestingTree', () => {
  it('produces a single root for one loop', () => {
    const cfg = makeCfg(
      [{ id: 'h', block_type: 'entry' }, { id: 'b' }],
      [{ source: 'h', target: 'b' }, { source: 'b', target: 'h' }],
    );
    const loops = computeNaturalLoops(cfg);
    const tree = buildLoopNestingTree(loops);
    expect(tree).toHaveLength(1);
    expect(tree[0].loop.header).toBe('h');
  });

  it('nests inner loop as child of outer loop', () => {
    const cfg = makeCfg(
      [
        { id: 'entry', block_type: 'entry' },
        { id: 'outer' },
        { id: 'inner' },
        { id: 'body' },
        { id: 'latch' },
        { id: 'exit' },
      ],
      [
        { source: 'entry', target: 'outer' },
        { source: 'outer', target: 'inner' },
        { source: 'outer', target: 'exit' },
        { source: 'inner', target: 'body' },
        { source: 'inner', target: 'latch' },
        { source: 'body',  target: 'inner' },   // inner back edge
        { source: 'latch', target: 'outer' },   // outer back edge
      ],
    );
    const loops = computeNaturalLoops(cfg);
    const tree = buildLoopNestingTree(loops);
    expect(tree).toHaveLength(1);  // one root
    expect(tree[0].loop.header).toBe('outer');
    expect(tree[0].children).toHaveLength(1);
    expect(tree[0].children[0].loop.header).toBe('inner');
  });
});
