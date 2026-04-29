/**
 * cfgSignalExtractor — Control Flow Graph → NEST correlation signals
 *
 * Analyses a `CfgGraph` (from Tauri command `build_cfg`) and produces:
 *   - `SuspiciousPattern[]`  — fed into `correlationEngine.computeVerdict` via `CorrelationInput.patterns`
 *   - `CfgAnalysisSummary`   — human-readable stats stored in the NEST iteration snapshot
 *
 * Detection rules:
 *   1. Indirect calls (call edges to external/unknown targets)     → indirect_call
 *   2. Tight loops (back-edges in DFS)                            → tight_loop
 *   3. Jump tables (node with ≥4 outgoing branch edges)           → jump_table
 *   4. Unreachable blocks (not reachable from entry node)         → obfuscation (anti-analysis)
 *   5. Obfuscated dispatch (external block with no label)         → indirect_call
 */

import type { SuspiciousPattern } from '../App';
import type { DomTree } from './ssaTransform';

// ── Input type (mirrors CfgGraph from graph.rs) ───────────────────────────────

export interface CfgNode {
  id:                string;
  label?:            string | null;
  start?:            number | null;
  end?:              number | null;
  instruction_count?: number | null;
  block_type?:       string | null;  // "entry" | "fallthrough" | "target" | "external"
  layout_x?:         number | null;
  layout_y?:         number | null;
  layout_depth?:     number | null;
}

export interface CfgEdge {
  source:     string;
  target:     string;
  kind?:      string | null;       // "branch" | "fallthrough" | "call"
  condition?: string | null;       // "conditional" | "unconditional"
}

export interface CfgGraph {
  nodes: CfgNode[];
  edges: CfgEdge[];
}

// ── Output ────────────────────────────────────────────────────────────────────

export interface CfgAnalysisSummary {
  totalBlocks:      number;
  totalEdges:       number;
  indirectCalls:    number;
  backEdges:        number;      // approximate loop count
  unreachableBlocks: number;
  jumpTables:       number;
  externalTargets:  number;
  complexityScore:  number;      // 0–100 heuristic
  naturalLoops:     NaturalLoop[];   // detected natural loops
  maxNestingDepth:  number;          // maximum loop nesting depth
}

// ── Natural Loop types ────────────────────────────────────────────────────────

export type LoopClassification = 'for' | 'while' | 'do-while' | 'infinite' | 'unknown';

export interface NaturalLoop {
  /** Block ID of the loop header (dominator of all back-edge sources). */
  header: string;
  /** Block ID of the back-edge source (the block that jumps back to header). */
  latch: string;
  /** Set of all block IDs in the loop body (including header and latch). */
  body: Set<string>;
  /** Nesting depth: 1 = outermost, 2 = nested inside another loop, etc. */
  depth: number;
  /** Original back-edge key from findBackEdges: "latch->header". */
  backEdgeKey: string;
  /** Structural classification based on block content heuristics. */
  classification: LoopClassification;
  /** Header block start address (for display). */
  headerAddress: number;
}

export interface LoopNestingNode {
  loop: NaturalLoop;
  children: LoopNestingNode[];
}

// ── Natural loop detection ───────────────────────────────────────────────────

/**
 * Build a reverse-adjacency map from the forward adjacency.
 */
function buildReverseAdjacency(adjacency: Map<string, string[]>): Map<string, string[]> {
  const rev = new Map<string, string[]>();
  for (const [id] of adjacency) rev.set(id, []);
  for (const [src, targets] of adjacency) {
    for (const tgt of targets) {
      if (!rev.has(tgt)) rev.set(tgt, []);
      rev.get(tgt)!.push(src);
    }
  }
  return rev;
}

/**
 * Collect all nodes in the natural loop body for the back-edge latch→header.
 * Uses reverse-DFS from latch, stopping at header (which is still included).
 */
function collectLoopBody(
  latch: string,
  header: string,
  revAdjacency: Map<string, string[]>,
): Set<string> {
  const body = new Set<string>();
  body.add(header);
  const worklist = [latch];
  while (worklist.length > 0) {
    const node = worklist.pop()!;
    if (body.has(node)) continue;
    body.add(node);
    for (const pred of revAdjacency.get(node) ?? []) {
      if (!body.has(pred)) worklist.push(pred);
    }
  }
  return body;
}

/**
 * Classify a natural loop based on heuristics about the header and latch blocks.
 *   - 'infinite'  : no conditional jump at header or latch
 *   - 'do-while'  : conditional jump at latch (test is at the bottom)
 *   - 'while'     : conditional jump at header (test is at the top)
 *   - 'for'       : conditional at header + an increment-like pattern in latch
 *   - 'unknown'   : cannot determine
 */
function classifyNaturalLoop(
  loop: Omit<NaturalLoop, 'classification' | 'depth'>,
  nodeMap: Map<string, CfgNode>,
): LoopClassification {
  const header = nodeMap.get(loop.header);
  const latch  = nodeMap.get(loop.latch);

  // No header info — unknown
  if (!header) return 'unknown';

  // Detect conditional branch at header (block has 2 outgoing edges)
  // We infer this from CfgEdge data, but CfgNode doesn't carry edges.
  // Use instruction_count as a proxy: very low count (≤2) with no latch cond = infinite.
  const headerInstrCount = header.instruction_count ?? 0;
  const latchInstrCount  = latch?.instruction_count ?? 0;

  if (headerInstrCount === 0 && latchInstrCount === 0) return 'unknown';

  // If latch has exactly 1 instruction and header has a compare-like count (≥2)
  // → while pattern
  // These are coarse heuristics; talonEngine does deeper analysis with IRBlock stmts.
  if (headerInstrCount >= 2 && latchInstrCount <= 2) return 'while';
  if (latchInstrCount >= 2 && headerInstrCount <= 2) return 'do-while';
  if (headerInstrCount === 1 && latchInstrCount === 1) return 'infinite';
  return 'unknown';
}

/**
 * Compute all natural loops in the CFG.
 *
 * For each back edge (latch → header), finds:
 *   - The loop body via reverse-DFS
 *   - The nesting depth (by containment in other loops)
 *   - A structural classification
 */
export function computeNaturalLoops(cfg: CfgGraph): NaturalLoop[] {
  if (cfg.nodes.length === 0) return [];

  const adjacency = new Map<string, string[]>();
  for (const node of cfg.nodes) adjacency.set(node.id, []);
  for (const edge of cfg.edges) {
    adjacency.get(edge.source)?.push(edge.target);
  }

  const entryNode = cfg.nodes.find(n => n.block_type === 'entry') ?? cfg.nodes[0];
  const entryId   = entryNode.id;
  const revAdj    = buildReverseAdjacency(adjacency);
  const nodeMap   = new Map<string, CfgNode>(cfg.nodes.map(n => [n.id, n]));

  const backEdges = findBackEdges(adjacency, entryId);

  // Build preliminary loops (no depth yet)
  type PartialLoop = Omit<NaturalLoop, 'classification' | 'depth'>;
  const partial: PartialLoop[] = [];

  for (const key of backEdges) {
    const sepIdx = key.indexOf('->');
    if (sepIdx < 0) continue;
    const latch  = key.slice(0, sepIdx);
    const header = key.slice(sepIdx + 2);

    const body = collectLoopBody(latch, header, revAdj);
    const headerNode = nodeMap.get(header);
    partial.push({
      header,
      latch,
      body,
      backEdgeKey: key,
      headerAddress: headerNode?.start ?? 0,
    });
  }

  // Assign nesting depths by containment (A is inside B iff A.body ⊂ B.body)
  const loops: NaturalLoop[] = partial.map(loop => {
    // Count how many other loops strictly contain this one
    const depth = partial.filter(other =>
      other !== loop &&
      other.body.has(loop.header) &&
      loop.body.size < other.body.size
    ).length + 1;

    return {
      ...loop,
      depth,
      classification: classifyNaturalLoop(loop, nodeMap),
    };
  });

  // Sort by depth (outermost first), then by header address
  loops.sort((a, b) => a.depth - b.depth || a.headerAddress - b.headerAddress);

  return loops;
}

/**
 * Organise natural loops into a nesting tree (outermost loops are roots;
 * inner loops are children of the smallest enclosing outer loop).
 */
export function buildLoopNestingTree(loops: NaturalLoop[]): LoopNestingNode[] {
  const nodes: LoopNestingNode[] = loops.map(l => ({ loop: l, children: [] }));
  const roots: LoopNestingNode[] = [];

  // For each loop, find its parent = smallest loop whose body strictly contains it
  for (const node of nodes) {
    const candidates = nodes.filter(other =>
      other !== node &&
      other.loop.body.has(node.loop.header) &&
      node.loop.body.size < other.loop.body.size
    );
    if (candidates.length === 0) {
      roots.push(node);
    } else {
      // Pick smallest enclosing loop (minimum body size)
      const parent = candidates.reduce((a, b) =>
        a.loop.body.size <= b.loop.body.size ? a : b
      );
      parent.children.push(node);
    }
  }

  return roots;
}

// ── DFS cycle detection (back-edge) ──────────────────────────────────────────

function findBackEdges(
  adjacency: Map<string, string[]>,
  entryId:   string,
): Set<string> {
  const visited = new Set<string>();
  const inStack = new Set<string>();
  const backEdgePairs = new Set<string>();

  function dfs(nodeId: string): void {
    visited.add(nodeId);
    inStack.add(nodeId);
    const neighbors = adjacency.get(nodeId) ?? [];
    for (const neighbor of neighbors) {
      if (!visited.has(neighbor)) {
        dfs(neighbor);
      } else if (inStack.has(neighbor)) {
        backEdgePairs.add(`${nodeId}->${neighbor}`);
      }
    }
    inStack.delete(nodeId);
  }

  dfs(entryId);
  return backEdgePairs;
}

function findReachable(
  adjacency: Map<string, string[]>,
  entryId:   string,
): Set<string> {
  const reachable = new Set<string>();
  const queue = [entryId];
  while (queue.length > 0) {
    const id = queue.pop()!;
    if (reachable.has(id)) continue;
    reachable.add(id);
    for (const next of adjacency.get(id) ?? []) {
      queue.push(next);
    }
  }
  return reachable;
}

// ── Main extraction ───────────────────────────────────────────────────────────

export function extractCfgSignals(cfg: CfgGraph): {
  patterns: SuspiciousPattern[];
  summary:  CfgAnalysisSummary;
} {
  const patterns: SuspiciousPattern[] = [];

  if (cfg.nodes.length === 0) {
    return {
      patterns,
      summary: {
        totalBlocks: 0, totalEdges: 0, indirectCalls: 0, backEdges: 0,
        unreachableBlocks: 0, jumpTables: 0, externalTargets: 0, complexityScore: 0,
        naturalLoops: [], maxNestingDepth: 0,
      },
    };
  }

  // Build adjacency map (all edges)
  const adjacency = new Map<string, string[]>();
  const outDegree  = new Map<string, number>();
  for (const node of cfg.nodes) {
    adjacency.set(node.id, []);
    outDegree.set(node.id, 0);
  }
  for (const edge of cfg.edges) {
    adjacency.get(edge.source)?.push(edge.target);
    outDegree.set(edge.source, (outDegree.get(edge.source) ?? 0) + 1);
  }

  // Locate entry node
  const entryNode = cfg.nodes.find(n => n.block_type === 'entry') ?? cfg.nodes[0];
  const entryId   = entryNode.id;

  // 1. Back-edges (loops)
  const backEdges = findBackEdges(adjacency, entryId);

  // 2. Reachability
  const reachable = findReachable(adjacency, entryId);

  // 3. Per-node analysis
  let indirectCalls    = 0;
  let jumpTables       = 0;
  let unreachableCount = 0;
  let externalTargets  = 0;

  const nodeMap = new Map<string, CfgNode>(cfg.nodes.map(n => [n.id, n]));

  for (const node of cfg.nodes) {
    const isReachable = reachable.has(node.id);

    // Unreachable block (excluding the entry)
    if (!isReachable && node.id !== entryId) {
      unreachableCount++;
      const addr = node.start ?? 0;
      patterns.push({
        address:     addr,
        type:        'obfuscation',
        severity:    'warning',
        description: `Unreachable CFG block at 0x${addr.toString(16).toUpperCase()} — possible dead code or anti-analysis trampoline`,
        relatedAddresses: node.end != null ? [node.end] : [],
      });
    }

    // External target (call to unknown external, unlabeled)
    if (node.block_type === 'external') {
      externalTargets++;
      if (!node.label) {
        // Unlabeled external = indirect dispatch
        const addr = node.start ?? 0;
        indirectCalls++;
        patterns.push({
          address:     addr,
          type:        'indirect_call',
          severity:    'warning',
          description: `CFG external block at 0x${addr.toString(16).toUpperCase()} with no resolved label — indirect dispatch`,
        });
      }
    }

    // Jump table: node with ≥4 outgoing branch edges
    const nodeOutEdges = cfg.edges.filter(
      e => e.source === node.id && e.kind === 'branch',
    );
    if (nodeOutEdges.length >= 4) {
      jumpTables++;
      const addr = node.start ?? 0;
      patterns.push({
        address:     addr,
        type:        'jump_table',
        severity:    'warning',
        description: `CFG block at 0x${addr.toString(16).toUpperCase()} has ${nodeOutEdges.length} branch targets — likely switch/jump table`,
        relatedAddresses: nodeOutEdges.map(e => {
          const t = nodeMap.get(e.target);
          return t?.start ?? 0;
        }).filter(a => a > 0),
      });
    }
  }

  // 4. Back-edge → tight_loop per pair
  for (const pair of backEdges) {
    const [src] = pair.split('->');
    const srcNode = nodeMap.get(src);
    const addr    = srcNode?.start ?? 0;
    indirectCalls; // intentional no-op; patterns below
    patterns.push({
      address:     addr,
      type:        'tight_loop',
      severity:    srcNode?.instruction_count != null && srcNode.instruction_count < 5
        ? 'critical'   // very tight loop
        : 'warning',
      description: `CFG back-edge at 0x${addr.toString(16).toUpperCase()} — loop detected (${srcNode?.instruction_count ?? '?'} instructions in block)`,
    });
  }

  // 5. Call edges to external nodes with no label → indirect calls
  const callEdgesToExternal = cfg.edges.filter(e => {
    if (e.kind !== 'call') return false;
    const target = nodeMap.get(e.target);
    return target?.block_type === 'external' && !target.label;
  });
  for (const edge of callEdgesToExternal) {
    const srcNode = nodeMap.get(edge.source);
    const addr    = srcNode?.start ?? 0;
    if (!patterns.some(p => p.address === addr && p.type === 'indirect_call')) {
      indirectCalls++;
      patterns.push({
        address:     addr,
        type:        'indirect_call',
        severity:    'warning',
        description: `Call at 0x${addr.toString(16).toUpperCase()} to unresolved external — indirect call pattern`,
      });
    }
  }

  // 6. Opaque predicate: block with 2 conditional successors where both targets
  //    have the same immediate post-dominator (join at the very next node).
  //    This means the branch never actually diverges — one path is dead.
  const nodeSuccMap = new Map<string, string[]>();
  for (const edge of cfg.edges) {
    const list = nodeSuccMap.get(edge.source) ?? [];
    list.push(edge.target);
    nodeSuccMap.set(edge.source, list);
  }
  for (const node of cfg.nodes) {
    const succs = nodeSuccMap.get(node.id) ?? [];
    if (succs.length !== 2) continue;
    // If both successors have the same set of forward successors, it's opaque
    const [s1, s2] = succs;
    const s1Succs = (nodeSuccMap.get(s1) ?? []).sort().join(',');
    const s2Succs = (nodeSuccMap.get(s2) ?? []).sort().join(',');
    if (s1Succs === s2Succs && s1Succs.length > 0) {
      const addr = node.start ?? 0;
      patterns.push({
        address:     addr,
        type:        'opaque_predicate',
        severity:    'warning',
        description: `Opaque predicate at 0x${addr.toString(16).toUpperCase()} — both branch targets converge immediately, one path is never taken`,
      });
    }
  }

  // 7. Flattened control flow / dispatcher: block with ≥6 branch targets and
  //    small instruction count — classic control-flow flattening dispatcher hub.
  for (const node of cfg.nodes) {
    const branchEdges = cfg.edges.filter(
      e => e.source === node.id && e.kind === 'branch',
    );
    const instrCount = node.instruction_count ?? 0;
    if (branchEdges.length >= 6 && instrCount <= 5) {
      const addr = node.start ?? 0;
      patterns.push({
        address:     addr,
        type:        'flattened_cf',
        severity:    'critical',
        description: `Dispatcher block at 0x${addr.toString(16).toUpperCase()} — ${branchEdges.length} branch targets with only ${instrCount} instruction(s) — probable control-flow flattening`,
        relatedAddresses: branchEdges.map(e => {
          const t = nodeMap.get(e.target);
          return t?.start ?? 0;
        }).filter(a => a > 0),
      });
    }
  }

  // 8. Anti-tamper: block that both reads a code-section region AND contains a
  //    conditional branch — suggests a CRC/hash integrity check pattern.
  //    Heuristic: node with ≥2 successors whose block_type is NOT 'loop'
  //    and whose label contains 'crc', 'hash', 'check', 'verify', 'guard'.
  for (const node of cfg.nodes) {
    if (!node.label) continue;
    const lbl = node.label.toLowerCase();
    if (
      (lbl.includes('crc') || lbl.includes('hash') || lbl.includes('check') ||
       lbl.includes('verify') || lbl.includes('guard') || lbl.includes('integrity')) &&
      (nodeSuccMap.get(node.id) ?? []).length >= 2
    ) {
      const addr = node.start ?? 0;
      patterns.push({
        address:     addr,
        type:        'anti_tamper',
        severity:    'critical',
        description: `Anti-tamper check at 0x${addr.toString(16).toUpperCase()} — block labelled '${node.label}' with conditional branch suggests integrity verification`,
      });
    }
  }

  // 9. Self-modifying code: block that both writes to an address that overlaps
  //    with a code-segment region. Detected by the presence of external nodes
  //    whose label includes known SMC APIs (VirtualProtect + write combo).
  const externalLabels = cfg.nodes
    .filter(n => n.block_type === 'external' && n.label)
    .map(n => n.label!.toLowerCase());
  const hasSMCWrite = externalLabels.some(l =>
    l.includes('virtualprotect') || l.includes('writeprocessmemory'),
  );
  const hasCodeAlloc = externalLabels.some(l =>
    l.includes('virtualalloc') || l.includes('mmap') || l.includes('mprotect'),
  );
  if (hasSMCWrite && hasCodeAlloc) {
    const smcNode = cfg.nodes.find(n =>
      n.block_type === 'external' && n.label &&
      (n.label.toLowerCase().includes('virtualprotect') ||
       n.label.toLowerCase().includes('writeprocessmemory')),
    );
    const addr = smcNode?.start ?? 0;
    patterns.push({
      address:     addr,
      type:        'self_modifying',
      severity:    'critical',
      description: `Self-modifying code indicators detected — VirtualProtect/WriteProcessMemory + allocation API combination suggests runtime code patching`,
    });
  }

  // ── Complexity score ─────────────────────────────────────────────────────────
  // Range 0–100; factors: nodes, back-edges, indirect calls, unreachable blocks
  const nodeScore    = Math.min(30, cfg.nodes.length * 0.5);
  const loopScore    = Math.min(25, backEdges.size * 5);
  const callScore    = Math.min(20, indirectCalls * 5);
  const unreachScore = Math.min(15, unreachableCount * 5);
  const jtScore      = Math.min(10, jumpTables * 3);
  const complexityScore = Math.round(nodeScore + loopScore + callScore + unreachScore + jtScore);

  // Natural loop detection
  const naturalLoops = computeNaturalLoops(cfg);
  const maxNestingDepth = naturalLoops.reduce((max, l) => Math.max(max, l.depth), 0);

  return {
    patterns,
    summary: {
      totalBlocks:      cfg.nodes.length,
      totalEdges:       cfg.edges.length,
      indirectCalls:    indirectCalls + callEdgesToExternal.length,
      backEdges:        backEdges.size,
      unreachableBlocks: unreachableCount,
      jumpTables,
      externalTargets,
      complexityScore,
      naturalLoops,
      maxNestingDepth,
    },
  };
}

// ── Dominator tree from CFG ──────────────────────────────────────────────────

/**
 * Build forward and post-dominator trees directly from a CfgGraph.
 *
 * Uses the Cooper, Harvey & Kennedy (2001) iterative algorithm — the same
 * algorithm as ssaTransform.ts — but operates on CfgGraph edges so that a
 * full IR decompilation is not required.
 *
 * RE concepts exposed:
 *   - dominator:          every path from entry to B passes through D → D dom B
 *   - immediate dominator: closest strict dominator of B
 *   - post-dominator:     every path from B to exit passes through P → P pdom B
 *   - dominator tree:     idom relationships visualised as a tree
 *   - dominance frontier: DF(B) = set of join points at the boundary of B's dominance
 */
export function buildDomTreeFromCfg(cfg: CfgGraph): {
  domTree: DomTree;
  postDomTree: DomTree;
} {
  const nodeIds = cfg.nodes.map(n => n.id);
  const entryId = (cfg.nodes.find(n => n.block_type === 'entry') ?? cfg.nodes[0])?.id ?? '';

  // Build forward adjacency & predecessor maps
  const successors   = new Map<string, string[]>();
  const predecessors = new Map<string, string[]>();
  for (const id of nodeIds) { successors.set(id, []); predecessors.set(id, []); }
  for (const e of cfg.edges) {
    successors.get(e.source)?.push(e.target);
    if (!predecessors.has(e.target)) predecessors.set(e.target, []);
    predecessors.get(e.target)!.push(e.source);
  }

  // Reverse adjacency for post-dominator computation.
  // Post-dom = dominator in the REVERSED graph, starting from a virtual exit.
  // In the reversed graph:
  //   - original edge A→B becomes reversed edge B→A  (revSuccessors[B] includes A)
  //   - virtual exit VE acts as the new "entry"; VE→exitNode for each real exit
  const exitIds = cfg.nodes
    .filter(n => n.block_type === 'external' || (successors.get(n.id)?.length === 0))
    .map(n => n.id);
  const VIRTUAL_EXIT = '__dom_virtual_exit__';
  const revSuccessors   = new Map<string, string[]>();
  const revPredecessors = new Map<string, string[]>();
  for (const id of [...nodeIds, VIRTUAL_EXIT]) { revSuccessors.set(id, []); revPredecessors.set(id, []); }
  // Reverse all original edges: A→B becomes B→A in reversed graph
  for (const e of cfg.edges) {
    revSuccessors.get(e.target)?.push(e.source);    // B→A: B's succ is A
    revPredecessors.get(e.source)?.push(e.target);  // A's pred is B
  }
  // Add virtual exit edges: VE→exitNode in reversed graph
  // (corresponds to original exitNode→VE which we add conceptually)
  for (const exitId of exitIds) {
    revSuccessors.get(VIRTUAL_EXIT)?.push(exitId);  // VE can reach exit nodes
    revPredecessors.get(exitId)?.push(VIRTUAL_EXIT); // exit nodes have VE as predecessor
  }

  /**
   * Core iterative dominator computation (Cooper et al.).
   * @param entryId   start node for this graph direction
   * @param succMap   adjacency (forward or reverse)
   * @param predMap   predecessor map (forward or reverse)
   * @param allIds    all node IDs to process
   */
  function computeIdom(
    startId: string,
    succMap: Map<string, string[]>,
    predMap: Map<string, string[]>,
    allIds: string[],
  ): DomTree {
    // RPO via iterative DFS (avoids stack overflow on large CFGs)
    const rpo: string[] = [];
    const visited = new Set<string>();
    const stack = [startId];
    const postOrder: string[] = [];
    const onStack = new Set<string>();
    const iterStack: Array<{ id: string; childIdx: number }> = [{ id: startId, childIdx: 0 }];
    visited.add(startId);
    while (iterStack.length > 0) {
      const frame = iterStack[iterStack.length - 1];
      const children = succMap.get(frame.id) ?? [];
      if (frame.childIdx < children.length) {
        const child = children[frame.childIdx++];
        if (!visited.has(child)) {
          visited.add(child);
          iterStack.push({ id: child, childIdx: 0 });
        }
      } else {
        postOrder.push(frame.id);
        iterStack.pop();
      }
    }
    for (let i = postOrder.length - 1; i >= 0; i--) rpo.push(postOrder[i]);
    const rpoIdx = new Map<string, number>();
    rpo.forEach((id, i) => rpoIdx.set(id, i));

    // Cooper et al. intersect
    const idom = new Map<string, string | null>();
    idom.set(startId, null);
    const intersect = (b1: string, b2: string): string => {
      let f = b1, g = b2;
      while (f !== g) {
        while ((rpoIdx.get(f) ?? Infinity) > (rpoIdx.get(g) ?? Infinity)) {
          f = idom.get(f) ?? f;
        }
        while ((rpoIdx.get(g) ?? Infinity) > (rpoIdx.get(f) ?? Infinity)) {
          g = idom.get(g) ?? g;
        }
      }
      return f;
    };
    let changed = true;
    while (changed) {
      changed = false;
      for (const b of rpo) {
        if (b === startId) continue;
        const preds = (predMap.get(b) ?? []).filter(p => idom.has(p));
        if (preds.length === 0) continue;
        let newIdom = preds[0];
        for (const p of preds.slice(1)) newIdom = intersect(p, newIdom);
        if (idom.get(b) !== newIdom) { idom.set(b, newIdom); changed = true; }
      }
    }

    // Children map
    const children = new Map<string, string[]>();
    for (const id of allIds) children.set(id, []);
    for (const [id, dom] of idom) {
      if (dom !== null && children.has(dom)) children.get(dom)!.push(id);
    }

    // Dominance frontier
    const df = new Map<string, Set<string>>();
    for (const id of allIds) df.set(id, new Set());
    for (const b of allIds) {
      const preds = predMap.get(b) ?? [];
      if (preds.length < 2) continue;
      for (const p of preds) {
        let runner = p;
        const bIdom = idom.get(b);
        while (runner !== bIdom && runner !== null && idom.has(runner)) {
          df.get(runner)?.add(b);
          const next = idom.get(runner);
          if (next === runner || next === undefined) break;
          runner = next ?? runner;
        }
      }
    }

    return { idom, children, df, rpo: rpo.filter(id => allIds.includes(id)) };
  }

  const domTree     = computeIdom(entryId, successors, predecessors, nodeIds);
  const revAllIds   = [...nodeIds, VIRTUAL_EXIT];
  const postDomFull = computeIdom(VIRTUAL_EXIT, revSuccessors, revPredecessors, revAllIds);

  // Strip the virtual exit node from the post-dom tree output
  postDomFull.idom.delete(VIRTUAL_EXIT);
  postDomFull.children.delete(VIRTUAL_EXIT);
  postDomFull.df.delete(VIRTUAL_EXIT);
  const postDomTree: DomTree = {
    idom:     postDomFull.idom,
    children: new Map([...postDomFull.children].filter(([id]) => id !== VIRTUAL_EXIT)),
    df:       postDomFull.df,
    rpo:      postDomFull.rpo.filter(id => id !== VIRTUAL_EXIT),
  };
  // Fix roots: nodes whose idom was the virtual exit should now be null
  for (const [id, dom] of postDomTree.idom) {
    if (dom === VIRTUAL_EXIT) postDomTree.idom.set(id, null);
  }

  return { domTree, postDomTree };
}
