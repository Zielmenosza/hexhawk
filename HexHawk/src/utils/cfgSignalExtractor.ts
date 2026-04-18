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

  // ── Complexity score ─────────────────────────────────────────────────────────
  // Range 0–100; factors: nodes, back-edges, indirect calls, unreachable blocks
  const nodeScore    = Math.min(30, cfg.nodes.length * 0.5);
  const loopScore    = Math.min(25, backEdges.size * 5);
  const callScore    = Math.min(20, indirectCalls * 5);
  const unreachScore = Math.min(15, unreachableCount * 5);
  const jtScore      = Math.min(10, jumpTables * 3);
  const complexityScore = Math.round(nodeScore + loopScore + callScore + unreachScore + jtScore);

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
    },
  };
}
