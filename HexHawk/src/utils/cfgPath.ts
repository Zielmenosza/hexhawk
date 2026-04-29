import type { CfgGraph } from './cfgSignalExtractor';

/**
 * Return all block IDs that lie on at least one directed path from `startId` to `endId`.
 *
 * This is computed as intersection of:
 * - nodes reachable from start in the forward graph
 * - nodes that can reach end (reachable from end in the reversed graph)
 */
export function findPathNodesAnyRoute(
  cfg: CfgGraph,
  startId: string,
  endId: string,
): Set<string> {
  if (!startId || !endId) return new Set();
  if (cfg.nodes.length === 0) return new Set();

  const nodeIds = new Set(cfg.nodes.map(n => n.id));
  if (!nodeIds.has(startId) || !nodeIds.has(endId)) return new Set();

  const succ = new Map<string, string[]>();
  const pred = new Map<string, string[]>();
  for (const id of nodeIds) {
    succ.set(id, []);
    pred.set(id, []);
  }

  for (const e of cfg.edges) {
    if (!nodeIds.has(e.source) || !nodeIds.has(e.target)) continue;
    succ.get(e.source)?.push(e.target);
    pred.get(e.target)?.push(e.source);
  }

  const reachableFromStart = bfs(startId, succ);
  if (!reachableFromStart.has(endId)) {
    return new Set();
  }

  const canReachEnd = bfs(endId, pred);

  const onPath = new Set<string>();
  for (const id of reachableFromStart) {
    if (canReachEnd.has(id)) onPath.add(id);
  }
  return onPath;
}

function bfs(root: string, adjacency: Map<string, string[]>): Set<string> {
  const visited = new Set<string>();
  const queue: string[] = [root];

  while (queue.length > 0) {
    const id = queue.shift()!;
    if (visited.has(id)) continue;
    visited.add(id);

    for (const nxt of adjacency.get(id) ?? []) {
      if (!visited.has(nxt)) queue.push(nxt);
    }
  }

  return visited;
}
