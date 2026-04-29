/**
 * CallGraphPanel.tsx — SVG-based inter-function call graph.
 *
 * Renders a force-directed or hierarchical call graph from the detected
 * `FunctionMetadata` map.  Each node is a detected function; each edge is a
 * direct call.  Recursive functions show a self-loop indicator.
 *
 * Pro-tier feature.
 */

import React, { useMemo, useRef, useState, useCallback } from 'react';
import type { FunctionMetadata } from '../App';

// ─── Types ────────────────────────────────────────────────────────────────────

interface CallGraphPanelProps {
  functions: Map<number, FunctionMetadata>;
  /** Address of the currently selected function (highlighted node). */
  selectedFunction: number | null;
  onFunctionSelect: (address: number) => void;
}

interface GraphNode {
  id: number;
  label: string;
  x: number;
  y: number;
  isRecursive: boolean;
  isSelected: boolean;
  complexity: number;
}

interface GraphEdge {
  source: number;
  target: number;
}

// ─── Layout helpers ───────────────────────────────────────────────────────────

const W = 800;
const H = 560;
const NODE_R = 22;

/** Deterministic spring-relaxation layout (single pass, no animation). */
function buildLayout(
  functions: Map<number, FunctionMetadata>,
  selected: number | null,
): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const addrs = Array.from(functions.keys());
  if (addrs.length === 0) return { nodes: [], edges: [] };

  // Cap the graph at 80 nodes for readability
  const cappedAddrs = addrs.slice(0, 80);
  const cappedSet = new Set(cappedAddrs);

  // Build edges from incomingCalls (caller → callee)
  const edges: GraphEdge[] = [];
  for (const addr of cappedAddrs) {
    const meta = functions.get(addr)!;
    for (const caller of meta.incomingCalls) {
      if (cappedSet.has(caller) && caller !== addr) {
        edges.push({ source: caller, target: addr });
      }
    }
  }

  // Simple circular layout as starting positions
  const positions = new Map<number, { x: number; y: number }>();
  const cx = W / 2;
  const cy = H / 2;
  const radius = Math.min(cx, cy) - 60;
  cappedAddrs.forEach((addr, i) => {
    const angle = (2 * Math.PI * i) / cappedAddrs.length;
    positions.set(addr, {
      x: cx + radius * Math.cos(angle),
      y: cy + radius * Math.sin(angle),
    });
  });

  // 30 iterations of force-directed relaxation
  const K = 80;   // spring rest length
  const REPULSION = 4000;
  for (let iter = 0; iter < 30; iter++) {
    const forces = new Map<number, { fx: number; fy: number }>();
    for (const addr of cappedAddrs) forces.set(addr, { fx: 0, fy: 0 });

    // Repulsion between all pairs
    for (let i = 0; i < cappedAddrs.length; i++) {
      for (let j = i + 1; j < cappedAddrs.length; j++) {
        const a = cappedAddrs[i];
        const b = cappedAddrs[j];
        const pa = positions.get(a)!;
        const pb = positions.get(b)!;
        const dx = pa.x - pb.x || 0.1;
        const dy = pa.y - pb.y || 0.1;
        const dist2 = dx * dx + dy * dy;
        const dist = Math.sqrt(dist2) || 1;
        const force = REPULSION / dist2;
        forces.get(a)!.fx += force * (dx / dist);
        forces.get(a)!.fy += force * (dy / dist);
        forces.get(b)!.fx -= force * (dx / dist);
        forces.get(b)!.fy -= force * (dy / dist);
      }
    }

    // Attraction along edges
    for (const { source, target } of edges) {
      const ps = positions.get(source);
      const pt = positions.get(target);
      if (!ps || !pt) continue;
      const dx = pt.x - ps.x;
      const dy = pt.y - ps.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const spring = (dist - K) * 0.05;
      forces.get(source)!.fx += spring * (dx / dist);
      forces.get(source)!.fy += spring * (dy / dist);
      forces.get(target)!.fx -= spring * (dx / dist);
      forces.get(target)!.fy -= spring * (dy / dist);
    }

    // Center attraction
    for (const addr of cappedAddrs) {
      const p = positions.get(addr)!;
      forces.get(addr)!.fx += (cx - p.x) * 0.01;
      forces.get(addr)!.fy += (cy - p.y) * 0.01;
    }

    // Apply forces (with damping + boundary clamping)
    for (const addr of cappedAddrs) {
      const p = positions.get(addr)!;
      const f = forces.get(addr)!;
      const newX = Math.max(NODE_R + 4, Math.min(W - NODE_R - 4, p.x + Math.sign(f.fx) * Math.min(Math.abs(f.fx), 12)));
      const newY = Math.max(NODE_R + 4, Math.min(H - NODE_R - 4, p.y + Math.sign(f.fy) * Math.min(Math.abs(f.fy), 12)));
      positions.set(addr, { x: newX, y: newY });
    }
  }

  const nodes: GraphNode[] = cappedAddrs.map(addr => {
    const meta = functions.get(addr)!;
    const p = positions.get(addr)!;
    return {
      id: addr,
      label: `0x${addr.toString(16).toUpperCase()}`,
      x: p.x,
      y: p.y,
      isRecursive: meta.isRecursive,
      isSelected: addr === selected,
      complexity: meta.complexity,
    };
  });

  return { nodes, edges };
}

// ─── Component ────────────────────────────────────────────────────────────────

function nodeColor(node: GraphNode): string {
  if (node.isSelected)   return '#4fc3f7';
  if (node.isRecursive)  return '#ff9800';
  if (node.complexity >= 8) return '#f44336';
  if (node.complexity >= 5) return '#ffd54f';
  return '#81c784';
}

const CallGraphPanel: React.FC<CallGraphPanelProps> = React.memo(({
  functions,
  selectedFunction,
  onFunctionSelect,
}) => {
  const [tooltip, setTooltip] = useState<{ x: number; y: number; addr: number } | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  const { nodes, edges } = useMemo(
    () => buildLayout(functions, selectedFunction),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [functions, selectedFunction],
  );

  const nodeMap = useMemo(() => {
    const m = new Map<number, GraphNode>();
    for (const n of nodes) m.set(n.id, n);
    return m;
  }, [nodes]);

  const handleNodeClick = useCallback((addr: number) => {
    onFunctionSelect(addr);
  }, [onFunctionSelect]);

  if (functions.size === 0) {
    return (
      <div className="callgraph-empty">
        <div className="callgraph-empty-icon">🕸</div>
        <div>Disassemble the binary to populate the call graph.</div>
      </div>
    );
  }

  return (
    <div className="callgraph-panel">
      <div className="callgraph-toolbar">
        <span className="callgraph-title">Call Graph</span>
        <span className="callgraph-meta">
          {nodes.length} functions · {edges.length} calls
          {functions.size > 80 ? ` (showing first 80 of ${functions.size})` : ''}
        </span>
        <span className="callgraph-legend">
          <span className="legend-dot" style={{ background: '#81c784' }} /> Simple
          <span className="legend-dot" style={{ background: '#ffd54f' }} /> Medium
          <span className="legend-dot" style={{ background: '#f44336' }} /> Complex
          <span className="legend-dot" style={{ background: '#ff9800' }} /> Recursive
        </span>
      </div>

      <svg
        ref={svgRef}
        viewBox={`0 0 ${W} ${H}`}
        width="100%"
        style={{ display: 'block', cursor: 'default' }}
        onMouseLeave={() => setTooltip(null)}
      >
        <defs>
          <marker
            id="arrowhead"
            markerWidth="7"
            markerHeight="5"
            refX="6"
            refY="2.5"
            orient="auto"
          >
            <polygon points="0 0, 7 2.5, 0 5" fill="#555" />
          </marker>
        </defs>

        {/* Edges */}
        {edges.map((edge, i) => {
          const src = nodeMap.get(edge.source);
          const tgt = nodeMap.get(edge.target);
          if (!src || !tgt) return null;
          const dx = tgt.x - src.x;
          const dy = tgt.y - src.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          // Trim line to node boundary
          const x1 = src.x + (dx / dist) * (NODE_R + 2);
          const y1 = src.y + (dy / dist) * (NODE_R + 2);
          const x2 = tgt.x - (dx / dist) * (NODE_R + 4);
          const y2 = tgt.y - (dy / dist) * (NODE_R + 4);
          return (
            <line
              key={i}
              x1={x1} y1={y1}
              x2={x2} y2={y2}
              stroke="#555"
              strokeWidth={1.2}
              markerEnd="url(#arrowhead)"
              opacity={0.65}
            />
          );
        })}

        {/* Nodes */}
        {nodes.map(node => (
          <g
            key={node.id}
            transform={`translate(${node.x},${node.y})`}
            style={{ cursor: 'pointer' }}
            onClick={() => handleNodeClick(node.id)}
            onMouseEnter={() => setTooltip({ x: node.x, y: node.y, addr: node.id })}
            onMouseLeave={() => setTooltip(null)}
          >
            {/* Recursive self-loop indicator */}
            {node.isRecursive && (
              <ellipse
                cx={NODE_R - 4}
                cy={-(NODE_R - 4)}
                rx={10}
                ry={7}
                fill="none"
                stroke="#ff9800"
                strokeWidth={1.5}
              />
            )}

            <circle
              r={NODE_R}
              fill={nodeColor(node)}
              stroke={node.isSelected ? '#fff' : '#222'}
              strokeWidth={node.isSelected ? 2.5 : 1}
              opacity={0.9}
            />
            <text
              textAnchor="middle"
              dominantBaseline="middle"
              fontSize={9}
              fill="#111"
              fontFamily="monospace"
              pointerEvents="none"
            >
              {node.label.slice(-6)}
            </text>
          </g>
        ))}

        {/* Tooltip */}
        {tooltip && (() => {
          const meta = functions.get(tooltip.addr);
          if (!meta) return null;
          const tx = Math.min(tooltip.x + 10, W - 160);
          const ty = Math.max(tooltip.y - 60, 4);
          return (
            <g transform={`translate(${tx},${ty})`} pointerEvents="none">
              <rect x={0} y={0} width={165} height={80} rx={4} fill="#1e1e1e" opacity={0.92} />
              <text x={6} y={14} fontSize={9} fill="#4fc3f7" fontFamily="monospace">
                {`0x${tooltip.addr.toString(16).toUpperCase().padStart(8, '0')}`}
              </text>
              <text x={6} y={27} fontSize={9} fill="#ccc" fontFamily="sans-serif">
                {`Callers: ${meta.incomingCalls.size} · Calls out: ${meta.callCount}`}
              </text>
              <text x={6} y={40} fontSize={9} fill="#ccc" fontFamily="sans-serif">
                {`Size: ${meta.size}B · CC: ${meta.complexity}`}
                {meta.isRecursive ? ' · recursive' : ''}
              </text>
              <text x={6} y={52} fontSize={9} fill="#aaa" fontFamily="sans-serif">
                {meta.callingConvention ?? 'unknown calling conv'}
              </text>
              <text x={6} y={64} fontSize={9} fill="#aaa" fontFamily="sans-serif">
                {[
                  meta.isThunk ? 'thunk' : null,
                  meta.prologueType === 'leaf' ? 'leaf' : null,
                  meta.hasTailCall ? 'tail-call' : null,
                ].filter(Boolean).join(' · ') || (meta.prologueType ?? '')}
              </text>
              <text x={6} y={76} fontSize={9} fill="#777" fontFamily="sans-serif">
                {`call site: 0x${tooltip.addr.toString(16).toUpperCase()}`}
              </text>
            </g>
          );
        })()}
      </svg>

      {/* Caller / Callee panel for the selected function */}
      {selectedFunction !== null && (() => {
        const meta = functions.get(selectedFunction);
        if (!meta) return null;
        // Callers: functions whose address appears in meta.incomingCalls
        const callers = Array.from(meta.incomingCalls).map(addr => ({
          addr,
          meta: functions.get(addr),
        }));
        // Callees: functions that list selectedFunction in their incomingCalls
        const callees: Array<{ addr: number; meta: FunctionMetadata | undefined }> = [];
        for (const [addr, fm] of functions) {
          if (fm.incomingCalls.has(selectedFunction) && addr !== selectedFunction) {
            callees.push({ addr, meta: fm });
          }
        }
        return (
          <div style={{ display: 'flex', gap: '1rem', padding: '0.5rem 0.75rem', borderTop: '1px solid #333', fontSize: '0.75rem', color: '#ccc' }}>
            <div style={{ flex: 1 }}>
              <div style={{ color: '#4fc3f7', fontWeight: 'bold', marginBottom: '0.25rem' }}>
                Callers ({callers.length})
              </div>
              {callers.length === 0
                ? <span style={{ color: '#666' }}>none</span>
                : callers.slice(0, 8).map(({ addr }) => (
                    <div
                      key={addr}
                      style={{ cursor: 'pointer', color: '#aaa', padding: '1px 0' }}
                      onClick={() => onFunctionSelect(addr)}
                    >
                      {`0x${addr.toString(16).toUpperCase().padStart(8, '0')}`}
                    </div>
                  ))
              }
              {callers.length > 8 && <div style={{ color: '#666' }}>+{callers.length - 8} more</div>}
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ color: '#81c784', fontWeight: 'bold', marginBottom: '0.25rem' }}>
                Callees ({callees.length})
              </div>
              {callees.length === 0
                ? <span style={{ color: '#666' }}>none</span>
                : callees.slice(0, 8).map(({ addr }) => (
                    <div
                      key={addr}
                      style={{ cursor: 'pointer', color: '#aaa', padding: '1px 0' }}
                      onClick={() => onFunctionSelect(addr)}
                    >
                      {`0x${addr.toString(16).toUpperCase().padStart(8, '0')}`}
                    </div>
                  ))
              }
              {callees.length > 8 && <div style={{ color: '#666' }}>+{callees.length - 8} more</div>}
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ color: '#ffb74d', fontWeight: 'bold', marginBottom: '0.25rem' }}>
                Properties
              </div>
              <div>Conv: {meta.callingConvention ?? 'unknown'}</div>
              <div>Size: {meta.size}B</div>
              <div>Complexity: {meta.complexity}</div>
              {meta.isThunk && <div style={{ color: '#79c0ff' }}>Thunk → {meta.thunkTarget !== undefined ? `0x${meta.thunkTarget.toString(16).toUpperCase()}` : '?'}</div>}
              {meta.prologueType === 'leaf' && <div style={{ color: '#00e5cc' }}>Leaf function</div>}
              {meta.hasTailCall && <div style={{ color: '#ff8a65' }}>Has tail call</div>}
              {meta.isRecursive && <div style={{ color: '#ff9800' }}>Recursive</div>}
            </div>
          </div>
        );
      })()}
    </div>
  );
});

CallGraphPanel.displayName = 'CallGraphPanel';

export default CallGraphPanel;
