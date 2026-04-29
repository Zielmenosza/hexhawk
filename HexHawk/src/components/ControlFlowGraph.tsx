import React, { useCallback, useMemo } from 'react';
import ReactFlow, { Background, Controls, Edge, MiniMap, Node } from 'reactflow';
import 'reactflow/dist/style.css';

interface GraphNode {
  id: string;
  address?: number;
  size?: number;
  label?: string;
  start?: number;
  end?: number;
  instruction_count?: number;
  block_type?: string;  // "entry", "target", "external"
  layout_x?: number;
  layout_y?: number;
}

interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type?: string;
  kind?: string;
  condition?: string;  // "conditional", "unconditional"
}

interface ControlFlowGraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

interface Props {
  graph: ControlFlowGraphData;
  onNodeClick?: (node: GraphNode) => void;
  highlightedBlockId?: string | null;
  /** Edge keys ("sourceId\x00targetId") that are loop back-edges. */
  backEdgeKeys?: Set<string>;
  /** Block IDs that are loop header blocks. */
  loopHeaders?: Set<string>;
  /** Map from block ID to its innermost loop nesting depth (1 = outermost). */
  loopBodies?: Map<string, number>;
  /** Block IDs classified as exit/external blocks. */
  exitBlocks?: Set<string>;
  /** Block IDs identified as CFF dispatcher nodes (≥6 branch targets, ≤5 instructions). */
  dispatcherBlocks?: Set<string>;
  /** Block IDs on selected execution path(s) from start to end. */
  pathNodes?: Set<string>;
}

export function ControlFlowGraph({
  graph,
  onNodeClick,
  highlightedBlockId,
  backEdgeKeys,
  loopHeaders,
  loopBodies,
  exitBlocks,
  dispatcherBlocks,
  pathNodes,
}: Props) {
  // Build a map of node id → incoming edge count for metrics display
  const inDegree = useMemo(() => {
    const map = new Map<string, number>();
    for (const e of graph.edges) {
      map.set(e.target, (map.get(e.target) ?? 0) + 1);
    }
    return map;
  }, [graph.edges]);

  const nodeList: Node[] = graph.nodes.map((node, index) => {
    const isExternal = node.block_type === 'external';
    const isEntry = node.block_type === 'entry';
    const isHighlighted = node.id === highlightedBlockId;
    const pathModeActive = pathNodes !== undefined;
    const isOnPath = pathNodes?.has(node.id) ?? false;
    const isDispatcher = dispatcherBlocks?.has(node.id) ?? false;
    const isLoopHeader = loopHeaders?.has(node.id) ?? false;
    const isExitBlock = exitBlocks?.has(node.id) ?? false;
    const loopDepth = loopBodies?.get(node.id) ?? 0;
    const isLoopBody = loopDepth > 0 && !isLoopHeader;

    let color: string;
    let bgColor: string;
    let boxShadow = 'none';

    if (isHighlighted) {
      color = '#00ff00';
      bgColor = 'rgba(0, 200, 100, 0.5)';
      boxShadow = '0 0 20px rgba(0, 255, 0, 0.6)';
    } else if (pathModeActive && isOnPath) {
      color = '#ffcf66';
      bgColor = 'rgba(160, 110, 0, 0.45)';
      boxShadow = '0 0 12px rgba(255, 207, 102, 0.4)';
    } else if (isDispatcher) {
      // CFF dispatcher hub: amber/orange to signal control-flow flattening
      color = '#ffb347';
      bgColor = 'rgba(180, 90, 0, 0.45)';
      boxShadow = '0 0 12px rgba(255, 160, 0, 0.5)';
    } else if (isLoopHeader) {
      color = '#00e5cc';
      bgColor = 'rgba(0, 150, 120, 0.45)';
      boxShadow = '0 0 10px rgba(0, 229, 204, 0.4)';
    } else if (isLoopBody) {
      const alpha = Math.min(0.15 + loopDepth * 0.1, 0.45);
      color = '#00bfa5';
      bgColor = `rgba(0, 100, 90, ${alpha})`;
    } else if (isExitBlock) {
      // True exit block: no outgoing edges (ret/syscall ending block)
      color = '#9c6aff';
      bgColor = 'rgba(70, 30, 120, 0.5)';
    } else if (isExternal) {
      // External target: jump/call to address outside the analyzed range
      color = '#7a7a9a';
      bgColor = 'rgba(40, 40, 70, 0.5)';
    } else if (isEntry) {
      color = '#00ff00';
      bgColor = 'rgba(0, 100, 0, 0.3)';
    } else {
      color = '#00d4ff';
      bgColor = 'rgba(0, 100, 150, 0.3)';
    }

    // Use layout coordinates from backend if available
    const x = node.layout_x ?? (index % 5) * 280;
    const y = node.layout_y ?? Math.floor(index / 5) * 180;

    // Build rich label: id + address range + instruction count + in-degree + loop/exit markers
    const instrCount = node.instruction_count ?? 0;
    const incoming = inDegree.get(node.id) ?? 0;
    const addrLine = node.start !== undefined
      ? `0x${node.start.toString(16).toUpperCase()}${node.end !== undefined ? `–0x${node.end.toString(16).toUpperCase()}` : ''}`
      : '';
    const metricLine = instrCount > 0
      ? `${instrCount} instr${incoming > 0 ? ` · ${incoming} in` : ''}`
      : '';
    const typeMarkers: string[] = [];
    if (isEntry) typeMarkers.push('[ENTRY]');
    if (isExitBlock) typeMarkers.push('[EXIT]');      // block with no outgoing edges
    if (isExternal) typeMarkers.push('[EXT]');        // external call/jump target
    if (pathModeActive && isOnPath) typeMarkers.push('[PATH]');
    if (isLoopHeader) typeMarkers.push('[LOOP HDR]');
    if (isDispatcher) typeMarkers.push('[DISPATCHER]'); // CFF dispatcher hub
    const typeLine = typeMarkers.join(' ');
    const labelParts = [node.label || node.id, addrLine, metricLine, typeLine].filter(Boolean);

    return {
      id: node.id,
      position: { x, y },
      data: { label: labelParts.join('\n') },
      style: {
        border: `2px solid ${color}`,
        background: bgColor,
        color: '#fff',
        padding: 10,
        minWidth: 170,
        textAlign: 'center' as const,
        fontSize: '11px',
        borderRadius: '8px',
        cursor: onNodeClick ? 'pointer' : 'default',
        fontFamily: 'monospace',
        whiteSpace: 'pre-wrap' as const,
        boxShadow,
        transition: 'all 0.2s ease',
        lineHeight: '1.4',
        opacity: pathModeActive ? (isOnPath ? 1 : 0.35) : 1,
      },
    };
  });

  const edgeList: Edge[] = graph.edges.map((edge, idx) => {
    const pathModeActive = pathNodes !== undefined;
    const edgeOnPath = (pathNodes?.has(edge.source) ?? false) && (pathNodes?.has(edge.target) ?? false);
    const isBranch = (edge.kind ?? edge.type) === 'branch';
    const isConditional = edge.condition === 'conditional';
    const isFallthrough = (edge.kind ?? edge.type) === 'fallthrough';
    const isBackEdge = backEdgeKeys?.has(`${edge.source}\x00${edge.target}`) ?? false;

    let strokeColor = '#7aaaff';
    let strokeWidth = 2;
    let animated = false;
    let label = '';
    let strokeDasharray: string | undefined;

    if (isBackEdge) {
      strokeColor = '#ff6b6b';
      strokeWidth = 2;
      strokeDasharray = '6 3';
      animated = true;
      label = 'BACK';
    } else if (isBranch) {
      strokeColor = isConditional ? '#f44336' : '#ff8c00';
      animated = true;
      label = isConditional ? 'TRUE' : 'JMP';
    } else if (isFallthrough) {
      strokeColor = '#7aaaff';
      label = isConditional ? 'FALSE' : '';
    }

    if (pathModeActive && edgeOnPath) {
      strokeColor = '#ffcf66';
      strokeWidth = 3;
      if (!label) label = 'PATH';
    }

    return {
      id: `${edge.source}-${edge.target}-${idx}`,
      source: edge.source,
      target: edge.target,
      type: 'smoothstep',
      animated,
      style: {
        stroke: strokeColor,
        strokeWidth,
        strokeDasharray,
        opacity: pathModeActive ? (edgeOnPath ? 1 : 0.25) : 1,
      },
      label,
      labelStyle: { fill: strokeColor, fontSize: 10, fontWeight: 'bold', fontFamily: 'monospace' },
      labelBgStyle: { fill: 'rgba(0,0,0,0.6)', borderRadius: 3 },
    };
  });

  const handleNodeClick = useCallback((event: React.MouseEvent, node: Node) => {
    const graphNode = graph.nodes.find(n => n.id === node.id);
    if (graphNode && onNodeClick) {
      onNodeClick(graphNode);
    }
  }, [graph.nodes, onNodeClick]);

  return (
    <div className="cfg-view">
      <ReactFlow
        nodes={nodeList}
        edges={edgeList}
        fitView
        attributionPosition="bottom-left"
        onNodeClick={handleNodeClick}
      >
        <Background gap={16} />
        <Controls />
        <MiniMap
          nodeColor={(node) => {
            const s = node.style as React.CSSProperties | undefined;
            const border = typeof s?.border === 'string' ? s.border : '';
            if (border.includes('#00ff00')) return '#00ff00';
            if (border.includes('#00e5cc')) return '#00e5cc';
            if (border.includes('#00bfa5')) return '#00bfa5';
            if (border.includes('#9c6aff')) return '#9c6aff';
            if (border.includes('#666')) return '#555';
            return '#00d4ff';
          }}
          maskColor="rgba(0,0,0,0.5)"
          style={{ background: '#111', border: '1px solid #333' }}
        />
      </ReactFlow>
    </div>
  );
}
