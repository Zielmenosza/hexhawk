import React, { useCallback, useMemo } from 'react';
import ReactFlow, { Background, Controls, Edge, MarkerType, MiniMap, Node, NodeProps } from 'reactflow';
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

type CfgNodeData = {
  title: string;
  addrLine: string;
  metricLine: string;
  badges: string[];
  level: 'highlight' | 'path' | 'dispatcher' | 'loop-header' | 'loop-body' | 'exit' | 'external' | 'entry' | 'normal';
  muted: boolean;
  loopDepth: number;
};

const CfgBlockNode = React.memo(({ data }: NodeProps<CfgNodeData>) => {
  return (
    <div className={`cfg-node cfg-node--${data.level}${data.muted ? ' cfg-node--muted' : ''}`}>
      <div className="cfg-node-title">{data.title}</div>
      {data.addrLine && <div className="cfg-node-addr">{data.addrLine}</div>}
      {data.metricLine && <div className="cfg-node-metrics">{data.metricLine}</div>}
      {data.badges.length > 0 && (
        <div className="cfg-node-badges">
          {data.badges.map(b => (
            <span key={b} className="cfg-node-badge">{b}</span>
          ))}
        </div>
      )}
      {data.loopDepth > 1 && (
        <div className="cfg-node-depth">Loop depth {data.loopDepth}</div>
      )}
    </div>
  );
});

CfgBlockNode.displayName = 'CfgBlockNode';

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

  const nodeList: Node<CfgNodeData>[] = graph.nodes.map((node, index) => {
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

    let level: CfgNodeData['level'] = 'normal';

    if (isHighlighted) {
      level = 'highlight';
    } else if (pathModeActive && isOnPath) {
      level = 'path';
    } else if (isDispatcher) {
      level = 'dispatcher';
    } else if (isLoopHeader) {
      level = 'loop-header';
    } else if (isLoopBody) {
      level = 'loop-body';
    } else if (isExitBlock) {
      level = 'exit';
    } else if (isExternal) {
      level = 'external';
    } else if (isEntry) {
      level = 'entry';
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
    const badges: string[] = [];
    if (isEntry) badges.push('ENTRY');
    if (isExitBlock) badges.push('EXIT');
    if (isExternal) badges.push('EXTERNAL');
    if (pathModeActive && isOnPath) badges.push('PATH');
    if (isLoopHeader) badges.push('LOOP HDR');
    if (isDispatcher) badges.push('DISPATCHER');

    return {
      id: node.id,
      position: { x, y },
      type: 'cfgNode',
      data: {
        title: node.label || node.id,
        addrLine,
        metricLine,
        badges,
        level,
        muted: pathModeActive ? !isOnPath : false,
        loopDepth,
      },
      style: {
        minWidth: 204,
        cursor: onNodeClick ? 'pointer' : 'default',
        opacity: pathModeActive ? (isOnPath ? 1 : 0.32) : 1,
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
      strokeWidth = 3.2;
      if (!label) label = 'PATH';
    }

    return {
      id: `${edge.source}-${edge.target}-${idx}`,
      source: edge.source,
      target: edge.target,
      type: 'smoothstep',
      animated,
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: strokeColor,
        width: 16,
        height: 16,
      },
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

  const nodeTypes = useMemo(() => ({
    cfgNode: CfgBlockNode,
  }), []);

  return (
    <div className="cfg-view cfg-view--modern">
      <ReactFlow
        nodes={nodeList}
        edges={edgeList}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2, maxZoom: 1.35 }}
        minZoom={0.15}
        maxZoom={2}
        attributionPosition="bottom-left"
        onNodeClick={handleNodeClick}
      >
        <Background gap={22} size={1.1} color="rgba(154, 208, 255, 0.18)" />
        <Controls showInteractive={false} />
        <MiniMap
          nodeColor={(node: Node) => {
            const d = node.data as CfgNodeData | undefined;
            if (!d) return '#7aaaff';
            if (d.level === 'highlight') return '#6effb4';
            if (d.level === 'path') return '#ffcf66';
            if (d.level === 'loop-header') return '#00e5cc';
            if (d.level === 'loop-body') return '#00bfa5';
            if (d.level === 'dispatcher') return '#ffb347';
            if (d.level === 'exit') return '#b38cff';
            if (d.level === 'external') return '#8c8ca8';
            if (d.level === 'entry') return '#66ffa8';
            return '#68c2ff';
          }}
          maskColor="rgba(0,0,0,0.44)"
          style={{ background: '#0e1526', border: '1px solid rgba(255,255,255,0.18)' }}
        />
      </ReactFlow>
    </div>
  );
}
