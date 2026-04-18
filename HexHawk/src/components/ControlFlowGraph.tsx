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
}

export function ControlFlowGraph({ graph, onNodeClick, highlightedBlockId }: Props) {
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

    const color = isHighlighted ? '#00ff00' : isExternal ? '#666' : isEntry ? '#00ff00' : '#00d4ff';
    const bgColor = isHighlighted
      ? 'rgba(0, 200, 100, 0.5)'
      : isExternal
      ? 'rgba(50, 50, 50, 0.8)'
      : isEntry
      ? 'rgba(0, 100, 0, 0.3)'
      : 'rgba(0, 100, 150, 0.3)';

    // Use layout coordinates from backend if available
    const x = node.layout_x ?? (index % 5) * 280;
    const y = node.layout_y ?? Math.floor(index / 5) * 180;

    // Build rich label: id + address range + instruction count + in-degree
    const instrCount = node.instruction_count ?? 0;
    const incoming = inDegree.get(node.id) ?? 0;
    const addrLine = node.start !== undefined
      ? `0x${node.start.toString(16).toUpperCase()}${node.end !== undefined ? `–0x${node.end.toString(16).toUpperCase()}` : ''}`
      : '';
    const metricLine = instrCount > 0
      ? `${instrCount} instr${incoming > 0 ? ` · ${incoming} in` : ''}`
      : '';
    const typeLine = isEntry ? '[ENTRY]' : isExternal ? '[EXTERN]' : '';
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
        boxShadow: isHighlighted ? '0 0 20px rgba(0, 255, 0, 0.6)' : 'none',
        transition: 'all 0.2s ease',
        lineHeight: '1.4',
      },
    };
  });

  const edgeList: Edge[] = graph.edges.map((edge, idx) => {
    const isBranch = (edge.kind ?? edge.type) === 'branch';
    const isConditional = edge.condition === 'conditional';
    const isFallthrough = (edge.kind ?? edge.type) === 'fallthrough';

    let strokeColor = '#7aaaff';
    const strokeWidth = 2;
    let animated = false;
    let label = '';

    if (isBranch) {
      strokeColor = isConditional ? '#f44336' : '#ff8c00';
      animated = true;
      label = isConditional ? 'TRUE' : 'JMP';
    } else if (isFallthrough) {
      strokeColor = '#7aaaff';
      label = isConditional ? 'FALSE' : '';
    }

    return {
      id: `${edge.source}-${edge.target}-${idx}`,
      source: edge.source,
      target: edge.target,
      type: 'smoothstep',
      animated,
      style: { stroke: strokeColor, strokeWidth },
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
