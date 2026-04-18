/**
 * AnalysisGraph — Interactive Knowledge Graph for Binary Analysis
 *
 * Visualises the relationships between binary artifacts using ReactFlow:
 *   • Import clusters (grouped by capability)
 *   • Suspicious strings (URLs, IPs, paths, commands)
 *   • Functions detected by disassembly analysis
 *   • Behavioral verdict node at the centre
 *
 * Click any node to navigate to the relevant data in the rest of the app.
 */

import React, { useCallback, useMemo, useState } from 'react';
import ReactFlow, { Background, Controls, Edge, MiniMap, Node, MarkerType } from 'reactflow';
import 'reactflow/dist/style.css';
import type { BinaryVerdictResult } from '../utils/correlationEngine';
import type { SuspiciousPattern } from '../App';

// ─── Types ────────────────────────────────────────────────────────────────────

interface Props {
  imports: Array<{ name: string; library: string }>;
  strings: Array<{ offset: number; text: string }>;
  disassembly: Array<{ address: number; mnemonic: string; operands: string }>;
  patterns: SuspiciousPattern[];
  verdict: BinaryVerdictResult | null;
  onNavigate?: (tab: 'metadata' | 'strings' | 'disassembly' | 'cfg' | 'hex') => void;
  onSelectStringOffset?: (offset: number) => void;
  onSelectAddress?: (address: number) => void;
}

// ─── Cluster definitions ─────────────────────────────────────────────────────

const CLUSTERS: Array<{
  id: string;
  label: string;
  color: string;
  pattern: RegExp;
  tab: 'metadata' | 'disassembly' | 'strings' | 'cfg' | 'hex';
}> = [
  { id: 'cluster-injection', label: 'Injection', color: '#ff4d4d', pattern: /^(VirtualAlloc(Ex)?|WriteProcessMemory|CreateRemoteThread(Ex)?|NtCreateThreadEx|OpenProcess|RtlCreateUserThread)$/, tab: 'disassembly' },
  { id: 'cluster-network',   label: 'Network / C2', color: '#4da6ff', pattern: /^(WSAStartup|connect|send|recv|InternetOpen|InternetConnect|HttpSendRequest|URLDownloadToFile|WinHttpOpen|WinHttpConnect|WinHttpSendRequest|WSASend)$/, tab: 'strings' },
  { id: 'cluster-evasion',   label: 'Evasion', color: '#ffa64d', pattern: /^(IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|GetProcAddress|LoadLibrary[AW]?|NtSetInformationThread|SetUnhandledExceptionFilter)$/, tab: 'disassembly' },
  { id: 'cluster-persistence', label: 'Persistence', color: '#b366ff', pattern: /^(RegSetValueEx[AW]?|RegCreateKey(Ex)?[AW]?|CreateService[AW]?|ChangeServiceConfig|StartService)$/, tab: 'metadata' },
  { id: 'cluster-exec',      label: 'Execution', color: '#ff9900', pattern: /^(ShellExecute[AW]?|CreateProcess[AW]?|WinExec|system|_exec|popen|CreateProcessWithToken[AW]?)$/, tab: 'disassembly' },
  { id: 'cluster-crypto',    label: 'Crypto', color: '#4dffb8', pattern: /^(CryptEncrypt|CryptDecrypt|CryptGenRandom|BCryptEncrypt|BCryptDecrypt|BCryptGenRandom|CryptAcquireContext)$/, tab: 'disassembly' },
];

const SUSPICIOUS_STRING_PATTERNS: RegExp[] = [
  /^https?:\/\//i,
  /^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/,
  /HKEY_/i,
  /%TEMP%|%APPDATA%/i,
  /cmd\.exe|powershell\.exe|wscript\.exe/i,
  /bitcoin|monero|ransom/i,
  /password|credential/i,
  /vmware|virtualbox|sandboxie/i,
];

// ─── Build graph data ─────────────────────────────────────────────────────────

function buildGraphData(
  imports: Props['imports'],
  strings: Props['strings'],
  patterns: Props['patterns'],
  verdict: BinaryVerdictResult | null,
): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const PADDING_X = 260;
  const COL_X = { clusters: 40, verdict: 400, strings: 760 };

  // ── Verdict node (centre) ─────────────────────────────────────────────────
  const classColor: Record<string, string> = {
    clean: '#4dff91',
    suspicious: '#ffcc00',
    packer: '#ff9900',
    dropper: '#ff6633',
    rat: '#ff3333',
    'ransomware-like': '#cc0000',
    'info-stealer': '#ff66cc',
    loader: '#aa88ff',
    'likely-malware': '#ff3300',
    unknown: '#888888',
  };
  const verdictColor = verdict ? (classColor[verdict.classification] ?? '#888888') : '#444';
  const verdictLabel = verdict ? `${verdict.classification.toUpperCase()}\n${verdict.threatScore}/100` : 'No verdict yet';

  nodes.push({
    id: 'verdict',
    position: { x: COL_X.verdict, y: 300 },
    data: {
      label: (
        <div style={{ textAlign: 'center', fontFamily: 'monospace' }}>
          <div style={{ fontSize: 11, color: '#aaa', marginBottom: 2 }}>VERDICT</div>
          <div style={{ fontWeight: 'bold', color: verdictColor, fontSize: 13 }}>
            {verdict?.classification.toUpperCase() ?? 'UNKNOWN'}
          </div>
          <div style={{ color: verdictColor, fontSize: 11 }}>
            {verdict ? `${verdict.threatScore}/100` : '—'}
          </div>
        </div>
      ),
    },
    style: {
      background: 'rgba(0,0,0,0.7)',
      border: `2px solid ${verdictColor}`,
      borderRadius: 8,
      padding: '8px 16px',
      minWidth: 120,
    },
  });

  // ── Cluster nodes (left column) ───────────────────────────────────────────
  const matchedClusters: typeof CLUSTERS = [];
  for (const cluster of CLUSTERS) {
    const clusterImports = imports.filter(i => cluster.pattern.test(i.name));
    if (clusterImports.length === 0) continue;

    matchedClusters.push(cluster);
    const y = 60 + matchedClusters.length * 100;

    nodes.push({
      id: cluster.id,
      position: { x: COL_X.clusters, y },
      data: {
        label: (
          <div style={{ fontFamily: 'monospace' }}>
            <div style={{ fontWeight: 'bold', color: cluster.color, fontSize: 12 }}>
              {cluster.label}
            </div>
            <div style={{ color: '#ccc', fontSize: 10, marginTop: 2 }}>
              {clusterImports.slice(0, 3).map(i => i.name).join(', ')}
              {clusterImports.length > 3 ? ` +${clusterImports.length - 3}` : ''}
            </div>
          </div>
        ),
      },
      style: {
        background: 'rgba(0,0,0,0.6)',
        border: `1.5px solid ${cluster.color}`,
        borderRadius: 6,
        padding: '6px 12px',
        minWidth: 160,
        cursor: 'pointer',
      },
    });

    edges.push({
      id: `e-${cluster.id}-verdict`,
      source: cluster.id,
      target: 'verdict',
      style: { stroke: cluster.color, strokeWidth: 2 },
      markerEnd: { type: MarkerType.ArrowClosed, color: cluster.color },
    });
  }

  // ── Suspicious string nodes (right column) ────────────────────────────────
  const suspiciousStrings = strings.filter(s =>
    SUSPICIOUS_STRING_PATTERNS.some(p => p.test(s.text))
  ).slice(0, 10);

  suspiciousStrings.forEach((str, idx) => {
    const nodeId = `str-${idx}`;
    const y = 60 + idx * 90;
    const shortened = str.text.length > 40 ? str.text.slice(0, 38) + '…' : str.text;

    nodes.push({
      id: nodeId,
      position: { x: COL_X.strings, y },
      data: {
        label: (
          <div style={{ fontFamily: 'monospace' }}>
            <div style={{ color: '#ffcc44', fontSize: 10, marginBottom: 2 }}>STRING</div>
            <div style={{ color: '#fff', fontSize: 11, wordBreak: 'break-all' }}>{shortened}</div>
          </div>
        ),
      },
      style: {
        background: 'rgba(0,0,0,0.6)',
        border: '1.5px solid #ffcc44',
        borderRadius: 6,
        padding: '6px 10px',
        minWidth: 180,
        cursor: 'pointer',
      },
    });

    edges.push({
      id: `e-verdict-${nodeId}`,
      source: 'verdict',
      target: nodeId,
      style: { stroke: '#ffcc44', strokeWidth: 1.5, strokeDasharray: '4 3' },
    });
  });

  // ── Pattern nodes (bottom row) ────────────────────────────────────────────
  const criticalPatterns = patterns.filter(p => p.severity === 'critical').slice(0, 4);
  criticalPatterns.forEach((pattern, idx) => {
    const nodeId = `pat-${idx}`;
    const y = matchedClusters.length > 0
      ? 60 + (matchedClusters.length + 1) * 100 + idx * 80
      : 80 + idx * 80;

    nodes.push({
      id: nodeId,
      position: { x: COL_X.clusters + PADDING_X / 2, y },
      data: {
        label: (
          <div style={{ fontFamily: 'monospace' }}>
            <div style={{ color: '#ff6666', fontSize: 10 }}>PATTERN</div>
            <div style={{ color: '#fff', fontSize: 10 }}>
              {`0x${pattern.address.toString(16).toUpperCase()}: ${pattern.type}`}
            </div>
          </div>
        ),
      },
      style: {
        background: 'rgba(80,0,0,0.5)',
        border: '1.5px solid #ff6666',
        borderRadius: 6,
        padding: '4px 8px',
        minWidth: 160,
        cursor: 'pointer',
      },
    });

    edges.push({
      id: `e-${nodeId}-verdict`,
      source: nodeId,
      target: 'verdict',
      style: { stroke: '#ff6666', strokeWidth: 1.5, strokeDasharray: '2 3' },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#ff6666' },
    });
  });

  return { nodes, edges };
}

// ─── Component ────────────────────────────────────────────────────────────────

export function AnalysisGraph({
  imports,
  strings,
  disassembly: _disassembly,
  patterns,
  verdict,
  onNavigate,
  onSelectStringOffset,
  onSelectAddress,
}: Props) {
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  const { nodes, edges } = useMemo(
    () => buildGraphData(imports, strings, patterns, verdict),
    [imports, strings, patterns, verdict],
  );

  const onNodeClick = useCallback((_event: React.MouseEvent, node: Node) => {
    setSelectedNode(node.id);

    if (node.id === 'verdict') {
      onNavigate?.('metadata');
      return;
    }

    if (node.id.startsWith('cluster-')) {
      const cluster = CLUSTERS.find(c => c.id === node.id);
      if (cluster) onNavigate?.(cluster.tab);
      return;
    }

    if (node.id.startsWith('str-')) {
      const idx = parseInt(node.id.split('-')[1], 10);
      const suspiciousStrings = strings.filter(s =>
        SUSPICIOUS_STRING_PATTERNS.some(p => p.test(s.text))
      );
      const str = suspiciousStrings[idx];
      if (str) {
        onNavigate?.('strings');
        onSelectStringOffset?.(str.offset);
      }
      return;
    }

    if (node.id.startsWith('pat-')) {
      const idx = parseInt(node.id.split('-')[1], 10);
      const criticalPatterns = patterns.filter(p => p.severity === 'critical');
      const pattern = criticalPatterns[idx];
      if (pattern) {
        onNavigate?.('disassembly');
        onSelectAddress?.(pattern.address);
      }
      return;
    }
  }, [strings, patterns, onNavigate, onSelectStringOffset, onSelectAddress]);

  const hasData = imports.length > 0 || strings.length > 0 || patterns.length > 0;

  if (!hasData) {
    return (
      <div className="analysis-graph-empty">
        <div className="empty-graph-icon">⬡</div>
        <div className="empty-graph-title">Analysis Graph</div>
        <div className="empty-graph-subtitle">
          Load a binary file and run Inspect to populate the knowledge graph.
        </div>
      </div>
    );
  }

  const nodeCount = imports.length > 0
    ? CLUSTERS.filter(c => imports.some(i => c.pattern.test(i.name))).length
    : 0;

  const stringCount = strings.filter(s =>
    SUSPICIOUS_STRING_PATTERNS.some(p => p.test(s.text))
  ).length;

  return (
    <div className="analysis-graph-container">
      <div className="analysis-graph-header">
        <span className="analysis-graph-title">Knowledge Graph</span>
        <span className="analysis-graph-stats">
          {nodeCount} capability cluster{nodeCount !== 1 ? 's' : ''}
          {' · '}
          {stringCount} suspicious string{stringCount !== 1 ? 's' : ''}
          {' · '}
          {patterns.filter(p => p.severity === 'critical').length} critical pattern{patterns.filter(p => p.severity === 'critical').length !== 1 ? 's' : ''}
        </span>
        {selectedNode && (
          <span className="analysis-graph-selected">
            Selected: {selectedNode}
          </span>
        )}
      </div>
      <div style={{ width: '100%', height: 560 }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodeClick={onNodeClick}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          attributionPosition="bottom-right"
        >
          <Background color="#1a2a1a" gap={20} />
          <Controls />
          <MiniMap
            nodeStrokeColor="#00ff88"
            nodeColor="#001a0d"
            style={{ background: '#0a0f0a', border: '1px solid #00ff88' }}
          />
        </ReactFlow>
      </div>
      <div className="analysis-graph-legend">
        <span className="legend-item" style={{ color: '#ff4d4d' }}>■ Injection</span>
        <span className="legend-item" style={{ color: '#4da6ff' }}>■ Network/C2</span>
        <span className="legend-item" style={{ color: '#ffa64d' }}>■ Evasion</span>
        <span className="legend-item" style={{ color: '#b366ff' }}>■ Persistence</span>
        <span className="legend-item" style={{ color: '#4dffb8' }}>■ Crypto</span>
        <span className="legend-item" style={{ color: '#ffcc44' }}>■ Strings</span>
        <span className="legend-item" style={{ color: '#ff6666' }}>■ Patterns</span>
      </div>
    </div>
  );
}
