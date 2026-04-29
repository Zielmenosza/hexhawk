import React, { useCallback, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

// ─── Tauri response types ─────────────────────────────────────────────────────

interface DocSignal {
  label: string;
  confidence: number;
  category: string;
}

interface PdfScript {
  object_id: number;
  source: string;
  dangerous_patterns: string[];
}

interface PdfAnalysisResult {
  javascript: PdfScript[];
  embedded_files: string[];
  uri_actions: string[];
  signals: DocSignal[];
  object_count: number;
  parse_error: string | null;
}

interface VbaModule {
  name: string;
  source: string;
  dangerous_patterns: string[];
}

interface OfficeAnalysisResult {
  modules: VbaModule[];
  signals: DocSignal[];
  parse_error: string | null;
}

// ─── Props ────────────────────────────────────────────────────────────────────

interface Props {
  binaryPath: string;
  /** file format hint from the inspect result (e.g. "PDF", "OLE2", "ZIP") */
  formatHint: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function categoryColor(cat: string): string {
  switch (cat) {
    case 'security': return '#ff6b6b';
    case 'dropper':  return '#ffaa44';
    case 'macro':    return '#ffd166';
    case 'info':     return '#6bcfff';
    default:         return '#aaa';
  }
}

function confidencePill(conf: number): React.ReactElement {
  const color = conf >= 85 ? '#ff4444' : conf >= 70 ? '#ffaa44' : '#ffdd55';
  return (
    <span style={{
      fontSize: '0.72rem', fontWeight: 700, color,
      border: `1px solid ${color}`, borderRadius: '0.25rem',
      padding: '0 0.3rem', marginLeft: '0.4rem',
    }}>{conf}%</span>
  );
}

// ─── Sub-views ────────────────────────────────────────────────────────────────

function SignalList({ signals }: { signals: DocSignal[] }) {
  if (signals.length === 0) return <p style={{ color: '#888', fontSize: '0.85rem' }}>No signals detected.</p>;
  return (
    <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
      {signals.map((s, i) => (
        <li key={i} style={{
          display: 'flex', alignItems: 'center', gap: '0.5rem',
          padding: '0.35rem 0.5rem', borderBottom: '1px solid #2a2a2a',
          fontSize: '0.85rem',
        }}>
          <span style={{
            fontSize: '0.7rem', fontWeight: 700, color: categoryColor(s.category),
            border: `1px solid ${categoryColor(s.category)}`, borderRadius: '0.25rem',
            padding: '0 0.3rem', textTransform: 'uppercase', whiteSpace: 'nowrap',
          }}>{s.category}</span>
          <span style={{ color: '#ddd', flex: 1 }}>{s.label}</span>
          {confidencePill(s.confidence)}
        </li>
      ))}
    </ul>
  );
}

function ScriptBlock({ script }: { script: PdfScript }) {
  const [expanded, setExpanded] = useState(false);
  const preview = script.source.slice(0, 200);
  return (
    <div style={{
      backgroundColor: '#1a1a1a', border: '1px solid #333',
      borderRadius: '0.4rem', marginBottom: '0.75rem',
    }}>
      <div
        style={{
          display: 'flex', alignItems: 'center', gap: '0.5rem',
          padding: '0.5rem 0.75rem', cursor: 'pointer', userSelect: 'none',
        }}
        onClick={() => setExpanded(e => !e)}
      >
        <span style={{ color: '#888', fontSize: '0.8rem' }}>Obj #{script.object_id}</span>
        {script.dangerous_patterns.length > 0 && (
          <span style={{
            fontSize: '0.7rem', color: '#ff6b6b',
            border: '1px solid #ff6b6b', borderRadius: '0.25rem', padding: '0 0.3rem',
          }}>⚠ {script.dangerous_patterns.length} issue{script.dangerous_patterns.length > 1 ? 's' : ''}</span>
        )}
        <span style={{ marginLeft: 'auto', color: '#666', fontSize: '0.8rem' }}>{expanded ? '▲' : '▼'}</span>
      </div>

      {expanded && (
        <div style={{ padding: '0 0.75rem 0.75rem' }}>
          {script.dangerous_patterns.length > 0 && (
            <ul style={{ margin: '0 0 0.5rem 0', padding: 0, listStyle: 'none' }}>
              {script.dangerous_patterns.map((p, i) => (
                <li key={i} style={{ color: '#ff9944', fontSize: '0.78rem', paddingBottom: '0.2rem' }}>⚠ {p}</li>
              ))}
            </ul>
          )}
          <pre style={{
            backgroundColor: '#111', color: '#c8e6c9', fontSize: '0.75rem',
            padding: '0.5rem', borderRadius: '0.3rem',
            overflowX: 'auto', maxHeight: '300px', overflow: 'auto',
            margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all',
          }}>
            {script.source.length > 4000
              ? script.source.slice(0, 4000) + '\n... [truncated]'
              : script.source}
          </pre>
        </div>
      )}

      {!expanded && preview && (
        <div style={{ padding: '0 0.75rem 0.5rem' }}>
          <span style={{ color: '#666', fontSize: '0.75rem', fontFamily: 'monospace' }}>
            {preview}{script.source.length > 200 ? '…' : ''}
          </span>
        </div>
      )}
    </div>
  );
}

function MacroBlock({ mod: m }: { mod: VbaModule }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div style={{
      backgroundColor: '#1a1a1a', border: '1px solid #333',
      borderRadius: '0.4rem', marginBottom: '0.75rem',
    }}>
      <div
        style={{
          display: 'flex', alignItems: 'center', gap: '0.5rem',
          padding: '0.5rem 0.75rem', cursor: 'pointer', userSelect: 'none',
        }}
        onClick={() => setExpanded(e => !e)}
      >
        <span style={{ color: '#aad4ff', fontWeight: 600, fontSize: '0.85rem', fontFamily: 'monospace' }}>{m.name}</span>
        {m.dangerous_patterns.length > 0 && (
          <span style={{
            fontSize: '0.7rem', color: '#ff6b6b',
            border: '1px solid #ff6b6b', borderRadius: '0.25rem', padding: '0 0.3rem',
          }}>⚠ {m.dangerous_patterns.length} issue{m.dangerous_patterns.length > 1 ? 's' : ''}</span>
        )}
        <span style={{ marginLeft: 'auto', color: '#666', fontSize: '0.8rem' }}>{expanded ? '▲' : '▼'}</span>
      </div>

      {expanded && (
        <div style={{ padding: '0 0.75rem 0.75rem' }}>
          {m.dangerous_patterns.length > 0 && (
            <ul style={{ margin: '0 0 0.5rem 0', padding: 0, listStyle: 'none' }}>
              {m.dangerous_patterns.map((p, i) => (
                <li key={i} style={{ color: '#ff9944', fontSize: '0.78rem', paddingBottom: '0.2rem' }}>⚠ {p}</li>
              ))}
            </ul>
          )}
          <pre style={{
            backgroundColor: '#111', color: '#ffe082', fontSize: '0.75rem',
            padding: '0.5rem', borderRadius: '0.3rem',
            overflowX: 'auto', maxHeight: '400px', overflow: 'auto',
            margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all',
          }}>
            {m.source.length > 8000
              ? m.source.slice(0, 8000) + '\n... [truncated]'
              : m.source}
          </pre>
        </div>
      )}
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function DocumentAnalysisPanel({ binaryPath, formatHint }: Props) {
  const [pdfResult, setPdfResult] = useState<PdfAnalysisResult | null>(null);
  const [officeResult, setOfficeResult] = useState<OfficeAnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const lowerHint = formatHint.toLowerCase();
  const isPdf = lowerHint.includes('pdf');
  const isOffice = lowerHint.includes('ole') || lowerHint.includes('zip') ||
    lowerHint.includes('doc') || lowerHint.includes('xls') || lowerHint.includes('ppt') ||
    lowerHint.includes('office') || lowerHint.includes('ooxml');

  const runPdfAnalysis = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await invoke<PdfAnalysisResult>('analyze_pdf', { path: binaryPath });
      setPdfResult(result);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [binaryPath]);

  const runOfficeAnalysis = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await invoke<OfficeAnalysisResult>('analyze_office', { path: binaryPath });
      setOfficeResult(result);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [binaryPath]);

  const panelStyle: React.CSSProperties = {
    height: '100%', overflowY: 'auto', padding: '1rem',
    backgroundColor: '#141414', color: '#ddd', fontFamily: 'sans-serif',
    fontSize: '0.9rem',
  };

  const sectionHead: React.CSSProperties = {
    color: '#00bfff', fontWeight: 700, fontSize: '1rem',
    marginBottom: '0.5rem', marginTop: '1.25rem',
    borderBottom: '1px solid #2a2a2a', paddingBottom: '0.3rem',
  };

  const btnStyle: React.CSSProperties = {
    padding: '0.5rem 1.2rem', backgroundColor: '#1e3a5f',
    border: '1px solid #00bfff', borderRadius: '0.35rem',
    color: '#00bfff', cursor: 'pointer', fontWeight: 600,
    fontSize: '0.85rem', marginRight: '0.5rem',
  };

  return (
    <div style={panelStyle}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '0.5rem' }}>
        <h2 style={{ margin: 0, fontSize: '1.1rem', color: '#00bfff' }}>📄 Document Content Analysis</h2>
        <span style={{ color: '#888', fontSize: '0.8rem' }}>{formatHint || 'unknown format'}</span>
      </div>

      <p style={{ color: '#888', fontSize: '0.82rem', margin: '0 0 1rem 0' }}>
        Extracts embedded JavaScript (PDF) and VBA macros (OLE2 / OOXML) for static analysis.
        Content is never executed.
      </p>

      {/* Action buttons */}
      <div style={{ marginBottom: '1rem', display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
        <button style={btnStyle} disabled={loading} onClick={runPdfAnalysis}>
          {loading ? '⏳ Analyzing…' : '🔍 Analyze as PDF'}
        </button>
        <button style={btnStyle} disabled={loading} onClick={runOfficeAnalysis}>
          {loading ? '⏳ Analyzing…' : '🔍 Analyze as Office / OLE2'}
        </button>
      </div>

      {!isPdf && !isOffice && !pdfResult && !officeResult && (
        <div style={{
          backgroundColor: '#1e1e2e', border: '1px solid #444',
          borderRadius: '0.4rem', padding: '0.75rem',
          color: '#aaa', fontSize: '0.83rem', marginBottom: '1rem',
        }}>
          ℹ Format hint: <strong style={{ color: '#ddd' }}>{formatHint || 'unknown'}</strong>.
          This file may not be a PDF or Office document, but you can still try the analysis buttons above.
        </div>
      )}

      {error && (
        <div style={{
          backgroundColor: '#2a1010', border: '1px solid #ff4444',
          borderRadius: '0.4rem', padding: '0.75rem',
          color: '#ff8888', fontSize: '0.83rem', marginBottom: '1rem',
        }}>
          ❌ {error}
        </div>
      )}

      {/* PDF results */}
      {pdfResult && (
        <>
          {pdfResult.parse_error && (
            <div style={{
              backgroundColor: '#2a1a10', border: '1px solid #ff8844',
              borderRadius: '0.4rem', padding: '0.6rem',
              color: '#ff9966', fontSize: '0.82rem', marginBottom: '0.75rem',
            }}>
              ⚠ Partial parse: {pdfResult.parse_error}
            </div>
          )}

          <div style={sectionHead}>PDF Signals ({pdfResult.signals.length})</div>
          <SignalList signals={pdfResult.signals} />

          <div style={sectionHead}>
            JavaScript ({pdfResult.javascript.length} block{pdfResult.javascript.length !== 1 ? 's' : ''})
          </div>
          {pdfResult.javascript.length === 0
            ? <p style={{ color: '#888', fontSize: '0.85rem' }}>No JavaScript found.</p>
            : pdfResult.javascript.map((s, i) => <ScriptBlock key={i} script={s} />)
          }

          {pdfResult.embedded_files.length > 0 && (
            <>
              <div style={sectionHead}>Embedded Files ({pdfResult.embedded_files.length})</div>
              <ul style={{ margin: 0, padding: '0 0 0 1.2rem' }}>
                {pdfResult.embedded_files.map((f, i) => (
                  <li key={i} style={{ color: '#ffaa44', fontSize: '0.85rem', paddingBottom: '0.2rem' }}>{f}</li>
                ))}
              </ul>
            </>
          )}

          {pdfResult.uri_actions.length > 0 && (
            <>
              <div style={sectionHead}>URI / Launch Actions ({pdfResult.uri_actions.length})</div>
              <ul style={{ margin: 0, padding: '0 0 0 1.2rem' }}>
                {pdfResult.uri_actions.map((u, i) => (
                  <li key={i} style={{ color: '#88ccff', fontSize: '0.85rem', paddingBottom: '0.2rem', wordBreak: 'break-all' }}>{u}</li>
                ))}
              </ul>
            </>
          )}

          <p style={{ color: '#555', fontSize: '0.75rem', marginTop: '1rem' }}>
            {pdfResult.object_count} PDF objects inspected
          </p>
        </>
      )}

      {/* Office results */}
      {officeResult && (
        <>
          {officeResult.parse_error && (
            <div style={{
              backgroundColor: '#2a1a10', border: '1px solid #ff8844',
              borderRadius: '0.4rem', padding: '0.6rem',
              color: '#ff9966', fontSize: '0.82rem', marginBottom: '0.75rem',
            }}>
              ⚠ Partial parse: {officeResult.parse_error}
            </div>
          )}

          <div style={sectionHead}>Office Signals ({officeResult.signals.length})</div>
          <SignalList signals={officeResult.signals} />

          <div style={sectionHead}>
            VBA Modules ({officeResult.modules.length})
          </div>
          {officeResult.modules.length === 0
            ? <p style={{ color: '#888', fontSize: '0.85rem' }}>No VBA modules extracted.</p>
            : officeResult.modules.map((m, i) => <MacroBlock key={i} mod={m} />)
          }
        </>
      )}
    </div>
  );
}
