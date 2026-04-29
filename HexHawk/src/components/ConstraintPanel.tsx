import React, { useCallback, useMemo, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { talonDecompile } from '../utils/talonEngine';
import { runTaintAnalysis } from '../utils/taintEngine';
import type {
  TaintAnalysisResult,
  KeygenShape,
  TaintSource,
  TaintTransform,
} from '../utils/taintEngine';
import { clampInt } from '../utils/tauriGuards';

const MAX_UI_SMTLIB_BYTES = 1024 * 1024;
// ─── Local types (mirror Rust Z3Result) ──────────────────────────────────────

interface Z3ModelEntry {
  name: string;
  value: string;
}

interface Z3Result {
  verdict: 'sat' | 'unsat' | 'unknown' | 'error';
  raw_output: string;
  model: Z3ModelEntry[];
  z3_missing: boolean;
  runtime_ms: number;
  error: string | null;
}

// ─── Props ────────────────────────────────────────────────────────────────────

type DisassembledInstruction = {
  address: number;
  mnemonic: string;
  operands: string;
};

type CfgGraph = {
  nodes: Array<{ id: string; start?: number; end?: number; block_type?: string }>;
  edges: Array<{ source: string; target: string; kind?: string; condition?: string }>;
};

interface Props {
  disassembly: DisassembledInstruction[];
  cfg: CfgGraph | null;
  onAddressSelect: (address: number) => void;
  /** NEST-owned signal IDs for this binary — used to highlight relevant taint patterns */
  ownedSignals?: string[];
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function fmt(v: number): string {
  return `0x${v.toString(16).toUpperCase()}`;
}

function confidenceColor(c: number): string {
  if (c >= 80) return '#ff6b6b';
  if (c >= 65) return '#ffaa44';
  return '#ffdd55';
}

function ConfidencePill({ value }: { value: number }) {
  const color = confidenceColor(value);
  return (
    <span style={{
      fontSize: '0.72rem', fontWeight: 700, color,
      border: `1px solid ${color}`, borderRadius: '0.25rem',
      padding: '0 0.3rem', marginLeft: '0.4rem',
    }}>{value}%</span>
  );
}

function Section({
  title, children, defaultOpen = true,
}: { title: string; children: React.ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div style={{ marginBottom: '1rem', border: '1px solid #2a2a2a', borderRadius: '0.4rem', overflow: 'hidden' }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          width: '100%', textAlign: 'left', padding: '0.5rem 0.75rem',
          background: '#1a1a1a', border: 'none', color: '#ccc',
          cursor: 'pointer', fontWeight: 600, fontSize: '0.85rem',
          display: 'flex', justifyContent: 'space-between',
        }}
      >
        {title}
        <span style={{ color: '#666' }}>{open ? '▲' : '▼'}</span>
      </button>
      {open && (
        <div style={{ padding: '0.5rem 0.75rem', background: '#161616' }}>
          {children}
        </div>
      )}
    </div>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function TaintSourceList({ sources }: { sources: TaintSource[] }) {
  if (sources.length === 0) {
    return <p style={{ color: '#888', fontSize: '0.85rem', margin: 0 }}>No user-input sources detected in IR.</p>;
  }
  return (
    <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
      {sources.map((s, i) => (
        <li key={i} style={{
          padding: '0.35rem 0.5rem', borderBottom: '1px solid #222',
          fontSize: '0.83rem', display: 'flex', gap: '0.75rem', alignItems: 'center',
        }}>
          <span style={{
            minWidth: '90px', textAlign: 'center', fontSize: '0.72rem', fontWeight: 700,
            background: '#1e3a5f', color: '#6bcfff',
            border: '1px solid #2a5a8f', borderRadius: '0.25rem', padding: '1px 0.4rem',
          }}>{s.kind}</span>
          <span style={{ color: '#adf', fontFamily: 'monospace' }}>{fmt(s.address)}</span>
          {s.apiName && <span style={{ color: '#ccc' }}>{s.apiName}</span>}
          <span style={{ color: '#888', fontSize: '0.78rem' }}>
            taints: {s.vars.join(', ')}
          </span>
        </li>
      ))}
    </ul>
  );
}

function TransformChain({ chain }: { chain: TaintTransform[] }) {
  if (chain.length === 0) return <span style={{ color: '#888' }}>direct comparison (no transforms)</span>;
  return (
    <span style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: '#adf' }}>
      {chain.map((t, i) => (
        <span key={i}>
          {i > 0 && <span style={{ color: '#666' }}> → </span>}
          <span style={{ color: '#ffd166' }}>{t.op}</span>
          <span style={{ color: '#ccc' }}> {t.rhs}</span>
        </span>
      ))}
    </span>
  );
}

function KeygenShapeCard({
  shape,
  onSolve,
  z3Result,
  solving,
}: {
  shape: KeygenShape;
  onSolve: (shape: KeygenShape) => void;
  z3Result: Z3Result | null;
  solving: boolean;
}) {
  const [smtExpanded, setSmtExpanded] = useState(false);

  return (
    <div style={{
      border: '1px solid #3a3a3a', borderRadius: '0.4rem',
      marginBottom: '0.75rem', overflow: 'hidden',
      background: '#131313',
    }}>
      {/* Header */}
      <div style={{
        background: '#1a1a2e', padding: '0.5rem 0.75rem',
        display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap',
      }}>
        <span style={{ fontWeight: 700, color: '#fff', fontSize: '0.88rem' }}>{shape.id}</span>
        <ConfidencePill value={shape.confidence} />
        <span style={{ color: '#888', fontSize: '0.78rem', marginLeft: 'auto' }}>
          branch @ <span style={{ fontFamily: 'monospace', color: '#adf' }}>{fmt(shape.branchAddress)}</span>
        </span>
      </div>

      {/* Summary */}
      <div style={{ padding: '0.5rem 0.75rem', borderBottom: '1px solid #2a2a2a' }}>
        <div style={{ fontSize: '0.83rem', color: '#ddd', marginBottom: '0.4rem' }}>
          {shape.summary}
        </div>
        <div style={{ fontSize: '0.8rem', color: '#aaa', display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
          <span>Source: <span style={{ color: '#6bcfff' }}>{shape.source.kind}</span>
            {shape.source.apiName && <span style={{ color: '#ccc' }}> ({shape.source.apiName})</span>}
          </span>
          <span>Transforms: <TransformChain chain={shape.transformChain} /></span>
          <span>
            Comparison: <span style={{ fontFamily: 'monospace', color: '#ffd166' }}>
              {shape.comparison.taintedExpr} {shape.comparison.inferredOp}{' '}
              {shape.comparison.constValue !== null ? fmt(shape.comparison.constValue) : '?'}
            </span>
          </span>
        </div>
      </div>

      {/* SMT-LIB2 + Z3 */}
      <div style={{ padding: '0.5rem 0.75rem' }}>
        {shape.smtLib2 ? (
          <>
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.4rem' }}>
              <button
                onClick={() => setSmtExpanded(e => !e)}
                style={{
                  background: 'none', border: '1px solid #3a3a3a', color: '#aaa',
                  borderRadius: '0.2rem', padding: '2px 0.5rem', cursor: 'pointer', fontSize: '0.75rem',
                }}
              >{smtExpanded ? 'Hide SMT-LIB2' : 'Show SMT-LIB2'}</button>
              <button
                onClick={() => onSolve(shape)}
                disabled={solving}
                style={{
                  background: solving ? '#222' : '#1a3a1a',
                  color: solving ? '#666' : '#88ff88',
                  border: '1px solid ' + (solving ? '#333' : '#2a6a2a'),
                  borderRadius: '0.2rem', padding: '2px 0.6rem',
                  cursor: solving ? 'not-allowed' : 'pointer', fontSize: '0.78rem', fontWeight: 600,
                }}
              >{solving ? '⏳ Solving…' : '▶ Solve with Z3'}</button>
            </div>

            {smtExpanded && (
              <pre style={{
                margin: '0 0 0.5rem 0', background: '#0e0e0e', border: '1px solid #2a2a2a',
                borderRadius: '0.3rem', padding: '0.5rem', fontSize: '0.75rem',
                color: '#88cc88', fontFamily: 'monospace', maxHeight: '200px',
                overflow: 'auto', whiteSpace: 'pre-wrap',
              }}>{shape.smtLib2}</pre>
            )}

            {z3Result && (
              <Z3ResultDisplay result={z3Result} />
            )}
          </>
        ) : (
          <span style={{ fontSize: '0.8rem', color: '#888' }}>
            Constraint not reducible to SMT-LIB2 (non-linear or unknown operator).
          </span>
        )}
      </div>
    </div>
  );
}

function Z3ResultDisplay({ result }: { result: Z3Result }) {
  const [rawExpanded, setRawExpanded] = useState(false);

  if (result.z3_missing) {
    return (
      <div style={{
        background: '#1e1400', border: '1px solid #665500',
        borderRadius: '0.3rem', padding: '0.5rem', fontSize: '0.82rem', color: '#ffcc66',
      }}>
        <strong>Z3 not found.</strong> Install Z3 from{' '}
        <a href="https://github.com/Z3Prover/z3/releases" target="_blank" rel="noreferrer"
          style={{ color: '#6bcfff' }}>github.com/Z3Prover/z3</a>{' '}
        and ensure <code>z3</code> is on your PATH.
      </div>
    );
  }

  const verdictColor = result.verdict === 'sat' ? '#66ff88'
    : result.verdict === 'unsat' ? '#ff6b6b'
    : '#ffdd55';

  return (
    <div style={{ border: '1px solid #2a2a2a', borderRadius: '0.3rem', overflow: 'hidden' }}>
      <div style={{
        background: '#1a1a1a', padding: '0.4rem 0.6rem',
        display: 'flex', gap: '1rem', alignItems: 'center', fontSize: '0.82rem',
      }}>
        <span style={{ fontWeight: 700, color: verdictColor, fontSize: '0.9rem' }}>
          {result.verdict.toUpperCase()}
        </span>
        <span style={{ color: '#888' }}>{result.runtime_ms} ms</span>
        {result.error && <span style={{ color: '#ff8888' }}>{result.error}</span>}
        <button
          onClick={() => setRawExpanded(e => !e)}
          style={{
            marginLeft: 'auto', background: 'none', border: '1px solid #3a3a3a',
            color: '#aaa', borderRadius: '0.2rem', padding: '1px 0.4rem',
            cursor: 'pointer', fontSize: '0.72rem',
          }}>{rawExpanded ? 'Hide raw' : 'Raw output'}</button>
      </div>

      {result.model.length > 0 && (
        <div style={{ padding: '0.4rem 0.6rem', borderTop: '1px solid #1e1e1e', background: '#111' }}>
          <div style={{ fontSize: '0.8rem', color: '#aaa', marginBottom: '0.3rem' }}>Candidate values:</div>
          {result.model.map((m, i) => (
            <div key={i} style={{ fontFamily: 'monospace', fontSize: '0.82rem', color: '#88ff88' }}>
              {m.name} = {m.value}
            </div>
          ))}
        </div>
      )}

      {rawExpanded && (
        <pre style={{
          margin: 0, background: '#0e0e0e', padding: '0.5rem',
          fontSize: '0.75rem', color: '#ccc', fontFamily: 'monospace',
          maxHeight: '200px', overflow: 'auto', whiteSpace: 'pre-wrap',
          borderTop: '1px solid #1e1e1e',
        }}>{result.raw_output}</pre>
      )}
    </div>
  );
}

// ─── Main panel ───────────────────────────────────────────────────────────────

export default function ConstraintPanel({ disassembly, cfg, onAddressSelect, ownedSignals }: Props) {
  const [z3Results, setZ3Results] = useState<Map<string, Z3Result>>(new Map());
  const [solvingId, setSolvingId] = useState<string | null>(null);

  // Derive relevant NEST signals for this panel (serial/keygen/crypto/validation)
  const nestHints = (ownedSignals ?? []).filter(id =>
    /serial|keygen|cmp|check|licen|valid|crypto|auth|crack|protect/i.test(id)
  );

  // Run taint analysis over the current decompile result
  const analysis = useMemo<TaintAnalysisResult | null>(() => {
    if (disassembly.length === 0) return null;
    try {
      const talon = talonDecompile(disassembly, cfg);
      return runTaintAnalysis(talon.irBlocks);
    } catch {
      return null;
    }
  }, [disassembly, cfg]);

  const handleSolve = useCallback(async (shape: KeygenShape) => {
    setSolvingId(shape.id);
    try {
      const smtlib = String(shape.smtLib2 ?? '');
      if (!smtlib.trim()) {
        throw new Error('Constraint payload is empty.');
      }
      if (new TextEncoder().encode(smtlib).length > MAX_UI_SMTLIB_BYTES) {
        throw new Error(`Constraint payload too large (max ${MAX_UI_SMTLIB_BYTES} bytes).`);
      }
      const res = await invoke<Z3Result>('solve_z3_constraint', {
        smtlib,
        timeoutSecs: clampInt(10, 1, 60, 'timeout'),
      });
      setZ3Results(prev => new Map(prev).set(shape.id, res));
    } catch (e) {
      setZ3Results(prev => new Map(prev).set(shape.id, {
        verdict: 'error',
        raw_output: '',
        model: [],
        z3_missing: false,
        runtime_ms: 0,
        error: String(e),
      }));
    } finally {
      setSolvingId(null);
    }
  }, []);

  // ── No disassembly loaded ─────────────────────────────────────────────────
  if (disassembly.length === 0) {
    return (
      <div style={{ padding: '2rem', color: '#888', textAlign: 'center' }}>
        No disassembly loaded. Open a binary and disassemble a function first.
      </div>
    );
  }

  if (!analysis) {
    return (
      <div style={{ padding: '2rem', color: '#888', textAlign: 'center' }}>
        Taint analysis failed. Try disassembling a different address range.
      </div>
    );
  }

  const { sources, taintedVars, comparisons, shapes, hasDownstreamSink } = analysis;

  return (
    <div style={{ padding: '1rem', fontFamily: 'sans-serif', color: '#ddd', maxWidth: '960px', overflowY: 'auto', height: '100%' }}>

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div style={{ marginBottom: '1rem' }}>
        <h2 style={{ margin: '0 0 0.25rem 0', fontSize: '1.1rem', color: '#fff' }}>
          ⊛ Constraint Solver — Keygen & Serial Check Detection
        </h2>
        <p style={{ margin: 0, color: '#888', fontSize: '0.85rem' }}>
          Tracks user-controlled data through the IR, detects serial-check patterns, and emits
          SMT-LIB2 constraints solvable by Z3.
        </p>
      </div>

      {/* ── NEST ownership context ──────────────────────────────────────── */}
      {nestHints.length > 0 && (
        <div style={{
          background: '#0d2a1f', border: '1px solid #22c55e', borderRadius: '0.4rem',
          padding: '0.5rem 0.75rem', marginBottom: '1rem', fontSize: '0.82rem',
        }}>
          <span style={{ color: '#4ade80', fontWeight: 700 }}>⟳ NEST-owned: </span>
          <span style={{ color: '#86efac' }}>
            {nestHints.length} relevant signal{nestHints.length !== 1 ? 's' : ''} identified —{' '}
            taint analysis has been pre-seeded with these patterns:
          </span>
          <div style={{ marginTop: '0.3rem', display: 'flex', flexWrap: 'wrap', gap: '0.3rem' }}>
            {nestHints.map(id => (
              <span key={id} style={{
                fontFamily: 'monospace', fontSize: '0.75rem', background: '#1a3a2a',
                border: '1px solid #2a5a3a', borderRadius: '0.2rem', padding: '1px 0.4rem', color: '#6ee7b7',
              }}>{id}</span>
            ))}
          </div>
        </div>
      )}

      {/* ── NEST ownership context ──────────────────────────────────────── */}
      {nestHints.length > 0 && (
        <div style={{
          background: '#0d2a1f', border: '1px solid #22c55e', borderRadius: '0.4rem',
          padding: '0.5rem 0.75rem', marginBottom: '1rem', fontSize: '0.82rem',
        }}>
          <span style={{ color: '#4ade80', fontWeight: 700 }}>⟳ NEST-owned: </span>
          <span style={{ color: '#86efac' }}>
            {nestHints.length} relevant signal{nestHints.length !== 1 ? 's' : ''} identified —{' '}
            taint analysis has been pre-seeded with these patterns:
          </span>
          <div style={{ marginTop: '0.3rem', display: 'flex', flexWrap: 'wrap', gap: '0.3rem' }}>
            {nestHints.map(id => (
              <span key={id} style={{
                fontFamily: 'monospace', fontSize: '0.75rem', background: '#1a3a2a',
                border: '1px solid #2a5a3a', borderRadius: '0.2rem', padding: '1px 0.4rem', color: '#6ee7b7',
              }}>{id}</span>
            ))}
          </div>
        </div>
      )}

      {/* ── Summary bar ──────────────────────────────────────────────────── */}
      <div style={{
        display: 'flex', gap: '1.5rem', flexWrap: 'wrap',
        background: '#181818', border: '1px solid #333',
        borderRadius: '0.4rem', padding: '0.6rem 1rem', marginBottom: '1rem',
        fontSize: '0.83rem',
      }}>
        <span><span style={{ color: '#888' }}>Taint sources: </span>
          <span style={{ fontWeight: 700, color: sources.length > 0 ? '#6bcfff' : '#888' }}>{sources.length}</span>
        </span>
        <span><span style={{ color: '#888' }}>Tainted vars: </span>
          <span style={{ fontFamily: 'monospace', color: '#ccc' }}>{taintedVars.size}</span>
        </span>
        <span><span style={{ color: '#888' }}>Tainted comparisons: </span>
          <span style={{ fontWeight: 700, color: comparisons.length > 0 ? '#ffd166' : '#888' }}>{comparisons.length}</span>
        </span>
        <span><span style={{ color: '#888' }}>Key-check shapes: </span>
          <span style={{ fontWeight: 700, color: shapes.length > 0 ? '#ff9944' : '#888' }}>{shapes.length}</span>
        </span>
        {hasDownstreamSink && (
          <span style={{ color: '#ff8888', fontWeight: 600 }}>
            ⚠ Tainted data reaches a downstream write/send sink
          </span>
        )}
      </div>

      {/* ── Z3 availability note ────────────────────────────────────────── */}
      <div style={{
        background: '#1a1a2e', border: '1px solid #334',
        borderRadius: '0.3rem', padding: '0.5rem 0.75rem', marginBottom: '1rem',
        fontSize: '0.82rem', color: '#aac',
      }}>
        <strong>Z3 is optional.</strong> Taint analysis and constraint generation run entirely
        in HexHawk. The "Solve with Z3" button requires{' '}
        <code style={{ color: '#88ccff' }}>z3</code> to be installed and available on your PATH.
        Get it at{' '}
        <a href="https://github.com/Z3Prover/z3/releases" target="_blank" rel="noreferrer"
          style={{ color: '#6bcfff' }}>github.com/Z3Prover/z3</a>.
      </div>

      {/* ── Taint sources ─────────────────────────────────────────────────── */}
      <Section title={`Taint Sources (${sources.length})`}>
        <TaintSourceList sources={sources} />
      </Section>

      {/* ── Key-check shapes ──────────────────────────────────────────────── */}
      <Section title={`Key-Check Shape Candidates (${shapes.length})`}>
        {shapes.length === 0 ? (
          <p style={{ color: '#888', fontSize: '0.85rem', margin: 0 }}>
            No keygen shapes detected. The function may not contain a serial check,
            or the taint source was not recognised.
          </p>
        ) : (
          shapes.map(shape => (
            <KeygenShapeCard
              key={shape.id}
              shape={shape}
              onSolve={handleSolve}
              z3Result={z3Results.get(shape.id) ?? null}
              solving={solvingId === shape.id}
            />
          ))
        )}
      </Section>

      {/* ── Tainted comparisons (all, including non-shape) ───────────────── */}
      {comparisons.length > 0 && (
        <Section title={`All Tainted Comparisons (${comparisons.length})`} defaultOpen={false}>
          <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
            {comparisons.map((c, i) => (
              <li key={i} style={{
                padding: '0.35rem 0.5rem', borderBottom: '1px solid #222',
                fontSize: '0.82rem', display: 'flex', gap: '0.75rem', alignItems: 'center',
                cursor: 'pointer',
              }}
                onClick={() => onAddressSelect(c.address)}
                title="Jump to this address in disassembly"
              >
                <span style={{ fontFamily: 'monospace', color: '#adf', minWidth: '80px' }}>{fmt(c.address)}</span>
                <span style={{ color: '#ccc' }}>{c.taintedExpr}</span>
                <span style={{ color: '#ffd166', fontWeight: 700 }}>{c.inferredOp}</span>
                <span style={{ color: '#ccc' }}>
                  {c.constValue !== null ? fmt(c.constValue) : '<tainted>'}
                </span>
                <span style={{ color: '#888', fontSize: '0.75rem', marginLeft: 'auto' }}>
                  block {c.blockId}
                </span>
              </li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
}
