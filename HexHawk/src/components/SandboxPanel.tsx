import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { clampInt, sanitizeBridgePath } from '../utils/tauriGuards';

// ─── Tauri response types ─────────────────────────────────────────────────────

interface SandboxSignal {
  label: string;
  confidence: number;
  category: string;
}

interface FileEvent {
  path: string;
  kind: 'created' | 'modified' | 'deleted';
}

interface SandboxResult {
  exit_code: number | null;
  stdout: string;
  stderr: string;
  timed_out: boolean;
  runtime_ms: number;
  interpreter: string;
  file_events: FileEvent[];
  signals: SandboxSignal[];
  warnings: string[];
  error: string | null;
}

// ─── Props ────────────────────────────────────────────────────────────────────

interface Props {
  binaryPath: string;
  /** NEST-owned signal IDs for this binary — highlights expected runtime behaviour */
  ownedSignals?: string[];
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function catColor(cat: string): string {
  switch (cat) {
    case 'network':       return '#ff6b6b';
    case 'exec':          return '#ff9944';
    case 'dropper':       return '#ffd166';
    case 'persistence':   return '#f78fff';
    case 'recon':         return '#6bcfff';
    case 'obfuscation':   return '#ff7ea0';
    case 'anti-analysis': return '#c084fc';
    case 'info':          return '#88cc88';
    default:              return '#aaa';
  }
}

function fileKindColor(kind: string): string {
  switch (kind) {
    case 'created':  return '#6bcfff';
    case 'modified': return '#ffd166';
    case 'deleted':  return '#ff6b6b';
    default:         return '#aaa';
  }
}

function ConfidencePill({ value }: { value: number }) {
  const color = value >= 85 ? '#ff4444' : value >= 70 ? '#ffaa44' : '#ffdd55';
  return (
    <span style={{
      fontSize: '0.72rem', fontWeight: 700, color,
      border: `1px solid ${color}`, borderRadius: '0.25rem',
      padding: '0 0.3rem', marginLeft: '0.4rem',
    }}>{value}%</span>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function SignalList({ signals }: { signals: SandboxSignal[] }) {
  if (signals.length === 0) {
    return <p style={{ color: '#888', fontSize: '0.85rem', margin: 0 }}>No behaviour signals detected.</p>;
  }
  return (
    <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
      {signals.map((s, i) => (
        <li key={i} style={{
          display: 'flex', alignItems: 'center', gap: '0.5rem',
          padding: '0.35rem 0.5rem', borderBottom: '1px solid #2a2a2a',
          fontSize: '0.85rem',
        }}>
          <span style={{
            minWidth: '90px', textAlign: 'center', fontSize: '0.72rem', fontWeight: 700,
            background: catColor(s.category) + '33', color: catColor(s.category),
            border: `1px solid ${catColor(s.category)}66`, borderRadius: '0.25rem',
            padding: '1px 0.4rem',
          }}>{s.category}</span>
          <span style={{ flex: 1, color: '#ddd' }}>{s.label}</span>
          <ConfidencePill value={s.confidence} />
        </li>
      ))}
    </ul>
  );
}

function FileEventTable({ events }: { events: FileEvent[] }) {
  if (events.length === 0) {
    return <p style={{ color: '#888', fontSize: '0.85rem', margin: 0 }}>No file system changes detected.</p>;
  }
  return (
    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.83rem' }}>
      <thead>
        <tr style={{ borderBottom: '1px solid #3a3a3a', color: '#aaa' }}>
          <th style={{ textAlign: 'left', padding: '0.3rem 0.5rem', width: '80px' }}>Kind</th>
          <th style={{ textAlign: 'left', padding: '0.3rem 0.5rem' }}>Path</th>
        </tr>
      </thead>
      <tbody>
        {events.map((e, i) => (
          <tr key={i} style={{ borderBottom: '1px solid #222' }}>
            <td style={{ padding: '0.3rem 0.5rem' }}>
              <span style={{
                color: fileKindColor(e.kind),
                fontWeight: 700, fontSize: '0.75rem',
              }}>{e.kind.toUpperCase()}</span>
            </td>
            <td style={{ padding: '0.3rem 0.5rem', color: '#ccc', wordBreak: 'break-all', fontFamily: 'monospace' }}>{e.path}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function OutputBlock({ title, text, maxHeight = 200 }: { title: string; text: string; maxHeight?: number }) {
  const [expanded, setExpanded] = useState(false);
  if (!text.trim()) return null;
  return (
    <div style={{ marginBottom: '0.75rem' }}>
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        marginBottom: '0.3rem',
      }}>
        <span style={{ fontSize: '0.8rem', color: '#aaa', fontWeight: 600 }}>{title}</span>
        <button
          onClick={() => setExpanded(e => !e)}
          style={{
            background: 'none', border: '1px solid #3a3a3a', color: '#aaa',
            borderRadius: '0.2rem', padding: '1px 0.5rem', cursor: 'pointer', fontSize: '0.75rem',
          }}
        >{expanded ? 'Collapse' : 'Expand'}</button>
      </div>
      <pre style={{
        margin: 0, background: '#111', border: '1px solid #2a2a2a',
        borderRadius: '0.3rem', padding: '0.5rem',
        fontSize: '0.78rem', color: '#ccc', fontFamily: 'monospace',
        maxHeight: expanded ? 'none' : `${maxHeight}px`,
        overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
      }}>{text}</pre>
    </div>
  );
}

// ─── Main panel ───────────────────────────────────────────────────────────────

export default function SandboxPanel({ binaryPath, ownedSignals }: Props) {
  const [consented, setConsented] = useState(false);
  const [timeoutSecs, setTimeoutSecs] = useState(30);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<SandboxResult | null>(null);

  // NEST-derived behaviour hints (network/exec/dropper/persistence categories)
  const behaviourHints = (ownedSignals ?? []).filter(id =>
    /network|exec|dropper|inject|c2|dns|http|shell|persist|download|spawn/i.test(id)
  );

  const supportedExtensions = ['.py', '.ps1', '.js', '.bat', '.cmd', '.sh', '.rb', '.pl'];
  const fileExt = binaryPath ? '.' + binaryPath.split('.').pop()?.toLowerCase() : '';
  const isSupported = supportedExtensions.includes(fileExt);

  async function handleRun() {
    if (!consented || running) return;
    setRunning(true);
    setResult(null);
    try {
      const safePath = sanitizeBridgePath(binaryPath, 'sandbox script path');
      const safeTimeoutSecs = clampInt(timeoutSecs, 1, 120, 'timeout');
      const res = await invoke<SandboxResult>('run_script_sandbox', {
        path: safePath,
        timeoutSecs: safeTimeoutSecs,
      });
      setResult(res);
    } catch (e) {
      setResult({
        exit_code: null,
        stdout: '',
        stderr: '',
        timed_out: false,
        runtime_ms: 0,
        interpreter: 'unknown',
        file_events: [],
        signals: [],
        warnings: [],
        error: String(e),
      });
    } finally {
      setRunning(false);
    }
  }

  // ── No file loaded ──────────────────────────────────────────────────────────
  if (!binaryPath) {
    return (
      <div style={{ padding: '2rem', color: '#888', textAlign: 'center' }}>
        No file loaded. Open a script file to use the sandbox.
      </div>
    );
  }

  return (
    <div style={{ padding: '1rem', fontFamily: 'sans-serif', color: '#ddd', maxWidth: '900px' }}>

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div style={{ marginBottom: '1rem' }}>
        <h2 style={{ margin: '0 0 0.25rem 0', fontSize: '1.1rem', color: '#fff' }}>
          ⬡ Script Sandbox
        </h2>
        <p style={{ margin: 0, color: '#888', fontSize: '0.85rem' }}>
          Execute a script in a monitored subprocess and analyse its runtime behaviour.
        </p>
      </div>

      {/* ── NEST ownership context ──────────────────────────────────────── */}
      {behaviourHints.length > 0 && (
        <div style={{
          background: '#0d2a1f', border: '1px solid #22c55e', borderRadius: '0.4rem',
          padding: '0.5rem 0.75rem', marginBottom: '1rem', fontSize: '0.82rem',
        }}>
          <span style={{ color: '#4ade80', fontWeight: 700 }}>⟳ NEST-owned: </span>
          <span style={{ color: '#86efac' }}>
            expect these runtime behaviour categories based on prior analysis:
          </span>
          <div style={{ marginTop: '0.3rem', display: 'flex', flexWrap: 'wrap', gap: '0.3rem' }}>
            {behaviourHints.map(id => (
              <span key={id} style={{
                fontFamily: 'monospace', fontSize: '0.75rem', background: '#1a3a2a',
                border: '1px solid #2a5a3a', borderRadius: '0.2rem', padding: '1px 0.4rem', color: '#6ee7b7',
              }}>{id}</span>
            ))}
          </div>
        </div>
      )}

      {/* ── Danger banner ──────────────────────────────────────────────────── */}
      <div style={{
        background: '#2a1111', border: '1px solid #ff4444', borderRadius: '0.4rem',
        padding: '0.75rem 1rem', marginBottom: '1rem',
      }}>
        <div style={{ fontWeight: 700, color: '#ff6666', marginBottom: '0.4rem', fontSize: '0.9rem' }}>
          ⚠ DANGER — READ BEFORE EXECUTING
        </div>
        <ul style={{ margin: 0, paddingLeft: '1.25rem', fontSize: '0.83rem', color: '#ffaaaa' }}>
          <li>This will <strong>execute the script</strong> on your host system.</li>
          <li>Network traffic is <strong>NOT blocked</strong>. The script can make outbound connections.</li>
          <li>File system access is <strong>NOT restricted</strong>. The script can read and write files.</li>
          <li>For analysis of untrusted malware, use a <strong>dedicated VM</strong>.</li>
          <li>A {timeoutSecs}-second wall-clock timeout will kill the process if it doesn&rsquo;t exit.</li>
          {!isSupported && (
            <li style={{ color: '#ff8888', fontWeight: 700 }}>
              File extension &ldquo;{fileExt}&rdquo; is not supported. Supported: {supportedExtensions.join(' ')}
            </li>
          )}
        </ul>
      </div>

      {/* ── Consent + controls ─────────────────────────────────────────────── */}
      <div style={{
        background: '#1a1a1a', border: '1px solid #333', borderRadius: '0.4rem',
        padding: '0.75rem 1rem', marginBottom: '1rem',
      }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.6rem', marginBottom: '0.75rem' }}>
          <input
            id="sandbox-consent"
            type="checkbox"
            checked={consented}
            onChange={e => setConsented(e.target.checked)}
            style={{ marginTop: '2px', accentColor: '#ff8844', cursor: 'pointer' }}
          />
          <label htmlFor="sandbox-consent" style={{ fontSize: '0.85rem', color: '#ddd', cursor: 'pointer', userSelect: 'none' }}>
            I understand that clicking &ldquo;Run in Sandbox&rdquo; will execute the script on my host machine.
            I accept responsibility for any consequences.
          </label>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
          <label style={{ fontSize: '0.83rem', color: '#aaa', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            Timeout:
            <input
              type="number" min={5} max={120} value={timeoutSecs}
              onChange={e => setTimeoutSecs(Number(e.target.value))}
              style={{
                width: '60px', background: '#111', color: '#ddd', border: '1px solid #444',
                borderRadius: '0.2rem', padding: '2px 6px', fontSize: '0.83rem',
              }}
            />
            seconds
          </label>

          <div style={{ fontSize: '0.83rem', color: '#888' }}>
            Script: <span style={{ fontFamily: 'monospace', color: '#aaa' }}>{binaryPath.split(/[\\/]/).pop()}</span>
          </div>

          <button
            onClick={handleRun}
            disabled={!consented || running || !isSupported}
            style={{
              marginLeft: 'auto',
              background: consented && isSupported ? '#cc3300' : '#333',
              color: consented && isSupported ? '#fff' : '#666',
              border: 'none', borderRadius: '0.3rem', padding: '0.4rem 1.2rem',
              cursor: consented && isSupported ? 'pointer' : 'not-allowed',
              fontWeight: 700, fontSize: '0.88rem',
              transition: 'background 0.15s',
            }}
          >
            {running ? '⏳ Running…' : '▶ Run in Sandbox'}
          </button>
        </div>
      </div>

      {/* ── Results ─────────────────────────────────────────────────────────── */}
      {result && (
        <div>
          {/* Error */}
          {result.error && (
            <div style={{
              background: '#2a1111', border: '1px solid #ff4444',
              borderRadius: '0.4rem', padding: '0.75rem 1rem', marginBottom: '1rem',
              color: '#ff8888', fontSize: '0.85rem',
            }}>
              <strong>Error:</strong> {result.error}
            </div>
          )}

          {/* Warnings */}
          {result.warnings.map((w, i) => (
            <div key={i} style={{
              background: '#1e1600', border: '1px solid #665500',
              borderRadius: '0.3rem', padding: '0.5rem 0.75rem', marginBottom: '0.5rem',
              color: '#ffcc66', fontSize: '0.82rem',
            }}>{w}</div>
          ))}

          {/* Summary bar */}
          {!result.error && (
            <div style={{
              display: 'flex', gap: '1rem', flexWrap: 'wrap',
              background: '#181818', border: '1px solid #333',
              borderRadius: '0.4rem', padding: '0.6rem 1rem', marginBottom: '1rem',
              fontSize: '0.83rem', alignItems: 'center',
            }}>
              <span>
                <span style={{ color: '#888' }}>Exit code: </span>
                <span style={{
                  fontWeight: 700, fontFamily: 'monospace',
                  color: result.exit_code === 0 ? '#66ff88' : result.exit_code === null ? '#ffdd55' : '#ff6b6b',
                }}>
                  {result.timed_out ? 'KILLED (timeout)' : result.exit_code === null ? 'none' : result.exit_code}
                </span>
              </span>
              <span>
                <span style={{ color: '#888' }}>Runtime: </span>
                <span style={{ fontFamily: 'monospace', color: '#ccc' }}>{result.runtime_ms} ms</span>
              </span>
              <span>
                <span style={{ color: '#888' }}>Interpreter: </span>
                <span style={{ fontFamily: 'monospace', color: '#adf' }}>{result.interpreter}</span>
              </span>
              <span>
                <span style={{ color: '#888' }}>Signals: </span>
                <span style={{ fontWeight: 700, color: result.signals.length > 0 ? '#ffaa44' : '#66ff88' }}>
                  {result.signals.length}
                </span>
              </span>
              <span>
                <span style={{ color: '#888' }}>File events: </span>
                <span style={{ fontFamily: 'monospace', color: '#ccc' }}>{result.file_events.length}</span>
              </span>
            </div>
          )}

          {/* Behaviour Signals */}
          <Section title={`Behaviour Signals (${result.signals.length})`}>
            <SignalList signals={result.signals} />
          </Section>

          {/* File Events */}
          <Section title={`File System Events (${result.file_events.length})`}>
            <FileEventTable events={result.file_events} />
          </Section>

          {/* stdout / stderr */}
          {(result.stdout || result.stderr) && (
            <Section title="Output">
              <OutputBlock title="stdout" text={result.stdout} />
              <OutputBlock title="stderr" text={result.stderr} />
            </Section>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Collapsible section wrapper ─────────────────────────────────────────────

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(true);
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
