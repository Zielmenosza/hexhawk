import React, { useCallback, useEffect, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

// ─── Backend Types ─────────────────────────────────────────────────────────────

interface ReplSessionInfo {
  session_id: string;
  path: string;
  eval_count: number;
  stored_keys: string[];
}

interface ReplEvalResponse {
  session_id: string;
  path: string;
  result: unknown;
  eval_count: number;
  stored_keys: string[];
}

// ─── UI Types ─────────────────────────────────────────────────────────────────

interface HistoryEntry {
  id: number;
  code: string;
  result: unknown;
  error: string | null;
  durationMs: number;
  eval_count: number;
}

interface Props {
  binaryPath: string | null;
}

// ─── Quick-action snippets ─────────────────────────────────────────────────────

const SNIPPETS: { label: string; code: string }[] = [
  { label: 'File size',    code: 'file_size()' },
  { label: 'Inspect',      code: 'inspect()' },
  { label: 'Sections',     code: 'section_map()' },
  { label: 'Strings',      code: 'strings()' },
  { label: 'Disasm @0',    code: 'disasm(0, 512)' },
  { label: 'Hex @0',       code: 'hex(0, 64)' },
  { label: 'Entropy',      code: 'entropy(0, 65536)' },
  { label: 'Find MZ',      code: 'find_bytes("4D 5A")' },
  { label: 'XRefs @0',     code: 'xref_to(0)' },
  { label: 'Store result', code: 'store("my_key", inspect())' },
  { label: 'Load key',     code: 'load("my_key")' },
  { label: 'Stored keys',  code: 'keys()' },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function resultToString(value: unknown): string {
  if (value === null || value === undefined) return '()';
  if (typeof value === 'string') return value;
  return JSON.stringify(value, null, 2);
}

function isComplex(value: unknown): boolean {
  if (typeof value !== 'object' || value === null) return false;
  const s = JSON.stringify(value);
  return s.length > 120 || s.includes('\n');
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function ReplView({ binaryPath }: Props) {
  const [session, setSession] = useState<ReplSessionInfo | null>(null);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [historyIndex, setHistoryIndex] = useState<number>(-1);
  const [running, setRunning] = useState(false);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const entryIdRef = useRef(0);
  const prevPathRef = useRef<string | null>(null);

  // Create / re-create session when binary path changes
  useEffect(() => {
    if (!binaryPath) { setSession(null); return; }
    if (binaryPath === prevPathRef.current) return;
    prevPathRef.current = binaryPath;

    setSessionError(null);
    setHistory([]);
    setCode('');
    setSession(null);

    invoke<ReplSessionInfo>('create_repl_session', { request: { path: binaryPath } })
      .then((info) => setSession(info))
      .catch((e: unknown) => setSessionError(String(e)));
  }, [binaryPath]);

  // Auto-scroll history to bottom after each new entry
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [history.length]);

  const runCode = useCallback(async () => {
    if (!session || !code.trim() || running) return;
    const snippet = code.trim();
    setRunning(true);
    const t0 = performance.now();
    try {
      const resp = await invoke<ReplEvalResponse>('repl_eval', {
        request: { session_id: session.session_id, code: snippet },
      });
      const ms = Math.round(performance.now() - t0);
      const id = ++entryIdRef.current;
      setHistory((h) => [
        ...h,
        { id, code: snippet, result: resp.result, error: null, durationMs: ms, eval_count: resp.eval_count },
      ]);
      setSession((s) =>
        s ? { ...s, eval_count: resp.eval_count, stored_keys: resp.stored_keys } : s,
      );
    } catch (e: unknown) {
      const ms = Math.round(performance.now() - t0);
      const id = ++entryIdRef.current;
      setHistory((h) => [
        ...h,
        { id, code: snippet, result: null, error: String(e), durationMs: ms, eval_count: session.eval_count },
      ]);
    }
    setRunning(false);
    setCode('');
    setHistoryIndex(-1);
    inputRef.current?.focus();
  }, [session, code, running]);

  // ──  keyboard handling ────────────────────────────────────────────────────
  function onKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      runCode();
      return;
    }
    // history navigation
    if (e.key === 'ArrowUp' && !e.shiftKey && code === '') {
      e.preventDefault();
      const cmds = history.map((h) => h.code).reverse();
      const next = historyIndex + 1;
      if (next < cmds.length) {
        setHistoryIndex(next);
        setCode(cmds[next]);
      }
      return;
    }
    if (e.key === 'ArrowDown' && !e.shiftKey) {
      e.preventDefault();
      const cmds = history.map((h) => h.code).reverse();
      const next = historyIndex - 1;
      if (next < 0) { setHistoryIndex(-1); setCode(''); }
      else { setHistoryIndex(next); setCode(cmds[next]); }
      return;
    }
  }

  function toggleExpanded(id: number) {
    setExpanded((s) => {
      const next = new Set(s);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  // ─── Render ───────────────────────────────────────────────────────────────

  if (!binaryPath) {
    return (
      <div className="repl-root repl-empty">
        <div className="repl-empty-msg">
          <span className="repl-empty-icon">{'>'}_</span>
          <p>Load a binary to open a REPL session.</p>
        </div>
      </div>
    );
  }

  if (sessionError) {
    return (
      <div className="repl-root repl-empty">
        <div className="repl-empty-msg">
          <span className="repl-empty-icon" style={{ color: '#ff6b6b' }}>!</span>
          <p style={{ color: '#ff6b6b' }}>Session error: {sessionError}</p>
          <button className="repl-retry-btn" onClick={() => {
            prevPathRef.current = null;
            setSessionError(null);
          }}>Retry</button>
        </div>
      </div>
    );
  }

  if (!session) {
    return (
      <div className="repl-root repl-empty">
        <div className="repl-empty-msg">
          <span className="repl-empty-icon" style={{ color: '#00d4ff' }}>⟳</span>
          <p style={{ color: '#aaa' }}>Starting REPL session…</p>
        </div>
      </div>
    );
  }

  return (
    <div className="repl-root">
      {/* ── Header ────────────────────────────────────────────────────── */}
      <div className="repl-header">
        <span className="repl-header-title">REPL</span>
        <span className="repl-header-path" title={session.path}>{session.path.split(/[\\/]/).pop()}</span>
        <span className="repl-header-badge">{session.eval_count} eval{session.eval_count !== 1 ? 's' : ''}</span>
        {session.stored_keys.length > 0 && (
          <span className="repl-header-badge" style={{ background: '#1a3a1a', color: '#44ff88' }}>
            {session.stored_keys.length} stored
          </span>
        )}
      </div>

      {/* ── Quick-action strip ────────────────────────────────────────── */}
      <div className="repl-snippets">
        {SNIPPETS.map((s) => (
          <button
            key={s.label}
            className="repl-snippet-btn"
            title={s.code}
            onClick={() => { setCode(s.code); inputRef.current?.focus(); }}
          >
            {s.label}
          </button>
        ))}
      </div>

      {/* ── History ──────────────────────────────────────────────────── */}
      <div className="repl-history">
        {history.length === 0 && (
          <div className="repl-history-empty">
            Type a Rhai expression and press Enter — or click a quick-action above.
          </div>
        )}
        {history.map((entry) => {
          const resultStr = resultToString(entry.result);
          const complex = isComplex(entry.result);
          const isExpanded = expanded.has(entry.id);
          return (
            <div key={entry.id} className={`repl-entry${entry.error ? ' repl-entry-error' : ''}`}>
              {/* Input line */}
              <div className="repl-entry-input">
                <span className="repl-prompt">{'>'}</span>
                <span className="repl-entry-code">{entry.code}</span>
                <span className="repl-entry-ms">{entry.durationMs}ms</span>
              </div>
              {/* Output */}
              {entry.error ? (
                <div className="repl-entry-result repl-entry-err-text">{entry.error}</div>
              ) : (
                <div
                  className={`repl-entry-result${complex && !isExpanded ? ' repl-entry-collapsed' : ''}`}
                  onClick={complex ? () => toggleExpanded(entry.id) : undefined}
                  style={complex ? { cursor: 'pointer' } : undefined}
                >
                  {complex && (
                    <span className="repl-expand-toggle">{isExpanded ? '▾' : '▸'} </span>
                  )}
                  <pre className="repl-result-pre">{resultStr}</pre>
                </div>
              )}
            </div>
          );
        })}
        <div ref={bottomRef} />
      </div>

      {/* ── Input ────────────────────────────────────────────────────── */}
      <div className="repl-input-bar">
        <span className="repl-prompt">{'>'}</span>
        <textarea
          ref={inputRef}
          className="repl-input"
          value={code}
          onChange={(e) => { setCode(e.target.value); setHistoryIndex(-1); }}
          onKeyDown={onKeyDown}
          placeholder="Rhai expression — Enter to run, Shift+Enter for newline, ↑/↓ for history"
          rows={Math.min(6, (code.match(/\n/g)?.length ?? 0) + 1)}
          disabled={running}
          spellCheck={false}
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="off"
        />
        <button
          className="repl-run-btn"
          onClick={runCode}
          disabled={running || !code.trim()}
          title="Run (Enter)"
        >
          {running ? '⟳' : '▶'}
        </button>
      </div>

      {/* ── Stored keys sidebar (if any) ─────────────────────────────── */}
      {session.stored_keys.length > 0 && (
        <div className="repl-stored-keys">
          <span className="repl-stored-label">Stored:</span>
          {session.stored_keys.map((k) => (
            <button
              key={k}
              className="repl-snippet-btn"
              title={`load("${k}")`}
              onClick={() => { setCode(`load("${k}")`); inputRef.current?.focus(); }}
            >
              {k}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
