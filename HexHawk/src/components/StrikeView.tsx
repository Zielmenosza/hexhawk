/**
 * StrikeView — STRIKE Runtime Intelligence UI
 *
 * Enhanced debugger interface with:
 *   - Delta Engine: per-step register/flag change highlighting
 *   - Timeline strip: scrollable history with replay
 *   - Pattern alerts: detected behavioral anomalies
 *   - Sync controls: navigate disassembly/hex to current RIP
 *
 * Relies on DebuggerPanel's Tauri backend invocations for actual execution.
 * STRIKE adds the intelligence layer on top of raw snapshots.
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type {
  DebugSnapshot,
  RegisterState,
  StartDebugResult,
  DebugStatus,
} from './DebuggerPanel';
import {
  createTimeline,
  appendStep,
  seekTimeline,
  currentStep,
  detectPatterns,
  extractCorrelationSignals,
  REG_KEYS,
  REG_LABELS,
  type StrikeTimeline,
  type StrikeStep,
  type StrikeDelta,
  type RegisterDelta,
  type FlagDelta,
  type PatternTag,
  type StrikePattern,
} from '../utils/strikeEngine';
import { sanitizeAddress, sanitizeBridgePath, sanitizeHexOrDecAddress, clampInt } from '../utils/tauriGuards';

// ── Props ─────────────────────────────────────────────────────────────────────

interface StrikeViewProps {
  binaryPath:      string | null;
  currentAddress:  number | null;
  onAddressSelect: (address: number) => void;
  onNavigateHex:   (address: number) => void;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const hex16 = (n: number) => '0x' + n.toString(16).toUpperCase().padStart(16, '0');
const hex8  = (n: number) => '0x' + n.toString(16).toUpperCase().padStart(8, '0');
const hexShort = (n: number) => n.toString(16).toUpperCase().padStart(8, '0');

function numDir(prev: number, curr: number): 'up' | 'down' | 'same' {
  if (curr > prev) return 'up';
  if (curr < prev) return 'down';
  return 'same';
}

const STATUS_COLORS: Record<DebugStatus, string> = {
  Starting: '#888',
  Paused:   '#ffcc44',
  Running:  '#44cc88',
  Exited:   '#666',
  Error:    '#ff5555',
};

const PATTERN_COLORS: Record<PatternTag, string> = {
  'timing-check':           '#ff9800',
  'exception-probe':        '#e91e63',
  'stack-pivot':            '#f44336',
  'rop-chain':              '#9c27b0',
  'nop-sled':               '#607d8b',
  'anti-step':              '#ff5722',
  'cpuid-check':            '#795548',
  'anti-debug-probe':       '#f06292',
  'self-modifying-code':    '#ff7043',
  'oep-transfer':           '#ab47bc',
  'dynamic-api-resolution': '#26a69a',
  'peb-walk':               '#8d6e63',
};

const JUMP_LABELS: Record<string, string> = {
  sequential:    '→',
  'branch-taken': '⤷',
  call:          '⟶',
  ret:           '⟵',
  indirect:      '⟿',
  exception:     '⚡',
};

// ── Sub-components ────────────────────────────────────────────────────────────

const DeltaPanel: React.FC<{ delta: StrikeDelta | null }> = ({ delta }) => {
  if (!delta || (!delta.hasChanges && delta.flags.length === 0)) {
    return (
      <div className="stk-delta-empty">
        No changes this step
      </div>
    );
  }

  return (
    <div className="stk-delta-list">
      {delta.registers.map(r => {
        const dir = numDir(r.prev, r.curr);
        return (
          <div key={r.key} className={`stk-delta-row stk-delta-row--${dir}`}>
            <span className="stk-delta-reg">{r.label}</span>
            <span className="stk-delta-arrow">
              {dir === 'up' ? '▲' : dir === 'down' ? '▼' : '='}
            </span>
            <span className="stk-delta-val stk-delta-val--prev">{hex16(r.prev)}</span>
            <span className="stk-delta-sep">→</span>
            <span className="stk-delta-val stk-delta-val--curr">{hex16(r.curr)}</span>
          </div>
        );
      })}
      {delta.flags.length > 0 && (
        <div className="stk-delta-flags-row">
          <span className="stk-delta-flags-label">FLAGS</span>
          {delta.flags.map(f => (
            <span
              key={f.flag}
              className={`stk-delta-flag ${f.curr ? 'stk-delta-flag--set' : 'stk-delta-flag--clear'}`}
            >
              {f.flag}{f.curr ? '↑' : '↓'}
            </span>
          ))}
        </div>
      )}
      <div className="stk-delta-jump">
        <span className="stk-delta-jump-sym">
          {JUMP_LABELS[delta.jumpType] ?? '?'}
        </span>
        <span className="stk-delta-jump-type">{delta.jumpType}</span>
        <span className="stk-delta-jump-off">
          {delta.ripOffset >= 0 ? '+' : ''}{delta.ripOffset} bytes
        </span>
      </div>
    </div>
  );
};

const PatternBadge: React.FC<{ pattern: StrikePattern; onSeek: (i: number) => void }> = ({
  pattern, onSeek,
}) => {
  const color = PATTERN_COLORS[pattern.tag];
  return (
    <div
      className="stk-pattern-badge"
      style={{ borderColor: color + '66', background: color + '18' }}
      onClick={() => onSeek(pattern.firstStep)}
      title={`${pattern.description}\nSteps ${pattern.firstStep}–${pattern.firstStep + pattern.stepSpan - 1}`}
    >
      <span className="stk-pattern-icon" style={{ color }}>⚠</span>
      <span className="stk-pattern-label" style={{ color }}>{pattern.label}</span>
      <span className="stk-pattern-conf">{pattern.confidence}%</span>
    </div>
  );
};

const TimelineStrip: React.FC<{
  timeline:  StrikeTimeline;
  onSeek:    (i: number) => void;
}> = ({ timeline, onSeek }) => {
  const stripRef = useRef<HTMLDivElement>(null);
  const { steps, playheadIndex } = timeline;

  // Auto-scroll to current playhead
  useEffect(() => {
    const el = stripRef.current;
    if (!el) return;
    const active = el.querySelector('.stk-tl-step--active') as HTMLElement | null;
    if (active) {
      active.scrollIntoView({ behavior: 'smooth', inline: 'center', block: 'nearest' });
    }
  }, [playheadIndex]);

  if (steps.length === 0) {
    return <div className="stk-tl-empty">No steps recorded</div>;
  }

  return (
    <div className="stk-timeline-strip" ref={stripRef}>
      {steps.map(step => {
        const isActive    = step.index === playheadIndex;
        const hasDelta    = step.delta?.hasChanges ?? false;
        const isBp        = step.hitBreakpoint;
        const jumpSym     = step.delta ? (JUMP_LABELS[step.delta.jumpType] ?? '?') : '○';
        const deltaCount  = step.delta?.registers.length ?? 0;

        return (
          <div
            key={step.index}
            className={[
              'stk-tl-step',
              isActive  ? 'stk-tl-step--active'  : '',
              hasDelta  ? 'stk-tl-step--dirty'   : '',
              isBp      ? 'stk-tl-step--bp'       : '',
            ].join(' ')}
            onClick={() => onSeek(step.index)}
            title={`Step ${step.index}: ${step.event}\nRIP: 0x${hexShort(step.snapshot.registers.rip)}`}
          >
            <span className="stk-tl-idx">#{step.index}</span>
            <span className="stk-tl-sym">{jumpSym}</span>
            <span className="stk-tl-rip">{hexShort(step.snapshot.registers.rip)}</span>
            {deltaCount > 0 && (
              <span className="stk-tl-chg">{deltaCount}Δ</span>
            )}
            {isBp && <span className="stk-tl-bp-dot" title="Breakpoint hit" />}
          </div>
        );
      })}
    </div>
  );
};

const RegisterGrid: React.FC<{
  regs:    RegisterState;
  changed: Set<string>;
  onNav:   (addr: number) => void;
}> = ({ regs, changed, onNav }) => {
  const PAIRS: Array<[keyof RegisterState, string]> = [
    ['rax','RAX'],['rbx','RBX'],['rcx','RCX'],['rdx','RDX'],
    ['rsi','RSI'],['rdi','RDI'],['rsp','RSP'],['rbp','RBP'],
    ['rip','RIP'],
    ['r8','R8'], ['r9','R9'], ['r10','R10'],['r11','R11'],
    ['r12','R12'],['r13','R13'],['r14','R14'],['r15','R15'],
  ];
  const navKeys = new Set(['rip', 'rsp', 'rbp']);

  return (
    <div className="stk-reg-grid">
      {PAIRS.map(([key, label]) => {
        const val      = (regs as unknown as Record<string, number>)[key as string] ?? 0;
        const isDirty  = changed.has(key as string);
        const isNav    = navKeys.has(key as string);
        return (
          <div
            key={key}
            className={`stk-reg-row${isDirty ? ' stk-reg-row--changed' : ''}`}
          >
            <span className="stk-reg-name">{label}</span>
            <span
              className={`stk-reg-val${isNav ? ' stk-reg-val--addr' : ''}`}
              onClick={isNav ? () => onNav(val) : undefined}
              style={isNav ? { cursor: 'pointer' } : undefined}
              title={isNav ? `Navigate to ${hex16(val)}` : undefined}
            >
              {hex16(val)}
            </span>
          </div>
        );
      })}
    </div>
  );
};

const StackPane: React.FC<{ stack: number[]; rsp: number; onNav: (addr: number) => void }> = ({
  stack, rsp, onNav,
}) => (
  <div className="stk-stack-list">
    {stack.length === 0 ? (
      <div className="stk-empty">Stack not readable</div>
    ) : (
      stack.slice(0, 12).map((val, i) => {
        const addr = rsp + i * 8;
        return (
          <div key={i} className={`stk-stack-row${i === 0 ? ' stk-stack-row--top' : ''}`}>
            <span className="stk-stack-addr clickable" onClick={() => onNav(addr)} title="Go to address">
              {hex8(addr)}
            </span>
            <span className="stk-stack-val">{hex16(val)}</span>
          </div>
        );
      })
    )}
  </div>
);

// ── Main component ────────────────────────────────────────────────────────────

const StrikeView: React.FC<StrikeViewProps> = ({
  binaryPath,
  currentAddress,
  onAddressSelect,
  onNavigateHex,
}) => {
  const [timeline, setTimeline]   = useState<StrikeTimeline | null>(null);
  const [snapshot, setSnapshot]   = useState<DebugSnapshot | null>(null);
  const [status,   setStatus]     = useState<DebugStatus>('Exited');
  const [arch,     setArch]       = useState<string>('x86_64');
  const [error,    setError]      = useState<string | null>(null);
  const [bpInput,  setBpInput]    = useState<string>('');
  const [pidInput, setPidInput]   = useState<string>('');
  const [sessionId, setSessionId] = useState<number | null>(null);
  const [loading,  setLoading]    = useState(false);

  const playStep = useCallback((tl: StrikeTimeline, index: number) => {
    const seeked = seekTimeline(tl, index);
    setTimeline(seeked);
    const step = seeked.steps[seeked.playheadIndex];
    if (step) setSnapshot(step.snapshot);
  }, []);

  // Subscribe to real-time 'strike-snapshot' events emitted by the debug thread
  // (fired on every Step / StepOver / Continue stop).
  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    listen<DebugSnapshot>('strike-snapshot', event => {
      const snap = event.payload;
      setStatus(snap.status);
      setSnapshot(snap);
      setTimeline(tl => tl ? appendStep(tl, snap).timeline : null);
    }).then(fn => {
      if (disposed) {
        fn();
        return;
      }
      unlisten = fn;
    }).catch(() => {
      // no-op on listener registration failure
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  const handleLoad = useCallback(async () => {
    if (!binaryPath) { setError('No binary loaded'); return; }
    setError(null);
    setLoading(true);
    try {
      const safePath = sanitizeBridgePath(binaryPath, 'debug binary path');
      const result = await invoke<StartDebugResult>('start_debug_session', {
        path: safePath,
        args: [],
      });
      setSessionId(result.sessionId);
      setArch(result.arch);
      setStatus(result.snapshot.status);
      setSnapshot(result.snapshot);
      const tl = createTimeline(result.sessionId);
      const { timeline: tl2 } = appendStep(tl, result.snapshot);
      setTimeline(tl2);
    } catch (e) {
      setError(String(e));
      setStatus('Error');
    } finally {
      setLoading(false);
    }
  }, [binaryPath]);

  const handleStepOver = useCallback(async () => {
    if (sessionId === null || !timeline) return;
    setLoading(true);
    try {
      const snap = await invoke<DebugSnapshot>('debug_step_over', { sessionId });
      setStatus(snap.status);
      setSnapshot(snap);
      const { timeline: updated } = appendStep(timeline, snap);
      setTimeline(updated);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [sessionId, timeline]);

  const handleStepOut = useCallback(async () => {
    if (sessionId === null || !timeline) return;
    setLoading(true);
    try {
      const snap = await invoke<DebugSnapshot>('debug_step_out', { sessionId });
      setStatus(snap.status);
      setSnapshot(snap);
      const { timeline: updated } = appendStep(timeline, snap);
      setTimeline(updated);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [sessionId, timeline]);

  const handleAttach = useCallback(async () => {
    const pid = Number.parseInt(pidInput.trim(), 10);
    if (!Number.isInteger(pid)) { setError('Invalid PID (must be a positive integer)'); return; }
    const safePid = clampInt(pid, 1, 0x7FFFFFFF, 'PID');
    const confirmed = window.confirm(`Attach debugger to PID ${safePid}?`);
    if (!confirmed) return;
    setError(null);
    setLoading(true);
    try {
      const result = await invoke<StartDebugResult>('debug_attach', { pid: safePid });
      setSessionId(result.sessionId);
      setArch(result.arch);
      setStatus(result.snapshot.status);
      setSnapshot(result.snapshot);
      const tl = createTimeline(result.sessionId);
      const { timeline: tl2 } = appendStep(tl, result.snapshot);
      setTimeline(tl2);
      setPidInput('');
    } catch (e) {
      setError(String(e));
      setStatus('Error');
    } finally {
      setLoading(false);
    }
  }, [pidInput]);

  const handleStep = useCallback(async () => {
    if (sessionId === null || !timeline) return;
    setLoading(true);
    try {
      const snap = await invoke<DebugSnapshot>('debug_step', { sessionId });
      setStatus(snap.status);
      setSnapshot(snap);
      const { timeline: updated } = appendStep(timeline, snap);
      setTimeline(updated);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [sessionId, timeline]);

  const handleContinue = useCallback(async () => {
    if (sessionId === null || !timeline) return;
    setLoading(true);
    try {
      const snap = await invoke<DebugSnapshot>('debug_continue', { sessionId });
      setStatus(snap.status);
      setSnapshot(snap);
      const { timeline: updated } = appendStep(timeline, snap);
      setTimeline(updated);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [sessionId, timeline]);

  const handleStop = useCallback(async () => {
    if (sessionId === null) return;
    const confirmed = window.confirm('Stop the active debug session?');
    if (!confirmed) return;
    try {
      await invoke('debug_stop', { sessionId });
    } catch (_) { /* ignore */ }
    setStatus('Exited');
    setSessionId(null);
  }, [sessionId]);

  const handleAddBreakpoint = useCallback(async () => {
    if (sessionId === null || !bpInput.trim()) return;
    let safeAddr: number;
    try {
      safeAddr = sanitizeHexOrDecAddress(bpInput, 'breakpoint address');
    } catch (e) {
      setError(String(e));
      return;
    }
    try {
      await invoke('debug_set_breakpoint', { sessionId, address: safeAddr });
      setSnapshot(s => s ? { ...s, breakpoints: [...s.breakpoints, safeAddr] } : s);
      setBpInput('');
    } catch (e) {
      setError(String(e));
    }
  }, [sessionId, bpInput]);

  const handleRemoveBreakpoint = useCallback(async (addr: number) => {
    if (sessionId === null) return;
    try {
      const safeAddr = sanitizeAddress(addr, 'breakpoint address');
      await invoke('debug_remove_breakpoint', { sessionId, address: safeAddr });
      setSnapshot(s => s ? { ...s, breakpoints: s.breakpoints.filter(b => b !== safeAddr) } : s);
    } catch (e) {
      setError(String(e));
    }
  }, [sessionId]);

  const step    = timeline ? currentStep(timeline) : null;
  const delta   = step?.delta ?? null;
  const patterns = timeline ? detectPatterns(timeline) : [];

  const changedRegs = new Set<string>(
    (delta?.registers ?? []).map(r => r.key)
  );

  const canStep     = status === 'Paused' && !loading;
  const canContinue = status === 'Paused' && !loading;
  const canStop     = sessionId !== null;
  const canLoad     = !loading;

  return (
    <div className="stk-root">
      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <div className="stk-header">
        <span className="stk-brand">STRIKE</span>
        <span className="stk-arch-badge">{arch}</span>
        {binaryPath && (
          <span className="stk-binary-name" title={binaryPath}>
            {binaryPath.split(/[/\\]/).pop()}
          </span>
        )}
        <span
          className="stk-status-pill"
          style={{ background: STATUS_COLORS[status] + '22', color: STATUS_COLORS[status] }}
        >
          {status}
        </span>
        {timeline && (
          <span className="stk-step-count">
            {timeline.steps.length} step{timeline.steps.length !== 1 ? 's' : ''}
          </span>
        )}
        {patterns.length > 0 && (
          <span className="stk-alert-pill">
            ⚠ {patterns.length} pattern{patterns.length !== 1 ? 's' : ''}
          </span>
        )}
      </div>

      {/* ── Controls ────────────────────────────────────────────────────────── */}
      <div className="stk-controls">
        <button className="stk-btn stk-btn--primary" onClick={handleLoad} disabled={!canLoad}>
          {loading ? '…' : '⊞ Load'}
        </button>
        <button className="stk-btn" onClick={handleStep} disabled={!canStep}>
          ⬥ Step
        </button>
        <button className="stk-btn" onClick={handleStepOver} disabled={!canStep}>
          ⇥ Step Over
        </button>
        <button className="stk-btn" onClick={handleStepOut} disabled={!canStep}>
          ⇤ Step Out
        </button>
        <button className="stk-btn" onClick={handleContinue} disabled={!canContinue}>
          ▶ Continue
        </button>
        <button className="stk-btn stk-btn--danger" onClick={handleStop} disabled={!canStop}>
          ■ Stop
        </button>

        {snapshot && (
          <>
            <button
              className="stk-btn stk-btn--nav"
              onClick={() => onAddressSelect(snapshot.registers.rip)}
              title="Navigate disassembly to RIP"
            >
              ⟶ Disasm
            </button>
            <button
              className="stk-btn stk-btn--nav"
              onClick={() => onNavigateHex(snapshot.registers.rip)}
              title="Navigate hex to RIP"
            >
              ⟶ Hex
            </button>
          </>
        )}

        <div className="stk-bp-input">
          <input
            className="stk-bp-field"
            value={bpInput}
            onChange={e => setBpInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleAddBreakpoint()}
            placeholder="Breakpoint addr (hex)"
            spellCheck={false}
          />
          <button
            className="stk-btn stk-btn--bp"
            onClick={handleAddBreakpoint}
            disabled={sessionId === null}
          >
            + BP
          </button>
        </div>

        <div className="stk-bp-input">
          <input
            className="stk-bp-field"
            value={pidInput}
            onChange={e => setPidInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleAttach()}
            placeholder="Attach to PID"
            spellCheck={false}
          />
          <button
            className="stk-btn stk-btn--bp"
            onClick={handleAttach}
            disabled={loading}
          >
            ⚡ Attach
          </button>
        </div>
      </div>

      {/* ── Error banner ────────────────────────────────────────────────────── */}
      {error && (
        <div className="stk-error-banner">
          <span>⚠ {error}</span>
          <button className="stk-error-dismiss" onClick={() => setError(null)}>✕</button>
        </div>
      )}

      {/* ── Pattern alerts ──────────────────────────────────────────────────── */}
      {patterns.length > 0 && (
        <div className="stk-patterns">
          {patterns.map(p => (
            <PatternBadge
              key={p.tag}
              pattern={p}
              onSeek={i => timeline && playStep(timeline, i)}
            />
          ))}
        </div>
      )}

      {/* ── Body ────────────────────────────────────────────────────────────── */}
      <div className="stk-body">
        {/* Registers */}
        <div className="stk-pane stk-pane--regs">
          <div className="stk-pane-title">Registers</div>
          {snapshot ? (
            <RegisterGrid
              regs={snapshot.registers}
              changed={changedRegs}
              onNav={onAddressSelect}
            />
          ) : (
            <div className="stk-empty">Not running</div>
          )}
        </div>

        {/* Delta */}
        <div className="stk-pane stk-pane--delta">
          <div className="stk-pane-title">
            Delta
            {step && <span className="stk-pane-step-badge">step #{step.index}</span>}
          </div>
          <DeltaPanel delta={delta} />

          {/* Breakpoints */}
          {snapshot && snapshot.breakpoints.length > 0 && (
            <div className="stk-bp-section">
              <div className="stk-pane-title stk-pane-title--sub">Breakpoints</div>
              {snapshot.breakpoints.map(addr => (
                <div
                  key={addr}
                  className={`stk-bp-row${addr === snapshot.registers.rip ? ' stk-bp-row--hit' : ''}`}
                >
                  <span
                    className="stk-bp-addr clickable"
                    onClick={() => onAddressSelect(addr)}
                  >
                    0x{hexShort(addr)}
                  </span>
                  <button
                    className="stk-bp-remove"
                    onClick={() => handleRemoveBreakpoint(addr)}
                  >
                    ✕
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Stack */}
        <div className="stk-pane stk-pane--stack">
          <div className="stk-pane-title">Stack</div>
          {snapshot ? (
            <StackPane
              stack={snapshot.stack}
              rsp={snapshot.registers.rsp}
              onNav={onAddressSelect}
            />
          ) : (
            <div className="stk-empty">Not running</div>
          )}
        </div>
      </div>

      {/* ── Timeline strip ──────────────────────────────────────────────────── */}
      {timeline && (
        <div className="stk-timeline-section">
          <div className="stk-pane-title">
            Timeline
            {timeline.steps.length > 0 && (
              <span className="stk-tl-nav">
                <button
                  className="stk-tl-nav-btn"
                  onClick={() => playStep(timeline, (timeline.playheadIndex ?? 0) - 1)}
                  disabled={timeline.playheadIndex <= 0}
                >
                  ◀
                </button>
                <span className="stk-tl-pos">
                  {timeline.playheadIndex + 1} / {timeline.steps.length}
                </span>
                <button
                  className="stk-tl-nav-btn"
                  onClick={() => playStep(timeline, (timeline.playheadIndex ?? 0) + 1)}
                  disabled={timeline.playheadIndex >= timeline.steps.length - 1}
                >
                  ▶
                </button>
              </span>
            )}
          </div>
          <TimelineStrip
            timeline={timeline}
            onSeek={i => playStep(timeline, i)}
          />
        </div>
      )}

      {/* ── Empty state ─────────────────────────────────────────────────────── */}
      {!snapshot && !loading && (
        <div className="stk-splash">
          <div className="stk-splash-title">STRIKE</div>
          <div className="stk-splash-sub">Runtime validation + behavioral analysis</div>
          <div className="stk-splash-hint">
            {binaryPath ? 'Click ⊞ Load to begin a debug session' : 'Open a binary first'}
          </div>
        </div>
      )}
    </div>
  );
};

export default StrikeView;
