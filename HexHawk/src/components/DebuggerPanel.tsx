/**
 * DebuggerPanel — Minimal Native Debugger UI
 *
 * Connects to the Rust debug backend (Windows Debug API) to provide:
 *   - Single-step execution
 *   - Register inspection with change highlighting
 *   - Stack view (16 qwords at RSP)
 *   - Software breakpoints (add/remove by address)
 *   - Memory preview at RIP
 *   - Sync with Disassembly / Hex tabs
 */

import React, { useCallback, useMemo, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

// ── Types mirroring Rust structs ──────────────────────────────────────────────

export interface RegisterState {
  rax: number; rbx: number; rcx: number; rdx: number;
  rsi: number; rdi: number; rsp: number; rbp: number;
  rip: number;
  r8: number;  r9: number;  r10: number; r11: number;
  r12: number; r13: number; r14: number; r15: number;
  eflags: number;
  cs: number;  ss: number;
}

export type DebugStatus = 'Starting' | 'Paused' | 'Running' | 'Exited' | 'Error';

export interface DebugSnapshot {
  sessionId: number;
  status: DebugStatus;
  registers: RegisterState;
  stack: number[];
  breakpoints: number[];
  stepCount: number;
  exitCode: number | null;
  lastEvent: string;
}

export interface StartDebugResult {
  sessionId: number;
  snapshot: DebugSnapshot;
  arch: string;
  warnings: string[];
}

// ── Props ─────────────────────────────────────────────────────────────────────

interface DebuggerPanelProps {
  binaryPath: string | null;
  onAddressSelect: (address: number) => void;
  onNavigateHex: (address: number) => void;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const hex = (n: number, pad = 16): string =>
  '0x' + n.toString(16).toUpperCase().padStart(pad, '0');

const hexShort = (n: number): string =>
  '0x' + n.toString(16).toUpperCase().padStart(8, '0');

const EFLAGS_BITS: Array<[number, string, string]> = [
  [0x0001, 'CF', 'Carry'],
  [0x0004, 'PF', 'Parity'],
  [0x0010, 'AF', 'Adjust'],
  [0x0040, 'ZF', 'Zero'],
  [0x0080, 'SF', 'Sign'],
  [0x0100, 'TF', 'Trap'],
  [0x0200, 'IF', 'Interrupt'],
  [0x0400, 'DF', 'Direction'],
  [0x0800, 'OF', 'Overflow'],
];

const REG_NAMES = [
  'rax','rbx','rcx','rdx','rsi','rdi','rsp','rbp','rip',
  'r8','r9','r10','r11','r12','r13','r14','r15',
] as const;
type RegName = typeof REG_NAMES[number];

function regChanged(prev: RegisterState | null, cur: RegisterState, name: RegName): boolean {
  if (!prev) return false;
  return prev[name] !== cur[name];
}

// ── Sub-components ────────────────────────────────────────────────────────────

interface RegisterGridProps {
  registers: RegisterState;
  prev: RegisterState | null;
  onNavigate: (addr: number) => void;
}

const RegisterGrid: React.FC<RegisterGridProps> = ({ registers, prev, onNavigate }) => {
  const rows: Array<[RegName, string]> = [
    ['rax','RAX'],['rbx','RBX'],['rcx','RCX'],['rdx','RDX'],
    ['rsi','RSI'],['rdi','RDI'],['rsp','RSP'],['rbp','RBP'],
    ['rip','RIP'],
    ['r8','R8'], ['r9','R9'], ['r10','R10'],['r11','R11'],
    ['r12','R12'],['r13','R13'],['r14','R14'],['r15','R15'],
  ];

  return (
    <div className="dbg-reg-grid">
      {rows.map(([key, label]) => {
        const val = registers[key];
        const changed = regChanged(prev, registers, key);
        const isAddr = key === 'rip' || key === 'rsp' || key === 'rbp';
        return (
          <div
            key={key}
            className={`dbg-reg-row${changed ? ' dbg-reg-row--changed' : ''}`}
            title={changed ? 'Changed this step' : undefined}
          >
            <span className="dbg-reg-name">{label}</span>
            <span
              className={`dbg-reg-value${isAddr ? ' dbg-reg-value--addr' : ''}`}
              onClick={isAddr ? () => onNavigate(val) : undefined}
              style={isAddr ? { cursor: 'pointer' } : undefined}
              title={isAddr ? `Navigate to ${hex(val)}` : undefined}
            >
              {hex(val)}
            </span>
          </div>
        );
      })}
      {/* EFLAGS */}
      <div className="dbg-reg-row dbg-reg-flags-row">
        <span className="dbg-reg-name">EFLAGS</span>
        <span className="dbg-reg-flags">
          {EFLAGS_BITS.map(([bit, abbr, name]) => (
            <span
              key={abbr}
              className={`dbg-flag${registers.eflags & bit ? ' dbg-flag--set' : ''}`}
              title={name}
            >
              {abbr}
            </span>
          ))}
        </span>
      </div>
    </div>
  );
};

interface StackViewProps {
  stack: number[];
  rsp: number;
  onNavigate: (addr: number) => void;
}

const StackView: React.FC<StackViewProps> = ({ stack, rsp, onNavigate }) => (
  <div className="dbg-stack">
    {stack.length === 0 ? (
      <div className="dbg-empty">Stack not readable</div>
    ) : (
      stack.map((val, i) => {
        const addr = rsp + i * 8;
        return (
          <div key={i} className={`dbg-stack-row${i === 0 ? ' dbg-stack-row--top' : ''}`}>
            <span
              className="dbg-stack-addr"
              onClick={() => onNavigate(addr)}
              title="Navigate to address"
            >
              {hexShort(addr)}
            </span>
            <span className="dbg-stack-value">{hex(val)}</span>
          </div>
        );
      })
    )}
  </div>
);

interface BreakpointListProps {
  breakpoints: number[];
  currentRip: number;
  onRemove: (addr: number) => void;
  onNavigate: (addr: number) => void;
}

const BreakpointList: React.FC<BreakpointListProps> = ({
  breakpoints, currentRip, onRemove, onNavigate,
}) => (
  <div className="dbg-bplist">
    {breakpoints.length === 0 ? (
      <div className="dbg-empty">No breakpoints set</div>
    ) : (
      breakpoints.map((addr) => (
        <div
          key={addr}
          className={`dbg-bp-row${addr === currentRip ? ' dbg-bp-row--hit' : ''}`}
        >
          <span
            className="dbg-bp-addr"
            onClick={() => onNavigate(addr)}
            title="Navigate to breakpoint"
          >
            {hex(addr)}
          </span>
          {addr === currentRip && <span className="dbg-bp-badge">● HIT</span>}
          <button
            className="dbg-bp-remove"
            onClick={() => onRemove(addr)}
            title="Remove breakpoint"
          >
            ✕
          </button>
        </div>
      ))
    )}
  </div>
);

// ── Status badge ──────────────────────────────────────────────────────────────

const StatusBadge: React.FC<{ status: DebugStatus; stepCount: number; lastEvent: string }> = ({
  status, stepCount, lastEvent,
}) => {
  const colors: Record<DebugStatus, string> = {
    Starting: '#888',
    Paused:   '#00d4ff',
    Running:  '#4caf50',
    Exited:   '#ff9800',
    Error:    '#f44336',
  };
  return (
    <span className="dbg-status-badge" style={{ borderColor: colors[status], color: colors[status] }}>
      {status === 'Paused'  ? '⏸ PAUSED' :
       status === 'Running' ? '▶ RUNNING' :
       status === 'Exited'  ? '⏹ EXITED' :
       status === 'Error'   ? '✕ ERROR' : '… STARTING'}
      {status === 'Paused' && stepCount > 0 && (
        <span className="dbg-step-count"> step {stepCount}</span>
      )}
      {lastEvent && lastEvent !== 'system-breakpoint' && (
        <span className="dbg-last-event"> [{lastEvent}]</span>
      )}
    </span>
  );
};

// ── Main component ────────────────────────────────────────────────────────────

const DebuggerPanel: React.FC<DebuggerPanelProps> = ({
  binaryPath,
  onAddressSelect,
  onNavigateHex,
}) => {
  const [session, setSession] = useState<DebugSnapshot | null>(null);
  const [sessionId, setSessionId] = useState<number | null>(null);
  const [prevRegs, setPrevRegs] = useState<RegisterState | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [newBpInput, setNewBpInput] = useState('');
  const [memoryBytes, setMemoryBytes] = useState<number[] | null>(null);
  const [activeSection, setActiveSection] = useState<'regs' | 'stack' | 'memory' | 'bps'>('regs');
  const bpInputRef = useRef<HTMLInputElement>(null);

  const applySnapshot = useCallback((snap: DebugSnapshot) => {
    setSession((prev) => {
      setPrevRegs(prev?.registers ?? null);
      return snap;
    });
  }, []);

  const withLoading = useCallback(
    async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
      setIsLoading(true);
      setError(null);
      try {
        return await fn();
      } catch (e) {
        setError(String(e));
        return undefined;
      } finally {
        setIsLoading(false);
      }
    },
    [],
  );

  const handleStart = async () => {
    if (!binaryPath) { setError('No binary loaded — open a file first'); return; }
    await withLoading(async () => {
      const result = await invoke<StartDebugResult>('start_debug_session', {
        path: binaryPath,
        args: [],
      });
      setSessionId(result.sessionId);
      applySnapshot(result.snapshot);
      setWarnings(result.warnings);
      setMemoryBytes(null);
    });
  };

  const handleStep = async () => {
    if (sessionId === null) return;
    await withLoading(async () => {
      const snap = await invoke<DebugSnapshot>('debug_step', { sessionId });
      applySnapshot(snap);
      setMemoryBytes(null);
    });
  };

  const handleContinue = async () => {
    if (sessionId === null) return;
    await withLoading(async () => {
      const snap = await invoke<DebugSnapshot>('debug_continue', { sessionId });
      applySnapshot(snap);
      setMemoryBytes(null);
    });
  };

  const handleStop = async () => {
    if (sessionId === null) return;
    await withLoading(async () => {
      await invoke<void>('debug_stop', { sessionId });
    });
    setSession(null);
    setSessionId(null);
    setPrevRegs(null);
    setMemoryBytes(null);
    setWarnings([]);
  };

  const handleAddBreakpoint = async () => {
    if (sessionId === null) return;
    const raw = newBpInput.trim();
    const addr = raw.startsWith('0x') || raw.startsWith('0X')
      ? parseInt(raw, 16)
      : parseInt(raw, 10);
    if (isNaN(addr)) { setError(`Invalid address: ${raw}`); return; }
    setNewBpInput('');
    await withLoading(async () => {
      const snap = await invoke<DebugSnapshot>('debug_set_breakpoint', { sessionId, address: addr });
      applySnapshot(snap);
    });
  };

  const handleRemoveBreakpoint = async (addr: number) => {
    if (sessionId === null) return;
    await withLoading(async () => {
      const snap = await invoke<DebugSnapshot>('debug_remove_breakpoint', { sessionId, address: addr });
      applySnapshot(snap);
    });
  };

  const handleReadMemory = async () => {
    if (sessionId === null || !session) return;
    const addr = session.registers.rip;
    await withLoading(async () => {
      const bytes = await invoke<number[]>('debug_read_memory', { sessionId, address: addr, size: 64 });
      setMemoryBytes(bytes);
    });
  };

  const handleSyncDisasm = () => {
    if (session) onAddressSelect(session.registers.rip);
  };

  const handleSyncHex = () => {
    if (session) onNavigateHex(session.registers.rip);
  };

  const isActive = sessionId !== null && session !== null;
  const isPaused = session?.status === 'Paused';
  const isExited = session?.status === 'Exited';

  const memHexRows = useMemo(() => {
    if (!memoryBytes || memoryBytes.length === 0) return [];
    const rows: Array<{ addr: number; bytes: number[] }> = [];
    const base = session?.registers.rip ?? 0;
    for (let i = 0; i < memoryBytes.length; i += 16) {
      rows.push({ addr: base + i, bytes: memoryBytes.slice(i, i + 16) });
    }
    return rows;
  }, [memoryBytes, session?.registers.rip]);

  return (
    <div className="dbg-root">
      {/* Toolbar */}
      <div className="dbg-toolbar">
        <div className="dbg-toolbar-left">
          <span className="dbg-toolbar-title">⚙ Debugger</span>
          {binaryPath && (
            <span className="dbg-binary-name" title={binaryPath}>
              {binaryPath.split(/[/\\]/).pop()}
            </span>
          )}
          {session && (
            <StatusBadge
              status={session.status}
              stepCount={session.stepCount}
              lastEvent={session.lastEvent}
            />
          )}
        </div>

        <div className="dbg-toolbar-right">
          {!isActive ? (
            <button
              className="dbg-btn dbg-btn--primary"
              onClick={handleStart}
              disabled={isLoading || !binaryPath}
              title="Launch binary under debugger"
            >
              ▶ Launch
            </button>
          ) : (
            <>
              <button
                className="dbg-btn"
                onClick={handleStep}
                disabled={isLoading || !isPaused}
                title="Step one instruction (F10)"
              >
                ⤵ Step
              </button>
              <button
                className="dbg-btn"
                onClick={handleContinue}
                disabled={isLoading || !isPaused}
                title="Continue to next breakpoint"
              >
                ▶ Continue
              </button>
              <button
                className="dbg-btn"
                onClick={handleReadMemory}
                disabled={isLoading || !isPaused}
                title="Read memory at RIP"
              >
                Mem@RIP
              </button>
              <button
                className="dbg-btn"
                onClick={handleSyncDisasm}
                disabled={!isPaused}
                title="Show RIP in Disassembly"
              >
                → Disasm
              </button>
              <button
                className="dbg-btn"
                onClick={handleSyncHex}
                disabled={!isPaused}
                title="Show RIP in Hex Viewer"
              >
                → Hex
              </button>
              <button
                className="dbg-btn dbg-btn--danger"
                onClick={handleStop}
                disabled={isLoading || isExited}
                title="Terminate process and end session"
              >
                ■ Stop
              </button>
            </>
          )}
          {isLoading && <span className="dbg-spinner">⏳</span>}
        </div>
      </div>

      {/* Warnings */}
      {warnings.length > 0 && (
        <div className="dbg-warnings">
          {warnings.map((w, i) => (
            <div key={i} className="dbg-warning-item">⚠ {w}</div>
          ))}
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="dbg-error">
          <span className="dbg-error-icon">✕</span>
          <span>{error}</span>
          <button className="dbg-error-dismiss" onClick={() => setError(null)}>✕</button>
        </div>
      )}

      {/* Platform note when no session */}
      {!isActive && !isLoading && (
        <div className="dbg-empty-state">
          <div className="dbg-empty-title">Native Debugger</div>
          <div className="dbg-empty-body">
            <p>Launches the binary as a child process under Windows Debug API control.</p>
            <ul>
              <li>Starts paused at the system breakpoint (ntdll)</li>
              <li>Single-step with trap flag (EFLAGS.TF)</li>
              <li>Software breakpoints via INT3 (0xCC) patching</li>
              <li>Reads register context after each step</li>
            </ul>
            <p className="dbg-note">Windows only. x86-64 PE binaries.</p>
          </div>
        </div>
      )}

      {/* Main content */}
      {isActive && session && (
        <div className="dbg-content">
          {/* Section nav */}
          <div className="dbg-section-nav">
            {(['regs', 'stack', 'bps', 'memory'] as const).map((s) => (
              <button
                key={s}
                className={`dbg-section-tab${activeSection === s ? ' active' : ''}`}
                onClick={() => setActiveSection(s)}
              >
                {s === 'regs'   ? 'Registers' :
                 s === 'stack'  ? `Stack (${session.stack.length})` :
                 s === 'bps'    ? `Breakpoints (${session.breakpoints.length})` :
                 'Memory'}
              </button>
            ))}
          </div>

          <div className="dbg-panel-body">
            {/* Registers */}
            {activeSection === 'regs' && (
              <div className="dbg-section">
                <RegisterGrid
                  registers={session.registers}
                  prev={prevRegs}
                  onNavigate={onAddressSelect}
                />
              </div>
            )}

            {/* Stack */}
            {activeSection === 'stack' && (
              <div className="dbg-section">
                <div className="dbg-section-header">
                  Stack at RSP = {hex(session.registers.rsp)}
                </div>
                <StackView
                  stack={session.stack}
                  rsp={session.registers.rsp}
                  onNavigate={onAddressSelect}
                />
              </div>
            )}

            {/* Breakpoints */}
            {activeSection === 'bps' && (
              <div className="dbg-section">
                <div className="dbg-add-bp">
                  <input
                    ref={bpInputRef}
                    className="dbg-input"
                    value={newBpInput}
                    onChange={(e) => setNewBpInput(e.target.value)}
                    placeholder="0x4012a0 or decimal"
                    onKeyDown={(e) => e.key === 'Enter' && handleAddBreakpoint()}
                  />
                  <button
                    className="dbg-btn dbg-btn--primary"
                    onClick={handleAddBreakpoint}
                    disabled={!newBpInput.trim() || isLoading}
                  >
                    Add BP
                  </button>
                </div>
                <BreakpointList
                  breakpoints={session.breakpoints}
                  currentRip={session.registers.rip}
                  onRemove={handleRemoveBreakpoint}
                  onNavigate={onAddressSelect}
                />
              </div>
            )}

            {/* Memory preview */}
            {activeSection === 'memory' && (
              <div className="dbg-section">
                {memHexRows.length === 0 ? (
                  <div className="dbg-empty">
                    Click <strong>Mem@RIP</strong> to read memory at the current instruction pointer.
                  </div>
                ) : (
                  <div className="dbg-mem-view">
                    {memHexRows.map((row, ri) => (
                      <div key={ri} className="dbg-mem-row">
                        <span className="dbg-mem-addr">{hexShort(row.addr)}</span>
                        <span className="dbg-mem-bytes">
                          {row.bytes.map((b, bi) => (
                            <span
                              key={bi}
                              className={`dbg-mem-byte${ri === 0 && bi === 0 ? ' dbg-mem-byte--rip' : ''}`}
                            >
                              {b.toString(16).padStart(2, '0').toUpperCase()}
                            </span>
                          ))}
                        </span>
                        <span className="dbg-mem-ascii">
                          {row.bytes
                            .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.'))
                            .join('')}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Exit info */}
          {isExited && (
            <div className="dbg-exit-banner">
              Process exited with code {session.exitCode ?? '?'} after {session.stepCount} steps.
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default DebuggerPanel;
