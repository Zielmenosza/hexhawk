import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import DebuggerPanel, { type DebugSnapshot } from '../DebuggerPanel';
import { invoke } from '@tauri-apps/api/core';

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

const baseSnapshot = (overrides: Partial<DebugSnapshot> = {}): DebugSnapshot => ({
  sessionId: 1,
  status: 'Paused',
  registers: {
    rax: 0, rbx: 0, rcx: 0, rdx: 0,
    rsi: 0, rdi: 0, rsp: 0x700000, rbp: 0x700100,
    rip: 0x401000,
    r8: 0, r9: 0, r10: 0, r11: 0,
    r12: 0, r13: 0, r14: 0, r15: 0,
    eflags: 0x202, cs: 0x33, ss: 0x2b,
  },
  stack: [],
  callStack: [],
  breakpoints: [],
  stepCount: 0,
  exitCode: null,
  lastEvent: 'system-breakpoint',
  warnings: [],
  ...overrides,
});

describe('DebuggerPanel call stack display', () => {
  beforeEach(() => {
    vi.mocked(invoke).mockReset();
  });

  it('renders runtime call stack frames when the snapshot includes advisory frames', async () => {
    vi.mocked(invoke).mockResolvedValueOnce({
      sessionId: 1,
      arch: 'x86-64',
      warnings: [],
      snapshot: baseSnapshot({
        stack: [0x401050],
        callStack: [{
          frameIndex: 0,
          returnAddress: 0x401050,
          framePointer: 0x700100,
          moduleName: 'kernel32.dll',
          symbolName: 'CreateFileW',
        }],
      }),
    });

    render(<DebuggerPanel binaryPath="C:/tmp/sample.exe" onAddressSelect={vi.fn()} onNavigateHex={vi.fn()} />);
    fireEvent.click(screen.getByText('▶ Launch'));
    await waitFor(() => expect(screen.getByText(/Stack \(1\) \/ Calls \(1\)/)).toBeInTheDocument());

    fireEvent.click(screen.getByText(/Stack \(1\) \/ Calls \(1\)/));

    expect(screen.getByText('runtime call stack — advisory evidence')).toBeInTheDocument();
    expect(screen.getByText('kernel32.dll!CreateFileW')).toBeInTheDocument();
    expect(screen.getByText('#0')).toBeInTheDocument();
  });

  it('renders an empty call stack without error', async () => {
    vi.mocked(invoke).mockResolvedValueOnce({
      sessionId: 1,
      arch: 'x86-64',
      warnings: [],
      snapshot: baseSnapshot({ callStack: [] }),
    });

    render(<DebuggerPanel binaryPath="C:/tmp/sample.exe" onAddressSelect={vi.fn()} onNavigateHex={vi.fn()} />);
    fireEvent.click(screen.getByText('▶ Launch'));
    await waitFor(() => expect(screen.getByText(/Stack \(0\) \/ Calls \(0\)/)).toBeInTheDocument());

    fireEvent.click(screen.getByText(/Stack \(0\) \/ Calls \(0\)/));

    expect(screen.getByText('runtime call stack — advisory evidence')).toBeInTheDocument();
    expect(screen.getByText('Call stack unavailable')).toBeInTheDocument();
  });
});

describe('DebuggerPanel conditional breakpoints', () => {
  beforeEach(() => {
    vi.mocked(invoke).mockReset();
  });

  it('renders condition text and hit count for a breakpoint', async () => {
    vi.mocked(invoke).mockResolvedValueOnce({
      sessionId: 1,
      arch: 'x86-64',
      warnings: [],
      snapshot: baseSnapshot({
        breakpoints: [{ address: 0x401000, enabled: true, condition: 'rax == 0', hitCount: 3, lastEvaluation: 'condition true at hit 3' }],
      }),
    });

    render(<DebuggerPanel binaryPath="C:/tmp/sample.exe" onAddressSelect={vi.fn()} onNavigateHex={vi.fn()} />);
    fireEvent.click(screen.getByText('▶ Launch'));
    await waitFor(() => expect(screen.getByText(/Breakpoints \(1\)/)).toBeInTheDocument());

    fireEvent.click(screen.getByText(/Breakpoints \(1\)/));

    expect(screen.getByText('if rax == 0')).toBeInTheDocument();
    expect(screen.getByText('hits 3')).toBeInTheDocument();
    expect(screen.getByText('condition true at hit 3')).toBeInTheDocument();
  });

  it('allows entering a condition when adding a breakpoint', async () => {
    vi.mocked(invoke).mockResolvedValueOnce({ sessionId: 1, arch: 'x86-64', warnings: [], snapshot: baseSnapshot() });
    vi.mocked(invoke).mockResolvedValueOnce(baseSnapshot({
      breakpoints: [{ address: 0x401020, enabled: true, condition: 'hit_count >= 3', hitCount: 0, lastEvaluation: null }],
    }));

    render(<DebuggerPanel binaryPath="C:/tmp/sample.exe" onAddressSelect={vi.fn()} onNavigateHex={vi.fn()} />);
    fireEvent.click(screen.getByText('▶ Launch'));
    await waitFor(() => expect(screen.getByText(/Breakpoints \(0\)/)).toBeInTheDocument());
    fireEvent.click(screen.getByText(/Breakpoints \(0\)/));

    fireEvent.change(screen.getByLabelText('breakpoint address'), { target: { value: '0x401020' } });
    fireEvent.change(screen.getByLabelText('breakpoint condition'), { target: { value: 'hit_count >= 3' } });
    fireEvent.click(screen.getByText('Add BP'));

    await waitFor(() => expect(vi.mocked(invoke)).toHaveBeenLastCalledWith('debug_set_breakpoint', {
      sessionId: 1,
      address: 0x401020,
      condition: 'hit_count >= 3',
    }));
  });

  it('renders invalid-condition warnings from snapshots', async () => {
    vi.mocked(invoke).mockResolvedValueOnce({
      sessionId: 1,
      arch: 'x86-64',
      warnings: [],
      snapshot: baseSnapshot({ warnings: ['invalid breakpoint condition at 0x401000: unsafe text; breakpoint fired'] }),
    });

    render(<DebuggerPanel binaryPath="C:/tmp/sample.exe" onAddressSelect={vi.fn()} onNavigateHex={vi.fn()} />);
    fireEvent.click(screen.getByText('▶ Launch'));

    await waitFor(() => expect(screen.getByText(/invalid breakpoint condition/)).toBeInTheDocument());
  });

  it('renders legacy numeric breakpoints normally', async () => {
    vi.mocked(invoke).mockResolvedValueOnce({
      sessionId: 1,
      arch: 'x86-64',
      warnings: [],
      snapshot: baseSnapshot({ breakpoints: [0x401000] }),
    });

    render(<DebuggerPanel binaryPath="C:/tmp/sample.exe" onAddressSelect={vi.fn()} onNavigateHex={vi.fn()} />);
    fireEvent.click(screen.getByText('▶ Launch'));
    await waitFor(() => expect(screen.getByText(/Breakpoints \(1\)/)).toBeInTheDocument());
    fireEvent.click(screen.getByText(/Breakpoints \(1\)/));

    expect(screen.getByText('0x0000000000401000')).toBeInTheDocument();
  });
});
