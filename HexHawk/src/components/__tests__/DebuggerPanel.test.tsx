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
