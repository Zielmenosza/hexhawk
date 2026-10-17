import React from 'react';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from '../../App';
import { invoke } from '@tauri-apps/api/core';
import { open } from '@tauri-apps/plugin-dialog';
import { computeVerdict } from '../../utils/correlationEngine';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(async () => () => {}) }));
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn() }));
vi.mock('../../utils/correlationEngine', async importOriginal => {
  const actual = await importOriginal<typeof import('../../utils/correlationEngine')>();
  return { ...actual, computeVerdict: vi.fn(actual.computeVerdict) };
});
// Only peripheral presentation is replaced. Selection, handlers, state,
// analysis adapter, GYRE calculation and native invoke orchestration are real App.
vi.mock('../ActionBar', () => ({ default: (p: any) => <div>
  {['Inspect', 'ScanStrings', 'Disassemble', 'BuildCfg', 'RunAnalysis', 'Export'].map(action =>
    <button key={action} data-testid={`test-${action}`} onClick={() => p[`on${action}`]()}>{action}</button>)}
  <output data-testid="test-loading">{String(p.disassemblyLoading)}</output>
</div> }));
vi.mock('../NestView', () => ({ default: (p: any) => <div>
  <button data-testid="test-training" onClick={() => p.onLoadTrainingBinary('B.exe')}>Training</button>
  <output data-testid="test-evidence">{JSON.stringify({ path: p.binaryPath, sha: p.metadata?.sha256 ?? null,
    strings: p.strings, instructions: p.disassembly, patterns: p.disassemblyAnalysis.suspiciousPatterns })}</output>
</div> }));
// Presentation-only fixture expansion: expose the report's real App navigation
// callback; export validation remains covered by the real report component tests.
const reportNavigation = vi.hoisted(() => ({ current: null as ((view: string) => void) | null }));
vi.mock('../IntelligenceReport', () => ({ IntelligenceReport: (p: any) => {
  reportNavigation.current = p.onNavigate;
  return <div data-testid="test-report-route" />;
} }));

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const meta = (path: string) => ({ file_type: 'PE', architecture: 'x86_64', file_size: 8192,
  entry_point: 0, sections: [], imports: [], exports: [], sha256: path === 'A.exe' ? 'a'.repeat(64) : 'b'.repeat(64), sha1: '', md5: '' });
const disasm = (mnemonic = 'ret') => ({ arch: 'x86_64', is_fallback: false, has_more: false, next_byte_offset: 1,
  instructions: [{ address: 0, mnemonic, operands: '', bytes: [0xc3], size: 1 }] });
const invokeMock = vi.mocked(invoke);
function evidence() {
  fireEvent.click(screen.getByTestId('nav-nest'));
  return JSON.parse(screen.getByTestId('test-evidence').textContent!);
}
function apply(path: string) {
  fireEvent.click(screen.getByTestId('nav-load'));
  fireEvent.change(screen.getByTestId('load-path-input'), { target: { value: path } });
  fireEvent.click(screen.getByTestId('load-apply-path'));
}
async function settle() { await act(async () => { await Promise.resolve(); }); }
async function inspect() { fireEvent.click(screen.getByTestId('test-Inspect')); await settle(); }

beforeEach(() => {
  reportNavigation.current = null;
  localStorage.clear();
  localStorage.setItem('hexhawk.firstRunComplete', 'true');
  localStorage.setItem('hexhawk.tier', 'enterprise');
  localStorage.setItem('hexhawk.binaryPath', 'A.exe');
  localStorage.setItem('hexhawk.activeView', 'load');
  Object.defineProperty(window, '__TAURI_INTERNALS__', { configurable: true, value: {} });
  vi.clearAllMocks();
  invokeMock.mockImplementation(async (command, args: any) => {
    if (command === 'inspect_file_metadata') return meta(args.path) as any;
    if (command === 'inspect_pe_extras') return { tls_callbacks: [], resources: [] } as any;
    if (command === 'list_available_plugins') return [] as any;
    if (command === 'find_strings') return [{ offset: 0, text: args.path, kind: 'ascii' }] as any;
    if (command === 'disassemble_file_range') return disasm() as any;
    if (command === 'build_cfg') return { nodes: [], edges: [] } as any;
    if (command === 'read_hex_range') return [0x42] as any;
    if (command === 'get_build_info') return { version: 'test', is_trial: false } as any;
    if (command === 'gyre_record_verdict_snapshot') return { snapshotId: 'test', binarySha256: args.request.binarySha256 } as any;
    return undefined as any;
  });
});
afterEach(() => { cleanup(); delete (window as any).__TAURI_INTERNALS__; });

describe('mounted App selected-file custody (mocked transport, not native runtime proof)', () => {
  it('navigates report guidance without starting static analysis implicitly', async () => {
    render(<App />); await settle(); await inspect();
    fireEvent.click(screen.getByTestId('nav-report'));
    invokeMock.mockClear();
    act(() => reportNavigation.current!('strings'));
    await settle();
    expect(localStorage.getItem('hexhawk.activeView')).toBe('strings');
    expect(invokeMock.mock.calls.some(([command]) => ['find_strings', 'disassemble_file_range', 'inspect_file_metadata'].includes(command))).toBe(false);
  });
  it.each(['replacement', 'same-path reinspection'])('rejects an old report callback after %s', async mode => {
    render(<App />); await settle(); await inspect();
    fireEvent.click(screen.getByTestId('nav-report'));
    const oldNavigation = reportNavigation.current!;
    if (mode === 'replacement') apply('B.exe');
    else await inspect();
    await settle();
    const viewBefore = localStorage.getItem('hexhawk.activeView');
    invokeMock.mockClear();
    act(() => oldNavigation('strings')); await settle();
    expect(localStorage.getItem('hexhawk.activeView')).toBe(viewBefore);
    expect(invokeMock).not.toHaveBeenCalled();
  });
  it('does not restore an excluded native workflow or scan/load plugins during startup', async () => {
    localStorage.setItem('hexhawk.activeView', 'repl');
    render(<App />); await settle();
    expect(screen.getByTestId('nav-load')).toHaveClass('wf-nav-item--active');
    expect(screen.getByTestId('nav-repl')).toBeDisabled();
    expect(screen.getByTestId('nav-plugins')).toBeDisabled();
    expect(invokeMock.mock.calls.filter(([command]) => ['list_available_plugins', 'run_plugins_on_file', 'create_repl_session'].includes(command))).toEqual([]);
  });

  it.each([
    { addresses: [0, 1], end: 4 },
    { addresses: [0], end: 2 },
  ])('uses the decoder exclusive end $end for a complete CFG range', async ({ addresses, end }) => {
    const normal = invokeMock.getMockImplementation()!;
    invokeMock.mockImplementation((command, args) => command === 'disassemble_file_range'
      ? Promise.resolve({ ...disasm(), next_byte_offset: end,
        instructions: addresses.map(address => ({ address, mnemonic: 'nop', operands: '' })) } as any)
      : normal(command, args));
    render(<App />); await inspect();
    fireEvent.click(screen.getByTestId('test-Disassemble')); await settle();
    fireEvent.click(screen.getByTestId('test-BuildCfg')); await settle();
    const args = invokeMock.mock.calls.filter(([command]) => command === 'build_cfg').at(-1)?.[1];
    expect(args).toMatchObject({ offset: 0, length: end, expectedSha256: 'a'.repeat(64) });
  });

  it.each(['status-export', 'test-Export'])('routes %s through the validated report surface instead of a second exporter', async trigger => {
    const create = vi.fn(() => 'blob:test');
    const original = URL.createObjectURL;
    URL.createObjectURL = create;
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    try {
      render(<App />); await inspect();
      fireEvent.click(screen.getByTestId(trigger));
      expect(screen.queryByTestId('test-report-route')).not.toBeNull();
      expect(create).not.toHaveBeenCalled();
    } finally { URL.createObjectURL = original; click.mockRestore(); }
  });

  it.each(['success', 'error'])('retains newer same-selection strings after an older %s', async outcome => {
    const first = deferred<any>(); const second = deferred<any>();
    let count = 0; const normal = invokeMock.getMockImplementation()!;
    invokeMock.mockImplementation((name, args) => name === 'find_strings' ? (++count === 1 ? first.promise : second.promise) : normal(name, args));
    render(<App />); await inspect();
    fireEvent.click(screen.getByTestId('test-ScanStrings'));
    fireEvent.click(screen.getByTestId('test-ScanStrings'));
    await act(async () => second.resolve([{ offset: 0, text: 'NEW', kind: 'ascii' }]));
    if (outcome === 'success') await act(async () => first.resolve([{ offset: 0, text: 'OLD', kind: 'ascii' }]));
    else await act(async () => first.reject(new Error('OLDER-REQUEST')));
    expect(evidence().strings[0]?.text).toBe('NEW');
    expect(document.querySelector('.wf-status-msg')).not.toHaveTextContent('OLDER-REQUEST');
  });

  it('keeps same-selection disassembly loading owned by the newest request', async () => {
    const first = deferred<any>(); const second = deferred<any>();
    let count = 0; const normal = invokeMock.getMockImplementation()!;
    invokeMock.mockImplementation((name, args) => name === 'disassemble_file_range' ? (++count === 1 ? first.promise : second.promise) : normal(name, args));
    render(<App />); await inspect();
    fireEvent.click(screen.getByTestId('test-Disassemble'));
    fireEvent.click(screen.getByTestId('test-Disassemble'));
    await act(async () => first.resolve(disasm('int3')));
    expect(screen.getByTestId('test-loading')).toHaveTextContent('true');
    expect(evidence().instructions).toEqual([]);
    await act(async () => second.resolve(disasm('ret')));
    expect(evidence().instructions[0].mnemonic).toBe('ret');
    expect(screen.getByTestId('test-loading')).toHaveTextContent('false');
  });

  it('sends inspected identity on every evidence command and the applied camel-case instruction limit', async () => {
    render(<App />); await inspect();
    for (const action of ['test-ScanStrings', 'test-Disassemble', 'test-BuildCfg']) {
      fireEvent.click(screen.getByTestId(action)); await settle();
    }
    for (const command of ['inspect_pe_extras', 'find_strings', 'disassemble_file_range', 'build_cfg']) {
      const args = invokeMock.mock.calls.find(call => call[0] === command)?.[1];
      expect(args).toMatchObject({ expectedSha256: 'a'.repeat(64) });
    }
    const args = invokeMock.mock.calls.find(call => call[0] === 'disassemble_file_range')![1] as any;
    expect(args.maxInstructions).toBeGreaterThan(0);
    expect(args).not.toHaveProperty('max_instructions');
  });

  it('keeps a typed draft out of selected identity and persisted evidence path', async () => {
    render(<App />); await inspect();
    fireEvent.click(screen.getByTestId('nav-load'));
    fireEvent.change(screen.getByTestId('load-path-input'), { target: { value: 'B.exe' } });
    expect(evidence()).toMatchObject({ path: 'A.exe', sha: 'a'.repeat(64) });
    expect(localStorage.getItem('hexhawk.binaryPath')).toBe('A.exe');
    fireEvent.click(screen.getByTestId('nav-load'));
    fireEvent.click(screen.getByTestId('load-apply-path'));
    expect(evidence()).toMatchObject({ path: 'B.exe', sha: null, strings: [], instructions: [], patterns: [] });
  });

  it('training selection clears existing metadata, strings, instructions and patterns', async () => {
    render(<App />); await inspect();
    fireEvent.click(screen.getByTestId('test-ScanStrings')); await settle();
    fireEvent.click(screen.getByTestId('test-Disassemble')); await settle();
    expect(evidence().instructions).toHaveLength(1);
    fireEvent.click(screen.getByTestId('test-training'));
    expect(evidence()).toMatchObject({ path: 'B.exe', sha: null, strings: [], instructions: [], patterns: [] });
  });

  it('re-inspection computes its corpus verdict from only fresh metadata, not closure-held evidence', async () => {
    render(<App />); await inspect();
    fireEvent.click(screen.getByTestId('test-ScanStrings')); await settle();
    expect(evidence().strings).toHaveLength(1);
    vi.mocked(computeVerdict).mockClear();
    await inspect();
    const inputs = vi.mocked(computeVerdict).mock.calls.map(call => call[0]);
    expect(inputs.every(input => input.strings.length === 0 && input.patterns.length === 0)).toBe(true);
    expect(evidence()).toMatchObject({ strings: [], instructions: [], patterns: [] });
  });

  it.each(['inspect_file_metadata', 'find_strings', 'disassemble_file_range', 'build_cfg', 'read_hex_range'])
  ('discards delayed %s success after selecting B', async command => {
    const held = deferred<any>();
    const normal = invokeMock.getMockImplementation()!;
    invokeMock.mockImplementation((name, args) => name === command && (args as any)?.path === 'A.exe' ? held.promise : normal(name, args));
    render(<App />);
    if (command !== 'inspect_file_metadata') await inspect();
    const actions: Record<string, string> = { inspect_file_metadata: 'test-Inspect', find_strings: 'test-ScanStrings',
      disassemble_file_range: 'test-Disassemble', build_cfg: 'test-BuildCfg' };
    if (command === 'read_hex_range') fireEvent.click(screen.getByTestId('nav-hex'));
    else fireEvent.click(screen.getByTestId(actions[command]));
    expect(invokeMock.mock.calls.some(call => call[0] === command && (call[1] as any)?.path === 'A.exe')).toBe(true);
    apply('B.exe'); await inspect();
    const before = evidence();
    const values: Record<string, any> = { inspect_file_metadata: meta('A.exe'), find_strings: [{ offset: 0, text: 'OLD-A', kind: 'ascii' }],
      disassemble_file_range: disasm('int3'), build_cfg: { nodes: [], edges: [] }, read_hex_range: [0x41] };
    await act(async () => held.resolve(values[command]));
    expect(evidence()).toEqual(before);
    expect(document.querySelector('.wf-status-msg')).toHaveTextContent('File inspection completed');
    expect(screen.getByTestId('status-export')).not.toBeDisabled();
  });

  it('discards an old inspection error instead of clearing B metadata', async () => {
    const held = deferred<any>();
    const normal = invokeMock.getMockImplementation()!;
    invokeMock.mockImplementation((name, args) => name === 'inspect_file_metadata' && (args as any)?.path === 'A.exe' ? held.promise : normal(name, args));
    render(<App />); fireEvent.click(screen.getByTestId('test-Inspect'));
    apply('B.exe'); await inspect();
    await act(async () => held.reject(new Error('OLD-A error')));
    expect(evidence()).toMatchObject({ path: 'B.exe', sha: 'b'.repeat(64) });
    expect(document.querySelector('.wf-status-msg')).not.toHaveTextContent('OLD-A error');
  });

  it('invalidates same-path work on re-inspect and keeps newer disassembly loading owned by B', async () => {
    const first = deferred<any>(); const second = deferred<any>();
    let count = 0; const normal = invokeMock.getMockImplementation()!;
    invokeMock.mockImplementation((name, args) => name === 'disassemble_file_range' ? (++count === 1 ? first.promise : second.promise) : normal(name, args));
    render(<App />); await inspect(); fireEvent.click(screen.getByTestId('test-Disassemble'));
    await inspect();
    fireEvent.click(screen.getByTestId('test-Disassemble'));
    await act(async () => first.resolve(disasm('int3')));
    expect(screen.getByTestId('test-loading')).toHaveTextContent('true');
    expect(evidence().instructions).toEqual([]);
    await act(async () => second.resolve(disasm()));
    expect(screen.getByTestId('test-loading')).toHaveTextContent('false');
    expect(evidence().instructions[0].mnemonic).toBe('ret');
  });

  it('does not continue a cancelled quick-analysis chain with old-file strings/CFG', async () => {
    const held = deferred<any>(); const normal = invokeMock.getMockImplementation()!;
    invokeMock.mockImplementation((name, args) => name === 'inspect_file_metadata' && (args as any)?.path === 'A.exe' ? held.promise : normal(name, args));
    render(<App />); fireEvent.click(screen.getByTestId('test-RunAnalysis'));
    apply('B.exe'); await inspect();
    await act(async () => held.resolve(meta('A.exe')));
    expect(invokeMock.mock.calls.filter(call => ['find_strings', 'disassemble_file_range', 'build_cfg'].includes(call[0]) && (call[1] as any)?.path === 'A.exe')).toEqual([]);
    expect(evidence()).toMatchObject({ path: 'B.exe', sha: 'b'.repeat(64) });
  });
});
