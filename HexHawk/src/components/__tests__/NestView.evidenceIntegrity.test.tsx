import React from 'react';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import NestView from '../NestView';
import { DEFAULT_NEST_CONFIG, createNestSession, computeVerdictStability } from '../../utils/nestEngine';
import { computeVerdict } from '../../utils/correlationEngine';

const mocks = vi.hoisted(() => ({ invoke: vi.fn(), step: vi.fn(), complete: vi.fn(), commit: vi.fn(), construct: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: mocks.invoke }));
vi.mock('../CorpusBenchmarkPanel', () => ({ default: () => null }));
vi.mock('../../utils/nestEngine', async (original) => {
  const actual = await original<typeof import('../../utils/nestEngine')>();
  return { ...actual, DEFAULT_NEST_CONFIG: { ...actual.DEFAULT_NEST_CONFIG, autoAdvance: false } };
});
// Actual rendered startSession -> handleStep -> real NestLifecycleCoordinator.
// Native IPC and the analysis runner are adapters mocked at their boundaries;
// this is not an installed/native application smoke test.
vi.mock('../../engines/nest/NestSessionRunner', () => ({
  NestSessionRunner: class {
    constructor(options: unknown) { mocks.construct(options); }
    session = { status: 'idle', iterations: [] };
    learningSession = {};
    disassembly = [];
    currentOffset = 0;
    currentLength = 16;
    decisions = [];
    step = mocks.step;
    commitPostProcessing = mocks.commit;
  },
  runNestSession: vi.fn(),
}));

function element(path = 'C:/fixtures/identity.bin', sha = 'a'.repeat(64)) {
  return <NestView binaryPath={path} gyreSnapshotId="gyresnap_recorded"
    metadata={{ sha256: sha, file_size: 16 } as never}
    disassembly={[]} strings={[]} disassemblyAnalysis={{} as never}
    disasmOffset={0} disasmLength={16} onAddressSelect={() => {}} onNestComplete={mocks.complete} />;
}
function mountAndStart() {
  const view = render(element());
  fireEvent.click(screen.getByRole('button', { name: /Start NEST Session/ }));
  return view;
}

function iterationFixture(status = 'running', shouldContinue = true) {
  const verdict = computeVerdict({ sections: [], imports: [], strings: [], patterns: [] });
  const snapshot = {
    iteration: 0, timestamp: Date.now(), input: { disasmOffset: 0, disasmLength: 16, instructionCount: 0, sections: [], imports: [], strings: [], patterns: [], signatureMatches: [] }, verdict, confidence: verdict.confidence,
    refinementPlan: null, delta: null, annotations: [], durationMs: 1,
    stabilityReport: computeVerdictStability([], verdict),
    reasoningChain: { verdict: verdict.classification, confidence: verdict.confidence,
      iteration: 0, topSignals: [], steps: [], narrative: 'Authored empty-analysis fixture', suggestions: [] },
  };
  const session = { ...createNestSession('C:/fixtures/identity.bin', DEFAULT_NEST_CONFIG),
    status, iterations: [snapshot], finalVerdict: shouldContinue ? null : verdict, endTime: shouldContinue ? null : Date.now() };
  return { session, snapshot, learningSession: { decisions: [] }, analysisPlan: null, shouldContinue };
}

beforeEach(() => {
  vi.clearAllMocks();
  const storage = new Map<string, string>();
  vi.stubGlobal('localStorage', {
    getItem: (key: string) => storage.get(key) ?? null,
    setItem: (key: string, value: string) => storage.set(key, value),
    removeItem: (key: string) => storage.delete(key),
    clear: () => storage.clear(),
  });
  mocks.step.mockResolvedValue(iterationFixture());
  mocks.invoke.mockImplementation(async (command: string) => {
    if (command === 'nest_create_session') return { sessionId: 'nestsession_active', binarySha256: 'a'.repeat(64), iterationCount: 0 };
    if (command === 'nest_verify_binary_identity') return { verified: true, mismatch: false, message: 'matched' };
    if (command === 'nest_append_iteration') return { iterationId: 'nestiter_canonical_0001', iterationCount: 1 };
    if (command === 'nest_finalize_session') return {};
    throw new Error(`Unexpected command ${command}`);
  });
});
afterEach(cleanup);

async function expectBlocked() {
  await waitFor(() => expect(screen.getByRole('button', { name: /Next Iteration/ })).not.toBeDisabled());
  expect(mocks.invoke.mock.calls.some(([command]) => command === 'nest_verify_binary_identity')).toBe(true);
  expect(mocks.step).not.toHaveBeenCalled();
  expect(mocks.invoke.mock.calls.filter(([command]) => ['nest_append_iteration', 'nest_finalize_session'].includes(command))).toEqual([]);
  expect(mocks.complete).not.toHaveBeenCalled();
  expect(document.querySelector('.nest-error')?.textContent).toContain('NEST fidelity gate:');
}

describe('NEST rendered identity custody flow', () => {
  it.each(['nest_append_iteration', 'nest_finalize_session'])('defers learning until held %s succeeds', async phase => {
    let resolve!: (value: unknown) => void;
    const held = new Promise<unknown>(yes => { resolve = yes; });
    const normal = mocks.invoke.getMockImplementation()!;
    mocks.step.mockResolvedValue(iterationFixture('max-reached', false));
    mocks.invoke.mockImplementation((command, args) => command === phase ? held : normal(command, args));
    mountAndStart();
    await waitFor(() => expect(mocks.invoke.mock.calls.some(([command]) => command === phase)).toBe(true));
    expect(mocks.construct.mock.calls[0][0]).toMatchObject({ deferStepPostProcessing: true });
    expect(mocks.commit).not.toHaveBeenCalled();
    expect(mocks.complete).not.toHaveBeenCalled();
    await act(async () => { resolve(phase === 'nest_append_iteration' ? { iterationId: 'nestiter_canonical_0001', iterationCount: 1 } : {}); await held; });
    await waitFor(() => expect(mocks.complete).toHaveBeenCalledTimes(1));
    expect(mocks.commit).toHaveBeenCalledTimes(1);
    expect(mocks.commit.mock.invocationCallOrder[0]).toBeLessThan(mocks.complete.mock.invocationCallOrder[0]);
  });

  it('retains entered work on Stop Early and clears intentional stop only for Resume', async () => {
    let reject!: (error: Error) => void;
    const held = new Promise<never>((_, no) => { reject = no; });
    mocks.step.mockReturnValueOnce(held);
    mountAndStart();
    await waitFor(() => expect(mocks.step).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole('button', { name: /Stop Early/ }));
    expect(screen.getByRole('button', { name: /Resume/ })).toBeDisabled();
    const error = new Error('NEST operation cancelled'); error.name = 'AbortError';
    await act(async () => { reject(error); await held.catch(() => {}); });
    await waitFor(() => expect(screen.getByRole('button', { name: /Resume/ })).not.toBeDisabled());
    expect(document.querySelector('.nest-error')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: /Resume/ }));
    await waitFor(() => expect(mocks.step).toHaveBeenCalledTimes(2));
    expect(mocks.construct.mock.calls[0][0].shouldStop()).toBe(false);
    expect(mocks.commit).not.toHaveBeenCalled();
  });

  it.each(['nest_create_session', 'nest_verify_binary_identity', 'runner.step', 'nest_append_iteration'])
  ('discards old selection publication after held %s settles', async phase => {
    let resolve!: (value: any) => void;
    const held = new Promise<any>(yes => { resolve = yes; });
    const normal = mocks.invoke.getMockImplementation()!;
    if (phase === 'runner.step') mocks.step.mockReturnValue(held);
    else mocks.invoke.mockImplementation((command, args) => command === phase ? held : normal(command, args));
    const view = mountAndStart();
    await waitFor(() => expect(phase === 'runner.step' ? mocks.step.mock.calls.length
      : mocks.invoke.mock.calls.filter(([command]) => command === phase).length).toBe(1));
    view.rerender(element('C:/fixtures/other.bin', 'b'.repeat(64)));
    const response = phase === 'nest_create_session'
      ? { sessionId: 'nestsession_active', binarySha256: 'a'.repeat(64), iterationCount: 0 }
      : phase === 'nest_verify_binary_identity' ? { verified: true, mismatch: false, message: 'matched' }
      : phase === 'runner.step' ? iterationFixture()
      : { iterationId: 'nestiter_canonical_0001', iterationCount: 1 };
    await act(async () => { resolve(response); await held; });
    expect(document.querySelector('.nest-bundle-indicator')).toBeNull();
    expect(document.querySelector('.status-running')).toBeNull();
    if (['nest_create_session', 'nest_verify_binary_identity'].includes(phase)) expect(mocks.step).not.toHaveBeenCalled();
    if (phase !== 'nest_append_iteration') expect(mocks.invoke.mock.calls.filter(([command]) => command === 'nest_append_iteration')).toEqual([]);
    expect(mocks.complete).not.toHaveBeenCalled();
  });

  it.each(['source identity rejected', 'native lifecycle unavailable'])('does not start a local-only runner when lifecycle creation fails: %s', async message => {
    const base = mocks.invoke.getMockImplementation()!;
    mocks.invoke.mockImplementation((command, args) => command === 'nest_create_session'
      ? Promise.reject(new Error(message)) : base(command, args));
    mountAndStart();
    await waitFor(() => expect(document.querySelector('.nest-error')?.textContent).toContain(message));
    expect(mocks.step).not.toHaveBeenCalled();
    expect(mocks.invoke.mock.calls.filter(([command]) => ['nest_append_iteration', 'nest_finalize_session'].includes(command))).toEqual([]);
    expect(mocks.complete).not.toHaveBeenCalled();
  });

  it.each([null, { sessionId: '', binarySha256: 'a'.repeat(64) }, { sessionId: 'nestsession_wrong', binarySha256: 'b'.repeat(64) }])
  ('rejects a malformed or wrong-identity lifecycle creation result: %j', async result => {
    const base = mocks.invoke.getMockImplementation()!;
    mocks.invoke.mockImplementation((command, args) => command === 'nest_create_session'
      ? Promise.resolve(result) : base(command, args));
    mountAndStart();
    await waitFor(() => expect(document.querySelector('.nest-error')?.textContent).toMatch(/session creation/i));
    expect(mocks.step).not.toHaveBeenCalled();
    expect(mocks.complete).not.toHaveBeenCalled();
  });

  it.each(['Cannot read binary: file missing', 'native transport unavailable', 'Permission denied'])('fails closed on native rejection: %s', async (message) => {
    const base = mocks.invoke.getMockImplementation()!;
    mocks.invoke.mockImplementation((command, args) => command === 'nest_verify_binary_identity'
      ? Promise.reject(new Error(message)) : base(command, args));
    mountAndStart();
    await expectBlocked();
    expect(document.querySelector('.nest-error')?.textContent).toContain(message);
  });

  it.each([
    { verified: false, mismatch: false, message: 'not verified' },
    { verified: true, mismatch: true, message: 'hash mismatch' },
    { mismatch: false, message: 'missing verified flag' },
    { verified: true, message: 'missing mismatch flag' },
    { verified: 'true', mismatch: false, message: 'invalid verified type' },
    null,
  ])('fails closed on unverified/malformed identity result: %j', async (result) => {
    const base = mocks.invoke.getMockImplementation()!;
    mocks.invoke.mockImplementation((command, args) => command === 'nest_verify_binary_identity'
      ? Promise.resolve(result) : base(command, args));
    mountAndStart();
    await expectBlocked();
  });

  it('only steps and persists a locked iteration after an affirmative native verification', async () => {
    mountAndStart();
    await waitFor(() => expect(mocks.invoke.mock.calls.some(([command]) => command === 'nest_append_iteration')).toBe(true));
    expect(mocks.step).toHaveBeenCalledTimes(1);
    const verifyIndex = mocks.invoke.mock.calls.findIndex(([command]) => command === 'nest_verify_binary_identity');
    expect(mocks.invoke.mock.invocationCallOrder[verifyIndex]).toBeLessThan(mocks.step.mock.invocationCallOrder[0]);
    const append = mocks.invoke.mock.calls.find(([command]) => command === 'nest_append_iteration')!;
    expect(append[1].request).toMatchObject({ sessionId: 'nestsession_active', fileIdentityLocked: true });
    expect(mocks.complete).not.toHaveBeenCalled();
  });
});

describe('NEST native config and convergence evidence repair', () => {
  it('sends the selected config rather than an invented native default', async () => {
    mountAndStart();
    await waitFor(() => expect(mocks.invoke.mock.calls.some(([command]) => command === 'nest_append_iteration')).toBe(true));
    const create = mocks.invoke.mock.calls.find(([command]) => command === 'nest_create_session')!;
    expect(create[1].request.config).toEqual({ config_version: '1.0.0',
      max_iterations: DEFAULT_NEST_CONFIG.maxIterations, min_iterations: DEFAULT_NEST_CONFIG.minIterations,
      confidence_threshold: DEFAULT_NEST_CONFIG.confidenceThreshold, plateau_threshold: DEFAULT_NEST_CONFIG.plateauThreshold,
      disasm_expansion: DEFAULT_NEST_CONFIG.disasmExpansion, aggressiveness: DEFAULT_NEST_CONFIG.aggressiveness,
      enable_talon: DEFAULT_NEST_CONFIG.enableTalon, enable_strike: DEFAULT_NEST_CONFIG.enableStrike,
      enable_echo: DEFAULT_NEST_CONFIG.enableEcho, auto_advance: false,
      auto_advance_delay_ms: DEFAULT_NEST_CONFIG.autoAdvanceDelay });
  });

  it.each(['max-reached', 'paused'])('does not turn terminal %s into convergence or classification stability', async status => {
    mocks.step.mockResolvedValue(iterationFixture(status, false));
    mountAndStart();
    await waitFor(() => expect(mocks.invoke.mock.calls.some(([command]) => command === 'nest_append_iteration')).toBe(true));
    const append = mocks.invoke.mock.calls.find(([command]) => command === 'nest_append_iteration')!;
    expect(append[1].request).toMatchObject({ hasConverged: false, classificationStable: false });
    expect(append[1].request.convergenceReason).toBe(status === 'max-reached' ? 'max-iterations' : 'external-stop');
  });

  it('binds the actual reasoning content with a digest and carries measured stability', async () => {
    const fixture = iterationFixture();
    mocks.step.mockResolvedValue(fixture);
    mountAndStart();
    await waitFor(() => expect(mocks.invoke.mock.calls.some(([command]) => command === 'nest_append_iteration')).toBe(true));
    const append = mocks.invoke.mock.calls.find(([command]) => command === 'nest_append_iteration')!;
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(fixture.snapshot.reasoningChain)));
    const expected = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
    expect(append[1].request.reasoningChainHash).toBe(expected);
    expect(append[1].request.stabilityScore).toBe(fixture.snapshot.stabilityReport.score);
  });
});

it('retains genuine measured convergence without promoting NEST to final verdict authority', async () => {
  const fixture = iterationFixture('converged', false);
  const verdict = computeVerdict({ sections: [], imports: [
    { name: 'VirtualAllocEx', library: 'kernel32.dll' },
    { name: 'WriteProcessMemory', library: 'kernel32.dll' },
    { name: 'CreateRemoteThread', library: 'kernel32.dll' },
  ], strings: [], patterns: [] });
  expect(verdict.signalCount).toBeGreaterThan(0);
  fixture.snapshot.verdict = verdict;
  fixture.snapshot.confidence = verdict.confidence;
  fixture.session.config = { ...DEFAULT_NEST_CONFIG, minIterations: 2, confidenceThreshold: 0 };
  fixture.session.iterations = [{ ...fixture.snapshot }, { ...fixture.snapshot, iteration: 1 }];
  fixture.snapshot = fixture.session.iterations[1];
  mocks.step.mockResolvedValue(fixture);
  mountAndStart();
  await waitFor(() => expect(mocks.invoke.mock.calls.some(([command]) => command === 'nest_append_iteration')).toBe(true));
  const append = mocks.invoke.mock.calls.find(([command]) => command === 'nest_append_iteration')!;
  expect(append[1].request).toMatchObject({ hasConverged: true, classificationStable: true, convergenceReason: 'confidence-threshold' });
  const finalize = mocks.invoke.mock.calls.find(([command]) => command === 'nest_finalize_session')!;
  expect(finalize[1].request.gyreSnapshotId).toBe('gyresnap_recorded');
  expect(finalize[1].request).not.toHaveProperty('confidence');
});
