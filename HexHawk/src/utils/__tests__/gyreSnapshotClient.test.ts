import { describe, expect, it, vi } from 'vitest';
import type { BinaryVerdictResult } from '../correlationEngine';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

import {
  buildNestFinalizeRequest,
  formatGyreSnapshotRecordingError,
  GyreSnapshotRecordingCoordinator,
  isCurrentGyreSnapshotResponse,
  NestLifecycleCoordinator,
  NestLifecycleOperationError,
  recordGyreVerdictSnapshot,
} from '../gyreSnapshotClient';

describe('GYRE snapshot boundary client', () => {
  it('rejects a stale file-generation response', () => {
    const expected = { binaryPath: 'a.exe', binarySha256: 'a'.repeat(64), generation: 4 };
    expect(isCurrentGyreSnapshotResponse(expected, expected)).toBe(true);
    expect(isCurrentGyreSnapshotResponse(expected, { ...expected, generation: 5 })).toBe(false);
    expect(isCurrentGyreSnapshotResponse(expected, { ...expected, binaryPath: 'b.exe' })).toBe(false);
    expect(isCurrentGyreSnapshotResponse(expected, { ...expected, binarySha256: 'b'.repeat(64) })).toBe(false);
  });

  it('builds NEST finalization with only snapshot identity and NEST-owned fields', () => {
    const request = buildNestFinalizeRequest('nestsession_test', 'gyresnap_test', {
      nestSummary: 'advisory only',
    });

    expect(request).toEqual({
      sessionId: 'nestsession_test',
      gyreSnapshotId: 'gyresnap_test',
      linkedIterationId: null,
      nestSummary: 'advisory only',
      runtimeProof: null,
      notes: null,
    });
    expect(request).not.toHaveProperty('classification');
    expect(request).not.toHaveProperty('confidence');
    expect(request).not.toHaveProperty('threatScore');
    expect(request).not.toHaveProperty('sourceEngine');
    expect(request).not.toHaveProperty('verdictSnapshotId');
  });

  it('records the original GYRE fields with the metadata SHA-256', async () => {
    invokeMock.mockResolvedValueOnce({ snapshotId: 'gyresnap_test' });
    const verdict = {
      classification: 'suspicious',
      confidence: 67,
      threatScore: 42,
      summary: 'original GYRE summary',
      signalCount: 2,
      contradictions: [{ description: 'conflict' }],
      reasoningChain: [{ stage: 1, name: 'Signals', findings: [], conclusion: 'review', confidence: 67 }],
    } as unknown as BinaryVerdictResult;

    await recordGyreVerdictSnapshot(
      'gyrerecord_boundary_test',
      'a'.repeat(64),
      verdict,
    );

    expect(invokeMock).toHaveBeenCalledWith('gyre_record_verdict_snapshot', {
      request: expect.objectContaining({
        clientRecordKey: 'gyrerecord_boundary_test',
        binarySha256: 'a'.repeat(64),
        classification: 'suspicious',
        baseConfidence: 67,
        threatScore: 42,
        summary: 'original GYRE summary',
        signalCount: 2,
        contradictionCount: 1,
      }),
    });
  });
});


describe('GYRE snapshot recording errors', () => {
  it('collapses control whitespace and bounds displayed error details', () => {
    expect(formatGyreSnapshotRecordingError('line one\nline two\tline three'))
      .toBe('line one line two line three');

    const bounded = formatGyreSnapshotRecordingError('x'.repeat(700));
    expect(bounded.length).toBe(503);
    expect(bounded.endsWith('...')).toBe(true);
  });
});

describe('GYRE snapshot recording coordinator', () => {
  const verdict = {
    classification: 'suspicious',
    confidence: 67,
    threatScore: 42,
    summary: 'original GYRE verdict',
    signalCount: 2,
    contradictions: [],
    reasoningChain: [],
  } as unknown as BinaryVerdictResult;

  function recorded(snapshotId: string, binarySha256: string) {
    return {
      snapshotId,
      binarySha256,
    } as Awaited<ReturnType<typeof recordGyreVerdictSnapshot>>;
  }

  function deferred<T>() {
    let resolve!: (value: T) => void;
    let reject!: (reason?: unknown) => void;
    const promise = new Promise<T>((resolvePromise, rejectPromise) => {
      resolve = resolvePromise;
      reject = rejectPromise;
    });
    return { promise, resolve, reject };
  }

  it('deduplicates replay for the same path and SHA-256 identity', async () => {
    const sha = 'a'.repeat(64);
    const record = vi.fn(async () => recorded('gyresnap_same', sha));
    const coordinator = new GyreSnapshotRecordingCoordinator(record);

    const [first, replay] = await Promise.all([
      coordinator.record('sample.exe', sha, verdict),
      coordinator.record('sample.exe', sha, verdict),
    ]);

    expect(record).toHaveBeenCalledTimes(1);
    expect(replay).toEqual(first);
    expect(coordinator.currentBinding('sample.exe', sha)).toEqual(first);
  });

  it('does not create a second snapshot after the first result is accepted', async () => {
    const sha = 'b'.repeat(64);
    const record = vi.fn(async () => recorded('gyresnap_accepted', sha));
    const coordinator = new GyreSnapshotRecordingCoordinator(record);

    const first = await coordinator.record('accepted.exe', sha, verdict);
    const replay = await coordinator.record('accepted.exe', sha, {
      ...verdict,
      summary: 'later advisory or rerender state',
    } as BinaryVerdictResult);

    expect(record).toHaveBeenCalledTimes(1);
    expect(replay).toEqual(first);
  });

  it('rejects a stale completion after selection changes', async () => {
    const firstSha = 'c'.repeat(64);
    const secondSha = 'd'.repeat(64);
    const firstDeferred = deferred<Awaited<ReturnType<typeof recordGyreVerdictSnapshot>>>();
    const secondDeferred = deferred<Awaited<ReturnType<typeof recordGyreVerdictSnapshot>>>();
    const record = vi.fn()
      .mockReturnValueOnce(firstDeferred.promise)
      .mockReturnValueOnce(secondDeferred.promise);
    const coordinator = new GyreSnapshotRecordingCoordinator(record);

    const first = coordinator.record('first.exe', firstSha, verdict);
    const second = coordinator.record('second.exe', secondSha, verdict);

    secondDeferred.resolve(recorded('gyresnap_second', secondSha));
    const acceptedSecond = await second;

    firstDeferred.resolve(recorded('gyresnap_first', firstSha));
    const staleFirst = await first;

    expect(staleFirst).toBeNull();
    expect(acceptedSecond?.snapshotId).toBe('gyresnap_second');
    expect(coordinator.currentBinding('first.exe', firstSha)).toBeNull();
    expect(coordinator.currentBinding('second.exe', secondSha)).toEqual(acceptedSecond);
  });

  it('keeps the newest binding when responses resolve out of order', async () => {
    const firstSha = 'e'.repeat(64);
    const secondSha = 'f'.repeat(64);
    const firstDeferred = deferred<Awaited<ReturnType<typeof recordGyreVerdictSnapshot>>>();
    const secondDeferred = deferred<Awaited<ReturnType<typeof recordGyreVerdictSnapshot>>>();
    const record = vi.fn()
      .mockReturnValueOnce(firstDeferred.promise)
      .mockReturnValueOnce(secondDeferred.promise);
    const coordinator = new GyreSnapshotRecordingCoordinator(record);

    const first = coordinator.record('one.exe', firstSha, verdict);
    const second = coordinator.record('two.exe', secondSha, verdict);

    secondDeferred.resolve(recorded('gyresnap_newest', secondSha));
    await second;
    firstDeferred.resolve(recorded('gyresnap_old', firstSha));
    await first;

    expect(coordinator.currentBinding('two.exe', secondSha)?.snapshotId)
      .toBe('gyresnap_newest');
  });

  it('clears a failed in-flight operation and permits an explicit retry', async () => {
    const sha = '1'.repeat(64);
    const record = vi.fn()
      .mockRejectedValueOnce(new Error('temporary recording failure'))
      .mockResolvedValueOnce(recorded('gyresnap_retry', sha));
    const createClientRecordKey = vi.fn(() => 'gyrerecord_retry_test');
    const coordinator = new GyreSnapshotRecordingCoordinator(
      record,
      createClientRecordKey,
    );

    await expect(coordinator.record('retry.exe', sha, verdict))
      .rejects.toThrow('temporary recording failure');

    const retried = await coordinator.record('retry.exe', sha, verdict);

    expect(record).toHaveBeenCalledTimes(2);
    expect(createClientRecordKey).toHaveBeenCalledTimes(1);
    expect(record).toHaveBeenNthCalledWith(
      1,
      'gyrerecord_retry_test',
      sha,
      verdict,
    );
    expect(record).toHaveBeenNthCalledWith(
      2,
      'gyrerecord_retry_test',
      sha,
      verdict,
    );
    expect(retried?.snapshotId).toBe('gyresnap_retry');
  });

  it('never exposes a binding for a mismatched path or hash', async () => {
    const sha = '2'.repeat(64);
    const record = vi.fn(async () => recorded('gyresnap_bound', sha));
    const coordinator = new GyreSnapshotRecordingCoordinator(record);

    await coordinator.record('bound.exe', sha, verdict);

    expect(coordinator.currentBinding('other.exe', sha)).toBeNull();
    expect(coordinator.currentBinding('bound.exe', '3'.repeat(64))).toBeNull();
    expect(coordinator.currentBinding('bound.exe', sha)?.snapshotId)
      .toBe('gyresnap_bound');
  });
});

describe('NEST lifecycle coordinator', () => {
  const sessionId = 'nestsession_test';
  const snapshotId = 'gyresnap_test';
  const appendResponse = {
    sessionId,
    iterationCount: 1,
    iterationId: 'nestiter_backend_canonical_0001',
    replayed: false,
  };

  function work(step: number, terminal: boolean) {
    return {
      step: { step, advisoryConfidence: 0.72 },
      terminal,
      appendRequest: {
        classification: 'suspicious',
        confidence: 72,
        threatScore: 40,
        hasConverged: terminal,
      },
      finalizeAdvisory: { nestSummary: 'NEST advisory only' },
    };
  }

  it('appends first-iteration convergence before finalizing with the canonical ID', async () => {
    const calls: string[] = [];
    const nativeInvoke = vi.fn(async (command: string, args?: Record<string, unknown>) => {
      calls.push(command);
      if (command === 'nest_append_iteration') return appendResponse;
      expect(args).toEqual({
        request: {
          sessionId,
          gyreSnapshotId: snapshotId,
          linkedIterationId: appendResponse.iterationId,
          nestSummary: 'NEST advisory only',
          runtimeProof: null,
          notes: null,
        },
      });
      return {};
    });
    const createWork = vi.fn(async () => work(1, true));
    const coordinator = new NestLifecycleCoordinator(nativeInvoke, () => 'client_key_1');

    const result = await coordinator.processNext(sessionId, snapshotId, createWork);

    expect(result.finalized).toBe(true);
    expect(createWork).toHaveBeenCalledTimes(1);
    expect(calls).toEqual(['nest_append_iteration', 'nest_finalize_session']);
    const finalizeRequest = (nativeInvoke.mock.calls[1][1] as { request: Record<string, unknown> }).request;
    expect(finalizeRequest.linkedIterationId).toBe(appendResponse.iterationId);
    expect(finalizeRequest.gyreSnapshotId).toBe(snapshotId);
    for (const field of ['classification', 'confidence', 'baseConfidence', 'threatScore', 'summary', 'signalCount', 'contradictionCount', 'sourceEngine', 'gyreIsSoleVerdictSource']) {
      expect(finalizeRequest).not.toHaveProperty(field);
    }
  });

  it('appends each later iteration once and finalizes only after the terminal append', async () => {
    const calls: string[] = [];
    let count = 0;
    const nativeInvoke = vi.fn(async (command: string) => {
      calls.push(command);
      if (command === 'nest_append_iteration') {
        count += 1;
        return { ...appendResponse, iterationCount: count, iterationId: `canonical_${count}` };
      }
      return {};
    });
    const coordinator = new NestLifecycleCoordinator(nativeInvoke, () => `client_key_${count + 1}`);

    await coordinator.processNext(sessionId, snapshotId, async () => work(1, false));
    await coordinator.processNext(sessionId, snapshotId, async () => work(2, false));
    await coordinator.processNext(sessionId, snapshotId, async () => work(3, true));

    expect(calls).toEqual([
      'nest_append_iteration',
      'nest_append_iteration',
      'nest_append_iteration',
      'nest_finalize_session',
    ]);
  });

  it('retains the same step, key and payload after append failure', async () => {
    const appendRequests: unknown[] = [];
    let attempts = 0;
    const nativeInvoke = vi.fn(async (command: string, args?: Record<string, unknown>) => {
      if (command !== 'nest_append_iteration') return {};
      appendRequests.push(args);
      attempts += 1;
      if (attempts === 1) throw new Error('uncertain append');
      return { ...appendResponse, replayed: true };
    });
    const createWork = vi.fn(async () => work(1, false));
    const coordinator = new NestLifecycleCoordinator(nativeInvoke, () => 'stable_client_key');

    await expect(coordinator.processNext(sessionId, snapshotId, createWork))
      .rejects.toMatchObject({ stage: 'append' } satisfies Partial<NestLifecycleOperationError>);
    await coordinator.processNext(sessionId, snapshotId, createWork);

    expect(createWork).toHaveBeenCalledTimes(1);
    expect(appendRequests).toHaveLength(2);
    expect(appendRequests[1]).toEqual(appendRequests[0]);
    expect(nativeInvoke).not.toHaveBeenCalledWith('nest_finalize_session', expect.anything());
  });

  it('retries finalization without re-appending and preserves the canonical ID', async () => {
    let finalizeAttempts = 0;
    const nativeInvoke = vi.fn(async (command: string, args?: Record<string, unknown>) => {
      if (command === 'nest_append_iteration') return appendResponse;
      finalizeAttempts += 1;
      const linkedId = (args as { request: { linkedIterationId: string } }).request.linkedIterationId;
      expect(linkedId).toBe(appendResponse.iterationId);
      if (finalizeAttempts === 1) throw new Error('finalization unavailable');
      return {};
    });
    const createWork = vi.fn(async () => work(1, true));
    const coordinator = new NestLifecycleCoordinator(nativeInvoke, () => 'stable_terminal_key');

    await expect(coordinator.processNext(sessionId, snapshotId, createWork))
      .rejects.toMatchObject({ stage: 'finalize' } satisfies Partial<NestLifecycleOperationError>);
    await coordinator.processNext(sessionId, snapshotId, createWork);

    expect(createWork).toHaveBeenCalledTimes(1);
    expect(nativeInvoke.mock.calls.filter(([command]) => command === 'nest_append_iteration')).toHaveLength(1);
    expect(nativeInvoke.mock.calls.filter(([command]) => command === 'nest_finalize_session')).toHaveLength(2);
  });

  it('deduplicates concurrent replay of append and finalization', async () => {
    const nativeInvoke = vi.fn(async (command: string) => {
      await Promise.resolve();
      return command === 'nest_append_iteration' ? appendResponse : {};
    });
    const createWork = vi.fn(async () => work(1, true));
    const coordinator = new NestLifecycleCoordinator(nativeInvoke, () => 'strict_mode_key');

    await Promise.all([
      coordinator.processNext(sessionId, snapshotId, createWork),
      coordinator.processNext(sessionId, snapshotId, createWork),
    ]);

    expect(createWork).toHaveBeenCalledTimes(1);
    expect(nativeInvoke.mock.calls.filter(([command]) => command === 'nest_append_iteration')).toHaveLength(1);
    expect(nativeInvoke.mock.calls.filter(([command]) => command === 'nest_finalize_session')).toHaveLength(1);
  });

  it('surfaces conflicting duplicate-key errors and does not finalize', async () => {
    const nativeInvoke = vi.fn(async (command: string) => {
      if (command === 'nest_append_iteration') throw new Error('client_iteration_key conflicts');
      return {};
    });
    const coordinator = new NestLifecycleCoordinator(nativeInvoke, () => 'conflict_key');

    await expect(coordinator.processNext(sessionId, snapshotId, async () => work(1, true)))
      .rejects.toThrow('client_iteration_key conflicts');
    expect(nativeInvoke).not.toHaveBeenCalledWith('nest_finalize_session', expect.anything());
  });

  it('keeps NEST advisory confidence outside finalization authority fields', async () => {
    const nativeInvoke = vi.fn(async (command: string, args?: Record<string, unknown>) => {
      if (command === 'nest_append_iteration') {
        const request = (args as { request: Record<string, unknown> }).request;
        expect(request.confidence).toBe(72);
        return appendResponse;
      }
      const request = (args as { request: Record<string, unknown> }).request;
      expect(request).not.toHaveProperty('confidence');
      expect(request).not.toHaveProperty('baseConfidence');
      return {};
    });
    const coordinator = new NestLifecycleCoordinator(nativeInvoke, () => 'advisory_key');
    await coordinator.processNext(sessionId, snapshotId, async () => work(1, true));
  });
});
