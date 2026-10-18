/** @vitest-environment jsdom */
import React, { StrictMode } from 'react';
import { act, renderHook, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { BinaryVerdictResult } from '../correlationEngine';
import type {
  GyreRecordedVerdictSnapshot,
  GyreSnapshotRecordFunction,
} from '../gyreSnapshotClient';
import { useGyreSnapshotRecording } from '../useGyreSnapshotRecording';

const verdict = {
  classification: 'suspicious',
  confidence: 67,
  threatScore: 42,
  summary: 'ordinary GYRE verdict',
  signalCount: 2,
  contradictions: [],
  reasoningChain: [],
} as unknown as BinaryVerdictResult;

function recorded(
  snapshotId: string,
  binarySha256: string,
): GyreRecordedVerdictSnapshot {
  return {
    snapshotId,
    binarySha256,
  } as GyreRecordedVerdictSnapshot;
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

const strictWrapper = ({ children }: { children: React.ReactNode }) => (
  <StrictMode>{children}</StrictMode>
);

describe('useGyreSnapshotRecording', () => {
  it('does not record before a metadata SHA-256 exists', async () => {
    const recordSnapshot = vi.fn<GyreSnapshotRecordFunction>();

    const { result } = renderHook(
      () => useGyreSnapshotRecording({
        browserMode: false,
        binaryPath: 'sample.exe',
        binarySha256: null,
        verdict,
        recordSnapshot,
      }),
      { wrapper: strictWrapper },
    );

    expect(recordSnapshot).not.toHaveBeenCalled();
    expect(result.current.binding).toBeNull();
    expect(result.current.error).toBeNull();
  });

  it('deduplicates StrictMode effect replay for one path/hash identity', async () => {
    const sha = 'a'.repeat(64);
    const pending = deferred<GyreRecordedVerdictSnapshot>();
    const recordSnapshot = vi.fn<GyreSnapshotRecordFunction>(
      () => pending.promise,
    );

    const { result } = renderHook(
      () => useGyreSnapshotRecording({
        browserMode: false,
        binaryPath: 'strict.exe',
        binarySha256: sha,
        verdict,
        recordSnapshot,
      }),
      { wrapper: strictWrapper },
    );

    await waitFor(() => expect(recordSnapshot).toHaveBeenCalledTimes(1));

    await act(async () => {
      pending.resolve(recorded('gyresnap_strict', sha));
      await pending.promise;
    });

    await waitFor(() => {
      expect(result.current.binding?.snapshotId).toBe('gyresnap_strict');
    });
    expect(recordSnapshot).toHaveBeenCalledTimes(1);
  });

  it('does not record again when only the verdict object rerenders', async () => {
    const sha = 'b'.repeat(64);
    const recordSnapshot = vi.fn<GyreSnapshotRecordFunction>(
      async () => recorded('gyresnap_once', sha),
    );

    const initialProps = { currentVerdict: verdict };
    const { result, rerender } = renderHook(
      ({ currentVerdict }) => useGyreSnapshotRecording({
        browserMode: false,
        binaryPath: 'rerender.exe',
        binarySha256: sha,
        verdict: currentVerdict,
        recordSnapshot,
      }),
      { initialProps, wrapper: strictWrapper },
    );

    await waitFor(() => {
      expect(result.current.binding?.snapshotId).toBe('gyresnap_once');
    });

    rerender({
      currentVerdict: {
        ...verdict,
        summary: 'later advisory or analysis rerender',
      } as BinaryVerdictResult,
    });

    await waitFor(() => {
      expect(result.current.binding?.snapshotId).toBe('gyresnap_once');
    });
    expect(recordSnapshot).toHaveBeenCalledTimes(1);
  });

  it('rejects an old completion after path and hash selection change', async () => {
    const firstSha = 'c'.repeat(64);
    const secondSha = 'd'.repeat(64);
    const first = deferred<GyreRecordedVerdictSnapshot>();
    const second = deferred<GyreRecordedVerdictSnapshot>();
    const recordSnapshot = vi.fn<GyreSnapshotRecordFunction>()
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(second.promise);

    const initialProps = {
      binaryPath: 'first.exe',
      binarySha256: firstSha,
    };

    const { result, rerender } = renderHook(
      ({ binaryPath, binarySha256 }) => useGyreSnapshotRecording({
        browserMode: false,
        binaryPath,
        binarySha256,
        verdict,
        recordSnapshot,
      }),
      { initialProps, wrapper: strictWrapper },
    );

    await waitFor(() => expect(recordSnapshot).toHaveBeenCalledTimes(1));

    rerender({
      binaryPath: 'second.exe',
      binarySha256: secondSha,
    });

    await waitFor(() => expect(recordSnapshot).toHaveBeenCalledTimes(2));

    await act(async () => {
      second.resolve(recorded('gyresnap_second', secondSha));
      await second.promise;
    });

    await waitFor(() => {
      expect(result.current.binding?.snapshotId).toBe('gyresnap_second');
    });

    await act(async () => {
      first.resolve(recorded('gyresnap_first', firstSha));
      await first.promise;
    });

    await waitFor(() => {
      expect(result.current.binding?.snapshotId).toBe('gyresnap_second');
    });
  });

  it('surfaces a bounded failure and retries intentionally', async () => {
    const sha = 'e'.repeat(64);
    const recordSnapshot = vi.fn<GyreSnapshotRecordFunction>()
      .mockRejectedValueOnce(new Error(`temporary\n${'x'.repeat(700)}`))
      .mockResolvedValueOnce(recorded('gyresnap_retry', sha));

    const { result } = renderHook(
      () => useGyreSnapshotRecording({
        browserMode: false,
        binaryPath: 'retry.exe',
        binarySha256: sha,
        verdict,
        recordSnapshot,
      }),
      { wrapper: strictWrapper },
    );

    await waitFor(() => {
      expect(result.current.error).not.toBeNull();
    });
    expect(result.current.error?.includes('\n')).toBe(false);
    expect(result.current.error?.length).toBeLessThanOrEqual(503);
    expect(result.current.binding).toBeNull();

    act(() => {
      result.current.retry();
    });

    await waitFor(() => {
      expect(result.current.binding?.snapshotId).toBe('gyresnap_retry');
    });

    expect(recordSnapshot).toHaveBeenCalledTimes(2);
    expect(result.current.error).toBeNull();
  });
});
