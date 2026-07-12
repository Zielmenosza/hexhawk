import { useCallback, useEffect, useRef, useState } from 'react';
import type { BinaryVerdictResult } from './correlationEngine';
import {
  formatGyreSnapshotRecordingError,
  GyreSnapshotRecordingCoordinator,
  recordGyreVerdictSnapshot,
  type GyreSnapshotBinding,
  type GyreSnapshotRecordFunction,
} from './gyreSnapshotClient';

export interface UseGyreSnapshotRecordingOptions {
  browserMode: boolean;
  binaryPath: string;
  binarySha256: string | null;
  verdict: BinaryVerdictResult;
  recordSnapshot?: GyreSnapshotRecordFunction;
}

export interface UseGyreSnapshotRecordingResult {
  binding: GyreSnapshotBinding | null;
  error: string | null;
  retry: () => void;
}

/**
 * React integration for one immutable renderer-computed GYRE snapshot per
 * selected path/hash. StrictMode effect replay shares the same component-local
 * coordinator and therefore reuses an existing in-flight or accepted record.
 */
export function useGyreSnapshotRecording({
  browserMode,
  binaryPath,
  binarySha256,
  verdict,
  recordSnapshot = recordGyreVerdictSnapshot,
}: UseGyreSnapshotRecordingOptions): UseGyreSnapshotRecordingResult {
  const coordinatorRef = useRef<GyreSnapshotRecordingCoordinator | null>(null);
  const recordSnapshotRef = useRef(recordSnapshot);

  if (!coordinatorRef.current) {
    coordinatorRef.current = new GyreSnapshotRecordingCoordinator(
      recordSnapshotRef.current,
    );
  }

  const [binding, setBinding] = useState<GyreSnapshotBinding | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [retryNonce, setRetryNonce] = useState(0);

  useEffect(() => {
    const coordinator = coordinatorRef.current;
    if (!coordinator) return;

    if (browserMode || !binarySha256) {
      coordinator.clear();
      setBinding(null);
      setError(null);
      return;
    }

    let cancelled = false;
    const accepted = coordinator.currentBinding(binaryPath, binarySha256);

    setBinding(accepted);
    setError(null);

    void coordinator.record(binaryPath, binarySha256, verdict)
      .then((nextBinding) => {
        if (cancelled || !nextBinding) return;
        setBinding(nextBinding);
      })
      .catch((recordingError) => {
        if (cancelled) return;
        setBinding(null);
        setError(formatGyreSnapshotRecordingError(recordingError));
      });

    return () => {
      cancelled = true;
    };
  }, [
    binaryPath,
    binarySha256,
    browserMode,
    retryNonce,
    verdict,
  ]);

  const activeBinding = binarySha256
    ? coordinatorRef.current.currentBinding(binaryPath, binarySha256)
    : null;

  const retry = useCallback(() => {
    setRetryNonce(value => value + 1);
  }, []);

  return {
    binding: binding && activeBinding ? activeBinding : null,
    error,
    retry,
  };
}
