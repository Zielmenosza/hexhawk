import { describe, expect, it, vi } from 'vitest';
import { NestLifecycleCoordinator } from '../gyreSnapshotClient';

describe('NestLifecycleCoordinator project linkage', () => {
  it('returns canonical backend linkage only after terminal finalization', async () => {
    const sessionId = 'nestsession_test';
    const snapshotId = 'gyresnap_test';
    const appendResponse = {
      sessionId,
      iterationCount: 3,
      iterationId: 'nestiter_backend_canonical',
      replayed: false,
    };

    const nativeInvoke = vi.fn(async (command: string) => {
      if (command === 'nest_append_iteration') return appendResponse;
      if (command === 'nest_finalize_session') return { sessionId, status: 'completed' };
      throw new Error(`Unexpected command: ${command}`);
    });

    const coordinator = new NestLifecycleCoordinator<{ completed: boolean }>(
      nativeInvoke as never,
      () => 'nestclient_stable',
    );

    const result = await coordinator.processNext(
      sessionId,
      snapshotId,
      async () => ({
        step: { completed: true },
        terminal: true,
        appendRequest: { confidence: 77 },
      }),
    );

    expect(result.finalized).toBe(true);
    expect(result.projectLinkage).toEqual({
      sessionId,
      finalIterationId: appendResponse.iterationId,
      finalVerdictSnapshotId: snapshotId,
    });
    expect(nativeInvoke).toHaveBeenNthCalledWith(
      2,
      'nest_finalize_session',
      {
        request: expect.objectContaining({
          sessionId,
          gyreSnapshotId: snapshotId,
          linkedIterationId: appendResponse.iterationId,
        }),
      },
    );
  });

  it('does not expose project linkage for a non-terminal append', async () => {
    const nativeInvoke = vi.fn(async () => ({
      sessionId: 'nestsession_test',
      iterationCount: 1,
      iterationId: 'nestiter_backend_first',
      replayed: false,
    }));

    const coordinator = new NestLifecycleCoordinator<{ completed: boolean }>(
      nativeInvoke as never,
      () => 'nestclient_stable',
    );

    const result = await coordinator.processNext(
      'nestsession_test',
      'gyresnap_test',
      async () => ({
        step: { completed: false },
        terminal: false,
        appendRequest: { confidence: 42 },
      }),
    );

    expect(result.finalized).toBe(false);
    expect(result.projectLinkage).toBeNull();
    expect(nativeInvoke).toHaveBeenCalledTimes(1);
  });
});
