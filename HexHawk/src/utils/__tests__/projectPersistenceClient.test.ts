import { describe, expect, it, vi } from 'vitest';
import { ProjectPersistenceCoordinator, type ResolvedProject } from '../projectPersistenceClient';

const deferred = <T,>() => { let resolve!: (value: T) => void; const promise = new Promise<T>(r => { resolve = r; }); return { promise, resolve }; };
const project = (id: string) => ({ manifest: { projectId: id }, gyreSnapshot: { classification: 'suspicious' } } as ResolvedProject);

describe('ProjectPersistenceCoordinator', () => {
  it('prevents duplicate native saves caused by StrictMode effect replay', async () => {
    const save = vi.fn(async request => ({ projectId: request.projectId } as never));
    const coordinator = new ProjectPersistenceCoordinator(save, vi.fn());
    const request = { projectId: 'hhproj_12345678', name: 'x', binaryPath: 'a', gyreSnapshotId: 'g' };
    const [a, b] = await Promise.all([coordinator.save(request), coordinator.save(request)]);
    expect(save).toHaveBeenCalledTimes(1); expect(a).toBe(b);
  });
  it('drops a stale open response after a newer open wins', async () => {
    const first = deferred<ResolvedProject>(); const second = deferred<ResolvedProject>();
    const open = vi.fn().mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    const coordinator = new ProjectPersistenceCoordinator(vi.fn(), open);
    const oldPromise = coordinator.open('hhproj_11111111');
    const newPromise = coordinator.open('hhproj_22222222');
    second.resolve(project('hhproj_22222222')); first.resolve(project('hhproj_11111111'));
    expect((await newPromise)?.manifest.projectId).toBe('hhproj_22222222');
    expect(await oldPromise).toBeNull();
  });
});
