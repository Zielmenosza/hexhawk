import { describe, expect, it } from 'vitest';
import { assertReplayableDynamicTrace, buildOfflineDynamicTrace, summarizeDynamicTrace } from '../utils/dynamicSessionTrace';

const SHA = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

describe('Phase 1 dynamic session trace contract', () => {
  it('builds replayable offline traces without live execution', () => {
    const trace = buildOfflineDynamicTrace({
      sessionId: 'dyn_001',
      binarySha256: SHA,
      binaryPath: 'sample.exe',
      architecture: 'x86-64',
      createdAt: '2026-07-16T00:00:00.000Z',
      events: [
        {
          id: 'evt_001',
          kind: 'module-load',
          timestamp: '2026-07-16T00:00:00.000Z',
          moduleName: 'sample.exe',
          summary: 'Main module loaded in imported trace fixture.',
          evidenceBasis: ['fixture-json'],
        },
        {
          id: 'evt_002',
          kind: 'register-snapshot',
          timestamp: '2026-07-16T00:00:01.000Z',
          address: 0x401000,
          summary: 'RIP observed at function entry.',
          evidenceBasis: ['fixture-registers'],
        },
      ],
    });

    expect(() => assertReplayableDynamicTrace(trace)).not.toThrow();
    expect(trace.mode).toBe('offline-trace');
    expect(trace.liveExecutionPerformed).toBe(false);
    expect(trace.consent.granted).toBe(false);
    expect(trace.gyre_is_sole_verdict_authority).toBe(true);
    expect(summarizeDynamicTrace(trace)).toContain('2 dynamic event(s), offline replay only');
  });

  it('rejects invalid hashes and malformed replay events', () => {
    expect(() => buildOfflineDynamicTrace({ sessionId: 'bad', binarySha256: 'abc' })).toThrow('binarySha256');
    const trace = buildOfflineDynamicTrace({
      sessionId: 'dyn_002',
      binarySha256: SHA,
      events: [{ id: 'evt_bad', kind: 'note', timestamp: '2026-07-16T00:00:00.000Z', summary: 'missing basis', evidenceBasis: [] }],
    });
    expect(() => assertReplayableDynamicTrace(trace)).toThrow('requires evidenceBasis');
  });
});
