import { describe, it, expect } from 'vitest';
import {
  createNestSession,
  finalizeSession,
  assessConvergence,
  DEFAULT_NEST_CONFIG,
} from '../../utils/nestEngine';
import type { NestSession } from '../../utils/nestEngine';

// ── createNestSession ─────────────────────────────────────────────────────────

describe('createNestSession', () => {
  it('creates a session with correct initial state', () => {
    const session = createNestSession('C:\\sample.exe');
    expect(session.binaryPath).toBe('C:\\sample.exe');
    expect(session.status).toBe('idle');
    expect(session.iterations).toHaveLength(0);
    expect(session.finalVerdict).toBeNull();
    expect(session.convergedAt).toBeNull();
    expect(session.errorMessage).toBeNull();
  });

  it('applies default config when none provided', () => {
    const session = createNestSession('sample.exe');
    expect(session.config.maxIterations).toBe(DEFAULT_NEST_CONFIG.maxIterations);
    expect(session.config.minIterations).toBe(DEFAULT_NEST_CONFIG.minIterations);
    expect(session.config.confidenceThreshold).toBe(DEFAULT_NEST_CONFIG.confidenceThreshold);
  });

  it('merges partial config with defaults', () => {
    const session = createNestSession('sample.exe', { maxIterations: 10 });
    expect(session.config.maxIterations).toBe(10);
    expect(session.config.minIterations).toBe(DEFAULT_NEST_CONFIG.minIterations); // unchanged
  });

  it('generates unique session IDs', () => {
    const ids = new Set(
      Array.from({ length: 10 }, () => createNestSession('a.exe').id),
    );
    expect(ids.size).toBe(10);
  });
});

// ── finalizeSession ───────────────────────────────────────────────────────────

describe('finalizeSession', () => {
  const base: NestSession = createNestSession('C:\\test.exe');

  it('sets status correctly', () => {
    const result = finalizeSession(base, 'converged');
    expect(result.status).toBe('converged');
  });

  it('sets endTime on finalize', () => {
    const result = finalizeSession(base, 'max-reached');
    expect(result.endTime).not.toBeNull();
    expect(typeof result.endTime).toBe('number');
  });

  it('sets convergedAt for converged status', () => {
    const result = finalizeSession(base, 'converged');
    expect(result.convergedAt).not.toBeNull();
  });

  it('does NOT set convergedAt for non-convergence statuses', () => {
    const result = finalizeSession(base, 'error');
    expect(result.convergedAt).toBeNull();
  });

  it('stores error message', () => {
    const result = finalizeSession(base, 'error', 'disk read failed');
    expect(result.errorMessage).toBe('disk read failed');
  });
});

// ── assessConvergence — minIterations guard ───────────────────────────────────

describe('assessConvergence — minIterations guard', () => {
  it('returns continue when iterations < minIterations', () => {
    const session = createNestSession('x.exe', { minIterations: 3 });
    // 0 iterations completed
    const fakeVerdict = {
      threatScore: 50,
      confidence: 90, // high confidence but not enough iterations
      classification: 'suspicious' as const,
      signals: [],
      negativeSignals: [],
      amplifiers: [],
      dismissals: [],
      summary: '',
      explainability: [],
      nextSteps: [],
      signalCount: 5,
      behaviors: [],
      reasoningChain: [],
      contradictions: [],
      alternatives: [],
    };
    const result = assessConvergence(session, fakeVerdict);
    expect(result.hasConverged).toBe(false);
    expect(result.reason).not.toBe('confidence-threshold');
  });

  it('can declare convergence once minIterations are complete', () => {
    // Build a session that already has 3 completed iterations recorded
    const session = createNestSession('x.exe', {
      minIterations: 3,
      maxIterations: 10,
      confidenceThreshold: 85,
    });

    // Mock the iteration snapshots — just needs .confidence and .verdict fields
    const snap = (confidence: number) => ({
      iteration: 1,
      timestamp: Date.now(),
      input: { filePath: 'x.exe', options: {} },
      verdict: {
        threatScore: 10,
        confidence,
        classification: 'clean' as const,
        signals: [],
        negativeSignals: [],
        amplifiers: [],
        dismissals: [],
        summary: '',
        explainability: [],
        nextSteps: [],
        signalCount: 0,
        behaviors: [],
        reasoningChain: [],
        contradictions: [],
        alternatives: [],
      },
      confidence,
      delta: null,
      refinementPlan: null,
      annotations: [],
      durationMs: 100,
    });

    const sessionWith3 = {
      ...session,
      iterations: [snap(88), snap(89), snap(90)],
    } as unknown as NestSession;

    const highConfVerdict = {
      ...sessionWith3.iterations[2].verdict,
      confidence: 91,
    };

    const result = assessConvergence(sessionWith3, highConfVerdict);
    // Should now be allowed to converge (confidence 91 >= threshold 85)
    expect(result.hasConverged).toBe(true);
  });
});

// ── assessConvergence — no-data guard ────────────────────────────────────────

describe('assessConvergence — no-data guard', () => {
  it('returns no-data when signalCount=0 and no iterations', () => {
    const session = createNestSession('x.exe');
    const emptyVerdict = {
      threatScore: 0,
      confidence: 0,
      classification: 'unknown' as const,
      signals: [],
      negativeSignals: [],
      amplifiers: [],
      dismissals: [],
      summary: '',
      explainability: [],
      nextSteps: [],
      signalCount: 0,
      behaviors: [],
      reasoningChain: [],
      contradictions: [],
      alternatives: [],
    };
    const result = assessConvergence(session, emptyVerdict);
    expect(result.reason).toBe('no-data');
    expect(result.hasConverged).toBe(false);
  });
});
