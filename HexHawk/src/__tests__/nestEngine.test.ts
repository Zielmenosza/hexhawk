import { describe, it, expect } from 'vitest';
import {
  createNestSession,
  finalizeSession,
  runCorrelationPass,
  assessConvergence,
  evaluateUncertainty,
  generateRefinementPlan,
  computeIterationDelta,
  annotateIteration,
  buildIterationSnapshot,
  selectNextDisasmRange,
  summarizeSession,
  DEFAULT_NEST_CONFIG,
} from '../utils/nestEngine';
import type {
  NestSession,
  NestIterationSnapshot,
  NestIterationInput,
  NestConfig,
} from '../utils/nestEngine';
import type { BinaryVerdictResult } from '../utils/correlationEngine';

// ── Helpers ───────────────────────────────────────────────────────────────────

function minimalInput(overrides: Partial<NestIterationInput> = {}): NestIterationInput {
  return {
    disasmOffset:     0x1000,
    disasmLength:     0x200,
    instructionCount: 20,
    sections:         [{ name: '.text', entropy: 4.5, file_size: 4096 }],
    imports:          [],
    strings:          [],
    patterns:         [],
    signatureMatches: [],
    ...overrides,
  };
}

/** Build a BinaryVerdictResult by running the real correlation pass. */
function realVerdict(
  inputOverrides: Partial<NestIterationInput> = {},
): BinaryVerdictResult {
  return runCorrelationPass(minimalInput(inputOverrides));
}

/** Minimal mock BinaryVerdictResult for tests that don't need real signal computation. */
function mockVerdict(
  overrides: Partial<BinaryVerdictResult> = {},
): BinaryVerdictResult {
  return {
    classification:  'clean',
    threatScore:     10,
    confidence:      60,
    signals:         [],
    negativeSignals: [],
    amplifiers:      [],
    dismissals:      [],
    summary:         'Mock clean verdict',
    explainability:  [],
    nextSteps:       [],
    signalCount:     0,
    behaviors:       [],
    reasoningChain:  [],
    contradictions:  [],
    alternatives:    [],
    ...overrides,
  };
}

/** Build a NestSession with N already-completed iterations. */
function sessionWithIterations(
  count: number,
  config: Partial<NestConfig> = {},
): NestSession {
  const session = createNestSession('test.exe', config);
  const snapshots: NestIterationSnapshot[] = [];
  for (let i = 0; i < count; i++) {
    const v = mockVerdict({ confidence: 60 + i * 5 });
    const prev = snapshots[i - 1] ?? null;
    const snap = buildIterationSnapshot(i, minimalInput(), v, prev, null, Date.now());
    snapshots.push(snap);
  }
  return { ...session, iterations: snapshots };
}

// ── createNestSession ─────────────────────────────────────────────────────────

describe('createNestSession', () => {
  it('returns a session with the given binaryPath', () => {
    const s = createNestSession('notepad.exe');
    expect(s.binaryPath).toBe('notepad.exe');
  });

  it('initial status is idle', () => {
    const s = createNestSession('test.exe');
    expect(s.status).toBe('idle');
  });

  it('initial iterations is empty', () => {
    const s = createNestSession('test.exe');
    expect(s.iterations).toEqual([]);
  });

  it('initial finalVerdict is null', () => {
    const s = createNestSession('test.exe');
    expect(s.finalVerdict).toBeNull();
  });

  it('merges config overrides with defaults', () => {
    const s = createNestSession('test.exe', { maxIterations: 10 });
    expect(s.config.maxIterations).toBe(10);
    expect(s.config.minIterations).toBe(DEFAULT_NEST_CONFIG.minIterations);
  });

  it('generates a unique id each call', () => {
    const s1 = createNestSession('test.exe');
    const s2 = createNestSession('test.exe');
    expect(s1.id).not.toBe(s2.id);
  });
});

// ── finalizeSession ───────────────────────────────────────────────────────────

describe('finalizeSession', () => {
  it('sets status to converged', () => {
    const s = createNestSession('test.exe');
    const s2 = finalizeSession(s, 'converged');
    expect(s2.status).toBe('converged');
  });

  it('sets endTime to a number', () => {
    const s = createNestSession('test.exe');
    const s2 = finalizeSession(s, 'converged');
    expect(typeof s2.endTime).toBe('number');
  });

  it('sets errorMessage when provided', () => {
    const s = createNestSession('test.exe');
    const s2 = finalizeSession(s, 'error', 'disk full');
    expect(s2.errorMessage).toBe('disk full');
  });

  it('sets convergedAt to last iteration index on convergence', () => {
    const s = sessionWithIterations(3);
    const s2 = finalizeSession(s, 'converged');
    expect(s2.convergedAt).toBe(2);
  });

  it('convergedAt is null for non-convergence status', () => {
    const s = sessionWithIterations(3);
    const s2 = finalizeSession(s, 'max-reached');
    expect(s2.convergedAt).toBeNull();
  });

  it('finalVerdict reflects last iteration verdict', () => {
    const session = sessionWithIterations(2);
    const s2 = finalizeSession(session, 'converged');
    expect(s2.finalVerdict).not.toBeNull();
    expect(s2.finalVerdict?.classification).toBe('clean');
  });
});

// ── runCorrelationPass ────────────────────────────────────────────────────────

describe('runCorrelationPass', () => {
  it('returns a BinaryVerdictResult for minimal input', () => {
    const v = runCorrelationPass(minimalInput());
    expect(v.classification).toBeDefined();
    expect(typeof v.confidence).toBe('number');
    expect(typeof v.threatScore).toBe('number');
  });

  it('confidence is in [0, 100]', () => {
    const v = runCorrelationPass(minimalInput());
    expect(v.confidence).toBeGreaterThanOrEqual(0);
    expect(v.confidence).toBeLessThanOrEqual(100);
  });

  it('raises threat score for injection imports', () => {
    const clean = runCorrelationPass(minimalInput());
    const threat = runCorrelationPass(minimalInput({
      imports: [
        { name: 'WriteProcessMemory', library: 'KERNEL32' },
        { name: 'VirtualAllocEx',     library: 'KERNEL32' },
        { name: 'CreateRemoteThread', library: 'KERNEL32' },
      ],
    }));
    expect(threat.threatScore).toBeGreaterThan(clean.threatScore);
  });

  it('is deterministic for identical inputs', () => {
    const input = minimalInput();
    const v1 = runCorrelationPass(input);
    const v2 = runCorrelationPass(input);
    expect(v1.classification).toBe(v2.classification);
    expect(v1.confidence).toBe(v2.confidence);
    expect(v1.threatScore).toBe(v2.threatScore);
  });

  it('includes reasoning chain', () => {
    const v = runCorrelationPass(minimalInput());
    expect(Array.isArray(v.reasoningChain)).toBe(true);
  });
});

// ── assessConvergence ─────────────────────────────────────────────────────────

describe('assessConvergence', () => {
  it('returns no-data when no signals and no iterations', () => {
    const s = createNestSession('test.exe');
    const ca = assessConvergence(s, mockVerdict({ signalCount: 0 }));
    expect(ca.reason).toBe('no-data');
    expect(ca.hasConverged).toBe(false);
  });

  it('returns max-iterations when iteration cap reached', () => {
    const s = sessionWithIterations(5, { maxIterations: 5 });
    const ca = assessConvergence(s, mockVerdict({ signalCount: 1 }));
    expect(ca.reason).toBe('max-iterations');
    expect(ca.hasConverged).toBe(true);
  });

  it('returns continue when minIterations not yet met', () => {
    const s = sessionWithIterations(1, { minIterations: 3, maxIterations: 10 });
    const ca = assessConvergence(s, mockVerdict({ confidence: 90, signalCount: 1 }));
    expect(ca.reason).toBe('continue');
    expect(ca.hasConverged).toBe(false);
  });

  it('returns confidence-threshold when confidence meets threshold', () => {
    const s = sessionWithIterations(3, { minIterations: 3, confidenceThreshold: 85 });
    const ca = assessConvergence(s, mockVerdict({ confidence: 90, signalCount: 3 }));
    expect(ca.reason).toBe('confidence-threshold');
    expect(ca.hasConverged).toBe(true);
  });

  it('returns a valid ConvergenceAssessment shape', () => {
    const s = createNestSession('test.exe');
    const ca = assessConvergence(s, mockVerdict({ signalCount: 0 }));
    expect(typeof ca.confidence).toBe('number');
    expect(typeof ca.projectedLoss).toBe('number');
    expect(typeof ca.classificationStable).toBe('boolean');
    expect(typeof ca.confidenceVariance).toBe('number');
    expect(typeof ca.contradictionBurden).toBe('number');
    expect(typeof ca.signalDelta).toBe('number');
    expect(typeof ca.message).toBe('string');
  });
});

// ── evaluateUncertainty ───────────────────────────────────────────────────────

describe('evaluateUncertainty', () => {
  it('returns NestUncertaintyAssessment with shouldStop boolean', () => {
    const s = createNestSession('test.exe');
    const ua = evaluateUncertainty(s, mockVerdict({ signalCount: 0 }));
    expect(typeof ua.shouldStop).toBe('boolean');
    expect(typeof ua.confidence).toBe('number');
    expect(typeof ua.message).toBe('string');
  });

  it('shouldStop is true when max iterations reached', () => {
    const s = sessionWithIterations(5, { maxIterations: 5 });
    const ua = evaluateUncertainty(s, mockVerdict({ signalCount: 1 }));
    expect(ua.shouldStop).toBe(true);
  });

  it('shouldStop is false on first iteration with low confidence', () => {
    const s = createNestSession('test.exe');
    const ua = evaluateUncertainty(s, mockVerdict({ confidence: 40, signalCount: 1 }));
    expect(ua.shouldStop).toBe(false);
  });
});

// ── generateRefinementPlan ────────────────────────────────────────────────────

describe('generateRefinementPlan', () => {
  it('returns a plan with at least one action', () => {
    const v = realVerdict({ sections: [{ name: '.text', entropy: 7.5, file_size: 8192 }] });
    const plan = generateRefinementPlan(v, minimalInput(), 0);
    expect(plan.actions.length).toBeGreaterThan(0);
  });

  it('primaryAction is null or a valid action', () => {
    const v = realVerdict();
    const plan = generateRefinementPlan(v, minimalInput(), 0);
    if (plan.primaryAction !== null) {
      expect(plan.primaryAction.type).toBeDefined();
      expect(plan.primaryAction.reason).toBeTruthy();
    }
  });

  it('expectedBoost is non-negative', () => {
    const v = realVerdict();
    const plan = generateRefinementPlan(v, minimalInput(), 0);
    expect(plan.expectedBoost).toBeGreaterThanOrEqual(0);
  });

  it('rationale is a non-empty string', () => {
    const v = realVerdict();
    const plan = generateRefinementPlan(v, minimalInput(), 0);
    expect(plan.rationale.length).toBeGreaterThan(0);
  });

  it('returns a light consolidation plan for confident-clean binary', () => {
    const v = mockVerdict({ classification: 'clean', confidence: 85, signalCount: 2 });
    const plan = generateRefinementPlan(v, minimalInput(), 1);
    expect(plan.actions.length).toBeGreaterThanOrEqual(1);
    expect(plan.actions[0].priority).toBe('low');
  });
});

// ── computeIterationDelta ─────────────────────────────────────────────────────

describe('computeIterationDelta', () => {
  it('computes zero delta for identical verdicts', () => {
    const v = mockVerdict({ confidence: 60 });
    const snap = buildIterationSnapshot(0, minimalInput(), v, null, null, Date.now());
    const delta = computeIterationDelta(snap, v);
    expect(delta.confidenceDelta).toBe(0);
    expect(delta.verdictChanged).toBe(false);
    expect(delta.newSignals).toEqual([]);
    expect(delta.removedSignals).toEqual([]);
    expect(delta.behaviorsAdded).toEqual([]);
  });

  it('detects confidence improvement', () => {
    const prev = mockVerdict({ confidence: 60 });
    const snap = buildIterationSnapshot(0, minimalInput(), prev, null, null, Date.now());
    const curr = mockVerdict({ confidence: 70 });
    const delta = computeIterationDelta(snap, curr);
    expect(delta.confidenceDelta).toBe(10);
  });

  it('detects verdict change', () => {
    const prev = mockVerdict({ classification: 'clean' });
    const snap = buildIterationSnapshot(0, minimalInput(), prev, null, null, Date.now());
    const curr = mockVerdict({ classification: 'suspicious' });
    const delta = computeIterationDelta(snap, curr);
    expect(delta.verdictChanged).toBe(true);
  });

  it('detects new signals', () => {
    const prev = mockVerdict({ signals: [] });
    const snap = buildIterationSnapshot(0, minimalInput(), prev, null, null, Date.now());
    const curr = mockVerdict({
      signals: [{
        source: 'imports',
        id: 'injection-imports',
        finding: 'Injection API',
        weight: 8,
        corroboratedBy: [],
      }],
    });
    const delta = computeIterationDelta(snap, curr);
    expect(delta.newSignals).toContain('injection-imports');
  });

  it('sets significantChange=true when confidence delta > 3', () => {
    const prev = mockVerdict({ confidence: 50 });
    const snap = buildIterationSnapshot(0, minimalInput(), prev, null, null, Date.now());
    const curr = mockVerdict({ confidence: 60 });
    const delta = computeIterationDelta(snap, curr);
    expect(delta.significantChange).toBe(true);
  });

  it('summary is always a non-empty string', () => {
    const prev = mockVerdict({ confidence: 60 });
    const snap = buildIterationSnapshot(0, minimalInput(), prev, null, null, Date.now());
    const delta = computeIterationDelta(snap, mockVerdict({ confidence: 60 }));
    expect(delta.summary.length).toBeGreaterThan(0);
  });
});

// ── annotateIteration ─────────────────────────────────────────────────────────

describe('annotateIteration', () => {
  it('returns an array of strings', () => {
    const v = mockVerdict({ confidence: 65 });
    const partial = {
      iteration: 0,
      timestamp: Date.now(),
      input: minimalInput(),
      verdict: v,
      confidence: v.confidence,
      refinementPlan: null,
      delta: null,
      durationMs: 100,
    };
    const notes = annotateIteration(partial, null);
    expect(Array.isArray(notes)).toBe(true);
    expect(notes.length).toBeGreaterThan(0);
    expect(typeof notes[0]).toBe('string');
  });

  it('first note always mentions the verdict classification and confidence', () => {
    const v = mockVerdict({ classification: 'suspicious', confidence: 72 });
    const partial = {
      iteration: 0,
      timestamp: Date.now(),
      input: minimalInput(),
      verdict: v,
      confidence: v.confidence,
      refinementPlan: null,
      delta: null,
      durationMs: 50,
    };
    const notes = annotateIteration(partial, null);
    expect(notes[0]).toContain('suspicious');
    expect(notes[0]).toContain('72');
  });

  it('includes delta summary when delta is provided', () => {
    const v = mockVerdict({ confidence: 70 });
    const snap = buildIterationSnapshot(0, minimalInput(), mockVerdict({ confidence: 60 }), null, null, Date.now());
    const delta = computeIterationDelta(snap, v);
    const partial = {
      iteration: 1,
      timestamp: Date.now(),
      input: minimalInput(),
      verdict: v,
      confidence: v.confidence,
      refinementPlan: null,
      delta,
      durationMs: 80,
    };
    const notes = annotateIteration(partial, delta);
    expect(notes.some(n => n.includes('confidence') || n.includes('change') || n.includes('Marginal') || n.includes('Significant'))).toBe(true);
  });
});

// ── buildIterationSnapshot ────────────────────────────────────────────────────

describe('buildIterationSnapshot', () => {
  it('returns a snapshot with matching iteration index', () => {
    const v = mockVerdict({ confidence: 65 });
    const snap = buildIterationSnapshot(2, minimalInput(), v, null, null, Date.now());
    expect(snap.iteration).toBe(2);
  });

  it('confidence matches verdict confidence', () => {
    const v = mockVerdict({ confidence: 73 });
    const snap = buildIterationSnapshot(0, minimalInput(), v, null, null, Date.now());
    expect(snap.confidence).toBe(73);
  });

  it('delta is null for first snapshot (no prev)', () => {
    const v = mockVerdict();
    const snap = buildIterationSnapshot(0, minimalInput(), v, null, null, Date.now());
    expect(snap.delta).toBeNull();
  });

  it('delta is computed when prev is provided', () => {
    const v1 = mockVerdict({ confidence: 60 });
    const snap1 = buildIterationSnapshot(0, minimalInput(), v1, null, null, Date.now());
    const v2 = mockVerdict({ confidence: 70 });
    const snap2 = buildIterationSnapshot(1, minimalInput(), v2, snap1, null, Date.now());
    expect(snap2.delta).not.toBeNull();
    expect(snap2.delta?.confidenceDelta).toBe(10);
  });

  it('annotations array is non-empty', () => {
    const v = mockVerdict({ confidence: 65 });
    const snap = buildIterationSnapshot(0, minimalInput(), v, null, null, Date.now());
    expect(snap.annotations.length).toBeGreaterThan(0);
  });

  it('durationMs is non-negative', () => {
    const start = Date.now() - 50;
    const v = mockVerdict();
    const snap = buildIterationSnapshot(0, minimalInput(), v, null, null, start);
    expect(snap.durationMs).toBeGreaterThanOrEqual(0);
  });
});

// ── selectNextDisasmRange ─────────────────────────────────────────────────────

describe('selectNextDisasmRange', () => {
  it('extends forward when primary action is expand-disasm-forward', () => {
    const plan = generateRefinementPlan(
      mockVerdict({ confidence: 40, signalCount: 1 }),
      minimalInput({ sections: [{ name: '.text', entropy: 7.8, file_size: 8192 }] }),
      0,
    );
    // Override plan to ensure a known type
    const forward = {
      ...plan,
      primaryAction: {
        type: 'expand-disasm-forward' as const,
        priority: 'medium' as const,
        offset: 0x1200,
        length: 0x200,
        reason: 'test forward expansion',
      },
    };
    const range = selectNextDisasmRange(forward, { offset: 0x1000, length: 0x200 }, DEFAULT_NEST_CONFIG);
    expect(range.offset).toBe(0x1200);
    expect(range.length).toBe(0x200);
  });

  it('extends backward when primary action is expand-disasm-backward', () => {
    const plan = generateRefinementPlan(realVerdict(), minimalInput(), 0);
    const backward = {
      ...plan,
      primaryAction: {
        type: 'expand-disasm-backward' as const,
        priority: 'medium' as const,
        reason: 'test backward expansion',
      },
    };
    const range = selectNextDisasmRange(backward, { offset: 0x1000, length: 0x200 }, DEFAULT_NEST_CONFIG);
    expect(range.offset).toBeLessThanOrEqual(0x1000);
    expect(range.length).toBeGreaterThanOrEqual(0x200);
  });

  it('falls back to extending forward when no primary action', () => {
    const emptyPlan = {
      actions: [],
      rationale: 'empty',
      expectedBoost: 0,
      primaryAction: null,
    };
    const range = selectNextDisasmRange(emptyPlan, { offset: 0x1000, length: 0x200 }, DEFAULT_NEST_CONFIG);
    expect(range.offset).toBe(0x1000);
    expect(range.length).toBeGreaterThan(0x200);
  });
});

// ── summarizeSession ──────────────────────────────────────────────────────────

describe('summarizeSession', () => {
  it('returns 0 iterations for a fresh session', () => {
    const s = createNestSession('test.exe');
    const summary = summarizeSession(finalizeSession(s, 'max-reached'));
    expect(summary.totalIterations).toBe(0);
    expect(summary.finalConfidence).toBe(0);
  });

  it('returns correct totalIterations', () => {
    const s = sessionWithIterations(4);
    const summary = summarizeSession(finalizeSession(s, 'max-reached'));
    expect(summary.totalIterations).toBe(4);
  });

  it('finalConfidence matches last iteration confidence', () => {
    const s = sessionWithIterations(3);
    const last = s.iterations[2];
    const summary = summarizeSession(finalizeSession(s, 'converged'));
    expect(summary.finalConfidence).toBe(last.confidence);
  });

  it('confidenceProgression has correct length', () => {
    const s = sessionWithIterations(4);
    const summary = summarizeSession(finalizeSession(s, 'max-reached'));
    expect(summary.confidenceProgression.length).toBe(4);
  });

  it('convergedReason is confidence-threshold on converged session', () => {
    const s = sessionWithIterations(3);
    const summary = summarizeSession(finalizeSession(s, 'converged'));
    expect(summary.convergedReason).toBe('confidence-threshold');
  });

  it('convergedReason is plateau on plateau session', () => {
    const s = sessionWithIterations(3);
    const summary = summarizeSession(finalizeSession(s, 'plateau'));
    expect(summary.convergedReason).toBe('plateau');
  });

  it('convergedReason is max-iterations on max-reached session', () => {
    const s = sessionWithIterations(3);
    const summary = summarizeSession(finalizeSession(s, 'max-reached'));
    expect(summary.convergedReason).toBe('max-iterations');
  });

  it('totalDurationMs is non-negative', () => {
    const s = sessionWithIterations(2);
    const summary = summarizeSession(finalizeSession(s, 'converged'));
    expect(summary.totalDurationMs).toBeGreaterThanOrEqual(0);
  });
});

// ── Behavioral regression ─────────────────────────────────────────────────────

describe('nestEngine — behavioral regression', () => {
  /** Fixed benign input: benign .text section, no imports, no strings */
  const BENIGN_INPUT: NestIterationInput = minimalInput({
    sections:    [{ name: '.text', entropy: 4.2, file_size: 4096 }],
    imports:     [],
    strings:     [],
    patterns:    [],
  });

  /** Fixed threat input: injection APIs */
  const THREAT_INPUT: NestIterationInput = minimalInput({
    sections: [{ name: '.text', entropy: 7.6, file_size: 8192 }],
    imports:  [
      { name: 'WriteProcessMemory', library: 'KERNEL32' },
      { name: 'VirtualAllocEx',     library: 'KERNEL32' },
      { name: 'CreateRemoteThread', library: 'KERNEL32' },
    ],
    strings:  [],
    patterns: [],
  });

  it('benign input never produces likely-malware or ransomware-like verdict', () => {
    for (let i = 0; i < 3; i++) {
      const v = runCorrelationPass(BENIGN_INPUT);
      expect(['likely-malware', 'ransomware-like', 'dropper']).not.toContain(v.classification);
    }
  });

  it('threat input always raises threat score above benign', () => {
    const benign = runCorrelationPass(BENIGN_INPUT);
    const threat = runCorrelationPass(THREAT_INPUT);
    expect(threat.threatScore).toBeGreaterThan(benign.threatScore);
  });

  it('identical input always produces identical verdict classification', () => {
    const v1 = runCorrelationPass(BENIGN_INPUT);
    const v2 = runCorrelationPass(BENIGN_INPUT);
    expect(v1.classification).toBe(v2.classification);
  });

  it('max-iterations convergence is always triggered at config.maxIterations', () => {
    const s = sessionWithIterations(3, { maxIterations: 3, minIterations: 0 });
    const ca = assessConvergence(s, mockVerdict({ signalCount: 1, confidence: 50 }));
    expect(ca.reason).toBe('max-iterations');
    expect(ca.hasConverged).toBe(true);
  });
});
