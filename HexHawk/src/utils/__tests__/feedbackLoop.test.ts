/**
 * @vitest-environment jsdom
 *
 * feedbackLoop.test.ts — Integration tests for the NEST feedback-loop additions:
 *   1. ingestDirectory   — bulk corpus ingestion with CLEAN/SUSPICIOUS/MALICIOUS labels
 *   2. promoteRecurringSignals — signals recurring in stable correct verdicts are promoted
 *   3. promoteRecurringSignals — unstable / incorrect records do NOT trigger promotion
 *   4. detectRegressions — a previously high-performing signal that degrades is flagged
 *   5. getAccuracyTimeline — returns chronologically sorted snapshots from completed runs
 */
import { describe, it, expect, beforeEach } from 'vitest';
import {
  ingestDirectory,
  getCorpusEntry,
  clearCorpus,
  type DirectoryIngestManifest,
} from '../corpusManager';
import {
  promoteRecurringSignals,
  detectRegressions,
  type LearningDecision,
  type ImprovementBreakdown,
  type PatternPromotionRule,
} from '../iterationLearning';
import {
  createBenchmarkRun,
  computeBenchmarkSummary,
  saveBenchmarkRun,
  getAccuracyTimeline,
  clearBenchmarkHistory,
  gradeEntry,
  type BenchmarkRun,
} from '../benchmarkHarness';
import { DEFAULT_NEST_CONFIG } from '../nestEngine';
import type { TrainingRecord, NestSummary } from '../nestEngine';
import type { CorpusEntry } from '../corpusManager';

// ─── Shared fixtures ──────────────────────────────────────────────────────────

function makeSummary(
  confidence: number,
  verdict: string,
  prog?: number[],
  findings: string[] = [],
): NestSummary {
  return {
    totalIterations: prog?.length ?? 3,
    finalConfidence: confidence,
    finalVerdict: verdict,
    totalDurationMs: 500,
    confidenceProgression: prog ?? [60, 75, confidence],
    convergedReason: 'confidence-threshold',
    keyFindings: findings,
    improvementTotal: confidence - (prog?.[0] ?? 60),
  };
}

function makeTrainingRecord(
  sha256: string,
  groundTruth: 'clean' | 'malicious' | 'unknown',
  finalVerdict: string,
  verdictStability: number,
  groundTruthMatch: boolean,
  signalIds: string[],
): TrainingRecord {
  return {
    sha256,
    binaryPath: `C:\\samples\\${sha256}.exe`,
    summary: makeSummary(80, finalVerdict, [60, 70, 80], signalIds),
    verdictStability,
    confidenceDelta: 20,
    groundTruthMatch,
    signalIds,
  };
}

function makeDecision(
  iteration: number,
  level: LearningDecision['improvementLevel'],
  reinforceSignals: string[] = [],
  deprioritise: string[] = [],
): LearningDecision {
  const composite =
    level === 'high' ? 15 : level === 'medium' ? 6 : level === 'low' ? 2 : -5;
  const breakdown: ImprovementBreakdown = {
    confidenceDelta: composite > 0 ? 5 : -3,
    contradictionReduction: 0,
    clarityGain: 0,
    uncorroboratedDelta: 0,
    composite,
  };
  return {
    iteration,
    improvementLevel: level,
    breakdown,
    diagnosis: 'test',
    signalLearning: [],
    strategyAdjustments: [],
    shouldPivot: level === 'negative',
    shouldReinforce: level === 'high',
    reinforceSignals,
    deprioritise,
    promote: [],
  };
}

function makeCorpusEntry(sha256: string, groundTruth: 'clean' | 'malicious' | 'unknown'): CorpusEntry {
  return {
    sha256,
    binaryPath: `C:\\samples\\${sha256}.exe`,
    label: `${sha256}.exe`,
    groundTruth,
    expectedClassification: null,
    tags: [],
    addedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    lastNestSummary: null,
    lastSessionId: null,
    notes: '',
  };
}

// ─── Setup ────────────────────────────────────────────────────────────────────

beforeEach(() => {
  clearCorpus();
  clearBenchmarkHistory();
});

// ─── Test 1: ingestDirectory maps CLEAN/SUSPICIOUS/MALICIOUS to corpus labels ─

describe('ingestDirectory', () => {
  it('maps CLEAN→clean, SUSPICIOUS→unknown, MALICIOUS→malicious and deduplicates by sha256', () => {
    const manifest: DirectoryIngestManifest = {
      name: 'test-corpus-v1',
      entries: [
        { sha256: 'aaa', path: 'C:\\samples\\aaa.exe', label: 'CLEAN' },
        { sha256: 'bbb', path: 'C:\\samples\\bbb.exe', label: 'SUSPICIOUS' },
        { sha256: 'ccc', path: 'C:\\samples\\ccc.exe', label: 'MALICIOUS' },
      ],
    };

    const result = ingestDirectory(manifest);

    expect(result.added).toBe(3);
    expect(result.updated).toBe(0);
    expect(result.skipped).toBe(0);
    expect(result.errors).toHaveLength(0);

    expect(getCorpusEntry('aaa')?.groundTruth).toBe('clean');
    expect(getCorpusEntry('bbb')?.groundTruth).toBe('unknown');   // SUSPICIOUS → unknown
    expect(getCorpusEntry('ccc')?.groundTruth).toBe('malicious');

    // Re-ingesting the same manifest must be idempotent (updated, not added again)
    const second = ingestDirectory(manifest);
    expect(second.added).toBe(0);
    expect(second.updated).toBe(3);
  });
});

// ─── Test 2: promoteRecurringSignals promotes signals in stable correct records ─

describe('promoteRecurringSignals', () => {
  it('promotes signals appearing in ≥2 stable, ground-truth-correct records', () => {
    const records: TrainingRecord[] = [
      makeTrainingRecord('h1', 'malicious', 'ransomware-like', 0.9,  true,  ['sig-crypto', 'sig-shadow']),
      makeTrainingRecord('h2', 'malicious', 'ransomware-like', 0.85, true,  ['sig-crypto', 'sig-shadow']),
      makeTrainingRecord('h3', 'malicious', 'ransomware-like', 0.8,  true,  ['sig-crypto']),
      // Only appears once → should NOT be promoted
      makeTrainingRecord('h4', 'clean',     'clean',           0.95, true,  ['sig-unique-once']),
    ];

    const promoted = promoteRecurringSignals(records, [], 2, 0.75);

    // sig-crypto appears in 3 qualifying records → promoted
    // sig-shadow appears in 2 qualifying records → promoted
    // sig-unique-once appears in only 1 → not promoted
    const ids = promoted.map(p => p.patternId);
    expect(ids).toContain('sig-crypto');
    expect(ids).toContain('sig-shadow');
    expect(ids).not.toContain('sig-unique-once');

    // All promoted patterns are active
    promoted.forEach(p => expect(p.isActive).toBe(true));

    // Result is deterministic: highest benefit score first
    const scores = promoted.map(p => p.globalBenefitScore);
    expect(scores[0]).toBeGreaterThanOrEqual(scores[scores.length - 1]);
  });

// ─── Test 3: unstable or incorrect records do not trigger promotion ───────────

  it('does not promote signals from unstable or ground-truth-mismatched records', () => {
    const records: TrainingRecord[] = [
      // High stability, but verdict is WRONG
      makeTrainingRecord('h1', 'clean', 'ransomware-like', 0.9,  false, ['sig-wrong']),
      makeTrainingRecord('h2', 'clean', 'ransomware-like', 0.88, false, ['sig-wrong']),
      makeTrainingRecord('h3', 'clean', 'ransomware-like', 0.9,  false, ['sig-wrong']),
      // Correct verdict, but stability too low
      makeTrainingRecord('h4', 'malicious', 'ransomware-like', 0.3, true, ['sig-unstable']),
      makeTrainingRecord('h5', 'malicious', 'ransomware-like', 0.4, true, ['sig-unstable']),
      makeTrainingRecord('h6', 'malicious', 'ransomware-like', 0.5, true, ['sig-unstable']),
    ];

    const promoted = promoteRecurringSignals(records, [], 2, 0.75);

    expect(promoted).toHaveLength(0);
  });
});

// ─── Test 4: detectRegressions flags a formerly high-performing signal ─────────

describe('detectRegressions', () => {
  it('reports critical regression when a previously high-success pattern now drives negative improvement', () => {
    // Build a history where 'pat-X' consistently drove high improvement
    // (4 out of 4 = 100% high rate → critical severity → rollbackRecommended)
    const history: LearningDecision[] = [
      makeDecision(0, 'high', ['pat-X'], []),
      makeDecision(1, 'high', ['pat-X'], []),
      makeDecision(2, 'high', ['pat-X'], []),
      makeDecision(3, 'high', ['pat-X'], []),
    ];

    // The current decision shows pat-X now in deprioritise with negative level
    const current = makeDecision(4, 'negative', [], ['pat-X']);

    const regressions = detectRegressions(current, history);

    expect(regressions.length).toBeGreaterThan(0);
    const reg = regressions.find(r => r.patternId === 'pat-X');
    expect(reg).toBeDefined();
    expect(reg!.rollbackRecommended).toBe(true);
    expect(['critical', 'major']).toContain(reg!.regressionSeverity);
  });
});

// ─── Test 5: getAccuracyTimeline returns chronologically sorted snapshots ──────

describe('getAccuracyTimeline', () => {
  it('returns one snapshot per completed run in ascending timestamp order', () => {
    // Manufacture two completed runs with different timestamps
    const runA = createBenchmarkRun('Run-Alpha', DEFAULT_NEST_CONFIG);
    runA.status = 'complete';
    runA.completedAt = '2026-01-10T08:00:00.000Z';
    runA.entries = [
      gradeEntry(makeCorpusEntry('s1', 'clean'), makeSummary(80, 'clean'), 70, null, null),
      gradeEntry(makeCorpusEntry('s2', 'malicious'), makeSummary(85, 'ransomware-like'), 70, null, null),
    ];
    runA.summary = computeBenchmarkSummary(runA.entries);
    saveBenchmarkRun(runA);

    const runB = createBenchmarkRun('Run-Beta', DEFAULT_NEST_CONFIG);
    runB.status = 'complete';
    runB.completedAt = '2026-02-14T12:00:00.000Z';
    runB.entries = [
      gradeEntry(makeCorpusEntry('s1', 'clean'), makeSummary(90, 'clean'), 70, null, null),
    ];
    runB.summary = computeBenchmarkSummary(runB.entries);
    saveBenchmarkRun(runB);

    const timeline = getAccuracyTimeline();

    expect(timeline).toHaveLength(2);
    // Oldest run comes first
    expect(timeline[0].runName).toBe('Run-Alpha');
    expect(timeline[1].runName).toBe('Run-Beta');

    // passRate must be a fraction in [0,1]
    timeline.forEach(snap => {
      expect(snap.passRate).toBeGreaterThanOrEqual(0);
      expect(snap.passRate).toBeLessThanOrEqual(1);
      expect(snap.totalEntries).toBeGreaterThan(0);
    });
  });
});
