import { describe, it, expect, beforeEach } from 'vitest';
import {
  createBenchmarkRun,
  gradeEntry,
  computeBenchmarkSummary,
  scoreClassifications,
  compareBenchmarkRuns,
  saveBenchmarkRun,
  loadBenchmarkHistory,
  getBenchmarkRun,
  deleteBenchmarkRun,
  clearBenchmarkHistory,
  type BenchmarkRun,
  type BenchmarkEntry,
} from '../../utils/benchmarkHarness';
import { DEFAULT_NEST_CONFIG } from '../../utils/nestEngine';
import type { NestSummary } from '../../utils/nestEngine';
import type { CorpusEntry } from '../../utils/corpusManager';

// ── Fixtures ──────────────────────────────────────────────────────────────────

function makeSummary(confidence: number, verdict: string): NestSummary {
  return {
    totalIterations: 4,
    finalConfidence: confidence,
    finalVerdict: verdict,
    totalDurationMs: 1000,
    confidenceProgression: [60, 75, 90, confidence],
    convergedReason: 'confidence-threshold',
    keyFindings: [],
    improvementTotal: confidence - 60,
  };
}

function makeCorpusEntry(
  sha256: string,
  groundTruth: 'clean' | 'malicious' | 'unknown',
  expectedClassification: string | null = null
): CorpusEntry {
  return {
    sha256,
    binaryPath: `C:\\test\\${sha256}.exe`,
    label: `${sha256}.exe`,
    groundTruth,
    expectedClassification: expectedClassification as any,
    tags: [],
    addedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    lastNestSummary: null,
    lastSessionId: null,
    notes: '',
  };
}

// ── Setup ─────────────────────────────────────────────────────────────────────

beforeEach(() => {
  clearBenchmarkHistory();
});

// ── createBenchmarkRun ────────────────────────────────────────────────────────

describe('createBenchmarkRun', () => {
  it('creates a run in pending state with empty entries', () => {
    const run = createBenchmarkRun('Test Run', DEFAULT_NEST_CONFIG);
    expect(run.status).toBe('pending');
    expect(run.entries).toHaveLength(0);
    expect(run.summary).toBeNull();
    expect(run.name).toBe('Test Run');
  });

  it('generates unique IDs', () => {
    const ids = new Set(
      Array.from({ length: 5 }, () => createBenchmarkRun('r', DEFAULT_NEST_CONFIG).id)
    );
    expect(ids.size).toBe(5);
  });
});

// ── gradeEntry ────────────────────────────────────────────────────────────────

describe('gradeEntry', () => {
  it('passes when verdict and confidence both match', () => {
    const entry = makeCorpusEntry('hash1', 'clean', 'clean');
    const be = gradeEntry(entry, makeSummary(90, 'clean'), 75, null, null);
    expect(be.pass).toBe(true);
    expect(be.verdictPass).toBe(true);
    expect(be.confidencePass).toBe(true);
    expect(be.failReason).toBe('');
  });

  it('fails on verdict mismatch', () => {
    const entry = makeCorpusEntry('hash2', 'malicious', 'dropper');
    const be = gradeEntry(entry, makeSummary(90, 'clean'), 75, null, null);
    expect(be.pass).toBe(false);
    expect(be.verdictPass).toBe(false);
    expect(be.failReason).toContain('Expected');
  });

  it('fails when confidence below threshold', () => {
    const entry = makeCorpusEntry('hash3', 'clean', 'clean');
    const be = gradeEntry(entry, makeSummary(60, 'clean'), 75, null, null);
    expect(be.pass).toBe(false);
    expect(be.confidencePass).toBe(false);
    expect(be.failReason).toContain('Confidence');
  });

  it('computes confidenceDelta vs prior run', () => {
    const entry = makeCorpusEntry('hash4', 'clean', 'clean');
    const be = gradeEntry(entry, makeSummary(90, 'clean'), 75, 80, null);
    expect(be.confidenceDelta).toBe(10);
  });

  it('marks entry as skipped when summary is null and no error', () => {
    const entry = makeCorpusEntry('hash5', 'clean', null);
    const be = gradeEntry(entry, null, 75, null, null);
    expect(be.skipped).toBe(true);
    expect(be.pass).toBe(false);
  });

  it('stores error message and marks not skipped when error provided', () => {
    const entry = makeCorpusEntry('hash6', 'clean', null);
    const be = gradeEntry(entry, null, 75, null, 'Tauri IPC timeout');
    expect(be.skipped).toBe(false);
    expect(be.errorMessage).toBe('Tauri IPC timeout');
  });

  it('falls back to polarity when no expectedClassification', () => {
    const entry = makeCorpusEntry('hash7', 'malicious', null);
    const be = gradeEntry(entry, makeSummary(85, 'dropper'), 75, null, null);
    expect(be.verdictPass).toBe(true);
  });
});

// ── computeBenchmarkSummary ───────────────────────────────────────────────────

describe('computeBenchmarkSummary', () => {
  it('computes correct pass rate', () => {
    const e1 = makeCorpusEntry('e1', 'clean', 'clean');
    const e2 = makeCorpusEntry('e2', 'clean', 'clean');
    const entries: BenchmarkEntry[] = [
      gradeEntry(e1, makeSummary(95, 'clean'), 75, null, null),
      gradeEntry(e2, makeSummary(60, 'clean'), 75, null, null), // confidence fail
    ];
    const summary = computeBenchmarkSummary(entries);
    expect(summary.passed).toBe(1);
    expect(summary.failed).toBe(1);
    expect(summary.passRate).toBe(0.5);
  });

  it('computes avg confidence from entries with results', () => {
    const e1 = makeCorpusEntry('c1', 'clean', 'clean');
    const e2 = makeCorpusEntry('c2', 'clean', 'clean');
    const entries: BenchmarkEntry[] = [
      gradeEntry(e1, makeSummary(80, 'clean'), 75, null, null),
      gradeEntry(e2, makeSummary(100, 'clean'), 75, null, null),
    ];
    const summary = computeBenchmarkSummary(entries);
    expect(summary.avgConfidence).toBe(90);
  });
});

// ── scoreClassifications ──────────────────────────────────────────────────────

describe('scoreClassifications', () => {
  it('returns empty result for no graded entries', () => {
    const { perClassification, macroF1 } = scoreClassifications([]);
    expect(perClassification).toHaveLength(0);
    expect(macroF1).toBeNull();
  });

  it('computes precision=1, recall=1, f1=1 for perfect run', () => {
    const e1 = makeCorpusEntry('p1', 'clean', 'clean');
    const e2 = makeCorpusEntry('p2', 'malicious', 'dropper');
    const entries: BenchmarkEntry[] = [
      gradeEntry(e1, makeSummary(90, 'clean'), 75, null, null),
      gradeEntry(e2, makeSummary(85, 'dropper'), 75, null, null),
    ];
    const { perClassification, macroF1 } = scoreClassifications(entries);
    const cleanMetrics = perClassification.find(m => m.classification === 'clean')!;
    expect(cleanMetrics.precision).toBe(1);
    expect(cleanMetrics.recall).toBe(1);
    expect(cleanMetrics.f1).toBe(1);
    expect(macroF1).toBe(1);
  });

  it('detects false positives correctly', () => {
    // Both expected 'clean', one gets 'dropper'
    const e1 = makeCorpusEntry('fp1', 'clean', 'clean');
    const e2 = makeCorpusEntry('fp2', 'clean', 'clean');
    const e1graded = gradeEntry(e1, makeSummary(90, 'clean'), 75, null, null);
    const e2graded = gradeEntry(e2, makeSummary(90, 'dropper'), 75, null, null);
    const { perClassification } = scoreClassifications([e1graded, e2graded]);
    const dropperMetrics = perClassification.find(m => m.classification === 'dropper')!;
    expect(dropperMetrics.falsePositives).toBe(1);
  });
});

// ── compareBenchmarkRuns ──────────────────────────────────────────────────────

describe('compareBenchmarkRuns', () => {
  function makeRun(id: string, passAll: boolean): BenchmarkRun {
    const run = createBenchmarkRun(id, DEFAULT_NEST_CONFIG);
    const e = makeCorpusEntry('shared-hash', 'clean', 'clean');
    const verdict = passAll ? 'clean' : 'dropper';
    const conf = passAll ? 90 : 90;
    run.entries = [gradeEntry(e, makeSummary(conf, verdict), 75, null, null)];
    run.summary = computeBenchmarkSummary(run.entries);
    run.status = 'complete';
    run.completedAt = new Date().toISOString();
    return run;
  }

  it('detects regression when pass becomes fail', () => {
    const runA = makeRun('A', true);
    const runB = makeRun('B', false);
    const cmp = compareBenchmarkRuns(runA, runB);
    expect(cmp.hasRegression).toBe(true);
    expect(cmp.newFailures).toContain('shared-hash');
  });

  it('detects improvement when fail becomes pass', () => {
    const runA = makeRun('A', false);
    const runB = makeRun('B', true);
    const cmp = compareBenchmarkRuns(runA, runB);
    expect(cmp.hasImprovement).toBe(true);
    expect(cmp.newPasses).toContain('shared-hash');
  });

  it('computes passRateDelta correctly', () => {
    const runA = makeRun('A', false); // 0% pass rate
    const runB = makeRun('B', true);  // 100% pass rate
    const cmp = compareBenchmarkRuns(runA, runB);
    expect(cmp.passRateDelta).toBeCloseTo(1.0);
  });
});

// ── persistence ───────────────────────────────────────────────────────────────

describe('benchmark persistence', () => {
  it('saves and loads a run', () => {
    const run = createBenchmarkRun('Persisted', DEFAULT_NEST_CONFIG);
    run.status = 'complete';
    run.completedAt = new Date().toISOString();
    saveBenchmarkRun(run);
    const loaded = getBenchmarkRun(run.id);
    expect(loaded).not.toBeNull();
    expect(loaded!.name).toBe('Persisted');
  });

  it('loadBenchmarkHistory returns newest first', () => {
    const r1 = createBenchmarkRun('First', DEFAULT_NEST_CONFIG);
    r1.createdAt = '2024-01-01T00:00:00.000Z';
    const r2 = createBenchmarkRun('Second', DEFAULT_NEST_CONFIG);
    r2.createdAt = '2024-06-01T00:00:00.000Z';
    saveBenchmarkRun(r1);
    saveBenchmarkRun(r2);
    const history = loadBenchmarkHistory();
    expect(history[0].name).toBe('Second');
    expect(history[1].name).toBe('First');
  });

  it('deleteBenchmarkRun removes the run', () => {
    const run = createBenchmarkRun('Delete me', DEFAULT_NEST_CONFIG);
    saveBenchmarkRun(run);
    expect(deleteBenchmarkRun(run.id)).toBe(true);
    expect(getBenchmarkRun(run.id)).toBeNull();
  });

  it('deleteBenchmarkRun returns false for unknown id', () => {
    expect(deleteBenchmarkRun('no-such-id')).toBe(false);
  });
});
