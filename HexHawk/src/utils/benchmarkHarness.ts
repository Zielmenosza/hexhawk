/**
 * benchmarkHarness — NEST Benchmark Orchestration
 *
 * Runs NEST against a corpus of labelled binaries and tracks verdict accuracy
 * over time. Supports:
 *   - Creating and saving benchmark runs
 *   - Per-entry pass/fail grading against expected labels
 *   - Precision, recall, F1 by classification
 *   - Run-to-run comparison (regression / improvement detection)
 *   - Full run history persisted in localStorage
 *
 * Storage key: 'hexhawk:benchmarks'
 */

import type { BinaryClassification } from './correlationEngine';
import type { NestConfig, NestSummary } from './nestEngine';
import type { CorpusEntry, CorpusLabel } from './corpusManager';

// ── Constants ──────────────────────────────────────────────────────────────────

const STORE_KEY     = 'hexhawk:benchmarks';
const STORE_VERSION = 1;
const MAX_RUNS      = 50;   // keep the 50 most recent runs

// ── Types ──────────────────────────────────────────────────────────────────────

/** Result for a single corpus entry within a benchmark run. */
export interface BenchmarkEntry {
  sha256: string;
  binaryPath: string;
  binaryLabel: string;
  /** Ground-truth label from corpus. */
  groundTruth: CorpusLabel;
  /** More specific expected NEST classification, if set. */
  expectedClassification: BinaryClassification | null;
  /** NEST classification produced during this run. */
  actualClassification: BinaryClassification | null;
  /** NEST confidence produced during this run. */
  actualConfidence: number | null;
  /** Expected confidence threshold for a pass. */
  expectedMinConfidence: number;
  /**
   * A run is a "verdict pass" when:
   *   - expectedClassification is set AND actualClassification matches, OR
   *   - expectedClassification is null AND groundTruth aligns with
   *     the clean/malicious polarity of actualClassification
   * Additionally confidence must meet expectedMinConfidence.
   */
  verdictPass: boolean;
  confidencePass: boolean;
  /** Both verdictPass AND confidencePass. */
  pass: boolean;
  /** Human-readable reason for failure, empty string on pass. */
  failReason: string;
  /** Confidence delta vs the previous run for this sha256 (null if no prior run). */
  confidenceDelta: number | null;
  /** True if this entry was already in the corpus but no NEST result was found. */
  skipped: boolean;
  /** Error message if NEST threw during this entry. */
  errorMessage: string | null;
}

/** Aggregate precision/recall/F1 for a single classification label. */
export interface ClassificationMetrics {
  classification: BinaryClassification;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1: number;
}

/** Summary statistics for a complete benchmark run. */
export interface BenchmarkSummary {
  totalEntries: number;
  passed: number;
  failed: number;
  skipped: number;
  passRate: number;
  avgConfidence: number | null;
  avgConfidenceDelta: number | null;
  perClassification: ClassificationMetrics[];
  /** Macro-averaged F1 across all classifications with ground truth. */
  macroF1: number | null;
}

/** A complete benchmark run. */
export interface BenchmarkRun {
  id: string;
  name: string;
  createdAt: string;
  completedAt: string | null;
  status: 'pending' | 'running' | 'complete' | 'aborted';
  config: NestConfig;
  entries: BenchmarkEntry[];
  summary: BenchmarkSummary | null;
  /** Freeform notes attached to the run. */
  notes: string;
}

/** Comparison between two runs (b vs a). */
export interface BenchmarkComparison {
  runAId: string;
  runBId: string;
  runAName: string;
  runBName: string;
  passRateDelta: number;   // positive = improvement
  avgConfidenceDelta: number | null;
  macroF1Delta: number | null;
  /** Entries that changed from fail → pass. */
  newPasses: string[];     // sha256 list
  /** Entries that changed from pass → fail (regressions). */
  newFailures: string[];   // sha256 list
  hasRegression: boolean;
  hasImprovement: boolean;
}

interface BenchmarkStore {
  version: number;
  updated: number;
  runs: BenchmarkRun[];
}

// ── Helpers — polarity mapping ─────────────────────────────────────────────────

const CLEAN_CLASSIFICATIONS: ReadonlySet<BinaryClassification> = new Set([
  'clean',
  'unknown',
]);

function polarityOf(cls: BinaryClassification | null): CorpusLabel {
  if (!cls) return 'unknown';
  return CLEAN_CLASSIFICATIONS.has(cls) ? 'clean' : 'malicious';
}

// ── Storage ────────────────────────────────────────────────────────────────────

function loadStore(): BenchmarkStore {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    if (!raw) return emptyStore();
    const parsed: BenchmarkStore = JSON.parse(raw);
    if (parsed.version !== STORE_VERSION) return emptyStore();
    return parsed;
  } catch {
    return emptyStore();
  }
}

function emptyStore(): BenchmarkStore {
  return { version: STORE_VERSION, updated: Date.now(), runs: [] };
}

function saveStore(store: BenchmarkStore): void {
  store.updated = Date.now();
  // Evict oldest runs if over budget
  if (store.runs.length > MAX_RUNS) {
    store.runs.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
    store.runs = store.runs.slice(store.runs.length - MAX_RUNS);
  }
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify(store));
  } catch {
    // Quota exceeded — drop the oldest half and retry
    store.runs = store.runs.slice(Math.ceil(store.runs.length / 2));
    try {
      localStorage.setItem(STORE_KEY, JSON.stringify(store));
    } catch {
      // Silent fail
    }
  }
}

let _runIdCounter = 0;
function makeRunId(): string {
  return `bm-${Date.now()}-${++_runIdCounter}`;
}

// ── Grading ────────────────────────────────────────────────────────────────────

/**
 * Grade a single corpus entry against the NEST summary produced for it.
 * @param entry         Corpus entry (ground truth source)
 * @param summary       NEST summary produced this run (null if skipped/error)
 * @param minConfidence Minimum confidence threshold for a pass
 * @param priorConfidence Confidence from the previous run for delta calculation
 * @param error         Error message if NEST threw
 */
export function gradeEntry(
  entry: CorpusEntry,
  summary: NestSummary | null,
  minConfidence: number,
  priorConfidence: number | null,
  error: string | null
): BenchmarkEntry {
  const base: BenchmarkEntry = {
    sha256: entry.sha256,
    binaryPath: entry.binaryPath,
    binaryLabel: entry.label,
    groundTruth: entry.groundTruth,
    expectedClassification: entry.expectedClassification,
    actualClassification: null,
    actualConfidence: null,
    expectedMinConfidence: minConfidence,
    verdictPass: false,
    confidencePass: false,
    pass: false,
    failReason: '',
    confidenceDelta: null,
    skipped: summary === null && error === null,
    errorMessage: error,
  };

  if (!summary) {
    base.failReason = error ?? 'No NEST result available';
    return base;
  }

  base.actualClassification = summary.finalVerdict as BinaryClassification;
  base.actualConfidence = summary.finalConfidence;

  if (priorConfidence !== null) {
    base.confidenceDelta = summary.finalConfidence - priorConfidence;
  }

  // Verdict pass
  if (entry.expectedClassification !== null) {
    base.verdictPass = summary.finalVerdict === entry.expectedClassification;
  } else {
    // Fall back to clean/malicious polarity check
    base.verdictPass = polarityOf(summary.finalVerdict as BinaryClassification) === entry.groundTruth ||
                       entry.groundTruth === 'unknown';
  }

  // Confidence pass
  base.confidencePass = summary.finalConfidence >= minConfidence;

  base.pass = base.verdictPass && base.confidencePass;

  if (!base.pass) {
    const reasons: string[] = [];
    if (!base.verdictPass) {
      reasons.push(
        entry.expectedClassification !== null
          ? `Expected '${entry.expectedClassification}', got '${summary.finalVerdict}'`
          : `Polarity mismatch: ground truth '${entry.groundTruth}', got '${polarityOf(summary.finalVerdict as BinaryClassification)}'`
      );
    }
    if (!base.confidencePass) {
      reasons.push(`Confidence ${summary.finalConfidence}% < required ${minConfidence}%`);
    }
    base.failReason = reasons.join('; ');
  }

  return base;
}

// ── Scoring ────────────────────────────────────────────────────────────────────

/**
 * Compute per-classification precision/recall/F1 and macro-F1.
 */
export function scoreClassifications(entries: BenchmarkEntry[]): {
  perClassification: ClassificationMetrics[];
  macroF1: number | null;
} {
  // Only consider entries that have both expected and actual classifications
  const graded = entries.filter(
    e => e.expectedClassification !== null && e.actualClassification !== null
  );

  if (graded.length === 0) return { perClassification: [], macroF1: null };

  const classes = Array.from(
    new Set(graded.flatMap(e => [e.expectedClassification!, e.actualClassification!]))
  );

  const metrics: ClassificationMetrics[] = classes.map(cls => {
    const tp = graded.filter(
      e => e.actualClassification === cls && e.expectedClassification === cls
    ).length;
    const fp = graded.filter(
      e => e.actualClassification === cls && e.expectedClassification !== cls
    ).length;
    const fn = graded.filter(
      e => e.expectedClassification === cls && e.actualClassification !== cls
    ).length;

    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall    = tp + fn > 0 ? tp / (tp + fn) : 0;
    const f1        = precision + recall > 0
      ? (2 * precision * recall) / (precision + recall)
      : 0;

    return { classification: cls, truePositives: tp, falsePositives: fp, falseNegatives: fn, precision, recall, f1 };
  });

  const macroF1 = metrics.length > 0
    ? metrics.reduce((s, m) => s + m.f1, 0) / metrics.length
    : null;

  return { perClassification: metrics, macroF1 };
}

/**
 * Compute aggregate summary for a set of graded entries.
 */
export function computeBenchmarkSummary(entries: BenchmarkEntry[]): BenchmarkSummary {
  const passed  = entries.filter(e => e.pass).length;
  const failed  = entries.filter(e => !e.pass && !e.skipped && !e.errorMessage).length;
  const skipped = entries.filter(e => e.skipped || e.errorMessage !== null).length;
  const total   = entries.length;

  const withConf = entries.filter(e => e.actualConfidence !== null);
  const avgConfidence = withConf.length > 0
    ? withConf.reduce((s, e) => s + e.actualConfidence!, 0) / withConf.length
    : null;

  const withDelta = entries.filter(e => e.confidenceDelta !== null);
  const avgConfidenceDelta = withDelta.length > 0
    ? withDelta.reduce((s, e) => s + e.confidenceDelta!, 0) / withDelta.length
    : null;

  const { perClassification, macroF1 } = scoreClassifications(entries);

  return {
    totalEntries: total,
    passed,
    failed,
    skipped,
    passRate: total > 0 ? passed / total : 0,
    avgConfidence,
    avgConfidenceDelta,
    perClassification,
    macroF1,
  };
}

// ── Public API ─────────────────────────────────────────────────────────────────

/**
 * Create a new benchmark run record in "pending" state.
 */
export function createBenchmarkRun(name: string, config: NestConfig, notes = ''): BenchmarkRun {
  return {
    id: makeRunId(),
    name,
    createdAt: new Date().toISOString(),
    completedAt: null,
    status: 'pending',
    config,
    entries: [],
    summary: null,
    notes,
  };
}

/**
 * Run a benchmark against a corpus slice.
 *
 * @param run        Benchmark run (must be in 'pending' state)
 * @param corpus     Corpus entries to evaluate
 * @param nestRunFn  Async function that runs NEST for a given path+config and
 *                   returns a NestSummary or null (null means skip, throw means error)
 * @param options    Optional: minConfidence threshold (default 75), prior run for deltas
 */
export async function runBenchmark(
  run: BenchmarkRun,
  corpus: CorpusEntry[],
  nestRunFn: (path: string, config: NestConfig) => Promise<NestSummary | null>,
  options: {
    minConfidence?: number;
    priorRun?: BenchmarkRun;
    onProgress?: (completed: number, total: number, current: CorpusEntry) => void;
    shouldStop?: () => boolean;
  } = {}
): Promise<BenchmarkRun> {
  const { minConfidence = 75, priorRun, onProgress, shouldStop } = options;

  // Build a lookup for prior confidences
  const priorConf = new Map<string, number>();
  if (priorRun) {
    for (const e of priorRun.entries) {
      if (e.actualConfidence !== null) priorConf.set(e.sha256, e.actualConfidence);
    }
  }

  run.status = 'running';
  run.entries = [];

  for (let i = 0; i < corpus.length; i++) {
    if (shouldStop?.()) {
      run.status = 'aborted';
      break;
    }

    const corpusEntry = corpus[i];
    onProgress?.(i, corpus.length, corpusEntry);

    let summary: NestSummary | null = null;
    let error: string | null = null;

    try {
      summary = await nestRunFn(corpusEntry.binaryPath, run.config);
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
    }

    const benchmarkEntry = gradeEntry(
      corpusEntry,
      summary,
      minConfidence,
      priorConf.get(corpusEntry.sha256) ?? null,
      error
    );
    run.entries.push(benchmarkEntry);
  }

  if (run.status !== 'aborted') {
    run.status = 'complete';
    run.completedAt = new Date().toISOString();
  }

  run.summary = computeBenchmarkSummary(run.entries);
  return run;
}

/**
 * Persist a completed benchmark run to localStorage.
 */
export function saveBenchmarkRun(run: BenchmarkRun): void {
  const store = loadStore();
  const idx = store.runs.findIndex(r => r.id === run.id);
  if (idx >= 0) {
    store.runs[idx] = run;
  } else {
    store.runs.push(run);
  }
  saveStore(store);
}

/**
 * Retrieve all saved benchmark runs sorted newest-first.
 */
export function loadBenchmarkHistory(): BenchmarkRun[] {
  return loadStore().runs
    .slice()
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

/**
 * Retrieve a single run by ID.
 */
export function getBenchmarkRun(id: string): BenchmarkRun | null {
  return loadStore().runs.find(r => r.id === id) ?? null;
}

/**
 * Delete a saved benchmark run.
 * @returns true if found and deleted.
 */
export function deleteBenchmarkRun(id: string): boolean {
  const store = loadStore();
  const before = store.runs.length;
  store.runs = store.runs.filter(r => r.id !== id);
  if (store.runs.length !== before) {
    saveStore(store);
    return true;
  }
  return false;
}

/**
 * Compare two benchmark runs (runB vs runA).
 * runA is the "baseline" and runB is the "new" run.
 */
export function compareBenchmarkRuns(
  runA: BenchmarkRun,
  runB: BenchmarkRun
): BenchmarkComparison {
  const passA = new Set(runA.entries.filter(e => e.pass).map(e => e.sha256));
  const passB = new Set(runB.entries.filter(e => e.pass).map(e => e.sha256));

  const newPasses   = [...passB].filter(s => !passA.has(s));
  const newFailures = [...passA].filter(s => !passB.has(s));

  const summA = runA.summary;
  const summB = runB.summary;

  const passRateDelta = (summB?.passRate ?? 0) - (summA?.passRate ?? 0);

  const avgConfA = summA?.avgConfidence ?? null;
  const avgConfB = summB?.avgConfidence ?? null;
  const avgConfidenceDelta =
    avgConfA !== null && avgConfB !== null ? avgConfB - avgConfA : null;

  const macroF1A = summA?.macroF1 ?? null;
  const macroF1B = summB?.macroF1 ?? null;
  const macroF1Delta =
    macroF1A !== null && macroF1B !== null ? macroF1B - macroF1A : null;

  return {
    runAId: runA.id,
    runBId: runB.id,
    runAName: runA.name,
    runBName: runB.name,
    passRateDelta,
    avgConfidenceDelta,
    macroF1Delta,
    newPasses,
    newFailures,
    hasRegression: newFailures.length > 0,
    hasImprovement: newPasses.length > 0,
  };
}

/**
 * Clear all saved benchmark runs. Irreversible.
 */
export function clearBenchmarkHistory(): void {
  saveStore(emptyStore());
}

// ── Accuracy Timeline ──────────────────────────────────────────────────────────

/**
 * A single point on the corpus accuracy timeline.
 * One snapshot is produced per completed benchmark run, allowing % correct
 * verdicts to be tracked across successive runs as the corpus and engine evolve.
 */
export interface CorpusAccuracySnapshot {
  /** Benchmark run ID. */
  runId: string;
  /** Human-readable run name. */
  runName: string;
  /** ISO-8601 timestamp when the run completed. */
  completedAt: string;
  /** Fraction of corpus entries where the verdict matched ground truth (0–1). */
  passRate: number;
  /** Macro-averaged F1 across all classifications, or null if not computable. */
  macroF1: number | null;
  /** Total number of entries evaluated in this run. */
  totalEntries: number;
  /** Absolute count of entries that passed. */
  passed: number;
}

/**
 * Return a chronologically-sorted timeline of accuracy snapshots derived from
 * all completed benchmark runs in localStorage.
 *
 * Each snapshot captures the % correct verdicts (passRate) and macro-F1 for
 * one run, enabling regression / improvement detection across runs over time.
 * Pending, running, or aborted runs are excluded.
 */
export function getAccuracyTimeline(): CorpusAccuracySnapshot[] {
  return loadStore()
    .runs
    .filter(r => r.status === 'complete' && r.summary !== null && r.completedAt !== null)
    .map(r => ({
      runId:        r.id,
      runName:      r.name,
      completedAt:  r.completedAt!,
      passRate:     r.summary!.passRate,
      macroF1:      r.summary!.macroF1,
      totalEntries: r.summary!.totalEntries,
      passed:       r.summary!.passed,
    }))
    .sort((a, b) => a.completedAt.localeCompare(b.completedAt));
}
