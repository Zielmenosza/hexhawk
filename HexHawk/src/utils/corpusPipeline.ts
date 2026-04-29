/**
 * corpusPipeline — Corpus Ingestion & Benchmarking Pipeline
 *
 * Deterministic, Node.js-compatible pipeline that:
 *   1. Scans /corpus/clean, /corpus/suspicious, /corpus/malicious
 *   2. Hashes each binary (SHA-256) and builds a DirectoryIngestManifest
 *   3. Ingests the manifest into corpusManager (best-effort — no-op in Node env)
 *   4. Runs NEST multi-iteration on each binary via an injected nestRunFn
 *   5. Records per-binary: final verdict, convergence count, confidence deltas,
 *      and signals fired
 *   6. Computes aggregate accuracy %, false positive rate, avg convergence speed
 *   7. Writes results to /corpus/results.json
 *   8. Throws RegressionError when accuracy < regressionThreshold (default 80 %)
 *
 * All filesystem operations go through PipelineIoFns — inject mocks for tests.
 * The module has zero UI or Tauri dependencies.
 */

import type { NestSummary, NestConfig, TrainingCorpusEntry } from './nestEngine';
import { DEFAULT_NEST_CONFIG, runTrainingLoop } from './nestEngine';
import type {
  CorpusLabel,
  IngestLabel,
  DirectoryIngestManifest,
  DirectoryIngestEntry,
} from './corpusManager';
import { ingestDirectory } from './corpusManager';

// ── I/O abstraction ────────────────────────────────────────────────────────────

/**
 * Pluggable I/O interface — all filesystem operations route through these
 * functions so the pipeline is fully testable without touching real disk.
 *
 * Production implementation (Node.js):
 *   listFiles  → fs.readdirSync / fs.promises.readdir (files only)
 *   hashFile   → crypto.createHash('sha256').update(fs.readFileSync(path)).digest('hex')
 *   writeJson  → fs.promises.writeFile(path, JSON.stringify(data, null, 2))
 */
export interface PipelineIoFns {
  /** Return absolute paths of every file directly inside the given directory. */
  listFiles: (dir: string) => Promise<string[]>;
  /** Compute the SHA-256 hex digest of the file at the given path. */
  hashFile: (path: string) => Promise<string>;
  /** Serialise `data` as indented JSON and write to `path`. */
  writeJson: (path: string, data: unknown) => Promise<void>;
}

// ── Label constants ────────────────────────────────────────────────────────────

/**
 * Maps corpus subdirectory name → IngestLabel.
 * Determines the ground-truth assigned to every binary inside that folder.
 */
export const CORPUS_DIR_MAP: Readonly<Record<string, IngestLabel>> = {
  clean:      'CLEAN',
  suspicious: 'SUSPICIOUS',
  malicious:  'MALICIOUS',
  challenge:  'CHALLENGE',
};

// ── Core types ─────────────────────────────────────────────────────────────────

/** Metadata for one binary after directory scan but before NEST analysis. */
export interface ScannedBinary {
  /** Absolute path to the binary on disk. */
  path:        string;
  /** SHA-256 hex digest. */
  sha256:      string;
  /** File name extracted from path. */
  filename:    string;
  /** Directory-derived IngestLabel. */
  label:       IngestLabel;
  /** CorpusLabel equivalent (used as ground truth during grading). */
  groundTruth: CorpusLabel;
}

/**
 * Per-binary record produced after a complete NEST multi-iteration run.
 * Serialised into results.json.
 */
export interface BinaryRunRecord {
  sha256:                string;
  path:                  string;
  filename:              string;
  label:                 IngestLabel;
  groundTruth:           CorpusLabel;
  /** NEST final classification string (e.g. 'clean', 'dropper'). */
  finalVerdict:          string;
  finalConfidence:       number;
  /** Number of NEST iterations that completed before convergence. */
  convergenceIterations: number;
  /** Reason convergence was declared, or null when the run was skipped. */
  convergenceReason:     string | null;
  /**
   * Per-iteration confidence deltas.
   * For a 3-iteration run with progression [60, 75, 85] this is [15, 10].
   */
  confidenceDeltas:      number[];
  /**
   * Key findings emitted by nestEngine (proxy for signals fired).
   * Maps to NestSummary.keyFindings.
   */
  signalsFired:          string[];
  durationMs:            number;
  /**
   * True when finalVerdict polarity matched the corpus ground truth.
   * Always true when groundTruth is 'unknown' (no expectation).
   */
  pass:                  boolean;
  /** Non-null when the NEST run was skipped or threw. */
  errorMessage:          string | null;
}

/** Aggregate metrics for a complete corpus benchmark run. */
export interface CorpusBenchmarkMetrics {
  /** ISO-8601 timestamp of generation. */
  generatedAt:              string;
  totalBinaries:            number;
  passCount:                number;
  failCount:                number;
  /** Binaries whose nestRunFn returned null or threw. */
  skipCount:                number;
  /**
   * Accuracy over non-skipped records:
   *   passCount / (passCount + failCount) × 100
   * Rounded to two decimal places.
   */
  accuracyPct:              number;
  /**
   * False positive rate: clean binaries classified as malicious
   *   / total clean binaries  (0 when no clean binaries exist).
   * Rounded to two decimal places.
   */
  falsePositiveRate:        number;
  /**
   * False negative rate: malicious binaries classified as clean
   *   / total malicious binaries  (0 when none exist).
   * Rounded to two decimal places.
   */
  falseNegativeRate:        number;
  /** Mean convergenceIterations across all non-skipped records. */
  avgConvergenceIterations: number;
  records:                  BinaryRunRecord[];
}

// ── Pure helpers ───────────────────────────────────────────────────────────────

/** Extract the file name from a path that uses either / or \. */
export function filenameFromPath(p: string): string {
  return p.replace(/\\/g, '/').split('/').pop() ?? p;
}

/**
 * Convert an IngestLabel to the CorpusLabel polarity used for ground-truth
 * grading.  SUSPICIOUS maps to 'unknown' — no polarity expectation.
 */
export function ingestLabelToCorpusLabel(l: IngestLabel): CorpusLabel {
  if (l === 'CLEAN')     return 'clean';
  if (l === 'MALICIOUS') return 'malicious';
  if (l === 'CHALLENGE') return 'challenge';
  return 'unknown'; // SUSPICIOUS
}

/**
 * Map a NEST classification string to a ground-truth polarity.
 *   clean / unknown / suspicious → 'clean'
 *   anything else                → 'malicious'
 */
export function verdictPolarity(verdict: string): CorpusLabel {
  if (verdict === 'clean' || verdict === 'unknown' || verdict === 'suspicious') {
    return 'clean';
  }
  return 'malicious';
}

/**
 * Return true when the NEST verdict polarity matches the expected ground truth.
 * 'unknown' ground truth always returns true (no expectation).
 */
export function verdictMatchesGroundTruth(
  verdict:     string,
  groundTruth: CorpusLabel,
): boolean {
  if (groundTruth === 'unknown') return true;
  return verdictPolarity(verdict) === groundTruth;
}

/**
 * Compute per-iteration confidence deltas from a progression array.
 * Returns [] for arrays shorter than 2 elements.
 */
export function computeConfidenceDeltas(progression: number[]): number[] {
  if (progression.length < 2) return [];
  const deltas: number[] = [];
  for (let i = 1; i < progression.length; i++) {
    deltas.push(progression[i] - progression[i - 1]);
  }
  return deltas;
}

// ── Directory scanning ─────────────────────────────────────────────────────────

/**
 * Scan a single corpus subdirectory and return one ScannedBinary per file.
 *
 * @param dir   Absolute path to the subdirectory (e.g. '/corpus/clean').
 * @param label IngestLabel to assign to every file in this directory.
 * @param io    I/O functions (injected for testability).
 */
export async function scanCorpusDir(
  dir:   string,
  label: IngestLabel,
  io:    Pick<PipelineIoFns, 'listFiles' | 'hashFile'>,
): Promise<ScannedBinary[]> {
  const paths = await io.listFiles(dir);
  const results: ScannedBinary[] = [];

  for (const p of paths) {
    const sha256 = await io.hashFile(p);
    results.push({
      path:        p,
      sha256,
      filename:    filenameFromPath(p),
      label,
      groundTruth: ingestLabelToCorpusLabel(label),
    });
  }

  return results;
}

/**
 * Scan the full corpus directory structure (clean / suspicious / malicious)
 * and return a DirectoryIngestManifest ready for ingestDirectory().
 *
 * @param baseDir  Absolute path to the corpus root (e.g. '/corpus').
 * @param io       I/O functions.
 */
export async function buildCorpusManifest(
  baseDir: string,
  io:      Pick<PipelineIoFns, 'listFiles' | 'hashFile'>,
): Promise<DirectoryIngestManifest> {
  const entries: DirectoryIngestEntry[] = [];
  const sep = baseDir.endsWith('/') ? '' : '/';

  for (const [subDir, label] of Object.entries(CORPUS_DIR_MAP) as [string, IngestLabel][]) {
    const dir = `${baseDir}${sep}${subDir}`;
    const scanned = await scanCorpusDir(dir, label, io);
    for (const s of scanned) {
      entries.push({ path: s.path, sha256: s.sha256, label });
    }
  }

  return {
    name: `corpus-scan-${new Date().toISOString()}`,
    entries,
  };
}

// ── Benchmark runner ───────────────────────────────────────────────────────────

/**
 * Run NEST in multi-iteration mode over every binary in a scanned list.
 *
 * Wraps nestEngine.runTrainingLoop(), converting each TrainingRecord into a
 * BinaryRunRecord that additionally carries confidence deltas and signals fired.
 * Binaries whose nestRunFn returns null are recorded as skipped entries.
 *
 * @param scanned    List produced by scanCorpusDir / buildCorpusManifest.
 * @param nestRunFn  Async function that drives a full NEST session.
 * @param config     Optional NestConfig overrides.
 */
export async function runCorpusBenchmark(
  scanned:   ScannedBinary[],
  nestRunFn: (path: string, config: NestConfig) => Promise<NestSummary | null>,
  config:    Partial<NestConfig> = {},
): Promise<BinaryRunRecord[]> {
  const corpus: TrainingCorpusEntry[] = scanned.map(s => ({
    sha256:      s.sha256,
    binaryPath:  s.path,
    groundTruth: (s.groundTruth === 'challenge' ? 'unknown' : s.groundTruth) as 'clean' | 'malicious' | 'unknown',
  }));

  const mergedConfig: NestConfig = { ...DEFAULT_NEST_CONFIG, ...config };
  const trainingRecords = await runTrainingLoop(corpus, nestRunFn, {
    config: mergedConfig,
  });

  // Index scanned metadata by sha256 for O(1) lookup
  const scannedMap = new Map<string, ScannedBinary>(
    scanned.map(s => [s.sha256, s]),
  );

  const records: BinaryRunRecord[] = [];

  // Processed binaries — those for which runTrainingLoop produced a record
  for (const tr of trainingRecords) {
    const meta = scannedMap.get(tr.sha256);
    if (!meta) continue; // sha256 not in scanned list (shouldn't happen)

    const deltas = computeConfidenceDeltas(tr.summary.confidenceProgression);

    records.push({
      sha256:                tr.sha256,
      path:                  tr.binaryPath,
      filename:              filenameFromPath(tr.binaryPath),
      label:                 meta.label,
      groundTruth:           meta.groundTruth,
      finalVerdict:          tr.summary.finalVerdict,
      finalConfidence:       tr.summary.finalConfidence,
      convergenceIterations: tr.summary.totalIterations,
      convergenceReason:     tr.summary.convergedReason,
      confidenceDeltas:      deltas,
      signalsFired:          tr.summary.keyFindings.slice(),
      durationMs:            tr.summary.totalDurationMs,
      pass:                  tr.groundTruthMatch,
      errorMessage:          null,
    });
  }

  // Skipped binaries — present in scanned but absent from trainingRecords
  const processedHashes = new Set<string>(trainingRecords.map(r => r.sha256));
  for (const s of scanned) {
    if (processedHashes.has(s.sha256)) continue;
    records.push({
      sha256:                s.sha256,
      path:                  s.path,
      filename:              s.filename,
      label:                 s.label,
      groundTruth:           s.groundTruth,
      finalVerdict:          'unknown',
      finalConfidence:       0,
      convergenceIterations: 0,
      convergenceReason:     null,
      confidenceDeltas:      [],
      signalsFired:          [],
      durationMs:            0,
      pass:                  s.groundTruth === 'unknown', // no expectation → pass
      errorMessage:          'NEST run returned no summary (skipped)',
    });
  }

  return records;
}

// ── Metrics computation ────────────────────────────────────────────────────────

/**
 * Compute aggregate benchmark metrics from a list of run records.
 * Deterministic: given identical records always produces identical output.
 *
 * Skipped records (errorMessage !== null) are counted in skipCount but
 * excluded from accuracy, FP rate, and FN rate calculations.
 */
export function computeCorpusMetrics(records: BinaryRunRecord[]): CorpusBenchmarkMetrics {
  const nonSkipped = records.filter(r => r.errorMessage === null);
  const skipped    = records.length - nonSkipped.length;
  const passed     = nonSkipped.filter(r => r.pass).length;
  const failed     = nonSkipped.filter(r => !r.pass).length;
  const total      = nonSkipped.length;

  const accuracyPct =
    total > 0 ? round2(passed / total * 100) : 0;

  // FP: clean binaries classified as malicious
  const cleanRecords     = nonSkipped.filter(r => r.groundTruth === 'clean');
  const fpCount          = cleanRecords.filter(
    r => verdictPolarity(r.finalVerdict) === 'malicious',
  ).length;
  const falsePositiveRate =
    cleanRecords.length > 0 ? round2(fpCount / cleanRecords.length * 100) : 0;

  // FN: malicious binaries classified as clean
  const maliciousRecords = nonSkipped.filter(r => r.groundTruth === 'malicious');
  const fnCount          = maliciousRecords.filter(
    r => verdictPolarity(r.finalVerdict) === 'clean',
  ).length;
  const falseNegativeRate =
    maliciousRecords.length > 0 ? round2(fnCount / maliciousRecords.length * 100) : 0;

  // Average convergence iterations over non-skipped records
  const avgConvergenceIterations =
    nonSkipped.length > 0
      ? round2(
          nonSkipped.reduce((s, r) => s + r.convergenceIterations, 0) / nonSkipped.length,
        )
      : 0;

  return {
    generatedAt:              new Date().toISOString(),
    totalBinaries:            records.length,
    passCount:                passed,
    failCount:                failed,
    skipCount:                skipped,
    accuracyPct,
    falsePositiveRate,
    falseNegativeRate,
    avgConvergenceIterations,
    records,
  };
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

// ── Regression guard ───────────────────────────────────────────────────────────

/**
 * Thrown by checkRegressionGuard when accuracy drops below the threshold.
 * Carries the list of regressed binary descriptions and the observed accuracy.
 */
export class RegressionError extends Error {
  constructor(
    message: string,
    public readonly regressedBinaries: string[],
    public readonly accuracyPct: number,
  ) {
    super(message);
    this.name = 'RegressionError';
  }
}

/**
 * Assert that corpus accuracy meets the required threshold.
 *
 * @param metrics         Computed benchmark metrics.
 * @param threshold       Minimum required accuracy % (default: 80).
 * @param priorMetrics    Optional prior run — when supplied, only binaries
 *                        that were passing before and are now failing are
 *                        reported as regressions (rather than all failures).
 * @throws {RegressionError} when accuracyPct < threshold.
 */
export function checkRegressionGuard(
  metrics:       CorpusBenchmarkMetrics,
  threshold      = 80,
  priorMetrics?: CorpusBenchmarkMetrics,
): void {
  if (metrics.accuracyPct >= threshold) return;

  let regressedBinaries: string[];

  if (priorMetrics) {
    // Narrow to entries that were passing in the prior run but now fail
    const priorPassSet = new Set<string>(
      priorMetrics.records.filter(r => r.pass).map(r => r.sha256),
    );
    regressedBinaries = metrics.records
      .filter(r => !r.pass && r.errorMessage === null && priorPassSet.has(r.sha256))
      .map(r =>
        `${r.filename} (was passing, now: ${r.finalVerdict} @ ${r.finalConfidence}%)`,
      );
  } else {
    // Report all non-skipped failures
    regressedBinaries = metrics.records
      .filter(r => !r.pass && r.errorMessage === null)
      .map(r =>
        `${r.filename} (${r.groundTruth} → got ${r.finalVerdict} @ ${r.finalConfidence}%)`,
      );
  }

  const bulletList = regressedBinaries.map(b => `  • ${b}`).join('\n');
  const msg =
    `NEST accuracy ${metrics.accuracyPct}% is below the ${threshold}% threshold. ` +
    `${metrics.failCount} binaries failed:\n${bulletList}`;

  throw new RegressionError(msg, regressedBinaries, metrics.accuracyPct);
}

// ── End-to-end pipeline ────────────────────────────────────────────────────────

/**
 * Run the full corpus ingestion and benchmarking pipeline end-to-end:
 *
 *   1. Scan /baseDir/clean, /baseDir/suspicious, /baseDir/malicious
 *   2. Ingest into corpusManager (best-effort — swallowed in Node env where
 *      localStorage is unavailable)
 *   3. Run NEST multi-iteration on each binary via nestRunFn
 *   4. Compute aggregate metrics
 *   5. Write results to outputPath as JSON
 *   6. Check regression guard (throws RegressionError if accuracy < threshold)
 *
 * @param baseDir             Corpus root (must contain clean/, suspicious/,
 *                            malicious/ subdirectories).
 * @param outputPath          Absolute path to write results.json.
 * @param nestRunFn           Injected NEST session runner.
 * @param io                  I/O functions (injected for testability).
 * @param regressionThreshold Accuracy % threshold (default: 80).
 * @param nestConfig          Optional NestConfig overrides.
 * @returns                   Computed benchmark metrics.
 */
export async function runFullCorpusPipeline(
  baseDir:              string,
  outputPath:           string,
  nestRunFn:            (path: string, config: NestConfig) => Promise<NestSummary | null>,
  io:                   PipelineIoFns,
  regressionThreshold = 80,
  nestConfig:           Partial<NestConfig> = {},
): Promise<CorpusBenchmarkMetrics> {
  // Step 1 — Scan all three subdirectories
  const scanned: ScannedBinary[] = [];
  const sep = baseDir.endsWith('/') ? '' : '/';

  for (const [subDir, label] of Object.entries(CORPUS_DIR_MAP) as [string, IngestLabel][]) {
    const dir = `${baseDir}${sep}${subDir}`;
    const results = await scanCorpusDir(dir, label, io);
    scanned.push(...results);
  }

  // Step 2 — Ingest into corpusManager (browser corpus store)
  // Best-effort: localStorage is unavailable in Node/test environments.
  try {
    const manifest: DirectoryIngestManifest = {
      name:    `pipeline-${new Date().toISOString()}`,
      entries: scanned.map(s => ({ path: s.path, sha256: s.sha256, label: s.label })),
    };
    ingestDirectory(manifest);
  } catch {
    // localStorage not available — skip silently
  }

  // Step 3 — Run NEST on every binary
  const records = await runCorpusBenchmark(scanned, nestRunFn, nestConfig);

  // Step 4 — Compute aggregate metrics
  const metrics = computeCorpusMetrics(records);

  // Step 5 — Write results.json
  await io.writeJson(outputPath, metrics);

  // Step 6 — Regression guard (throws if accuracy < threshold)
  checkRegressionGuard(metrics, regressionThreshold);

  return metrics;
}
