/**
 * nestTrainingStore — Persistent NEST Training Records
 *
 * Stores post-run diagnostics and applied fixes in localStorage so HexHawk
 * can track improvement over time and detect regressions.
 *
 * Key: 'hexhawk:nest-training'
 *
 * Each TrainingRecord captures:
 *   - iteration history (confidence per step)
 *   - loss progression (uncertainty per step)
 *   - classification changes (verdict flips)
 *   - fixes applied (healer actions)
 *   - outcome classification from nestDiagnostics
 */

import type { DiagnosticOutcome } from './nestDiagnostics';
import type { NestConfig } from './nestEngine';

// ── Store types ────────────────────────────────────────────────────────────────

const STORE_KEY     = 'hexhawk:nest-training';
const STORE_VERSION = 1;
const MAX_RECORDS   = 200;   // evict oldest when exceeded

export interface IterationHistoryEntry {
  iteration:      number;
  confidence:     number;
  /** Uncertainty proxy: 100 - confidence */
  loss:           number;
  contradictions: number;
  signalCount:    number;
  verdictClass:   string;
}

export interface ClassificationChange {
  fromIteration:  number;
  toIteration:    number;
  fromClass:      string;
  toClass:        string;
}

export interface AppliedFix {
  field:      keyof NestConfig;
  oldValue:   NestConfig[keyof NestConfig];
  newValue:   NestConfig[keyof NestConfig];
  reason:     string;
}

/**
 * A single training record — one completed NEST session.
 */
export interface TrainingRecord {
  /** Unique record ID (reuses NestSession.id) */
  id:                   string;
  /** Absolute path of the analysed binary */
  binaryPath:           string;
  /** Filename extracted from path for display */
  binaryLabel:          string;
  /** Unix timestamp of record creation */
  timestamp:            number;
  /** Outcome from nestDiagnostics */
  outcome:              DiagnosticOutcome;
  /** diagnosticConfidence 0–100 */
  outcomeConfidence:    number;
  /** Short sentence explaining the outcome */
  outcomeReason:        string;
  /** Per-iteration trace */
  iterationHistory:     IterationHistoryEntry[];
  /** Subset of iterationHistory mapped to loss values (duplicate for charting convenience) */
  lossProgression:      number[];
  /** Classification (verdict) changes across iterations */
  classificationChanges:ClassificationChange[];
  /** Config mutations the healer applied AFTER this session */
  fixesApplied:         AppliedFix[];
  /** Config that was active when this session ran */
  configUsed:           NestConfig;
  /** Config that will be active for the NEXT session (after healer) */
  configAfter:          NestConfig | null;
  /** Dimension scores 0–100 */
  dimensionScores: {
    progression:    number;
    contradictions: number;
    convergence:    number;
    depth:          number;
  };
  /** Final stats */
  finalConfidence:  number;
  totalGain:        number;
  verdictFlipCount: number;
  stabilityScore:   number;
}

export interface NestTrainingStore {
  version:  number;
  updated:  number;
  records:  TrainingRecord[];
}

// ── Persistence ────────────────────────────────────────────────────────────────

function empty(): NestTrainingStore {
  return { version: STORE_VERSION, updated: Date.now(), records: [] };
}

export function loadTrainingStore(): NestTrainingStore {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    if (!raw) return empty();
    const parsed = JSON.parse(raw) as Partial<NestTrainingStore>;
    return {
      version: STORE_VERSION,
      updated: parsed.updated ?? Date.now(),
      records: Array.isArray(parsed.records) ? parsed.records : [],
    };
  } catch {
    return empty();
  }
}

function saveTrainingStore(store: NestTrainingStore): void {
  try {
    // Evict oldest records if over limit
    if (store.records.length > MAX_RECORDS) {
      store.records = store.records
        .sort((a, b) => b.timestamp - a.timestamp)
        .slice(0, MAX_RECORDS);
    }
    store.updated = Date.now();
    localStorage.setItem(STORE_KEY, JSON.stringify(store));
  } catch {
    // Non-critical — silent fail
    try {
      // Last resort: trim to half and retry
      const trimmed: NestTrainingStore = {
        ...store,
        records: store.records.slice(0, Math.floor(MAX_RECORDS / 2)),
      };
      localStorage.setItem(STORE_KEY, JSON.stringify(trimmed));
    } catch {
      // Give up silently
    }
  }
}

// ── Record builders ────────────────────────────────────────────────────────────

/**
 * Build classification-change list from a flat iteration history array.
 */
function extractClassificationChanges(
  history: IterationHistoryEntry[],
): ClassificationChange[] {
  const changes: ClassificationChange[] = [];
  for (let i = 1; i < history.length; i++) {
    if (history[i].verdictClass !== history[i - 1].verdictClass) {
      changes.push({
        fromIteration: history[i - 1].iteration,
        toIteration:   history[i].iteration,
        fromClass:     history[i - 1].verdictClass,
        toClass:       history[i].verdictClass,
      });
    }
  }
  return changes;
}

// ── Public API ─────────────────────────────────────────────────────────────────

/**
 * Append a new training record (or update an existing one with the same id).
 * Called after the healer has decided what fixes (if any) to apply.
 */
export function appendTrainingRecord(record: TrainingRecord): void {
  const store = loadTrainingStore();
  const existing = store.records.findIndex(r => r.id === record.id);
  if (existing >= 0) {
    store.records[existing] = record;
  } else {
    store.records.unshift(record); // newest first
  }
  saveTrainingStore(store);
}

/**
 * Build a TrainingRecord from diagnostic report data and healer output.
 * This is the canonical factory function — call it, then appendTrainingRecord().
 */
export function buildTrainingRecord(opts: {
  sessionId:     string;
  binaryPath:    string;
  outcome:       DiagnosticOutcome;
  outcomeConfidence: number;
  outcomeReason: string;
  iterationHistory: IterationHistoryEntry[];
  fixesApplied:  AppliedFix[];
  configUsed:    NestConfig;
  configAfter:   NestConfig | null;
  dimensionScores: { progression: number; contradictions: number; convergence: number; depth: number };
  finalConfidence:  number;
  totalGain:        number;
  verdictFlipCount: number;
  stabilityScore:   number;
}): TrainingRecord {
  const label = opts.binaryPath.split(/[\\/]/).pop() ?? opts.binaryPath;
  const lossProgression = opts.iterationHistory.map(e => e.loss);
  const classificationChanges = extractClassificationChanges(opts.iterationHistory);

  return {
    id:                   opts.sessionId,
    binaryPath:           opts.binaryPath,
    binaryLabel:          label,
    timestamp:            Date.now(),
    outcome:              opts.outcome,
    outcomeConfidence:    opts.outcomeConfidence,
    outcomeReason:        opts.outcomeReason,
    iterationHistory:     opts.iterationHistory,
    lossProgression,
    classificationChanges,
    fixesApplied:         opts.fixesApplied,
    configUsed:           opts.configUsed,
    configAfter:          opts.configAfter,
    dimensionScores:      opts.dimensionScores,
    finalConfidence:      opts.finalConfidence,
    totalGain:            opts.totalGain,
    verdictFlipCount:     opts.verdictFlipCount,
    stabilityScore:       opts.stabilityScore,
  };
}

/**
 * Return the most recent N records (newest first).
 */
export function getRecentRecords(limit = 20): TrainingRecord[] {
  return loadTrainingStore().records.slice(0, limit);
}

/**
 * Return all records for a given binary (by path).
 */
export function getRecordsForBinary(binaryPath: string): TrainingRecord[] {
  return loadTrainingStore().records.filter(r => r.binaryPath === binaryPath);
}

/**
 * Aggregate stats across all stored records.
 */
export interface TrainingStats {
  totalSessions:   number;
  outcomeBreakdown: Record<DiagnosticOutcome, number>;
  avgFinalConfidence: number;
  avgTotalGain:    number;
  avgStability:    number;
  /** Fraction of sessions where fixes were applied */
  healRate:        number;
  /** Fraction of sessions where outcome was SUCCESS */
  successRate:     number;
  /** Most recent 10 outcomes (newest first) */
  recentOutcomes:  DiagnosticOutcome[];
  /**
   * Regression flag: true when the last 3 non-SUCCESS outcomes in a row
   * are the same failure type AND the failure type was previously resolved.
   */
  regressionDetected: boolean;
  regressionDetail:   string;
}

export function computeTrainingStats(): TrainingStats {
  const records = loadTrainingStore().records;

  const breakdown: Record<DiagnosticOutcome, number> = {
    SUCCESS: 0, OVERFITTING: 0, UNDERFITTING: 0, MISCLASSIFICATION: 0,
  };
  let sumConf = 0, sumGain = 0, sumStab = 0, healed = 0;

  for (const r of records) {
    breakdown[r.outcome]++;
    sumConf += r.finalConfidence;
    sumGain += r.totalGain;
    sumStab += r.stabilityScore;
    if (r.fixesApplied.length > 0) healed++;
  }

  const n = records.length || 1;

  // Regression detection: last 3+ records are the same failure type, but
  // a prior SUCCESS existed — so we've regressed.
  let regressionDetected = false;
  let regressionDetail = '';
  if (records.length >= 4) {
    const recent3 = records.slice(0, 3).map(r => r.outcome);
    const allSameFail = recent3.every(o => o !== 'SUCCESS' && o === recent3[0]);
    if (allSameFail) {
      const hadPriorSuccess = records.slice(3).some(r => r.outcome === 'SUCCESS');
      if (hadPriorSuccess) {
        regressionDetected = true;
        regressionDetail = `Last 3 sessions: ${recent3[0]} — regression after previous SUCCESS.`;
      }
    }
  }

  return {
    totalSessions:       records.length,
    outcomeBreakdown:    breakdown,
    avgFinalConfidence:  records.length ? sumConf / records.length : 0,
    avgTotalGain:        records.length ? sumGain / records.length : 0,
    avgStability:        records.length ? sumStab / records.length : 0,
    healRate:            records.length ? healed / records.length : 0,
    successRate:         records.length ? breakdown.SUCCESS / records.length : 0,
    recentOutcomes:      records.slice(0, 10).map(r => r.outcome),
    regressionDetected,
    regressionDetail,
  };
}

/**
 * Clear all training records.
 */
export function clearTrainingStore(): void {
  localStorage.removeItem(STORE_KEY);
}
