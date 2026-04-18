/**
 * multiBinaryRunner — Cross-Binary NEST Batch Orchestrator
 *
 * Manages running NEST sessions across 3–5 different binaries to:
 *   - Track convergence speed per binary (iterations + gain rate)
 *   - Track result stability (verdict flip detection, confidence oscillation)
 *   - Identify repeated patterns (signals present in 2+ binaries)
 *   - Detect weak areas: overconfidence, unstable reasoning, strategy stalls
 *   - Adapt NestConfig between binaries based on accumulating evidence
 *
 * Integration:
 *   NestView drives the Tauri calls and NEST iteration loops.
 *   NestView calls this module to manage batch state and derive adjustments.
 *   All Tauri invocations live in NestView; this file is pure TypeScript.
 */

import type { NestConfig, NestIterationSnapshot } from './nestEngine';
import type { StrategyClass } from './strategyEngine';

// ── Batch item ────────────────────────────────────────────────────────────────

export type BatchItemStatus = 'pending' | 'running' | 'completed' | 'error' | 'skipped';

export interface BatchQueueItem {
  /** Stable local ID */
  id:     string;
  /** Absolute path to the binary */
  path:   string;
  /** User-visible filename */
  label:  string;
  status: BatchItemStatus;
  /** Config actually used (may differ from original due to auto-adjust) */
  configUsed?: NestConfig;
  /** Populated after successful completion */
  result?: BatchItemResult;
  errorMessage?: string;
}

// ── Per-binary result ─────────────────────────────────────────────────────────

export interface ConvergenceSpeed {
  /** Total iterations before stop */
  iterations: number;
  /** (finalConfidence − firstConfidence) / iterations */
  gainPerIteration: number;
  stopReason: 'converged' | 'plateau' | 'max-reached' | 'error' | 'unknown';
  /** Converged in ≤ ½ of maxIterations */
  isFast: boolean;
  /** Hit maxIterations without reaching confidence threshold */
  isSlow: boolean;
}

export type WeaknessFlag =
  | 'unstable-reasoning'    // verdict classification changed 2+ times
  | 'overconfident'         // confidence ≥ 80% but dominance = RESISTANT
  | 'strategy-stall'        // total confidence gain across all iterations < 3 pts
  | 'low-coverage'          // < 30 instructions at final iteration
  | 'contradiction-heavy'   // ≥ 2 unresolved contradictions at final verdict
  | 'negative-improvement'; // final confidence < first-iteration confidence

export interface BatchItemResult {
  finalConfidence:  number;
  verdict:          string;
  iterationCount:   number;
  convergenceSpeed: ConvergenceSpeed;
  /** 0–100. 100 = same verdict every iteration, no oscillation */
  stabilityScore:   number;
  weaknessFlags:    WeaknessFlag[];
  /** Signal IDs present in the final verdict */
  signalIds:        string[];
  dominanceStatus:  'DOMINATED' | 'RESISTANT' | 'unknown';
  /** How many times the verdict classification changed across iterations */
  verdictFlipCount: number;
  /** Human-readable list of config changes applied before this binary */
  configAdjustmentsApplied: string[];
  /** Primary strategy class used (from first action of each iteration plan) */
  primaryStrategies: StrategyClass[];
}

// ── Config change record ──────────────────────────────────────────────────────

export interface ConfigChange {
  /** Index of the next batch item this config was applied before */
  appliedBeforeIndex: number;
  changes: Array<{
    field:    keyof NestConfig;
    oldValue: NestConfig[keyof NestConfig];
    newValue: NestConfig[keyof NestConfig];
    reason:   string;
  }>;
  /** Short human-readable summary of all changes */
  summary: string;
}

// ── Batch-level metrics ───────────────────────────────────────────────────────

export interface BatchMetrics {
  completedCount:     number;
  totalCount:         number;
  avgFinalConfidence: number;
  avgIterations:      number;
  avgStabilityScore:  number;
  /** Fraction of completed binaries that converged (not plateau/max-reached) */
  convergenceRate:    number;
  /** Fraction with stabilityScore ≥ 75 */
  stableRate:         number;
  /** Signal IDs present in ≥ 2 completed binaries, sorted by prevalence */
  repeatedPatterns:   Array<{
    signalId:  string;
    count:     number;
    fraction:  number;
  }>;
  overconfidenceCases: Array<{
    path:       string;
    confidence: number;
    verdict:    string;
  }>;
  unstableReasoningCases: Array<{
    path:        string;
    verdictFlips: number;
  }>;
  /** How often each strategy class was the primary action */
  strategyHitCounts: Partial<Record<StrategyClass, number>>;
  /** Weakness flag frequency across all completed binaries */
  weaknessSummary: Array<{
    flag:     WeaknessFlag;
    count:    number;
    fraction: number;
  }>;
  /** Number of adaptive config changes applied during this run */
  configAdjustmentsMade: number;
}

// ── Batch run state ───────────────────────────────────────────────────────────

export interface BatchRunState {
  id:             string;
  items:          BatchQueueItem[];
  currentIndex:   number;
  status:         'idle' | 'running' | 'paused' | 'complete';
  /** Config currently in use (updated between binaries) */
  activeConfig:   NestConfig;
  /** Config at the start of the batch (for diff display) */
  originalConfig: NestConfig;
  /** Ordered record of config changes made during the run */
  configHistory:  ConfigChange[];
  /** Aggregated metrics over all completed items */
  metrics:        BatchMetrics;
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Factory ───────────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

export function createBatchRun(
  paths:      Array<{ path: string; label?: string }>,
  baseConfig: NestConfig,
): BatchRunState {
  const items: BatchQueueItem[] = paths.map((p, i) => ({
    id:     `batch-${i}-${Date.now()}`,
    path:   p.path,
    label:  p.label ?? p.path.split(/[\\/]/).pop() ?? p.path,
    status: 'pending',
  }));

  return {
    id:             `batchrun-${Date.now()}`,
    items,
    currentIndex:   0,
    status:         'idle',
    activeConfig:   { ...baseConfig },
    originalConfig: { ...baseConfig },
    configHistory:  [],
    metrics:        emptyMetrics(items.length),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Per-binary analysis ────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compute a 0–100 stability score from a session's iteration snapshots.
 *
 * Penalty model:
 *   - Each verdict classification flip: −20 pts (capped at −50)
 *   - Confidence standard deviation contribution: −(stdDev × 2), capped at −30
 */
export function computeStabilityScore(snapshots: NestIterationSnapshot[]): number {
  if (snapshots.length <= 1) return 100;

  const verdicts    = snapshots.map(s => s.verdict.classification);
  const flipCount   = verdicts.reduce((c, v, i) =>
    i > 0 && verdicts[i - 1] !== v ? c + 1 : c, 0,
  );

  const confidences = snapshots.map(s => s.confidence);
  const mean        = confidences.reduce((a, b) => a + b, 0) / confidences.length;
  const variance    = confidences.reduce((s, c) => s + (c - mean) ** 2, 0) / confidences.length;
  const stdDev      = Math.sqrt(variance);

  const flipPenalty = Math.min(50, flipCount * 20);
  const oscPenalty  = Math.min(30, stdDev * 2);

  return Math.max(0, Math.round(100 - flipPenalty - oscPenalty));
}

/**
 * Compute convergence speed metrics from snapshots + config + final stop reason.
 */
export function computeConvergenceSpeed(
  snapshots:  NestIterationSnapshot[],
  config:     NestConfig,
  stopReason: string,
): ConvergenceSpeed {
  const iterations     = snapshots.length;
  const firstConf      = snapshots[0]?.confidence ?? 0;
  const lastConf       = snapshots[iterations - 1]?.confidence ?? 0;
  const gainPerIter    = iterations > 1
    ? Math.round(((lastConf - firstConf) / (iterations - 1)) * 10) / 10
    : 0;

  return {
    iterations,
    gainPerIteration: gainPerIter,
    stopReason:       stopReason as ConvergenceSpeed['stopReason'],
    isFast:           iterations <= Math.ceil(config.maxIterations / 2),
    isSlow:           stopReason === 'max-reached',
  };
}

/**
 * Detect per-binary weakness flags from iteration snapshots + dominance result.
 */
export function detectWeaknessFlags(
  snapshots:       NestIterationSnapshot[],
  dominanceStatus: 'DOMINATED' | 'RESISTANT' | 'unknown',
): WeaknessFlag[] {
  if (snapshots.length === 0) return [];

  const flags: WeaknessFlag[] = [];
  const last     = snapshots[snapshots.length - 1];
  const first    = snapshots[0];
  const verdicts = snapshots.map(s => s.verdict.classification);
  const flipCount = verdicts.reduce((c, v, i) =>
    i > 0 && verdicts[i - 1] !== v ? c + 1 : c, 0,
  );

  // Unstable reasoning — classification changed ≥ 2 times
  if (flipCount >= 2) {
    flags.push('unstable-reasoning');
  }

  // Overconfidence — high confidence but binary resisted
  if (last.confidence >= 80 && dominanceStatus === 'RESISTANT') {
    flags.push('overconfident');
  }

  // Strategy stall — total confidence gain < 3 percentage points
  if (snapshots.length >= 2 && (last.confidence - first.confidence) < 3) {
    flags.push('strategy-stall');
  }

  // Low coverage — few instructions even at the final iteration
  if (last.input.instructionCount < 30) {
    flags.push('low-coverage');
  }

  // Contradiction heavy — many contradictions remain at the end
  const finalContras = last.verdict.contradictions?.length ?? 0;
  if (finalContras >= 2) {
    flags.push('contradiction-heavy');
  }

  // Negative improvement — ended with lower confidence than start
  if (snapshots.length >= 2 && last.confidence < first.confidence) {
    flags.push('negative-improvement');
  }

  return flags;
}

/**
 * Count verdict classification flips across a snapshot sequence.
 */
export function countVerdictFlips(snapshots: NestIterationSnapshot[]): number {
  const verdicts = snapshots.map(s => s.verdict.classification);
  return verdicts.reduce((c, v, i) =>
    i > 0 && verdicts[i - 1] !== v ? c + 1 : c, 0,
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Adaptive config between binaries ─────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Given all completed batch items, compute adjustments to apply before
 * starting the next binary. Returns the updated config and a list of
 * human-readable change descriptions.
 *
 * Rules (applied in priority order):
 *   1. Slow convergence (≥ ½ items hit maxIterations) → increase maxIterations
 *   2. Overconfidence (any RESISTANT at ≥ 80% confidence) → raise confidenceThreshold
 *   3. Unstable reasoning (majority have ≥ 2 verdict flips) → tighten plateauThreshold
 *   4. Strategy stall (majority show no confidence gain) → switch to aggressive + autoAdvance
 *   5. Low coverage (majority have < 30 instructions) → double disasmExpansion
 *   6. Fast but shallow (majority fast-converge at < 65% avg) → lower confidenceThreshold
 */
export function computeAdaptiveConfig(
  currentConfig:   NestConfig,
  completedItems:  BatchQueueItem[],
): { config: NestConfig; changes: ConfigChange['changes'] } {
  const results = completedItems
    .filter(i => i.status === 'completed' && i.result)
    .map(i => i.result!);

  if (results.length === 0) {
    return { config: currentConfig, changes: [] };
  }

  const n      = results.length;
  const half   = Math.ceil(n / 2);
  const changes: ConfigChange['changes'] = [];
  let cfg = { ...currentConfig };

  // 1. Slow convergence → increase maxIterations
  const slowCount = results.filter(r => r.convergenceSpeed.isSlow).length;
  if (slowCount >= half && cfg.maxIterations < 10) {
    const newMax = Math.min(10, cfg.maxIterations + 2);
    changes.push({
      field:    'maxIterations',
      oldValue: cfg.maxIterations,
      newValue: newMax,
      reason:   `${slowCount}/${n} binaries hit the iteration limit without converging`,
    });
    cfg = { ...cfg, maxIterations: newMax };
  }

  // 2. Overconfidence → raise confidence threshold
  const overconfidentCount = results.filter(r => r.weaknessFlags.includes('overconfident')).length;
  if (overconfidentCount > 0 && cfg.confidenceThreshold < 92) {
    const newThresh = Math.min(92, cfg.confidenceThreshold + 4);
    changes.push({
      field:    'confidenceThreshold',
      oldValue: cfg.confidenceThreshold,
      newValue: newThresh,
      reason:   `${overconfidentCount} overconfidence case(s) — requiring stronger evidence before declaring convergence`,
    });
    cfg = { ...cfg, confidenceThreshold: newThresh };
  }

  // 3. Unstable reasoning → tighten plateau detection
  const unstableCount = results.filter(r => r.weaknessFlags.includes('unstable-reasoning')).length;
  if (unstableCount >= half && cfg.plateauThreshold > 1) {
    const newPlateau = Math.max(1, cfg.plateauThreshold - 1);
    changes.push({
      field:    'plateauThreshold',
      oldValue: cfg.plateauThreshold,
      newValue: newPlateau,
      reason:   `${unstableCount}/${n} binaries had unstable reasoning — forcing more iterations before plateau detection`,
    });
    cfg = { ...cfg, plateauThreshold: newPlateau };
  }

  // 4. Strategy stall → switch to aggressive + autoAdvance
  const stallCount = results.filter(r => r.weaknessFlags.includes('strategy-stall')).length;
  if (stallCount >= half) {
    if (cfg.aggressiveness !== 'aggressive') {
      changes.push({
        field:    'aggressiveness',
        oldValue: cfg.aggressiveness,
        newValue: 'aggressive',
        reason:   `${stallCount}/${n} binaries showed no confidence improvement — aggressive coverage expansion needed`,
      });
      cfg = { ...cfg, aggressiveness: 'aggressive' };
    }
    if (!cfg.autoAdvance) {
      changes.push({
        field:    'autoAdvance',
        oldValue: false,
        newValue: true,
        reason:   `Enabling auto-advance to ensure all iterations run for stalled binaries`,
      });
      cfg = { ...cfg, autoAdvance: true };
    }
  }

  // 5. Low coverage → double disasm expansion
  const lowCovCount = results.filter(r => r.weaknessFlags.includes('low-coverage')).length;
  if (lowCovCount >= half && cfg.disasmExpansion < 2048) {
    const newExpansion = Math.min(2048, cfg.disasmExpansion * 2);
    changes.push({
      field:    'disasmExpansion',
      oldValue: cfg.disasmExpansion,
      newValue: newExpansion,
      reason:   `${lowCovCount}/${n} binaries had insufficient instruction coverage`,
    });
    cfg = { ...cfg, disasmExpansion: newExpansion };
  }

  // 6. Fast-but-shallow convergence → lower confidence threshold to allow more depth
  const fastCount = results.filter(r => r.convergenceSpeed.isFast).length;
  const avgConf   = results.reduce((s, r) => s + r.finalConfidence, 0) / n;
  if (
    fastCount >= Math.ceil(n * 0.7) &&
    avgConf < 65 &&
    cfg.confidenceThreshold > 72
  ) {
    const newThresh = Math.max(72, cfg.confidenceThreshold - 5);
    changes.push({
      field:    'confidenceThreshold',
      oldValue: cfg.confidenceThreshold,
      newValue: newThresh,
      reason:   `Sessions converge in ≤${Math.ceil(n / 2)} iterations but only reach avg ${Math.round(avgConf)}% — adjusting threshold`,
    });
    cfg = { ...cfg, confidenceThreshold: newThresh };
  }

  return { config: cfg, changes };
}

// ─────────────────────────────────────────────────────────────────────────────
// ── State transition helpers ──────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/** Mark an item as 'running' and lock in the active config */
export function markItemRunning(state: BatchRunState, index: number): BatchRunState {
  const items = [...state.items];
  items[index] = { ...items[index], status: 'running', configUsed: { ...state.activeConfig } };
  return { ...state, items, currentIndex: index, status: 'running' };
}

/** Record a completed result, recompute metrics, and derive next config */
export function completeItem(
  state:  BatchRunState,
  index:  number,
  result: BatchItemResult,
): BatchRunState {
  const items = [...state.items];
  items[index] = { ...items[index], status: 'completed', result };

  const completedSoFar = items.filter(i => i.status === 'completed');
  const metrics        = recomputeMetrics(items);

  // Compute adaptive config for the NEXT binary
  const nextIndex = index + 1;
  const hasMore   = nextIndex < items.length;
  const configHistory = [...state.configHistory];

  if (hasMore) {
    const { config: nextConfig, changes } = computeAdaptiveConfig(
      state.activeConfig,
      completedSoFar,
    );
    if (changes.length > 0) {
      const summary = changes.map(c => {
        if (c.field === 'aggressiveness') return `aggressiveness → ${String(c.newValue)}`;
        if (c.field === 'autoAdvance')    return 'auto-advance enabled';
        return `${c.field}: ${String(c.oldValue)} → ${String(c.newValue)}`;
      }).join(' · ');
      configHistory.push({ appliedBeforeIndex: nextIndex, changes, summary });
      return {
        ...state, items, metrics,
        activeConfig: nextConfig,
        configHistory,
      };
    }
  }

  return { ...state, items, metrics, configHistory };
}

/** Record an error for an item */
export function failItem(
  state:   BatchRunState,
  index:   number,
  message: string,
): BatchRunState {
  const items = [...state.items];
  items[index] = { ...items[index], status: 'error', errorMessage: message };
  return { ...state, items, metrics: recomputeMetrics(items) };
}

/** Mark the batch as complete */
export function finalizeBatch(state: BatchRunState): BatchRunState {
  return { ...state, status: 'complete' };
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Internal metric computation ───────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

const ALL_WEAKNESS_FLAGS: WeaknessFlag[] = [
  'unstable-reasoning',
  'overconfident',
  'strategy-stall',
  'low-coverage',
  'contradiction-heavy',
  'negative-improvement',
];

function emptyMetrics(total: number): BatchMetrics {
  return {
    completedCount:          0,
    totalCount:              total,
    avgFinalConfidence:      0,
    avgIterations:           0,
    avgStabilityScore:       0,
    convergenceRate:         0,
    stableRate:              0,
    repeatedPatterns:        [],
    overconfidenceCases:     [],
    unstableReasoningCases:  [],
    strategyHitCounts:       {},
    weaknessSummary:         [],
    configAdjustmentsMade:   0,
  };
}

function recomputeMetrics(items: BatchQueueItem[]): BatchMetrics {
  const total     = items.length;
  const completed = items.filter(i => i.status === 'completed' && i.result);

  if (completed.length === 0) return emptyMetrics(total);

  const results = completed.map(i => i.result!);
  const n       = results.length;

  const avgConf  = results.reduce((s, r) => s + r.finalConfidence, 0) / n;
  const avgIters = results.reduce((s, r) => s + r.iterationCount, 0) / n;
  const avgStab  = results.reduce((s, r) => s + r.stabilityScore, 0) / n;

  const convergedCount = results.filter(r => r.convergenceSpeed.stopReason === 'converged').length;
  const stableCount    = results.filter(r => r.stabilityScore >= 75).length;

  // Repeated patterns — signal IDs present in ≥ 2 binaries
  const signalCounts = new Map<string, number>();
  for (const r of results) {
    for (const id of new Set(r.signalIds)) {
      signalCounts.set(id, (signalCounts.get(id) ?? 0) + 1);
    }
  }
  const repeatedPatterns = [...signalCounts.entries()]
    .filter(([, count]) => count >= 2)
    .map(([signalId, count]) => ({ signalId, count, fraction: count / n }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 15);

  // Overconfidence cases
  const overconfidenceCases = completed
    .filter(i => i.result!.weaknessFlags.includes('overconfident'))
    .map(i => ({
      path:       i.path,
      confidence: i.result!.finalConfidence,
      verdict:    i.result!.verdict,
    }));

  // Unstable reasoning cases
  const unstableReasoningCases = completed
    .filter(i => i.result!.weaknessFlags.includes('unstable-reasoning'))
    .map(i => ({ path: i.path, verdictFlips: i.result!.verdictFlipCount }));

  // Strategy hit counts
  const strategyHitCounts: Partial<Record<StrategyClass, number>> = {};
  for (const r of results) {
    for (const strat of r.primaryStrategies) {
      strategyHitCounts[strat] = (strategyHitCounts[strat] ?? 0) + 1;
    }
  }

  // Weakness summary
  const weaknessSummary = ALL_WEAKNESS_FLAGS.map(flag => ({
    flag,
    count:    results.filter(r => r.weaknessFlags.includes(flag)).length,
    fraction: results.filter(r => r.weaknessFlags.includes(flag)).length / n,
  })).filter(w => w.count > 0);

  // Config adjustments made — count non-empty configHistory entries from completed items
  const configAdjustmentsMade = items
    .filter(i => i.result?.configAdjustmentsApplied && i.result.configAdjustmentsApplied.length > 0)
    .length;

  return {
    completedCount:          n,
    totalCount:              total,
    avgFinalConfidence:      Math.round(avgConf),
    avgIterations:           Math.round(avgIters * 10) / 10,
    avgStabilityScore:       Math.round(avgStab),
    convergenceRate:         convergedCount / n,
    stableRate:              stableCount / n,
    repeatedPatterns,
    overconfidenceCases,
    unstableReasoningCases,
    strategyHitCounts,
    weaknessSummary,
    configAdjustmentsMade,
  };
}
