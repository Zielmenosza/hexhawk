/**
 * crossBinaryAdvisor — Cross-Binary NEST Improvement Engine
 *
 * Analyses completed NEST sessions across multiple binaries to identify
 * systemic weaknesses and recommend NEST configuration adjustments.
 *
 * Pipeline:
 *   1. Collect all stored dominance assessments (resistance patterns)
 *   2. Read cross-binary strategy stats from learningStore
 *   3. Read per-binary verdict history for convergence metrics
 *   4. Detect systemic weak areas (overconfidence, unstable reasoning, etc.)
 *   5. Produce a ranked list of NestConfig adjustments
 *
 * This engine requires ≥3 sessions across different binaries to be meaningful.
 * With fewer sessions it returns a "not enough data" report.
 *
 * Storage: reads from existing `hexhawk.dominance.*` and `hexhawk.learningStore`
 * keys — no new storage introduced.
 */

import type { NestConfig } from './nestEngine';
import type { StrategyClass } from './strategyEngine';
import type { ResistanceReason } from './dominanceEngine';
import { loadStore } from './learningStore';

// ── Minimum data requirements ─────────────────────────────────────────────────

/** Minimum distinct binaries needed before the advisor produces recommendations */
const MIN_BINARIES_FOR_ADVICE = 3;

// ── Cross-binary metrics ──────────────────────────────────────────────────────

/**
 * Aggregated metrics computed across all analysed binaries.
 */
export interface CrossBinaryMetrics {
  /** Total distinct binaries analysed */
  totalBinaries: number;
  /** Binaries with DOMINATED verdict */
  dominatedCount: number;
  /** Binaries with RESISTANT verdict */
  resistantCount: number;
  /** Dominant rate (0–1) */
  dominanceRate: number;
  /** Average final confidence across all sessions */
  avgFinalConfidence: number;
  /** Average iteration count to finish */
  avgIterations: number;
  /** Fraction of sessions that reached convergence within first 3 iterations */
  fastConvergenceRate: number;
  /** Fraction of sessions where verdict flipped in last 2 iterations */
  instabilityRate: number;
  /** Fraction of sessions with unresolved contradictions */
  contradictionRate: number;
  /**
   * Most common resistance failure reasons, sorted by frequency.
   * Each entry: { reason, count, fraction }
   */
  topFailureReasons: Array<{
    reason:   ResistanceReason;
    count:    number;
    fraction: number;
  }>;
  /**
   * Repeated patterns: signal IDs that appear in the majority of sessions.
   * Sorted by prevalence.
   */
  repeatedPatterns: Array<{
    signalId:   string;
    prevalence: number; // fraction of binaries where this signal appeared
    avgConfidence: number;
  }>;
  /**
   * Per-strategy reliability from the learning store.
   * Only strategies with ≥3 observations are included.
   */
  strategyReliability: Array<{
    strategy:    StrategyClass;
    reliability: number;
    uses:        number;
    avgImprovement: number;
  }>;
}

// ── Detected weakness types ───────────────────────────────────────────────────

export type WeaknessCategory =
  | 'low-iteration-depth'      // sessions plateau too early / hit max-iter limit
  | 'strategy-underperformance' // one or more strategies are consistently ineffective
  | 'signal-instability'       // verdicts flip frequently → signals are unreliable
  | 'overconfidence'           // high confidence achieved but RESISTANT verdict → false confidence
  | 'contradiction-stall'      // recurring unresolved contradictions
  | 'shallow-coverage'         // sessions converge but with low iteration count and low confidence
  | 'signal-weight-imbalance'; // a single signal type dominates decisions

export interface DetectedWeakness {
  category:    WeaknessCategory;
  severity:    'critical' | 'high' | 'medium' | 'low';
  title:       string;
  description: string;
  /** Which metric values drove this detection */
  evidence:    string[];
  /** How frequently this problem appeared (fraction of binaries, 0–1) */
  prevalence:  number;
}

// ── Config adjustment recommendations ────────────────────────────────────────

export type AdjustmentType =
  | 'increase-max-iterations'
  | 'decrease-max-iterations'
  | 'lower-confidence-threshold'
  | 'raise-confidence-threshold'
  | 'set-aggressiveness-aggressive'
  | 'set-aggressiveness-conservative'
  | 'enable-talon'
  | 'enable-echo'
  | 'enable-autoadvance'
  | 'increase-plateau-sensitivity';

export interface NestConfigAdjustment {
  type:        AdjustmentType;
  title:       string;
  rationale:   string;
  /** The config key(s) and values to apply */
  apply:       Partial<NestConfig>;
  /** Weakness category this adjustment addresses */
  addresses:   WeaknessCategory;
  priority:    'critical' | 'high' | 'medium' | 'low';
  /** Expected confidence improvement (percentage points, approximate) */
  expectedGain: number;
}

// ── Full report ───────────────────────────────────────────────────────────────

export interface CrossBinaryReport {
  /** ISO timestamp when the report was generated */
  generatedAt: number;
  /** Number of binaries the report is based on */
  binaryCount: number;
  /** Whether there's enough data for reliable recommendations */
  sufficientData: boolean;
  /** If insufficient data, an explanation */
  insufficientDataReason?: string;
  metrics:     CrossBinaryMetrics;
  weaknesses:  DetectedWeakness[];
  adjustments: NestConfigAdjustment[];
  /**
   * Merged NestConfig that applies all recommended adjustments to the supplied
   * base config. Ready to `setConfig(report.recommendedConfig)`.
   */
  recommendedConfig: NestConfig;
  /** One-line overall assessment */
  overallAssessment: string;
}

// ── Internal persistence helpers ──────────────────────────────────────────────

const DOMINANCE_KEY_PREFIX = 'hexhawk.dominance.';

interface StoredDominanceRecord {
  fileHash:   string;
  fileName:   string;
  assessment: import('./dominanceEngine').DominanceAssessment;
}

function loadAllDominanceRecords(): StoredDominanceRecord[] {
  const records: StoredDominanceRecord[] = [];
  try {
    const indexKey = `${DOMINANCE_KEY_PREFIX}index`;
    const hashes: string[] = (() => {
      try { return JSON.parse(localStorage.getItem(indexKey) ?? '[]'); } catch { return []; }
    })();
    for (const hash of hashes) {
      try {
        const raw = localStorage.getItem(`${DOMINANCE_KEY_PREFIX}${hash}`);
        if (raw) {
          const rec = JSON.parse(raw) as StoredDominanceRecord;
          if (rec?.assessment) records.push(rec);
        }
      } catch {
        // Skip malformed records
      }
    }
  } catch {
    // Ignore
  }
  return records;
}

// ── Metric computation ────────────────────────────────────────────────────────

function computeMetrics(
  records:  StoredDominanceRecord[],
  baseConfig: NestConfig,
): CrossBinaryMetrics {
  const total = records.length;
  if (total === 0) {
    return {
      totalBinaries: 0,
      dominatedCount: 0,
      resistantCount: 0,
      dominanceRate: 0,
      avgFinalConfidence: 0,
      avgIterations: 0,
      fastConvergenceRate: 0,
      instabilityRate: 0,
      contradictionRate: 0,
      topFailureReasons: [],
      repeatedPatterns: [],
      strategyReliability: [],
    };
  }

  const dominated = records.filter(r => r.assessment.status === 'DOMINATED').length;
  const resistant = total - dominated;
  const avgConf   = records.reduce((s, r) => s + r.assessment.finalConfidence, 0) / total;
  const avgIters  = records.reduce((s, r) => s + r.assessment.iterationCount, 0) / total;
  const fastConv  = records.filter(r => r.assessment.iterationCount <= 3).length / total;
  const unstable  = records.filter(r => !r.assessment.verdictStable).length / total;
  const contraRate = records.filter(r => r.assessment.contradictionCount > 0).length / total;

  // Failure reason frequency
  const reasonCounts = new Map<ResistanceReason, number>();
  for (const rec of records) {
    for (const f of rec.assessment.failures ?? []) {
      reasonCounts.set(f.reason, (reasonCounts.get(f.reason) ?? 0) + 1);
    }
  }
  const topFailureReasons = [...reasonCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([reason, count]) => ({
      reason,
      count,
      fraction: count / total,
    }));

  // Repeated patterns from learningStore
  const store = loadStore();
  const globalPatterns = Object.values(store.globalPatterns)
    .filter(gp => gp.observedInCount >= 2 && total >= 3)
    .map(gp => ({
      signalId:      gp.signalId,
      prevalence:    gp.observedInCount / total,
      avgConfidence: gp.avgConfidenceWhenPresent,
    }))
    .sort((a, b) => b.prevalence - a.prevalence)
    .slice(0, 10);

  // Strategy reliability
  const strategyReliability = Object.values(store.strategyStats)
    .filter(s => s && s.uses >= 3 && s.reliability !== null)
    .map(s => ({
      strategy:       s.strategyClass,
      reliability:    s.reliability as number,
      uses:           s.uses,
      avgImprovement: s.avgImprovement,
    }))
    .sort((a, b) => a.reliability - b.reliability);

  return {
    totalBinaries:      total,
    dominatedCount:     dominated,
    resistantCount:     resistant,
    dominanceRate:      dominated / total,
    avgFinalConfidence: Math.round(avgConf),
    avgIterations:      Math.round(avgIters * 10) / 10,
    fastConvergenceRate: fastConv,
    instabilityRate:    unstable,
    contradictionRate:  contraRate,
    topFailureReasons,
    repeatedPatterns:   globalPatterns,
    strategyReliability,
  };
}

// ── Weakness detection ────────────────────────────────────────────────────────

function detectWeaknesses(
  metrics:    CrossBinaryMetrics,
  baseConfig: NestConfig,
): DetectedWeakness[] {
  const weaknesses: DetectedWeakness[] = [];

  // 1. Low iteration depth — sessions regularly hit max-iter
  //    OR average confidence is low yet iterations are high
  if (
    metrics.avgFinalConfidence < 70 &&
    metrics.avgIterations >= baseConfig.maxIterations * 0.9
  ) {
    weaknesses.push({
      category:    'low-iteration-depth',
      severity:    metrics.avgFinalConfidence < 55 ? 'critical' : 'high',
      title:       'Iteration Limit Reached Before Convergence',
      description: `Sessions average ${metrics.avgIterations} iterations but only reach ` +
                   `${metrics.avgFinalConfidence}% confidence — the analysis is being cut off ` +
                   `before it can resolve uncertainty.`,
      evidence:    [
        `Average final confidence: ${metrics.avgFinalConfidence}%`,
        `Average iterations: ${metrics.avgIterations} (limit: ${baseConfig.maxIterations})`,
        `Dominance rate: ${Math.round(metrics.dominanceRate * 100)}%`,
      ],
      prevalence:  metrics.resistantCount / Math.max(1, metrics.totalBinaries),
    });
  }

  // 2. Strategy underperformance
  const underperformingStrategies = metrics.strategyReliability.filter(s => s.reliability < 0.4);
  if (underperformingStrategies.length > 0) {
    weaknesses.push({
      category:    'strategy-underperformance',
      severity:    underperformingStrategies.some(s => s.reliability < 0.2) ? 'high' : 'medium',
      title:       'Underperforming Analysis Strategies',
      description: `${underperformingStrategies.length} strategy class(es) have reliability below 40% — ` +
                   `they are being selected but rarely produce meaningful improvement.`,
      evidence:    underperformingStrategies.map(
        s => `${s.strategy}: ${Math.round(s.reliability * 100)}% reliable over ${s.uses} uses`,
      ),
      prevalence:  underperformingStrategies.length / Math.max(1, metrics.strategyReliability.length),
    });
  }

  // 3. Signal instability
  if (metrics.instabilityRate > 0.3) {
    weaknesses.push({
      category:    'signal-instability',
      severity:    metrics.instabilityRate > 0.6 ? 'critical' : 'high',
      title:       'Unstable Verdict Classification',
      description: `${Math.round(metrics.instabilityRate * 100)}% of sessions had verdict flips ` +
                   `in the final iterations — signals are producing contradictory classifications ` +
                   `as more evidence is gathered.`,
      evidence:    [
        `Instability rate: ${Math.round(metrics.instabilityRate * 100)}%`,
        `Unresolved contradictions in ${Math.round(metrics.contradictionRate * 100)}% of sessions`,
      ],
      prevalence:  metrics.instabilityRate,
    });
  }

  // 4. Overconfidence — high confidence but RESISTANT (false confidence)
  const highConfResistant = metrics.topFailureReasons.find(r =>
    r.reason === 'low-confidence',
  );
  if (
    metrics.avgFinalConfidence > 80 &&
    metrics.dominanceRate < 0.5 &&
    !highConfResistant
  ) {
    weaknesses.push({
      category:    'overconfidence',
      severity:    'high',
      title:       'Overconfidence Without Supporting Evidence',
      description: `Average confidence is ${metrics.avgFinalConfidence}% but only ` +
                   `${Math.round(metrics.dominanceRate * 100)}% of binaries were DOMINATED. ` +
                   `High confidence is being reached without clear reasoning chains or corroboration.`,
      evidence:    [
        `Avg confidence: ${metrics.avgFinalConfidence}%`,
        `Dominance rate: ${Math.round(metrics.dominanceRate * 100)}%`,
        `Sessions with weak reasoning: ${
          Math.round(
            (metrics.topFailureReasons.find(r => r.reason === 'weak-reasoning-chain')?.fraction ?? 0) * 100,
          )
        }%`,
      ],
      prevalence:  1 - metrics.dominanceRate,
    });
  }

  // 5. Contradiction stall
  if (metrics.contradictionRate > 0.4) {
    weaknesses.push({
      category:    'contradiction-stall',
      severity:    metrics.contradictionRate > 0.7 ? 'critical' : 'high',
      title:       'Recurring Unresolved Contradictions',
      description: `${Math.round(metrics.contradictionRate * 100)}% of sessions end with ` +
                   `unresolved contradictions — analysis consistently fails to break signal ties.`,
      evidence:    [
        `Contradiction rate: ${Math.round(metrics.contradictionRate * 100)}%`,
        ...metrics.topFailureReasons
          .filter(r => r.reason === 'unresolved-contradictions')
          .map(r => `Contradiction failures: ${r.count}/${metrics.totalBinaries} sessions`),
      ],
      prevalence:  metrics.contradictionRate,
    });
  }

  // 6. Shallow coverage — converges fast but with low confidence
  if (
    metrics.fastConvergenceRate > 0.6 &&
    metrics.avgFinalConfidence < 72
  ) {
    weaknesses.push({
      category:    'shallow-coverage',
      severity:    'medium',
      title:       'Fast But Shallow Convergence',
      description: `${Math.round(metrics.fastConvergenceRate * 100)}% of sessions converge within ` +
                   `3 iterations but only reach ${metrics.avgFinalConfidence}% confidence. ` +
                   `Analysis is stopping before gathering sufficient evidence.`,
      evidence:    [
        `Fast convergence rate: ${Math.round(metrics.fastConvergenceRate * 100)}%`,
        `Average final confidence: ${metrics.avgFinalConfidence}%`,
      ],
      prevalence:  metrics.fastConvergenceRate,
    });
  }

  // Sort by severity then prevalence
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  weaknesses.sort(
    (a, b) => sevOrder[a.severity] - sevOrder[b.severity] || b.prevalence - a.prevalence,
  );

  return weaknesses;
}

// ── Config adjustment generation ──────────────────────────────────────────────

function generateAdjustments(
  weaknesses:  DetectedWeakness[],
  metrics:     CrossBinaryMetrics,
  baseConfig:  NestConfig,
): NestConfigAdjustment[] {
  const adj: NestConfigAdjustment[] = [];

  for (const w of weaknesses) {
    switch (w.category) {
      case 'low-iteration-depth': {
        const newMax = Math.min(10, baseConfig.maxIterations + 3);
        adj.push({
          type:        'increase-max-iterations',
          title:       `Increase Max Iterations to ${newMax}`,
          rationale:   `Sessions are hitting the ${baseConfig.maxIterations}-iteration limit ` +
                       `without converging. Adding 3 more iterations gives analysis more room ` +
                       `to gather evidence and resolve uncertainty.`,
          apply:       { maxIterations: newMax },
          addresses:   'low-iteration-depth',
          priority:    w.severity === 'critical' ? 'critical' : 'high',
          expectedGain: 8,
        });
        if (baseConfig.aggressiveness !== 'aggressive') {
          adj.push({
            type:        'set-aggressiveness-aggressive',
            title:       'Switch to Aggressive Analysis Mode',
            rationale:   `With ${metrics.avgFinalConfidence}% average confidence, conservative ` +
                         `coverage expansion is leaving evidence on the table. Aggressive mode ` +
                         `enables wider disassembly sweeps and TALON deep passes.`,
            apply:       { aggressiveness: 'aggressive' },
            addresses:   'low-iteration-depth',
            priority:    'high',
            expectedGain: 6,
          });
        }
        break;
      }

      case 'strategy-underperformance': {
        // Enable TALON if weak strategies are coverage-related
        const coverageWeak = metrics.strategyReliability.find(
          s => s.reliability < 0.4 && (
            s.strategy === 'expand-coverage' || s.strategy === 'talon-deep'
          ),
        );
        if (coverageWeak && !baseConfig.enableTalon) {
          adj.push({
            type:        'enable-talon',
            title:       'Enable TALON Decompilation Pass',
            rationale:   `Coverage expansion strategies are underperforming. TALON's decompiler ` +
                         `can see through obfuscation that raw disassembly cannot, providing ` +
                         `richer signal sets for the correlation engine.`,
            apply:       { enableTalon: true },
            addresses:   'strategy-underperformance',
            priority:    'high',
            expectedGain: 5,
          });
        }
        // Enable ECHO retuning if echo-retune is unreliable
        const echoWeak = metrics.strategyReliability.find(
          s => s.reliability < 0.4 && s.strategy === 'echo-retune',
        );
        if (echoWeak && !baseConfig.enableEcho) {
          adj.push({
            type:        'enable-echo',
            title:       'Enable ECHO Fuzzy Scanning',
            rationale:   `ECHO retuning is underperforming. Enabling the ECHO engine ` +
                         `broadens fuzzy pattern matching which can surface signals that ` +
                         `exact signature matching misses.`,
            apply:       { enableEcho: true },
            addresses:   'strategy-underperformance',
            priority:    'medium',
            expectedGain: 4,
          });
        }
        break;
      }

      case 'signal-instability': {
        // Tighten plateau detection so unstable verdicts trigger more investigation
        const newPlateau = Math.max(1, baseConfig.plateauThreshold - 1);
        if (newPlateau < baseConfig.plateauThreshold) {
          adj.push({
            type:        'increase-plateau-sensitivity',
            title:       `Increase Plateau Sensitivity (threshold → ${newPlateau}%)`,
            rationale:   `Verdict instability suggests NEST is stopping too early on false ` +
                         `plateaus. Reducing the plateau delta from ${baseConfig.plateauThreshold}% ` +
                         `to ${newPlateau}% forces more iterations when confidence is oscillating.`,
            apply:       { plateauThreshold: newPlateau },
            addresses:   'signal-instability',
            priority:    w.severity === 'critical' ? 'critical' : 'high',
            expectedGain: 5,
          });
        }
        break;
      }

      case 'overconfidence': {
        // Raise the confidence threshold so DOMINATED requires truly high evidence
        const newThresh = Math.min(95, baseConfig.confidenceThreshold + 5);
        if (newThresh > baseConfig.confidenceThreshold) {
          adj.push({
            type:        'raise-confidence-threshold',
            title:       `Raise Convergence Threshold to ${newThresh}%`,
            rationale:   `Binaries are reaching the ${baseConfig.confidenceThreshold}% ` +
                         `threshold without full corroboration. Raising to ${newThresh}% ` +
                         `forces NEST to gather more evidence before declaring convergence.`,
            apply:       { confidenceThreshold: newThresh },
            addresses:   'overconfidence',
            priority:    'high',
            expectedGain: 7,
          });
        }
        break;
      }

      case 'contradiction-stall': {
        // More iterations = more chances to resolve
        const newMax = Math.min(10, baseConfig.maxIterations + 2);
        if (newMax > baseConfig.maxIterations) {
          adj.push({
            type:        'increase-max-iterations',
            title:       `Increase Max Iterations to ${newMax} (contradiction depth)`,
            rationale:   `Recurring unresolved contradictions require more iterations to resolve. ` +
                         `Allowing ${newMax} iterations gives NEST more rounds to gather ` +
                         `corroborating or disconfirming evidence.`,
            apply:       { maxIterations: newMax },
            addresses:   'contradiction-stall',
            priority:    w.severity === 'critical' ? 'critical' : 'high',
            expectedGain: 6,
          });
        }
        break;
      }

      case 'shallow-coverage': {
        // Lower confidence threshold so it doesn't stop prematurely
        const newThresh = Math.max(70, baseConfig.confidenceThreshold - 5);
        if (newThresh < baseConfig.confidenceThreshold) {
          adj.push({
            type:        'lower-confidence-threshold',
            title:       `Lower Convergence Threshold to ${newThresh}%`,
            rationale:   `Sessions are converging prematurely at ${metrics.avgFinalConfidence}% ` +
                         `average confidence. Lowering the threshold from ` +
                         `${baseConfig.confidenceThreshold}% to ${newThresh}% prevents ` +
                         `premature stopping while still allowing convergence at reasonable confidence.`,
            apply:       { confidenceThreshold: newThresh },
            addresses:   'shallow-coverage',
            priority:    'medium',
            expectedGain: 4,
          });
        }
        // Also auto-advance to fill more iterations without manual clicking
        if (!baseConfig.autoAdvance) {
          adj.push({
            type:        'enable-autoadvance',
            title:       'Enable Auto-Advance',
            rationale:   `Sessions are completing very quickly (avg ${metrics.avgIterations} iterations). ` +
                         `Auto-advance removes friction, allowing NEST to run all iterations ` +
                         `without waiting for manual clicks, improving coverage depth.`,
            apply:       { autoAdvance: true },
            addresses:   'shallow-coverage',
            priority:    'low',
            expectedGain: 3,
          });
        }
        break;
      }
    }
  }

  // Deduplicate by type (keep highest priority)
  const seen = new Map<AdjustmentType, NestConfigAdjustment>();
  for (const a of adj) {
    const existing = seen.get(a.type);
    const order    = { critical: 0, high: 1, medium: 2, low: 3 };
    if (!existing || order[a.priority] < order[existing.priority]) {
      seen.set(a.type, a);
    }
  }

  // Sort: priority → expectedGain
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  return [...seen.values()].sort(
    (a, b) => order[a.priority] - order[b.priority] || b.expectedGain - a.expectedGain,
  );
}

// ── Merge adjustments into a config ──────────────────────────────────────────

function mergeAdjustments(
  base:        NestConfig,
  adjustments: NestConfigAdjustment[],
): NestConfig {
  let result = { ...base };
  for (const adj of adjustments) {
    result = { ...result, ...adj.apply };
  }
  return result;
}

// ── Overall assessment text ───────────────────────────────────────────────────

function buildOverallAssessment(
  metrics:    CrossBinaryMetrics,
  weaknesses: DetectedWeakness[],
): string {
  if (metrics.totalBinaries === 0) return 'No sessions recorded yet.';

  const domPct  = Math.round(metrics.dominanceRate * 100);
  const critW   = weaknesses.filter(w => w.severity === 'critical').length;
  const highW   = weaknesses.filter(w => w.severity === 'high').length;

  if (critW > 0) {
    return `NEST is struggling across ${metrics.totalBinaries} binaries (${domPct}% dominated, ` +
           `${metrics.avgFinalConfidence}% avg confidence). ` +
           `${critW} critical weakness${critW > 1 ? 'es' : ''} detected — immediate tuning required.`;
  }
  if (highW > 0) {
    return `NEST is partially effective across ${metrics.totalBinaries} binaries (${domPct}% dominated). ` +
           `${highW} high-severity weakness${highW > 1 ? 'es require' : ' requires'} attention.`;
  }
  if (weaknesses.length === 0 && metrics.dominanceRate >= 0.7) {
    return `NEST is performing well — ${domPct}% dominance rate across ${metrics.totalBinaries} binaries ` +
           `at ${metrics.avgFinalConfidence}% average confidence. No systemic weaknesses detected.`;
  }
  return `NEST has moderate performance across ${metrics.totalBinaries} binaries (${domPct}% dominated). ` +
         `Minor tuning is available — ${weaknesses.length} weakness${weaknesses.length > 1 ? 'es' : ''} identified.`;
}

// ── Main entry point ──────────────────────────────────────────────────────────

/**
 * Build a cross-binary advisor report based on all stored session data.
 *
 * @param baseConfig  The current NestConfig (used to compute relative adjustments)
 */
export function buildCrossBinaryReport(baseConfig: NestConfig): CrossBinaryReport {
  const records = loadAllDominanceRecords();
  const now     = Date.now();

  if (records.length < MIN_BINARIES_FOR_ADVICE) {
    const empty = emptyMetrics();
    return {
      generatedAt:          now,
      binaryCount:          records.length,
      sufficientData:       false,
      insufficientDataReason:
        `Cross-binary analysis requires at least ${MIN_BINARIES_FOR_ADVICE} completed sessions. ` +
        `${records.length}/${MIN_BINARIES_FOR_ADVICE} collected so far — ` +
        `run NEST on ${MIN_BINARIES_FOR_ADVICE - records.length} more binary/binaries to unlock recommendations.`,
      metrics:              empty,
      weaknesses:           [],
      adjustments:          [],
      recommendedConfig:    baseConfig,
      overallAssessment:    `${records.length} session${records.length !== 1 ? 's' : ''} recorded — ` +
                            `${MIN_BINARIES_FOR_ADVICE - records.length} more needed before recommendations are available.`,
    };
  }

  const metrics    = computeMetrics(records, baseConfig);
  const weaknesses = detectWeaknesses(metrics, baseConfig);
  const adjustments = generateAdjustments(weaknesses, metrics, baseConfig);
  const recommended = mergeAdjustments(baseConfig, adjustments);
  const overall     = buildOverallAssessment(metrics, weaknesses);

  return {
    generatedAt:       now,
    binaryCount:       records.length,
    sufficientData:    true,
    metrics,
    weaknesses,
    adjustments,
    recommendedConfig: recommended,
    overallAssessment: overall,
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function emptyMetrics(): CrossBinaryMetrics {
  return {
    totalBinaries:      0,
    dominatedCount:     0,
    resistantCount:     0,
    dominanceRate:      0,
    avgFinalConfidence: 0,
    avgIterations:      0,
    fastConvergenceRate: 0,
    instabilityRate:    0,
    contradictionRate:  0,
    topFailureReasons:  [],
    repeatedPatterns:   [],
    strategyReliability: [],
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Signal weight adjustments (cross-binary) ──────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compute per-signal weight multipliers derived from cross-binary data.
 *
 * Each signal ID gets a multiplier in the range 0.4–1.6:
 *   - High corroboration rate (> 60% of appearances) → boost up to 1.6
 *   - Low corroboration rate (< 20% of appearances) → penalty down to 0.5
 *   - Signal appeared in RESISTANT sessions with high confidence → penalty (overconfidence signal)
 *   - Signal appears in ≥ 70% of all binaries → slight reduction (too generic)
 *
 * Returns a plain Record so it can be stored and passed to strategyEngine via
 * `learnedReliability` (which already supports per-signal discounting via
 * `signalWeightAdjustments` in LearningDecision).
 *
 * @param overconfidenceSignalIds  Signal IDs observed in overconfidence sessions
 *   (high confidence but RESISTANT verdict). Caller collects these from batch metrics.
 */
export function computeSignalWeightAdjustments(
  overconfidenceSignalIds: string[] = [],
): Record<string, number> {
  const store   = loadStore();
  const total   = Object.keys(store.binaryRecords).length;
  const result: Record<string, number> = {};

  if (total === 0) return result;

  const overconfSet = new Set(overconfidenceSignalIds);

  for (const gp of Object.values(store.globalPatterns)) {
    if (!gp.signalId) continue;

    const appearances = gp.observedInCount;
    if (appearances < 2) continue; // not enough data

    const corrRate   = appearances > 0 ? gp.corroborationHits / appearances : 0;
    const prevalence = appearances / total;

    let mult = 1.0;

    // High corroboration → trust boost
    if (corrRate > 0.6) {
      mult += Math.min(0.6, corrRate * 0.8);
    }
    // Low corroboration → trust penalty
    else if (corrRate < 0.2) {
      mult -= Math.min(0.5, (0.2 - corrRate) * 2.5);
    }

    // Too generic (in most binaries) → slight reduction
    if (prevalence > 0.7) {
      mult -= 0.1;
    }

    // Overconfidence signal → stronger penalty
    if (overconfSet.has(gp.signalId)) {
      mult -= 0.25;
    }

    // Clamp to [0.4, 1.6]
    result[gp.signalId] = Math.max(0.4, Math.min(1.6, Math.round(mult * 100) / 100));
  }

  return result;
}
