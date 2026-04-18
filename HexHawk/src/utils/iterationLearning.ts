/**
 * iterationLearning — Per-Iteration Meta-Learning Engine
 *
 * After each NEST iteration this module:
 *   1. Scores the improvement achieved (confidence gain, contradiction reduction, signal clarity)
 *   2. Classifies the result as high / medium / low / negative improvement
 *   3. Produces a LearningDecision — what to ADJUST (low improvement) or REINFORCE (high improvement)
 *   4. Stores all decisions in a LearningSession record for the full analysis run
 *
 * The LearningDecision is consumed by:
 *   - strategyEngine (via signalWeightAdjustments + focusAdjustments)
 *   - NestView (to annotate iterations with learning context in the UI)
 *   - learningStore (persisted per binary hash)
 */

import type { NestIterationSnapshot } from './nestEngine';
import type { CorrelatedSignal } from './correlationEngine';

// ── Types ─────────────────────────────────────────────────────────────────────

/** Component scores that make up the composite improvement measure */
export interface ImprovementBreakdown {
  /** Raw confidence delta (current - previous), 0 for first iteration */
  confidenceDelta:         number;
  /** Reduction in contradiction count vs previous iteration (positive = fewer contradictions) */
  contradictionReduction:  number;
  /** Increase in total corroborations across all signals vs previous iteration */
  clarityGain:             number;
  /** Change in uncorroborated-signal count (negative = more uncorroborated, bad) */
  uncorroboratedDelta:     number;
  /**
   * Composite improvement score.
   * Formula:  confidenceDelta * 2
   *         + contradictionReduction * 3
   *         + clarityGain * 1.5
   *         - uncorroboratedDelta (penalty when more signals lack corroboration)
   * Typical range: −20 … +40
   */
  composite:               number;
}

export type ImprovementLevel = 'high' | 'medium' | 'low' | 'negative';

/** Thresholds for composite improvement score → level */
const LEVEL_THRESHOLDS = {
  high:     12,   // composite ≥ 12 → reinforce
  medium:   4,    // composite ≥  4 → continue current strategy
  low:      0,    // composite ≥  0 → soft adjust
  // negative: composite < 0 → hard adjust
} as const;

// ── Signal-level focus recommendations ────────────────────────────────────────

export type FocusAction =
  | 'boost-weight'          // signal contributed significantly — raise its weight
  | 'reduce-weight'         // signal fired but added no corroboration — reduce reliance
  | 'prioritise-corroboration' // signal exists but is isolated — try to corroborate
  | 'investigate-contradiction'; // signal is part of an active contradiction — investigate

export interface SignalLearning {
  signalId:   string;
  action:     FocusAction;
  reason:     string;
  /** Suggested weight multiplier (0.5–2.0). Applied as a hint to strategyEngine. */
  weightMult: number;
}

// ── Strategy adjustments produced by this module ─────────────────────────────

export interface StrategyAdjustment {
  /** The type name from RefinementActionType / StrategyClass that fired */
  strategyType:   string;
  /** Did this strategy produce improvement? */
  wasEffective:   boolean;
  /** Suggested priority shift: +1 raise, 0 neutral, −1 lower */
  priorityDelta:  number;
  reason:         string;
}

// ── Main output ───────────────────────────────────────────────────────────────

export interface LearningDecision {
  /** Index of the iteration this decision covers */
  iteration:          number;
  improvementLevel:   ImprovementLevel;
  breakdown:          ImprovementBreakdown;
  /**
   * Human-readable explanation of what happened and what to do next.
   * Displayed in the iteration card.
   */
  diagnosis:          string;
  /** Per-signal learning recommendations */
  signalLearning:     SignalLearning[];
  /** Strategy effectiveness assessment */
  strategyAdjustments: StrategyAdjustment[];
  /** True when current strategy should be changed before next iteration */
  shouldPivot:        boolean;
  /** True when a successful path was confirmed and should be reinforced */
  shouldReinforce:    boolean;
  /** IDs of signals that proved most valuable this iteration */
  reinforceSignals:   string[];
  /** Strategies to deprioritise next iteration */
  deprioritise:       string[];
  /** Strategies to promote next iteration */
  promote:            string[];
}

// ── Per-session store ─────────────────────────────────────────────────────────

export interface LearningSession {
  /** SHA-256 hash of the analysed binary */
  fileHash:        string;
  /** Timestamp the session started */
  startTime:       number;
  /** Timestamp the session ended (null if in progress) */
  endTime:         number | null;
  /** One decision record per completed iteration */
  decisions:       LearningDecision[];
  /**
   * Cumulative improvement over the session.
   * Sum of all composite scores.
   */
  totalImprovement: number;
  /**
   * Number of iterations classified as 'high' improvement.
   */
  highImprovementCount: number;
  /**
   * Number of iterations classified as 'low' or 'negative'.
   */
  lowImprovementCount:  number;
  /**
   * Strategies that proved effective (appeared in ≥1 high-improvement iteration).
   */
  effectiveStrategies: string[];
  /**
   * Strategies that produced low/negative improvement and should be avoided.
   */
  ineffectiveStrategies: string[];
  /**
   * Signal IDs reinforced across multiple high-improvement iterations.
   */
  reinforcedSignals: string[];
  /**
   * Final assessment written at session end.
   */
  finalAssessment: string | null;
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Core scoring ─────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/** Count total corroborations across all signals */
function totalCorroborations(signals: CorrelatedSignal[]): number {
  return signals.reduce((sum, s) => sum + s.corroboratedBy.length, 0);
}

/** Count signals with zero corroboration */
function uncorroboratedCount(signals: CorrelatedSignal[]): number {
  return signals.filter(s => s.corroboratedBy.length === 0).length;
}

/**
 * Compute the improvement breakdown between two consecutive snapshots.
 * Pass `prev = null` for the first iteration (scores will be 0).
 */
export function scoreIterationImprovement(
  snap: NestIterationSnapshot,
  prev: NestIterationSnapshot | null,
): ImprovementBreakdown {
  if (!prev) {
    // First iteration: no comparison possible
    return {
      confidenceDelta:        0,
      contradictionReduction: 0,
      clarityGain:            0,
      uncorroboratedDelta:    0,
      composite:              0,
    };
  }

  const confidenceDelta = snap.confidence - prev.confidence;

  const prevContradictions = prev.verdict.contradictions?.length ?? 0;
  const currContradictions = snap.verdict.contradictions?.length ?? 0;
  const contradictionReduction = prevContradictions - currContradictions; // positive = fewer

  const prevCorroborations = totalCorroborations(prev.verdict.signals);
  const currCorroborations = totalCorroborations(snap.verdict.signals);
  const clarityGain = currCorroborations - prevCorroborations;

  const prevUncorroborated = uncorroboratedCount(prev.verdict.signals);
  const currUncorroborated = uncorroboratedCount(snap.verdict.signals);
  const uncorroboratedDelta = currUncorroborated - prevUncorroborated; // positive = more (bad)

  const composite =
    confidenceDelta        * 2
    + contradictionReduction * 3
    + clarityGain            * 1.5
    - uncorroboratedDelta;   // penalise adding uncorroborated signals

  return {
    confidenceDelta,
    contradictionReduction,
    clarityGain,
    uncorroboratedDelta,
    composite,
  };
}

export function classifyImprovement(breakdown: ImprovementBreakdown): ImprovementLevel {
  if (breakdown.composite >= LEVEL_THRESHOLDS.high)   return 'high';
  if (breakdown.composite >= LEVEL_THRESHOLDS.medium) return 'medium';
  if (breakdown.composite >= LEVEL_THRESHOLDS.low)    return 'low';
  return 'negative';
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Per-signal analysis ───────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

function analyseSignals(
  snap: NestIterationSnapshot,
  prev: NestIterationSnapshot | null,
  level: ImprovementLevel,
): SignalLearning[] {
  const learning: SignalLearning[] = [];
  const prevIds = new Set(prev?.verdict.signals.map(s => s.id) ?? []);
  const contradictionIds = new Set(
    snap.verdict.contradictions?.flatMap(c => [c.id]) ?? [],
  );

  for (const sig of snap.verdict.signals) {
    const isNew        = !prevIds.has(sig.id);
    const corroborated = sig.corroboratedBy.length > 0;
    const inContra     = contradictionIds.has(sig.id);

    if (inContra) {
      learning.push({
        signalId:   sig.id,
        action:     'investigate-contradiction',
        reason:     'Signal is part of an unresolved contradiction — investigate before relying on it',
        weightMult: 0.7,
      });
    } else if (isNew && corroborated && sig.weight >= 5) {
      // New, corroborated, high-weight: reinforce
      learning.push({
        signalId:   sig.id,
        action:     'boost-weight',
        reason:     `New signal with weight ${sig.weight} and ${sig.corroboratedBy.length} corroborator(s) — strong evidence`,
        weightMult: Math.min(2.0, 1 + sig.corroboratedBy.length * 0.2),
      });
    } else if (!corroborated && sig.weight >= 4 && level === 'low' || level === 'negative') {
      // Isolated high-weight signal during low improvement → try to corroborate
      learning.push({
        signalId:   sig.id,
        action:     'prioritise-corroboration',
        reason:     `Isolated signal (weight ${sig.weight}, no corroborators) — should be corroborated or deprioritised`,
        weightMult: 0.8,
      });
    } else if (isNew && !corroborated && sig.weight < 4) {
      // New weak signal, not corroborated: reduce reliance
      learning.push({
        signalId:   sig.id,
        action:     'reduce-weight',
        reason:     `New weak signal (weight ${sig.weight}) with no corroboration — low information value`,
        weightMult: 0.6,
      });
    }
  }

  // Cap to most important 5 signals
  return learning.slice(0, 5);
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Strategy effectiveness ────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

function assessStrategy(
  snap:    NestIterationSnapshot,
  prev:    NestIterationSnapshot | null,
  level:   ImprovementLevel,
): StrategyAdjustment[] {
  const adjustments: StrategyAdjustment[] = [];
  const prevPlan = prev?.refinementPlan;

  if (!prevPlan?.primaryAction) return adjustments;

  const stratType   = prevPlan.primaryAction.type;
  const wasEffective = level === 'high' || level === 'medium';

  adjustments.push({
    strategyType:  stratType,
    wasEffective,
    priorityDelta: level === 'high' ? 1 : level === 'negative' ? -1 : 0,
    reason: wasEffective
      ? `Strategy '${stratType}' from previous iteration produced ${level} improvement`
      : `Strategy '${stratType}' produced ${level} improvement — consider alternative`,
  });

  // CFG-specific: if back-edges present but we didn't follow them → recommend
  const cfgSummary = snap.input.cfgSummary;
  if (cfgSummary && cfgSummary.backEdges > 0 && stratType !== 'follow-cfg-path') {
    adjustments.push({
      strategyType:  'follow-cfg-path',
      wasEffective:  false,
      priorityDelta: 1,
      reason: `CFG has ${cfgSummary.backEdges} back-edge(s) — follow-cfg-path not yet attempted`,
    });
  }

  return adjustments;
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Diagnosis text ────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

function buildDiagnosis(
  breakdown: ImprovementBreakdown,
  level:     ImprovementLevel,
  snap:      NestIterationSnapshot,
  session:   LearningSession,
): string {
  const parts: string[] = [];

  if (level === 'high') {
    parts.push(`Strong improvement (+${breakdown.composite.toFixed(1)} score).`);
    if (breakdown.confidenceDelta > 0)       parts.push(`Confidence +${breakdown.confidenceDelta}%.`);
    if (breakdown.clarityGain > 0)           parts.push(`${breakdown.clarityGain} new corroboration(s).`);
    if (breakdown.contradictionReduction > 0) parts.push(`Resolved ${breakdown.contradictionReduction} contradiction(s).`);
    parts.push('Reinforcing current strategy.');
  } else if (level === 'medium') {
    parts.push(`Moderate improvement (+${breakdown.composite.toFixed(1)} score).`);
    if (breakdown.confidenceDelta > 0)       parts.push(`Confidence +${breakdown.confidenceDelta}%.`);
    parts.push('Continuing current approach.');
  } else if (level === 'low') {
    parts.push(`Low improvement (score ${breakdown.composite.toFixed(1)}).`);
    if (breakdown.uncorroboratedDelta > 0)   parts.push(`${breakdown.uncorroboratedDelta} new signal(s) lack corroboration.`);
    parts.push('Adjusting signal weights and focus areas.');
  } else {
    parts.push(`Negative improvement (score ${breakdown.composite.toFixed(1)}).`);
    if (breakdown.contradictionReduction < 0) parts.push(`${-breakdown.contradictionReduction} new contradiction(s) introduced.`);
    if (breakdown.confidenceDelta < 0)        parts.push(`Confidence dropped ${breakdown.confidenceDelta}%.`);
    parts.push('Pivoting strategy — current approach counterproductive.');
  }

  if (session.lowImprovementCount >= 2 && level !== 'high') {
    parts.push(`Warning: ${session.lowImprovementCount} consecutive low-improvement iterations — consider changing aggressiveness.`);
  }

  return parts.join(' ');
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Main: build LearningDecision ─────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Evaluate one iteration's outcome and produce a learning decision.
 *
 * @param snap     — completed iteration snapshot
 * @param prev     — previous snapshot (null for first iteration)
 * @param session  — in-progress learning session (updated in-place)
 */
export function buildLearningDecision(
  snap:    NestIterationSnapshot,
  prev:    NestIterationSnapshot | null,
  session: LearningSession,
): LearningDecision {
  const breakdown  = scoreIterationImprovement(snap, prev);
  const level      = classifyImprovement(breakdown);
  const signalLrn  = analyseSignals(snap, prev, level);
  const stratAdj   = assessStrategy(snap, prev, level);
  const diagnosis  = buildDiagnosis(breakdown, level, snap, session);

  const shouldPivot     = level === 'negative' || (level === 'low' && session.lowImprovementCount >= 1);
  const shouldReinforce = level === 'high';

  // Signals to reinforce: new, corroborated, high-weight
  const reinforceSignals = snap.verdict.signals
    .filter(s => s.corroboratedBy.length > 0 && s.weight >= 5)
    .map(s => s.id)
    .slice(0, 4);

  const promote     = stratAdj.filter(a => a.priorityDelta > 0).map(a => a.strategyType);
  const deprioritise = stratAdj.filter(a => a.priorityDelta < 0).map(a => a.strategyType);

  return {
    iteration:           snap.iteration,
    improvementLevel:    level,
    breakdown,
    diagnosis,
    signalLearning:      signalLrn,
    strategyAdjustments: stratAdj,
    shouldPivot,
    shouldReinforce,
    reinforceSignals,
    deprioritise,
    promote,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Session lifecycle ─────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/** Create a new in-progress learning session */
export function createLearningSession(fileHash: string): LearningSession {
  return {
    fileHash,
    startTime:             Date.now(),
    endTime:               null,
    decisions:             [],
    totalImprovement:      0,
    highImprovementCount:  0,
    lowImprovementCount:   0,
    effectiveStrategies:   [],
    ineffectiveStrategies: [],
    reinforcedSignals:     [],
    finalAssessment:       null,
  };
}

/**
 * Update the session with a new decision.
 * Returns the updated session (immutable-style copy).
 */
export function applyDecisionToSession(
  session:  LearningSession,
  decision: LearningDecision,
): LearningSession {
  const s = { ...session };
  s.decisions = [...s.decisions, decision];
  s.totalImprovement += decision.breakdown.composite;

  if (decision.improvementLevel === 'high') {
    s.highImprovementCount++;
    // Track effective strategies
    for (const adj of decision.strategyAdjustments.filter(a => a.wasEffective)) {
      if (!s.effectiveStrategies.includes(adj.strategyType)) {
        s.effectiveStrategies = [...s.effectiveStrategies, adj.strategyType];
      }
    }
    // Track reinforced signals
    for (const id of decision.reinforceSignals) {
      if (!s.reinforcedSignals.includes(id)) {
        s.reinforcedSignals = [...s.reinforcedSignals, id];
      }
    }
    // Reset low-improvement counter on a good iteration
    s.lowImprovementCount = 0;
  } else if (decision.improvementLevel === 'low' || decision.improvementLevel === 'negative') {
    s.lowImprovementCount++;
    // Track ineffective strategies
    for (const adj of decision.strategyAdjustments.filter(a => !a.wasEffective)) {
      if (!s.ineffectiveStrategies.includes(adj.strategyType)) {
        s.ineffectiveStrategies = [...s.ineffectiveStrategies, adj.strategyType];
      }
    }
  }

  return s;
}

/**
 * Finalise the session: compute the summary assessment and set endTime.
 */
export function finalizeLearningSession(session: LearningSession): LearningSession {
  const s = { ...session, endTime: Date.now() };

  const total = s.decisions.length;
  if (total === 0) {
    s.finalAssessment = 'No iterations completed.';
    return s;
  }

  const avgImprovement = s.totalImprovement / total;
  const lastLevel      = s.decisions[total - 1]?.improvementLevel ?? 'low';

  const parts: string[] = [];
  parts.push(`${total} iteration(s) completed.`);
  parts.push(`Average improvement score: ${avgImprovement.toFixed(1)}.`);
  parts.push(`${s.highImprovementCount} high-improvement / ${s.lowImprovementCount} low-improvement iteration(s).`);

  if (s.effectiveStrategies.length > 0) {
    parts.push(`Effective: ${s.effectiveStrategies.join(', ')}.`);
  }
  if (s.ineffectiveStrategies.length > 0) {
    parts.push(`Avoided next time: ${s.ineffectiveStrategies.join(', ')}.`);
  }
  if (s.reinforcedSignals.length > 0) {
    parts.push(`${s.reinforcedSignals.length} signal(s) reinforced for future sessions.`);
  }
  if (lastLevel === 'negative') {
    parts.push('Final iteration showed negative improvement — consider more aggressive coverage next time.');
  }

  s.finalAssessment = parts.join(' ');
  return s;
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Signal weight adjustments (consumed by strategyEngine) ───────────────────
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Aggregate signal weight multipliers from a session's history.
 * Returns a map: signalId → effective weight multiplier (product of all decisions).
 * Clamped to [0.3, 2.0].
 */
export function aggregateWeightAdjustments(
  session: LearningSession,
): Map<string, number> {
  const result = new Map<string, number>();

  for (const decision of session.decisions) {
    for (const sl of decision.signalLearning) {
      const prev = result.get(sl.signalId) ?? 1.0;
      result.set(sl.signalId, Math.max(0.3, Math.min(2.0, prev * sl.weightMult)));
    }
  }

  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// ── WS11: Pattern Promotion, Regression Detection, Stability Scoring ──────────
// ─────────────────────────────────────────────────────────────────────────────

/**
 * A pattern (rule, signature, heuristic) that can be promoted to higher
 * priority when it repeatedly contributes to high-improvement iterations,
 * or demoted when it contributes to negative/low iterations.
 */
export interface PatternPromotionRule {
  patternId:        string;
  /** Weighted benefit score across all LearningDecisions — higher = promote */
  globalBenefitScore: number;
  promotionCount:   number;
  demotionCount:    number;
  /** Whether the pattern is currently active (not suppressed) */
  isActive:         boolean;
  /** Conditions under which this pattern fires (human-readable description) */
  conditions:       string;
}

/**
 * Evaluate which patterns should be promoted or demoted based on the full
 * history of LearningDecisions.
 *
 * A pattern is promoted when it appears in `reinforceSignals` of high-improvement
 * decisions more than it appears in `deprioritise` of negative decisions.
 */
export function evaluatePatternPromotion(
  decisions: LearningDecision[],
  patterns: PatternPromotionRule[],
): PatternPromotionRule[] {
  // Build a benefit map: patternId → net benefit
  const benefit = new Map<string, number>();

  for (const dec of decisions) {
    const levelMult = dec.improvementLevel === 'high' ? 2 :
                      dec.improvementLevel === 'medium' ? 1 :
                      dec.improvementLevel === 'low' ? -0.5 : -2;

    for (const id of dec.reinforceSignals) {
      benefit.set(id, (benefit.get(id) ?? 0) + Math.abs(levelMult) * (levelMult > 0 ? 1 : -1));
    }
    for (const id of dec.deprioritise) {
      benefit.set(id, (benefit.get(id) ?? 0) - 1.5);
    }
    for (const id of dec.promote) {
      benefit.set(id, (benefit.get(id) ?? 0) + 1.5);
    }
  }

  return patterns.map(p => {
    const delta = benefit.get(p.patternId) ?? 0;
    const newScore = p.globalBenefitScore + delta;
    const promoted = delta > 0;
    const demoted  = delta < 0;

    return {
      ...p,
      globalBenefitScore: newScore,
      promotionCount: p.promotionCount + (promoted ? 1 : 0),
      demotionCount:  p.demotionCount  + (demoted  ? 1 : 0),
      // Suppress pattern if it has been demoted more than promoted by 3x
      isActive: p.demotionCount + (demoted ? 1 : 0) < (p.promotionCount + (promoted ? 1 : 0)) * 3 + 1,
    };
  });
}

// ── Regression Detection ──────────────────────────────────────────────────────

export type RegressionSeverity = 'critical' | 'major' | 'minor' | 'none';

export interface RegressionDetectionResult {
  patternId:            string;
  regressionSeverity:   RegressionSeverity;
  /** Number of binaries (or iterations) adversely affected */
  affectedCount:        number;
  /** Whether the system recommends rolling back this pattern */
  rollbackRecommended:  boolean;
  reason:               string;
}

/**
 * Detect whether the current LearningDecision represents a regression
 * relative to the historical average for any patterns involved.
 *
 * A regression is when a pattern that previously drove high-improvement
 * iterations now drives negative/low-improvement ones.
 */
export function detectRegressions(
  currentDecision: LearningDecision,
  history: LearningDecision[],
): RegressionDetectionResult[] {
  const results: RegressionDetectionResult[] = [];

  if (history.length < 2) return results; // need baseline

  // Compute historical level distribution for each promoted pattern
  const patternHistory = new Map<string, ImprovementLevel[]>();
  for (const dec of history) {
    for (const id of dec.reinforceSignals) {
      const arr = patternHistory.get(id) ?? [];
      arr.push(dec.improvementLevel);
      patternHistory.set(id, arr);
    }
  }

  // For each signal in current decision, check if it has degraded
  for (const id of [...currentDecision.deprioritise, ...currentDecision.reinforceSignals]) {
    const hist = patternHistory.get(id);
    if (!hist || hist.length < 2) continue;

    const highCount = hist.filter(l => l === 'high').length;
    const highRate  = highCount / hist.length;

    const isCurrentlyBad =
      currentDecision.deprioritise.includes(id) ||
      currentDecision.improvementLevel === 'negative';

    if (highRate >= 0.6 && isCurrentlyBad) {
      // Pattern was high-performing but now performing poorly
      const severity: RegressionSeverity =
        highRate >= 0.8 ? 'critical' :
        highRate >= 0.6 ? 'major' : 'minor';

      results.push({
        patternId: id,
        regressionSeverity: severity,
        affectedCount: hist.length,
        rollbackRecommended: severity === 'critical',
        reason: `Pattern "${id}" achieved high improvement in ${(highRate * 100).toFixed(0)}% of past iterations but is now contributing to ${currentDecision.improvementLevel} improvement. Possible over-fitting or environmental change.`,
      });
    }
  }

  return results;
}

// ── Stability Scoring ─────────────────────────────────────────────────────────

export interface StabilityScore {
  /** Hash of the binary (or pattern group) being assessed */
  binaryHash:           string;
  /** Number of analysis runs observed */
  runCount:             number;
  /** Percentage of runs where the final classification was consistent (0–100) */
  consistencyPct:       number;
  /** Most frequent final classification */
  lastClassification:   string;
  /** Number of times the classification flipped between runs */
  flipCount:            number;
}

/**
 * Compute a stability score for a binary by comparing its finalAssessment
 * across multiple LearningSession snapshots.
 *
 * `snapshots` here are lightweight records: each has the binary hash and
 * the final improvement level of the last decision.
 */
export function computeStabilityScore(
  snapshots: Array<{ binaryHash: string; finalLevel: ImprovementLevel; runId: string }>,
): StabilityScore[] {
  // Group by binaryHash
  const groups = new Map<string, Array<{ finalLevel: ImprovementLevel; runId: string }>>();
  for (const s of snapshots) {
    const arr = groups.get(s.binaryHash) ?? [];
    arr.push({ finalLevel: s.finalLevel, runId: s.runId });
    groups.set(s.binaryHash, arr);
  }

  const results: StabilityScore[] = [];

  for (const [binaryHash, runs] of groups.entries()) {
    const levels = runs.map(r => r.finalLevel);

    // Find modal classification
    const freq = new Map<string, number>();
    for (const l of levels) freq.set(l, (freq.get(l) ?? 0) + 1);
    let modal = 'unknown';
    let maxFreq = 0;
    for (const [l, c] of freq.entries()) {
      if (c > maxFreq) { maxFreq = c; modal = l; }
    }

    const consistencyPct = (maxFreq / levels.length) * 100;

    // Count flips: consecutive runs with different classification
    let flipCount = 0;
    for (let i = 1; i < levels.length; i++) {
      if (levels[i] !== levels[i - 1]) flipCount++;
    }

    results.push({
      binaryHash,
      runCount: runs.length,
      consistencyPct: Math.round(consistencyPct),
      lastClassification: modal,
      flipCount,
    });
  }

  return results;
}

