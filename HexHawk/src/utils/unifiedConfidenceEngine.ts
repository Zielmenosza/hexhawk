/**
 * unifiedConfidenceEngine.ts — WS12 Unified Confidence Aggregation
 *
 * Computes a single, auditable confidence score that combines contributions
 * from TALON (static analysis), STRIKE (dynamic analysis), and NEST
 * (iterative refinement) using a weighted Bayesian-inspired fusion.
 *
 * The score is fully explainable: every component and adjustment is recorded
 * in `explanation[]` — a first-class differentiator vs IDA/Ghidra/BinNinja.
 */

import type { SharedIntelligenceContext } from './sharedIntelligenceContext';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface EngineContribution {
  engine: string;
  rawScore: number;       // 0–100 score from the engine
  weight: number;         // normalised weight (0–1, sum = 1)
  weightedScore: number;  // rawScore * weight
  available: boolean;     // false if engine hasn't run
}

export interface UnifiedConfidence {
  /** Final aggregate score (0–100) */
  overall: number;
  /** Per-engine contribution breakdown */
  contributions: EngineContribution[];
  /** Bonus added when ≥2 engines agree */
  agreementBonus: number;
  /** Penalty for each engine disagreement */
  contradictionPenalty: number;
  /** Number of multi-engine confirmed threats */
  confirmedThreatCount: number;
  /** Step-by-step explanation of how the score was derived */
  explanation: string[];
}

// ─── Configuration ────────────────────────────────────────────────────────────

/** Base weights when all three engines are available */
const BASE_WEIGHTS = {
  talon:  0.35,   // static analysis: moderate weight; can miss runtime tricks
  strike: 0.40,   // dynamic analysis: highest weight; highest runtime fidelity
  nest:   0.25,   // iterative refinement: medium weight; consensus via convergence
};

const AGREEMENT_BONUS_PER_ENGINE_PAIR = 4;   // per agreed pair (max 3 pairs = +12)
const CONTRADICTION_PENALTY_PER_ITEM  = 5;   // per disagreement

// ─── Main function ────────────────────────────────────────────────────────────

export function computeUnifiedConfidence(
  ctx: SharedIntelligenceContext
): UnifiedConfidence {
  const explanation: string[] = [];
  const contributions: EngineContribution[] = [];

  // ── Gather raw scores ────────────────────────────────────────────────────

  // TALON: average over all function summaries
  const talonAvailable = ctx.talonFindings.length > 0;
  const talonRaw = talonAvailable
    ? ctx.talonFindings.reduce((s, f) => s + f.overallConfidence, 0) / ctx.talonFindings.length
    : 0;

  // STRIKE: latest verdict confidence
  const strikeAvailable = ctx.strikeVerdict !== null;
  const strikeRaw = strikeAvailable ? (ctx.strikeVerdict!.confidence ?? 0) : 0;

  // NEST: latest snapshot confidence
  const nestAvailable = ctx.nestLatestSnapshot !== null;
  const nestRaw = nestAvailable ? ctx.nestLatestSnapshot!.confidence : 0;

  // ── Compute normalised weights ───────────────────────────────────────────

  const totalWeight =
    (talonAvailable  ? BASE_WEIGHTS.talon  : 0) +
    (strikeAvailable ? BASE_WEIGHTS.strike : 0) +
    (nestAvailable   ? BASE_WEIGHTS.nest   : 0);

  const normalise = (w: number, available: boolean) =>
    available && totalWeight > 0 ? w / totalWeight : 0;

  const tw = normalise(BASE_WEIGHTS.talon,  talonAvailable);
  const sw = normalise(BASE_WEIGHTS.strike, strikeAvailable);
  const nw = normalise(BASE_WEIGHTS.nest,   nestAvailable);

  // ── Build contribution objects ───────────────────────────────────────────

  contributions.push({
    engine: 'TALON',
    rawScore: talonAvailable ? Math.round(talonRaw) : 0,
    weight: tw,
    weightedScore: talonRaw * tw,
    available: talonAvailable,
  });

  contributions.push({
    engine: 'STRIKE',
    rawScore: strikeAvailable ? Math.round(strikeRaw) : 0,
    weight: sw,
    weightedScore: strikeRaw * sw,
    available: strikeAvailable,
  });

  contributions.push({
    engine: 'NEST',
    rawScore: nestAvailable ? Math.round(nestRaw) : 0,
    weight: nw,
    weightedScore: nestRaw * nw,
    available: nestAvailable,
  });

  const base = contributions.reduce((s, c) => s + c.weightedScore, 0);

  if (talonAvailable) {
    explanation.push(`TALON (static): ${Math.round(talonRaw)} × ${(tw * 100).toFixed(0)}% = ${(talonRaw * tw).toFixed(1)} pts from ${ctx.talonFindings.length} function(s)`);
  } else {
    explanation.push('TALON: not run — excluded from aggregate');
  }

  if (strikeAvailable) {
    explanation.push(`STRIKE (dynamic): ${Math.round(strikeRaw)} × ${(sw * 100).toFixed(0)}% = ${(strikeRaw * sw).toFixed(1)} pts`);
  } else {
    explanation.push('STRIKE: not run — excluded from aggregate');
  }

  if (nestAvailable) {
    explanation.push(`NEST (iterative): ${Math.round(nestRaw)} × ${(nw * 100).toFixed(0)}% = ${(nestRaw * nw).toFixed(1)} pts (${ctx.nestSnapshots.length} iterations)`);
  } else {
    explanation.push('NEST: not run — excluded from aggregate');
  }

  // ── Agreement bonus ──────────────────────────────────────────────────────

  const { talonNestAgree, talonStrikeAgree, strikeNestAgree, allAgree, disagreements } =
    ctx.engineAgreement;

  let agreementBonus = 0;
  if (talonNestAgree && talonAvailable && nestAvailable) {
    agreementBonus += AGREEMENT_BONUS_PER_ENGINE_PAIR;
    explanation.push(`+${AGREEMENT_BONUS_PER_ENGINE_PAIR} pts: TALON and NEST agree on threat classification`);
  }
  if (talonStrikeAgree && talonAvailable && strikeAvailable) {
    agreementBonus += AGREEMENT_BONUS_PER_ENGINE_PAIR;
    explanation.push(`+${AGREEMENT_BONUS_PER_ENGINE_PAIR} pts: TALON and STRIKE agree on threat classification`);
  }
  if (strikeNestAgree && strikeAvailable && nestAvailable) {
    agreementBonus += AGREEMENT_BONUS_PER_ENGINE_PAIR;
    explanation.push(`+${AGREEMENT_BONUS_PER_ENGINE_PAIR} pts: STRIKE and NEST agree on threat classification`);
  }
  if (allAgree) {
    explanation.push('  → All three engines agree — maximum corroboration achieved');
  }

  // ── Contradiction penalty ────────────────────────────────────────────────

  const contradictionPenalty = disagreements.length * CONTRADICTION_PENALTY_PER_ITEM;
  if (contradictionPenalty > 0) {
    explanation.push(`−${contradictionPenalty} pts: ${disagreements.length} engine disagreement(s): ${disagreements.join('; ')}`);
  }

  // ── Multi-engine confirmed threats ───────────────────────────────────────

  const confirmedThreatCount = ctx.confirmedThreats.length;
  if (confirmedThreatCount > 0) {
    explanation.push(`${confirmedThreatCount} threat(s) confirmed by ≥2 engines: ${ctx.confirmedThreats.map(t => t.label).join(', ')}`);
  }

  // ── Final score ──────────────────────────────────────────────────────────

  const overall = Math.max(0, Math.min(100, Math.round(base + agreementBonus - contradictionPenalty)));

  explanation.push(`Base: ${base.toFixed(1)} + bonus: ${agreementBonus} − penalty: ${contradictionPenalty} = Overall: ${overall}`);

  return {
    overall,
    contributions,
    agreementBonus,
    contradictionPenalty,
    confirmedThreatCount,
    explanation,
  };
}

// ─── Formatting helper ────────────────────────────────────────────────────────

/** Returns a one-line human-readable confidence summary */
export function formatUnifiedConfidence(uc: UnifiedConfidence): string {
  const available = uc.contributions.filter(c => c.available).map(c => c.engine);
  const enginesStr = available.length > 0 ? available.join('+') : 'no engines';
  return `${uc.overall}/100 [${enginesStr}]${uc.confirmedThreatCount > 0 ? ` · ${uc.confirmedThreatCount} confirmed threat(s)` : ''}`;
}
