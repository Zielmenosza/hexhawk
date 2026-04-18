/**
 * sharedIntelligenceContext.ts — WS12 Cross-Engine Intelligence Bus
 *
 * Provides a shared context object that all three analysis engines (TALON,
 * STRIKE, NEST) can read from and write to, enabling:
 *   - Cross-engine threat corroboration
 *   - Engine agreement/disagreement matrix
 *   - Aggregate confidence scoring
 *   - Unified confirmed-threat list
 *
 * The context is immutable-style: mutations return new context objects.
 */

import type { TalonFunctionSummary } from './talonEngine';
import type { BinaryVerdictResult } from './correlationEngine';
import type { NestIterationSnapshot } from './nestEngine';

// ─── Engine names ──────────────────────────────────────────────────────────────

export type EngineName = 'talon' | 'strike' | 'nest';

// ─── Threat types ─────────────────────────────────────────────────────────────

export interface ConfirmedThreat {
  id: string;
  label: string;
  /** Which engines independently detected this threat */
  confirmedByEngines: EngineName[];
  /** Highest confidence reported by any confirming engine (0–100) */
  maxConfidence: number;
  /** Address of the most specific evidence (if available) */
  evidenceAddress?: number;
  /** Human-readable multi-engine rationale */
  rationale: string;
}

// ─── Engine agreement ─────────────────────────────────────────────────────────

export interface EngineAgreementMatrix {
  /** True when TALON and NEST agree on threat classification */
  talonNestAgree: boolean;
  /** True when TALON and STRIKE agree on threat classification */
  talonStrikeAgree: boolean;
  /** True when STRIKE and NEST agree on threat classification */
  strikeNestAgree: boolean;
  /** True when all three engines agree */
  allAgree: boolean;
  /** Disagreements as human-readable strings */
  disagreements: string[];
}

// ─── Shared context ───────────────────────────────────────────────────────────

export interface SharedIntelligenceContext {
  /** Hash of the binary being analysed */
  binaryHash: string;
  /** TALON-discovered function summaries */
  talonFindings: TalonFunctionSummary[];
  /** Most recent NEST iteration snapshot (null if NEST not run) */
  nestLatestSnapshot: NestIterationSnapshot | null;
  /** All NEST snapshots in this session */
  nestSnapshots: NestIterationSnapshot[];
  /** Latest STRIKE-reported verdict (null if STRIKE not run) */
  strikeVerdict: BinaryVerdictResult | null;
  /** Derived: threats corroborated by 2+ engines */
  confirmedThreats: ConfirmedThreat[];
  /** Derived: engine agreement matrix */
  engineAgreement: EngineAgreementMatrix;
  /** Derived: aggregate confidence (0–100) across all engines */
  crossEngineConfidence: number;
  /** When the context was last updated */
  updatedAt: number;
}

// ─── Factory ──────────────────────────────────────────────────────────────────

export function createSharedContext(binaryHash: string): SharedIntelligenceContext {
  return {
    binaryHash,
    talonFindings: [],
    nestLatestSnapshot: null,
    nestSnapshots: [],
    strikeVerdict: null,
    confirmedThreats: [],
    engineAgreement: {
      talonNestAgree: false,
      talonStrikeAgree: false,
      strikeNestAgree: false,
      allAgree: false,
      disagreements: [],
    },
    crossEngineConfidence: 0,
    updatedAt: Date.now(),
  };
}

// ─── Updaters ─────────────────────────────────────────────────────────────────

export function withTalonFindings(
  ctx: SharedIntelligenceContext,
  findings: TalonFunctionSummary[]
): SharedIntelligenceContext {
  const updated = { ...ctx, talonFindings: findings, updatedAt: Date.now() };
  return rebuildDerivedFields(updated);
}

export function withNestSnapshot(
  ctx: SharedIntelligenceContext,
  snapshot: NestIterationSnapshot
): SharedIntelligenceContext {
  const snapshots = [...ctx.nestSnapshots, snapshot];
  const updated = {
    ...ctx,
    nestSnapshots: snapshots,
    nestLatestSnapshot: snapshot,
    updatedAt: Date.now(),
  };
  return rebuildDerivedFields(updated);
}

export function withStrikeVerdict(
  ctx: SharedIntelligenceContext,
  verdict: BinaryVerdictResult
): SharedIntelligenceContext {
  const updated = { ...ctx, strikeVerdict: verdict, updatedAt: Date.now() };
  return rebuildDerivedFields(updated);
}

// ─── Derived field computation ────────────────────────────────────────────────

function rebuildDerivedFields(ctx: SharedIntelligenceContext): SharedIntelligenceContext {
  const confirmedThreats = computeConfirmedThreats(ctx);
  const engineAgreement  = computeEngineAgreement(ctx);
  const crossEngineConfidence = computeCrossEngineConfidence(ctx, engineAgreement);

  return { ...ctx, confirmedThreats, engineAgreement, crossEngineConfidence };
}

function computeConfirmedThreats(ctx: SharedIntelligenceContext): ConfirmedThreat[] {
  const threats = new Map<string, ConfirmedThreat>();

  // Collect behavioral tags from TALON
  for (const fn of ctx.talonFindings) {
    for (const tag of fn.behavioralTags) {
      const id = `tag:${tag}`;
      const existing = threats.get(id);
      if (existing) {
        if (!existing.confirmedByEngines.includes('talon')) {
          existing.confirmedByEngines.push('talon');
        }
      } else {
        threats.set(id, {
          id,
          label: tag,
          confirmedByEngines: ['talon'],
          maxConfidence: fn.overallConfidence,
          rationale: `TALON detected "${tag}" in function "${fn.name}"`,
        });
      }
    }
  }

  // Collect signals from NEST
  const nestVerdicts = ctx.nestSnapshots.map(s => s.verdict);
  for (const verdict of nestVerdicts) {
    for (const sig of verdict.signals) {
      const id = `sig:${sig.id}`;
      const existing = threats.get(id);
      if (existing) {
        if (!existing.confirmedByEngines.includes('nest')) {
          existing.confirmedByEngines.push('nest');
          existing.maxConfidence = Math.max(existing.maxConfidence, sig.weight * 10);
          existing.rationale += '; corroborated by NEST';
        }
      } else {
        threats.set(id, {
          id,
          label: sig.label,
          confirmedByEngines: ['nest'],
          maxConfidence: sig.weight * 10,
          rationale: `NEST detected "${sig.label}"`,
        });
      }
    }
  }

  // Collect signals from STRIKE
  if (ctx.strikeVerdict) {
    for (const sig of ctx.strikeVerdict.signals) {
      const id = `sig:${sig.id}`;
      const existing = threats.get(id);
      if (existing) {
        if (!existing.confirmedByEngines.includes('strike')) {
          existing.confirmedByEngines.push('strike');
          existing.maxConfidence = Math.max(existing.maxConfidence, sig.weight * 10);
          existing.rationale += '; confirmed at runtime by STRIKE';
        }
      } else {
        threats.set(id, {
          id,
          label: sig.label,
          confirmedByEngines: ['strike'],
          maxConfidence: sig.weight * 10,
          rationale: `STRIKE detected "${sig.label}" at runtime`,
        });
      }
    }
  }

  // Return only threats confirmed by 2+ engines
  return Array.from(threats.values()).filter(t => t.confirmedByEngines.length >= 2);
}

export function computeEngineAgreement(ctx: SharedIntelligenceContext): EngineAgreementMatrix {
  const talonClassification = ctx.talonFindings.length > 0
    ? (ctx.talonFindings.some(f => f.warningCount > 0) ? 'malicious' : 'clean')
    : null;

  const nestClassification = ctx.nestLatestSnapshot?.verdict.classification ?? null;
  const strikeClassification = ctx.strikeVerdict?.classification ?? null;

  const disagreements: string[] = [];

  const agree = (a: string | null, b: string | null) =>
    a !== null && b !== null && (
      (isThreatening(a) && isThreatening(b)) ||
      (!isThreatening(a) && !isThreatening(b))
    );

  const talonNestAgree    = agree(talonClassification, nestClassification);
  const talonStrikeAgree  = agree(talonClassification, strikeClassification);
  const strikeNestAgree   = agree(strikeClassification, nestClassification);
  const allAgree = talonNestAgree && talonStrikeAgree && strikeNestAgree;

  if (talonClassification && nestClassification && !talonNestAgree) {
    disagreements.push(`TALON: ${talonClassification} vs NEST: ${nestClassification}`);
  }
  if (talonClassification && strikeClassification && !talonStrikeAgree) {
    disagreements.push(`TALON: ${talonClassification} vs STRIKE: ${strikeClassification}`);
  }
  if (strikeClassification && nestClassification && !strikeNestAgree) {
    disagreements.push(`STRIKE: ${strikeClassification} vs NEST: ${nestClassification}`);
  }

  return { talonNestAgree, talonStrikeAgree, strikeNestAgree, allAgree, disagreements };
}

function isThreatening(classification: string): boolean {
  return ['malicious', 'suspicious', 'likely-malicious'].includes(classification.toLowerCase());
}

function computeCrossEngineConfidence(
  ctx: SharedIntelligenceContext,
  agreement: EngineAgreementMatrix
): number {
  const scores: number[] = [];

  if (ctx.talonFindings.length > 0) {
    const avg = ctx.talonFindings.reduce((s, f) => s + f.overallConfidence, 0) / ctx.talonFindings.length;
    scores.push(avg);
  }
  if (ctx.nestLatestSnapshot) {
    scores.push(ctx.nestLatestSnapshot.confidence);
  }
  if (ctx.strikeVerdict) {
    scores.push(ctx.strikeVerdict.confidence);
  }

  if (scores.length === 0) return 0;

  const base = scores.reduce((a, b) => a + b, 0) / scores.length;

  // Agreement bonus: up to +8 when all 3 agree
  const agreementBonus = agreement.allAgree ? 8 :
    (agreement.talonNestAgree || agreement.talonStrikeAgree || agreement.strikeNestAgree) ? 4 : 0;

  // Contradiction penalty: -4 per disagreement
  const penalty = agreement.disagreements.length * 4;

  return Math.max(0, Math.min(100, Math.round(base + agreementBonus - penalty)));
}
