/**
 * dominanceEngine — Post-session Conquest Assessment
 *
 * After a NEST session ends, evaluates whether HexHawk fully conquered
 * the binary or whether the binary resisted analysis.
 *
 * Verdict:
 *   DOMINATED — HexHawk has high-confidence, contradiction-free,
 *               stable, well-reasoned understanding of the binary.
 *   RESISTANT — Analysis was inconclusive in one or more dimensions.
 *               Logs specific failure modes so future sessions know
 *               exactly what to target.
 *
 * Four criteria (all must pass for DOMINATED):
 *   1. Confidence      — final confidence ≥ CONFIDENCE_THRESHOLD (90%)
 *   2. Contradictions  — no unresolved HIGH/MEDIUM contradictions remain
 *   3. Stability       — verdict classification identical in last 2 iterations
 *   4. Reasoning chain — every stage of the reasoning chain is populated
 *                        and the primary stage has confidence ≥ 70%
 */

import type { NestIterationSnapshot, NestSession } from './nestEngine';
import type { LearningSession } from './iterationLearning';

// ── Thresholds ────────────────────────────────────────────────────────────────

/** Minimum final confidence to pass the confidence gate */
const CONFIDENCE_THRESHOLD = 90;

/** Maximum number of medium-or-higher contradictions allowed */
const MAX_CONTRADICTIONS = 0;

/** Minimum reasoning-chain stage confidence (stages 1–3) */
const REASONING_CONFIDENCE_MIN = 70;

// ── Public types ──────────────────────────────────────────────────────────────

export type DominanceStatus = 'DOMINATED' | 'RESISTANT';

export type ResistanceReason =
  | 'low-confidence'          // final confidence < threshold
  | 'unresolved-contradictions' // contradictions remain at medium/high severity
  | 'unstable-verdict'        // last 2 iterations disagree on classification
  | 'weak-reasoning-chain'    // reasoning stages empty or low-confidence
  | 'missing-signals'         // too few signals overall / uncorroborated
  | 'unclear-logic'           // low explanation coverage (few explainability entries)
  | 'weak-heuristics';        // successful heuristics fired below expectation

/** A single reason the binary resisted */
export interface ResistanceFailure {
  reason:      ResistanceReason;
  /** Human-readable diagnostic sentence */
  description: string;
  /** How severe the failure is */
  severity:    'critical' | 'high' | 'medium';
}

/** Full post-session dominance assessment */
export interface DominanceAssessment {
  status:      DominanceStatus;
  /** Only populated when status === 'RESISTANT' */
  failures:    ResistanceFailure[];
  /** Final confidence at session end */
  finalConfidence: number;
  /** Contradiction count (medium+high severity) */
  contradictionCount: number;
  /** Whether the last-2-iteration verdict was stable */
  verdictStable: boolean;
  /** Whether the reasoning chain passed quality checks */
  reasoningChainClear: boolean;
  /** One-line summary for display */
  summary: string;
  /** Timestamp when assessment was run */
  timestamp: number;
  /** Total iterations the session ran */
  iterationCount: number;
}

// ── Main entry point ──────────────────────────────────────────────────────────

/**
 * Evaluate whether the session achieved DOMINATED or RESISTANT status.
 *
 * @param session  The finalized NestSession
 * @param learning The completed LearningSession (may be null if not available)
 */
export function assessDominance(
  session:  NestSession,
  learning: LearningSession | null,
): DominanceAssessment {
  const iters = session.iterations;
  if (iters.length === 0) {
    return emptyAssessment('No iterations completed — analysis never ran.');
  }

  const last = iters[iters.length - 1];
  const prev = iters.length >= 2 ? iters[iters.length - 2] : null;
  const failures: ResistanceFailure[] = [];

  // ── Gate 1: Confidence ────────────────────────────────────────────────────
  const finalConfidence = last.confidence;
  if (finalConfidence < CONFIDENCE_THRESHOLD) {
    const gap = CONFIDENCE_THRESHOLD - finalConfidence;
    failures.push({
      reason:      'low-confidence',
      severity:    gap > 20 ? 'critical' : gap > 10 ? 'high' : 'medium',
      description: `Final confidence ${finalConfidence}% is ${gap}% below the ${CONFIDENCE_THRESHOLD}% dominance threshold.` +
                   (learning && learning.lowImprovementCount > learning.highImprovementCount
                     ? ` Most iterations (${learning.lowImprovementCount}) showed low improvement — strategies may need retuning.`
                     : ''),
    });
  }

  // ── Gate 2: Contradictions ────────────────────────────────────────────────
  const significantContras = (last.verdict.contradictions ?? []).filter(
    c => c.severity === 'high' || c.severity === 'medium',
  );
  const contradictionCount = significantContras.length;
  if (contradictionCount > MAX_CONTRADICTIONS) {
    const highCount = significantContras.filter(c => c.severity === 'high').length;
    failures.push({
      reason:   'unresolved-contradictions',
      severity: highCount > 0 ? 'critical' : 'high',
      description:
        `${contradictionCount} unresolved contradiction(s) remain (${highCount} high, ` +
        `${contradictionCount - highCount} medium). ` +
        `Example: "${significantContras[0].observation}" vs "${significantContras[0].conflict}".`,
    });
  }

  // ── Gate 3: Verdict stability ─────────────────────────────────────────────
  const verdictStable = prev
    ? prev.verdict.classification === last.verdict.classification
    : true; // single-iteration session is stable by definition

  if (!verdictStable && prev) {
    failures.push({
      reason:      'unstable-verdict',
      severity:    'high',
      description: `Verdict flipped between iterations ${prev.iteration + 1} ` +
                   `(${prev.verdict.classification}, ${prev.confidence}%) ` +
                   `and ${last.iteration + 1} (${last.verdict.classification}, ${last.confidence}%) ` +
                   `— binary requires more evidence to settle classification.`,
    });
  }

  // ── Gate 4: Reasoning chain quality ──────────────────────────────────────
  const chain = last.verdict.reasoningChain ?? [];
  const chainClear = chain.length >= 3 &&
    chain.every(stage => stage.findings.length > 0) &&
    chain.every(stage => stage.confidence >= REASONING_CONFIDENCE_MIN);
  const reasoningChainClear = chainClear;

  if (!reasoningChainClear) {
    const weakStages = chain.filter(
      s => s.findings.length === 0 || s.confidence < REASONING_CONFIDENCE_MIN,
    );
    const emptyStages = chain.filter(s => s.findings.length === 0);
    const reason: ResistanceReason = emptyStages.length > 0 ? 'unclear-logic' : 'weak-reasoning-chain';
    failures.push({
      reason,
      severity: emptyStages.length > 0 ? 'high' : 'medium',
      description:
        chain.length < 3
          ? `Reasoning chain is incomplete (${chain.length}/3 stages). Insufficient analysis depth.`
          : `${weakStages.length} reasoning stage(s) are weak — ` +
            weakStages.map(s => `Stage ${s.stage} (${s.name}): ${
              s.findings.length === 0 ? 'no findings' : `confidence ${s.confidence}%`
            }`).join('; ') + '.',
    });
  }

  // ── Supplementary check: signal coverage ─────────────────────────────────
  const signals = last.verdict.signals ?? [];
  const corroboratedCount = signals.filter(s => s.corroboratedBy.length > 0).length;
  const uncorroboratedHigh = signals.filter(
    s => s.corroboratedBy.length === 0 && s.weight >= 5,
  );
  if (signals.length < 3 || uncorroboratedHigh.length >= 2) {
    const reason: ResistanceReason =
      signals.length < 3 ? 'missing-signals' : 'weak-heuristics';
    failures.push({
      reason,
      severity: signals.length < 3 ? 'critical' : 'medium',
      description:
        signals.length < 3
          ? `Only ${signals.length} signal(s) detected — binary may be sparse, obfuscated, or outside coverage.`
          : `${uncorroboratedHigh.length} high-weight signal(s) have no corroboration ` +
            `(${corroboratedCount}/${signals.length} signals corroborated). ` +
            `Heuristic coverage is incomplete.`,
    });
  }

  // ── Supplementary check: explainability coverage ──────────────────────────
  const explain = last.verdict.explainability ?? [];
  if (explain.length < 2) {
    failures.push({
      reason:      'unclear-logic',
      severity:    'medium',
      description: `Explainability entries are sparse (${explain.length} factor(s)). ` +
                   `The verdict lacks a clear audit trail.`,
    });
  }

  // ── Derive status ─────────────────────────────────────────────────────────
  const criticalOrHigh = failures.filter(f => f.severity === 'critical' || f.severity === 'high');
  const status: DominanceStatus = criticalOrHigh.length === 0 ? 'DOMINATED' : 'RESISTANT';

  // ── Build summary line ────────────────────────────────────────────────────
  const summary = status === 'DOMINATED'
    ? `Binary conquered in ${iters.length} iteration${iters.length !== 1 ? 's' : ''} ` +
      `at ${finalConfidence}% confidence — verdict: ${last.verdict.classification}.`
    : `Binary resisted analysis (${finalConfidence}% confidence, ` +
      `${criticalOrHigh.length} critical/high failure${criticalOrHigh.length !== 1 ? 's' : ''}). ` +
      `Primary: ${failures[0]?.description.slice(0, 80) ?? 'unknown'}`;

  return {
    status,
    failures,
    finalConfidence,
    contradictionCount,
    verdictStable,
    reasoningChainClear,
    summary,
    timestamp:      Date.now(),
    iterationCount: iters.length,
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function emptyAssessment(reason: string): DominanceAssessment {
  return {
    status:              'RESISTANT',
    failures:            [{ reason: 'missing-signals', severity: 'critical', description: reason }],
    finalConfidence:     0,
    contradictionCount:  0,
    verdictStable:       false,
    reasoningChainClear: false,
    summary:             reason,
    timestamp:           Date.now(),
    iterationCount:      0,
  };
}

// ── Persistence helpers ───────────────────────────────────────────────────────

const DOMINANCE_KEY_PREFIX = 'hexhawk.dominance.';
const MAX_DOMINANCE_RECORDS = 100;

interface StoredDominanceRecord {
  fileHash:   string;
  fileName:   string;
  assessment: DominanceAssessment;
}

/** Persist a dominance assessment keyed by file hash. */
export function saveDominanceAssessment(
  fileHash: string,
  fileName: string,
  assessment: DominanceAssessment,
): void {
  if (!fileHash) return;
  try {
    const key = `${DOMINANCE_KEY_PREFIX}${fileHash}`;
    localStorage.setItem(key, JSON.stringify({ fileHash, fileName, assessment }));

    // Keep an index of all hashes for pruning
    const indexKey = `${DOMINANCE_KEY_PREFIX}index`;
    const existing: string[] = (() => {
      try { return JSON.parse(localStorage.getItem(indexKey) ?? '[]'); } catch { return []; }
    })();
    if (!existing.includes(fileHash)) {
      existing.push(fileHash);
      // Prune oldest if over budget
      if (existing.length > MAX_DOMINANCE_RECORDS) {
        const toRemove = existing.shift()!;
        localStorage.removeItem(`${DOMINANCE_KEY_PREFIX}${toRemove}`);
      }
      localStorage.setItem(indexKey, JSON.stringify(existing));
    }
  } catch {
    // Non-critical
  }
}

/** Load the most recent assessment for a file hash, or null if not found. */
export function loadDominanceAssessment(fileHash: string): DominanceAssessment | null {
  if (!fileHash) return null;
  try {
    const raw = localStorage.getItem(`${DOMINANCE_KEY_PREFIX}${fileHash}`);
    if (!raw) return null;
    const rec = JSON.parse(raw) as StoredDominanceRecord;
    return rec.assessment ?? null;
  } catch {
    return null;
  }
}
