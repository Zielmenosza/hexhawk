/**
 * strikeBehaviorAnalyzer.ts — WS10 STRIKE Cross-Run Behavioural Analysis
 *
 * Analyses multiple STRIKE execution runs to:
 *   1. Diff two runs and identify what changed
 *   2. Score anomalies by severity and type
 *   3. Produce a BehavioralAnomalyReport for consumption by the UI
 *      and the cross-engine SharedIntelligenceContext
 */

import type { StrikeDelta, StrikeStep, StrikeTimeline } from './strikeEngine';
import type { RegKey } from './strikeEngine';

// ─── Types ────────────────────────────────────────────────────────────────────

export type AnomalyType =
  | 'register-value-drift'    // same instruction, different register value
  | 'path-divergence'         // different instruction sequence between runs
  | 'timing-drift'            // step count or RIP trajectory changed
  | 'stack-pivot-inconsistent' // stack pointer behaviour changed
  | 'api-sequence-change'     // different API calls observed
  | 'pattern-appeared'        // a STRIKE pattern triggered in one run but not another
  | 'pattern-disappeared';

export type AnomalySeverity = 'critical' | 'high' | 'medium' | 'low';

export interface AnomalyScore {
  type: AnomalyType;
  severity: AnomalySeverity;
  /** 0–100 confidence that this is a real anomaly (not noise) */
  confidence: number;
  description: string;
  /** Step index where the anomaly first manifests */
  firstStepIndex: number;
  /** Affected register or address, if applicable */
  affectedRegister?: RegKey;
}

/** Lightweight representation of a single execution run */
export interface StrikeRun {
  runId:     string;
  timestamp: number;
  steps:     StrikeStep[];
  timeline:  StrikeTimeline;
  patterns:  string[];   // pattern IDs that fired
}

/** Diff between two runs */
export interface RunDiff {
  runA: string;  // runId
  runB: string;  // runId
  /** Steps that appear in A but not B (by RIP address) */
  stepsOnlyInA: StrikeStep[];
  /** Steps that appear in B but not A */
  stepsOnlyInB: StrikeStep[];
  /** Steps present in both, with register deltas that changed */
  changedSteps: Array<{
    stepIndex: number;
    ripAddress: number;
    registerChanges: Array<{ reg: RegKey; valueInA: number; valueInB: number }>;
  }>;
  /** Patterns that fired in A but not B */
  patternsOnlyInA: string[];
  /** Patterns that fired in B but not A */
  patternsOnlyInB: string[];
  /** True when the overall step sequences diverge (path-sensitive difference) */
  hasPathDivergence: boolean;
}

export interface BehavioralAnomalyReport {
  runIds:     string[];
  diffs:      RunDiff[];
  anomalies:  AnomalyScore[];
  /** Overall risk score change between runs (positive = getting more suspicious) */
  riskTrend:  number;
  summary:    string;
}

// ─── Run Diffing ──────────────────────────────────────────────────────────────

export function diffRuns(a: StrikeRun, b: StrikeRun): RunDiff {
  const ripSetA = new Map(a.steps.map((s, i) => [s.rip, { step: s, index: i }]));
  const ripSetB = new Map(b.steps.map((s, i) => [s.rip, { step: s, index: i }]));

  const stepsOnlyInA = a.steps.filter(s => !ripSetB.has(s.rip));
  const stepsOnlyInB = b.steps.filter(s => !ripSetA.has(s.rip));

  const changedSteps: RunDiff['changedSteps'] = [];

  for (const [rip, entA] of ripSetA.entries()) {
    const entB = ripSetB.get(rip);
    if (!entB) continue;

    const regChanges: Array<{ reg: RegKey; valueInA: number; valueInB: number }> = [];

    const regsA = entA.step.snapshot?.registers ?? {};
    const regsB = entB.step.snapshot?.registers ?? {};

    const allKeys = new Set([...Object.keys(regsA), ...Object.keys(regsB)]) as Set<RegKey>;
    for (const reg of allKeys) {
      const vA = (regsA as Record<string, number>)[reg] ?? 0;
      const vB = (regsB as Record<string, number>)[reg] ?? 0;
      if (vA !== vB) {
        regChanges.push({ reg, valueInA: vA, valueInB: vB });
      }
    }

    if (regChanges.length > 0) {
      changedSteps.push({
        stepIndex: entA.index,
        ripAddress: rip,
        registerChanges: regChanges,
      });
    }
  }

  const hasPathDivergence = stepsOnlyInA.length > 0 || stepsOnlyInB.length > 0;

  const patternsOnlyInA = a.patterns.filter(p => !b.patterns.includes(p));
  const patternsOnlyInB = b.patterns.filter(p => !a.patterns.includes(p));

  return {
    runA: a.runId,
    runB: b.runId,
    stepsOnlyInA,
    stepsOnlyInB,
    changedSteps,
    patternsOnlyInA,
    patternsOnlyInB,
    hasPathDivergence,
  };
}

// ─── Anomaly Scoring ──────────────────────────────────────────────────────────

export function scoreAnomalies(diffs: RunDiff[]): AnomalyScore[] {
  const anomalies: AnomalyScore[] = [];

  for (const diff of diffs) {
    // Path divergence
    if (diff.hasPathDivergence) {
      const totalDivergent = diff.stepsOnlyInA.length + diff.stepsOnlyInB.length;
      anomalies.push({
        type: 'path-divergence',
        severity: totalDivergent > 10 ? 'critical' : totalDivergent > 4 ? 'high' : 'medium',
        confidence: Math.min(95, 50 + totalDivergent * 4),
        description: `Execution path diverged: ${diff.stepsOnlyInA.length} steps only in run A, ${diff.stepsOnlyInB.length} only in run B. Possible environment-sensitive branching or anti-analysis trigger.`,
        firstStepIndex: 0,
      });
    }

    // Register value drift
    for (const changed of diff.changedSteps) {
      for (const rc of changed.registerChanges) {
        // Stack pointer changes are especially interesting
        const isSP = rc.reg === 'rsp';
        anomalies.push({
          type: isSP ? 'stack-pivot-inconsistent' : 'register-value-drift',
          severity: isSP ? 'high' : 'low',
          confidence: isSP ? 80 : 45,
          description: `${rc.reg.toUpperCase()} differs at RIP 0x${changed.ripAddress.toString(16).toUpperCase()}: run A = 0x${rc.valueInA.toString(16)}, run B = 0x${rc.valueInB.toString(16)}`,
          firstStepIndex: changed.stepIndex,
          affectedRegister: rc.reg,
        });
      }
    }

    // Pattern changes
    if (diff.patternsOnlyInA.length > 0) {
      anomalies.push({
        type: 'pattern-disappeared',
        severity: 'medium',
        confidence: 70,
        description: `Patterns fired in run A but not run B: ${diff.patternsOnlyInA.join(', ')}. Pattern may be triggered by non-deterministic conditions.`,
        firstStepIndex: 0,
      });
    }
    if (diff.patternsOnlyInB.length > 0) {
      anomalies.push({
        type: 'pattern-appeared',
        severity: 'high',
        confidence: 75,
        description: `New patterns in run B: ${diff.patternsOnlyInB.join(', ')}. Behaviour escalated between runs — possible deferred payload or time-based trigger.`,
        firstStepIndex: 0,
      });
    }
  }

  // Deduplicate (keep highest severity per type)
  const best = new Map<AnomalyType, AnomalyScore>();
  for (const a of anomalies) {
    const existing = best.get(a.type);
    if (!existing || severityRank(a.severity) > severityRank(existing.severity)) {
      best.set(a.type, a);
    }
  }

  return Array.from(best.values()).sort(
    (x, y) => severityRank(y.severity) - severityRank(x.severity)
  );
}

function severityRank(s: AnomalySeverity): number {
  return { critical: 4, high: 3, medium: 2, low: 1 }[s];
}

// ─── Full Analysis ────────────────────────────────────────────────────────────

export function runBehavioralAnalysis(runs: StrikeRun[]): BehavioralAnomalyReport {
  if (runs.length < 2) {
    return {
      runIds: runs.map(r => r.runId),
      diffs: [],
      anomalies: [],
      riskTrend: 0,
      summary: runs.length === 0
        ? 'No STRIKE runs available.'
        : 'Only one STRIKE run — need ≥2 runs for behavioural diff analysis.',
    };
  }

  // Compare each consecutive pair
  const diffs: RunDiff[] = [];
  for (let i = 0; i < runs.length - 1; i++) {
    diffs.push(diffRuns(runs[i], runs[i + 1]));
  }

  const anomalies = scoreAnomalies(diffs);

  // Risk trend: count of high/critical anomalies
  const riskTrend = anomalies.filter(a => severityRank(a.severity) >= 3).length;

  const criticalCount = anomalies.filter(a => a.severity === 'critical').length;
  const highCount     = anomalies.filter(a => a.severity === 'high').length;

  const summary =
    anomalies.length === 0
      ? `${runs.length} STRIKE runs analysed — behaviour consistent across all runs.`
      : `${runs.length} STRIKE runs analysed — ${criticalCount} critical / ${highCount} high anomaly(ies) detected across ${diffs.length} run comparison(s).`;

  return {
    runIds: runs.map(r => r.runId),
    diffs,
    anomalies,
    riskTrend,
    summary,
  };
}
