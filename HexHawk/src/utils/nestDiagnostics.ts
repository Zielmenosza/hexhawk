/**
 * nestDiagnostics — NEST Post-Run Diagnostics Engine
 *
 * After each NEST session completes, analyze the full iteration history and
 * classify the failure mode (or success). The goal is to understand *why* the
 * system behaved the way it did before making any config changes.
 *
 * Outcome taxonomy:
 *   SUCCESS         — stable + high confidence, contradictions resolved
 *   OVERFITTING     — too aggressive: many iterations, tiny gain, or overconfident
 *   UNDERFITTING    — shallow analysis: stopped too early, low coverage, stalled
 *   MISCLASSIFICATION — reasoning broke down: verdict oscillated or contradictions grew
 *
 * Usage:
 *   import { runDiagnostics } from './nestDiagnostics';
 *   const report = runDiagnostics(session, dominanceStatus, weaknessFlags, verdictFlipCount);
 */

import type { NestSession, NestIterationSnapshot } from './nestEngine';
import type { WeaknessFlag } from './multiBinaryRunner';

// ── Public types ─────────────────────────────────────────────────────────────

export type DiagnosticOutcome =
  | 'SUCCESS'
  | 'OVERFITTING'
  | 'UNDERFITTING'
  | 'MISCLASSIFICATION';

export type EvidenceSeverity = 'critical' | 'major' | 'minor';

/**
 * A single check result within a dimension.
 * `pass = true` means the check found no problem.
 */
export interface DiagnosticEvidence {
  id:       string;
  label:    string;
  value:    string;
  pass:     boolean;
  severity: EvidenceSeverity;
  detail:   string;
}

/** Thematic grouping of related checks with an aggregate health score. */
export interface DiagnosticDimension {
  id:           string;
  label:        string;
  icon:         string;
  /** 0–100. Higher = healthier. */
  score:        number;
  status:       'healthy' | 'warning' | 'critical';
  observations: string[];
  checks:       DiagnosticEvidence[];
}

/** Per-iteration numeric metrics used to build trajectory sparklines. */
export interface IterationTrace {
  iteration:         number;
  confidence:        number;
  contradictions:    number;
  signalCount:       number;
  /** Confidence gain vs. the previous iteration (0 for the first). */
  gainThisIter:      number;
  verdictClass:      string;
}

/** Complete diagnostics report returned by runDiagnostics(). */
export interface NestDiagnosticsReport {
  sessionId:            string;
  outcome:              DiagnosticOutcome;
  outcomeLabel:         string;
  /** Single sentence explaining the primary cause of the outcome. */
  outcomeReason:        string;
  /** 0–100. How confident the diagnostics engine is in its classification. */
  diagnosticConfidence: number;
  dimensions: {
    progression:    DiagnosticDimension;
    contradictions: DiagnosticDimension;
    convergence:    DiagnosticDimension;
    depth:          DiagnosticDimension;
  };
  /** Flat list of all collected evidence, sorted by severity then dimension. */
  evidence:             DiagnosticEvidence[];
  /** Prioritised, actionable next steps (≤4). */
  actionableInsights:   string[];
  /** Per-iteration trace data for sparkline charts. */
  trace:                IterationTrace[];
  summary: {
    totalIterations:     number;
    firstConfidence:     number;
    finalConfidence:     number;
    totalGain:           number;
    avgGainPerIter:      number;
    finalContradictions: number;
    finalSignals:        number;
    stopReason:          string;
    durationMs:          number;
    verdictFlipCount:    number;
    stabilityScore:      number;
  };
}

// ── Internal helpers ─────────────────────────────────────────────────────────

function contradictionCount(snap: NestIterationSnapshot): number {
  const cs = snap.verdict.contradictions ?? [];
  return cs.filter(c => c.severity === 'high' || c.severity === 'medium').length;
}

function dimStatus(score: number): 'healthy' | 'warning' | 'critical' {
  if (score >= 70) return 'healthy';
  if (score >= 40) return 'warning';
  return 'critical';
}

function stopReasonLabel(status: NestSession['status']): string {
  const map: Record<string, string> = {
    converged:    'Converged',
    plateau:      'Plateau',
    'max-reached':'Max iterations',
    error:        'Error',
    idle:         'Not run',
    running:      'Running',
    paused:       'Paused',
  };
  return map[status] ?? status;
}

/** 0–100 stability score: 100 = same verdict every iteration. */
function computeStability(snaps: NestIterationSnapshot[]): number {
  if (snaps.length <= 1) return 100;
  const flips = snaps.reduce((c, s, i) =>
    i > 0 && snaps[i - 1].verdict.classification !== s.verdict.classification ? c + 1 : c, 0,
  );
  return Math.max(0, Math.round(100 - (flips / (snaps.length - 1)) * 100));
}

// ── Dimension analysis functions ─────────────────────────────────────────────

function analyzeProgression(
  snaps:   NestIterationSnapshot[],
  flags:   WeaknessFlag[],
): DiagnosticDimension {
  const checks: DiagnosticEvidence[] = [];
  const obs: string[] = [];

  const first = snaps[0];
  const last  = snaps[snaps.length - 1];
  const totalGain  = last.confidence - first.confidence;
  const avgGain    = snaps.length > 1 ? totalGain / (snaps.length - 1) : totalGain;

  // ── Check 1: Total confidence gain ──────────────────────────────────────
  const positiveGain = totalGain >= 5;
  checks.push({
    id: 'conf-gain-total',
    label: 'Total confidence gain',
    value: `${totalGain >= 0 ? '+' : ''}${totalGain.toFixed(1)}%`,
    pass: positiveGain,
    severity: totalGain < 0 ? 'critical' : totalGain < 5 ? 'major' : 'minor',
    detail: totalGain >= 5
      ? `Confidence grew ${totalGain.toFixed(1)} pts overall — solid improvement.`
      : totalGain < 0
        ? `Confidence regressed ${Math.abs(totalGain).toFixed(1)} pts — analysis got worse.`
        : `Only ${totalGain.toFixed(1)} pts gained total — essentially no learning.`,
  });

  // ── Check 2: Average gain per iteration ─────────────────────────────────
  const goodAvg = avgGain >= 3.0;
  checks.push({
    id: 'conf-gain-avg',
    label: 'Avg gain per iteration',
    value: `${avgGain >= 0 ? '+' : ''}${avgGain.toFixed(1)} pts/iter`,
    pass: goodAvg,
    severity: avgGain < 1.0 ? 'major' : 'minor',
    detail: goodAvg
      ? `Each iteration contributed ${avgGain.toFixed(1)} pts — healthy velocity.`
      : `Only ${avgGain.toFixed(1)} pts/iter — iterations are not generating signal.`,
  });

  // ── Check 3: Monotone trajectory ────────────────────────────────────────
  const dips = snaps.filter((s, i) => i > 0 && s.confidence < snaps[i - 1].confidence).length;
  const monotone = dips === 0;
  checks.push({
    id: 'conf-monotone',
    label: 'Confidence trajectory',
    value: monotone ? 'Monotone ↑' : `${dips} dip(s)`,
    pass: dips <= 1,
    severity: dips >= 3 ? 'critical' : dips >= 2 ? 'major' : 'minor',
    detail: monotone
      ? 'Confidence increased every iteration — no regression.'
      : `Confidence dipped ${dips} time(s) — evidence conflict or noise.`,
  });

  // ── Check 4: Negative improvement flag ──────────────────────────────────
  const negFlag = flags.includes('negative-improvement');
  if (negFlag) {
    checks.push({
      id: 'negative-improvement',
      label: 'Negative improvement',
      value: 'Final < First',
      pass: false,
      severity: 'critical',
      detail: 'Final confidence is lower than the opening iteration — contradictory analysis.',
    });
  }

  // Observations
  if (snaps.length >= 2) {
    obs.push(`Gained ${totalGain >= 0 ? '+' : ''}${totalGain.toFixed(0)} pts over ${snaps.length} iteration(s).`);
  }
  if (!monotone) obs.push(`${dips} confidence regression(s) detected.`);
  if (flags.includes('strategy-stall')) obs.push('Strategy stall — no meaningful confidence gain.');

  // Score: base 60, +20 for positive total gain, +20 for good avg
  let score = 60;
  if (positiveGain)  score += 20;
  if (goodAvg)       score += 20;
  if (negFlag)       score -= 40;
  if (dips >= 2)     score -= 15;
  score = Math.max(0, Math.min(100, score));

  return { id: 'progression', label: 'Confidence Progression', icon: '📈', score, status: dimStatus(score), observations: obs, checks };
}

function analyzeContradictions(
  snaps: NestIterationSnapshot[],
  flags: WeaknessFlag[],
): DiagnosticDimension {
  const checks: DiagnosticEvidence[] = [];
  const obs: string[] = [];

  const firstContras  = contradictionCount(snaps[0]);
  const lastContras   = contradictionCount(snaps[snaps.length - 1]);
  const peak          = Math.max(...snaps.map(contradictionCount));
  const trend         = lastContras - firstContras;

  // ── Check 1: Contradiction trend ────────────────────────────────────────
  checks.push({
    id: 'contra-trend',
    label: 'Contradiction trend',
    value: trend < 0 ? `↓ ${Math.abs(trend)}` : trend > 0 ? `↑ ${trend}` : 'Flat',
    pass: trend <= 0,
    severity: trend > 1 ? 'critical' : trend > 0 ? 'major' : 'minor',
    detail: trend < 0
      ? `Contradictions decreased by ${Math.abs(trend)} — analysis resolved conflicts.`
      : trend > 0
        ? `Contradictions grew by ${trend} — analysis introduced more conflicts.`
        : 'Contradiction count unchanged across iterations.',
  });

  // ── Check 2: Final contradiction burden ─────────────────────────────────
  checks.push({
    id: 'contra-final',
    label: 'Final contradiction count',
    value: `${lastContras}`,
    pass: lastContras <= 1,
    severity: lastContras >= 3 ? 'critical' : lastContras === 2 ? 'major' : 'minor',
    detail: lastContras <= 1
      ? 'At most 1 contradiction remaining — well-resolved.'
      : `${lastContras} medium/high contradictions unresolved at session end.`,
  });

  // ── Check 3: Peak contradictions ────────────────────────────────────────
  if (peak > firstContras) {
    checks.push({
      id: 'contra-peak',
      label: 'Peak during analysis',
      value: `${peak}`,
      pass: peak <= 2,
      severity: peak >= 4 ? 'major' : 'minor',
      detail: `Contradictions peaked at ${peak} — analysis temporarily destabilised.`,
    });
  }

  // ── Check 4: Contradiction-heavy flag ───────────────────────────────────
  if (flags.includes('contradiction-heavy')) {
    checks.push({
      id: 'contra-heavy-flag',
      label: 'Contradiction-heavy',
      value: '≥2 unresolved',
      pass: false,
      severity: 'major',
      detail: 'Final verdict carries ≥2 unresolved contradictions — evidence in conflict.',
    });
  }

  obs.push(`${lastContras} contradiction(s) at session end.`);
  if (trend > 0) obs.push(`Grew by ${trend} during analysis.`);
  if (trend < 0) obs.push(`Resolved ${Math.abs(trend)} contradiction(s).`);

  let score = 80;
  if (lastContras === 0) score = 100;
  else if (lastContras === 1) score = 85;
  else if (lastContras === 2) score -= 25;
  else if (lastContras >= 3) score -= 45;
  if (trend > 0) score -= 20;
  score = Math.max(0, Math.min(100, score));

  return { id: 'contradictions', label: 'Contradiction Resolution', icon: '⚡', score, status: dimStatus(score), observations: obs, checks };
}

function analyzeConvergence(
  session: NestSession,
  snaps:   NestIterationSnapshot[],
  flags:   WeaknessFlag[],
): DiagnosticDimension {
  const checks: DiagnosticEvidence[] = [];
  const obs: string[] = [];

  const { config, status } = session;
  const last          = snaps[snaps.length - 1];
  const finalConf     = last.confidence;
  const iters         = snaps.length;
  const hitMax        = status === 'max-reached';
  const stoppedFast   = iters <= Math.ceil(config.maxIterations / 2);
  const stoppedEarly  = (status === 'converged' || status === 'plateau') && finalConf < 65;

  // ── Check 1: Premature convergence ──────────────────────────────────────
  const earlyStop = stoppedFast && stoppedEarly;
  checks.push({
    id: 'convergence-early',
    label: 'Premature stop',
    value: earlyStop ? `${iters} iter @ ${finalConf}%` : 'OK',
    pass: !earlyStop,
    severity: earlyStop ? 'major' : 'minor',
    detail: earlyStop
      ? `Stopped after only ${iters} iteration(s) with ${finalConf}% confidence — too shallow.`
      : 'Session ran long enough relative to the confidence achieved.',
  });

  // ── Check 2: Hit max iterations without convergence ─────────────────────
  checks.push({
    id: 'convergence-max-hit',
    label: 'Reached max iterations',
    value: hitMax ? `${iters}/${config.maxIterations}` : 'No',
    pass: !hitMax,
    severity: hitMax && finalConf < 75 ? 'major' : 'minor',
    detail: hitMax
      ? `Session used all ${config.maxIterations} iterations without satisfying convergence criteria.`
      : 'Session converged before hitting the iteration limit.',
  });

  // ── Check 3: Gain in final 2 iterations ─────────────────────────────────
  if (iters >= 3) {
    const last2Gain = snaps[iters - 1].confidence - snaps[iters - 3].confidence;
    const wastedLate = hitMax && last2Gain < 2.0;
    checks.push({
      id: 'convergence-late-gain',
      label: 'Gain in last 2 iters',
      value: `${last2Gain >= 0 ? '+' : ''}${last2Gain.toFixed(1)} pts`,
      pass: !wastedLate,
      severity: wastedLate ? 'major' : 'minor',
      detail: wastedLate
        ? `Only ${last2Gain.toFixed(1)} pts gained in the last 2 iterations while running at max — wasted work.`
        : 'Late-stage iterations contributed meaningfully.',
    });
  }

  // ── Check 4: Low coverage flag ───────────────────────────────────────────
  if (flags.includes('low-coverage')) {
    checks.push({
      id: 'convergence-low-coverage',
      label: 'Low instruction coverage',
      value: `${last.input.instructionCount} instr`,
      pass: false,
      severity: 'major',
      detail: `Only ${last.input.instructionCount} instructions analysed at session end — too little code to reach conclusions.`,
    });
  }

  obs.push(`${stopReasonLabel(status)} after ${iters} iteration(s) at ${finalConf}% confidence.`);
  if (earlyStop) obs.push('Converged too early relative to confidence achieved.');
  if (hitMax) obs.push('Hit iteration ceiling — consider raising maxIterations or aggressiveness.');

  let score = 75;
  if (!hitMax && !earlyStop)  score = 90;
  if (earlyStop)              score -= 35;
  if (hitMax && finalConf < 75) score -= 20;
  if (flags.includes('low-coverage')) score -= 25;
  score = Math.max(0, Math.min(100, score));

  return { id: 'convergence', label: 'Convergence Quality', icon: '🔄', score, status: dimStatus(score), observations: obs, checks };
}

function analyzeDepth(
  snaps:          NestIterationSnapshot[],
  flags:          WeaknessFlag[],
  verdictFlips:   number,
  dominanceStatus: 'DOMINATED' | 'RESISTANT' | 'unknown',
): DiagnosticDimension {
  const checks: DiagnosticEvidence[] = [];
  const obs: string[] = [];

  const last       = snaps[snaps.length - 1];
  const totalGain  = last.confidence - snaps[0].confidence;
  const avgGain    = snaps.length > 1 ? totalGain / (snaps.length - 1) : totalGain;

  // ── Check 1: Verdict oscillation ────────────────────────────────────────
  checks.push({
    id: 'depth-flips',
    label: 'Verdict flips',
    value: verdictFlips === 0 ? 'None' : `${verdictFlips}×`,
    pass: verdictFlips <= 1,
    severity: verdictFlips >= 3 ? 'critical' : verdictFlips === 2 ? 'major' : 'minor',
    detail: verdictFlips === 0
      ? 'Classification never changed — stable reasoning.'
      : `Classification changed ${verdictFlips} time(s) — analysis oscillated.`,
  });

  // ── Check 2: Strategy stall ──────────────────────────────────────────────
  if (flags.includes('strategy-stall')) {
    checks.push({
      id: 'depth-stall',
      label: 'Strategy stall',
      value: `${totalGain.toFixed(1)} pts total`,
      pass: false,
      severity: 'major',
      detail: 'Total confidence gain < 3 pts — expansion strategy generated no new signal.',
    });
  }

  // ── Check 3: Overconfidence ──────────────────────────────────────────────
  const overconf = flags.includes('overconfident');
  if (overconf) {
    checks.push({
      id: 'depth-overconfident',
      label: 'Overconfidence',
      value: `${last.confidence}% but RESISTANT`,
      pass: false,
      severity: 'major',
      detail: 'High confidence was declared but the binary resisted NEST dominance — verdict may be unreliable.',
    });
  }

  // ── Check 4: Diminishing returns ────────────────────────────────────────
  const dimReturns = snaps.length >= 4 && avgGain < 1.5;
  if (dimReturns) {
    checks.push({
      id: 'depth-dim-returns',
      label: 'Diminishing returns',
      value: `${avgGain.toFixed(1)} pts/iter`,
      pass: false,
      severity: 'minor',
      detail: `With ${snaps.length} iterations and only ${avgGain.toFixed(1)} pts/iter average, later iterations wasted compute.`,
    });
  }

  // ── Check 5: Signal velocity in late iterations ─────────────────────────
  if (snaps.length >= 3) {
    const lateIters = snaps.slice(-2);
    const lateNewSigs = lateIters.reduce((acc, s) => acc + (s.delta?.newSignals.length ?? 0), 0);
    checks.push({
      id: 'depth-late-signals',
      label: 'Late-stage new signals',
      value: `${lateNewSigs}`,
      pass: lateNewSigs > 0 || snaps.length <= 3,
      severity: 'minor',
      detail: lateNewSigs > 0
        ? `Found ${lateNewSigs} new signal(s) in the final 2 iterations — still learning.`
        : 'No new signals in the final 2 iterations — analysis had exhausted the binary.',
    });
  }

  obs.push(verdictFlips === 0 ? 'Verdict was stable throughout.' : `Verdict changed ${verdictFlips} time(s).`);
  if (dominanceStatus === 'RESISTANT') obs.push('Binary resisted NEST dominance despite high confidence.');
  if (flags.includes('strategy-stall')) obs.push('No meaningful signal gain — expansion strategy failed.');

  let score = 80;
  if (verdictFlips === 0) score += 10;
  if (verdictFlips >= 2)  score -= 30;
  if (verdictFlips >= 3)  score -= 20; // extra penalty
  if (overconf)           score -= 20;
  if (flags.includes('strategy-stall')) score -= 20;
  if (dimReturns)         score -= 10;
  score = Math.max(0, Math.min(100, score));

  return { id: 'depth', label: 'Analysis Depth', icon: '🔍', score, status: dimStatus(score), observations: obs, checks };
}

// ── Outcome classifier ────────────────────────────────────────────────────────

function classifyOutcome(
  session:         NestSession,
  snaps:           NestIterationSnapshot[],
  flags:           WeaknessFlag[],
  verdictFlips:    number,
  dominanceStatus: 'DOMINATED' | 'RESISTANT' | 'unknown',
  dims:            NestDiagnosticsReport['dimensions'],
): { outcome: DiagnosticOutcome; reason: string; confidence: number } {

  const last          = snaps[snaps.length - 1];
  const first         = snaps[0];
  const finalConf     = last.confidence;
  const totalGain     = last.confidence - first.confidence;
  const avgGain       = snaps.length > 1 ? totalGain / (snaps.length - 1) : totalGain;
  const lastContras   = contradictionCount(last);
  const firstContras  = contradictionCount(first);
  const contraTrend   = lastContras - firstContras;
  const hitMax        = session.status === 'max-reached';
  const stoppedFast   = snaps.length <= Math.ceil(session.config.maxIterations / 2);

  // ─────────────────────────────────────────────────────────────────────────
  // MISCLASSIFICATION — verdict is unreliable
  // ─────────────────────────────────────────────────────────────────────────
  const misclassSignals: string[] = [];
  if (verdictFlips >= 2)                                        misclassSignals.push('verdict oscillation');
  if (flags.includes('unstable-reasoning'))                     misclassSignals.push('unstable reasoning flag');
  if (contraTrend > 1)                                          misclassSignals.push('contradictions grew');
  if (flags.includes('negative-improvement'))                   misclassSignals.push('confidence regression');
  if (last.verdict.classification === 'unknown' && snaps.length >= 3) misclassSignals.push('unresolved verdict');

  if (misclassSignals.length >= 2 || (misclassSignals.length >= 1 && flags.includes('unstable-reasoning'))) {
    return {
      outcome: 'MISCLASSIFICATION',
      reason: `Reasoning broke down: ${misclassSignals.slice(0, 2).join(' + ')}.`,
      confidence: Math.min(90, 60 + misclassSignals.length * 10),
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // OVERFITTING — too aggressive or overconfident
  // ─────────────────────────────────────────────────────────────────────────
  const overfitSignals: string[] = [];
  if (flags.includes('overconfident'))                          overfitSignals.push('overconfident verdict');
  if (hitMax && avgGain < 2.0 && snaps.length >= 4)            overfitSignals.push('wasted iterations');
  if (flags.includes('contradiction-heavy') && hitMax)         overfitSignals.push('unresolved contradictions at max');
  if (verdictFlips >= 1 && flags.includes('strategy-stall'))   overfitSignals.push('oscillating + stalled');

  if (overfitSignals.length >= 1) {
    return {
      outcome: 'OVERFITTING',
      reason: `Analysis too aggressive: ${overfitSignals.slice(0, 2).join(', ')}.`,
      confidence: Math.min(85, 55 + overfitSignals.length * 10),
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // UNDERFITTING — analysis was too shallow
  // ─────────────────────────────────────────────────────────────────────────
  const underfitSignals: string[] = [];
  if (flags.includes('low-coverage'))                           underfitSignals.push('low instruction coverage');
  if (flags.includes('strategy-stall') && !hitMax)             underfitSignals.push('strategy stall before limit');
  if (stoppedFast && finalConf < 65)                            underfitSignals.push('premature convergence');
  if (totalGain < 3 && snaps.length >= 2)                      underfitSignals.push('no confidence gain');

  if (underfitSignals.length >= 1) {
    return {
      outcome: 'UNDERFITTING',
      reason: `Analysis was too shallow: ${underfitSignals.slice(0, 2).join(', ')}.`,
      confidence: Math.min(85, 55 + underfitSignals.length * 10),
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // SUCCESS
  // ─────────────────────────────────────────────────────────────────────────
  const succConf =
    finalConf >= 85 ? 90 :
    finalConf >= 75 ? 80 :
    finalConf >= 65 ? 70 : 60;

  return {
    outcome: 'SUCCESS',
    reason: `Session converged cleanly at ${finalConf}% confidence with ${lastContras} contradiction(s) remaining.`,
    confidence: succConf,
  };
}

// ── Actionable insights ───────────────────────────────────────────────────────

function buildInsights(
  outcome: DiagnosticOutcome,
  session: NestSession,
  snaps:   NestIterationSnapshot[],
  flags:   WeaknessFlag[],
  verdictFlips: number,
): string[] {
  const insights: string[] = [];
  const { config } = session;
  const last = snaps[snaps.length - 1];

  switch (outcome) {
    case 'MISCLASSIFICATION': {
      if (flags.includes('unstable-reasoning') || verdictFlips >= 2) {
        insights.push('Raise plateauThreshold to 4+ to let the verdict stabilise before stopping.');
      }
      if (contradictionCount(last) >= 2) {
        insights.push('Review the contradictions list — resolve or dismiss conflicting evidence before re-running.');
      }
      if (flags.includes('negative-improvement')) {
        insights.push('Check for high-entropy resource sections that may be triggering false-positive signals.');
      }
      insights.push('Do not change aggressiveness until contradictions are resolved.');
      break;
    }
    case 'OVERFITTING': {
      if (flags.includes('overconfident')) {
        insights.push('Raise confidenceThreshold (e.g. to 90) to prevent premature overconfidence on resistant binaries.');
      }
      if (session.status === 'max-reached') {
        insights.push(`${config.maxIterations} iterations exhausted with low gain — reduce aggressiveness to "balanced" or "conservative".`);
      }
      if (flags.includes('contradiction-heavy')) {
        insights.push('Many contradictions persisted — the expansion strategy may be amplifying noise. Try disabling ECHO on re-run.');
      }
      break;
    }
    case 'UNDERFITTING': {
      if (flags.includes('low-coverage')) {
        insights.push(`Increase disasmExpansion (currently ${config.disasmExpansion}B) to analyse more code per iteration.`);
      }
      if (flags.includes('strategy-stall')) {
        insights.push('Switch aggressiveness to "aggressive" and enable TALON to break the signal stall.');
      }
      if (snaps.length <= Math.ceil(config.maxIterations / 2) && last.confidence < 65) {
        insights.push(`Raise maxIterations (currently ${config.maxIterations}) — session stopped too early relative to confidence.`);
      }
      break;
    }
    case 'SUCCESS': {
      insights.push('No changes required. Session met its objectives.');
      if (last.confidence < 90 && config.confidenceThreshold < 90) {
        insights.push('Consider raising confidenceThreshold to 90 for even tighter success criteria on future runs.');
      }
      break;
    }
  }

  return insights.slice(0, 4);
}

// ── Public entry point ────────────────────────────────────────────────────────

/**
 * Run the full diagnostics pipeline on a completed NEST session.
 *
 * @param session         — The finalised NestSession.
 * @param dominanceStatus — Result of assessDominance() on the session.
 * @param weaknessFlags   — WeaknessFlags from detectWeaknessFlags() or BatchItemResult.
 * @param verdictFlipCount — From countVerdictFlips() or BatchItemResult.
 */
export function runDiagnostics(
  session:         NestSession,
  dominanceStatus: 'DOMINATED' | 'RESISTANT' | 'unknown' = 'unknown',
  weaknessFlags:   WeaknessFlag[] = [],
  verdictFlipCount = 0,
): NestDiagnosticsReport {
  const snaps = session.iterations;

  if (snaps.length === 0) {
    // Degenerate: nothing ran
    const empty: DiagnosticDimension = {
      id: 'empty', label: '', icon: '', score: 0, status: 'critical', observations: [], checks: [],
    };
    return {
      sessionId: session.id,
      outcome: 'UNDERFITTING',
      outcomeLabel: 'Underfitting',
      outcomeReason: 'No iterations completed — session produced no data.',
      diagnosticConfidence: 95,
      dimensions: { progression: empty, contradictions: empty, convergence: empty, depth: empty },
      evidence: [],
      actionableInsights: ['Ensure the binary is readable and NEST is configured correctly before re-running.'],
      trace: [],
      summary: {
        totalIterations: 0, firstConfidence: 0, finalConfidence: 0,
        totalGain: 0, avgGainPerIter: 0, finalContradictions: 0,
        finalSignals: 0, stopReason: stopReasonLabel(session.status),
        durationMs: (session.endTime ?? Date.now()) - session.startTime,
        verdictFlipCount: 0, stabilityScore: 0,
      },
    };
  }

  const first = snaps[0];
  const last  = snaps[snaps.length - 1];

  // ── Build trace ───────────────────────────────────────────────────────────
  const trace: IterationTrace[] = snaps.map((s, i) => ({
    iteration:      s.iteration,
    confidence:     s.confidence,
    contradictions: contradictionCount(s),
    signalCount:    s.verdict.signals.length,
    gainThisIter:   i === 0 ? 0 : s.confidence - snaps[i - 1].confidence,
    verdictClass:   s.verdict.classification,
  }));

  // ── Analyse dimensions ────────────────────────────────────────────────────
  const dimProgression    = analyzeProgression(snaps, weaknessFlags);
  const dimContradictions = analyzeContradictions(snaps, weaknessFlags);
  const dimConvergence    = analyzeConvergence(session, snaps, weaknessFlags);
  const dimDepth          = analyzeDepth(snaps, weaknessFlags, verdictFlipCount, dominanceStatus);

  const dimensions = {
    progression:    dimProgression,
    contradictions: dimContradictions,
    convergence:    dimConvergence,
    depth:          dimDepth,
  };

  // ── Classify outcome ──────────────────────────────────────────────────────
  const { outcome, reason, confidence: diagConf } = classifyOutcome(
    session, snaps, weaknessFlags, verdictFlipCount, dominanceStatus, dimensions,
  );

  const outcomeLabels: Record<DiagnosticOutcome, string> = {
    SUCCESS:          'Success',
    OVERFITTING:      'Overfitting',
    UNDERFITTING:     'Underfitting',
    MISCLASSIFICATION:'Misclassification',
  };

  // ── Flatten evidence ──────────────────────────────────────────────────────
  const severityOrder: Record<EvidenceSeverity, number> = { critical: 0, major: 1, minor: 2 };
  const evidence = [
    ...dimProgression.checks,
    ...dimContradictions.checks,
    ...dimConvergence.checks,
    ...dimDepth.checks,
  ].sort((a, b) => {
    const sd = severityOrder[a.severity] - severityOrder[b.severity];
    return sd !== 0 ? sd : (a.pass ? 1 : -1);
  });

  // ── Insights ──────────────────────────────────────────────────────────────
  const actionableInsights = buildInsights(outcome, session, snaps, weaknessFlags, verdictFlipCount);

  // ── Summary ───────────────────────────────────────────────────────────────
  const totalGain    = last.confidence - first.confidence;
  const avgGainPerIter = snaps.length > 1 ? totalGain / (snaps.length - 1) : totalGain;

  return {
    sessionId: session.id,
    outcome,
    outcomeLabel: outcomeLabels[outcome],
    outcomeReason: reason,
    diagnosticConfidence: diagConf,
    dimensions,
    evidence,
    actionableInsights,
    trace,
    summary: {
      totalIterations:     snaps.length,
      firstConfidence:     first.confidence,
      finalConfidence:     last.confidence,
      totalGain,
      avgGainPerIter,
      finalContradictions: contradictionCount(last),
      finalSignals:        last.verdict.signals.length,
      stopReason:          stopReasonLabel(session.status),
      durationMs:          (session.endTime ?? Date.now()) - session.startTime,
      verdictFlipCount,
      stabilityScore:      computeStability(snaps),
    },
  };
}
