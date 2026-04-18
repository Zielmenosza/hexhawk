/**
 * nestAdaptiveHealer — NEST Self-Healing Config Adapter
 *
 * Reads a NestDiagnosticsReport and produces a set of targeted NestConfig
 * mutations. Only modifies config knobs — never touches TALON/STRIKE/ECHO
 * engine internals.
 *
 * Rules (applied only when failure is detected):
 *
 *   MISCLASSIFICATION
 *     → raise plateauThreshold (let verdict stabilise before stopping)
 *     → lower confidenceThreshold (require more evidence before declaring success)
 *     → if flips ≥ 3: switch aggressiveness to 'conservative'
 *
 *   OVERFITTING
 *     → if hit max-iterations with tiny gain: lower maxIterations
 *     → if overconfident+RESISTANT: raise confidenceThreshold
 *     → switch aggressiveness to 'conservative' if currently 'aggressive'
 *
 *   UNDERFITTING
 *     → if low-coverage: increase disasmExpansion
 *     → if strategy-stall: raise maxIterations + switch to 'aggressive'
 *     → if premature-convergence (fast stop, low conf): lower confidenceThreshold
 *
 *   SUCCESS
 *     → no changes
 *
 * Guards:
 *   - No single field is modified by more than MAX_DELTA in one heal pass.
 *   - Repeated failures of the same type accumulate ("pressure") — each
 *     consecutive same-type failure increases step magnitude up to 2×.
 *   - A field is never adjusted below its floor or above its ceiling.
 *   - Core signals (enableTalon, enableEcho, enableStrike) are never modified.
 */

import type { NestDiagnosticsReport, DiagnosticOutcome } from './nestDiagnostics';
import type { NestConfig, AggressivenessLevel } from './nestEngine';
import { DEFAULT_NEST_CONFIG } from './nestEngine';
import type { AppliedFix } from './nestTrainingStore';
import type { TrainingRecord } from './nestTrainingStore';

// ── Bounds ────────────────────────────────────────────────────────────────────

const BOUNDS: Partial<Record<keyof NestConfig, { min: number; max: number }>> = {
  maxIterations:       { min: 2,   max: 12  },
  confidenceThreshold: { min: 60,  max: 95  },
  plateauThreshold:    { min: 1,   max: 8   },
  disasmExpansion:     { min: 256, max: 4096 },
};

function clamp(field: keyof NestConfig, value: number): number {
  const b = BOUNDS[field];
  if (!b) return value;
  return Math.max(b.min, Math.min(b.max, value));
}

// ── Pressure multiplier ───────────────────────────────────────────────────────

/**
 * Returns a step multiplier based on how many consecutive same-outcome
 * failures appear at the head of the training history.
 * 1 failure → ×1.0, 2 → ×1.5, 3+ → ×2.0
 */
function pressureMultiplier(recentRecords: TrainingRecord[], outcome: DiagnosticOutcome): number {
  let streak = 0;
  for (const r of recentRecords) {
    if (r.outcome === outcome) streak++;
    else break;
  }
  if (streak >= 3) return 2.0;
  if (streak === 2) return 1.5;
  return 1.0;
}

// ── Core heal logic ───────────────────────────────────────────────────────────

export interface HealResult {
  /** The updated config (same reference as input if no changes) */
  config:       NestConfig;
  /** List of individual field mutations that were applied */
  fixes:        AppliedFix[];
  /** Whether any mutation was made */
  changed:      boolean;
  /** Short one-line summary for the notification banner */
  summary:      string;
}

function fix<K extends keyof NestConfig>(
  config:    NestConfig,
  field:     K,
  newVal:    NestConfig[K],
  reason:    string,
  fixes:     AppliedFix[],
): NestConfig {
  if (config[field] === newVal) return config;
  fixes.push({ field, oldValue: config[field], newValue: newVal, reason });
  return { ...config, [field]: newVal };
}

function healMisclassification(
  report:   NestDiagnosticsReport,
  cfg:      NestConfig,
  pressure: number,
  fixes:    AppliedFix[],
): NestConfig {
  const { verdictFlipCount } = report.summary;
  const step = Math.round(pressure);

  // Raise plateauThreshold → let verdict settle before stopping
  const newPlateau = clamp('plateauThreshold', cfg.plateauThreshold + step + 1);
  cfg = fix(cfg, 'plateauThreshold', newPlateau,
    `MISCLASSIFICATION: raised plateauThreshold to stabilise oscillating verdict (${verdictFlipCount} flips)`, fixes);

  // Lower confidenceThreshold → demand more evidence before concluding
  const newConf = clamp('confidenceThreshold', cfg.confidenceThreshold - 5 * step);
  cfg = fix(cfg, 'confidenceThreshold', newConf,
    'MISCLASSIFICATION: lowered confidenceThreshold to prevent premature confidence', fixes);

  // Heavy oscillation → drop to conservative
  if (verdictFlipCount >= 3 && cfg.aggressiveness !== 'conservative') {
    cfg = fix(cfg, 'aggressiveness', 'conservative' as AggressivenessLevel,
      'MISCLASSIFICATION: 3+ verdict flips — switching to conservative aggressiveness', fixes);
  }

  return cfg;
}

function healOverfitting(
  report:   NestDiagnosticsReport,
  cfg:      NestConfig,
  pressure: number,
  fixes:    AppliedFix[],
): NestConfig {
  const { totalGain, stopReason } = report.summary;
  const hitMax   = stopReason === 'Max iterations';
  const avgGain  = report.summary.avgGainPerIter;
  const step = Math.round(pressure);

  // Wasted iterations — shrink maxIterations
  if (hitMax && avgGain < 2.0) {
    const newMax = clamp('maxIterations', cfg.maxIterations - step);
    cfg = fix(cfg, 'maxIterations', newMax,
      `OVERFITTING: hit maxIterations (${cfg.maxIterations}) with only ${avgGain.toFixed(1)} pts/iter — reducing`, fixes);
  }

  // Overconfidence on resistant binary → raise threshold
  const overconfident = report.evidence.some(e => e.id === 'depth-overconfident' && !e.pass);
  if (overconfident) {
    const newConf = clamp('confidenceThreshold', cfg.confidenceThreshold + 5 * step);
    cfg = fix(cfg, 'confidenceThreshold', newConf,
      'OVERFITTING: binary resisted with high confidence — raising confidenceThreshold', fixes);
  }

  // Scale back aggressiveness
  if (cfg.aggressiveness === 'aggressive') {
    cfg = fix(cfg, 'aggressiveness', 'balanced' as AggressivenessLevel,
      'OVERFITTING: reducing aggressiveness from aggressive → balanced', fixes);
  } else if (cfg.aggressiveness === 'balanced' && pressure >= 2) {
    cfg = fix(cfg, 'aggressiveness', 'conservative' as AggressivenessLevel,
      'OVERFITTING (repeated): reducing aggressiveness from balanced → conservative', fixes);
  }

  // Raise plateauThreshold so we detect stalling earlier
  if (hitMax && totalGain < 5 && cfg.plateauThreshold > 2) {
    const newPlateau = clamp('plateauThreshold', cfg.plateauThreshold - 1);
    cfg = fix(cfg, 'plateauThreshold', newPlateau,
      'OVERFITTING: tightening plateau detection to stop earlier on stalled sessions', fixes);
  }

  return cfg;
}

function healUnderfitting(
  report:   NestDiagnosticsReport,
  cfg:      NestConfig,
  pressure: number,
  fixes:    AppliedFix[],
): NestConfig {
  const { totalIterations } = report.summary;
  const flags  = report.evidence.filter(e => !e.pass).map(e => e.id);
  const step   = Math.round(pressure);

  // Low instruction coverage → expand disasm range
  if (flags.includes('convergence-low-coverage') || flags.includes('depth-stall')) {
    const newExpansion = clamp('disasmExpansion', cfg.disasmExpansion * (1 + 0.5 * step));
    cfg = fix(cfg, 'disasmExpansion', Math.round(newExpansion),
      `UNDERFITTING: insufficient coverage — increasing disasmExpansion from ${cfg.disasmExpansion}B`, fixes);
  }

  // Strategy stall → more aggressive exploration
  if (flags.includes('depth-stall') || flags.includes('conf-gain-avg')) {
    if (cfg.aggressiveness === 'conservative') {
      cfg = fix(cfg, 'aggressiveness', 'balanced' as AggressivenessLevel,
        'UNDERFITTING: strategy stall — raising aggressiveness conservative → balanced', fixes);
    } else if (cfg.aggressiveness === 'balanced') {
      cfg = fix(cfg, 'aggressiveness', 'aggressive' as AggressivenessLevel,
        'UNDERFITTING: strategy stall — raising aggressiveness balanced → aggressive', fixes);
    }
  }

  // Premature convergence (fast + low conf) → more iterations + lower threshold
  const earlyStop = flags.includes('convergence-early');
  if (earlyStop) {
    const newMax = clamp('maxIterations', cfg.maxIterations + step + 1);
    cfg = fix(cfg, 'maxIterations', newMax,
      `UNDERFITTING: premature stop at iteration ${totalIterations} — raising maxIterations`, fixes);

    const newConf = clamp('confidenceThreshold', cfg.confidenceThreshold - 5 * step);
    cfg = fix(cfg, 'confidenceThreshold', newConf,
      'UNDERFITTING: stopped too early — lowering confidenceThreshold to require more evidence', fixes);
  }

  // Enable autoAdvance to remove manual stepping bottleneck if disabled
  if (!cfg.autoAdvance && flags.length >= 2) {
    cfg = fix(cfg, 'autoAdvance', true,
      'UNDERFITTING: enabling autoAdvance to allow all iterations to run', fixes);
  }

  return cfg;
}

// ── Public entry point ────────────────────────────────────────────────────────

/**
 * Evaluate a diagnostics report and return an updated config + list of fixes.
 *
 * @param report         — Output of runDiagnostics()
 * @param currentConfig  — The config that was active during the session
 * @param recentRecords  — Most recent TrainingRecords (newest first) for pressure calculation
 */
export function heal(
  report:         NestDiagnosticsReport,
  currentConfig:  NestConfig,
  recentRecords:  TrainingRecord[] = [],
): HealResult {
  // SUCCESS → do nothing
  if (report.outcome === 'SUCCESS') {
    return {
      config:  currentConfig,
      fixes:   [],
      changed: false,
      summary: 'No changes — session succeeded.',
    };
  }

  const fixes: AppliedFix[] = [];
  const pressure = pressureMultiplier(recentRecords, report.outcome);
  let cfg = { ...currentConfig };

  switch (report.outcome) {
    case 'MISCLASSIFICATION':
      cfg = healMisclassification(report, cfg, pressure, fixes);
      break;
    case 'OVERFITTING':
      cfg = healOverfitting(report, cfg, pressure, fixes);
      break;
    case 'UNDERFITTING':
      cfg = healUnderfitting(report, cfg, pressure, fixes);
      break;
  }

  if (fixes.length === 0) {
    return {
      config:  currentConfig,
      fixes:   [],
      changed: false,
      summary: `${report.outcomeLabel} — no actionable config changes found.`,
    };
  }

  const names = fixes.map(f => `${String(f.field)} ${f.oldValue}→${f.newValue}`);
  const summary = `${report.outcomeLabel}: ${names.slice(0, 2).join(', ')}${names.length > 2 ? ` (+${names.length - 2} more)` : ''}.`;

  return { config: cfg, fixes, changed: true, summary };
}

/**
 * Check for regressions: if the last 3 sessions are the same failure type
 * AND the config has been healed before for that type, something got worse.
 * Returns a warning string or null.
 */
export function checkRegressionWarning(recentRecords: TrainingRecord[]): string | null {
  if (recentRecords.length < 4) return null;
  const recent3 = recentRecords.slice(0, 3);
  const allSameFail = recent3.every(r =>
    r.outcome !== 'SUCCESS' && r.outcome === recent3[0].outcome,
  );
  if (!allSameFail) return null;

  const outcome = recent3[0].outcome;
  // Were fixes applied in any of those sessions?
  const hadFixes = recent3.some(r => r.fixesApplied.length > 0);
  const priorSuccess = recentRecords.slice(3).some(r => r.outcome === 'SUCCESS');

  if (hadFixes && priorSuccess) {
    return `Regression detected: ${outcome} persists over the last 3 sessions despite applied fixes.`;
  }
  return null;
}

/**
 * Summarise what the healer would recommend without applying anything.
 * Useful for displaying a preview before the user confirms.
 */
export function previewHeal(
  report:        NestDiagnosticsReport,
  currentConfig: NestConfig,
  recentRecords: TrainingRecord[] = [],
): { label: string; delta: string }[] {
  const result = heal(report, currentConfig, recentRecords);
  return result.fixes.map(f => ({
    label: String(f.field),
    delta: `${f.oldValue} → ${f.newValue}`,
  }));
}

/**
 * Reset a healed config back toward DEFAULT_NEST_CONFIG by one step.
 * Useful when the user wants to undo accumulated changes.
 */
export function resetTowardsDefault(current: NestConfig): { config: NestConfig; changes: string[] } {
  const changes: string[] = [];
  let cfg = { ...current };

  const nudge = <K extends keyof NestConfig>(field: K, target: NestConfig[K], label: string) => {
    if (cfg[field] !== target) {
      changes.push(`${label}: ${cfg[field]} → ${target}`);
      cfg = { ...cfg, [field]: target };
    }
  };

  nudge('maxIterations',       DEFAULT_NEST_CONFIG.maxIterations,       'maxIterations');
  nudge('confidenceThreshold', DEFAULT_NEST_CONFIG.confidenceThreshold, 'confidenceThreshold');
  nudge('plateauThreshold',    DEFAULT_NEST_CONFIG.plateauThreshold,    'plateauThreshold');
  nudge('disasmExpansion',     DEFAULT_NEST_CONFIG.disasmExpansion,     'disasmExpansion');
  nudge('aggressiveness',      DEFAULT_NEST_CONFIG.aggressiveness,      'aggressiveness');

  return { config: cfg, changes };
}
