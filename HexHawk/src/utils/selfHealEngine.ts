/**
 * selfHealEngine — Automatic Analysis Gap Detection and Remediation
 *
 * Inspects the current pipeline state and verdict to detect conditions where
 * the analysis is unreliable or incomplete, then produces an ordered list of
 * prescriptions the analyst (or the UI) can act on to restore confidence.
 *
 * Design goals:
 *  - Pure TypeScript: no Tauri calls, no UI, fully testable
 *  - Reactive: called after each analysis step completes, not on a timer
 *  - Actionable: every diagnosis maps to a concrete UI action or LLM query
 */

import type { BinaryVerdictResult } from './correlationEngine';

// ─── Types ────────────────────────────────────────────────────────────────────

/**
 * A single recommended remediation step ordered by expected confidence gain.
 */
export interface HealPrescription {
  /** Machine-readable action identifier wired to a UI callback */
  action:
    | 'scan_strings'
    | 'disassemble'
    | 'build_cfg'
    | 'inspect'
    | 'run_nest'
    | 'run_strike'
    | 'ask_llm';
  /** Short label for the action button */
  label: string;
  /** Human-readable explanation of why this prescription was issued */
  reason: string;
  /** Estimated confidence gain (0–100) if this action is taken */
  estimatedGain: number;
}

export type HealSeverity = 'info' | 'warning' | 'critical';

/**
 * Full diagnosis produced by selfHealEngine. When `needed` is false, the
 * pipeline is healthy and no banner should be shown.
 */
export interface HealDiagnosis {
  needed: boolean;
  severity: HealSeverity;
  /** Short summary sentence shown in the banner headline */
  summary: string;
  /** All detected conditions that contributed to this diagnosis */
  conditions: string[];
  /** Ordered prescriptions, highest estimated gain first */
  prescriptions: HealPrescription[];
  /** Current verdict confidence, or null if no verdict exists */
  currentConfidence: number | null;
  /**
   * Whether an LLM narrative pass is recommended.
   * True when contradictions are high or conditions are complex.
   */
  suggestLlm: boolean;
}

// ─── Pipeline state snapshot passed by the caller ─────────────────────────────

export interface PipelineState {
  /** True if binary metadata has been loaded via Inspect */
  hasMetadata: boolean;
  /** Number of disassembled instructions (0 = not run) */
  disassemblyCount: number;
  /** Number of recovered strings (0 = not run) */
  stringCount: number;
  /** True if a CFG has been built and has nodes */
  hasCfg: boolean;
  /** True if a STRIKE dynamic session is attached */
  hasStrike: boolean;
  /** True if NEST has been run at least once for this binary */
  hasNest: boolean;
  /** Current GYRE verdict, or null if analysis hasn't produced one yet */
  verdict: BinaryVerdictResult | null;
}

// ─── Thresholds ───────────────────────────────────────────────────────────────

const CONFIDENCE_CRITICAL = 30;
const CONFIDENCE_WARNING   = 55;
const CONTRADICTION_WARN   = 3;
const MIN_SIGNALS_WARN     = 3;

// ─── Core diagnosis function ──────────────────────────────────────────────────

export function diagnose(state: PipelineState): HealDiagnosis {
  const { verdict, hasMetadata, disassemblyCount, stringCount, hasCfg, hasStrike, hasNest } = state;
  const conditions: string[] = [];
  const prescriptions: HealPrescription[] = [];

  // No binary loaded yet — nothing to heal.
  if (!hasMetadata) {
    return {
      needed: false,
      severity: 'info',
      summary: 'No binary loaded.',
      conditions: [],
      prescriptions: [],
      currentConfidence: null,
      suggestLlm: false,
    };
  }

  const conf = verdict?.confidence ?? null;
  const classification = verdict?.classification ?? null;
  const signalCount = verdict?.signals?.length ?? 0;
  const contradictionCount = verdict?.contradictions?.length ?? 0;

  // ── Detect conditions ─────────────────────────────────────────────────────

  if (!verdict) {
    conditions.push('No verdict has been produced — run analysis first');
  }

  if (stringCount === 0) {
    conditions.push('String scan has not been run — IOC and behavioral signals are unavailable');
    prescriptions.push({
      action: 'scan_strings',
      label: 'Scan Strings',
      reason: 'String data is required for IOC extraction, URL detection, and behavioral tags. Without it, up to 40% of signals are missing.',
      estimatedGain: 20,
    });
  }

  if (disassemblyCount === 0) {
    conditions.push('Disassembly has not been run — code-level signals and annotations are unavailable');
    prescriptions.push({
      action: 'disassemble',
      label: 'Disassemble',
      reason: 'Disassembly is required for TALON annotations, crypto detection, API behavior signals, and anti-analysis indicators.',
      estimatedGain: 25,
    });
  }

  if (!hasCfg && disassemblyCount > 0) {
    conditions.push('No CFG — code structure signals and loop/branch patterns are unavailable');
    prescriptions.push({
      action: 'build_cfg',
      label: 'Build CFG',
      reason: 'Control flow graph analysis reveals packing patterns, obfuscation loops, and function structure.',
      estimatedGain: 10,
    });
  }

  if (verdict && classification === 'unknown') {
    conditions.push('Classification is unknown — the evidence is insufficient to classify the binary');
  }

  if (conf !== null && conf < CONFIDENCE_CRITICAL) {
    conditions.push(`Confidence is critically low (${conf}%) — verdict is unreliable`);
  } else if (conf !== null && conf < CONFIDENCE_WARNING) {
    conditions.push(`Confidence is below threshold (${conf}%) — more evidence is needed`);
  }

  if (verdict && signalCount < MIN_SIGNALS_WARN && hasMetadata) {
    conditions.push(`Only ${signalCount} signal${signalCount === 1 ? '' : 's'} — too few for a reliable verdict`);
  }

  if (contradictionCount >= CONTRADICTION_WARN) {
    conditions.push(`${contradictionCount} unresolved contradictions are reducing verdict reliability`);
  }

  // ── Generate prescriptions for confidence-based conditions ────────────────

  if ((conf !== null && conf < CONFIDENCE_WARNING) || classification === 'unknown') {
    if (!hasNest) {
      prescriptions.push({
        action: 'run_nest',
        label: 'Run NEST',
        reason: 'NEST iterative convergence runs up to 5 analysis passes, expanding coverage to resolve ambiguous or low-confidence verdicts.',
        estimatedGain: 30,
      });
    } else if (conf !== null && conf < CONFIDENCE_CRITICAL) {
      prescriptions.push({
        action: 'run_nest',
        label: 'Re-run NEST',
        reason: 'Confidence is still critically low after NEST. Re-running with expanded disassembly range may break the plateau.',
        estimatedGain: 15,
      });
    }
  }

  if (!hasStrike && verdict && conf !== null && conf < CONFIDENCE_WARNING) {
    prescriptions.push({
      action: 'run_strike',
      label: 'Add STRIKE Session',
      reason: 'Dynamic execution data resolves ambiguity that static analysis alone cannot — especially for packed or self-modifying binaries.',
      estimatedGain: 20,
    });
  }

  if (contradictionCount >= CONTRADICTION_WARN || (conf !== null && conf < CONFIDENCE_CRITICAL && prescriptions.length > 2)) {
    prescriptions.push({
      action: 'ask_llm',
      label: 'Ask AI to Diagnose',
      reason: 'The AI analyst can review all signals and contradictions and explain why confidence is low and what evidence is missing.',
      estimatedGain: 0, // indirect — improves analyst understanding
    });
  }

  // ── Sort by estimated gain, highest first ─────────────────────────────────
  prescriptions.sort((a, b) => b.estimatedGain - a.estimatedGain);

  // ── No conditions → no healing needed ────────────────────────────────────
  if (conditions.length === 0) {
    return {
      needed: false,
      severity: 'info',
      summary: 'Analysis is healthy.',
      conditions: [],
      prescriptions: [],
      currentConfidence: conf,
      suggestLlm: false,
    };
  }

  // ── Compute severity ──────────────────────────────────────────────────────
  let severity: HealSeverity = 'info';
  if (
    (conf !== null && conf < CONFIDENCE_CRITICAL) ||
    classification === 'unknown' ||
    !verdict
  ) {
    severity = 'critical';
  } else if (
    (conf !== null && conf < CONFIDENCE_WARNING) ||
    contradictionCount >= CONTRADICTION_WARN ||
    signalCount < MIN_SIGNALS_WARN
  ) {
    severity = 'warning';
  }

  // ── Build summary ─────────────────────────────────────────────────────────
  let summary: string;
  if (!verdict) {
    summary = 'No verdict yet — run the analysis pipeline to generate results.';
  } else if (conf !== null && conf < CONFIDENCE_CRITICAL) {
    summary = `Verdict confidence is critically low (${conf}%) — key analysis passes are missing or signals are contradictory.`;
  } else if (conf !== null && conf < CONFIDENCE_WARNING) {
    summary = `Verdict confidence is below threshold (${conf}%) — additional analysis passes will improve reliability.`;
  } else if (classification === 'unknown') {
    summary = 'Binary is unclassified — more signal coverage is needed to produce a reliable verdict.';
  } else {
    summary = `${conditions.length} analysis gap${conditions.length > 1 ? 's' : ''} detected — consider running the suggested passes.`;
  }

  const suggestLlm = contradictionCount >= CONTRADICTION_WARN || (conf !== null && conf < CONFIDENCE_CRITICAL);

  return {
    needed: true,
    severity,
    summary,
    conditions,
    prescriptions,
    currentConfidence: conf,
    suggestLlm,
  };
}

/**
 * Returns true if the current diagnosis represents a meaningful improvement
 * over the previous one (used to suppress redundant banner re-renders).
 */
export function diagnosisChanged(prev: HealDiagnosis, next: HealDiagnosis): boolean {
  if (prev.needed !== next.needed) return true;
  if (prev.severity !== next.severity) return true;
  if (prev.prescriptions.length !== next.prescriptions.length) return true;
  if (prev.currentConfidence !== next.currentConfidence) return true;
  return false;
}
