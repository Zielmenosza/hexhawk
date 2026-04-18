/**
 * nestEngine — NEST Self-Improving Analysis Loop
 *
 * Runs repeated analysis cycles on a binary, improving results each iteration:
 *   1. Run full pipeline (ECHO signals, TALON signals, signature matches)
 *   2. Compute verdict via correlationEngine
 *   3. Evaluate uncertainty — stop if confident enough or plateaued
 *   4. Generate refinement plan (expand disasm range, focus suspicious regions)
 *   5. Re-run targeted analysis with expanded coverage
 *   6. Compare with previous iteration — what changed, what improved
 *   7. Store iteration snapshot
 *
 * nestEngine is a pure TypeScript module with no UI or Tauri dependencies.
 * NestView.tsx orchestrates the Tauri calls and drives this engine.
 */

import type { BinaryVerdictResult, BehavioralTag, CorrelationInput } from './correlationEngine';
import { computeVerdict } from './correlationEngine';
import type { SignatureMatch } from './signatureEngine';
import type { TalonCorrelationSignal } from './talonEngine';
import type { StrikeCorrelationSignal } from './strikeEngine';
import type { EchoCorrelationSignal } from './echoEngine';
import type { SuspiciousPattern } from '../App';
import type { CfgAnalysisSummary } from './cfgSignalExtractor';

// ── Configuration ─────────────────────────────────────────────────────────────

/**
 * How aggressively NEST expands coverage and triggers expensive operations.
 *   conservative — minimal expansion, no expensive ops, faster but shallower
 *   balanced      — default: moderate expansion, TALON/ECHO enabled
 *   aggressive    — maximum expansion, STRIKE encouraged, all ops enabled
 */
export type AggressivenessLevel = 'conservative' | 'balanced' | 'aggressive';

export interface NestConfig {
  /** Maximum number of analysis iterations before forced stop (default: 5) */
  maxIterations: number;
  /**
   * Minimum number of iterations that must complete before any convergence
   * criterion (confidence-threshold, stable-clean, stable-threat, low-loss,
   * plateau) is evaluated. Prevents false convergence when the first-pass
   * confidence is high due to signal diversity rather than validated evidence.
   * Default: 3
   */
  minIterations: number;
  /** Stop when verdict confidence reaches this level (default: 85) */
  confidenceThreshold: number;
  /** Stop if confidence delta < this value for 3 consecutive iterations (default: 2) */
  plateauThreshold: number;
  /** Bytes to add to disassembly range per refinement action (default: 512) */
  disasmExpansion: number;
  /** How aggressively to expand coverage and trigger expensive operations */
  aggressiveness: AggressivenessLevel;
  /** Run TALON decompilation pass on each iteration (default: true) */
  enableTalon: boolean;
  /** Include STRIKE runtime signals if a session is active (default: false) */
  enableStrike: boolean;
  /** Run ECHO fuzzy scan on each iteration (default: true) */
  enableEcho: boolean;
  /** Automatically advance to next iteration without user input (default: false) */
  autoAdvance: boolean;
  /** Milliseconds to wait between auto-advance iterations (default: 600) */
  autoAdvanceDelay: number;
}

export const DEFAULT_NEST_CONFIG: NestConfig = {
  maxIterations:       5,
  minIterations:       3,
  confidenceThreshold: 85,
  plateauThreshold:    2,
  disasmExpansion:     512,
  aggressiveness:      'balanced',
  enableTalon:         true,
  enableStrike:        false,
  enableEcho:          true,
  autoAdvance:         false,
  autoAdvanceDelay:    600,
};

// ── Refinement action types ───────────────────────────────────────────────────

export type RefinementActionType =
  | 'expand-disasm-forward'   // disassemble more bytes beyond current range
  | 'expand-disasm-backward'  // disassemble bytes before current range
  | 'focus-high-entropy'      // re-analyse a high-entropy section
  | 'follow-cfg-path'         // disassemble along unexplored CFG edge
  | 'deep-echo'               // re-run ECHO with lower similarity threshold
  | 'talon-focus'             // run TALON on a specific function
  | 'string-context'          // disassemble code near a suspicious string offset
  | 'import-context';         // inspect code near a dangerous import's PLT entry

export interface NestRefinementAction {
  type:     RefinementActionType;
  priority: 'high' | 'medium' | 'low';
  /** Target binary offset, if known */
  offset?:  number;
  /** Byte length to analyse at `offset` */
  length?:  number;
  reason:   string;
  /** The signal id or finding that triggered this action */
  signal?:  string;
}

export interface NestRefinementPlan {
  actions:       NestRefinementAction[];
  rationale:     string;
  /** Estimated confidence-point improvement (0–20) */
  expectedBoost: number;
  primaryAction: NestRefinementAction | null;
}

// ── Uncertainty / Convergence assessment ──────────────────────────────────────

export type StopReason =
  | 'confidence-threshold'
  | 'plateau'
  | 'max-iterations'
  | 'no-data'
  | 'continue';

export interface NestUncertaintyAssessment {
  shouldStop:      boolean;
  reason:          StopReason;
  confidence:      number;
  plateauDetected: boolean;
  message:         string;
}

/**
 * Extended reason codes produced by the Convergence Engine.
 *   stable-clean  — binary confirmed clean; verdict stable, no high contradictions
 *   stable-threat — threat classification stable across 2+ iterations
 *   low-loss      — projected information gain from another iteration is negligible
 */
export type ConvergenceReason =
  | 'confidence-threshold'
  | 'stable-clean'
  | 'stable-threat'
  | 'low-loss'
  | 'plateau'
  | 'max-iterations'
  | 'no-data'
  | 'continue';

/**
 * Rich convergence assessment from the NEST Convergence Engine.
 * Carries all metrics the UI needs to explain why iteration stopped.
 */
export interface ConvergenceAssessment {
  /** Whether NEST should stop and finalise the session */
  hasConverged: boolean;
  /** Primary reason convergence was or was not declared */
  reason: ConvergenceReason;
  /** Current verdict confidence (0–100) */
  confidence: number;
  /**
   * Estimated information gain from one more iteration (0–100).
   * Computed from signal velocity, last refinement plan's expectedBoost,
   * and confidence delta trend.  Low value (< ~15) signals diminishing returns.
   */
  projectedLoss: number;
  /** True when last 2 iterations share the same classification */
  classificationStable: boolean;
  /** Population standard deviation of confidence over the last ≤3 iterations */
  confidenceVariance: number;
  /** Number of unresolved HIGH or MEDIUM contradictions */
  contradictionBurden: number;
  /** Net new/removed signals vs the previous iteration */
  signalDelta: number;
  /** Human-readable explanation of the convergence decision */
  message: string;
}


// ── Iteration delta ───────────────────────────────────────────────────────────

export interface NestDelta {
  confidenceDelta:      number;
  newSignals:           string[];
  removedSignals:       string[];
  verdictChanged:       boolean;
  behaviorsAdded:       BehavioralTag[];
  behaviorsRemoved:     BehavioralTag[];
  corroborationsAdded:  number;
  /** true when confidence changed >3 pts, verdict changed, or new behaviors appeared */
  significantChange:    boolean;
  summary:              string;
}

// ── Iteration snapshot ────────────────────────────────────────────────────────

export interface NestIterationInput {
  disasmOffset:     number;
  disasmLength:     number;
  instructionCount: number;
  sections:         Array<{ name: string; entropy: number; file_size: number }>;
  imports:          Array<{ name: string; library: string }>;
  strings:          Array<{ text: string }>;
  patterns:         SuspiciousPattern[];
  signatureMatches: SignatureMatch[];
  talonSignals?:    TalonCorrelationSignal;
  strikeSignals?:   StrikeCorrelationSignal;
  echoSignals?:     EchoCorrelationSignal;
  /** CFG-derived suspicious patterns (indirect calls, loops, jump tables, unreachable blocks) */
  cfgPatterns?:     SuspiciousPattern[];
  /** Summary statistics from CFG analysis */
  cfgSummary?:      CfgAnalysisSummary;
  /**
   * Zero-based index of the current iteration within the NEST session.
   * Used by correlationEngine to apply confidence dampening on early iterations
   * (high signal diversity on first pass should not produce 90%+ confidence
   * before evidence has been validated across multiple analysis cycles).
   */
  iterationIndex?:  number;
}

export interface NestIterationSnapshot {
  iteration:      number;
  timestamp:      number;
  input:          NestIterationInput;
  verdict:        BinaryVerdictResult;
  confidence:     number;
  refinementPlan: NestRefinementPlan | null;
  /** null for the first iteration */
  delta:          NestDelta | null;
  annotations:    string[];
  durationMs:     number;
}

// ── Session ───────────────────────────────────────────────────────────────────

export type NestSessionStatus =
  | 'idle'
  | 'running'
  | 'paused'
  | 'converged'
  | 'max-reached'
  | 'plateau'
  | 'error';

export interface NestSession {
  id:           string;
  binaryPath:   string;
  config:       NestConfig;
  iterations:   NestIterationSnapshot[];
  status:       NestSessionStatus;
  finalVerdict: BinaryVerdictResult | null;
  startTime:    number;
  endTime:      number | null;
  /** Index of the iteration that triggered convergence, if any */
  convergedAt:  number | null;
  errorMessage: string | null;
}

// ── Session lifecycle ─────────────────────────────────────────────────────────

export function createNestSession(
  binaryPath: string,
  config: Partial<NestConfig> = {},
): NestSession {
  return {
    id:           `nest-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    binaryPath,
    config:       { ...DEFAULT_NEST_CONFIG, ...config },
    iterations:   [],
    status:       'idle',
    finalVerdict: null,
    startTime:    Date.now(),
    endTime:      null,
    convergedAt:  null,
    errorMessage: null,
  };
}

export function finalizeSession(
  session: NestSession,
  status:  NestSessionStatus,
  error?:  string,
): NestSession {
  const last = session.iterations[session.iterations.length - 1] ?? null;
  const isConvergence = status === 'converged' || status === 'plateau';
  return {
    ...session,
    status,
    finalVerdict: last?.verdict ?? null,
    endTime:      Date.now(),
    convergedAt:  isConvergence ? session.iterations.length - 1 : null,
    errorMessage: error ?? null,
  };
}

// ── Core correlation pass ─────────────────────────────────────────────────────

export function runCorrelationPass(input: NestIterationInput): BinaryVerdictResult {
  const ci: CorrelationInput = {
    sections:         input.sections,
    imports:          input.imports,
    strings:          input.strings,
    // Merge disassembly patterns with CFG-derived patterns (dedup by address+type)
    patterns:         mergeCfgPatterns(input.patterns, input.cfgPatterns ?? []),
    signatureMatches: input.signatureMatches,
    talonSignals:     input.talonSignals,
    strikeSignals:    input.strikeSignals,
    echoSignals:      input.echoSignals,
    iterationIndex:   input.iterationIndex,
  };
  return computeVerdict(ci);
}

/** Merge disassembly patterns with CFG patterns, deduplicating by address+type */
function mergeCfgPatterns(
  disasm: SuspiciousPattern[],
  cfg:    SuspiciousPattern[],
): SuspiciousPattern[] {
  const seen = new Set<string>(disasm.map(p => `${p.address}:${p.type}`));
  const extras = cfg.filter(p => !seen.has(`${p.address}:${p.type}`));
  return [...disasm, ...extras];
}

// ── Convergence Engine ────────────────────────────────────────────────────────

/**
 * Assess whether the NEST session has converged.
 *
 * Convergence criteria (checked in priority order):
 *   A. max-iterations     — hard limit reached
 *   B. confidence-threshold — confidence ≥ config threshold
 *   C. stable-clean       — clean/suspicious verdict, conf ≥ 75%, no HIGH
 *                            contradictions, classification stable ≥ 2 iters
 *   D. stable-threat      — threat class stable ≥ 2 iters, conf ≥ 80%,
 *                            no new signals, ≤1 unresolved contradiction
 *   E. low-loss           — projected gain < 12 pts, conf ≥ 70%, ≥2 iters done
 *   F. plateau            — confidence delta < plateauThreshold for 3 iters
 */
export function assessConvergence(
  session: NestSession,
  verdict: BinaryVerdictResult,
): ConvergenceAssessment {
  const { iterations, config } = session;
  const conf  = verdict.confidence;
  const iters = iterations;

  // ── No-data guard ─────────────────────────────────────────────────────────
  if (verdict.signalCount === 0 && iters.length === 0) {
    return _ca(false, 'no-data', conf, 100, true, 0, 0, 0,
      'No signals collected — run Inspect, Strings, and Disassemble first');
  }

  // ── A: max iterations (always respected) ─────────────────────────────────
  if (iters.length >= config.maxIterations) {
    return _ca(true, 'max-iterations', conf, 0, true, 0, 0, 0,
      `Maximum iterations (${config.maxIterations}) reached`);
  }

  // ── Min-iterations guard ──────────────────────────────────────────────────
  // Criteria B-F are suppressed until config.minIterations completed iterations
  // have been recorded. This prevents false convergence where high first-pass
  // confidence reflects import-table signal DIVERSITY rather than validated
  // multi-pass evidence. Criterion A (hard cap) is the only early exit allowed.
  const minIter = config.minIterations ?? 0;
  if (iters.length < minIter) {
    return _ca(false, 'continue', conf, 100, false, 0, 0, 0,
      `Minimum iterations not yet reached — ${iters.length}/${minIter} completed`);
  }

  // ── B: confidence threshold ───────────────────────────────────────────────
  if (conf >= config.confidenceThreshold) {
    return _ca(true, 'confidence-threshold', conf, 0, true, 0, 0, 0,
      `Confidence ${conf}% ≥ threshold ${config.confidenceThreshold}%`);
  }

  // ── No prior iteration — first pass, always continue ─────────────────────
  // (Subsumed by the minIterations guard when minIterations ≥ 1; kept for
  //  the minIterations=0 edge case.)
  if (iters.length === 0) {
    return _ca(false, 'continue', conf, 100, true, 0, 0, 0,
      'First iteration — no convergence history yet');
  }

  // ── Shared metrics ────────────────────────────────────────────────────────

  const last = iters[iters.length - 1];
  const prev = iters.length >= 2 ? iters[iters.length - 2] : null;

  // Classification stability: current and last iteration agree
  const classificationStable =
    prev !== null
      ? prev.verdict.classification === verdict.classification &&
        last.verdict.classification === verdict.classification
      : last.verdict.classification === verdict.classification;

  // Confidence variance (σ) over up to the last 3 snapshots + current value
  const recentConfs = [...iters.slice(-3).map(i => i.confidence), conf];
  const mean = recentConfs.reduce((a, b) => a + b, 0) / recentConfs.length;
  const confidenceVariance = Math.sqrt(
    recentConfs.reduce((s, c) => s + (c - mean) ** 2, 0) / recentConfs.length,
  );

  // Unresolved HIGH or MEDIUM contradictions
  const allContradictions = verdict.contradictions ?? [];
  const contradictionBurden = allContradictions.filter(
    c => c.severity === 'high' || c.severity === 'medium',
  ).length;
  const highContradictions = allContradictions.filter(c => c.severity === 'high').length;

  // Signal delta: net change vs last snapshot
  const signalDelta = Math.abs(verdict.signals.length - last.verdict.signals.length);

  // Projected loss: estimated information gain from one more iteration (0–100).
  // Sources: last plan's boost estimate, recent confidence velocity, signal churn.
  const lastBoost  = last.refinementPlan?.expectedBoost ?? 0;
  const confDelta  = Math.abs(conf - last.confidence);
  const projectedLoss = Math.min(100, Math.round(
    lastBoost  * 0.5 +
    confDelta  * 3.0 +
    signalDelta * 4.0,
  ));

  // ── C: stable-clean ───────────────────────────────────────────────────────
  // Binary classified as clean/suspicious AND evidence is strong enough that
  // further analysis will not change the verdict.
  const isCleanish =
    verdict.classification === 'clean' ||
    verdict.classification === 'suspicious';

  if (isCleanish && conf >= 75 && highContradictions === 0 && classificationStable) {
    return _ca(true, 'stable-clean', conf, projectedLoss, classificationStable,
      confidenceVariance, contradictionBurden, signalDelta,
      `Clean/benign verdict stable at ${conf}% — no unresolved contradictions, converged`);
  }

  // ── D: stable-threat ─────────────────────────────────────────────────────
  const isThreat = !isCleanish && verdict.classification !== 'unknown';
  if (
    isThreat &&
    classificationStable &&
    conf >= 80 &&
    signalDelta === 0 &&
    contradictionBurden <= 1
  ) {
    return _ca(true, 'stable-threat', conf, projectedLoss, classificationStable,
      confidenceVariance, contradictionBurden, signalDelta,
      `Threat classification '${verdict.classification}' stable at ${conf}% — converged`);
  }

  // ── E: low-loss ───────────────────────────────────────────────────────────
  if (projectedLoss < 12 && conf >= 70 && highContradictions === 0 && iters.length >= 2) {
    return _ca(true, 'low-loss', conf, projectedLoss, classificationStable,
      confidenceVariance, contradictionBurden, signalDelta,
      `Projected gain (${projectedLoss} pts) negligible at ${conf}% — stopping early`);
  }

  // ── F: plateau ────────────────────────────────────────────────────────────
  if (iters.length >= 2) {
    const len = iters.length;
    const c2  = iters[len - 2].confidence;
    const c1  = iters[len - 1].confidence;
    if (
      Math.abs(c1 - c2) < config.plateauThreshold &&
      Math.abs(conf - c1) < config.plateauThreshold
    ) {
      return _ca(true, 'plateau', conf, projectedLoss, classificationStable,
        confidenceVariance, contradictionBurden, signalDelta,
        `Confidence plateau — delta < ${config.plateauThreshold}% for 3 consecutive iterations`);
    }
  }

  return _ca(false, 'continue', conf, projectedLoss, classificationStable,
    confidenceVariance, contradictionBurden, signalDelta,
    `Confidence ${conf}% — continuing (threshold: ${config.confidenceThreshold}%)`);
}

function _ca(
  hasConverged: boolean,
  reason: ConvergenceReason,
  confidence: number,
  projectedLoss: number,
  classificationStable: boolean,
  confidenceVariance: number,
  contradictionBurden: number,
  signalDelta: number,
  message: string,
): ConvergenceAssessment {
  return {
    hasConverged, reason, confidence, projectedLoss,
    classificationStable, confidenceVariance, contradictionBurden,
    signalDelta, message,
  };
}

/**
 * Evaluate uncertainty — backward-compatible wrapper around assessConvergence().
 * Call assessConvergence() directly when you need the full convergence metrics.
 */
export function evaluateUncertainty(
  session: NestSession,
  verdict: BinaryVerdictResult,
): NestUncertaintyAssessment {
  const ca = assessConvergence(session, verdict);

  // Map extended ConvergenceReason → legacy StopReason
  const stopReason: StopReason =
    ca.reason === 'stable-clean'  ? 'confidence-threshold' :
    ca.reason === 'stable-threat' ? 'confidence-threshold' :
    ca.reason === 'low-loss'      ? 'plateau'              :
    ca.reason as StopReason;

  return {
    shouldStop:      ca.hasConverged,
    reason:          stopReason,
    confidence:      ca.confidence,
    plateauDetected: ca.reason === 'plateau',
    message:         ca.message,
  };
}

// ── Refinement plan generation ────────────────────────────────────────────────

export function generateRefinementPlan(
  verdict:   BinaryVerdictResult,
  input:     NestIterationInput,
  iteration: number,
): NestRefinementPlan {
  const actions: NestRefinementAction[] = [];
  const currentEnd = input.disasmOffset + input.disasmLength;

  // ── Early return for confirmed-clean high-confidence verdicts ────────────
  // When the binary is already classified as clean/suspicious with high
  // confidence, aggressive expansion will not produce new evidence — it only
  // burns iterations and inflates instruction counts without changing the
  // verdict. Instead, generate a single low-priority consolidation action so
  // the UI has something to show but the session can terminate quickly.
  const isConfidentClean =
    (verdict.classification === 'clean' || verdict.classification === 'suspicious') &&
    verdict.confidence >= 80 &&
    (verdict.contradictions ?? []).filter(c => c.severity === 'high').length === 0;

  if (isConfidentClean) {
    const action: NestRefinementAction = {
      type:     'expand-disasm-forward',
      priority: 'low',
      offset:   currentEnd,
      length:   256,
      reason:   `Verdict is confidently ${verdict.classification} (${verdict.confidence}%) — extending coverage minimally to confirm no hidden threats beyond current range`,
    };
    return {
      actions:       [action],
      rationale:     `Iteration ${iteration + 1}: binary appears clean/benign at ${verdict.confidence}% confidence — light consolidation pass only`,
      expectedBoost: 2,
      primaryAction: action,
    };
  }

  // 1. Signals with no corroboration and meaningful weight → try to corroborate
  const weakSignals = verdict.signals
    .filter(s => s.corroboratedBy.length === 0 && s.weight >= 4)
    .slice(0, 2);
  for (const sig of weakSignals) {
    actions.push({
      type:     'deep-echo',
      priority: 'high',
      reason:   `Signal '${sig.id}' has no corroboration — ECHO deep scan may confirm it`,
      signal:   sig.id,
    });
  }

  // 2. Unresolved contradictions → expand disassembly to resolve
  const contras = (verdict.contradictions ?? []).slice(0, 2);
  for (const contra of contras) {
    actions.push({
      type:     'expand-disasm-forward',
      priority: 'high',
      offset:   currentEnd,
      length:   input.disasmLength,  // double current coverage
      reason:   `Contradiction '${contra.id}': "${contra.observation}" — more context may resolve it`,
      signal:   contra.id,
    });
  }

  // 3. High-entropy sections not obviously covered
  for (const section of input.sections) {
    if (section.entropy > 6.5 && section.name !== '.rsrc' && section.file_size > 128) {
      actions.push({
        type:     'focus-high-entropy',
        priority: section.entropy > 7.2 ? 'high' : 'medium',
        reason:   `Section '${section.name}' entropy ${section.entropy.toFixed(2)} — may contain packed/crypto code`,
        signal:   'high-entropy',
      });
    }
  }

  // 4. Low instruction coverage for current iteration
  const expectedCoverage = 30 + iteration * 25;
  if (input.instructionCount < expectedCoverage) {
    actions.push({
      type:     'expand-disasm-forward',
      priority: 'medium',
      offset:   currentEnd,
      length:   512 * (iteration + 1),
      reason:   `Only ${input.instructionCount} instructions analysed — expand to improve coverage`,
    });
  }

  // 5. Suspicious strings with known patterns → find surrounding code
  const suspStrings = input.strings.filter(s =>
    /https?:\/\/|cmd\.exe|powershell|regsvr|\\\\server|createprocess|wscript/i.test(s.text),
  );
  if (suspStrings.length > 0) {
    actions.push({
      type:     'string-context',
      priority: 'medium',
      reason:   `${suspStrings.length} suspicious string(s) found — disassemble code that references them`,
    });
  }

  // 6. Dangerous imports without disassembly coverage → find callers
  const dangerousImports = input.imports.filter(imp =>
    /VirtualAlloc|WriteProcessMemory|CreateRemoteThread|OpenProcess|WinExec|URLDownload|ShellExecute/i.test(imp.name),
  );
  if (dangerousImports.length > 0) {
    actions.push({
      type:     'import-context',
      priority: 'high',
      reason:   `${dangerousImports.length} dangerous import(s) (${dangerousImports[0].name}…) — locate callers in disassembly`,
    });
  }

  // 7. Low confidence + behavioural signals → TALON for clarity
  if (verdict.confidence < 70 && verdict.behaviors.length > 0) {
    actions.push({
      type:     'talon-focus',
      priority: 'medium',
      reason:   `Low confidence (${verdict.confidence}%) with ${verdict.behaviors.length} suspected behaviour(s) — TALON analysis may clarify`,
    });
  }

  // 8. If nothing else, just extend forward
  if (actions.length === 0) {
    actions.push({
      type:     'expand-disasm-forward',
      priority: 'low',
      offset:   currentEnd,
      length:   512,
      reason:   'No specific refinement target — extending disassembly range forward',
    });
  }

  // Sort by priority
  const pOrder = { high: 0, medium: 1, low: 2 };
  actions.sort((a, b) => pOrder[a.priority] - pOrder[b.priority]);

  const highCount  = actions.filter(a => a.priority === 'high').length;
  const medCount   = actions.filter(a => a.priority === 'medium').length;
  const expectedBoost = Math.min(20, highCount * 6 + medCount * 3);

  const rationale = `Iteration ${iteration + 1}: ${actions[0].reason}`;

  return {
    actions,
    rationale,
    expectedBoost,
    primaryAction: actions[0] ?? null,
  };
}

// ── Iteration delta ───────────────────────────────────────────────────────────

export function computeIterationDelta(
  prev:        NestIterationSnapshot,
  currVerdict: BinaryVerdictResult,
): NestDelta {
  const prevV        = prev.verdict;
  const prevIds      = new Set(prevV.signals.map(s => s.id));
  const currIds      = new Set(currVerdict.signals.map(s => s.id));

  const newSignals     = currVerdict.signals.filter(s => !prevIds.has(s.id)).map(s => s.id);
  const removedSignals = prevV.signals.filter(s => !currIds.has(s.id)).map(s => s.id);

  const prevBehaviors  = new Set(prevV.behaviors);
  const currBehaviors  = new Set(currVerdict.behaviors);
  const behaviorsAdded: BehavioralTag[]   = currVerdict.behaviors.filter(b => !prevBehaviors.has(b));
  const behaviorsRemoved: BehavioralTag[] = prevV.behaviors.filter(b => !currBehaviors.has(b));

  const corroborationsAdded = currVerdict.signals.reduce((acc, s) => {
    const ps = prevV.signals.find(p => p.id === s.id);
    if (!ps) return acc;
    return acc + Math.max(0, s.corroboratedBy.length - ps.corroboratedBy.length);
  }, 0);

  const confidenceDelta = currVerdict.confidence - prev.confidence;
  const verdictChanged  = currVerdict.classification !== prevV.classification;
  const significantChange =
    Math.abs(confidenceDelta) > 3 || verdictChanged || behaviorsAdded.length > 0;

  const parts: string[] = [];
  if (confidenceDelta > 0)         parts.push(`+${confidenceDelta.toFixed(0)}% confidence`);
  else if (confidenceDelta < 0)    parts.push(`${confidenceDelta.toFixed(0)}% confidence`);
  if (newSignals.length > 0)       parts.push(`${newSignals.length} new signal(s)`);
  if (behaviorsAdded.length > 0)   parts.push(`detected: ${behaviorsAdded.join(', ')}`);
  if (verdictChanged)              parts.push(`verdict \u2192 ${currVerdict.classification}`);
  if (corroborationsAdded > 0)     parts.push(`${corroborationsAdded} corroboration(s)`);
  const summary = parts.length > 0 ? parts.join(' · ') : 'No significant changes';

  return {
    confidenceDelta,
    newSignals,
    removedSignals,
    verdictChanged,
    behaviorsAdded,
    behaviorsRemoved,
    corroborationsAdded,
    significantChange,
    summary,
  };
}

// ── Iteration annotation ──────────────────────────────────────────────────────

export function annotateIteration(
  snapshot: Omit<NestIterationSnapshot, 'annotations'>,
  delta:    NestDelta | null,
): string[] {
  const notes: string[] = [];

  notes.push(`Verdict: ${snapshot.verdict.classification} (${snapshot.confidence}%)`);

  if (delta) {
    notes.push(delta.significantChange
      ? `Significant change: ${delta.summary}`
      : `Marginal: ${delta.summary}`);
  }

  const contradictions = snapshot.verdict.contradictions ?? [];
  if (contradictions.length > 0) {
    notes.push(`${contradictions.length} contradiction(s) unresolved`);
  }

  // CFG annotation
  const cfg = snapshot.input.cfgSummary;
  if (cfg && cfg.totalBlocks > 0) {
    const parts: string[] = [`CFG: ${cfg.totalBlocks} blocks`];
    if (cfg.backEdges > 0)         parts.push(`${cfg.backEdges} loop(s)`);
    if (cfg.indirectCalls > 0)     parts.push(`${cfg.indirectCalls} indirect call(s)`);
    if (cfg.unreachableBlocks > 0) parts.push(`${cfg.unreachableBlocks} unreachable`);
    if (cfg.jumpTables > 0)        parts.push(`${cfg.jumpTables} jump table(s)`);
    parts.push(`complexity ${cfg.complexityScore}/100`);
    notes.push(parts.join(' · '));
  }

  if (snapshot.refinementPlan?.actions.length) {
    const plan = snapshot.refinementPlan;
    notes.push(`Plan: ${plan.actions.length} action(s) · est. +${plan.expectedBoost}% boost`);
    if (plan.primaryAction) {
      notes.push(`Primary: ${plan.primaryAction.reason}`);
    }
  }

  return notes;
}

// ── Snapshot builder ──────────────────────────────────────────────────────────

export function buildIterationSnapshot(
  iterationIndex: number,
  input:          NestIterationInput,
  verdict:        BinaryVerdictResult,
  prev:           NestIterationSnapshot | null,
  refinementPlan: NestRefinementPlan | null,
  startTime:      number,
): NestIterationSnapshot {
  const delta = prev ? computeIterationDelta(prev, verdict) : null;
  const partial: Omit<NestIterationSnapshot, 'annotations'> = {
    iteration:      iterationIndex,
    timestamp:      Date.now(),
    input,
    verdict,
    confidence:     verdict.confidence,
    refinementPlan,
    delta,
    durationMs:     Date.now() - startTime,
  };
  return { ...partial, annotations: annotateIteration(partial, delta) };
}

// ── Disassembly range selection ───────────────────────────────────────────────

export interface DisasmRangeRequest {
  offset: number;
  length: number;
  reason: string;
}

export function selectNextDisasmRange(
  plan:    NestRefinementPlan,
  current: { offset: number; length: number },
  config:  NestConfig,
): DisasmRangeRequest {
  const primary = plan.primaryAction;
  const expansion = config.disasmExpansion;

  if (!primary) {
    return {
      offset: current.offset,
      length: current.length + expansion,
      reason: 'Default: extend forward',
    };
  }

  if (primary.type === 'expand-disasm-forward') {
    const off = primary.offset ?? (current.offset + current.length);
    return { offset: off, length: primary.length ?? expansion, reason: primary.reason };
  }

  if (primary.type === 'expand-disasm-backward') {
    const off = Math.max(0, current.offset - expansion);
    return { offset: off, length: current.length + expansion, reason: primary.reason };
  }

  if (primary.offset != null) {
    return { offset: primary.offset, length: expansion * 2, reason: primary.reason };
  }

  // Default: extend current range forward
  return {
    offset: current.offset,
    length: current.length + expansion,
    reason: primary.reason,
  };
}

// ── Session summary ───────────────────────────────────────────────────────────

export interface NestSummary {
  totalIterations:       number;
  finalConfidence:       number;
  finalVerdict:          string;
  totalDurationMs:       number;
  confidenceProgression: number[];
  convergedReason:       StopReason | null;
  keyFindings:           string[];
  improvementTotal:      number;
}

export function summarizeSession(session: NestSession): NestSummary {
  const iters = session.iterations;
  const last  = iters[iters.length - 1] ?? null;
  const first = iters[0] ?? null;

  const confidenceProgression = iters.map(i => i.confidence);
  const improvementTotal = last && first ? last.confidence - first.confidence : 0;

  const keyFindings: string[] = [];
  for (const iter of iters) {
    if (iter.delta?.significantChange) {
      keyFindings.push(`Iter ${iter.iteration + 1}: ${iter.delta.summary}`);
    }
  }

  const convergedReason: StopReason | null =
    session.status === 'converged'    ? 'confidence-threshold' :
    session.status === 'plateau'      ? 'plateau'              :
    session.status === 'max-reached'  ? 'max-iterations'       : null;

  return {
    totalIterations:       iters.length,
    finalConfidence:       last?.confidence ?? 0,
    finalVerdict:          last?.verdict.classification ?? 'unknown',
    totalDurationMs:       (session.endTime ?? Date.now()) - session.startTime,
    confidenceProgression,
    convergedReason,
    keyFindings,
    improvementTotal,
  };
}
