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

import type { BinaryVerdictResult, BehavioralTag, CorrelationInput, BinaryClassification, EvidenceTier, CorrelatedSignal, SignalSource } from './correlationEngine';
import { computeVerdict } from './correlationEngine';
import type { SignatureMatch } from './signatureEngine';
import type { TalonCorrelationSignal } from './talonEngine';
import type { StrikeCorrelationSignal } from './strikeEngine';
import type { EchoCorrelationSignal } from './echoEngine';
import type { YaraRuleMatch } from './yaraEngine';
import type { MythosCapabilityMatch } from './mythosEngine';
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
  confidenceThreshold: 80, // M8 tuning: 10/15 sessions converged at iter 4 with 81-99%; lowering from 85→80 prevents unnecessary extra iterations on borderline-clean binaries
  plateauThreshold:    3,  // M8 tuning: raised from 2→3 to give more patience before plateau-stop (helps project_chimera-style scripts with slow gain curves)
  disasmExpansion:     512,
  aggressiveness:      'balanced',
  enableTalon:         true,
  enableStrike:        false,
  enableEcho:          true,
  autoAdvance:         true,
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
  /** Verdict stability report — quantifies output drift across iterations */
  stabilityReport: VerdictStabilityReport;
}

// ── Verdict stability ─────────────────────────────────────────────────────────

/**
 * Quantifies how consistent NEST's output has been across iterations.
 *
 * Three factors are combined into a single 0–1 score:
 *   • Classification consistency  — fraction of iters agreeing on verdict class
 *   • Signal-set Jaccard stability — how much the active signal set changes
 *   • Confidence standard deviation — penalises large swings in the score
 *
 * Grades:
 *   stable      (score ≥ 0.80) — convergence is trustworthy
 *   unstable    (0.50–0.79)    — more iterations recommended
 *   oscillating (< 0.50)       — convergence MUST NOT be declared
 */
export interface VerdictStabilityReport {
  /** Composite stability score 0–1 */
  score: number;
  grade: 'stable' | 'unstable' | 'oscillating';
  /** Fraction of iterations whose classification matches the current verdict */
  classificationConsistency: number;
  /** Mean Jaccard similarity of signal IDs between consecutive iteration pairs */
  signalSetStability: number;
  /** Population std-dev of confidence across all iterations */
  confidenceStdDev: number;
  /** Number of classification direction changes (flip-flops) */
  classificationFlips: number;
  /**
   * Whether a convergence declaration is trustworthy.
   * True only when grade is 'stable' and ≥ 2 data points exist.
   */
  convergenceReliable: boolean;
  /** Human-readable stability diagnosis */
  diagnosis: string;
}


// ── NEST reasoning chain ───────────────────────────────────────────────────────

/** Identifies what kind of evidence a reasoning step represents. */
export type NestReasoningStepType =
  | 'signal-observation'     // a specific signal was observed
  | 'corroboration'          // two or more signals mutually confirm each other
  | 'contradiction-note'     // a conflicting piece of evidence
  | 'intermediate-conclusion'// what a group of signals implies together
  | 'final-verdict';         // the classification decision and its confidence

export type NestActionPriority = 'critical' | 'high' | 'medium';

/**
 * A single actionable next-step suggestion derived from observed signals.
 *
 * Stays deliberately concrete: names the tab or tool to use, quotes the
 * specific signal that motivated the suggestion, and states the expected
 * outcome so the analyst knows what they are looking for.
 */
export interface NestActionSuggestion {
  priority:   NestActionPriority;
  /** Imperative action title — short, scannable (≤ 60 chars). */
  action:     string;
  /**
   * One sentence explaining *why* this action is worth doing — derived
   * from the specific signal(s) that triggered the suggestion.
   */
  rationale:  string;
  /** The HexHawk tab most relevant to this action, when applicable. */
  tab?:       'hex' | 'strings' | 'disassembly' | 'cfg' | 'metadata' | 'plugins';
  /** Signal IDs that motivated this suggestion. */
  triggeredBy: string[];
}

export interface NestReasoningStep {
  /** 1-based position in the chain */
  step:   number;
  type:   NestReasoningStepType;
  /** Short label — signal id, behavior name, or verdict classification */
  subject: string;
  /** What was observed or concluded (human-readable sentence) */
  observation: string;
  /** What this step means for the final verdict */
  implication: string;
  /** This step's share of the total confidence build-up (0–100) */
  confidenceContribution: number;
  /** IDs of the signals that back this step */
  supportingSignalIds: string[];
}

/** Top signal summary used in the reasoning chain header. */
export interface NestTopSignal {
  id:      string;
  finding: string;
  weight:  number;
  tier:    EvidenceTier;
  source:  SignalSource;
}

/**
 * Structured reasoning chain for a single NEST iteration.
 *
 * Connects top contributing signals → intermediate behavioral conclusions
 * → final verdict in a step-by-step chain.  Designed for both machine
 * consumption (report export) and direct human reading (console / NestView).
 */
export interface NestReasoningChain {
  verdict:    BinaryClassification;
  confidence: number;
  iteration:  number;
  /**
   * Top 3–5 signals ranked by (weight × tier-multiplier).
   * DIRECT ×3, STRONG ×2, WEAK ×1.
   */
  topSignals: NestTopSignal[];
  /** Ordered chain: observations → conclusions → verdict */
  steps:      NestReasoningStep[];
  /**
   * One-paragraph plain-text summary — suitable for CREST reports and the
   * analyst console.  Mentions the top signals by name, the key behaviors,
   * any unresolved contradictions, and the final confidence.
   */
  narrative:  string;
  /**
   * 1–3 actionable next-step suggestions ranked by priority.
   * Derived from the specific signals that fired in this iteration.
   * Updated every iteration so suggestions stay relevant to the current evidence.
   */
  nextSteps:  NestActionSuggestion[];
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
  /**
   * Optional: YARA rule match results from yaraEngine.runYaraRules().
   * Typically populated on the first iteration when raw binary data is available.
   * Passed through to correlationEngine.computeVerdict() as §16.5 YARA signals.
   */
  yaraMatches?:     YaraRuleMatch[];
  /**
   * Optional: MYTHOS capability matches from mythosEngine.runMythosRules().
   * Populated before or during the first iteration; passed through to
   * correlationEngine.computeVerdict() as §16.6 Mythos capability signals.
   * Each match carries code locations (addresses) so NEST can link signals
   * to actual binary regions for navigation and reasoning display.
   */
  mythosMatches?:   MythosCapabilityMatch[];
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
  iteration:       number;
  timestamp:       number;
  input:           NestIterationInput;
  verdict:         BinaryVerdictResult;
  confidence:      number;
  refinementPlan:  NestRefinementPlan | null;
  /** null for the first iteration */
  delta:           NestDelta | null;
  annotations:     string[];
  durationMs:      number;
  /** Stability of the verdict up to and including this iteration */
  stabilityReport: VerdictStabilityReport;
  /**
   * Structured signal → conclusion → verdict reasoning chain.
   * Limits to the top 3–5 contributing signals for legibility.
   */
  reasoningChain: NestReasoningChain;
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
    yaraMatches:      input.yaraMatches,
    mythosMatches:    input.mythosMatches,
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
 * Compute a stability report from all completed iteration snapshots plus the
 * current verdict being evaluated.
 *
 * Called from assessConvergence() (convergence guard) and
 * buildIterationSnapshot() (per-iteration display).
 *
 * Requires ≥ 2 data points (snapshots + currentVerdict) for a meaningful
 * result; returns a neutral "insufficient data" report otherwise.
 */
export function computeVerdictStability(
  snapshots:      NestIterationSnapshot[],
  currentVerdict: BinaryVerdictResult,
): VerdictStabilityReport {
  // ── Not enough data ────────────────────────────────────────────────────────
  if (snapshots.length < 1) {
    return {
      score: 1, grade: 'stable',
      classificationConsistency: 1, signalSetStability: 1,
      confidenceStdDev: 0, classificationFlips: 0,
      convergenceReliable: false,
      diagnosis: 'Insufficient iterations to assess stability (need ≥ 2)',
    };
  }

  // ── Sequences including the current (not-yet-snapshotted) verdict ─────────
  const allClasses = [...snapshots.map(s => s.verdict.classification), currentVerdict.classification];
  const allConfs   = [...snapshots.map(s => s.confidence), currentVerdict.confidence];
  const finalClass = currentVerdict.classification;

  // ── Classification consistency ─────────────────────────────────────────────
  const consistentCount            = allClasses.filter(c => c === finalClass).length;
  const classificationConsistency  = consistentCount / allClasses.length;

  // ── Classification flips (direction changes, not just disagreements) ───────
  let classificationFlips = 0;
  for (let i = 1; i < allClasses.length; i++) {
    if (allClasses[i] !== allClasses[i - 1]) classificationFlips++;
  }

  // ── Signal-set Jaccard stability ───────────────────────────────────────────
  // Build signal-id sets for every iteration + current verdict
  const allSignalSets: Set<string>[] = [
    ...snapshots.map(s => new Set(s.verdict.signals.map(sig => sig.id))),
    new Set(currentVerdict.signals.map(s => s.id)),
  ];
  const jaccards: number[] = [];
  for (let i = 1; i < allSignalSets.length; i++) {
    const a = allSignalSets[i - 1];
    const b = allSignalSets[i];
    const intersection = [...a].filter(id => b.has(id)).length;
    const unionSize    = new Set([...a, ...b]).size;
    jaccards.push(unionSize === 0 ? 1 : intersection / unionSize);
  }
  const signalSetStability =
    jaccards.length > 0
      ? jaccards.reduce((s, j) => s + j, 0) / jaccards.length
      : 1;

  // ── Confidence standard deviation ──────────────────────────────────────────
  const meanConf = allConfs.reduce((s, c) => s + c, 0) / allConfs.length;
  const confidenceStdDev = Math.sqrt(
    allConfs.reduce((s, c) => s + (c - meanConf) ** 2, 0) / allConfs.length,
  );
  // Normalise: stdDev ≥ 15 → 0, stdDev = 0 → 1
  const stdDevScore = Math.max(0, 1 - confidenceStdDev / 15);

  // ── Composite score ────────────────────────────────────────────────────────
  // 40% classification consistency + 40% signal-set stability + 20% stdDev score
  const raw   = classificationConsistency * 0.40 + signalSetStability * 0.40 + stdDevScore * 0.20;
  const score = Math.round(raw * 100) / 100;

  const grade: VerdictStabilityReport['grade'] =
    score >= 0.80 ? 'stable'      :
    score >= 0.50 ? 'unstable'    :
    'oscillating';

  // Reliable only when enough data AND no oscillation
  const convergenceReliable = snapshots.length >= 1 && grade === 'stable';

  // ── Diagnosis ──────────────────────────────────────────────────────────────
  const parts: string[] = [];
  if (classificationFlips > 1) {
    parts.push(`${classificationFlips} classification flip(s) — verdict oscillating`);
  }
  if (signalSetStability < 0.70) {
    parts.push(`signal set unstable (mean Jaccard ${(signalSetStability * 100).toFixed(0)}%)`);
  }
  if (confidenceStdDev > 8) {
    parts.push(`confidence swings ±${confidenceStdDev.toFixed(1)}%`);
  }
  const diagnosis =
    parts.length > 0
      ? `${grade.charAt(0).toUpperCase() + grade.slice(1)}: ${parts.join('; ')}`
      : grade === 'stable'
        ? `Stable: classification and signals consistent across ${snapshots.length + 1} data points`
        : `Unstable output — additional iterations recommended`;

  return {
    score, grade,
    classificationConsistency, signalSetStability,
    confidenceStdDev, classificationFlips,
    convergenceReliable, diagnosis,
  };
}

/**
 * Assess whether the NEST session has converged.
 *
 * Convergence criteria (checked in priority order):
 *   A. max-iterations     — hard limit reached
 *   B. confidence-threshold — confidence ≥ config threshold (+ corpus hint)
 *   C. stable-clean       — clean/suspicious verdict, conf ≥ 75%, no HIGH
 *                            contradictions, classification stable ≥ 2 iters
 *   D. stable-threat      — threat class stable ≥ 2 iters, conf ≥ 77%,
 *                            no new signals, ≤1 unresolved contradiction
 *   E. low-loss           — projected gain < 12 pts, conf ≥ 70%, ≥2 iters done
 *                            (or conf ≥ 60% for packer stubs with import-table-anomaly)
 *   F. plateau            — confidence delta < plateauThreshold for 3 iters
 *
 * Stability guard: criteria B-F will NOT declare convergence when the
 * verdict stability grade is 'oscillating' (score < 0.50). Max-iterations
 * and no-data exits bypass this guard since they are hard stops.
 */
export function assessConvergence(
  session: NestSession,
  verdict: BinaryVerdictResult,
  expectedClass?: BinaryClassification,
): ConvergenceAssessment {
  const { iterations, config } = session;
  const conf  = verdict.confidence;
  const iters = iterations;

  // Compute stability early so it is attached to every return path.
  const stability = computeVerdictStability(iters, verdict);

  // ── No-data guard ─────────────────────────────────────────────────────────
  if (verdict.signalCount === 0 && iters.length === 0) {
    return _ca(false, 'no-data', conf, 100, true, 0, 0, 0,
      'No signals collected — run Inspect, Strings, and Disassemble first', stability);
  }

  // ── Parse-failure / format-blocked early exit ─────────────────────────────
  if (verdict.signalCount === 0 && iters.length >= 1) {
    return _ca(true, 'no-data', 0, 0, true, 0, 0, 0,
      'No signals after completed iteration — binary may be an unsupported format (ELF/DOS/16-bit), packed beyond stub recovery, or over the size limit', stability);
  }

  // ── A: max iterations (always respected — bypasses stability guard) ───────
  if (iters.length >= config.maxIterations) {
    return _ca(true, 'max-iterations', conf, 0, true, 0, 0, 0,
      `Maximum iterations (${config.maxIterations}) reached`, stability);
  }

  // ── Min-iterations guard ──────────────────────────────────────────────────
  const minIter = config.minIterations ?? 0;
  if (iters.length < minIter) {
    return _ca(false, 'continue', conf, 100, false, 0, 0, 0,
      `Minimum iterations not yet reached — ${iters.length}/${minIter} completed`, stability);
  }

  // ── Stability oscillation guard ───────────────────────────────────────────
  // If the verdict is oscillating (score < 0.50) we must NOT declare
  // convergence on criteria B-F — doing so would lock in an unstable output.
  // Expose the instability so the UI can warn the analyst; NEST will continue
  // until the verdict stabilises or max-iterations is hit.
  const isOscillating = stability.grade === 'oscillating';

  // ── B: confidence threshold ───────────────────────────────────────────────
  let effectiveConf = conf;
  if (
    expectedClass !== undefined &&
    verdict.classification === expectedClass &&
    effectiveConf >= 65 &&
    iters.length >= 1
  ) {
    effectiveConf = Math.min(99, effectiveConf + 10);
  }

  if (effectiveConf >= config.confidenceThreshold) {
    if (isOscillating) {
      return _ca(false, 'continue', conf, 100, false, 0, 0, 0,
        `Confidence ${conf}% meets threshold but verdict is OSCILLATING (stability ${(stability.score * 100).toFixed(0)}%) — continuing until stable: ${stability.diagnosis}`,
        stability);
    }
    return _ca(true, 'confidence-threshold', effectiveConf, 0, true, 0, 0, 0,
      `Confidence ${effectiveConf}%${
        effectiveConf !== conf ? ` (${conf}% + 10% corpus hint)` : ''
      } ≥ threshold ${config.confidenceThreshold}%`, stability);
  }

  // ── No prior iteration — first pass, always continue ─────────────────────
  if (iters.length === 0) {
    return _ca(false, 'continue', conf, 100, true, 0, 0, 0,
      'First iteration — no convergence history yet', stability);
  }

  // ── Shared metrics ────────────────────────────────────────────────────────

  const last = iters[iters.length - 1];
  const prev = iters.length >= 2 ? iters[iters.length - 2] : null;

  const classificationStable =
    prev !== null
      ? prev.verdict.classification === verdict.classification &&
        last.verdict.classification === verdict.classification
      : last.verdict.classification === verdict.classification;

  const recentConfs = [...iters.slice(-3).map(i => i.confidence), conf];
  const mean = recentConfs.reduce((a, b) => a + b, 0) / recentConfs.length;
  const confidenceVariance = Math.sqrt(
    recentConfs.reduce((s, c) => s + (c - mean) ** 2, 0) / recentConfs.length,
  );

  const allContradictions = verdict.contradictions ?? [];
  const contradictionBurden = allContradictions.filter(
    c => c.severity === 'high' || c.severity === 'medium',
  ).length;
  const highContradictions = allContradictions.filter(c => c.severity === 'high').length;

  const signalDelta = Math.abs(verdict.signals.length - last.verdict.signals.length);

  const lastBoost  = last.refinementPlan?.expectedBoost ?? 0;
  const confDelta  = Math.abs(conf - last.confidence);
  const projectedLoss = Math.min(100, Math.round(
    lastBoost  * 0.5 +
    confDelta  * 3.0 +
    signalDelta * 4.0,
  ));

  // Helper: if oscillating, substitute a 'continue' warning for any convergence
  const oscillatingOverride = (reason: string): ConvergenceAssessment =>
    _ca(false, 'continue', conf, projectedLoss, classificationStable,
      confidenceVariance, contradictionBurden, signalDelta,
      `${reason} — suppressed: verdict is OSCILLATING (stability ${(stability.score * 100).toFixed(0)}%): ${stability.diagnosis}`,
      stability);

  // ── C: stable-clean ───────────────────────────────────────────────────────
  const isCleanish =
    verdict.classification === 'clean' ||
    verdict.classification === 'suspicious';

  if (isCleanish && conf >= 75 && highContradictions === 0 && classificationStable) {
    if (isOscillating) return oscillatingOverride(`stable-clean at ${conf}%`);
    return _ca(true, 'stable-clean', conf, projectedLoss, classificationStable,
      confidenceVariance, contradictionBurden, signalDelta,
      `Clean/benign verdict stable at ${conf}% — no unresolved contradictions, converged`, stability);
  }

  // ── D: stable-threat ─────────────────────────────────────────────────────
  const isThreat = !isCleanish && verdict.classification !== 'unknown';
  if (
    isThreat &&
    classificationStable &&
    conf >= 77 &&
    signalDelta === 0 &&
    contradictionBurden <= 1
  ) {
    if (isOscillating) return oscillatingOverride(`stable-threat '${verdict.classification}' at ${conf}%`);
    return _ca(true, 'stable-threat', conf, projectedLoss, classificationStable,
      confidenceVariance, contradictionBurden, signalDelta,
      `Threat classification '${verdict.classification}' stable at ${conf}% — converged`, stability);
  }

  // ── E: low-loss ───────────────────────────────────────────────────────────
  if (projectedLoss < 12 && conf >= 70 && highContradictions === 0 && iters.length >= 2) {
    if (isOscillating) return oscillatingOverride(`low-loss at ${conf}%`);
    return _ca(true, 'low-loss', conf, projectedLoss, classificationStable,
      confidenceVariance, contradictionBurden, signalDelta,
      `Projected gain (${projectedLoss} pts) negligible at ${conf}% — stopping early`, stability);
  }

  const isPackerStub = verdict.signals.some(s => s.id === 'import-table-anomaly');
  if (isPackerStub && projectedLoss < 12 && conf >= 60 && iters.length >= 2) {
    if (isOscillating) return oscillatingOverride(`packer-stub low-loss at ${conf}%`);
    return _ca(true, 'low-loss', conf, projectedLoss, classificationStable,
      confidenceVariance, contradictionBurden, signalDelta,
      `Structurally-blocked packer stub at ${conf}% — single-DLL IAT indicates analysis has reached its limit without unpacking`, stability);
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
      if (isOscillating) return oscillatingOverride(`confidence plateau`);
      return _ca(true, 'plateau', conf, projectedLoss, classificationStable,
        confidenceVariance, contradictionBurden, signalDelta,
        `Confidence plateau — delta < ${config.plateauThreshold}% for 3 consecutive iterations`, stability);
    }
  }

  return _ca(false, 'continue', conf, projectedLoss, classificationStable,
    confidenceVariance, contradictionBurden, signalDelta,
    `Confidence ${conf}% — continuing (threshold: ${config.confidenceThreshold}%)`, stability);
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
  stabilityReport: VerdictStabilityReport,
): ConvergenceAssessment {
  return {
    hasConverged, reason, confidence, projectedLoss,
    classificationStable, confidenceVariance, contradictionBurden,
    signalDelta, message, stabilityReport,
  };
}

/**
 * Evaluate uncertainty — backward-compatible wrapper around assessConvergence().
 * Call assessConvergence() directly when you need the full convergence metrics.
 */
export function evaluateUncertainty(
  session: NestSession,
  verdict: BinaryVerdictResult,
  expectedClass?: BinaryClassification,
): NestUncertaintyAssessment {
  const ca = assessConvergence(session, verdict, expectedClass);

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
  // Cap the expected-coverage target at 5 iterations equivalent to prevent
  // unbounded growth that would generate different plans on re-runs.
  const effectiveIter = Math.min(iteration, 4);
  const expectedCoverage = 30 + effectiveIter * 25;
  if (input.instructionCount < expectedCoverage) {
    actions.push({
      type:     'expand-disasm-forward',
      priority: 'medium',
      offset:   currentEnd,
      // Cap at 2048 bytes — bounded regardless of how many iterations have run.
      length:   Math.min(512 * (effectiveIter + 1), 2048),
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

  // Stability annotation — only noteworthy when non-stable
  const stab = snapshot.stabilityReport;
  if (stab && stab.grade !== 'stable') {
    notes.push(`Stability ${stab.grade.toUpperCase()} (score ${(stab.score * 100).toFixed(0)}%): ${stab.diagnosis}`);
  }

  // Reasoning chain — top signals and narrative
  const chain = snapshot.reasoningChain;
  if (chain) {
    if (chain.topSignals.length > 0) {
      notes.push(
        `Top signals: ${chain.topSignals.map(s => `${s.id} (${s.tier}, w${s.weight})`).join(' · ')}`,
      );
    }
    notes.push(`Reasoning: ${chain.narrative}`);
  }

  return notes;
}

// ── NEST reasoning chain builder ─────────────────────────────────────────────

/**
 * Score a signal for ranking purposes.
 *
 * Tier multipliers: DIRECT ×3, STRONG ×2, WEAK ×1.
 * Combined with the signal's own weight (0–10) to produce a sort key.
 */
function signalRankScore(sig: CorrelatedSignal): number {
  const tierMult = sig.tier === 'DIRECT' ? 3 : sig.tier === 'STRONG' ? 2 : 1;
  return sig.weight * tierMult;
}

// ── Signal → action suggestion rules ─────────────────────────────────────────

/**
 * Each rule maps one or more signal ids (or a predicate on the signal set) to
 * a single actionable suggestion.  Rules are tested in priority order; once a
 * suggestion slot is claimed by a higher-priority rule the lower-priority rules
 * that would produce the same `tab` are skipped.
 */
interface SuggestionRule {
  /** Return true when this rule should fire given the observed signal ids. */
  matches: (ids: Set<string>, verdict: BinaryVerdictResult) => boolean;
  suggestion: (ids: Set<string>, verdict: BinaryVerdictResult) => NestActionSuggestion;
}

const SUGGESTION_RULES: SuggestionRule[] = [
  // ── Packer / loader / self-decryption ─────────────────────────────────────
  {
    matches: ids =>
      ids.has('import-table-anomaly') || ids.has('high-entropy') ||
      ids.has('encrypted-section')    || ids.has('echo-string-decode'),
    suggestion: ids => ({
      priority:    'critical',
      action:      'Locate and analyse the unpacking stub at the entry point',
      rationale:
        'High entropy or a minimal import table indicates the real code is packed or encrypted. ' +
        'The entry point (EP) region in the Disassembly tab contains the self-extraction loop — ' +
        'identifying it is the first step before any deeper analysis.',
      tab:         'disassembly',
      triggeredBy: [...ids].filter(id =>
        ['import-table-anomaly','high-entropy','encrypted-section','echo-string-decode'].includes(id)),
    }),
  },

  // ── Anti-debug evasion ────────────────────────────────────────────────────
  {
    matches: ids =>
      ids.has('antidebug-imports') || ids.has('talon-anti-debug') ||
      ids.has('strike-anti-debug') || ids.has('echo-anti-debug')  ||
      ids.has('anti-analysis-patterns'),
    suggestion: ids => ({
      priority:    'critical',
      action:      'Patch or bypass anti-debugging checks before dynamic analysis',
      rationale:
        'Anti-debug routines (IsDebuggerPresent, timing checks, PEB.NtGlobalFlag) will abort ' +
        'the process or alter its behaviour under a debugger. Locate them in the Disassembly tab ' +
        'and NOP or invert the guard branches with the IMP engine before running STRIKE.',
      tab:         'disassembly',
      triggeredBy: [...ids].filter(id =>
        ['antidebug-imports','talon-anti-debug','strike-anti-debug',
         'echo-anti-debug','anti-analysis-patterns'].includes(id)),
    }),
  },

  // ── Process injection ─────────────────────────────────────────────────────
  {
    matches: ids =>
      ids.has('injection-imports') || ids.has('talon-injection') ||
      ids.has('echo-injection')    || ids.has('rat-composite'),
    suggestion: ids => ({
      priority:    'critical',
      action:      'Trace injection APIs to identify the target process',
      rationale:
        'WriteProcessMemory / VirtualAllocEx / CreateRemoteThread indicate the malware migrates ' +
        'into another process. Follow the call chain in the Disassembly tab to find the string or ' +
        'handle that identifies the injection target.',
      tab:         'disassembly',
      triggeredBy: [...ids].filter(id =>
        ['injection-imports','talon-injection','echo-injection','rat-composite'].includes(id)),
    }),
  },

  // ── Validation logic / serial checks / keygen shape ─────────────────────
  {
    matches: (ids, verdict) =>
      verdict.classification === 'packer'  ||
      verdict.classification === 'rat'     ||
      ids.has('critical-patterns')         ||
      ids.has('talon-anti-debug')          ||  // talon sees compare chains too
      (ids.has('tight-loops') && ids.has('crypto-imports')),
    suggestion: (_ids, verdict) => ({
      priority:    'high',
      action:      'Inspect comparison and branch instructions for validation logic',
      rationale:
        verdict.classification === 'packer'
          ? 'Packers commonly validate a registration key or hardware fingerprint before decrypting. ' +
            'Look for cmp/test + conditional-jump patterns immediately after the input-reading routine.'
          : 'Critical disassembly patterns suggest the binary performs input validation or key checks. ' +
            'Locate the comparison block in the Disassembly / CFG tab — the Constraint engine can then ' +
            'taint-propagate from inputs to the branch to derive the expected value.',
      tab:         'cfg',
      triggeredBy: ['critical-patterns','tight-loops','talon-anti-debug'].filter(id => _ids.has(id)),
    }),
  },

  // ── Dynamic API resolution (hidden imports) ───────────────────────────────
  {
    matches: ids =>
      ids.has('dynload-imports') || ids.has('indirect-calls') ||
      ids.has('strike-indirect-flow') || ids.has('minimal-imports'),
    suggestion: ids => ({
      priority:    'high',
      action:      'Run TALON decompilation to surface dynamically resolved API calls',
      rationale:
        'Indirect calls or LoadLibrary/GetProcAddress usage means the true import table is hidden. ' +
        'TALON IR lifts through call-register patterns and labels them — enable it in the NEST ' +
        'config to reveal concealed capabilities before the next iteration.',
      tab:         'disassembly',
      triggeredBy: [...ids].filter(id =>
        ['dynload-imports','indirect-calls','strike-indirect-flow','minimal-imports'].includes(id)),
    }),
  },

  // ── C2 / network infrastructure ──────────────────────────────────────────
  {
    matches: ids =>
      ids.has('embedded-urls') || ids.has('hardcoded-ips') ||
      ids.has('embedded-domains') || ids.has('network-imports') ||
      ids.has('talon-network')   || ids.has('echo-network'),
    suggestion: ids => ({
      priority:    'high',
      action:      'Extract and triage all network indicators of compromise (IOCs)',
      rationale:
        'URLs, IPs, and domain strings found in the binary are candidate C2 or download endpoints. ' +
        'Review them in the Strings tab, then pivot to threat intelligence to assess whether any ' +
        'are known-malicious infrastructure.',
      tab:         'strings',
      triggeredBy: [...ids].filter(id =>
        ['embedded-urls','hardcoded-ips','embedded-domains',
         'network-imports','talon-network','echo-network'].includes(id)),
    }),
  },

  // ── Crypto without network → self-unpacking or ransomware ────────────────
  {
    matches: (ids, verdict) =>
      (ids.has('crypto-imports') || ids.has('talon-crypto') || ids.has('echo-crypto')) &&
      !ids.has('network-imports') && !ids.has('talon-network') &&
      verdict.classification !== 'clean',
    suggestion: ids => ({
      priority:    'high',
      action:      'Determine whether crypto is used for self-decryption or file encryption',
      rationale:
        'Cryptographic APIs without accompanying network signals suggest either runtime ' +
        'self-decryption (packer) or file encryption (ransomware). Compare section entropy before ' +
        'and after the crypto call cluster in the Disassembly tab to distinguish the two cases.',
      tab:         'disassembly',
      triggeredBy: [...ids].filter(id =>
        ['crypto-imports','talon-crypto','echo-crypto'].includes(id)),
    }),
  },

  // ── Persistence via registry ──────────────────────────────────────────────
  {
    matches: ids =>
      ids.has('registry-imports') || ids.has('registry-strings'),
    suggestion: ids => ({
      priority:    'high',
      action:      'Identify registry persistence keys from string cross-references',
      rationale:
        'Registry modification imports (RegSetValueEx) combined with Run-key strings indicate ' +
        'the malware installs a persistence entry. Confirm the exact key path in the Strings tab ' +
        'and validate via the CFG call graph.',
      tab:         'strings',
      triggeredBy: [...ids].filter(id =>
        ['registry-imports','registry-strings'].includes(id)),
    }),
  },

  // ── Embedded PE / dropper payload ────────────────────────────────────────
  {
    matches: (ids, verdict) =>
      ids.has('pe-names') ||
      verdict.classification === 'dropper' ||
      verdict.classification === 'loader',
    suggestion: (_ids, verdict) => ({
      priority:    'high',
      action:      'Locate and extract the embedded payload binary',
      rationale:
        verdict.classification === 'dropper'
          ? 'Dropper classification means a secondary PE or script is carried inside this binary. ' +
            'Scan the Hex view for MZ/PE headers or ELF magic bytes; carve the embedded file for ' +
            'independent analysis.'
          : 'PE-name strings suggest the binary references or drops another executable. ' +
            'Use the EmbeddedPayloadScanner plugin to locate embedded MZ/ELF sequences.',
      tab:         'hex',
      triggeredBy: [..._ids].filter(id => ['pe-names'].includes(id)),
    }),
  },

  // ── Script-based binary ───────────────────────────────────────────────────
  {
    matches: ids =>
      ids.has('script-dangerous-calls') || ids.has('script-network-modules') ||
      ids.has('script-crypto-modules')  || ids.has('script-powershell-dangerous') ||
      ids.has('script-shell-dangerous'),
    suggestion: ids => ({
      priority:    'medium',
      action:      'Run the script in the Sandbox with network and filesystem monitoring',
      rationale:
        'Dangerous Python/PowerShell/shell constructs were detected. The Sandbox engine can execute ' +
        'the script with a 30-second timeout and derive behavioral signals from its runtime output, ' +
        'file writes, and network calls.',
      tab:         'plugins',
      triggeredBy: [...ids].filter(id =>
        ['script-dangerous-calls','script-network-modules','script-crypto-modules',
         'script-powershell-dangerous','script-shell-dangerous'].includes(id)),
    }),
  },

  // ── CFG complexity fallback ───────────────────────────────────────────────
  {
    matches: (ids, verdict) =>
      ids.has('tight-loops') || ids.has('indirect-calls') ||
      (verdict.confidence < 70 && verdict.signals.length > 0),
    suggestion: (_ids, verdict) => ({
      priority:    'medium',
      action:      'Build the Control Flow Graph to map program structure',
      rationale:
        verdict.confidence < 70
          ? `Current confidence is ${verdict.confidence}% — the CFG will expose unreachable blocks, ` +
            'loop boundaries, and indirect-call targets that help distinguish obfuscation from ' +
            'legitimate complexity.'
          : 'Tight loops and indirect calls indicate obfuscated or data-driven control flow. ' +
            'The CFG tab visualises the basic-block structure and highlights back-edges (loops) ' +
            'and indirect dispatch tables.',
      tab:         'cfg',
      triggeredBy: [..._ids].filter(id => ['tight-loops','indirect-calls'].includes(id)),
    }),
  },
];

/**
 * Derive 1–3 actionable next-step suggestions from the observed signals.
 *
 * Rules are evaluated in priority order. At most one suggestion per `tab`
 * is emitted to avoid duplicate advice. The result is capped at 3.
 */
export function buildNestNextSteps(
  verdict: BinaryVerdictResult,
): NestActionSuggestion[] {
  const ids      = new Set(verdict.signals.map(s => s.id));
  const results: NestActionSuggestion[] = [];
  const usedTabs = new Set<string>();

  for (const rule of SUGGESTION_RULES) {
    if (results.length >= 3) break;
    if (!rule.matches(ids, verdict)) continue;

    const suggestion = rule.suggestion(ids, verdict);
    if (suggestion.triggeredBy.length === 0) continue;

    // Deduplicate by tab — one suggestion per tab maximum
    if (suggestion.tab && usedTabs.has(suggestion.tab)) continue;
    if (suggestion.tab) usedTabs.add(suggestion.tab);

    results.push(suggestion);
  }

  // If nothing fired (e.g. very early iteration with 0 signals), emit a
  // generic 'run more analysis' suggestion rather than an empty list.
  if (results.length === 0) {
    results.push({
      priority:    'medium',
      action:      'Run Inspect, Strings, and Disassemble to collect initial signals',
      rationale:
        'No threat signals have been collected yet. These three operations provide the ' +
        'minimum evidence base for NEST to produce a reliable verdict.',
      tab:         'metadata',
      triggeredBy: [],
    });
  }

  return results;
}

const TIER_LABEL: Record<EvidenceTier, string> = {
  DIRECT: 'direct evidence',
  STRONG: 'strong evidence',
  WEAK:   'weak indicator',
};

const CLASS_LABEL: Record<string, string> = {
  clean:            'a clean utility',
  suspicious:       'a suspicious binary',
  packer:           'a packer or protector',
  dropper:          'a dropper',
  'ransomware-like':'ransomware-like malware',
  'info-stealer':   'an information stealer',
  rat:              'a Remote Access Trojan',
  loader:           'a loader',
  'likely-malware': 'likely malware',
  unknown:          'an unclassified binary',
};

const BEHAVIOR_LABEL: Record<string, string> = {
  'code-injection':     'code injection into other processes',
  'c2-communication':   'command-and-control (C2) communication',
  persistence:          'persistence installation',
  'anti-analysis':      'anti-analysis evasion',
  'data-exfiltration':  'data exfiltration',
  'file-destruction':   'file destruction or wiping',
  'credential-theft':   'credential theft',
  'code-decryption':    'runtime self-decryption',
  'dynamic-resolution': 'dynamic API resolution',
  'process-execution':  'child process spawning',
  'data-encryption':    'local data encryption',
  'self-contained':     'self-contained / benign profile',
};

/**
 * Build a structured reasoning chain for one NEST iteration.
 *
 * The chain follows the format:
 *   signal-observation steps  → one per top signal
 *   corroboration step        → if signals mutually corroborate each other
 *   contradiction-note step   → for each HIGH severity contradiction
 *   intermediate-conclusion   → behavioral capabilities derived from signals
 *   final-verdict             → classification + confidence
 *
 * @param verdict   The verdict produced in this iteration.
 * @param iteration Zero-based iteration index.
 * @param maxSignals Maximum number of top signals to surface (default: 5, min: 3).
 */
export function buildNestReasoningChain(
  verdict:    BinaryVerdictResult,
  iteration:  number,
  maxSignals: number = 5,
): NestReasoningChain {
  const limit = Math.max(3, Math.min(maxSignals, 5));

  // ── 1. Rank signals ────────────────────────────────────────────────────────
  const ranked = [...verdict.signals]
    .sort((a, b) => signalRankScore(b) - signalRankScore(a))
    .slice(0, limit);

  const topSignals: NestTopSignal[] = ranked.map(s => ({
    id:      s.id,
    finding: s.finding,
    weight:  s.weight,
    tier:    s.tier ?? 'WEAK',
    source:  s.source,
  }));

  const steps: NestReasoningStep[] = [];
  let stepNum = 1;

  // Total weight across top signals — used to proportionally distribute
  // confidenceContribution across individual steps (so they sum to ~conf).
  const totalWeight = ranked.reduce((s, sig) => s + signalRankScore(sig), 0) || 1;

  // ── 2. Signal-observation steps ───────────────────────────────────────────
  for (const sig of ranked) {
    const tier     = sig.tier ?? 'WEAK';
    const rankFrac = signalRankScore(sig) / totalWeight;
    // Each observation's contribution is its fractional share of confidence
    const contribution = Math.round(rankFrac * verdict.confidence);

    steps.push({
      step: stepNum++,
      type: 'signal-observation',
      subject: sig.id,
      observation: `[${tier}] ${sig.finding} (weight ${sig.weight}/10, ${TIER_LABEL[tier]})`,
      implication: sig.corroboratedBy.length > 0
        ? `Corroborated by ${sig.corroboratedBy.length} other signal(s): ${sig.corroboratedBy.slice(0, 3).join(', ')}${sig.corroboratedBy.length > 3 ? '…' : ''}`
        : 'No additional corroboration — assessed independently',
      confidenceContribution: contribution,
      supportingSignalIds: [sig.id],
    });
  }

  // ── 3. Corroboration step (when top signals confirm each other) ───────────
  const corrobPairs = ranked.filter(
    sig => sig.corroboratedBy.some(cb => ranked.some(r => r.id === cb)),
  );
  if (corrobPairs.length >= 2) {
    const pairNames = corrobPairs.map(s => s.id).join(', ');
    steps.push({
      step: stepNum++,
      type: 'corroboration',
      subject: 'mutual-corroboration',
      observation: `${corrobPairs.length} top signals mutually corroborate each other: ${pairNames}.`,
      implication: 'Mutual corroboration raises confidence beyond what any single signal provides alone.',
      confidenceContribution: Math.round(verdict.amplifiers.length * 3),
      supportingSignalIds: corrobPairs.map(s => s.id),
    });
  }

  // ── 4. Contradiction notes (HIGH severity only — these matter for verdict) ─
  const highContras = (verdict.contradictions ?? []).filter(c => c.severity === 'high');
  for (const contra of highContras.slice(0, 2)) {
    steps.push({
      step: stepNum++,
      type: 'contradiction-note',
      subject: contra.id,
      observation: `Contradiction: ${contra.observation} — but ${contra.conflict}.`,
      implication: `${contra.resolution} This reduces verdict certainty.`,
      confidenceContribution: -5,
      supportingSignalIds: [],
    });
  }

  // ── 5. Intermediate-conclusion: behavioral capabilities ───────────────────
  const behaviors = verdict.behaviors ?? [];
  if (behaviors.length > 0) {
    const behaviorNames = behaviors
      .map(b => BEHAVIOR_LABEL[b] ?? b)
      .slice(0, 4);
    steps.push({
      step: stepNum++,
      type: 'intermediate-conclusion',
      subject: 'behavioral-capabilities',
      observation: `Signals combine to indicate ${behaviorNames.length} capability(-ies): ${behaviorNames.join('; ')}.`,
      implication: behaviors.includes('self-contained')
        ? 'Multiple clean indicators suggest this binary has a benign operational profile.'
        : `This behavioral profile is characteristic of ${CLASS_LABEL[verdict.classification] ?? 'a malicious binary'}.`,
      confidenceContribution: Math.round(behaviors.length * 4),
      supportingSignalIds: ranked.map(s => s.id),
    });
  }

  // ── 6. Final verdict step ─────────────────────────────────────────────────
  const mitigated = verdict.negativeSignals.length > 0
    ? ` ${verdict.negativeSignals.length} clean indicator(s) reduced the raw score.`
    : '';
  steps.push({
    step: stepNum,
    type: 'final-verdict',
    subject: verdict.classification,
    observation: `Verdict: ${CLASS_LABEL[verdict.classification] ?? verdict.classification}. Threat score ${verdict.threatScore}/100, confidence ${verdict.confidence}%.${mitigated}`,
    implication: verdict.confidence >= 80
      ? 'High confidence — this verdict is defensible and suitable for reporting.'
      : verdict.confidence >= 60
        ? 'Moderate confidence — further iterations or manual confirmation are recommended.'
        : 'Low confidence — additional analysis is required before acting on this verdict.',
    confidenceContribution: verdict.confidence,
    supportingSignalIds: ranked.map(s => s.id),
  });

  // ── 7. Narrative paragraph ────────────────────────────────────────────────
  const topNames = topSignals.slice(0, 3).map(s => s.finding).join('; ');
  const behLine  = behaviors.length > 0
    ? ` Derived behavioral capabilities: ${behaviors.map(b => BEHAVIOR_LABEL[b] ?? b).slice(0, 3).join(', ')}.`
    : '';
  const contraLine = highContras.length > 0
    ? ` ${highContras.length} high-severity contradiction(s) were noted (${highContras.map(c => c.id).join(', ')}), reducing certainty.`
    : '';
  const mitLine = verdict.negativeSignals.length > 0
    ? ` ${verdict.negativeSignals.length} clean indicator(s) offset the threat score.`
    : '';
  const iterLine = iteration === 0
    ? ' This is the first analysis pass; further iterations may refine the verdict.'
    : ` Iteration ${iteration + 1} of the NEST convergence loop.`;

  const narrative =
    `Analysis of iteration ${iteration + 1} classified this binary as ` +
    `${CLASS_LABEL[verdict.classification] ?? verdict.classification} ` +
    `with ${verdict.confidence}% confidence (threat score ${verdict.threatScore}/100). ` +
    `Top contributing signals: ${topNames}.` +
    behLine + contraLine + mitLine + iterLine;

  const nextSteps = buildNestNextSteps(verdict);

  return {
    verdict:    verdict.classification,
    confidence: verdict.confidence,
    iteration,
    topSignals,
    steps,
    narrative,
    nextSteps,
  };
}

// ── Snapshot builder ──────────────────────────────────────────────────────────

export function buildIterationSnapshot(
  iterationIndex: number,
  input:          NestIterationInput,
  verdict:        BinaryVerdictResult,
  prev:           NestIterationSnapshot | null,
  refinementPlan: NestRefinementPlan | null,
  startTime:      number,
  priorSnapshots: NestIterationSnapshot[] = [],
): NestIterationSnapshot {
  const delta           = prev ? computeIterationDelta(prev, verdict) : null;
  const stabilityReport = computeVerdictStability(priorSnapshots, verdict);
  const reasoningChain  = buildNestReasoningChain(verdict, iterationIndex);
  const partial: Omit<NestIterationSnapshot, 'annotations'> = {
    iteration:      iterationIndex,
    timestamp:      Date.now(),
    input,
    verdict,
    confidence:     verdict.confidence,
    refinementPlan,
    delta,
    durationMs:     Date.now() - startTime,
    stabilityReport,
    reasoningChain,
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

// ── Training Loop ─────────────────────────────────────────────────────────────

/**
 * Minimal corpus-entry shape required by runTrainingLoop.
 * Intentionally structurally compatible with CorpusEntry so callers can pass
 * either type without importing corpusManager (which would create a circular
 * dependency since corpusManager already imports NestSummary from this module).
 */
export interface TrainingCorpusEntry {
  sha256: string;
  binaryPath: string;
  groundTruth: 'clean' | 'malicious' | 'unknown';
}

/**
 * Per-entry record produced by the training loop.
 * Captures multi-iteration verdict stability and confidence dynamics for a
 * single binary run through NEST in training mode.
 */
export interface TrainingRecord {
  /** SHA-256 of the binary (from the corpus entry). */
  sha256: string;
  binaryPath: string;
  /** Full NEST summary produced during this training run. */
  summary: NestSummary;
  /**
   * Verdict stability (0–1).
   * Fraction of `confidenceProgression` values that fall on the same ≥50/<50
   * side as the final confidence.  1.0 = classification never wavered.
   */
  verdictStability: number;
  /**
   * Confidence delta: finalConfidence − first-iteration confidence.
   * Positive = the engine grew more confident as iterations progressed.
   */
  confidenceDelta: number;
  /**
   * Whether the final verdict matches the corpus ground-truth polarity.
   * Always `true` when groundTruth is 'unknown'.
   */
  groundTruthMatch: boolean;
  /**
   * Signal identifiers extracted from NestSummary.keyFindings.
   * Used by promoteRecurringSignals() to identify reusable patterns.
   */
  signalIds: string[];
}

// Map clean/unknown verdicts so we can compare against corpus groundTruth.
const TRAINING_CLEAN_VERDICTS: ReadonlySet<string> = new Set(['clean', 'unknown']);
function trainingPolarityOf(verdict: string): 'clean' | 'malicious' {
  return TRAINING_CLEAN_VERDICTS.has(verdict) ? 'clean' : 'malicious';
}

/**
 * Run NEST in multi-iteration training mode over a corpus slice.
 *
 * For each corpus entry the provided `nestRunFn` is called; the resulting
 * NestSummary is then analysed for verdict stability and confidence dynamics.
 * Results are purely observational — correlationEngine is never mutated.
 *
 * The function is deterministic: given the same corpus and a deterministic
 * `nestRunFn` the output is always identical.
 *
 * @param corpus      Corpus entries to train on.
 * @param nestRunFn   Async function that drives a full NEST session for the
 *                    given path + config and returns a NestSummary (null = skip).
 * @param options     Optional config overrides, progress callback, and abort signal.
 * @returns           One TrainingRecord per successfully evaluated entry, in
 *                    corpus order.
 */
export async function runTrainingLoop(
  corpus: TrainingCorpusEntry[],
  nestRunFn: (path: string, config: NestConfig) => Promise<NestSummary | null>,
  options: {
    config?: Partial<NestConfig>;
    onProgress?: (completed: number, total: number, current: TrainingCorpusEntry) => void;
    shouldStop?: () => boolean;
  } = {},
): Promise<TrainingRecord[]> {
  const config: NestConfig = { ...DEFAULT_NEST_CONFIG, ...options.config };
  const records: TrainingRecord[] = [];

  for (let i = 0; i < corpus.length; i++) {
    if (options.shouldStop?.()) break;

    const entry = corpus[i];
    options.onProgress?.(i, corpus.length, entry);

    let summary: NestSummary | null = null;
    try {
      summary = await nestRunFn(entry.binaryPath, config);
    } catch {
      // Errors during individual entries must not abort the whole training run
      continue;
    }

    if (!summary) continue;

    const prog = summary.confidenceProgression;
    const finalConf = summary.finalConfidence;

    // Verdict stability: fraction of per-iteration confidences on the same
    // ≥50 / <50 side as the final confidence value.
    const finalAbove50 = finalConf >= 50;
    const inAgreement = prog.filter(c => (c >= 50) === finalAbove50).length;
    const verdictStability = prog.length > 0 ? inAgreement / prog.length : 1;

    // Confidence delta over the session
    const firstConf = prog[0] ?? finalConf;
    const confidenceDelta = finalConf - firstConf;

    // Ground-truth match check
    const actualPolarity = trainingPolarityOf(summary.finalVerdict);
    const groundTruthMatch =
      entry.groundTruth === 'unknown' ||
      actualPolarity === entry.groundTruth;

    records.push({
      sha256: entry.sha256,
      binaryPath: entry.binaryPath,
      summary,
      verdictStability,
      confidenceDelta,
      groundTruthMatch,
      signalIds: summary.keyFindings.slice(),
    });
  }

  return records;
}

// ── Work Saved Metrics (Prompt 9) ─────────────────────────────────────────────

/**
 * Per signal-category breakdown of what HexHawk surfaced automatically vs what
 * would have required manual investigation.
 */
export interface WorkSavedCategory {
  /** Category name (e.g. "imports", "strings", "disassembly") */
  category: string;
  /** Number of signals fired in this category */
  signalsFired: number;
  /** Total possible signals in this category that could have fired */
  signalsTotal: number;
  /** Estimated manual minutes saved by auto-surfacing these signals */
  minutesSaved: number;
  /** Key findings surfaced in this category (max 3) */
  topFindings: string[];
}

/**
 * Quantifies how much manual reverse-engineering work HexHawk's automated
 * analysis replaced in a completed or in-progress NEST session.
 *
 * Three axes are measured:
 *   • Signal coverage — which signals fired vs those that would need manual hunting
 *   • Path reduction  — CFG paths narrowed from the full graph to relevant ones
 *   • Logic identification — structured entry points, validation gates, loops
 *
 * The `workSavedScore` (0–100) is a composite that improves as:
 *   - More iterations complete (deeper coverage)
 *   - Confidence rises (validated evidence, not guesses)
 *   - More behaviors and signals are corroborated
 */
export interface WorkSavedMetrics {
  // ── Signal axis ──────────────────────────────────────────────────────────
  /** Total unique signals surfaced across all iterations */
  signalsSurfaced: number;
  /**
   * Signal IDs that were NOT surfaced but exist in the engine's vocabulary —
   * these are the "blind spots" an analyst would still need to investigate.
   */
  hiddenSignalIds: string[];
  /** Fraction of possible signals that fired (0–1) */
  signalCoverage: number;
  /** Per-category breakdown */
  categoryBreakdown: WorkSavedCategory[];

  // ── Path axis ────────────────────────────────────────────────────────────
  /** CFG blocks covered (from the most recent iteration's cfgSummary) */
  cfgBlocksCovered: number;
  /** Estimated total CFG blocks in the binary (from import/entropy heuristics) */
  cfgBlocksEstimated: number;
  /** Fraction of CFG paths narrowed to likely-relevant ones (0–1) */
  pathReductionRate: number;

  // ── Logic identification axis ─────────────────────────────────────────────
  /** Number of named logic regions identified (validation, protection, loops) */
  keyLogicRegionsIdentified: number;
  /** Descriptive labels of the identified regions */
  keyLogicSummaries: string[];
  /** Suspicious patterns located by address (count) */
  patternsLocated: number;

  // ── Manual effort estimate ───────────────────────────────────────────────
  /**
   * Estimated time (minutes) a skilled analyst would need to arrive at the
   * same findings manually.  Computed from:
   *   - 20 min base (file format identification + initial triage)
   *   - +5 min per unique signal surfaced (each would need a dedicated check)
   *   - +10 min per behavior detected (behavioral profiling)
   *   - +8 min per contradiction resolved (conflicting evidence takes extra time)
   *   - +15 min if CFG was analysed (manual CFG tracing is time-consuming)
   *   - +12 min if TALON decompilation was run (manual IR lifting)
   */
  estimatedManualMinutes: number;
  /**
   * Estimated time (minutes) HexHawk spent doing the same work.
   * Based on measured iteration durations.
   */
  estimatedToolMinutes: number;
  /** Speed factor: estimatedManualMinutes / max(1, estimatedToolMinutes) */
  speedFactor: number;

  // ── Composite score ───────────────────────────────────────────────────────
  /**
   * 0–100 composite "work saved" score.
   *
   * Formula:
   *   30% × signalCoverage
   *   25% × pathReductionRate
   *   20% × (keyLogicRegionsIdentified / 5 capped at 1)
   *   15% × min(speedFactor / 20, 1)
   *   10% × (session.iterations.length / maxIterations)
   *
   * Score improves across iterations as more signals fire, more paths are
   * narrowed, and confidence is validated.
   */
  workSavedScore: number;

  /** Human-readable one-paragraph summary of what was automated */
  narrative: string;

  /** Iteration at which the score was last computed */
  computedAtIteration: number;
}

/**
 * All signal IDs defined in the GYRE corpus — used to compute "hidden" signals
 * (those in the vocabulary but not fired in this session).
 */
const ALL_KNOWN_SIGNAL_IDS: readonly string[] = [
  // Structure
  'high-entropy', 'elevated-entropy', 'packed-text', 'encrypted-section', 'encrypted-data',
  'packer-stub', 'import-table-anomaly', 'minimal-imports', 'unusual-section-names',
  // Imports
  'injection-imports', 'network-imports', 'crypto-imports', 'file-imports',
  'antidebug-imports', 'exec-imports', 'dynload-imports', 'registry-imports',
  'wiper-imports', 'sysinfo-imports', 'thread-imports', 'bcrypt-imports',
  'concurrency-imports',
  // Strings
  'embedded-urls', 'hardcoded-ips', 'registry-strings', 'base64-strings',
  'pe-names', 'embedded-domains', 'file-path-strings',
  // Disassembly / patterns
  'critical-patterns', 'tight-loops', 'anti-analysis-patterns', 'indirect-calls',
  'validation-logic',
  // TALON
  'talon-anti-debug', 'talon-network', 'talon-crypto', 'talon-injection',
  // STRIKE
  'strike-anti-debug', 'strike-indirect-flow',
  // ECHO
  'echo-anti-debug', 'echo-network', 'echo-crypto', 'echo-injection',
  'echo-string-decode',
  // Composites / amplifiers
  'rat-composite', 'ransomware-composite', 'dropper-composite',
  // Scripts
  'script-dangerous-calls', 'script-network-modules', 'script-crypto-modules',
  'script-powershell-dangerous', 'script-shell-dangerous',
  // YARA built-in rules — 13 rules ship with HexHawk (more may be added by user)
  'yara-upx-packer', 'yara-ransomware-note', 'yara-anti-debug-a-p-is',
  'yara-process-injection-a-p-is', 'yara-network-c-2', 'yara-embedded-p-e',
  'yara-registry-persistence', 'yara-aes-constants', 'yara-peb-direct-access',
  'yara-base-64-encoded-p-e', 'yara-suspicious-scheduled-task',
  'yara-crypto-mining-strings', 'yara-self-deleting-binary',
  // MYTHOS built-in capabilities — 20 rules (user-defined rules use dynamic ids)
  'mythos-inject-remote-thread', 'mythos-inject-process-hollow', 'mythos-inject-apc-queue',
  'mythos-inject-hook', 'mythos-anti-debug-presence', 'mythos-anti-debug-timing',
  'mythos-anti-vm-detection', 'mythos-evade-dynamic-resolve', 'mythos-evade-self-delete',
  'mythos-persist-registry-run', 'mythos-persist-scheduled-task', 'mythos-persist-service',
  'mythos-encrypt-files', 'mythos-encrypt-aes', 'mythos-decrypt-payload',
  'mythos-c2-http', 'mythos-c2-raw-socket', 'mythos-exfil-data',
  'mythos-exec-spawn-child', 'mythos-load-embedded-pe', 'mythos-load-reflective',
  'mythos-ransomware-full-profile', 'mythos-access-credentials', 'mythos-wiper-forced-shutdown',
];

/** Estimated manual investigation minutes per signal category */
const CATEGORY_MINUTES: Record<string, number> = {
  structure:    8,   // entropy reading, section review
  imports:      5,   // per-import lookup
  strings:      4,   // string triage
  disassembly:  12,  // manual code reading
  signatures:   6,   // pattern lookup in reference material
};

/**
 * Compute "Work Saved" metrics from a NEST session.
 *
 * Can be called at any point — even on an in-progress session — and produces
 * a snapshot of how much automation has been delivered so far.
 */
export function computeWorkSaved(session: NestSession): WorkSavedMetrics {
  const iters = session.iterations;
  const last  = iters[iters.length - 1] ?? null;
  const verdict = last?.verdict ?? session.finalVerdict;
  const iterCount = iters.length;

  // ── Collect all unique signals across all iterations ───────────────────
  const allSignalIds = new Set<string>();
  const allSignals: CorrelatedSignal[] = [];
  const seenIds = new Set<string>();
  for (const iter of iters) {
    for (const sig of iter.verdict.signals) {
      allSignalIds.add(sig.id);
      if (!seenIds.has(sig.id)) {
        seenIds.add(sig.id);
        allSignals.push(sig);
      }
    }
  }

  // ── Signal coverage ────────────────────────────────────────────────────
  const signalsSurfaced = allSignalIds.size;
  const hiddenSignalIds = ALL_KNOWN_SIGNAL_IDS.filter(id => !allSignalIds.has(id));
  const signalCoverage  = Math.min(1, signalsSurfaced / Math.max(1, ALL_KNOWN_SIGNAL_IDS.length));

  // ── Per-category breakdown ─────────────────────────────────────────────
  const sources: SignalSource[] = ['structure', 'imports', 'strings', 'disassembly', 'signatures'];
  const categoryBreakdown: WorkSavedCategory[] = sources.map(src => {
    const fired = allSignals.filter(s => s.source === src);
    const total = ALL_KNOWN_SIGNAL_IDS.filter(id => {
      // Rough source attribution by prefix
      if (src === 'structure')    return /entropy|packed|encrypted|packer|import-table|minimal-imports|unusual/.test(id);
      if (src === 'imports')      return /imports$/.test(id);
      if (src === 'strings')      return /string|url|ip|domain|pe-name|file-path/.test(id);
      if (src === 'disassembly')  return /pattern|loop|anti-analysis|indirect|talon|strike|echo|validation/.test(id);
      if (src === 'signatures')   return /composite|script|yara-|mythos-/.test(id);
      return false;
    }).length;
    const minutesSaved = fired.length * (CATEGORY_MINUTES[src] ?? 5);
    return {
      category: src,
      signalsFired: fired.length,
      signalsTotal:  Math.max(fired.length, total),
      minutesSaved,
      topFindings: fired.slice(0, 3).map(s => s.finding),
    };
  });

  // ── Path reduction ────────────────────────────────────────────────────
  // Use the most recent cfgSummary if available
  const cfgSummary = last?.input?.cfgSummary;
  const cfgBlocksCovered  = cfgSummary?.totalBlocks ?? 0;
  // Estimate total blocks: PE static analysis suggests ~1 block per 20 instructions
  // Use instruction count from last iteration as a proxy
  const instrCount = last?.input?.instructionCount ?? 0;
  const cfgBlocksEstimated = Math.max(cfgBlocksCovered, Math.ceil(instrCount / 8));
  // Path reduction = covered / estimated, capped at 1; boosted by corroboration
  const corrobCount = allSignals.filter(s => s.corroboratedBy.length > 0).length;
  const pathReductionRaw = cfgBlocksEstimated > 0
    ? Math.min(1, cfgBlocksCovered / cfgBlocksEstimated)
    : Math.min(1, 0.2 + corrobCount * 0.05);
  const pathReductionRate = Math.min(1, pathReductionRaw + signalCoverage * 0.15);

  // ── Key logic identification ───────────────────────────────────────────
  const patternsLocated = iters.reduce((acc, it) => acc + (it.input.patterns?.length ?? 0), 0);
  // Behaviors are our proxy for logic regions identified
  const allBehaviors = new Set<string>();
  for (const iter of iters) { for (const b of iter.verdict.behaviors) allBehaviors.add(b); }
  const keyLogicRegionsIdentified = allBehaviors.size + (cfgSummary?.backEdges ?? 0);
  const keyLogicSummaries: string[] = [];
  if (allBehaviors.size > 0) {
    keyLogicSummaries.push(
      ...Array.from(allBehaviors).slice(0, 4).map(b => b.replace(/-/g, ' ')),
    );
  }
  if (cfgSummary && cfgSummary.backEdges > 0) {
    keyLogicSummaries.push(`${cfgSummary.backEdges} loop(s) detected in CFG`);
  }
  if ((cfgSummary?.jumpTables ?? 0) > 0) {
    keyLogicSummaries.push(`${cfgSummary!.jumpTables} jump table(s) mapped`);
  }

  // ── Manual effort estimate ─────────────────────────────────────────────
  const hasCfg     = cfgBlocksCovered > 0;
  const hasTalon   = iters.some(it => it.input.talonSignals != null);
  const behaviorsCount = allBehaviors.size;
  const contradictions = verdict?.contradictions?.length ?? 0;

  const estimatedManualMinutes = Math.round(
    20                                   // base triage
    + signalsSurfaced   * 5             // per-signal manual check
    + behaviorsCount    * 10            // behavioral profiling
    + contradictions    * 8             // resolving conflicting evidence
    + (hasCfg   ? 15 : 0)              // manual CFG tracing
    + (hasTalon ? 12 : 0),             // manual IR lifting
  );

  const estimatedToolMinutes = Math.max(
    1,
    Math.round(iters.reduce((acc, it) => acc + it.durationMs, 0) / 60_000),
  );

  const speedFactor = Math.round((estimatedManualMinutes / estimatedToolMinutes) * 10) / 10;

  // ── Composite work saved score (0–100) ────────────────────────────────
  const maxIter = session.config.maxIterations;
  const iterFraction = Math.min(1, iterCount / maxIter);
  const logicFraction = Math.min(1, keyLogicRegionsIdentified / 5);
  const speedFraction = Math.min(1, speedFactor / 20);

  const raw =
    signalCoverage   * 30 +
    pathReductionRate * 25 +
    logicFraction     * 20 +
    speedFraction     * 15 +
    iterFraction      * 10;

  const workSavedScore = Math.round(Math.min(100, raw));

  // ── Narrative ──────────────────────────────────────────────────────────
  const signalLine = signalsSurfaced > 0
    ? `surfaced ${signalsSurfaced} of ${ALL_KNOWN_SIGNAL_IDS.length} known signal types automatically`
    : 'no signals collected yet';
  const pathLine = cfgBlocksCovered > 0
    ? `, reduced ${cfgBlocksEstimated} potential CFG paths to ${cfgBlocksCovered} covered blocks`
    : '';
  const logicLine = keyLogicRegionsIdentified > 0
    ? `, and identified ${keyLogicRegionsIdentified} key logic region(s) (${Array.from(allBehaviors).slice(0, 2).join(', ')})`
    : '';
  const effortLine = estimatedManualMinutes > 0
    ? ` Estimated manual effort replaced: ${estimatedManualMinutes} min → ${estimatedToolMinutes} min (${speedFactor}× faster).`
    : '';

  const narrative =
    `NEST ${signalLine}${pathLine}${logicLine}.${effortLine} ` +
    `Work saved score: ${workSavedScore}/100 across ${iterCount} iteration(s).`;

  return {
    signalsSurfaced,
    hiddenSignalIds,
    signalCoverage,
    categoryBreakdown,
    cfgBlocksCovered,
    cfgBlocksEstimated,
    pathReductionRate,
    keyLogicRegionsIdentified,
    keyLogicSummaries,
    patternsLocated,
    estimatedManualMinutes,
    estimatedToolMinutes,
    speedFactor,
    workSavedScore,
    narrative,
    computedAtIteration: iterCount,
  };
}
