/**
 * engines/nest/NestSessionRunner.ts
 *
 * Self-contained NEST execution engine.
 *
 * Contains:
 *   - Full analysis loop  (delegates to utils/nestRunner.ts)
 *   - All post-session processing (learning store, dominance, diagnostics,
 *     adaptive healer, training store)
 *   - runNestSession()  — high-level one-call entrypoint
 *
 * Has zero React / DOM dependencies. Works in UI, CLI, and tests.
 *
 * Usage (automated — NestView auto-advance, CLI):
 *   const result = await runNestSession(filePath, config, { onIteration, shouldStop });
 *
 * Usage (manual step-by-step — NestView "Next" button):
 *   const runner = new NestSessionRunner({ filePath, config, metadata, ... });
 *   const step   = await runner.step();   // call once per button click
 *   if (!step.shouldContinue) { applyResult(step.postProcessing); }
 */

// ── Core runner (iteration loop) ──────────────────────────────────────────────
import {
  NestSessionRunner as CoreRunner,
  type NestIterationResult,
  type NestRunnerOptions as CoreRunnerOptions,
} from '../../utils/nestRunner';

// ── Session utilities ─────────────────────────────────────────────────────────
import { summarizeSession } from '../../utils/nestEngine';
import type {
  NestConfig,
  NestSession,
  NestSummary,
} from '../../utils/nestEngine';

// ── Meta-learning ─────────────────────────────────────────────────────────────
import type { LearningSession, LearningDecision } from '../../utils/iterationLearning';
import type { AnalysisPlan, StrategyClass } from '../../utils/strategyEngine';
import type { LearningBoosts } from '../../utils/learningStore';
import type { NestIterationSnapshot } from '../../utils/nestEngine';

// ── Post-processing: learning store ──────────────────────────────────────────
import {
  saveLearningSession,
  recordBinarySession,
  getLearningRecord,
  getSimilarBinaries,
  getEchoEnhancements,
  buildVerdictHistory,
  getStrategyReliability,
  recordStrategyOutcomes,
  type BinaryLearningRecord,
  type SimilarBinary,
} from '../../utils/learningStore';

// ── Post-processing: dominance ────────────────────────────────────────────────
import {
  assessDominance,
  saveDominanceAssessment,
  type DominanceAssessment,
} from '../../utils/dominanceEngine';

// ── Post-processing: cross-binary advisor ─────────────────────────────────────
import { buildCrossBinaryReport, type CrossBinaryReport } from '../../utils/crossBinaryAdvisor';

// ── Post-processing: diagnostics ──────────────────────────────────────────────
import {
  runDiagnostics,
  type NestDiagnosticsReport,
} from '../../utils/nestDiagnostics';
import {
  detectWeaknessFlags,
  countVerdictFlips,
  type WeaknessFlag,
} from '../../utils/multiBinaryRunner';

// ── Post-processing: adaptive healer ─────────────────────────────────────────
import { heal, type HealResult } from '../../utils/nestAdaptiveHealer';

// ── Post-processing: training store ──────────────────────────────────────────
import {
  buildTrainingRecord,
  appendTrainingRecord,
  getRecentRecords,
  computeTrainingStats,
  type TrainingRecord,
  type TrainingStats,
} from '../../utils/nestTrainingStore';

// ── Backend ───────────────────────────────────────────────────────────────────
import type { NestBackend } from '../../utils/nestBackend';
import { tauriBackend } from '../tauriBackend';

// ── App types ─────────────────────────────────────────────────────────────────
import type {
  FileMetadata,
  DisassembledInstruction,
  DisassemblyAnalysis,
} from '../../App';
import type { StrikeCorrelationSignal } from '../../utils/strikeEngine';

// ═══════════════════════════════════════════════════════════════════════════════
// Public types
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Results produced after a session ends (learning persistence,
 * diagnostics, healer suggestions, training store snapshot).
 * Included as `step.postProcessing` on the final step, and flattened
 * into `NestSessionResult` when using `run()` / `runNestSession()`.
 */
export interface NestPostProcessingResult {
  /** Updated learning record for this binary. */
  learningRecord:      BinaryLearningRecord | null;
  /** Similar binaries from previous sessions. */
  similarBinaries:     SimilarBinary[];
  /** ECHO hints refreshed after this session. */
  echoHints:           string[];
  /** Updated global strategy reliability scores. */
  strategyReliability: Partial<Record<StrategyClass, number>>;
  /** Dominance assessment (DOMINATED / RESISTANT). */
  dominance:           DominanceAssessment | null;
  /** Weakness flags detected from iteration history. */
  weaknessFlags:       WeaknessFlag[];
  /** Verdict-flip count across iterations. */
  verdictFlipCount:    number;
  /** Cross-binary advisor report. */
  crossBinaryReport:   CrossBinaryReport | null;
  /** NEST diagnostics report (outcome classification). */
  diagReport:          NestDiagnosticsReport | null;
  /** Adaptive healer recommendation. */
  healResult:          HealResult;
  /** Config to use for the next session (possibly modified by healer). */
  healedConfig:        NestConfig;
  /** Recent training records (last 50). */
  trainingRecords:     TrainingRecord[];
  /** Aggregate training statistics. */
  trainingStats:       TrainingStats | null;
}

/** Returned by `runner.step()` — one completed iteration. */
export interface NestStepResult extends NestIterationResult {
  /**
   * Populated only when `shouldContinue === false`.
   * Contains all persistence and reporting results from the session.
   */
  postProcessing?: NestPostProcessingResult;
}

/** Final result returned by `runner.run()` and `runNestSession()`. */
export interface NestSessionResult {
  session:             NestSession;
  summary:             NestSummary;
  learningSession:     LearningSession;
  iterDecisions:       LearningDecision[];
  learningRecord:      BinaryLearningRecord | null;
  similarBinaries:     SimilarBinary[];
  echoHints:           string[];
  strategyReliability: Partial<Record<StrategyClass, number>>;
  dominance:           DominanceAssessment | null;
  weaknessFlags:       WeaknessFlag[];
  verdictFlipCount:    number;
  crossBinaryReport:   CrossBinaryReport | null;
  diagReport:          NestDiagnosticsReport | null;
  healResult:          HealResult;
  healedConfig:        NestConfig;
  trainingRecords:     TrainingRecord[];
  trainingStats:       TrainingStats | null;
}

/** Options for `NestSessionRunner` and `runNestSession()`. */
export interface NestSessionRunnerOptions {
  filePath:             string;
  config:               NestConfig;
  /** Backend implementation. Defaults to `tauriBackend`. */
  backend?:             NestBackend;
  metadata?:            FileMetadata | null;
  /** Provide initial disassembly to skip the first disassemble call. */
  initialDisassembly?:  DisassembledInstruction[];
  initialOffset?:       number;
  initialLength?:       number;
  strings?:             Array<{ text: string }>;
  disassemblyAnalysis?: DisassemblyAnalysis;
  strikeSignals?:       StrikeCorrelationSignal;
  echoHints?:           string[];
  strategyReliability?: Partial<Record<StrategyClass, number>>;
  /**
   * Confidence floor for iteration 0 (0–100).
   * Pass `learningRecord.bestConfidence` to resume from the owned baseline.
   */
  seedConfidence?:      number;
  /**
   * Compute learning-based confidence boosts for a verdict.
   * Wire to `getLearningBoosts` from learningStore for full ownership continuity.
   */
  getBoosts?:           (hash: string | null, signalIds: string[]) => import('../../utils/learningStore').LearningBoosts | null;
  /**
   * Called after every completed iteration.
   * For UI streaming: update React state here.
   * For CLI: log progress here.
   */
  onIteration?:         (step: NestStepResult) => void;
  /** Return true to abort the loop. Wire to a stopRef in the UI. */
  shouldStop?:          () => boolean;
  /** Delay in ms between iterations (used by `run()` / `runNestSession()`). */
  delay?:               number;
}

// ═══════════════════════════════════════════════════════════════════════════════
// NestSessionRunner
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Runs a NEST session — analysis loop + full post-processing.
 *
 * Delegates iteration logic to `utils/nestRunner.ts` (CoreRunner).
 * Adds post-processing (learning persistence, diagnostics, healer,
 * training store) on top.
 *
 * Two usage patterns:
 *   • `run(delay?)` — full automated loop, returns `NestSessionResult`
 *   • `step()`      — single iteration, returns `NestStepResult`
 *                     (use for manual "Next" button in the UI)
 */
export class NestSessionRunner {
  private readonly core: CoreRunner;
  private cachedPP: NestPostProcessingResult | undefined;

  constructor(private readonly opts: NestSessionRunnerOptions) {
    // Build core runner options — do NOT forward onIteration;
    // we intercept it in step() so we can attach postProcessing.
    const coreOpts: CoreRunnerOptions = {
      filePath:            opts.filePath,
      config:              opts.config,
      backend:             opts.backend ?? tauriBackend,
      metadata:            opts.metadata ?? null,
      initialDisassembly:  opts.initialDisassembly ?? [],
      initialOffset:       opts.initialOffset ?? 0,
      initialLength:       opts.initialLength ?? opts.config.disasmExpansion * 2,
      strings:             opts.strings ?? [],
      disassemblyAnalysis: opts.disassemblyAnalysis ?? {
        functions:        new Map(),
        suspiciousPatterns: [],
        loops:            [],
        referenceStrength: new Map(),
        blockAnalysis:    new Map(),
      },
      strikeSignals:       opts.strikeSignals,
      echoHints:           opts.echoHints ?? [],
      strategyReliability: opts.strategyReliability ?? {},
      seedConfidence:      opts.seedConfidence,
      getBoosts:           opts.getBoosts,
      shouldStop:          opts.shouldStop,
      // onIteration is not forwarded — we intercept in step() to attach postProcessing
    };
    this.core = new CoreRunner(coreOpts);
  }

  // ── Accessors ──────────────────────────────────────────────────────────────

  get session():         NestSession              { return this.core.session; }
  get learningSession(): LearningSession           { return this.core.learningSession; }
  get decisions():       LearningDecision[]        { return this.core.iterDecisions; }
  get disassembly():     DisassembledInstruction[] { return this.core.disassembly; }
  get currentOffset():   number                    { return this.core.currentOffset; }
  get currentLength():   number                    { return this.core.currentLength; }

  // ── Single step ────────────────────────────────────────────────────────────

  /**
   * Run one analysis iteration.
   * When `shouldContinue === false`, all post-processing is executed and
   * included in `step.postProcessing`.
   */
  async step(): Promise<NestStepResult> {
    const coreResult: NestIterationResult = await this.core.runOne();

    let postProcessing: NestPostProcessingResult | undefined;
    if (!coreResult.shouldContinue) {
      postProcessing = this.runPostProcessing();
    }

    const stepResult: NestStepResult = { ...coreResult, postProcessing };
    this.opts.onIteration?.(stepResult);
    return stepResult;
  }

  // ── Full automated loop ────────────────────────────────────────────────────

  /**
   * Run all iterations until convergence, plateau, max-reached, or stopped.
   * Returns the complete session result including post-processing.
   */
  async run(delayMs?: number): Promise<NestSessionResult> {
    const ms = delayMs ?? this.opts.delay ?? 0;
    let keepGoing = true;

    while (keepGoing) {
      if (this.opts.shouldStop?.()) break;
      const step = await this.step();
      keepGoing = step.shouldContinue;
      if (keepGoing && ms > 0) {
        await new Promise<void>(r => setTimeout(r, ms));
      }
    }

    // Ensure post-processing ran (e.g. stopped externally before converging)
    const pp = this.runPostProcessing();
    const sess = this.core.session;

    return {
      session:             sess,
      summary:             summarizeSession(sess),
      learningSession:     this.core.learningSession,
      iterDecisions:       this.core.iterDecisions,
      learningRecord:      pp.learningRecord,
      similarBinaries:     pp.similarBinaries,
      echoHints:           pp.echoHints,
      strategyReliability: pp.strategyReliability,
      dominance:           pp.dominance,
      weaknessFlags:       pp.weaknessFlags,
      verdictFlipCount:    pp.verdictFlipCount,
      crossBinaryReport:   pp.crossBinaryReport,
      diagReport:          pp.diagReport,
      healResult:          pp.healResult,
      healedConfig:        pp.healedConfig,
      trainingRecords:     pp.trainingRecords,
      trainingStats:       pp.trainingStats,
    };
  }

  // ── Post-processing (idempotent) ──────────────────────────────────────────

  private runPostProcessing(): NestPostProcessingResult {
    if (this.cachedPP) return this.cachedPP;
    this.cachedPP = this.postProcess();
    return this.cachedPP;
  }

  private postProcess(): NestPostProcessingResult {
    const { filePath, metadata, config } = this.opts;
    const sess  = this.core.session;
    const lsess = this.core.learningSession;

    // ── 1. Save learning session ─────────────────────────────────────────────
    saveLearningSession(lsess);

    // ── 2. Record strategy outcomes globally ─────────────────────────────────
    const outcomes = lsess.decisions.flatMap(d =>
      d.strategyAdjustments.map(sa => ({
        strategyClass:  sa.strategyType as StrategyClass,
        wasEffective:   sa.wasEffective,
        compositeDelta: d.breakdown.composite,
      }))
    );
    if (outcomes.length > 0) recordStrategyOutcomes(outcomes);
    const strategyReliability = getStrategyReliability();

    // ── 3. Record binary session in learning store ────────────────────────────
    const finalHash = metadata?.sha256 ?? null;
    let learningRecord: BinaryLearningRecord | null = null;
    let similarBinaries: SimilarBinary[]            = [];
    let echoHints: string[]                         = [];

    const lastSnap = sess.iterations[sess.iterations.length - 1] ?? null;

    if (finalHash && lastSnap) {
      const historyData = sess.iterations.map(it => ({
        iteration:      it.iteration,
        timestamp:      it.timestamp,
        confidence:     it.confidence,
        classification: it.verdict.classification,
        signalIds:      it.verdict.signals.map(s => s.id),
      }));
      recordBinarySession({
        hash:           finalHash,
        fileName:       filePath.split(/[\\/]/).pop() ?? filePath,
        classification: lastSnap.verdict.classification,
        confidence:     lastSnap.verdict.confidence,
        signals:        lastSnap.verdict.signals,
        behaviors:      lastSnap.verdict.behaviors,
        verdictHistory: buildVerdictHistory(historyData),
      });
      learningRecord  = getLearningRecord(finalHash);
      similarBinaries = getSimilarBinaries(lastSnap.verdict.signals.map(s => s.id), finalHash);
      echoHints       = getEchoEnhancements(finalHash);
    }

    // ── 4. Dominance assessment ───────────────────────────────────────────────
    const da = assessDominance(sess, lsess);
    if (finalHash) {
      saveDominanceAssessment(finalHash, filePath.split(/[\\/]/).pop() ?? filePath, da);
    }

    // ── 5. Cross-binary advisor ───────────────────────────────────────────────
    const crossBinaryReport = buildCrossBinaryReport(config);

    // ── 6. Diagnostics ────────────────────────────────────────────────────────
    const verdictFlipCount = countVerdictFlips(sess.iterations);
    const weaknessFlags    = detectWeaknessFlags(sess.iterations, da.status);
    const diagReport       = runDiagnostics(sess, da.status, weaknessFlags, verdictFlipCount);

    // ── 7. Adaptive healer ────────────────────────────────────────────────────
    const recent     = getRecentRecords(10);
    const healResult = heal(diagReport, config, recent);
    const healedConfig = healResult.changed ? healResult.config : config;

    // ── 8. Training store ─────────────────────────────────────────────────────
    const traceHistory = diagReport.trace.map(t => ({
      iteration:      t.iteration,
      confidence:     t.confidence,
      loss:           100 - t.confidence,
      contradictions: t.contradictions,
      signalCount:    t.signalCount,
      verdictClass:   t.verdictClass,
    }));
    appendTrainingRecord(buildTrainingRecord({
      sessionId:         sess.id,
      binaryPath:        filePath,
      outcome:           diagReport.outcome,
      outcomeConfidence: diagReport.diagnosticConfidence,
      outcomeReason:     diagReport.outcomeReason,
      iterationHistory:  traceHistory,
      fixesApplied:      healResult.fixes,
      configUsed:        config,
      configAfter:       healResult.changed ? healResult.config : null,
      dimensionScores: {
        progression:    diagReport.dimensions.progression.score,
        contradictions: diagReport.dimensions.contradictions.score,
        convergence:    diagReport.dimensions.convergence.score,
        depth:          diagReport.dimensions.depth.score,
      },
      finalConfidence:  diagReport.summary.finalConfidence,
      totalGain:        diagReport.summary.totalGain,
      verdictFlipCount,
      stabilityScore:   diagReport.summary.stabilityScore,
    }));
    const trainingRecords = getRecentRecords(50);
    const trainingStats   = computeTrainingStats();

    return {
      learningRecord,
      similarBinaries,
      echoHints,
      strategyReliability,
      dominance:        da,
      weaknessFlags,
      verdictFlipCount,
      crossBinaryReport,
      diagReport,
      healResult,
      healedConfig,
      trainingRecords,
      trainingStats,
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// runNestSession — one-call entrypoint
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Run a complete NEST session on a binary file.
 *
 * Automatically fetches metadata and initial disassembly if not supplied.
 * Runs the full analysis loop and all post-processing.
 * Returns a comprehensive `NestSessionResult`.
 *
 * @param filePath  Path to the binary to analyse.
 * @param config    NEST configuration (use DEFAULT_NEST_CONFIG if unsure).
 * @param opts      Optional overrides — callbacks, pre-fetched data, etc.
 */
export async function runNestSession(
  filePath: string,
  config:   NestConfig,
  opts:     Partial<NestSessionRunnerOptions> = {},
): Promise<NestSessionResult> {
  const backend = opts.backend ?? tauriBackend;

  // ── Auto-fetch metadata and initial disassembly ───────────────────────────
  let metadata           = opts.metadata ?? null;
  let initialDisassembly = opts.initialDisassembly ?? [];
  let initialOffset      = opts.initialOffset ?? 0;
  let initialLength      = opts.initialLength ?? config.disasmExpansion * 2;

  if (!metadata) {
    try { metadata = await backend.inspectMetadata(filePath); } catch { /* proceed without */ }
  }

  if (initialDisassembly.length === 0) {
    try {
      const res      = await backend.disassembleRange(filePath, initialOffset, initialLength);
      initialDisassembly = res.instructions;
    } catch { /* proceed with empty */ }
  }

  const runner = new NestSessionRunner({
    filePath,
    config,
    backend,
    metadata,
    initialDisassembly,
    initialOffset,
    initialLength,
    strings:             opts.strings,
    disassemblyAnalysis: opts.disassemblyAnalysis,
    strikeSignals:       opts.strikeSignals,
    echoHints:           opts.echoHints,
    strategyReliability: opts.strategyReliability,
    onIteration:         opts.onIteration,
    shouldStop:          opts.shouldStop,
    delay:               opts.delay,
  });

  return runner.run();
}
