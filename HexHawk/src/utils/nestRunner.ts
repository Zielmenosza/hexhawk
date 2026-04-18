/**
 * nestRunner — headless NEST session runner
 *
 * Contains all analysis loop logic extracted from NestView.tsx.
 * Has no React, no DOM, no Tauri-specific imports.
 *
 * Backend calls (disassemble, buildCfg, inspectMetadata) are routed through
 * a NestBackend implementation:
 *   • In the UI:  TauriNestBackend  (invokes Tauri commands)
 *   • In the CLI: ChildProcessNestBackend  (spawns nest_cli binary)
 *
 * Usage — full automated loop:
 *   const runner = new NestSessionRunner(opts);
 *   const result = await runner.run();
 *
 * Usage — manual step-by-step (for "Next" button in the UI):
 *   const runner = new NestSessionRunner(opts);
 *   const step   = await runner.runOne();   // first iteration
 *   if (step.shouldContinue) ...            // render then call again
 */

import {
  createNestSession,
  runCorrelationPass,
  evaluateUncertainty,
  buildIterationSnapshot,
  finalizeSession,
  selectNextDisasmRange,
  summarizeSession,
  type NestConfig,
  type NestSession,
  type NestIterationInput,
  type NestIterationSnapshot,
  type NestSummary,
} from './nestEngine';
import {
  echoScan,
  extractCorrelationSignals as extractEchoSignals,
  type EchoContext,
} from './echoEngine';
import {
  talonDecompile,
  extractCorrelationSignals as extractTalonSignals,
} from './talonEngine';
import { scanSignatures } from './signatureEngine';
import {
  extractCfgSignals,
  type CfgAnalysisSummary,
} from './cfgSignalExtractor';
import {
  buildAnalysisPlan,
  type AnalysisPlan,
  type StrategyClass,
} from './strategyEngine';
import {
  buildLearningDecision,
  createLearningSession,
  applyDecisionToSession,
  finalizeLearningSession,
  type LearningSession,
  type LearningDecision,
} from './iterationLearning';
import { applyLearningBoost, type LearningBoosts } from './learningStore';
import type { NestBackend } from './nestBackend';
import type {
  FileMetadata,
  SuspiciousPattern,
  DisassembledInstruction,
  DisassemblyAnalysis,
} from '../App';
import type { StrikeCorrelationSignal } from './strikeEngine';

// ── Public types ───────────────────────────────────────────────────────────────

/** Data returned after each completed iteration from runOne(). */
export interface NestIterationResult {
  /** The completed iteration snapshot. */
  snapshot:        NestIterationSnapshot;
  /** Session state after this iteration (finalized when shouldContinue=false). */
  session:         NestSession;
  /** Meta-learning decision made for this iteration. */
  decision:        LearningDecision;
  /** Updated (and finalized when shouldContinue=false) learning session. */
  learningSession: LearningSession;
  /** Strategy plan for the NEXT iteration (null when stopping). */
  analysisPlan:    AnalysisPlan | null;
  /** Learning confidence boosts applied to the verdict, or null. */
  boosts:          LearningBoosts | null;
  /** Whether the caller should keep iterating. */
  shouldContinue:  boolean;
}

/** Final result returned from run(). */
export interface NestRunResult {
  session:         NestSession;
  summary:         NestSummary;
  learningSession: LearningSession;
  iterDecisions:   LearningDecision[];
}

/** Options passed to NestSessionRunner constructor. */
export interface NestRunnerOptions {
  /** Path to the binary file being analysed. */
  filePath:            string;
  config:              NestConfig;
  backend:             NestBackend;
  metadata:            FileMetadata | null;
  initialDisassembly:  DisassembledInstruction[];
  initialOffset:       number;
  initialLength:       number;
  strings:             Array<{ text: string }>;
  disassemblyAnalysis: DisassemblyAnalysis;
  strikeSignals?:      StrikeCorrelationSignal;
  /** ECHO hints from learningStore.getEchoEnhancements(). */
  echoHints?:          string[];
  /** Strategy reliability from learningStore.getStrategyReliability(). */
  strategyReliability?: Partial<Record<StrategyClass, number>>;
  /** Resume an existing partial session (UI manual-advance use case). */
  existingSession?:    NestSession;
  existingLearningSession?: LearningSession;
  existingDecisions?:  LearningDecision[];
  /**
   * Called after each iteration completes — useful for streaming progress.
   * The UI uses this to update React state; the CLI uses it to log progress.
   */
  onIteration?:        (result: NestIterationResult) => void;
  /**
   * Provide learning confidence boosts for a verdict.
   * Omit for headless / CLI runs where localStorage is unavailable.
   */
  getBoosts?:          (hash: string | null, signalIds: string[]) => LearningBoosts | null;
  /**
   * Return true to stop the loop early (checked before each iteration).
   * Wire this to a stopRef in the UI, or to a signal in the CLI.
   */
  shouldStop?:         () => boolean;
}

// ── NestSessionRunner ─────────────────────────────────────────────────────────

/**
 * Runs a NEST self-improving analysis session.
 *
 * Holds all mutable iteration state internally so callers can drive it
 * step-by-step (runOne — for UI manual advance) or all-at-once (run — for
 * automated / CLI batch use).
 */
export class NestSessionRunner {
  private sess:      NestSession;
  private instrs:    DisassembledInstruction[];
  private offset:    number;
  private length:    number;
  private lsess:     LearningSession;
  private decisions: LearningDecision[];

  constructor(private readonly opts: NestRunnerOptions) {
    this.instrs    = [...opts.initialDisassembly];
    this.offset    = opts.initialOffset;
    this.length    = opts.initialLength;
    this.decisions = opts.existingDecisions ? [...opts.existingDecisions] : [];

    if (opts.existingSession) {
      this.sess  = opts.existingSession;
      this.lsess = opts.existingLearningSession
        ?? createLearningSession(opts.metadata?.sha256 ?? opts.filePath);
    } else {
      this.sess  = createNestSession(opts.filePath, opts.config);
      this.lsess = createLearningSession(opts.metadata?.sha256 ?? opts.filePath);
    }
  }

  // ── Accessors ──────────────────────────────────────────────────────────────

  get session():         NestSession              { return this.sess;      }
  get learningSession(): LearningSession           { return this.lsess;     }
  get iterDecisions():   LearningDecision[]        { return this.decisions; }
  get disassembly():     DisassembledInstruction[] { return this.instrs;    }
  get currentOffset():   number                    { return this.offset;    }
  get currentLength():   number                    { return this.length;    }

  // ── Core single-iteration logic ────────────────────────────────────────────

  /**
   * Run a single analysis iteration and return the result.
   * When shouldContinue=false the session and learning session are finalized.
   */
  async runOne(): Promise<NestIterationResult> {
    const { opts } = this;
    const {
      filePath, config, backend, metadata, strings,
      disassemblyAnalysis, strikeSignals,
    } = opts;

    const sess      = this.sess;
    const instrs    = this.instrs;
    const offset    = this.offset;
    const length    = this.length;
    const iterStart = Date.now();
    const iterIndex = sess.iterations.length;
    const fnMap     = disassemblyAnalysis.functions;

    // ── 1. Signature scan ───────────────────────────────────────────────────
    const sigResult = scanSignatures(instrs, fnMap);

    // ── 2. ECHO scan ────────────────────────────────────────────────────────
    const echoCtx: EchoContext = {
      imports:         (metadata?.imports ?? []).map(i => i.name),
      strings:         strings.map(s => s.text),
      knownSigMatches: [
        ...sigResult.matches.map(m => m.signature.id),
        ...(opts.echoHints ?? []),
      ],
    };
    const echoResult  = echoScan(instrs, echoCtx, fnMap);
    const echoSignals = extractEchoSignals(echoResult);

    // ── 3. TALON pass ───────────────────────────────────────────────────────
    let talonSignals = undefined;
    if (config.enableTalon && instrs.length > 0) {
      try {
        const tr = talonDecompile(instrs, null, {});
        talonSignals = extractTalonSignals(tr.summary ? [tr.summary] : []);
      } catch { /* non-fatal */ }
    }

    // ── 4. CFG analysis (backend call) ──────────────────────────────────────
    let cfgPatterns: SuspiciousPattern[] = [];
    let cfgSummary: CfgAnalysisSummary | undefined;
    if (instrs.length > 0) {
      try {
        const cfgGraph = await backend.buildCfg(filePath, offset, length);
        const cfgResult = extractCfgSignals(cfgGraph);
        cfgPatterns = cfgResult.patterns;
        cfgSummary  = cfgResult.summary;
      } catch { /* non-fatal */ }
    }

    // ── 5. Build iteration input ────────────────────────────────────────────
    const input: NestIterationInput = {
      disasmOffset:     offset,
      disasmLength:     length,
      instructionCount: instrs.length,
      sections:         metadata?.sections ?? [],
      imports:          metadata?.imports  ?? [],
      strings:          strings.map(s => ({ text: s.text })),
      patterns:         disassemblyAnalysis.suspiciousPatterns,
      signatureMatches: sigResult.matches,
      talonSignals,
      strikeSignals:    config.enableStrike ? strikeSignals : undefined,
      echoSignals,
      cfgPatterns,
      cfgSummary,
      iterationIndex:   iterIndex,
    };

    // ── 6. Correlation pass + learning boosts ────────────────────────────────
    const rawVerdict = runCorrelationPass(input);
    const hash       = metadata?.sha256 ?? null;
    const boosts     = opts.getBoosts?.(hash, rawVerdict.signals.map(s => s.id)) ?? null;
    const verdict    = boosts ? applyLearningBoost(rawVerdict, boosts) : rawVerdict;

    // ── 7. Convergence evaluation ────────────────────────────────────────────
    const uncertainty = evaluateUncertainty(sess, verdict);

    // ── 8. Strategy plan (only if continuing) ────────────────────────────────
    const analysisPlan: AnalysisPlan | null = uncertainty.shouldStop
      ? null
      : buildAnalysisPlan({
          iteration:          iterIndex,
          currentVerdict:     verdict,
          history:            sess.iterations,
          currentInput:       input,
          disasmOffset:       offset,
          disasmLength:       length,
          maxIterations:      config.maxIterations,
          strikeAvailable:    config.enableStrike,
          talonEnabled:       config.enableTalon,
          aggressiveness:     config.aggressiveness,
          learnedReliability: opts.strategyReliability ?? {},
        });

    // Convert AnalysisPlan → NestRefinementPlan shape for snapshot storage
    const plan = analysisPlan
      ? {
          actions:       analysisPlan.actions.map(a => ({
            type:     'expand-disasm-forward' as const,
            priority: (a.priority === 'critical' ? 'high' : a.priority) as 'high' | 'medium' | 'low',
            offset:   a.offset,
            length:   a.length,
            reason:   a.rationale,
            signal:   a.sourceId,
          })),
          rationale:     analysisPlan.rationale,
          expectedBoost: analysisPlan.totalExpectedGain,
          primaryAction: analysisPlan.actions[0]
            ? {
                type:     'expand-disasm-forward' as const,
                priority: (analysisPlan.actions[0].priority === 'critical'
                  ? 'high' : analysisPlan.actions[0].priority) as 'high' | 'medium' | 'low',
                offset:   analysisPlan.actions[0].offset,
                length:   analysisPlan.actions[0].length,
                reason:   analysisPlan.actions[0].rationale,
                signal:   analysisPlan.actions[0].sourceId,
              }
            : null,
        }
      : null;

    // ── 9. Snapshot + meta-learning ──────────────────────────────────────────
    const prev      = sess.iterations[sess.iterations.length - 1] ?? null;
    const snapshot  = buildIterationSnapshot(iterIndex, input, verdict, prev, plan, iterStart);
    const decision  = buildLearningDecision(snapshot, prev, this.lsess);
    const updatedLS = applyDecisionToSession(this.lsess, decision);
    this.lsess      = updatedLS;
    this.decisions  = [
      ...this.decisions.filter(d => d.iteration !== decision.iteration),
      decision,
    ];

    // ── 10. Update session ────────────────────────────────────────────────────
    this.sess = { ...sess, iterations: [...sess.iterations, snapshot] };

    // ── 11. Determine stop or continue ───────────────────────────────────────
    const externalStop  = opts.shouldStop?.() ?? false;
    const shouldContinue = !uncertainty.shouldStop && !externalStop;

    if (!shouldContinue) {
      const status =
        uncertainty.reason === 'confidence-threshold' ? 'converged' :
        uncertainty.reason === 'plateau'              ? 'plateau'   : 'max-reached';
      this.sess  = finalizeSession(this.sess, status);
      this.lsess = finalizeLearningSession(this.lsess);
    }

    const result: NestIterationResult = {
      snapshot,
      session:         this.sess,
      decision,
      learningSession: this.lsess,
      analysisPlan,
      boosts,
      shouldContinue,
    };

    opts.onIteration?.(result);

    // ── 12. Expand disassembly for next iteration (backend call) ─────────────
    if (shouldContinue && plan) {
      const rangeReq = analysisPlan?.disasmRequest
        ? { offset: analysisPlan.disasmRequest.offset, length: analysisPlan.disasmRequest.length }
        : selectNextDisasmRange(plan, { offset, length }, config);
      try {
        const response = await backend.disassembleRange(filePath, rangeReq.offset, rangeReq.length);
        const merged   = new Map<number, DisassembledInstruction>(
          this.instrs.map(i => [i.address, i]),
        );
        for (const instr of response.instructions) {
          merged.set(instr.address, instr);
        }
        this.instrs = Array.from(merged.values()).sort((a, b) => a.address - b.address);
        this.offset = Math.min(offset, rangeReq.offset);
        this.length = this.instrs.length * 4;
      } catch { /* expansion failed — keep current coverage */ }
    }

    return result;
  }

  // ── Full automated loop ────────────────────────────────────────────────────

  /**
   * Run all iterations until convergence, plateau, max-reached, or stopped.
   * Intended for automated (CLI / batch) use. Pass delayMs > 0 to throttle.
   */
  async run(delayMs = 0): Promise<NestRunResult> {
    let keepGoing = true;

    while (keepGoing) {
      if (this.opts.shouldStop?.()) break;
      const result = await this.runOne();
      keepGoing = result.shouldContinue;
      if (keepGoing && delayMs > 0) {
        await new Promise<void>(r => setTimeout(r, delayMs));
      }
    }

    // Ensure finalized even if stopped externally
    if (this.sess.status === 'running' || this.sess.status === 'idle') {
      this.sess  = finalizeSession(this.sess, 'max-reached');
      this.lsess = finalizeLearningSession(this.lsess);
    }

    return {
      session:         this.sess,
      summary:         summarizeSession(this.sess),
      learningSession: this.lsess,
      iterDecisions:   this.decisions,
    };
  }
}
