/**
 * strategyEngine — Autonomous Analysis Strategy Planner
 *
 * Answers the question: "Given what we know and where confidence is low,
 * HOW should HexHawk analyse further?"
 *
 * Unlike the simple heuristic rules in nestEngine.generateRefinementPlan,
 * strategyEngine reasons about:
 *   - WHY confidence is low (low-confidence area taxonomy)
 *   - WHAT strategy class addresses each root cause
 *   - WHICH specific action to execute next (ordered, ranked)
 *   - WHEN to trigger expensive operations (STRIKE, TALON deep)
 *   - HOW MUCH improvement to expect (calibrated per strategy)
 *
 * Key concepts:
 *   LowConfidenceArea   — a labelled region of uncertainty with a root cause
 *   StrategyClass       — the high-level approach to address that root cause
 *   StrategyAction      — a concrete, executable step
 *   AnalysisPlan        — ordered set of StrategyActions with full rationale
 *
 * Integration:
 *   NestView calls `buildAnalysisPlan(ctx)` at the end of each iteration
 *   instead of nestEngine.generateRefinementPlan.  nestEngine is still used
 *   for the iteration delta / snapshot infrastructure.
 */

import type {
  BinaryVerdictResult,
  BehavioralTag,
  CorrelatedSignal,
  Contradiction,
  AlternativeHypothesis,
} from './correlationEngine';
import type { NestIterationSnapshot, NestIterationInput } from './nestEngine';
import type { AggressivenessLevel } from './nestEngine';

// ── Low-confidence area taxonomy ──────────────────────────────────────────────

/**
 * Root causes of low confidence / uncertainty. Each maps to one or more
 * strategy classes.
 */
export type LowConfidenceCause =
  | 'insufficient-coverage'     // too few instructions disassembled
  | 'uncorroborated-signal'     // signal fires but nothing else confirms it
  | 'unresolved-contradiction'  // two signals actively disagree
  | 'opaque-control-flow'       // indirect jumps, computed calls, obfuscation
  | 'packed-or-encrypted'       // high entropy section, possible packer
  | 'missing-runtime-context'   // behavior only visible at runtime
  | 'unexplored-function'       // suspicious function not yet disassembled
  | 'weak-string-evidence'      // strings suggest threat but no code seen
  | 'weak-import-evidence'      // dangerous import present but no caller found
  | 'alternative-hypothesis'    // competing classification with similar evidence
  | 'low-instruction-density';  // wide offset range but few instructions (padding / data)

export interface LowConfidenceArea {
  cause:       LowConfidenceCause;
  severity:    'critical' | 'high' | 'medium' | 'low';
  /** Human-readable description of what is uncertain */
  description: string;
  /** Signal ID or section name that triggered this area */
  sourceId?:   string;
  /** Binary offset that this area is centred on, if known */
  offset?:     number;
  /** Confidence penalty this area is estimated to be causing (0–30) */
  confidencePenalty: number;
}

// ── Strategy classes ──────────────────────────────────────────────────────────

export type StrategyClass =
  | 'expand-coverage'         // disassemble more of the binary
  | 'focus-cfg-region'        // follow specific CFG paths, resolve indirect jumps
  | 'deep-string-scan'        // re-scan strings with wider/deeper patterns
  | 'trigger-strike'          // request STRIKE runtime execution trace
  | 'isolate-function'        // deep-dive a specific suspicious function
  | 'resolve-contradiction'   // add evidence to break a signal tie
  | 'entropy-investigation'   // probe high-entropy regions for packer/crypto
  | 'import-caller-hunt'      // find code that calls a dangerous import
  | 'talon-deep'              // run TALON with full decompile on a region
  | 'echo-retune'             // re-run ECHO with context from new findings
  | 'alternative-dismissal';  // gather evidence to reject an alternative hypothesis

// ── Strategy actions ──────────────────────────────────────────────────────────

export interface StrategyAction {
  /** Unique id for this action within the plan (for dedup / tracking) */
  id:            string;
  strategy:      StrategyClass;
  /** Directly addresses this low-confidence area */
  addressesCause: LowConfidenceCause;
  priority:      'critical' | 'high' | 'medium' | 'low';
  /** Short imperative label, e.g. "Expand disassembly forward 1 KB" */
  label:         string;
  /** Full explanation of why this action is chosen */
  rationale:     string;
  /** Binary offset to act on, if applicable */
  offset?:       number;
  /** Byte length to process at `offset` */
  length?:       number;
  /** Signal/section/import ID that motivated this action */
  sourceId?:     string;
  /** Estimated confidence gain if this action yields new evidence (0–20) */
  expectedGain:  number;
  /**
   * Cost tier — used to decide whether to run now or defer.
   *   cheap   : pure TypeScript, <5 ms (re-run ECHO, re-scan strings)
   *   moderate: Tauri invoke needed (expand disassembly, CFG query)
   *   expensive: heavy computation (TALON deep, STRIKE execution)
   */
  cost:          'cheap' | 'moderate' | 'expensive';
  /**
   * Prerequisite action IDs that should complete before this one.
   * Empty = can run immediately.
   */
  prerequisites: string[];
}

// ── Analysis plan ─────────────────────────────────────────────────────────────

export interface AnalysisPlan {
  /** Ordered list of actions (primary first, then supporting) */
  actions:              StrategyAction[];
  /** Root cause areas identified in the current iteration */
  lowConfidenceAreas:   LowConfidenceArea[];
  /** Primary strategy chosen (highest-priority action's class) */
  primaryStrategy:      StrategyClass;
  /** Narrative explanation of the plan */
  rationale:            string;
  /** Sum of expectedGain for all actions, capped at 30 */
  totalExpectedGain:    number;
  /** Should STRIKE be requested this iteration? */
  requestStrike:        boolean;
  /** Disassembly range request for the next iteration (offset + length) */
  disasmRequest:        { offset: number; length: number; reason: string } | null;
  /**
   * Per-strategy breakdown for the UI (how many actions per class)
   */
  strategySummary:      Partial<Record<StrategyClass, number>>;
}

// ── Strategy context (input) ──────────────────────────────────────────────────

export interface StrategyContext {
  /** Current iteration index (0-based) */
  iteration:        number;
  /** The verdict from the most recent correlation pass */
  currentVerdict:   BinaryVerdictResult;
  /** Full snapshot history (all previous iterations) */
  history:          NestIterationSnapshot[];
  /** The input that produced currentVerdict */
  currentInput:     NestIterationInput;
  /** Current disassembly window */
  disasmOffset:     number;
  disasmLength:     number;
  /** Max iterations configured */
  maxIterations:    number;
  /** Whether STRIKE is available/enabled */
  strikeAvailable:  boolean;
  /** Whether TALON is enabled */
  talonEnabled:     boolean;
  /** How aggressively to expand and trigger expensive operations */
  aggressiveness:   AggressivenessLevel;
  /**
   * Per-strategy reliability scores (0–1) from historical cross-binary data.
   * Strategies with reliability < 0.4 have their expectedGain discounted;
   * strategies with reliability > 0.7 get a small bonus.
   * Omit to use neutral weighting (no history yet).
   */
  learnedReliability?: Partial<Record<StrategyClass, number>>;
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Main entry point ─────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Build the next-iteration analysis plan.
 * This is the core of the strategy engine.
 *
 * Pipeline:
 *   1. Identify low-confidence areas (diagnose root causes)
 *   2. Rank areas by severity × penalty
 *   3. For each area, choose the best strategy
 *   4. Convert strategies into concrete actions
 *   5. Deduplicate, sort by priority
 *   6. Derive disasmRequest, requestStrike, strategySummary
 */
export function buildAnalysisPlan(ctx: StrategyContext): AnalysisPlan {
  // Step 1 — Diagnose
  const areas = diagnoseUncertainty(ctx);

  // Step 2 — Sort areas by impact
  const pOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  areas.sort((a, b) =>
    pOrder[a.severity] - pOrder[b.severity] ||
    b.confidencePenalty - a.confidencePenalty,
  );

  // Step 3 & 4 — Map to actions
  const rawActions = areas.flatMap(area => buildActionsForArea(area, ctx));

  // Step 5 — Dedup by id, sort by priority
  const seen     = new Set<string>();
  const actions: StrategyAction[] = [];
  for (const a of rawActions) {
    if (!seen.has(a.id)) { seen.add(a.id); actions.push(a); }
  }
  actions.sort((a, b) => pOrder[a.priority] - pOrder[b.priority] || b.expectedGain - a.expectedGain);

  // Step 5b — Adjust expectedGain using historical strategy reliability
  if (ctx.learnedReliability) {
    for (const action of actions) {
      const rel = ctx.learnedReliability[action.strategy];
      if (rel === undefined) continue;
      // rel < 0.4 → discount gain by up to 50%; rel > 0.7 → bonus up to 20%
      const mult = rel < 0.4
        ? 0.5 + rel * 1.25                    // 0.5 – 1.0 at rel 0–0.4
        : rel > 0.7
          ? 1.0 + (rel - 0.7) * 0.67          // 1.0 – 1.2 at rel 0.7–1.0
          : 1.0;
      action.expectedGain = Math.round(action.expectedGain * mult);
    }
    // Re-sort after gain adjustments (priority ties broken by updated gain)
    actions.sort((a, b) => pOrder[a.priority] - pOrder[b.priority] || b.expectedGain - a.expectedGain);
  }

  // Step 6 — Derive plan metadata
  const primaryAction   = actions[0] ?? null;
  const primaryStrategy = primaryAction?.strategy ?? 'expand-coverage';
  const requestStrike   = actions.some(a => a.strategy === 'trigger-strike');
  const totalGain       = Math.min(30, actions.reduce((s, a) => s + a.expectedGain, 0));
  const disasmRequest   = deriveDisasmRequest(actions, ctx);
  const rationale       = buildRationale(areas, primaryAction, ctx);

  const strategySummary: Partial<Record<StrategyClass, number>> = {};
  for (const a of actions) {
    strategySummary[a.strategy] = (strategySummary[a.strategy] ?? 0) + 1;
  }

  return {
    actions,
    lowConfidenceAreas:   areas,
    primaryStrategy,
    rationale,
    totalExpectedGain:    totalGain,
    requestStrike,
    disasmRequest,
    strategySummary,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Step 1: Diagnose low-confidence areas ────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

function diagnoseUncertainty(ctx: StrategyContext): LowConfidenceArea[] {
  const areas: LowConfidenceArea[] = [];
  const { currentVerdict: v, currentInput: inp, iteration, history, disasmOffset, disasmLength, talonEnabled, aggressiveness } = ctx;
  const currentEnd = disasmOffset + disasmLength;

  // Aggressiveness-adjusted thresholds
  // conservative: higher instruction bar → less likely to fire coverage area
  // aggressive: lower bar → fires earlier, pushes harder
  const coverageMultiplier = aggressiveness === 'aggressive' ? 1.5 : aggressiveness === 'conservative' ? 0.6 : 1.0;
  const signalWeightMin    = aggressiveness === 'conservative' ? 6 : aggressiveness === 'aggressive' ? 3 : 4;
  const entropyThreshold   = aggressiveness === 'aggressive' ? 6.2 : aggressiveness === 'conservative' ? 7.2 : 6.8;

  // ── 1. Insufficient coverage ───────────────────────────────────────────────
  const expectedInstructions = Math.round((40 + iteration * 30) * coverageMultiplier);
  if (inp.instructionCount < expectedInstructions) {
    const deficit = expectedInstructions - inp.instructionCount;
    areas.push({
      cause:             'insufficient-coverage',
      severity:          deficit > 60 ? 'high' : 'medium',
      description:       `Only ${inp.instructionCount} instructions analysed (expected ≥${expectedInstructions} at iteration ${iteration + 1})`,
      confidencePenalty: Math.min(15, Math.ceil(deficit / 6)),
    });
  }

  // ── 2. Uncorroborated signals (weight ≥ 4, zero corroborators) ────────────
  const uncorrob = v.signals.filter(s => s.corroboratedBy.length === 0 && s.weight >= 4);
  for (const sig of uncorrob.slice(0, 3)) {
    areas.push({
      cause:             'uncorroborated-signal',
      severity:          sig.weight >= 7 ? 'critical' : sig.weight >= 5 ? 'high' : 'medium',
      description:       `Signal '${sig.id}' (weight ${sig.weight}) has no corroboration — verdict rests on a single source`,
      sourceId:          sig.id,
      confidencePenalty: sig.weight * 2,
    });
  }

  // ── 3. Unresolved contradictions ───────────────────────────────────────────
  for (const contra of (v.contradictions ?? []).slice(0, 2)) {
    areas.push({
      cause:             'unresolved-contradiction',
      severity:          contra.severity === 'high' ? 'critical' : contra.severity === 'medium' ? 'high' : 'medium',
      description:       `Contradiction '${contra.id}': ${contra.observation} conflicts with ${contra.conflict}`,
      sourceId:          contra.id,
      confidencePenalty: contra.severity === 'high' ? 12 : contra.severity === 'medium' ? 7 : 4,
    });
  }

  // ── 4. Opaque control flow (indirect jumps in instruction stream) ──────────
  const indirectJumps = inp.patterns.filter(p =>
    /indirect|computed|obfuscat|jmp.*reg|call.*reg/i.test(p.description),
  );
  if (indirectJumps.length > 0) {
    areas.push({
      cause:             'opaque-control-flow',
      severity:          'high',
      description:       `${indirectJumps.length} indirect/computed jump(s) detected — true control flow is not fully mapped`,
      sourceId:          indirectJumps[0].description,
      confidencePenalty: Math.min(10, indirectJumps.length * 3),
    });
  }

  // ── 5. High-entropy sections (packing / encryption) ───────────────────────
  for (const sec of inp.sections) {
    if (sec.entropy > entropyThreshold && sec.name !== '.rsrc' && sec.file_size > 256) {
      areas.push({
        cause:             'packed-or-encrypted',
        severity:          sec.entropy > 7.5 ? 'critical' : 'high',
        description:       `Section '${sec.name}' has entropy ${sec.entropy.toFixed(2)} — likely packed or encrypted code`,
        sourceId:          sec.name,
        confidencePenalty: sec.entropy > 7.5 ? 14 : 8,
      });
    }
  }

  // ── 6. Missing runtime context (injection / evasion behaviors without STRIKE) ─
  const runtimeBehaviors: BehavioralTag[] = ['code-injection', 'anti-analysis', 'dynamic-resolution'];
  const hasRuntimeNeed = v.behaviors.some(b => runtimeBehaviors.includes(b));
  const hasStrikeData  = !!inp.strikeSignals;
  if (hasRuntimeNeed && !hasStrikeData && ctx.strikeAvailable) {
    areas.push({
      cause:             'missing-runtime-context',
      severity:          'high',
      description:       `Behaviors ${v.behaviors.filter(b => runtimeBehaviors.includes(b)).join(', ')} detected but no runtime trace available`,
      confidencePenalty: 10,
    });
  }

  // ── 7. Unexplored suspicious functions ────────────────────────────────────
  // TalonCorrelationSignal has functionCount + uncertainRatio
  const talonFunctions = inp.talonSignals?.functionCount ?? 0;
  const uncertainRatio = inp.talonSignals?.uncertainRatio ?? 0;
  const unexplored = Math.round(talonFunctions * uncertainRatio);
  if (unexplored > 0 && talonEnabled) {
    areas.push({
      cause:             'unexplored-function',
      severity:          unexplored >= 3 ? 'high' : 'medium',
      description:       `${unexplored} of ${talonFunctions} function(s) have uncertain TALON analysis (${(uncertainRatio * 100).toFixed(0)}% ratio)`,
      confidencePenalty: Math.min(8, unexplored * 2),
    });
  }

  // ── 8. Weak string evidence ────────────────────────────────────────────────
  const suspStrings = inp.strings.filter(s =>
    /https?:\/\/|cmd\.exe|powershell|base64|regsvr|\\\\server|createprocess|eval\(/i.test(s.text),
  );
  const stringSignalIds = new Set(v.signals.filter(s => s.source === 'strings').map(s => s.id));
  if (suspStrings.length > 0 && stringSignalIds.size > 0) {
    // Strings fired signals — but is there any disassembly corroborating them?
    const disasmCorroborators = v.signals.filter(
      s => s.source === 'disassembly' &&
           [...stringSignalIds].some(id => s.corroboratedBy.includes(id)),
    );
    if (disasmCorroborators.length === 0) {
      areas.push({
        cause:             'weak-string-evidence',
        severity:          'medium',
        description:       `${suspStrings.length} suspicious string(s) fired signals but no disassembly yet confirms the code that uses them`,
        confidencePenalty: 5,
      });
    }
  }

  // ── 9. Dangerous imports with no caller found ──────────────────────────────
  const dangerousImports = inp.imports.filter(imp =>
    /VirtualAlloc|WriteProcessMemory|CreateRemoteThread|OpenProcess|WinExec|URLDownload|ShellExecute/i.test(imp.name),
  );
  if (dangerousImports.length > 0) {
    // Check if any disassembly signal references these imports
    const importSignals = v.signals.filter(s => s.source === 'imports');
    const callerFound   = v.signals.some(s =>
      s.source === 'disassembly' &&
      importSignals.some(is => s.corroboratedBy.includes(is.id) || is.corroboratedBy.includes(s.id)),
    );
    if (!callerFound) {
      areas.push({
        cause:             'weak-import-evidence',
        severity:          dangerousImports.length >= 3 ? 'high' : 'medium',
        description:       `${dangerousImports.length} dangerous import(s) present (${dangerousImports[0].name}…) but no call site found in disassembly`,
        sourceId:          dangerousImports[0].name,
        confidencePenalty: Math.min(10, dangerousImports.length * 3),
      });
    }
  }

  // ── 10. Alternative hypothesis with high probability ──────────────────────
  for (const alt of (v.alternatives ?? []).filter(a => a.probability >= 30).slice(0, 1)) {
    areas.push({
      cause:             'alternative-hypothesis',
      severity:          alt.probability >= 50 ? 'high' : 'medium',
      description:       `Alternative classification '${alt.label}' (${alt.probability}% probability) — requires additional evidence to dismiss`,
      confidencePenalty: Math.round(alt.probability / 5),
    });
  }

  // ── 11. Low instruction density (wide window, sparse code) ────────────────
  if (disasmLength > 0 && inp.instructionCount > 0) {
    const density = inp.instructionCount / (disasmLength / 4); // instr per 4-byte slot
    if (density < 0.25 && disasmLength > 1024) {
      areas.push({
        cause:             'low-instruction-density',
        severity:          'low',
        description:       `Low instruction density (${(density * 100).toFixed(0)}%) in current window — may contain data/padding, consider redirecting coverage`,
        confidencePenalty: 3,
      });
    }
  }

  // ── 12. Stagnation across history ─────────────────────────────────────────
  if (history.length >= 2) {
    const recentGain = history.slice(-2).reduce((sum, snap, i, arr) => {
      if (i === 0) return sum;
      return sum + (snap.confidence - arr[i - 1].confidence);
    }, 0);
    if (Math.abs(recentGain) < 2 && v.confidence < ctx.maxIterations * 10) {
      areas.push({
        cause:             'insufficient-coverage',
        severity:          'medium',
        description:       `Confidence stagnant for last 2 iterations (Δ${recentGain.toFixed(1)}%) — current strategy is not improving results`,
        confidencePenalty: 5,
      });
    }
  }

  // ── 13. Complex CFG — unexplored loops or indirect calls ──────────────────
  const cfg = inp.cfgSummary;
  if (cfg && cfg.totalBlocks > 0) {
    if (cfg.indirectCalls > 0 && v.confidence < 80) {
      areas.push({
        cause:             'opaque-control-flow',
        severity:          cfg.indirectCalls >= 3 ? 'high' : 'medium',
        description:       `CFG: ${cfg.indirectCalls} indirect call(s) — true targets unresolved, follow-cfg-path needed`,
        sourceId:          'cfg-indirect-calls',
        confidencePenalty: Math.min(12, cfg.indirectCalls * 3),
      });
    }
    if (cfg.unreachableBlocks > 0) {
      areas.push({
        cause:             'opaque-control-flow',
        severity:          'medium',
        description:       `CFG: ${cfg.unreachableBlocks} unreachable block(s) — possible obfuscated entry points or dead code injection`,
        sourceId:          'cfg-unreachable',
        confidencePenalty: Math.min(8, cfg.unreachableBlocks * 2),
      });
    }
    if (cfg.backEdges >= 3 && v.confidence < 75) {
      areas.push({
        cause:             'packed-or-encrypted',
        severity:          'medium',
        description:       `CFG: ${cfg.backEdges} back-edge(s) — dense loop structure may indicate scanning, decryption, or packing`,
        sourceId:          'cfg-loops',
        confidencePenalty: Math.min(6, cfg.backEdges),
      });
    }
  }

  return areas;
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Step 2: Map each area to StrategyActions ─────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

function buildActionsForArea(
  area: LowConfidenceArea,
  ctx:  StrategyContext,
): StrategyAction[] {
  const { currentInput: inp, disasmOffset, disasmLength, iteration, talonEnabled, aggressiveness } = ctx;
  const currentEnd = disasmOffset + disasmLength;
  const expansionMult = aggressiveness === 'aggressive' ? 2 : aggressiveness === 'conservative' ? 0.5 : 1;
  const baseExpand = Math.max(512, Math.round(disasmLength * expansionMult));

  switch (area.cause) {

    // ── Insufficient coverage ──────────────────────────────────────────────
    case 'insufficient-coverage': {
      const expandLen = baseExpand;
      return [{
        id:             `expand-fwd-${currentEnd}`,
        strategy:       'expand-coverage',
        addressesCause: 'insufficient-coverage',
        priority:       area.severity === 'high' ? 'high' : 'medium',
        label:          `Expand disassembly forward +${expandLen} bytes`,
        rationale:      area.description,
        offset:         currentEnd,
        length:         expandLen,
        expectedGain:   Math.min(10, area.confidencePenalty),
        cost:           'moderate',
        prerequisites:  [],
      }];
    }

    // ── Uncorroborated signal ──────────────────────────────────────────────
    case 'uncorroborated-signal': {
      const actions: StrategyAction[] = [];
      // Primary: ECHO retune to find fuzzy matches for this signal
      actions.push({
        id:             `echo-retune-${area.sourceId}`,
        strategy:       'echo-retune',
        addressesCause: 'uncorroborated-signal',
        priority:       area.severity === 'critical' ? 'critical' : 'high',
        label:          `Re-tune ECHO for signal '${area.sourceId}'`,
        rationale:      `${area.description} — ECHO fuzzy scan with lower threshold may find behavioural matches`,
        sourceId:       area.sourceId,
        expectedGain:   Math.min(8, area.confidencePenalty),
        cost:           'cheap',
        prerequisites:  [],
      });
      // Secondary: if TALON enabled, deep-analyse the function
      if (talonEnabled) {
        actions.push({
          id:             `talon-deep-${area.sourceId}`,
          strategy:       'talon-deep',
          addressesCause: 'uncorroborated-signal',
          priority:       area.severity === 'critical' ? 'high' : 'medium',
          label:          `TALON deep analysis for signal '${area.sourceId}'`,
          rationale:      `TALON decompilation of the code region may confirm or deny the signal`,
          sourceId:       area.sourceId,
          expectedGain:   Math.min(6, area.confidencePenalty - 2),
          cost:           'expensive',
          prerequisites:  [],
        });
      }
      return actions;
    }

    // ── Unresolved contradiction ───────────────────────────────────────────
    case 'unresolved-contradiction': {
      return [{
        id:             `resolve-contra-${area.sourceId}`,
        strategy:       'resolve-contradiction',
        addressesCause: 'unresolved-contradiction',
        priority:       area.severity === 'critical' ? 'critical' : 'high',
        label:          `Gather evidence to resolve contradiction '${area.sourceId}'`,
        rationale:      `${area.description} — expanding disassembly near the conflict site may provide the tie-breaking evidence`,
        sourceId:       area.sourceId,
        offset:         currentEnd,
        length:         disasmLength,
        expectedGain:   area.confidencePenalty,
        cost:           'moderate',
        prerequisites:  [],
      }];
    }

    // ── Opaque control flow ────────────────────────────────────────────────
    case 'opaque-control-flow': {
      const actions: StrategyAction[] = [];
      // Focus CFG to resolve indirect jumps
      actions.push({
        id:             `cfg-indirect-focus-${iteration}`,
        strategy:       'focus-cfg-region',
        addressesCause: 'opaque-control-flow',
        priority:       'high',
        label:          'Focus CFG analysis on indirect/computed jumps',
        rationale:      `${area.description} — expanding disassembly around computed jump targets resolves true control flow`,
        offset:         currentEnd,
        length:         1024,
        expectedGain:   area.confidencePenalty,
        cost:           'moderate',
        prerequisites:  [],
      });
      // If runtime context is available, STRIKE can trace the actual paths
      if (ctx.strikeAvailable) {
        actions.push({
          id:             'strike-indirect-trace',
          strategy:       'trigger-strike',
          addressesCause: 'opaque-control-flow',
          priority:       'high',
          label:          'Trigger STRIKE to trace indirect jump targets at runtime',
          rationale:      'Runtime execution trace resolves computed targets that static analysis cannot',
          expectedGain:   Math.min(12, area.confidencePenalty + 2),
          cost:           'expensive',
          prerequisites:  [`cfg-indirect-focus-${iteration}`],
        });
      }
      return actions;
    }

    // ── Packed / encrypted ─────────────────────────────────────────────────
    case 'packed-or-encrypted': {
      const actions: StrategyAction[] = [];
      actions.push({
        id:             `entropy-probe-${area.sourceId}`,
        strategy:       'entropy-investigation',
        addressesCause: 'packed-or-encrypted',
        priority:       area.severity === 'critical' ? 'critical' : 'high',
        label:          `Probe high-entropy section '${area.sourceId}'`,
        rationale:      area.description,
        sourceId:       area.sourceId,
        expectedGain:   Math.min(14, area.confidencePenalty),
        cost:           'moderate',
        prerequisites:  [],
      });
      // STRIKE can observe unpacking stubs at runtime
      if (ctx.strikeAvailable) {
        actions.push({
          id:             `strike-unpack-${area.sourceId}`,
          strategy:       'trigger-strike',
          addressesCause: 'packed-or-encrypted',
          priority:       'high',
          label:          `STRIKE runtime trace to capture unpacking of '${area.sourceId}'`,
          rationale:      'Runtime execution captures the decrypted/unpacked code that static analysis cannot see',
          sourceId:       area.sourceId,
          expectedGain:   Math.min(16, area.confidencePenalty + 2),
          cost:           'expensive',
          prerequisites:  [`entropy-probe-${area.sourceId}`],
        });
      }
      return actions;
    }

    // ── Missing runtime context ────────────────────────────────────────────
    case 'missing-runtime-context': {
      return [{
        id:             'strike-runtime',
        strategy:       'trigger-strike',
        addressesCause: 'missing-runtime-context',
        priority:       'critical',
        label:          'Trigger STRIKE execution trace',
        rationale:      `${area.description} — only runtime execution can confirm these behaviors`,
        expectedGain:   area.confidencePenalty,
        cost:           'expensive',
        prerequisites:  [],
      }];
    }

    // ── Unexplored function ────────────────────────────────────────────────
    case 'unexplored-function': {
      return [{
        id:             `isolate-fn-${iteration}`,
        strategy:       'isolate-function',
        addressesCause: 'unexplored-function',
        priority:       area.severity === 'high' ? 'high' : 'medium',
        label:          `Isolate and analyse ${area.description.match(/\d+/)?.[0] ?? 'suspicious'} unexplored function(s)`,
        rationale:      area.description,
        expectedGain:   area.confidencePenalty,
        cost:           talonEnabled ? 'expensive' : 'moderate',
        prerequisites:  [],
      }];
    }

    // ── Weak string evidence ───────────────────────────────────────────────
    case 'weak-string-evidence': {
      return [{
        id:             'deep-string-scan',
        strategy:       'deep-string-scan',
        addressesCause: 'weak-string-evidence',
        priority:       'medium',
        label:          'Deep string scan — cross-reference string offsets with disassembly',
        rationale:      area.description,
        expectedGain:   area.confidencePenalty,
        cost:           'cheap',
        prerequisites:  [],
      }];
    }

    // ── Weak import evidence ───────────────────────────────────────────────
    case 'weak-import-evidence': {
      return [{
        id:             `import-caller-${area.sourceId}`,
        strategy:       'import-caller-hunt',
        addressesCause: 'weak-import-evidence',
        priority:       area.severity === 'high' ? 'high' : 'medium',
        label:          `Hunt call sites for dangerous import '${area.sourceId}'`,
        rationale:      area.description,
        sourceId:       area.sourceId,
        offset:         currentEnd,
        length:         Math.max(512, disasmLength / 2),
        expectedGain:   area.confidencePenalty,
        cost:           'moderate',
        prerequisites:  [],
      }];
    }

    // ── Alternative hypothesis ─────────────────────────────────────────────
    case 'alternative-hypothesis': {
      return [{
        id:             `alt-dismiss-${iteration}`,
        strategy:       'alternative-dismissal',
        addressesCause: 'alternative-hypothesis',
        priority:       area.severity === 'high' ? 'high' : 'medium',
        label:          'Gather dismissal evidence for alternative hypothesis',
        rationale:      area.description,
        expectedGain:   area.confidencePenalty,
        cost:           'cheap',
        prerequisites:  [],
      }];
    }

    // ── Low instruction density ────────────────────────────────────────────
    case 'low-instruction-density': {
      // Try a different offset — skip forward further
      const skipOffset = currentEnd + disasmLength; // skip the sparse region
      return [{
        id:             `density-skip-${skipOffset}`,
        strategy:       'expand-coverage',
        addressesCause: 'low-instruction-density',
        priority:       'low',
        label:          `Skip sparse region, disassemble at +${(disasmLength).toString(16).toUpperCase()}h`,
        rationale:      area.description,
        offset:         skipOffset,
        length:         512,
        expectedGain:   area.confidencePenalty,
        cost:           'moderate',
        prerequisites:  [],
      }];
    }

    default:
      return [];
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Helpers ───────────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/** Derive the disassembly range request from the highest-priority action that has an offset. */
function deriveDisasmRequest(
  actions: StrategyAction[],
  ctx:     StrategyContext,
): { offset: number; length: number; reason: string } | null {
  // Find the top 'moderate' cost action with an explicit offset
  const best = actions.find(a => a.cost !== 'cheap' && a.offset != null);
  if (best && best.offset != null) {
    return {
      offset: best.offset,
      length: best.length ?? ctx.disasmLength,
      reason: best.label,
    };
  }
  // Fallback: extend forward from current window
  if (ctx.disasmLength > 0) {
    return {
      offset: ctx.disasmOffset + ctx.disasmLength,
      length: Math.max(512, ctx.disasmLength),
      reason: 'Default: extend coverage forward',
    };
  }
  return null;
}

function buildRationale(
  areas:         LowConfidenceArea[],
  primaryAction: StrategyAction | null,
  ctx:           StrategyContext,
): string {
  if (!primaryAction) return 'No actionable areas identified — maintain current strategy.';

  const topArea = areas[0];
  const verb    = strategyVerb(primaryAction.strategy);
  const conf    = ctx.currentVerdict.confidence;
  const iter    = ctx.iteration + 1;

  return `Iteration ${iter} (confidence ${conf}%): ` +
    `primary cause is "${topArea?.description ?? 'uncertainty'}" — ` +
    `strategy is to ${verb}. ` +
    (areas.length > 1
      ? `${areas.length - 1} additional area(s) will be addressed in parallel.`
      : '');
}

function strategyVerb(s: StrategyClass): string {
  const verbs: Record<StrategyClass, string> = {
    'expand-coverage':        'expand disassembly coverage',
    'focus-cfg-region':       'follow CFG paths and resolve indirect jumps',
    'deep-string-scan':       'run a deeper string cross-reference scan',
    'trigger-strike':         'trigger STRIKE runtime execution trace',
    'isolate-function':       'isolate and deeply analyse suspicious functions',
    'resolve-contradiction':  'gather tie-breaking evidence for a contradiction',
    'entropy-investigation':  'probe the high-entropy region for packed/crypto code',
    'import-caller-hunt':     'hunt for dangerous import call sites in disassembly',
    'talon-deep':             'run TALON full decompilation on the target region',
    'echo-retune':            'retune ECHO with new context from this iteration',
    'alternative-dismissal':  'collect evidence to dismiss the competing hypothesis',
  };
  return verbs[s] ?? s;
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Utility exports ───────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Filter the plan to only the actions that can execute NOW — i.e. actions
 * whose prerequisites are all in `completedIds`.
 */
export function getReadyActions(
  plan:         AnalysisPlan,
  completedIds: Set<string> = new Set(),
): StrategyAction[] {
  return plan.actions.filter(a =>
    a.prerequisites.every(req => completedIds.has(req)),
  );
}

/**
 * Select only the actions up to a given total cost budget.
 * Useful for rate-limiting expensive steps per iteration.
 */
export function selectWithinBudget(
  actions: StrategyAction[],
  budget:  'cheap-only' | 'moderate' | 'all',
): StrategyAction[] {
  if (budget === 'all')         return actions;
  if (budget === 'moderate')    return actions.filter(a => a.cost !== 'expensive');
  return actions.filter(a => a.cost === 'cheap');
}

/**
 * Convert a StrategyAction (from strategyEngine) into the offset/length pair
 * needed by the Tauri `disassemble_file_range` command.
 * Returns null if the action doesn't require a disassembly fetch.
 */
export function actionToDisasmRange(
  action:      StrategyAction,
  currentEnd:  number,
  defaultLen:  number,
): { offset: number; length: number } | null {
  const needsFetch: StrategyClass[] = [
    'expand-coverage', 'focus-cfg-region', 'resolve-contradiction',
    'entropy-investigation', 'import-caller-hunt', 'isolate-function',
  ];
  if (!needsFetch.includes(action.strategy)) return null;
  return {
    offset: action.offset ?? currentEnd,
    length: action.length ?? defaultLen,
  };
}

/**
 * Summarise a plan for display in the UI — one sentence per strategy class.
 */
export function summarisePlan(plan: AnalysisPlan): string[] {
  return Object.entries(plan.strategySummary).map(([strategy, count]) => {
    const verb = strategyVerb(strategy as StrategyClass);
    return `${String(count)} action(s): ${verb}`;
  });
}
