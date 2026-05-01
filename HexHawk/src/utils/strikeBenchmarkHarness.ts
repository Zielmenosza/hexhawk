import type { DebugSnapshot, RegisterState, DebugStatus } from '../components/DebuggerPanel';
import {
  appendStep,
  buildCallStack,
  computeHotBlocks,
  createTimeline,
  detectExecutionLoops,
  detectPatterns,
  extractCorrelationSignals,
  type PatternTag,
  type StrikeCorrelationSignal,
  type StrikePattern,
} from './strikeEngine';

export interface StrikeBenchmarkStep {
  rip: number;
  event?: string;
  rsp?: number;
  eflags?: number;
  status?: DebugStatus;
}

export interface StrikeLoopExpectation {
  periodLen: number;
  minIterations: number;
}

export interface StrikeBenchmarkExpectations {
  requiredPatternTags?: PatternTag[];
  forbiddenPatternTags?: PatternTag[];
  expectedFinalCallDepth?: number;
  minHotBlockPct?: number;
  expectedLoop?: StrikeLoopExpectation;
  minRiskScore?: number;
  maxRiskScore?: number;
}

export interface StrikeBenchmarkBaselineScenario {
  score: number;
  riskScore: number;
  passed: boolean;
}

export interface StrikeBenchmarkRunOptions {
  stabilityRuns?: number;
  maxScoreJitter?: number;
  maxRiskJitter?: number;
  baselineByScenarioId?: Record<string, StrikeBenchmarkBaselineScenario>;
  maxAllowedScoreDrop?: number;
}

export interface StrikeBenchmarkScenario {
  id: string;
  name: string;
  description?: string;
  source?: {
    challenge?: string;
    targetPath?: string;
    sessionLogPath?: string;
    resultPath?: string;
    fidelity?: 'derived-from-session' | 'synthetic';
  };
  steps: StrikeBenchmarkStep[];
  expectations: StrikeBenchmarkExpectations;
}

export interface StrikeBenchmarkCheck {
  name: string;
  passed: boolean;
  expected: string;
  actual: string;
}

export interface StrikeBenchmarkScenarioResult {
  scenarioId: string;
  scenarioName: string;
  checks: StrikeBenchmarkCheck[];
  passedChecks: number;
  totalChecks: number;
  score: number;
  passed: boolean;
  penalties: {
    falsePositive: number;
    instability: number;
    regression: number;
    total: number;
  };
  stability: {
    runs: number;
    scoreJitter: number;
    riskJitter: number;
    stable: boolean;
  };
  regression: {
    hasBaseline: boolean;
    scoreDelta: number;
    riskDelta: number;
    passedDelta: number;
  };
  summary: {
    finalCallDepth: number;
    topHotBlockPct: number;
    loopCount: number;
    riskScore: number;
    patternTags: PatternTag[];
  };
  analysis: {
    patterns: StrikePattern[];
    signals: StrikeCorrelationSignal;
    loops: Array<{ startStep: number; periodLen: number; iterations: number }>;
    hotBlocks: Array<{ address: number; count: number; pct: number }>;
  };
}

export interface StrikeBenchmarkSuiteResult {
  scenarioCount: number;
  passedScenarios: number;
  failedScenarios: number;
  averageScore: number;
  averageScoreDelta: number;
  scenarios: StrikeBenchmarkScenarioResult[];
}

interface StrikeAnalysisSnapshot {
  patternTags: PatternTag[];
  finalCallDepth: number;
  topHotBlockPct: number;
  loops: ReturnType<typeof detectExecutionLoops>;
  signals: StrikeCorrelationSignal;
  patterns: StrikePattern[];
  hotBlocks: ReturnType<typeof computeHotBlocks>;
}

function makeRegisters(step: StrikeBenchmarkStep): RegisterState {
  return {
    rax: 0,
    rbx: 0,
    rcx: 0,
    rdx: 0,
    rsi: 0,
    rdi: 0,
    rsp: step.rsp ?? 0x7fff0000,
    rbp: 0,
    rip: step.rip,
    r8: 0,
    r9: 0,
    r10: 0,
    r11: 0,
    r12: 0,
    r13: 0,
    r14: 0,
    r15: 0,
    eflags: step.eflags ?? 0,
    cs: 0,
    ss: 0,
  };
}

function makeSnapshot(step: StrikeBenchmarkStep, index: number, sessionId: number): DebugSnapshot {
  return {
    sessionId,
    status: step.status ?? 'Running',
    registers: makeRegisters(step),
    stack: [],
    breakpoints: [],
    stepCount: index,
    exitCode: null,
    lastEvent: step.event ?? 'step',
  };
}

function addCheck(checks: StrikeBenchmarkCheck[], name: string, condition: boolean, expected: string, actual: string): void {
  checks.push({ name, passed: condition, expected, actual });
}

function analyzeScenario(scenario: StrikeBenchmarkScenario): StrikeAnalysisSnapshot {
  let timeline = createTimeline(1);

  for (let i = 0; i < scenario.steps.length; i++) {
    const snapshot = makeSnapshot(scenario.steps[i], i, 1);
    timeline = appendStep(timeline, snapshot).timeline;
  }

  const patterns = detectPatterns(timeline);
  const patternTags = patterns.map(p => p.tag);
  const signals = extractCorrelationSignals(timeline);
  const callStack = buildCallStack(timeline);
  const hotBlocks = computeHotBlocks(timeline);
  const loops = detectExecutionLoops(timeline);

  return {
    patternTags,
    finalCallDepth: callStack.length,
    topHotBlockPct: hotBlocks[0]?.pct ?? 0,
    loops,
    signals,
    patterns,
    hotBlocks,
  };
}

function toBaselineMap(
  baselineByScenarioId?: Record<string, StrikeBenchmarkBaselineScenario>,
): Record<string, StrikeBenchmarkBaselineScenario> {
  return baselineByScenarioId ?? {};
}

export function runStrikeBenchmarkScenario(
  scenario: StrikeBenchmarkScenario,
  options: StrikeBenchmarkRunOptions = {},
): StrikeBenchmarkScenarioResult {
  const base = analyzeScenario(scenario);
  const patternTags = base.patternTags;
  const signals = base.signals;
  const loops = base.loops;
  const finalCallDepth = base.finalCallDepth;
  const topHotBlockPct = base.topHotBlockPct;

  const checks: StrikeBenchmarkCheck[] = [];
  const ex = scenario.expectations;

  let falsePositivePenalty = 0;
  let instabilityPenalty = 0;
  let regressionPenalty = 0;

  if (ex.requiredPatternTags && ex.requiredPatternTags.length > 0) {
    const missing = ex.requiredPatternTags.filter(tag => !patternTags.includes(tag));
    addCheck(
      checks,
      'required_pattern_tags',
      missing.length === 0,
      `contains all: ${ex.requiredPatternTags.join(', ')}`,
      missing.length === 0 ? `ok (${patternTags.join(', ')})` : `missing: ${missing.join(', ')}`,
    );
  }

  if (ex.forbiddenPatternTags && ex.forbiddenPatternTags.length > 0) {
    const present = ex.forbiddenPatternTags.filter(tag => patternTags.includes(tag));
    addCheck(
      checks,
      'forbidden_pattern_tags',
      present.length === 0,
      `none of: ${ex.forbiddenPatternTags.join(', ')}`,
      present.length === 0 ? 'none present' : `present: ${present.join(', ')}`,
    );
    falsePositivePenalty += present.length * 8;
  }

  if (typeof ex.expectedFinalCallDepth === 'number') {
    addCheck(
      checks,
      'final_call_depth',
      finalCallDepth === ex.expectedFinalCallDepth,
      String(ex.expectedFinalCallDepth),
      String(finalCallDepth),
    );
  }

  if (typeof ex.minHotBlockPct === 'number') {
    addCheck(
      checks,
      'top_hot_block_pct',
      topHotBlockPct >= ex.minHotBlockPct,
      `>= ${ex.minHotBlockPct.toFixed(1)}%`,
      `${topHotBlockPct.toFixed(1)}%`,
    );
  }

  if (ex.expectedLoop) {
    const matchedLoop = loops.find(l => l.periodLen === ex.expectedLoop!.periodLen && l.iterations >= ex.expectedLoop!.minIterations);
    addCheck(
      checks,
      'execution_loop',
      !!matchedLoop,
      `period=${ex.expectedLoop.periodLen}, iterations>=${ex.expectedLoop.minIterations}`,
      matchedLoop ? `period=${matchedLoop.periodLen}, iterations=${matchedLoop.iterations}` : 'not found',
    );
  }

  if (typeof ex.minRiskScore === 'number') {
    addCheck(
      checks,
      'risk_score',
      signals.riskScore >= ex.minRiskScore,
      `>= ${ex.minRiskScore}`,
      String(signals.riskScore),
    );
  }

  if (typeof ex.maxRiskScore === 'number') {
    addCheck(
      checks,
      'max_risk_score',
      signals.riskScore <= ex.maxRiskScore,
      `<= ${ex.maxRiskScore}`,
      String(signals.riskScore),
    );
    if (signals.riskScore > ex.maxRiskScore) {
      falsePositivePenalty += Math.min(20, Math.round((signals.riskScore - ex.maxRiskScore) / 2));
    }
  }

  const stabilityRuns = Math.max(1, options.stabilityRuns ?? 3);
  let scoreJitter = 0;
  let riskJitter = 0;
  let stable = true;
  if (stabilityRuns > 1) {
    const riskVals: number[] = [signals.riskScore];
    for (let i = 1; i < stabilityRuns; i++) {
      riskVals.push(analyzeScenario(scenario).signals.riskScore);
    }
    const riskMin = Math.min(...riskVals);
    const riskMax = Math.max(...riskVals);
    riskJitter = riskMax - riskMin;
    // Score jitter in this deterministic harness follows risk jitter scale.
    scoreJitter = riskJitter;
    const maxRiskJitter = options.maxRiskJitter ?? 0;
    const maxScoreJitter = options.maxScoreJitter ?? 0;
    stable = riskJitter <= maxRiskJitter && scoreJitter <= maxScoreJitter;
    if (!stable) {
      instabilityPenalty += Math.max(5, riskJitter + scoreJitter);
    }
  }
  addCheck(
    checks,
    'stability',
    stable,
    `runs=${stabilityRuns}, scoreJitter<=${options.maxScoreJitter ?? 0}, riskJitter<=${options.maxRiskJitter ?? 0}`,
    `runs=${stabilityRuns}, scoreJitter=${scoreJitter}, riskJitter=${riskJitter}`,
  );

  const baseline = toBaselineMap(options.baselineByScenarioId)[scenario.id];
  let scoreDelta = 0;
  let riskDelta = 0;
  let passedDelta = 0;
  if (baseline) {
    const prePenaltyTotalChecks = checks.length;
    const prePenaltyPassedChecks = checks.filter(c => c.passed).length;
    const prePenaltyScore = prePenaltyTotalChecks === 0 ? 100 : Math.round((prePenaltyPassedChecks / prePenaltyTotalChecks) * 100);
    scoreDelta = prePenaltyScore - baseline.score;
    riskDelta = signals.riskScore - baseline.riskScore;
    const prePenaltyPassed = prePenaltyPassedChecks === prePenaltyTotalChecks;
    passedDelta = Number(prePenaltyPassed) - Number(baseline.passed);

    const maxAllowedDrop = options.maxAllowedScoreDrop ?? 0;
    const regOk = scoreDelta >= -maxAllowedDrop;
    if (!regOk) {
      regressionPenalty += Math.abs(scoreDelta);
    }
    addCheck(
      checks,
      'regression_delta',
      regOk,
      `scoreDelta >= -${maxAllowedDrop} (baseline=${baseline.score})`,
      `scoreDelta=${scoreDelta}`,
    );
  }

  const totalChecks = checks.length;
  const passedChecks = checks.filter(c => c.passed).length;
  const rawScore = totalChecks === 0 ? 100 : Math.round((passedChecks / totalChecks) * 100);
  const totalPenalty = falsePositivePenalty + instabilityPenalty + regressionPenalty;
  const score = Math.max(0, rawScore - totalPenalty);
  const passed = passedChecks === totalChecks && totalPenalty === 0;

  return {
    scenarioId: scenario.id,
    scenarioName: scenario.name,
    checks,
    passedChecks,
    totalChecks,
    score,
    passed,
    penalties: {
      falsePositive: falsePositivePenalty,
      instability: instabilityPenalty,
      regression: regressionPenalty,
      total: totalPenalty,
    },
    stability: {
      runs: stabilityRuns,
      scoreJitter,
      riskJitter,
      stable,
    },
    regression: {
      hasBaseline: !!baseline,
      scoreDelta,
      riskDelta,
      passedDelta,
    },
    summary: {
      finalCallDepth,
      topHotBlockPct,
      loopCount: loops.length,
      riskScore: signals.riskScore,
      patternTags,
    },
    analysis: {
      patterns: base.patterns,
      signals,
      loops: loops.map(l => ({ startStep: l.startStep, periodLen: l.periodLen, iterations: l.iterations })),
      hotBlocks: base.hotBlocks,
    },
  };
}

export function runStrikeBenchmarkSuite(
  scenarios: StrikeBenchmarkScenario[],
  options: StrikeBenchmarkRunOptions = {},
): StrikeBenchmarkSuiteResult {
  const results = scenarios.map(s => runStrikeBenchmarkScenario(s, options));
  const passedScenarios = results.filter(r => r.passed).length;
  const averageScore = results.length === 0
    ? 0
    : Math.round((results.reduce((sum, r) => sum + r.score, 0) / results.length) * 10) / 10;
  const averageScoreDelta = results.length === 0
    ? 0
    : Math.round((results.reduce((sum, r) => sum + r.regression.scoreDelta, 0) / results.length) * 10) / 10;

  return {
    scenarioCount: results.length,
    passedScenarios,
    failedScenarios: results.length - passedScenarios,
    averageScore,
    averageScoreDelta,
    scenarios: results,
  };
}
