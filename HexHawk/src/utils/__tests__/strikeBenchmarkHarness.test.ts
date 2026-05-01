import { describe, expect, it } from 'vitest';
import {
  runStrikeBenchmarkScenario,
  runStrikeBenchmarkSuite,
  type StrikeBenchmarkScenario,
} from '../strikeBenchmarkHarness';

describe('strikeBenchmarkHarness', () => {
  it('passes deterministic loop and pattern expectations', () => {
    const scenario: StrikeBenchmarkScenario = {
      id: 'loop-timing',
      name: 'Loop with timing checks',
      steps: [
        { rip: 0x401000, event: 'step' },
        { rip: 0x401020, event: 'rdtsc' },
        { rip: 0x401021, event: 'step' },
        { rip: 0x401022, event: 'step' },
        { rip: 0x401020, event: 'step' },
        { rip: 0x401021, event: 'rdtsc' },
        { rip: 0x401022, event: 'step' },
        { rip: 0x401020, event: 'step' },
        { rip: 0x401021, event: 'step' },
        { rip: 0x401022, event: 'step' },
      ],
      expectations: {
        requiredPatternTags: ['timing-check'],
        expectedLoop: { periodLen: 3, minIterations: 3 },
        expectedFinalCallDepth: 0,
        minHotBlockPct: 50,
      },
    };

    const result = runStrikeBenchmarkScenario(scenario);

    expect(result.passed).toBe(true);
    expect(result.score).toBe(100);
    expect(result.summary.patternTags).toContain('timing-check');
  });

  it('fails checks when expectations are intentionally wrong', () => {
    const scenario: StrikeBenchmarkScenario = {
      id: 'wrong-depth',
      name: 'Wrong depth expectation',
      steps: [
        { rip: 0x500000, event: 'step' },
        { rip: 0x600000, event: ' call ' },
        { rip: 0x500010, event: ' ret' },
      ],
      expectations: {
        expectedFinalCallDepth: 2,
      },
    };

    const result = runStrikeBenchmarkScenario(scenario);

    expect(result.passed).toBe(false);
    expect(result.checks.some(c => c.name === 'final_call_depth' && !c.passed)).toBe(true);
  });

  it('computes suite-level aggregate metrics', () => {
    const scenarios: StrikeBenchmarkScenario[] = [
      {
        id: 'ok',
        name: 'OK',
        steps: [
          { rip: 0x1000, event: 'step' },
          { rip: 0x1001, event: 'step' },
          { rip: 0x1002, event: 'step' },
        ],
        expectations: {
          expectedFinalCallDepth: 0,
        },
      },
      {
        id: 'bad',
        name: 'Bad',
        steps: [
          { rip: 0x2000, event: 'step' },
          { rip: 0x3000, event: ' call ' },
          { rip: 0x2004, event: ' ret' },
        ],
        expectations: {
          expectedFinalCallDepth: 1,
        },
      },
    ];

    const suite = runStrikeBenchmarkSuite(scenarios);

    expect(suite.scenarioCount).toBe(2);
    expect(suite.passedScenarios).toBe(1);
    expect(suite.failedScenarios).toBe(1);
    expect(suite.averageScore).toBeGreaterThan(0);
  });

  it('applies false-positive penalties for forbidden tags and risk overshoot', () => {
    const scenario: StrikeBenchmarkScenario = {
      id: 'false-positive-penalty',
      name: 'False positive guardrail',
      steps: [
        { rip: 0x900000, event: 'step' },
        { rip: 0x910000, event: 'getprocaddress call' },
        { rip: 0x920000, event: 'loadlibrary call' },
        { rip: 0x930000, event: 'jmp resolver' },
        { rip: 0x930010, event: 'step' },
      ],
      expectations: {
        forbiddenPatternTags: ['dynamic-api-resolution'],
        maxRiskScore: 10,
      },
    };

    const result = runStrikeBenchmarkScenario(scenario, {
      stabilityRuns: 3,
      maxRiskJitter: 0,
      maxScoreJitter: 0,
    });

    expect(result.passed).toBe(false);
    expect(result.checks.some(c => c.name === 'forbidden_pattern_tags' && !c.passed)).toBe(true);
    expect(result.checks.some(c => c.name === 'max_risk_score' && !c.passed)).toBe(true);
    expect(result.penalties.falsePositive).toBeGreaterThan(0);
    expect(result.penalties.total).toBe(result.penalties.falsePositive);
    expect(result.stability.stable).toBe(true);
  });

  it('reports regression deltas against a stored baseline', () => {
    const scenario: StrikeBenchmarkScenario = {
      id: 'regression-check',
      name: 'Regression check',
      steps: [
        { rip: 0x1000, event: 'step' },
        { rip: 0x1001, event: 'step' },
        { rip: 0x1002, event: 'step' },
      ],
      expectations: {
        expectedFinalCallDepth: 1,
      },
    };

    const result = runStrikeBenchmarkScenario(scenario, {
      baselineByScenarioId: {
        'regression-check': {
          score: 100,
          riskScore: 0,
          passed: true,
        },
      },
      maxAllowedScoreDrop: 5,
    });

    expect(result.regression.hasBaseline).toBe(true);
    expect(result.regression.scoreDelta).toBe(-50);
    expect(result.regression.passedDelta).toBe(-1);
    expect(result.checks.some(c => c.name === 'regression_delta' && !c.passed)).toBe(true);
    expect(result.penalties.regression).toBe(50);
    expect(result.score).toBe(0);
  });

  it('computes suite-level average drift against baseline', () => {
    const scenarios: StrikeBenchmarkScenario[] = [
      {
        id: 'baseline-hit',
        name: 'Baseline hit',
        steps: [
          { rip: 0x2000, event: 'step' },
          { rip: 0x2001, event: 'step' },
        ],
        expectations: {
          expectedFinalCallDepth: 0,
        },
      },
      {
        id: 'baseline-miss',
        name: 'Baseline miss',
        steps: [
          { rip: 0x3000, event: 'step' },
          { rip: 0x3001, event: 'step' },
        ],
        expectations: {
          expectedFinalCallDepth: 1,
        },
      },
    ];

    const suite = runStrikeBenchmarkSuite(scenarios, {
      baselineByScenarioId: {
        'baseline-hit': { score: 100, riskScore: 0, passed: true },
        'baseline-miss': { score: 100, riskScore: 0, passed: true },
      },
      maxAllowedScoreDrop: 5,
    });

    expect(suite.scenarioCount).toBe(2);
    expect(suite.averageScoreDelta).toBe(-25);
    expect(suite.scenarios[0].regression.hasBaseline).toBe(true);
    expect(suite.scenarios[1].regression.hasBaseline).toBe(true);
  });
});
