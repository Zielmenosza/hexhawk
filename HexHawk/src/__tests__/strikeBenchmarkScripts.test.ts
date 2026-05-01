import { describe, expect, it } from 'vitest';
import {
  buildScenario,
  buildScenariosFromInputs,
  type NestIteration,
  type NestResult,
} from '../../scripts/build-strike-fixtures-from-challenge-logs';
import { buildMarkdownSummary, collectBaselineDiffEntries } from '../../scripts/run-strike-benchmark';
import type { StrikeBenchmarkScenario, StrikeBenchmarkSuiteResult } from '../utils/strikeBenchmarkHarness';

function extractSection(markdown: string, heading: string): string {
  const marker = `## ${heading}\n\n`;
  const start = markdown.indexOf(marker);
  if (start === -1) {
    throw new Error(`Missing markdown section: ${heading}`);
  }

  const nextHeading = markdown.indexOf('\n## ', start + marker.length);
  return markdown.slice(start, nextHeading === -1 ? undefined : nextHeading).trimEnd();
}

function makeResult(overrides: Partial<NestResult> = {}): NestResult {
  return {
    file: 'D:\\Project\\HexHawk\\Challenges\\8 - FlareAuthenticator\\FlareAuthenticator.exe',
    date: '2026-05-01T10:29:43.168Z',
    status: 'plateau',
    finalConfidence: 44,
    finalVerdict: 'packer',
    totalGain: 15,
    totalIterations: 5,
    stopReason: 'plateau',
    healerTriggered: false,
    keyFindings: ['Iter 2: +7% confidence'],
    ...overrides,
  };
}

function makeIterations(): NestIteration[] {
  return [
    {
      iteration: 0,
      confidence: 29,
      loss: 71,
      contradictions: 2,
      verdict: 'packer',
      signalCount: 8,
      durationMs: 73,
    },
  ];
}

function makeSuiteResult(): StrikeBenchmarkSuiteResult {
  return {
    scenarioCount: 2,
    passedScenarios: 1,
    failedScenarios: 1,
    averageScore: 75,
    averageScoreDelta: -12.5,
    scenarios: [
      {
        scenarioId: 'challenge-flareauthenticator',
        scenarioName: 'Challenge Replay - FlareAuthenticator',
        checks: [],
        passedChecks: 4,
        totalChecks: 4,
        score: 100,
        passed: true,
        penalties: { falsePositive: 0, instability: 0, regression: 0, total: 0 },
        stability: { runs: 3, scoreJitter: 0, riskJitter: 0, stable: true },
        regression: { hasBaseline: true, scoreDelta: 0, riskDelta: 0, passedDelta: 0 },
        summary: {
          finalCallDepth: 0,
          topHotBlockPct: 92.3,
          loopCount: 2,
          riskScore: 45,
          patternTags: ['self-modifying-code', 'oep-transfer'],
        },
        analysis: {
          patterns: [],
          signals: {
            hasTimingCheck: false,
            hasExceptionProbe: false,
            hasStackPivot: false,
            hasRopActivity: false,
            hasAntiStep: false,
            hasCpuidCheck: false,
            hasAntiDebugProbe: false,
            hasUnpackingBehavior: true,
            hasDynamicApiResolution: false,
            hasPebWalk: false,
            hasRatPattern: false,
            hasWiperPattern: false,
            indirectJumpRatio: 0,
            detectedPatterns: ['self-modifying-code', 'oep-transfer'],
            stepCount: 26,
            behavioralTags: ['code-decryption'],
            riskScore: 45,
          },
          loops: [],
          hotBlocks: [],
        },
      },
      {
        scenarioId: 'challenge-ntfsm',
        scenarioName: 'Challenge Replay - ntfsm',
        checks: [
          {
            name: 'regression_delta',
            passed: false,
            expected: 'scoreDelta >= -5 (baseline=100)',
            actual: 'scoreDelta=-25',
          },
        ],
        passedChecks: 3,
        totalChecks: 4,
        score: 50,
        passed: false,
        penalties: { falsePositive: 0, instability: 0, regression: 25, total: 25 },
        stability: { runs: 3, scoreJitter: 0, riskJitter: 0, stable: true },
        regression: { hasBaseline: true, scoreDelta: -25, riskDelta: 10, passedDelta: -1 },
        summary: {
          finalCallDepth: 0,
          topHotBlockPct: 74.1,
          loopCount: 1,
          riskScore: 95,
          patternTags: ['timing-check', 'exception-probe', 'self-modifying-code', 'oep-transfer'],
        },
        analysis: {
          patterns: [],
          signals: {
            hasTimingCheck: true,
            hasExceptionProbe: true,
            hasStackPivot: false,
            hasRopActivity: false,
            hasAntiStep: false,
            hasCpuidCheck: false,
            hasAntiDebugProbe: false,
            hasUnpackingBehavior: true,
            hasDynamicApiResolution: false,
            hasPebWalk: false,
            hasRatPattern: false,
            hasWiperPattern: false,
            indirectJumpRatio: 0,
            detectedPatterns: ['timing-check', 'exception-probe', 'self-modifying-code', 'oep-transfer'],
            stepCount: 27,
            behavioralTags: ['anti-analysis', 'code-decryption'],
            riskScore: 95,
          },
          loops: [],
          hotBlocks: [],
        },
      },
    ],
  };
}

describe('STRIKE script helpers', () => {
  it('builds challenge-derived scenarios with provenance and verdict-specific expectations', () => {
    const scenario = buildScenario(makeResult(), makeIterations(), 'FlareAuthenticator', 'D:\\Project\\HexHawk\\nest_tests');

    expect(scenario.id).toBe('challenge-flareauthenticator');
    expect(scenario.source?.challenge).toBe('FlareAuthenticator');
    expect(scenario.source?.fidelity).toBe('derived-from-session');
    expect(scenario.source?.sessionLogPath).toContain('FlareAuthenticator');
    expect(scenario.expectations.requiredPatternTags).toEqual(['self-modifying-code', 'oep-transfer']);
    expect(scenario.steps.length).toBeGreaterThan(20);
  });

  it('filters non-challenge inputs and sorts generated scenarios by id', () => {
    const scenarios = buildScenariosFromInputs([
      {
        folderName: 'zeta',
        result: makeResult({
          file: 'D:\\Project\\HexHawk\\Challenges\\7 - The Boss Needs Help\\hopeanddreams.exe',
          finalVerdict: 'rat',
          finalConfidence: 72,
        }),
        iterations: makeIterations(),
      },
      {
        folderName: 'internal',
        result: makeResult({
          file: 'D:\\Project\\HexHawk\\internal\\sample.exe',
          finalVerdict: 'dropper',
        }),
        iterations: makeIterations(),
      },
      {
        folderName: 'alpha',
        result: makeResult({
          file: 'D:\\Project\\HexHawk\\Challenges\\5 - ntfsm\\ntfsm.exe',
          finalVerdict: 'ransomware-like',
          finalConfidence: 66,
        }),
        iterations: makeIterations(),
      },
    ], 'D:\\Project\\HexHawk\\nest_tests');

    expect(scenarios).toHaveLength(2);
    expect(scenarios.map(scenario => scenario.id)).toEqual(['challenge-hopeanddreams', 'challenge-ntfsm']);
  });

  it('collects only non-zero baseline diff entries', () => {
    const diffs = collectBaselineDiffEntries(makeSuiteResult());

    expect(diffs).toEqual([
      {
        scenarioName: 'Challenge Replay - ntfsm',
        scoreDelta: -25,
        riskDelta: 10,
        passedDelta: -1,
      },
    ]);
  });

  it('renders a stable failing baseline-diff table and includes source paths in provenance', () => {
    const scenarios: StrikeBenchmarkScenario[] = [
      buildScenario(makeResult(), makeIterations(), 'FlareAuthenticator', 'D:\\Project\\HexHawk\\nest_tests'),
      buildScenario(
        makeResult({
          file: 'D:\\Project\\HexHawk\\Challenges\\5 - ntfsm\\ntfsm.exe',
          finalVerdict: 'ransomware-like',
          finalConfidence: 66,
        }),
        makeIterations(),
        'ntfsm',
        'D:\\Project\\HexHawk\\nest_tests',
      ),
    ];

    const markdown = buildMarkdownSummary(
      makeSuiteResult(),
      scenarios,
      [
        'D:\\Project\\HexHawk\\HexHawk\\scripts\\strike-benchmarks\\default-scenarios.json',
        'D:\\Project\\HexHawk\\HexHawk\\scripts\\strike-benchmarks\\challenge-derived-scenarios.json',
      ],
      'D:\\Project\\HexHawk\\HexHawk\\scripts\\strike-benchmarks\\baseline.json',
      {
        stabilityRuns: 3,
        maxAllowedScoreDrop: 5,
        maxRiskJitter: 0,
        maxScoreJitter: 0,
        baselineByScenarioId: {},
      },
    );

    expect(extractSection(markdown, 'Baseline Diff')).toMatchInlineSnapshot(`
      "## Baseline Diff

      | Scenario | Score Delta | Risk Delta | Pass Delta |
      | --- | ---: | ---: | ---: |
      | Challenge Replay - ntfsm | -25 | 10 | -1 |"
    `);
    expect(markdown).toContain('| Scenario | Status | Score | Risk | Delta | Penalties | Fidelity | Provenance | Notes |');
    expect(markdown).toContain('derived-from-session');
    expect(markdown).toContain('FlareAuthenticator<br>target=Challenges/8 - FlareAuthenticator/FlareAuthenticator.exe');
    expect(markdown).toContain('session=nest_tests/FlareAuthenticator/session.log');
    expect(markdown).toContain('result=nest_tests/ntfsm/result.json');
  });
});
