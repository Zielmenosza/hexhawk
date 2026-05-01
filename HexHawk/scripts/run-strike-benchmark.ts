import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  runStrikeBenchmarkSuite,
  type StrikeBenchmarkBaselineScenario,
  type StrikeBenchmarkRunOptions,
  type StrikeBenchmarkScenario,
  type StrikeBenchmarkScenarioResult,
  type StrikeBenchmarkSuiteResult,
} from '../src/utils/strikeBenchmarkHarness.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const APP_ROOT = path.resolve(__dirname, '..');
const REPO_ROOT = path.resolve(__dirname, '../..');

const DEFAULT_SCENARIO_PATH = path.join(APP_ROOT, 'scripts', 'strike-benchmarks', 'default-scenarios.json');
const DEFAULT_CHALLENGE_SCENARIO_PATH = path.join(APP_ROOT, 'scripts', 'strike-benchmarks', 'challenge-derived-scenarios.json');
const DEFAULT_BASELINE_PATH = path.join(APP_ROOT, 'scripts', 'strike-benchmarks', 'baseline.json');
const DEFAULT_OUT_DIR = path.join(REPO_ROOT, 'nest_tests', 'strike_benchmarks');

interface CliOptions {
  scenarioPaths: string[];
  baselinePath: string;
  writeBaseline: boolean;
  maxScoreDrop: number;
  stabilityRuns: number;
}

interface BaselineDiffEntry {
  scenarioName: string;
  scoreDelta: number;
  riskDelta: number;
  passedDelta: number;
}

function toRepoRelativePath(filePath: string | undefined): string {
  if (!filePath) {
    return 'n/a';
  }

  const relativePath = path.relative(REPO_ROOT, filePath);
  const normalizedPath = relativePath && !relativePath.startsWith('..') ? relativePath : filePath;
  return normalizedPath.replace(/\\/g, '/');
}

function formatProvenanceCell(scenario: StrikeBenchmarkScenario | undefined): string {
  const source = scenario?.source;
  if (!source) {
    return 'synthetic';
  }

  const details = [
    source.challenge,
    `target=${toRepoRelativePath(source.targetPath)}`,
    `session=${toRepoRelativePath(source.sessionLogPath)}`,
    `result=${toRepoRelativePath(source.resultPath)}`,
  ].filter(Boolean);

  return details.join('<br>');
}

function parseArgs(): CliOptions {
  const args = process.argv.slice(2);
  const scenarioPaths: string[] = [];
  let baselinePath = DEFAULT_BASELINE_PATH;
  let writeBaseline = false;
  let maxScoreDrop = 0;
  let stabilityRuns = 3;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if ((arg === '--scenario' || arg === '-s') && args[i + 1]) {
      scenarioPaths.push(path.resolve(args[i + 1]));
      i += 1;
      continue;
    }
    if ((arg === '--baseline' || arg === '-b') && args[i + 1]) {
      baselinePath = path.resolve(args[i + 1]);
      i += 1;
      continue;
    }
    if (arg === '--write-baseline') {
      writeBaseline = true;
      continue;
    }
    if (arg === '--max-score-drop' && args[i + 1]) {
      maxScoreDrop = Number(args[i + 1]);
      i += 1;
      continue;
    }
    if (arg === '--stability-runs' && args[i + 1]) {
      stabilityRuns = Number(args[i + 1]);
      i += 1;
    }
  }

  if (scenarioPaths.length === 0) {
    scenarioPaths.push(DEFAULT_SCENARIO_PATH);
    if (fs.existsSync(DEFAULT_CHALLENGE_SCENARIO_PATH)) {
      scenarioPaths.push(DEFAULT_CHALLENGE_SCENARIO_PATH);
    }
  }

  return {
    scenarioPaths,
    baselinePath,
    writeBaseline,
    maxScoreDrop,
    stabilityRuns,
  };
}

function readScenarios(filePath: string): StrikeBenchmarkScenario[] {
  const raw = fs.readFileSync(filePath, 'utf8');
  const parsed = JSON.parse(raw) as StrikeBenchmarkScenario[];
  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new Error('Scenario file must be a non-empty JSON array.');
  }
  return parsed;
}

function readScenarioSet(paths: string[]): StrikeBenchmarkScenario[] {
  const merged = new Map<string, StrikeBenchmarkScenario>();
  for (const p of paths) {
    const scenarios = readScenarios(p);
    for (const scenario of scenarios) {
      merged.set(scenario.id, scenario);
    }
  }
  return Array.from(merged.values());
}

function readBaseline(filePath: string): Record<string, StrikeBenchmarkBaselineScenario> {
  if (!fs.existsSync(filePath)) {
    return {};
  }
  const raw = fs.readFileSync(filePath, 'utf8');
  const parsed = JSON.parse(raw) as { scenarios?: Record<string, StrikeBenchmarkBaselineScenario> };
  if (!parsed.scenarios || typeof parsed.scenarios !== 'object') {
    return {};
  }
  return parsed.scenarios;
}

function writeBaseline(filePath: string, result: ReturnType<typeof runStrikeBenchmarkSuite>, scenarioPaths: string[]): void {
  const baselineScenarios: Record<string, StrikeBenchmarkBaselineScenario> = {};
  for (const scenario of result.scenarios) {
    baselineScenarios[scenario.scenarioId] = {
      score: scenario.score,
      riskScore: scenario.summary.riskScore,
      passed: scenario.passed,
    };
  }

  const payload = {
    generatedAt: new Date().toISOString(),
    scenarioPaths,
    scenarioCount: result.scenarioCount,
    scenarios: baselineScenarios,
  };

  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(payload, null, 2), 'utf8');
}

function printSummary(result: StrikeBenchmarkSuiteResult): void {
  console.log('');
  console.log('STRIKE Benchmark Summary');
  console.log('========================');
  console.log(`Scenarios: ${result.scenarioCount}`);
  console.log(`Passed   : ${result.passedScenarios}`);
  console.log(`Failed   : ${result.failedScenarios}`);
  console.log(`Avg Score: ${result.averageScore}`);
  console.log(`Avg Delta: ${result.averageScoreDelta}`);
  console.log('');

  for (const s of result.scenarios) {
    const status = s.passed ? 'PASS' : 'FAIL';
    console.log(`[${status}] ${s.scenarioName} (${s.score})`);
    console.log(`      risk=${s.summary.riskScore} loops=${s.summary.loopCount} callDepth=${s.summary.finalCallDepth} topHot=${s.summary.topHotBlockPct.toFixed(1)}%`);
    console.log(`      penalties=falsePositive:${s.penalties.falsePositive}, stability:${s.penalties.instability}, regression:${s.penalties.regression} total:${s.penalties.total}`);
    if (s.regression.hasBaseline) {
      console.log(`      drift=scoreDelta:${s.regression.scoreDelta} riskDelta:${s.regression.riskDelta} passedDelta:${s.regression.passedDelta}`);
    }
    if (!s.passed) {
      for (const c of s.checks.filter(c => !c.passed)) {
        console.log(`      - ${c.name}: expected ${c.expected}, got ${c.actual}`);
      }
    }
  }
}

export function collectBaselineDiffEntries(result: StrikeBenchmarkSuiteResult): BaselineDiffEntry[] {
  return result.scenarios
    .filter(scenario => scenario.regression.hasBaseline)
    .map(scenario => ({
      scenarioName: scenario.scenarioName,
      scoreDelta: scenario.regression.scoreDelta,
      riskDelta: scenario.regression.riskDelta,
      passedDelta: scenario.regression.passedDelta,
    }))
    .filter(entry => entry.scoreDelta !== 0 || entry.riskDelta !== 0 || entry.passedDelta !== 0)
    .sort((a, b) => Math.abs(b.scoreDelta) - Math.abs(a.scoreDelta));
}

function formatScenarioNotes(scenario: StrikeBenchmarkScenarioResult): string {
  return scenario.passed
    ? `loops=${scenario.summary.loopCount}, hot=${scenario.summary.topHotBlockPct.toFixed(1)}%`
    : scenario.checks
        .filter(check => !check.passed)
        .map(check => `${check.name}: expected ${check.expected}, got ${check.actual}`)
        .join('; ');
}

export function buildMarkdownSummary(
  result: StrikeBenchmarkSuiteResult,
  scenarios: StrikeBenchmarkScenario[],
  scenarioPaths: string[],
  baselinePath: string,
  options: StrikeBenchmarkRunOptions,
): string {
  const scenarioById = new Map(scenarios.map(scenario => [scenario.id, scenario]));
  const diffEntries = collectBaselineDiffEntries(result);
  const lines: string[] = [];
  lines.push('# STRIKE Benchmark Report');
  lines.push('');
  lines.push(`- Generated: ${new Date().toISOString()}`);
  lines.push(`- Scenarios: ${result.scenarioCount}`);
  lines.push(`- Passed: ${result.passedScenarios}`);
  lines.push(`- Failed: ${result.failedScenarios}`);
  lines.push(`- Average score: ${result.averageScore}`);
  lines.push(`- Average delta: ${result.averageScoreDelta}`);
  lines.push(`- Stability runs: ${options.stabilityRuns ?? 1}`);
  lines.push(`- Max allowed score drop: ${options.maxAllowedScoreDrop ?? 0}`);
  lines.push(`- Baseline: ${baselinePath}`);
  lines.push('');
  lines.push('## Scenario Sources');
  lines.push('');
  for (const scenarioPath of scenarioPaths) {
    lines.push(`- ${scenarioPath}`);
  }
  lines.push('');
  lines.push('## Baseline Diff');
  lines.push('');
  if (diffEntries.length === 0) {
    lines.push('No score, risk, or pass/fail drift detected versus the committed baseline.');
  } else {
    lines.push('| Scenario | Score Delta | Risk Delta | Pass Delta |');
    lines.push('| --- | ---: | ---: | ---: |');
    for (const entry of diffEntries) {
      lines.push(`| ${entry.scenarioName} | ${entry.scoreDelta} | ${entry.riskDelta} | ${entry.passedDelta} |`);
    }
  }
  lines.push('');
  lines.push('## Scenario Results');
  lines.push('');
  lines.push('| Scenario | Status | Score | Risk | Delta | Penalties | Fidelity | Provenance | Notes |');
  lines.push('| --- | --- | ---: | ---: | ---: | ---: | --- | --- | --- |');

  for (const scenario of result.scenarios) {
    const status = scenario.passed ? 'PASS' : 'FAIL';
    const sourceScenario = scenarioById.get(scenario.scenarioId);
    const source = sourceScenario?.source;
    const fidelity = source?.fidelity ?? 'n/a';
    const provenance = formatProvenanceCell(sourceScenario);
    const notes = formatScenarioNotes(scenario);
    lines.push(
      `| ${scenario.scenarioName} | ${status} | ${scenario.score} | ${scenario.summary.riskScore} | ${scenario.regression.scoreDelta} | ${scenario.penalties.total} | ${fidelity} | ${provenance} | ${notes} |`,
    );
  }

  return `${lines.join('\n')}\n`;
}

function writeArtifact(
  result: StrikeBenchmarkSuiteResult,
  scenarios: StrikeBenchmarkScenario[],
  scenarioPaths: string[],
  baselinePath: string,
  options: StrikeBenchmarkRunOptions,
): { jsonPath: string; markdownPath: string } {
  fs.mkdirSync(DEFAULT_OUT_DIR, { recursive: true });
  const jsonPath = path.join(DEFAULT_OUT_DIR, 'latest.json');
  const markdownPath = path.join(DEFAULT_OUT_DIR, 'latest.md');
  const payload = {
    generatedAt: new Date().toISOString(),
    scenarioPaths,
    baselinePath,
    runOptions: options,
    ...result,
  };
  fs.writeFileSync(jsonPath, JSON.stringify(payload, null, 2), 'utf8');
  fs.writeFileSync(markdownPath, buildMarkdownSummary(result, scenarios, scenarioPaths, baselinePath, options), 'utf8');
  return { jsonPath, markdownPath };
}

export function main(): void {
  const cli = parseArgs();
  for (const scenarioPath of cli.scenarioPaths) {
    if (!fs.existsSync(scenarioPath)) {
      throw new Error(`Scenario file not found: ${scenarioPath}`);
    }
  }

  const scenarios = readScenarioSet(cli.scenarioPaths);
  const baselineByScenarioId = readBaseline(cli.baselinePath);
  const options: StrikeBenchmarkRunOptions = {
    baselineByScenarioId,
    maxAllowedScoreDrop: cli.maxScoreDrop,
    stabilityRuns: cli.stabilityRuns,
    maxRiskJitter: 0,
    maxScoreJitter: 0,
  };
  const result = runStrikeBenchmarkSuite(scenarios, options);

  printSummary(result);
  const artifactPaths = writeArtifact(result, scenarios, cli.scenarioPaths, cli.baselinePath, options);

  if (cli.writeBaseline) {
    writeBaseline(cli.baselinePath, result, cli.scenarioPaths);
  }

  console.log('');
  console.log(`Artifact: ${artifactPaths.jsonPath}`);
  console.log(`Markdown: ${artifactPaths.markdownPath}`);
  if (cli.writeBaseline) {
    console.log(`Baseline: ${cli.baselinePath}`);
  }

  if (result.failedScenarios > 0) {
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  main();
}
