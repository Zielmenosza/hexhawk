import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { StrikeBenchmarkScenario, StrikeBenchmarkStep } from '../src/utils/strikeBenchmarkHarness.js';

export interface NestIteration {
  iteration: number;
  confidence: number;
  loss: number;
  contradictions: number;
  verdict: string;
  signalCount: number;
  durationMs: number;
}

export interface NestResult {
  file: string;
  date: string;
  status: string;
  finalConfidence: number;
  finalVerdict: string;
  totalGain: number;
  totalIterations: number;
  stopReason: string;
  healerTriggered: boolean;
  keyFindings?: string[];
}

export interface NestIterationsFile {
  file: string;
  date: string;
  iterations: NestIteration[];
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const APP_ROOT = path.resolve(__dirname, '..');
const REPO_ROOT = path.resolve(__dirname, '../..');
const NEST_TESTS_ROOT = path.join(REPO_ROOT, 'nest_tests');
const OUT_PATH = path.join(APP_ROOT, 'scripts', 'strike-benchmarks', 'challenge-derived-scenarios.json');

export function hash32(value: string): number {
  let hash = 0;
  for (let i = 0; i < value.length; i++) {
    hash = ((hash << 5) - hash + value.charCodeAt(i)) | 0;
  }
  return hash >>> 0;
}

export function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

export function challengeNameFromPath(targetPath: string): string {
  const base = path.basename(targetPath);
  const ext = path.extname(base);
  return ext ? base.slice(0, -ext.length) : base;
}

export function loopSteps(baseRip: number, totalSteps: number, event: string = 'step'): StrikeBenchmarkStep[] {
  const offsets = [0x00, 0x02, 0x04, 0x06];
  const steps: StrikeBenchmarkStep[] = [];
  for (let i = 0; i < totalSteps; i++) {
    steps.push({ rip: baseRip + offsets[i % offsets.length], event });
  }
  return steps;
}

export function suspiciousSteps(baseRip: number): StrikeBenchmarkStep[] {
  return [
    { rip: baseRip + 0x00, event: 'step' },
    { rip: baseRip + 0x02, event: 'step' },
    { rip: baseRip + 0x08, event: 'call local' },
    { rip: baseRip + 0x0A, event: 'step' },
    { rip: baseRip + 0x0E, event: 'ret local' },
    { rip: baseRip + 0x12, event: 'step' },
    { rip: baseRip + 0x16, event: 'step' },
    { rip: baseRip + 0x1A, event: 'step' },
  ];
}

export function dropperSteps(baseRip: number): StrikeBenchmarkStep[] {
  return [
    { rip: baseRip + 0x00, event: 'step' },
    { rip: baseRip + 0x50000, event: 'getprocaddress call' },
    { rip: baseRip + 0xA2000, event: 'loadlibrary call' },
    { rip: baseRip + 0xF3000, event: 'jmp resolver' },
    { rip: baseRip + 0xF3010, event: 'step' },
  ];
}

export function packerSteps(baseRip: number): StrikeBenchmarkStep[] {
  const steps = loopSteps(baseRip + 0x1000, 24, 'step');
  steps.push({ rip: baseRip + 0x900000, event: 'jmp handoff' });
  steps.push({ rip: baseRip + 0x900006, event: 'step' });
  return steps;
}

export function ratSteps(baseRip: number): StrikeBenchmarkStep[] {
  return [
    { rip: baseRip + 0x00, event: 'step' },
    { rip: baseRip + 0x30, event: 'IsDebuggerPresent' },
    { rip: baseRip + 0x42, event: 'gs:0x60 peb walk' },
    { rip: baseRip + 0x50000, event: 'getprocaddress call' },
    { rip: baseRip + 0xA1000, event: 'loadlibrary call' },
    { rip: baseRip + 0xF8000, event: 'jmp resolver' },
    { rip: baseRip + 0xF8010, event: 'step' },
  ];
}

export function ransomwareLikeSteps(baseRip: number): StrikeBenchmarkStep[] {
  const steps = loopSteps(baseRip + 0x2000, 22, 'step');
  steps.splice(2, 0, { rip: baseRip + 0x2002, event: 'rdtsc' });
  steps.splice(3, 0, { rip: baseRip + 0x2003, event: 'rdtsc' });
  steps.splice(3, 0, { rip: baseRip + 0x2004, event: 'exception single-step trap' });
  steps.push({ rip: baseRip + 0xA00000, event: 'jmp handoff' });
  steps.push({ rip: baseRip + 0xA00008, event: 'step' });
  return steps;
}

export function buildScenario(
  result: NestResult,
  iterations: NestIteration[],
  folderName: string,
  nestTestsRoot: string = NEST_TESTS_ROOT,
): StrikeBenchmarkScenario {
  const challengeName = challengeNameFromPath(result.file);
  const id = `challenge-${slugify(challengeName)}`;
  const baseRip = 0x400000 + (hash32(challengeName) % 0x100000);
  const confidence = Math.max(0, Math.min(100, result.finalConfidence));
  const maxContradictions = iterations.reduce((max, iter) => Math.max(max, iter.contradictions), 0);

  let steps: StrikeBenchmarkStep[] = [];
  let expectations: StrikeBenchmarkScenario['expectations'] = {};

  switch (result.finalVerdict) {
    case 'dropper': {
      steps = dropperSteps(baseRip);
      expectations = {
        requiredPatternTags: ['dynamic-api-resolution'],
        minRiskScore: Math.min(33, Math.max(20, Math.round(confidence * 0.3))),
      };
      break;
    }
    case 'packer': {
      steps = packerSteps(baseRip);
      expectations = {
        requiredPatternTags: ['self-modifying-code', 'oep-transfer'],
        minHotBlockPct: 8,
        minRiskScore: Math.max(35, Math.round(confidence * 0.6)),
      };
      break;
    }
    case 'rat': {
      steps = ratSteps(baseRip);
      expectations = {
        requiredPatternTags: ['anti-debug-probe', 'peb-walk', 'dynamic-api-resolution'],
        minRiskScore: Math.max(45, Math.round(confidence * 0.75)),
      };
      break;
    }
    case 'ransomware-like': {
      steps = ransomwareLikeSteps(baseRip);
      expectations = {
        requiredPatternTags: ['timing-check', 'exception-probe', 'self-modifying-code', 'oep-transfer'],
        minHotBlockPct: 8,
        minRiskScore: Math.max(50, Math.round(confidence * 0.8)),
      };
      break;
    }
    default: {
      steps = suspiciousSteps(baseRip);
      expectations = {
        forbiddenPatternTags: ['dynamic-api-resolution', 'self-modifying-code', 'oep-transfer', 'anti-debug-probe', 'rop-chain'],
        maxRiskScore: Math.max(15, Math.round(confidence * 0.6) + maxContradictions),
      };
      break;
    }
  }

  return {
    id,
    name: `Challenge Replay - ${challengeName}`,
    description: [
      `Derived from real NEST session logs (${folderName})`,
      `verdict=${result.finalVerdict}`,
      `confidence=${result.finalConfidence}`,
      `iterations=${result.totalIterations}`,
      `stop=${result.stopReason}`,
    ].join(', '),
    source: {
      challenge: challengeName,
      targetPath: result.file,
      sessionLogPath: path.join(nestTestsRoot, folderName, 'session.log'),
      resultPath: path.join(nestTestsRoot, folderName, 'result.json'),
      fidelity: 'derived-from-session',
    },
    steps,
    expectations,
  };
}

export function readJson<T>(filePath: string): T {
  return JSON.parse(fs.readFileSync(filePath, 'utf8')) as T;
}

export interface ChallengeFixtureInput {
  folderName: string;
  result: NestResult;
  iterations: NestIteration[];
}

export function buildScenariosFromInputs(
  inputs: ChallengeFixtureInput[],
  nestTestsRoot: string = NEST_TESTS_ROOT,
): StrikeBenchmarkScenario[] {
  const scenarios = inputs
    .filter(input => input.result.file && input.result.finalVerdict)
    .filter(input => input.result.file.toLowerCase().includes('challenges'))
    .map(input => buildScenario(input.result, input.iterations, input.folderName, nestTestsRoot));

  scenarios.sort((a, b) => a.id.localeCompare(b.id));
  return scenarios;
}

export function collectScenarios(nestTestsRoot: string = NEST_TESTS_ROOT): StrikeBenchmarkScenario[] {
  if (!fs.existsSync(nestTestsRoot)) {
    return [];
  }

  const inputs: ChallengeFixtureInput[] = [];
  const dirs = fs.readdirSync(nestTestsRoot, { withFileTypes: true });

  for (const dirent of dirs) {
    if (!dirent.isDirectory()) {
      continue;
    }

    const folderName = dirent.name;
    const resultPath = path.join(nestTestsRoot, folderName, 'result.json');
    const iterationsPath = path.join(nestTestsRoot, folderName, 'iterations.json');
    if (!fs.existsSync(resultPath) || !fs.existsSync(iterationsPath)) {
      continue;
    }

    const result = readJson<NestResult>(resultPath);
    if (!result.file || !result.finalVerdict) {
      continue;
    }

    if (!result.file.toLowerCase().includes('challenges')) {
      continue;
    }

    const iterFile = readJson<NestIterationsFile>(iterationsPath);
    inputs.push({
      folderName,
      result,
      iterations: iterFile.iterations ?? [],
    });
  }

  return buildScenariosFromInputs(inputs, nestTestsRoot);
}

export function writeScenariosFile(
  scenarios: StrikeBenchmarkScenario[],
  outPath: string = OUT_PATH,
): void {
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(scenarios, null, 2), 'utf8');
}

export function main(): void {
  const scenarios = collectScenarios();
  if (scenarios.length === 0) {
    throw new Error('No challenge-derived NEST session logs found to build STRIKE fixtures.');
  }

  writeScenariosFile(scenarios, OUT_PATH);

  console.log(`Generated ${scenarios.length} challenge-derived STRIKE scenarios.`);
  console.log(`Output: ${OUT_PATH}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  main();
}
