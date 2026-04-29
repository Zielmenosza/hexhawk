/**
 * cross-validate — NEST Corpus Cross-Validation Harness
 *
 * Splits corpus/results.json 80/20 train/test (stratified by verdict class),
 * runs NEST on every test-split entry that has an `expectedClass`, and reports
 * precision/recall per verdict type.
 *
 * Usage:
 *   npx tsx scripts/cross-validate.ts [corpus.json] [--seed <n>] [--split <0.8>]
 *
 * Prerequisites:
 *   1. Build nest_cli:  cd src-tauri && cargo build --release --bin nest_cli
 *   2. Corpus must have entries with `binaryPath` pointing to existing files
 *      AND `expectedClass` set (entries without expectedClass are excluded
 *      from precision/recall; they still contribute to train-set signal).
 *
 * Output:
 *   stdout  — per-class precision/recall table + overall accuracy
 *   cross-validate-results.json  — full per-entry results (written to corpus/)
 */

// ── Node.js localStorage polyfill (reused from run-nest.ts) ──────────────────
if (typeof (globalThis as unknown as Record<string, unknown>)['localStorage'] === 'undefined') {
  const _store: Record<string, string> = {};
  (globalThis as unknown as Record<string, unknown>)['localStorage'] = {
    getItem:    (k: string) => _store[k] ?? null,
    setItem:    (k: string, v: string) => { _store[k] = v; },
    removeItem: (k: string) => { delete _store[k]; },
    clear:      () => { for (const k in _store) delete _store[k]; },
    get length()  { return Object.keys(_store).length; },
    key:        (i: number) => Object.keys(_store)[i] ?? null,
  } as Storage;
}

import * as path from 'node:path';
import * as fs   from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { NestSessionRunner } from '../src/utils/nestRunner.js';
import { DEFAULT_NEST_CONFIG } from '../src/utils/nestEngine.js';
import type { NestBackend, DisassemblyResult } from '../src/utils/nestBackend.js';
import type { FileMetadata } from '../src/App.js';
import type { CfgGraph } from '../src/utils/cfgSignalExtractor.js';

// ── Paths ─────────────────────────────────────────────────────────────────────

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');
const APP_ROOT  = path.resolve(__dirname, '..');

const NEST_CLI_PATHS = [
  path.join(REPO_ROOT, 'target', 'release', 'nest_cli.exe'),
  path.join(REPO_ROOT, 'target', 'release', 'nest_cli'),
  path.join(REPO_ROOT, 'target', 'debug',   'nest_cli.exe'),
  path.join(REPO_ROOT, 'target', 'debug',   'nest_cli'),
  path.join(REPO_ROOT, 'src-tauri', 'target', 'release', 'nest_cli.exe'),
  path.join(REPO_ROOT, 'src-tauri', 'target', 'release', 'nest_cli'),
  path.join(REPO_ROOT, 'src-tauri', 'target', 'debug',   'nest_cli.exe'),
  path.join(REPO_ROOT, 'src-tauri', 'target', 'debug',   'nest_cli'),
];

function findNestCli(): string {
  for (const p of NEST_CLI_PATHS) {
    if (fs.existsSync(p)) return p;
  }
  throw new Error(
    'nest_cli binary not found.\nBuild with:  cd src-tauri && cargo build --release --bin nest_cli',
  );
}

function callCli(nestCli: string, ...args: string[]): unknown {
  const out = execFileSync(nestCli, args, { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
  return JSON.parse(out);
}

class ChildProcessNestBackend implements NestBackend {
  constructor(private readonly cli: string) {}
  async disassembleRange(p: string, o: number, l: number): Promise<DisassemblyResult> {
    return callCli(this.cli, 'disassemble', p, String(o), String(l)) as DisassemblyResult;
  }
  async buildCfg(p: string, o: number, l: number): Promise<CfgGraph> {
    return callCli(this.cli, 'cfg', p, String(o), String(l)) as CfgGraph;
  }
  async inspectMetadata(p: string): Promise<FileMetadata> {
    return callCli(this.cli, 'inspect', p) as FileMetadata;
  }
  async extractStrings(p: string): Promise<string[]> {
    const r = callCli(this.cli, 'strings', p) as { ascii: string[]; unicode: string[]; urls: string[]; paths: string[]; api_names: string[] };
    return Array.from(new Set([...r.ascii, ...r.unicode, ...r.urls, ...r.paths, ...r.api_names]));
  }
  async identifyFormat(p: string): Promise<{ format: string; magic_hex: string; file_size: number; entropy_header_4kb: number }> {
    return callCli(this.cli, 'identify', p) as Awaited<ReturnType<NestBackend['identifyFormat']>>;
  }
}

// ── Types ─────────────────────────────────────────────────────────────────────

interface CorpusEntry {
  sha256:          string | null;
  binaryPath:      string;
  filename:        string;
  label:           string;
  groundTruth:     string;
  sizeBytes:       number;
  sizeLimitExceeded: boolean;
  isRuntimeCompanion: boolean;
  nestVerdict:     string;
  nestConfidence:  number | null;
  expectedClass:   string | null;
  tags:            string[];
  notes:           string;
}

interface Corpus {
  version:      number;
  generatedAt:  string;
  totalEntries: number;
  entries:      CorpusEntry[];
}

interface PerClassMetrics {
  tp: number; fp: number; fn: number;
  precision: number; recall: number; f1: number;
  support: number;
}

interface CvResult {
  entry:            CorpusEntry;
  split:            'train' | 'test';
  predictedVerdict: string | null;
  predictedConf:    number | null;
  correct:          boolean | null;  // null if no expectedClass
  error:            string | null;
  durationMs:       number;
}

// ── Seeded shuffle (Fisher-Yates) ─────────────────────────────────────────────

function seededRandom(seed: number): () => number {
  // LCG with known good constants
  let s = seed >>> 0;
  return () => {
    s = Math.imul(1664525, s) + 1013904223 >>> 0;
    return s / 0x100000000;
  };
}

function shuffle<T>(arr: T[], rng: () => number): T[] {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// Stratified 80/20 split — preserves class distribution in both splits.
function stratifiedSplit(
  entries: CorpusEntry[],
  trainFraction: number,
  rng: () => number,
): { train: CorpusEntry[]; test: CorpusEntry[] } {
  // Group by groundTruth
  const groups = new Map<string, CorpusEntry[]>();
  for (const e of entries) {
    const key = e.groundTruth || 'unknown';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(e);
  }

  const train: CorpusEntry[] = [];
  const test:  CorpusEntry[] = [];

  for (const [, group] of groups) {
    const shuffled = shuffle(group, rng);
    const nTrain   = Math.round(shuffled.length * trainFraction);
    train.push(...shuffled.slice(0, nTrain));
    test.push(...shuffled.slice(nTrain));
  }

  return { train, test };
}

// ── NEST run wrapper ──────────────────────────────────────────────────────────

async function runNestOnEntry(
  entry: CorpusEntry,
  backend: NestBackend,
): Promise<{ verdict: string; confidence: number }> {
  const runner = new NestSessionRunner(backend, {
    ...DEFAULT_NEST_CONFIG,
    autoAdvance: true,
    autoAdvanceDelay: 0,
    enableStrike: false,
    maxIterations: 5,
  });

  const meta = await backend.inspectMetadata(entry.binaryPath);
  await runner.initialize(meta);

  let lastVerdict = 'UNKNOWN';
  let lastConf    = 0;

  while (!runner.isComplete()) {
    const snap = await runner.advance();
    lastVerdict = snap.verdict.verdict;
    lastConf    = snap.confidence;
  }

  return { verdict: lastVerdict, confidence: lastConf };
}

// ── Metrics ───────────────────────────────────────────────────────────────────

function computeMetrics(results: CvResult[]): Map<string, PerClassMetrics> {
  const evalResults = results.filter(r => r.split === 'test' && r.expectedClass !== null && !r.error);

  // Gather all class names
  const classes = new Set<string>();
  for (const r of evalResults) {
    if (r.entry.expectedClass) classes.add(r.entry.expectedClass.toLowerCase());
    if (r.predictedVerdict)    classes.add(r.predictedVerdict.toLowerCase());
  }

  const metrics = new Map<string, PerClassMetrics>();

  for (const cls of classes) {
    let tp = 0, fp = 0, fn = 0;
    for (const r of evalResults) {
      const actual    = (r.entry.expectedClass ?? '').toLowerCase();
      const predicted = (r.predictedVerdict ?? '').toLowerCase();
      if (actual === cls && predicted === cls)  tp++;
      else if (actual !== cls && predicted === cls) fp++;
      else if (actual === cls && predicted !== cls) fn++;
    }
    const precision = tp + fp === 0 ? 0 : tp / (tp + fp);
    const recall    = tp + fn === 0 ? 0 : tp / (tp + fn);
    const f1        = precision + recall === 0 ? 0 : 2 * precision * recall / (precision + recall);
    metrics.set(cls, { tp, fp, fn, precision, recall, f1, support: tp + fn });
  }

  return metrics;
}

function printMetricsTable(metrics: Map<string, PerClassMetrics>, evalCount: number, correct: number) {
  console.log('');
  console.log('┌─────────────────────────┬───────────┬────────┬──────────┬─────────┐');
  console.log('│ Class                   │ Precision │ Recall │ F1-Score │ Support │');
  console.log('├─────────────────────────┼───────────┼────────┼──────────┼─────────┤');

  const sortedClasses = [...metrics.entries()].sort((a, b) => b[1].support - a[1].support);

  for (const [cls, m] of sortedClasses) {
    const name = cls.padEnd(23);
    const prec = (m.precision * 100).toFixed(1).padStart(7) + '%';
    const rec  = (m.recall * 100).toFixed(1).padStart(6) + '%';
    const f1   = (m.f1 * 100).toFixed(1).padStart(7) + '%';
    const sup  = String(m.support).padStart(7);
    console.log(`│ ${name} │ ${prec}   │ ${rec}  │ ${f1}   │ ${sup} │`);
  }

  const accuracy = evalCount === 0 ? 0 : (correct / evalCount * 100).toFixed(1);
  console.log('└─────────────────────────┴───────────┴────────┴──────────┴─────────┘');
  console.log(`  Overall accuracy: ${accuracy}%  (${correct}/${evalCount} test entries)`);
  console.log('');
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const argv = process.argv.slice(2);

  const getFlag = (name: string, def: string) => {
    const i = argv.indexOf(name);
    return i >= 0 ? argv[i + 1] ?? def : def;
  };
  const hasFlag = (name: string) => argv.includes(name);

  // Corpus path: first non-flag argument or default
  const corpusArg = argv.find(a => !a.startsWith('--')) ??
    path.join(APP_ROOT, 'corpus', 'results.json');

  const seed          = parseInt(getFlag('--seed', '42'), 10);
  const trainFraction = parseFloat(getFlag('--split', '0.8'));
  const dryRun        = hasFlag('--dry-run');

  if (!fs.existsSync(corpusArg)) {
    console.error(`Corpus not found: ${corpusArg}`);
    process.exit(1);
  }

  const corpus: Corpus = JSON.parse(fs.readFileSync(corpusArg, 'utf8'));
  console.log(`Corpus: ${corpus.totalEntries} entries  (seed=${seed}, train=${(trainFraction * 100).toFixed(0)}%)`);

  // Filter to analysable PE/ELF entries that exist on disk
  const analysable = corpus.entries.filter(e =>
    !e.sizeLimitExceeded &&
    !e.isRuntimeCompanion &&
    fs.existsSync(e.binaryPath),
  );

  console.log(`Analysable (on-disk, no size limit): ${analysable.length}`);
  console.log(`With expectedClass (evaluable):      ${analysable.filter(e => e.expectedClass).length}`);

  if (analysable.length === 0) {
    console.error('No analysable entries found. Ensure binaryPath values point to real files.');
    process.exit(1);
  }

  const rng = seededRandom(seed);
  const { train, test } = stratifiedSplit(analysable, trainFraction, rng);

  console.log(`Train split: ${train.length}  |  Test split: ${test.length}`);
  console.log('');

  if (dryRun) {
    console.log('--dry-run: split computed, skipping NEST analysis.');
    process.exit(0);
  }

  const nestCli = findNestCli();
  const backend = new ChildProcessNestBackend(nestCli);

  const cvResults: CvResult[] = [];

  // Mark train entries (no analysis needed — they define the training distribution)
  for (const e of train) {
    cvResults.push({
      entry: e, split: 'train',
      predictedVerdict: null, predictedConf: null,
      correct: null, error: null, durationMs: 0,
    });
  }

  // Analyse test entries
  let done = 0;
  let correct = 0;
  let evalCount = 0;

  for (const e of test) {
    process.stdout.write(`  [${String(done + 1).padStart(3)}/${test.length}] ${e.filename.padEnd(40)} `);
    const t0 = Date.now();

    let predictedVerdict: string | null = null;
    let predictedConf: number | null    = null;
    let error: string | null            = null;

    try {
      const result = await runNestOnEntry(e, backend);
      predictedVerdict = result.verdict;
      predictedConf    = result.confidence;
    } catch (err) {
      error = String(err);
    }

    const durationMs = Date.now() - t0;

    let isCorrect: boolean | null = null;
    if (e.expectedClass && predictedVerdict && !error) {
      // Map NEST verdict to expected class
      const predicted = nestVerdictToClass(predictedVerdict);
      isCorrect = predicted.toLowerCase() === e.expectedClass.toLowerCase();
      if (isCorrect) correct++;
      evalCount++;
    }

    const status = error ? '✗ ERR' :
      isCorrect === null ? '~ N/A' :
      isCorrect ? '✓ OK ' : '✗ MISS';

    console.log(`${status}  ${predictedVerdict ?? 'N/A'} (${predictedConf ?? '-'}%)  ${durationMs}ms`);

    cvResults.push({
      entry: e, split: 'test',
      predictedVerdict, predictedConf,
      correct: isCorrect, error, durationMs,
    });

    done++;
  }

  // ── Metrics ────────────────────────────────────────────────────────────────
  const metrics = computeMetrics(cvResults);
  printMetricsTable(metrics, evalCount, correct);

  // ── Save results ───────────────────────────────────────────────────────────
  const outPath = path.join(path.dirname(corpusArg), 'cross-validate-results.json');
  const output = {
    generatedAt: new Date().toISOString(),
    corpusPath:  corpusArg,
    seed,
    trainFraction,
    trainCount: train.length,
    testCount:  test.length,
    evalCount,
    accuracy:   evalCount === 0 ? null : correct / evalCount,
    metrics:    Object.fromEntries(metrics),
    results:    cvResults.map(r => ({
      filename:         r.entry.filename,
      split:            r.split,
      expectedClass:    r.entry.expectedClass,
      predictedVerdict: r.predictedVerdict,
      predictedConf:    r.predictedConf,
      correct:          r.correct,
      error:            r.error,
      durationMs:       r.durationMs,
    })),
  };

  fs.writeFileSync(outPath, JSON.stringify(output, null, 2));
  console.log(`Results written to: ${outPath}`);
}

// Map NEST verdict string → expected class name
function nestVerdictToClass(verdict: string): string {
  const map: Record<string, string> = {
    MALWARE:    'malware',
    SUSPICIOUS: 'suspicious',
    CLEAN:      'clean',
    UNKNOWN:    'unknown',
    DROPPER:    'dropper',
    RAT:        'rat',
    RANSOMWARE: 'ransomware',
    PACKER:     'packer',
    CHALLENGE:  'challenge',
  };
  return map[verdict.toUpperCase()] ?? verdict.toLowerCase();
}

main().catch(e => {
  console.error('cross-validate failed:', e);
  process.exit(1);
});
