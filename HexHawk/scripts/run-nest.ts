/**
 * run-nest — headless NEST CLI runner
 *
 * Runs a full NEST analysis session on a binary file without opening the UI.
 * Spawns `nest_cli` (the compiled Rust binary) for each backend call.
 *
 * Usage:
 *   npm run nest -- <path-to-binary>
 *   npx tsx scripts/run-nest.ts <path-to-binary>
 *
 * Outputs to stdout and writes artifacts to <repo>/nest_tests/<binary-name>/:
 *   session.log                  — human-readable iteration log
 *   result.json                  — legacy final session summary
 *   iterations.json              — legacy per-iteration summary
 *   evidence_bundle/*.json       — typed NEST evidence bundle files
 *
 * The typed evidence bundle is validated before finalization and re-validated
 * after disk write via read-back parsing.
 *
 * Prerequisites:
 *   1. Build the Rust nest_cli binary:
 *        cd src-tauri && cargo build --release --bin nest_cli
 *   2. The binary must be at: src-tauri/target/release/nest_cli.exe (Windows)
 *      or src-tauri/target/release/nest_cli (Linux/macOS)
 */

// ── Node.js localStorage polyfill ────────────────────────────────────────────
// learningStore.ts and nestTrainingStore.ts use localStorage. Provide a no-op
// implementation so they don't throw ReferenceError in Node.js context.
// The CLI runs without persistent learning state — each run is independent.

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

// ── Imports ───────────────────────────────────────────────────────────────────

import * as path  from 'node:path';
import * as fs    from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { NestSessionRunner, type NestIterationResult } from '../src/utils/nestRunner.js';
import { DEFAULT_NEST_CONFIG, type NestConfig } from '../src/utils/nestEngine.js';
import type { NestBackend, DisassemblyResult } from '../src/utils/nestBackend.js';
import {
  buildNestEvidenceBundleFromSession,
  toNestEvidenceFileMap,
  validateBuiltNestEvidenceBundle,
  parseNestEvidenceFileMap,
} from '../src/utils/nestEvidenceIntegration.js';
import type { FileMetadata } from '../src/App.js';
import type { CfgGraph } from '../src/utils/cfgSignalExtractor.js';

// ── ChildProcessNestBackend ───────────────────────────────────────────────────

const __dirname    = path.dirname(fileURLToPath(import.meta.url));
// scripts/ → HexHawk/ → repo root (D:\Project\HexHawk)
const APP_ROOT  = path.resolve(__dirname, '..');   // HexHawk/
const REPO_ROOT = path.resolve(__dirname, '../..'); // D:\Project\HexHawk

// Locate the compiled nest_cli binary.
// Build it first: cd src-tauri && cargo build --release --bin nest_cli
//
// REPO_ROOT = HexHawk/.. The workspace may share a top-level target/ dir
// (common when Cargo.toml at the workspace root sets [workspace]), so we
// probe both src-tauri/target/ and the workspace-root target/.
const NEST_CLI_PATHS = [
  // workspace-root shared target (most common layout)
  path.join(REPO_ROOT, 'target', 'release', 'nest_cli.exe'),
  path.join(REPO_ROOT, 'target', 'release', 'nest_cli'),
  path.join(REPO_ROOT, 'target', 'debug',   'nest_cli.exe'),
  path.join(REPO_ROOT, 'target', 'debug',   'nest_cli'),
  // per-crate target (fallback)
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
    'nest_cli binary not found. Build it first:\n' +
    '  cd src-tauri && cargo build --release --bin nest_cli',
  );
}

function callCli(nestCli: string, ...cliArgs: string[]): unknown {
  const output = execFileSync(nestCli, cliArgs, { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
  return JSON.parse(output);
}

class ChildProcessNestBackend implements NestBackend {
  constructor(private readonly nestCli: string) {}

  async disassembleRange(p: string, offset: number, length: number): Promise<DisassemblyResult> {
    return callCli(this.nestCli, 'disassemble', p, String(offset), String(length)) as DisassemblyResult;
  }

  async buildCfg(p: string, offset: number, length: number): Promise<CfgGraph> {
    return callCli(this.nestCli, 'cfg', p, String(offset), String(length)) as CfgGraph;
  }

  async inspectMetadata(p: string): Promise<FileMetadata> {
    return callCli(this.nestCli, 'inspect', p) as FileMetadata;
  }

  async extractStrings(p: string): Promise<string[]> {
    const result = callCli(this.nestCli, 'strings', p) as {
      ascii: string[];
      unicode: string[];
      urls: string[];
      paths: string[];
      api_names: string[];
      total: number;
    };
    // Merge all categories into one deduped list for NEST signal scoring
    const all = new Set([
      ...result.ascii,
      ...result.unicode,
      ...result.urls,
      ...result.paths,
      ...result.api_names,
    ]);
    return Array.from(all);
  }

  async identifyFormat(p: string): Promise<{ format: string; magic_hex: string; file_size: number; entropy_header_4kb: number }> {
    return callCli(this.nestCli, 'identify', p) as ReturnType<NestBackend['identifyFormat']> extends Promise<infer T> ? T : never;
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function log(msg: string) { process.stdout.write(msg + '\n'); }

function confidenceBar(c: number, width = 20): string {
  const filled = Math.round((c / 100) * width);
  return '[' + '█'.repeat(filled) + '░'.repeat(width - filled) + ']';
}

function readJson(p: string): unknown {
  return JSON.parse(fs.readFileSync(p, 'utf8')) as unknown;
}

// ── Main ───────────────────────────────────────────────────────────────────────

async function main() {
  const binaryPath = process.argv[2];
  if (!binaryPath) {
    log('Usage: npx tsx scripts/run-nest.ts <path-to-binary>');
    process.exit(1);
  }

  if (!fs.existsSync(binaryPath)) {
    log(`Error: File not found: ${binaryPath}`);
    process.exit(1);
  }

  const nestCli = findNestCli();
  const backend = new ChildProcessNestBackend(nestCli);

  log('');
  log('╔══════════════════════════════════════════════════════════╗');
  log('║   HexHawk NEST — Headless Session Runner                 ║');
  log('╚══════════════════════════════════════════════════════════╝');
  log(`  Binary : ${binaryPath}`);
  log(`  Backend: ${nestCli}`);
  log('');

  // ── Step 0: Identify format (works on any file, no parse needed) ────────
  log('[ 0/4 ] Identifying file format...');
  let formatHint = 'unknown';
  try {
    const ident = await backend.identifyFormat(binaryPath);
    formatHint = ident.format;
    log(`         Format  : ${ident.format}  [magic: ${ident.magic_hex}]`);
    log(`         Size    : ${(ident.file_size / 1024 / 1024).toFixed(2)} MB`);
    log(`         Header entropy (4 KB): ${ident.entropy_header_4kb.toFixed(3)}`);
  } catch (e) {
    log(`         Warning: identify failed (${String(e)})`);
  }

  // ── Step 1: Inspect metadata ─────────────────────────────────────────────
  log('[ 1/4 ] Inspecting file metadata...');
  let metadata: FileMetadata | null = null;
  try {
    metadata = await backend.inspectMetadata(binaryPath);
    log(`         ${metadata.architecture}  ${metadata.file_type}  ${(metadata.file_size / 1024).toFixed(0)} KB`);
    log(`         SHA-256: ${metadata.sha256}`);
    log(`         Imports: ${metadata.imports_count}   Exports: ${metadata.exports_count}`);
  } catch (e) {
    log(`         Warning: metadata inspection failed (${String(e)})`);
    log(`         Continuing with format-only analysis (format: ${formatHint})`);
  }

  // ── Step 1b: Extract strings (works on any format) ───────────────────────
  log('[ 1b/4] Extracting strings...');
  let extractedStrings: string[] = [];
  try {
    extractedStrings = await backend.extractStrings(binaryPath);
    log(`         ${extractedStrings.length} unique strings extracted`);
    if (process.env['NEST_VERBOSE']) {
      const sample = extractedStrings.slice(0, 20);
      log(`         Sample: ${sample.join(' | ')}`);
    }
  } catch (e) {
    log(`         Warning: string extraction failed (${String(e)})`);
  }

  // ── Step 2: Initial disassembly ──────────────────────────────────────────
  log('[ 2/4 ] Disassembling entry region...');
  // Use the .text section file offset when available, otherwise fall back to
  // offset 0.  Disassembling from 0 on a PE reads the MZ/PE header (not code)
  // and produces very few useful instructions.
  const textSection = metadata?.sections?.find(
    (s: { name: string }) => s.name === '.text' || s.name === 'text'
  );
  const initialOffset = (textSection as unknown as { file_offset?: number })?.file_offset ?? 0;
  const initialLength = 16384;  // 16 KB of code for richer initial analysis
  let initialDisassembly: DisassemblyResult['instructions'] = [];
  try {
    const res = await backend.disassembleRange(binaryPath, initialOffset, initialLength);
    initialDisassembly = res.instructions;
    log(`         ${initialDisassembly.length} instructions disassembled`);
  } catch (e) {
    log(`         Warning: disassembly failed (${String(e)})`);
  }

  // ── Step 3: Run NEST session ─────────────────────────────────────────────
  log('[ 3/4 ] Starting NEST session...');
  log('');
  log('  Iter  Confidence         Loss    Contradictions  Verdict');
  log('  ────  ─────────────────  ──────  ──────────────  ──────────────────');

  const config: NestConfig = {
    ...DEFAULT_NEST_CONFIG,
    autoAdvance:      true,
    autoAdvanceDelay: 0,
  };

  const iterLog: Array<{
    iteration:     number;
    confidence:    number;
    loss:          number;
    contradictions: number;
    verdict:       string;
    signalCount:   number;
    durationMs:    number;
  }> = [];

  const runner = new NestSessionRunner({
    filePath:            binaryPath,
    config,
    backend,
    metadata,
    initialDisassembly,
    initialOffset,
    initialLength,
    strings:             extractedStrings.map(s => ({ text: s })),
    disassemblyAnalysis: {
      functions:           new Map(),
      suspiciousPatterns:  [],
      loops:               [],
      referenceStrength:   new Map(),
      blockAnalysis:       new Map(),
    },
    echoHints:           [],
    strategyReliability: {},
    onIteration: (result: NestIterationResult) => {
      const { snapshot } = result;
      const conf = snapshot.confidence;
      const loss = (100 - conf).toFixed(1);
      const contra = snapshot.verdict.contradictions?.length ?? 0;
      const verdict = snapshot.verdict.classification.padEnd(18);
      const bar = confidenceBar(conf);
      log(`  #${String(snapshot.iteration + 1).padEnd(3)}  ${bar} ${String(conf).padStart(3)}%  ${loss.padStart(5)}%  ${String(contra).padStart(14)}  ${verdict}`);
      // Verbose signal dump: set NEST_VERBOSE=1 to see per-iteration signal breakdown
      if (process.env['NEST_VERBOSE'] && snapshot.iteration === 0) {
        const v = snapshot.verdict;
        log(`        threatScore=${v.threatScore}  signals:`);
        for (const s of (v.signals ?? [])) {
          log(`          [${s.source.padEnd(12)}] ${s.id.padEnd(30)} w=${s.weight}`);
        }
        for (const n of (v.negativeSignals ?? [])) {
          log(`          [negative     ] ${n.id.padEnd(30)} r=-${n.reduction}`);
        }
      }
      iterLog.push({
        iteration:     snapshot.iteration,
        confidence:    conf,
        loss:          100 - conf,
        contradictions: contra,
        verdict:       snapshot.verdict.classification,
        signalCount:   snapshot.verdict.signals.length,
        durationMs:    snapshot.durationMs,
      });
    },
  });

  const result = await runner.run();

  const { session, summary } = result;
  const finalIter = iterLog[iterLog.length - 1];

  log('');
  log('══════════════════════════════════════════════════════════════');
  log('  NEST SESSION COMPLETE');
  log('══════════════════════════════════════════════════════════════');
  log(`  File          : ${path.basename(binaryPath)}`);
  log(`  Iterations    : ${iterLog.length}`);
  log(`  Final Confidence: ${summary.finalConfidence}%  ${confidenceBar(summary.finalConfidence)}`);
  log(`  Final Verdict : ${summary.finalVerdict}`);
  log(`  Total Gain    : ${summary.improvementTotal >= 0 ? '+' : ''}${summary.improvementTotal}%`);
  log(`  Stop Reason   : ${session.status} (${summary.convergedReason ?? 'n/a'})`);
  log(`  Contradictions: ${finalIter?.contradictions ?? '—'}`);
  log('');

  // Confidence progression
  const progression = iterLog.map(i => `${i.confidence}%`).join(' → ');
  log(`  Confidence progression: ${progression}`);
  log(`  Loss progression:       ${iterLog.map(i => `${i.loss.toFixed(0)}`).join(' → ')}`);
  log('');

  // ── Write artifacts ──────────────────────────────────────────────────────
  // Write to <repo>/nest_tests/<binary-name>/ rather than next to the binary
  // (which may be in a system directory where we lack write permission).
  const binaryName = path.basename(binaryPath, path.extname(binaryPath));
  const outDir = path.join(REPO_ROOT, 'nest_tests', binaryName);
  fs.mkdirSync(outDir, { recursive: true });

  const sessionLog = [
    `NEST Session Log`,
    `Binary : ${binaryPath}`,
    `Date   : ${new Date().toISOString()}`,
    ``,
    `ITERATIONS`,
    `──────────`,
    ...iterLog.map(i =>
      `  #${i.iteration + 1}  confidence=${i.confidence}%  loss=${i.loss.toFixed(1)}%  contradictions=${i.contradictions}  verdict=${i.verdict}  signals=${i.signalCount}  ms=${i.durationMs}`
    ),
    ``,
    `FINAL RESULT`,
    `────────────`,
    `  status    : ${session.status}`,
    `  confidence: ${summary.finalConfidence}%`,
    `  verdict   : ${summary.finalVerdict}`,
    `  gain      : ${summary.improvementTotal >= 0 ? '+' : ''}${summary.improvementTotal}%`,
    `  stop      : ${summary.convergedReason ?? session.status}`,
    `  iterations: ${iterLog.length}`,
  ].join('\n');

  const resultJson = {
    file:            binaryPath,
    date:            new Date().toISOString(),
    status:          session.status,
    finalConfidence: summary.finalConfidence,
    finalVerdict:    summary.finalVerdict,
    totalGain:       summary.improvementTotal,
    totalIterations: iterLog.length,
    stopReason:      summary.convergedReason ?? session.status,
    healerTriggered: false,   // healer requires localStorage; not available headlessly
    keyFindings:     summary.keyFindings,
  };

  const iterationsJson = {
    file:       binaryPath,
    date:       new Date().toISOString(),
    iterations: iterLog,
  };

  const logPath  = path.join(outDir, 'session.log');
  const resPath  = path.join(outDir, 'result.json');
  const iterPath = path.join(outDir, 'iterations.json');
  const evidenceDir = path.join(outDir, 'evidence_bundle');

  fs.writeFileSync(logPath,  sessionLog,                          'utf8');
  fs.writeFileSync(resPath,  JSON.stringify(resultJson,  null, 2), 'utf8');
  fs.writeFileSync(iterPath, JSON.stringify(iterationsJson, null, 2), 'utf8');

  if (!metadata?.sha256 || !metadata.file_size) {
    throw new Error('Cannot emit typed evidence bundle: metadata.sha256 and metadata.file_size are required.');
  }

  const evidenceBundle = buildNestEvidenceBundleFromSession({
    binaryPath,
    binarySha256: metadata.sha256,
    fileSizeBytes: metadata.file_size,
    format: metadata.file_type || formatHint,
    architecture: metadata.architecture || 'unknown',
    session,
    summary,
    actorId: 'system:run-nest',
    actorType: 'system',
    engineBuildId: '1.0.0+run-nest-local',
    gyreBuildId: '1.0.0+run-nest-local',
    gyreSchemaVersion: '1.0.0',
    policyVersion: 'local-policy-1',
    executionMode: 'cli',
    exportMode: 'local-tauri',
  });

  const preWriteValidation = validateBuiltNestEvidenceBundle(evidenceBundle);
  if (!preWriteValidation.ok) {
    const sample = preWriteValidation.issues
      .slice(0, 8)
      .map((i) => `${i.path}: ${i.code} (${i.message})`)
      .join('; ');
    throw new Error(`Evidence bundle validation failed before write (${preWriteValidation.issues.length} issue(s)): ${sample}`);
  }

  fs.mkdirSync(evidenceDir, { recursive: true });
  const fileMap = toNestEvidenceFileMap(evidenceBundle);
  for (const [name, value] of Object.entries(fileMap)) {
    fs.writeFileSync(path.join(evidenceDir, name), JSON.stringify(value, null, 2), 'utf8');
  }

  const loadedFiles: Record<string, unknown> = {
    'manifest.json': readJson(path.join(evidenceDir, 'manifest.json')),
    'binary_identity.json': readJson(path.join(evidenceDir, 'binary_identity.json')),
    'session.json': readJson(path.join(evidenceDir, 'session.json')),
    'iterations.json': readJson(path.join(evidenceDir, 'iterations.json')),
    'deltas.json': readJson(path.join(evidenceDir, 'deltas.json')),
    'final_verdict_snapshot.json': readJson(path.join(evidenceDir, 'final_verdict_snapshot.json')),
    'audit_refs.json': readJson(path.join(evidenceDir, 'audit_refs.json')),
  };

  const runtimeProofPath = path.join(evidenceDir, 'runtime_proof.json');
  if (fs.existsSync(runtimeProofPath)) {
    loadedFiles['runtime_proof.json'] = readJson(runtimeProofPath);
  }

  const readBackValidation = parseNestEvidenceFileMap(loadedFiles);
  if (!readBackValidation.ok) {
    const sample = readBackValidation.issues
      .slice(0, 8)
      .map((i) => `${i.path}: ${i.code} (${i.message})`)
      .join('; ');
    throw new Error(`Evidence bundle read-back validation failed (${readBackValidation.issues.length} issue(s)): ${sample}`);
  }

  log('  Artifacts written:');
  log(`    ${logPath}`);
  log(`    ${resPath}`);
  log(`    ${iterPath}`);
  log(`    ${evidenceDir}`);
  log('  Evidence bundle status: validated pre-write and post-read-back');
  log('');
}

main().catch(e => {
  console.error('\nFatal error:', e);
  process.exit(1);
});
