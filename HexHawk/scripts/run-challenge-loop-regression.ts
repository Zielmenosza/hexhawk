import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { basename, resolve } from 'node:path';

const repoRoot = basename(process.cwd()) === 'HexHawk'
  ? resolve(process.cwd(), '..')
  : process.cwd();
const nestCli = resolve(repoRoot, 'target', 'debug', process.platform === 'win32' ? 'nest_cli.exe' : 'nest_cli');
const challenge = resolve(repoRoot, 'work', 'recreate_challenges', 'bin', 'pwn110_recreated');
const outDir = resolve(repoRoot, 'work', 'challenge-loop-regression');

function runJson<T>(args: string[]): T {
  const stdout = execFileSync(nestCli, args, {
    cwd: repoRoot,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  return JSON.parse(stdout) as T;
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

if (!existsSync(nestCli)) {
  throw new Error(`nest_cli not found at ${nestCli}; build it with cargo build --manifest-path src-tauri/Cargo.toml --bin nest_cli`);
}
if (!existsSync(challenge)) {
  throw new Error(`challenge corpus subject not found at ${challenge}`);
}

mkdirSync(outDir, { recursive: true });

execFileSync('cargo', ['build', '--manifest-path', 'src-tauri/Cargo.toml', '--bin', 'nest_cli'], {
  cwd: repoRoot,
  stdio: 'inherit',
});

type InspectOutput = {
  sha256?: string;
  file_size?: number;
  architecture?: string;
  file_type?: string;
};

type CfgOutput = {
  nodes: unknown[];
  edges: unknown[];
  truncated?: boolean;
  node_budget?: number;
  edge_budget?: number;
  omitted_nodes?: number;
  omitted_edges?: number;
};

const inspect = runJson<InspectOutput>(['inspect', challenge]);
const cfg = runJson<CfgOutput>(['cfg', challenge, '0', '1024']);

assert(typeof inspect.sha256 === 'string' && inspect.sha256.length === 64, 'inspect must emit a sha256 identity for provenance binding');
assert(cfg.truncated === true, 'pwn110 challenge CFG should exercise the renderer-budget truncation path');
assert(cfg.nodes.length <= 2_000, `CFG node budget exceeded: ${cfg.nodes.length}`);
assert(cfg.edges.length <= 4_000, `CFG edge budget exceeded: ${cfg.edges.length}`);
assert((cfg.omitted_nodes ?? 0) > 0, 'truncated CFG should report omitted nodes');

const provenance = {
  schema: 'hexhawk.challenge-loop-regression.v1',
  subject: challenge,
  backend: {
    cli: nestCli,
    commands: [
      `nest_cli inspect ${JSON.stringify(challenge)}`,
      `nest_cli cfg ${JSON.stringify(challenge)} 0 1024`,
    ],
  },
  inspect: {
    sha256: inspect.sha256,
    file_size: inspect.file_size,
    architecture: inspect.architecture,
    file_type: inspect.file_type,
  },
  cfg: {
    nodes: cfg.nodes.length,
    edges: cfg.edges.length,
    truncated: cfg.truncated,
    node_budget: cfg.node_budget,
    edge_budget: cfg.edge_budget,
    omitted_nodes: cfg.omitted_nodes,
    omitted_edges: cfg.omitted_edges,
  },
};

const outputPath = resolve(outDir, 'pwn110-loop-regression.json');
writeFileSync(outputPath, `${JSON.stringify(provenance, null, 2)}\n`);
console.log(`challenge loop regression passed: ${outputPath}`);
