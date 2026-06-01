import { describe, it, expect } from 'vitest';
import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { decompile, type CfgGraph, type DisassembledInstruction } from '../utils/decompilerEngine';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../');

function findNestCli(): string | null {
  const candidates = [
    path.join(repoRoot, 'target', 'debug', process.platform === 'win32' ? 'nest_cli.exe' : 'nest_cli'),
    path.join(repoRoot, 'src-tauri', 'target', 'debug', process.platform === 'win32' ? 'nest_cli.exe' : 'nest_cli'),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

function parseJsonFromStdout(stdout: string): any {
  const first = stdout.indexOf('{');
  const last = stdout.lastIndexOf('}');
  if (first < 0 || last < 0 || last <= first) {
    throw new Error('Could not find JSON payload in nest_cli output.');
  }
  return JSON.parse(stdout.slice(first, last + 1));
}

function runNestCliJson(nestCliPath: string, args: string[]): any {
  const result = spawnSync(nestCliPath, args, { encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(`nest_cli failed (${result.status}): ${result.stderr || result.stdout}`);
  }
  return parseJsonFromStdout(result.stdout ?? '');
}

describe('decompiler regressions - synthetic fixtures', () => {
  it('recovers call arguments across basic blocks', () => {
    const instructions: DisassembledInstruction[] = [
      { address: 0x1000, mnemonic: 'mov', operands: 'rcx, 42' },
      { address: 0x1004, mnemonic: 'jmp', operands: '0x1010' },
      { address: 0x1010, mnemonic: 'call', operands: '0x2000' },
      { address: 0x1015, mnemonic: 'ret', operands: '' },
    ];
    const cfg: CfgGraph = {
      nodes: [
        { id: 'a', start: 0x1000, end: 0x1004 },
        { id: 'b', start: 0x1010, end: 0x1015 },
      ],
      edges: [{ source: 'a', target: 'b', kind: 'fallthrough' }],
    };

    const result = decompile(instructions, cfg, { startAddress: 0x1000, endAddress: 0x1015, functionName: 'cross_block_call' });
    const callLine = result.lines.find(l => l.text.includes('sub_2000('));

    expect(callLine).toBeDefined();
    expect(callLine?.text).toContain('42');
  });

  it('applies first-pass loop-counter naming heuristics', () => {
    const instructions: DisassembledInstruction[] = [
      { address: 0x3000, mnemonic: 'mov', operands: 'rcx, 0' },
      { address: 0x3004, mnemonic: 'add', operands: 'rcx, 1' },
      { address: 0x3008, mnemonic: 'mov', operands: 'rax, qword ptr [rbx + rcx*4]' },
      { address: 0x300c, mnemonic: 'ret', operands: '' },
    ];

    const result = decompile(instructions, null, { startAddress: 0x3000, endAddress: 0x300c, functionName: 'naming_heuristics' });
    expect(result.varMap.get('reg:rcx')).toBe('i');
  });
});

describe('decompiler regressions - real binaries in workspace', () => {
  const nestCli = findNestCli();
  const binaryCandidates = [
    path.join(repoRoot, 'Challenges', 'Gujian3.exe'),
    path.join(repoRoot, 'Challenges', 'crackme_shroud.exe'),
  ];
  const sampleBinary = binaryCandidates.find(p => existsSync(p));

  const shouldSkip = !nestCli || !sampleBinary;

  it.skipIf(shouldSkip)('falls back to instruction-derived block partition when CFG is non-overlapping', () => {
    const dis = runNestCliJson(nestCli!, ['disassemble', sampleBinary!, '0', '8192']);
    const cfg = runNestCliJson(nestCli!, ['cfg', sampleBinary!, '0', '8192']);

    const instructions = (dis.instructions ?? []) as DisassembledInstruction[];
    const first = instructions[0]?.address;
    const end = instructions[Math.min(instructions.length - 1, 240)]?.address;

    expect(instructions.length).toBeGreaterThan(0);

    const poisonedCfg: CfgGraph = {
      nodes: (cfg.nodes ?? []).map((n: any) => ({
        id: n.id,
        start: typeof n.start === 'number' ? n.start - 0x400000 : 0,
        end: typeof n.end === 'number' ? n.end - 0x400000 : 1,
      })),
      edges: (cfg.edges ?? []).map((e: any) => ({ source: e.source, target: e.target, kind: e.kind })),
    };

    const result = decompile(instructions, poisonedCfg, {
      startAddress: first,
      endAddress: end,
      functionName: 'real_binary_fallback',
    });

    expect(result.irBlocks.length).toBeGreaterThan(0);
    expect(result.warnings.some(w => w.includes('fallback partitioning'))).toBe(true);
    expect(result.lines.some(l => l.text.includes('Could not build basic blocks'))).toBe(false);
  });
});
