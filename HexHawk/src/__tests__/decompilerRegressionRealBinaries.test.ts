import { describe, it, expect } from 'vitest';
import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { decompile, decompilerMaturityToExport, formatDecompilerMaturityMarkdown, type CfgGraph, type DisassembledInstruction } from '../utils/decompilerEngine';

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

  it('emits advisory maturity telemetry for calls, stack frame, CFG, and unknown decode regions', () => {
    const instructions: DisassembledInstruction[] = [
      { address: 0x4000, mnemonic: 'push', operands: 'rbp' },
      { address: 0x4001, mnemonic: 'mov', operands: 'rbp, rsp' },
      { address: 0x4004, mnemonic: 'mov', operands: 'qword ptr [rbp - 0x8], rcx' },
      { address: 0x4008, mnemonic: 'mov', operands: 'rdi, 0x2a' },
      { address: 0x400c, mnemonic: 'call', operands: '0x5000' },
      { address: 0x4011, mnemonic: 'ud2', operands: '' },
      { address: 0x4013, mnemonic: 'jne', operands: '0x4008' },
      { address: 0x4018, mnemonic: 'ret', operands: '' },
    ];
    const cfg: CfgGraph = {
      nodes: [
        { id: 'entry', start: 0x4000, end: 0x4013, block_type: 'entry' },
        { id: 'exit', start: 0x4018, end: 0x4018, block_type: 'exit' },
        { id: 'orphan', start: 0x5000, end: 0x5001, block_type: 'orphan' },
      ],
      edges: [
        { source: 'entry', target: 'entry', kind: 'back' },
        { source: 'entry', target: 'exit', kind: 'fallthrough' },
      ],
    };

    const result = decompile(instructions, cfg, { startAddress: 0x4000, endAddress: 0x4018, functionName: 'maturity_fixture' });
    const maturity = result.maturity;

    expect(maturity.advisoryOnly).toBe(true);
    expect(maturity.authorityBoundary).toBe('talon_veil_guidance_not_verdict_authority');
    expect(maturity.instructionSummary.total).toBe(instructions.length);
    expect(maturity.instructionSummary.unknown).toBeGreaterThanOrEqual(1);
    expect(maturity.instructionSummary.failedDecodeRanges[0]?.start).toBe(0x4011);
    expect(maturity.cfgSummary.blockCount).toBe(2);
    expect(maturity.cfgSummary.edgeCount).toBe(2);
    expect(maturity.cfgSummary.backEdgeCount).toBe(1);
    expect(maturity.callArgumentRecovery.callCount).toBe(1);
    expect(maturity.callArgumentRecovery.recoveredCallCount).toBe(1);
    expect(maturity.callArgumentRecovery.recoveredArgumentCount).toBeGreaterThanOrEqual(1);
    expect(maturity.stackFrameSummary.localCount).toBeGreaterThanOrEqual(1);
    expect(maturity.limitations.join(' ')).toContain('advisory analyst guidance only');
  });

  it('exports maturity telemetry without verdict-authority fields or classification mutation', () => {
    const instructions: DisassembledInstruction[] = [
      { address: 0x6000, mnemonic: 'mov', operands: 'rcx, 7' },
      { address: 0x6004, mnemonic: 'call', operands: '0x7000' },
      { address: 0x6009, mnemonic: 'ret', operands: '' },
    ];
    const result = decompile(instructions, null, { startAddress: 0x6000, endAddress: 0x6009, functionName: 'export_fixture' });
    const exported = decompilerMaturityToExport(result);
    const markdown = formatDecompilerMaturityMarkdown(result);

    expect(exported.schema).toBe('hexhawk.decompiler_maturity.v1');
    expect(exported.advisoryOnly).toBe(true);
    expect(JSON.stringify(exported)).not.toContain('classification');
    expect(JSON.stringify(exported)).not.toContain('threatScore');
    expect(markdown).toContain('Advisory only');
    expect(markdown).toContain('does not mutate NEST final verdicts');
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
