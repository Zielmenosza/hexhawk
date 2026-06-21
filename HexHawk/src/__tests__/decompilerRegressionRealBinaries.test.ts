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


describe('decompiler control-flow structuring', () => {
  const textOf = (instructions: DisassembledInstruction[], cfg: CfgGraph | null, name: string) =>
    decompile(instructions, cfg, { functionName: name }).lines.map(l => l.text).join('\n');

  it('keeps straight-line sequences free of control-flow keywords', () => {
    const text = textOf([
      { address: 0x1000, mnemonic: 'mov', operands: 'rax, 1' },
      { address: 0x1004, mnemonic: 'add', operands: 'rax, 2' },
      { address: 0x1008, mnemonic: 'ret', operands: '' },
    ], null, 'straight_line');

    expect(text).not.toMatch(/\b(if|else|while|do|for|goto|switch)\b/);
    expect(text).toMatch(/(?:rax|i) = 1;/);
  });

  it('emits if for a one-sided branch that merges back', () => {
    const instructions: DisassembledInstruction[] = [
      { address: 0x2000, mnemonic: 'cmp', operands: 'rax, 0' },
      { address: 0x2004, mnemonic: 'je', operands: '0x2010' },
      { address: 0x2008, mnemonic: 'jmp', operands: '0x2020' },
      { address: 0x2010, mnemonic: 'mov', operands: 'rbx, 1' },
      { address: 0x2020, mnemonic: 'ret', operands: '' },
    ];
    const cfg: CfgGraph = {
      nodes: [
        { id: 'entry', start: 0x2000, end: 0x2004, block_type: 'entry' },
        { id: 'skip', start: 0x2008, end: 0x2008 },
        { id: 'then', start: 0x2010, end: 0x2010 },
        { id: 'join', start: 0x2020, end: 0x2020 },
      ],
      edges: [
        { source: 'entry', target: 'then', kind: 'branch' },
        { source: 'entry', target: 'skip', kind: 'fallthrough' },
        { source: 'skip', target: 'join', kind: 'branch' },
        { source: 'then', target: 'join', kind: 'fallthrough' },
      ],
    };

    const result = decompile(instructions, cfg, { functionName: 'simple_if' });
    const text = result.lines.map(l => l.text).join('\n');
    expect(text).toContain('if (rax == 0) {');
    expect(text).not.toContain('goto 0x');
    expect(result.structured.kind).toBe('seq');
  });

  it('emits if/else when both branches converge at a join', () => {
    const instructions: DisassembledInstruction[] = [
      { address: 0x3000, mnemonic: 'cmp', operands: 'rax, 7' },
      { address: 0x3004, mnemonic: 'jne', operands: '0x3010' },
      { address: 0x3008, mnemonic: 'mov', operands: 'rbx, 1' },
      { address: 0x300c, mnemonic: 'jmp', operands: '0x3020' },
      { address: 0x3010, mnemonic: 'mov', operands: 'rbx, 2' },
      { address: 0x3020, mnemonic: 'ret', operands: '' },
    ];
    const cfg: CfgGraph = {
      nodes: [
        { id: 'entry', start: 0x3000, end: 0x3004, block_type: 'entry' },
        { id: 'else', start: 0x3010, end: 0x3010 },
        { id: 'then', start: 0x3008, end: 0x300c },
        { id: 'join', start: 0x3020, end: 0x3020 },
      ],
      edges: [
        { source: 'entry', target: 'else', kind: 'branch' },
        { source: 'entry', target: 'then', kind: 'fallthrough' },
        { source: 'then', target: 'join', kind: 'branch' },
        { source: 'else', target: 'join', kind: 'fallthrough' },
      ],
    };

    const text = textOf(instructions, cfg, 'if_else');
    expect(text).toContain('if (rax != 7) {');
    expect(text).toContain('} else {');
    expect(text).not.toContain('goto 0x');
  });

  it('emits while for a header-tested loop', () => {
    const instructions: DisassembledInstruction[] = [
      { address: 0x4000, mnemonic: 'cmp', operands: 'rcx, 10' },
      { address: 0x4004, mnemonic: 'jge', operands: '0x4020' },
      { address: 0x4008, mnemonic: 'add', operands: 'rcx, 1' },
      { address: 0x400c, mnemonic: 'jmp', operands: '0x4000' },
      { address: 0x4020, mnemonic: 'ret', operands: '' },
    ];
    const cfg: CfgGraph = {
      nodes: [
        { id: 'header', start: 0x4000, end: 0x4004, block_type: 'entry' },
        { id: 'body', start: 0x4008, end: 0x400c },
        { id: 'exit', start: 0x4020, end: 0x4020 },
      ],
      edges: [
        { source: 'header', target: 'body', kind: 'fallthrough' },
        { source: 'header', target: 'exit', kind: 'branch' },
        { source: 'body', target: 'header', kind: 'branch' },
      ],
    };

    const text = textOf(instructions, cfg, 'while_loop');
    expect(text).toMatch(/(?:while|for)\s*\(/);
    expect(text).not.toContain('goto 0x');
  });

  it('nests an if inside a loop body', () => {
    const instructions: DisassembledInstruction[] = [
      { address: 0x5000, mnemonic: 'cmp', operands: 'rcx, 10' },
      { address: 0x5004, mnemonic: 'jge', operands: '0x5040' },
      { address: 0x5010, mnemonic: 'cmp', operands: 'rax, 0' },
      { address: 0x5014, mnemonic: 'je', operands: '0x5020' },
      { address: 0x5018, mnemonic: 'mov', operands: 'rbx, 1' },
      { address: 0x5020, mnemonic: 'add', operands: 'rcx, 1' },
      { address: 0x5024, mnemonic: 'jmp', operands: '0x5000' },
      { address: 0x5040, mnemonic: 'ret', operands: '' },
    ];
    const cfg: CfgGraph = {
      nodes: [
        { id: 'header', start: 0x5000, end: 0x5004, block_type: 'entry' },
        { id: 'test', start: 0x5010, end: 0x5014 },
        { id: 'then', start: 0x5018, end: 0x5018 },
        { id: 'latch', start: 0x5020, end: 0x5024 },
        { id: 'exit', start: 0x5040, end: 0x5040 },
      ],
      edges: [
        { source: 'header', target: 'test', kind: 'fallthrough' },
        { source: 'header', target: 'exit', kind: 'branch' },
        { source: 'test', target: 'then', kind: 'branch' },
        { source: 'test', target: 'latch', kind: 'fallthrough' },
        { source: 'then', target: 'latch', kind: 'fallthrough' },
        { source: 'latch', target: 'header', kind: 'branch' },
      ],
    };

    const text = textOf(instructions, cfg, 'nested_if_loop');
    expect(text).toMatch(/(?:while|for)\s*\(/);
    expect(text).toContain('if (rax == 0) {');
    expect(text.indexOf('if (')).toBeGreaterThan(text.search(/(?:while|for)\s*\(/));
  });

  it('falls back to labels and gotos for irreducible CFGs without crashing', () => {
    const instructions: DisassembledInstruction[] = [
      { address: 0x6000, mnemonic: 'cmp', operands: 'rax, 0' },
      { address: 0x6004, mnemonic: 'je', operands: '0x6020' },
      { address: 0x6010, mnemonic: 'jmp', operands: '0x6030' },
      { address: 0x6020, mnemonic: 'jmp', operands: '0x6010' },
      { address: 0x6030, mnemonic: 'jmp', operands: '0x6020' },
    ];
    const cfg: CfgGraph = {
      nodes: [
        { id: 'entry', start: 0x6000, end: 0x6004, block_type: 'entry' },
        { id: 'a', start: 0x6010, end: 0x6010 },
        { id: 'b', start: 0x6020, end: 0x6020 },
        { id: 'c', start: 0x6030, end: 0x6030 },
      ],
      edges: [
        { source: 'entry', target: 'a', kind: 'fallthrough' },
        { source: 'entry', target: 'b', kind: 'branch' },
        { source: 'a', target: 'c', kind: 'branch' },
        { source: 'b', target: 'a', kind: 'branch' },
        { source: 'c', target: 'b', kind: 'branch' },
      ],
    };

    const result = decompile(instructions, cfg, { functionName: 'irreducible' });
    const text = result.lines.map(l => l.text).join('\n');
    expect(text).toContain('label_entry:');
    expect(text).toContain('goto label_');
    expect(result.warnings.join(' ')).toContain('Irreducible CFG detected');
  });
});


describe('decompiler switch recovery', () => {
  it('emits a 4-case jump-table switch with a default path', () => {
    const instructions: DisassembledInstruction[] = [
      { address: 0x7000, mnemonic: 'jmp', operands: 'qword ptr [rax*8 + 0x9000]' },
      { address: 0x7010, mnemonic: 'mov', operands: 'eax, 1' },
      { address: 0x7020, mnemonic: 'mov', operands: 'eax, 2' },
      { address: 0x7030, mnemonic: 'mov', operands: 'eax, 3' },
      { address: 0x7040, mnemonic: 'mov', operands: 'eax, 4' },
      { address: 0x7050, mnemonic: 'mov', operands: 'eax, 0' },
      { address: 0x7060, mnemonic: 'ret', operands: '' },
    ];
    const cfg: CfgGraph = {
      nodes: [
        { id: 'dispatch', start: 0x7000, end: 0x7000, block_type: 'entry' },
        { id: 'c0', start: 0x7010, end: 0x7010 },
        { id: 'c1', start: 0x7020, end: 0x7020 },
        { id: 'c2', start: 0x7030, end: 0x7030 },
        { id: 'c3', start: 0x7040, end: 0x7040 },
        { id: 'def', start: 0x7050, end: 0x7050 },
        { id: 'join', start: 0x7060, end: 0x7060 },
      ],
      edges: [
        { source: 'dispatch', target: 'c0', kind: 'branch' },
        { source: 'dispatch', target: 'c1', kind: 'branch' },
        { source: 'dispatch', target: 'c2', kind: 'branch' },
        { source: 'dispatch', target: 'c3', kind: 'branch' },
        { source: 'dispatch', target: 'def', kind: 'branch' },
        { source: 'c0', target: 'join', kind: 'fallthrough' },
        { source: 'c1', target: 'join', kind: 'fallthrough' },
        { source: 'c2', target: 'join', kind: 'fallthrough' },
        { source: 'c3', target: 'join', kind: 'fallthrough' },
        { source: 'def', target: 'join', kind: 'fallthrough' },
      ],
    };

    const text = decompile(instructions, cfg, { functionName: 'jump_table' }).lines.map(l => l.text).join('\n');
    expect(text).toContain('switch (selector) {');
    expect((text.match(/case /g) ?? []).length).toBe(4);
    expect(text).toContain('default:');
  });

  it('collapses a 3-case equality if-chain on the same variable into switch', () => {
    const instructions: DisassembledInstruction[] = [
      { address: 0x8000, mnemonic: 'cmp', operands: 'eax, 1' },
      { address: 0x8004, mnemonic: 'je', operands: '0x8040' },
      { address: 0x8010, mnemonic: 'cmp', operands: 'eax, 2' },
      { address: 0x8014, mnemonic: 'je', operands: '0x8050' },
      { address: 0x8020, mnemonic: 'cmp', operands: 'eax, 3' },
      { address: 0x8024, mnemonic: 'je', operands: '0x8060' },
      { address: 0x8030, mnemonic: 'ret', operands: '' },
      { address: 0x8040, mnemonic: 'ret', operands: '' },
      { address: 0x8050, mnemonic: 'ret', operands: '' },
      { address: 0x8060, mnemonic: 'ret', operands: '' },
    ];
    const cfg: CfgGraph = {
      nodes: [
        { id: 't1', start: 0x8000, end: 0x8004, block_type: 'entry' },
        { id: 't2', start: 0x8010, end: 0x8014 },
        { id: 't3', start: 0x8020, end: 0x8024 },
        { id: 'def', start: 0x8030, end: 0x8030 },
        { id: 'c1', start: 0x8040, end: 0x8040 },
        { id: 'c2', start: 0x8050, end: 0x8050 },
        { id: 'c3', start: 0x8060, end: 0x8060 },
      ],
      edges: [
        { source: 't1', target: 'c1', kind: 'branch' },
        { source: 't1', target: 't2', kind: 'fallthrough' },
        { source: 't2', target: 'c2', kind: 'branch' },
        { source: 't2', target: 't3', kind: 'fallthrough' },
        { source: 't3', target: 'c3', kind: 'branch' },
        { source: 't3', target: 'def', kind: 'fallthrough' },
      ],
    };

    const text = decompile(instructions, cfg, { functionName: 'if_chain_switch' }).lines.map(l => l.text).join('\n');
    expect(text).toContain('switch (eax) {');
    expect(text).toContain('case 1:');
    expect(text).toContain('case 2:');
    expect(text).toContain('case 3:');
  });

  it('does not collapse regular if/else checks on different variables into switch', () => {
    const instructions: DisassembledInstruction[] = [
      { address: 0x9000, mnemonic: 'cmp', operands: 'eax, 1' },
      { address: 0x9004, mnemonic: 'je', operands: '0x9020' },
      { address: 0x9010, mnemonic: 'cmp', operands: 'ebx, 2' },
      { address: 0x9014, mnemonic: 'je', operands: '0x9030' },
      { address: 0x9020, mnemonic: 'ret', operands: '' },
      { address: 0x9030, mnemonic: 'ret', operands: '' },
    ];
    const cfg: CfgGraph = {
      nodes: [
        { id: 'a', start: 0x9000, end: 0x9004, block_type: 'entry' },
        { id: 'b', start: 0x9010, end: 0x9014 },
        { id: 'ta', start: 0x9020, end: 0x9020 },
        { id: 'tb', start: 0x9030, end: 0x9030 },
      ],
      edges: [
        { source: 'a', target: 'ta', kind: 'branch' },
        { source: 'a', target: 'b', kind: 'fallthrough' },
        { source: 'b', target: 'tb', kind: 'branch' },
        { source: 'b', target: 'ta', kind: 'fallthrough' },
      ],
    };

    const text = decompile(instructions, cfg, { functionName: 'not_switch' }).lines.map(l => l.text).join('\n');
    expect(text).not.toContain('switch (');
    expect(text).toContain('if (eax == 1) {');
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
