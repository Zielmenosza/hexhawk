import { describe, expect, it } from 'vitest';
import {
  buildProgramAnalysis,
  buildXRefIndex,
  buildXRefs,
  detectFunctionEndCandidate,
  detectFunctionStartCandidates,
  splitBasicBlocks,
} from '../disassemblyAnalysis';
import type { Instruction } from '../disassemblyModel';

const fixture: Instruction[] = [
  { address: 0x1000, mnemonic: 'push', operands: 'rbp', source: 'synthetic-test' },
  { address: 0x1001, mnemonic: 'mov', operands: 'rbp, rsp', source: 'synthetic-test' },
  { address: 0x1004, mnemonic: 'call', operands: '0x2000', source: 'synthetic-test' },
  { address: 0x1009, mnemonic: 'cmp', operands: 'eax, 0', source: 'synthetic-test' },
  { address: 0x100c, mnemonic: 'jne', operands: '0x1018', source: 'synthetic-test' },
  { address: 0x1010, mnemonic: 'mov', operands: 'eax, 1', source: 'synthetic-test' },
  { address: 0x1015, mnemonic: 'jmp', operands: '0x101c', source: 'synthetic-test' },
  { address: 0x1018, mnemonic: 'xor', operands: 'eax, eax', source: 'synthetic-test' },
  { address: 0x101c, mnemonic: 'ret', operands: '', source: 'synthetic-test' },
  { address: 0x2000, mnemonic: 'push', operands: 'rbp', symbol: 'helper', source: 'synthetic-test' },
  { address: 0x2001, mnemonic: 'mov', operands: 'rbp, rsp', source: 'synthetic-test' },
  { address: 0x2004, mnemonic: 'ret', operands: '', source: 'synthetic-test' },
];

describe('typed disassembly analysis foundation', () => {
  it('detects function start candidates with conservative confidence', () => {
    const starts = detectFunctionStartCandidates(fixture, buildXRefs(fixture), { exportedAddresses: [0x2000] });
    const byAddress = new Map(starts.map(start => [start.address, start]));

    expect(byAddress.get(0x1000)?.reasons).toContain('entrypoint');
    expect(byAddress.get(0x1000)?.reasons).toContain('prologue');
    expect(byAddress.get(0x1000)?.confidence).toBe('medium');

    expect(byAddress.get(0x2000)?.reasons).toContain('known-call-target');
    expect(byAddress.get(0x2000)?.reasons).toContain('symbol');
    expect(byAddress.get(0x2000)?.reasons).toContain('export');
    expect(byAddress.get(0x2000)?.confidence).toBe('high');
  });

  it('detects function end candidates from returns and inferred boundaries', () => {
    const firstEnd = detectFunctionEndCandidate(fixture, 0x1000, 0x2000);
    expect(firstEnd.endAddress).toBe(0x101c);
    expect(firstEnd.reason).toBe('return');
    expect(firstEnd.confidence).toBe('high');

    const truncated: Instruction[] = fixture.slice(0, 4);
    const truncatedEnd = detectFunctionEndCandidate(truncated, 0x1000);
    expect(truncatedEnd.reason).toBe('end-of-input');
    expect(truncatedEnd.confidence).toBe('low');
    expect(truncatedEnd.warnings.some(w => w.kind === 'uncertain-function-end')).toBe(true);
  });

  it('builds direct call and jump xrefs', () => {
    const xrefs = buildXRefs(fixture);

    expect(xrefs).toContainEqual(expect.objectContaining({ kind: 'call', from: 0x1004, to: 0x2000, confidence: 'high' }));
    expect(xrefs).toContainEqual(expect.objectContaining({ kind: 'conditional-jump', from: 0x100c, to: 0x1018, confidence: 'high' }));
    expect(xrefs).toContainEqual(expect.objectContaining({ kind: 'jump', from: 0x1015, to: 0x101c, confidence: 'high' }));
  });

  it('uses trusted symbols for function names and direct import call evidence without verdict authority', () => {
    const analysis = buildProgramAnalysis([
      { address: 0x4000, mnemonic: 'push', operands: 'rbp', source: 'synthetic-test' },
      { address: 0x4001, mnemonic: 'mov', operands: 'rbp, rsp', source: 'synthetic-test' },
      { address: 0x4004, mnemonic: 'call', operands: '0x5000', source: 'synthetic-test' },
      { address: 0x4009, mnemonic: 'ret', operands: '', source: 'synthetic-test' },
      { address: 0x5000, mnemonic: 'jmp', operands: '0x6000', symbol: 'kernel32!CreateFileA', source: 'synthetic-test' },
    ]);

    expect(analysis.functions.find(fn => fn.startAddress === 0x5000)?.name).toBe('kernel32!CreateFileA');
    expect(analysis.callGraph.nodes).toContainEqual(expect.objectContaining({ address: 0x5000, name: 'kernel32!CreateFileA' }));
    expect(analysis.importCalls).toContainEqual(expect.objectContaining({
      callAddress: 0x4004,
      targetAddress: 0x5000,
      importName: 'CreateFileA',
      moduleName: 'kernel32',
      confidence: 'high',
    }));
    expect(analysis.importCalls[0]?.evidence).toContain('direct call target symbol kernel32!CreateFileA');
    expect(JSON.stringify(analysis)).not.toContain('classification');
    expect(JSON.stringify(analysis)).not.toContain('threatScore');
  });

  it('splits basic blocks at entries, jump targets, and post-transfer fallthroughs', () => {
    const blocks = splitBasicBlocks(fixture);
    const starts = blocks.map(block => block.startAddress);

    expect(starts).toEqual([0x1000, 0x1010, 0x1018, 0x101c, 0x2000]);
    expect(blocks.find(block => block.startAddress === 0x1000)?.successors).toEqual([0x1010, 0x1018]);
    expect(blocks.find(block => block.startAddress === 0x1010)?.successors).toEqual([0x101c]);
    expect(blocks.find(block => block.startAddress === 0x1018)?.successors).toEqual([0x101c]);
  });

  it('returns an advisory program model with warnings instead of verdict fields', () => {
    const analysis = buildProgramAnalysis([{ address: 0x3000, mnemonic: 'nop', operands: '', source: 'synthetic-test' }]);

    expect(analysis.schema).toBe('hexhawk.disassembly_program.v1');
    expect(analysis.advisoryOnly).toBe(true);
    expect(analysis.authority).toBe('analysis_evidence_not_gyre_verdict');
    expect(analysis.functions[0]?.confidence).toBe('low');
    expect(analysis.warnings.some(w => w.kind === 'uncertain-function-start')).toBe(true);
    expect(analysis.warnings.some(w => w.kind === 'uncertain-function-end')).toBe(true);
    expect(JSON.stringify(analysis)).not.toContain('classification');
    expect(JSON.stringify(analysis)).not.toContain('threatScore');
  });

  it('builds a queryable cross-reference index with O(1)-style lookup maps', () => {
    const analysis = buildProgramAnalysis(fixture);
    const index = buildXRefIndex({
      ...analysis,
      dataReferences: [
        { from: 0x1009, to: 0x3000, access: 'read', confidence: 'medium', evidence: 'synthetic data ref' },
      ],
    });

    expect(index.callersOf(0x2000)).toEqual([expect.objectContaining({ kind: 'call', from: 0x1004, to: 0x2000 })]);
    expect(index.calleesFrom(0x1004)).toEqual([expect.objectContaining({ kind: 'call', from: 0x1004, to: 0x2000 })]);
    expect(index.jumpsTo(0x1018)).toEqual([expect.objectContaining({ kind: 'conditional-jump', from: 0x100c, to: 0x1018 })]);
    expect(index.dataRefsTo(0x3000)).toEqual([expect.objectContaining({ kind: 'data', from: 0x1009, to: 0x3000 })]);
    expect(index.refsTo(0x101c)).toEqual([expect.objectContaining({ kind: 'jump', from: 0x1015, to: 0x101c })]);
    expect(index.refsFrom(0x1004)).toEqual([expect.objectContaining({ kind: 'call', from: 0x1004, to: 0x2000 })]);
    expect(index.refCount(0x2000)).toBe(1);
  });

  it('returns empty xref-index results for empty analysis without crashing', () => {
    const index = buildXRefIndex(buildProgramAnalysis([]));

    expect(index.callersOf(0x401000)).toEqual([]);
    expect(index.calleesFrom(0x401000)).toEqual([]);
    expect(index.jumpsTo(0x401000)).toEqual([]);
    expect(index.dataRefsTo(0x401000)).toEqual([]);
    expect(index.refsTo(0x401000)).toEqual([]);
    expect(index.refsFrom(0x401000)).toEqual([]);
    expect(index.refCount(0x401000)).toBe(0);
  });


  it('promotes prologue-pattern functions without prior calls as medium-confidence heuristic entries', () => {
    const analysis = buildProgramAnalysis([
      { address: 0x6000, mnemonic: 'push', operands: 'rdi', source: 'synthetic-test' },
      { address: 0x6001, mnemonic: 'push', operands: 'rsi', source: 'synthetic-test' },
      { address: 0x6002, mnemonic: 'ret', operands: '', source: 'synthetic-test' },
    ]);

    const fn = analysis.functions.find(candidate => candidate.startAddress === 0x6000);
    expect(fn).toMatchObject({ confidence: 'medium', startSource: 'prologue-pattern' });
    expect(fn?.startReasons).toContain('prologue-pattern');
  });

  it('promotes jump-table targets as medium-confidence heuristic function entries', () => {
    const analysis = buildProgramAnalysis([
      { address: 0x7000, mnemonic: 'jmp', operands: '0x7100', source: 'synthetic-test' },
      { address: 0x7100, mnemonic: 'mov', operands: 'eax, 1', source: 'synthetic-test' },
      { address: 0x7102, mnemonic: 'ret', operands: '', source: 'synthetic-test' },
    ], { jumpTableTargets: [0x7100] });

    const fn = analysis.functions.find(candidate => candidate.startAddress === 0x7100);
    expect(fn).toMatchObject({ confidence: 'medium', startSource: 'jump-table-target' });
    expect(fn?.startReasons).toContain('jump-table-target');
  });

  it('promotes instruction after short NOP padding gap as low-confidence heuristic entry', () => {
    const analysis = buildProgramAnalysis([
      { address: 0x8000, mnemonic: 'push', operands: 'rbp', source: 'synthetic-test' },
      { address: 0x8001, mnemonic: 'mov', operands: 'rbp, rsp', source: 'synthetic-test' },
      { address: 0x8004, mnemonic: 'ret', operands: '', source: 'synthetic-test' },
      { address: 0x8005, mnemonic: 'nop', operands: '', source: 'synthetic-test' },
      { address: 0x8006, mnemonic: 'nop', operands: '', source: 'synthetic-test' },
      { address: 0x8010, mnemonic: 'mov', operands: 'eax, 2', source: 'synthetic-test' },
      { address: 0x8012, mnemonic: 'ret', operands: '', source: 'synthetic-test' },
    ]);

    const fn = analysis.functions.find(candidate => candidate.startAddress === 0x8010);
    expect(fn).toMatchObject({ confidence: 'low', startSource: 'alignment-gap' });
    expect(fn?.startReasons).toContain('alignment-gap');
  });

  it('keeps existing call-target functions high-confidence without duplicating entries', () => {
    const analysis = buildProgramAnalysis([
      { address: 0x9000, mnemonic: 'call', operands: '0x9010', source: 'synthetic-test' },
      { address: 0x9005, mnemonic: 'ret', operands: '', source: 'synthetic-test' },
      { address: 0x9010, mnemonic: 'push', operands: 'rbp', source: 'synthetic-test' },
      { address: 0x9011, mnemonic: 'mov', operands: 'rbp, rsp', source: 'synthetic-test' },
      { address: 0x9014, mnemonic: 'ret', operands: '', source: 'synthetic-test' },
    ]);

    const matches = analysis.functions.filter(candidate => candidate.startAddress === 0x9010);
    expect(matches).toHaveLength(1);
    expect(matches[0]).toMatchObject({ confidence: 'high', startSource: 'call-target' });
    expect(matches[0].startReasons).toEqual(expect.arrayContaining(['known-call-target', 'call-target', 'prologue-pattern']));
  });


  it('infers known Win32 import prototypes as high-confidence Windows x64 metadata', () => {
    const analysis = buildProgramAnalysis([
      { address: 0x5000, mnemonic: 'jmp', operands: '0x6000', symbol: 'KERNEL32.dll!CreateFileW', source: 'synthetic-test' },
    ], { imports: [{ name: 'CreateFileW', dll: 'KERNEL32.dll', thunk_va: 0x5000 }] });

    const fn = analysis.functions.find(candidate => candidate.startAddress === 0x5000);
    expect(fn?.callingConvention).toMatchObject({
      name: 'windows-x64',
      confidence: 'high',
      source: 'import-prototype',
    });
    expect(fn?.callingConvention?.evidence.join(' ')).toContain('CreateFileW');
    expect(JSON.stringify(analysis)).not.toContain('classification');
    expect(JSON.stringify(analysis)).not.toContain('threatScore');
  });

  it('infers Windows x64 shadow-space stack frames with medium confidence', () => {
    const analysis = buildProgramAnalysis([
      { address: 0xA000, mnemonic: 'push', operands: 'rbp', source: 'synthetic-test' },
      { address: 0xA001, mnemonic: 'mov', operands: 'rbp, rsp', source: 'synthetic-test' },
      { address: 0xA004, mnemonic: 'sub', operands: 'rsp, 0x28', source: 'synthetic-test' },
      { address: 0xA008, mnemonic: 'ret', operands: '', source: 'synthetic-test' },
    ]);

    expect(analysis.functions[0]?.callingConvention).toMatchObject({
      name: 'windows-x64',
      confidence: 'medium',
      source: 'windows-x64-shadow-space',
    });
    expect(analysis.functions[0]?.callingConvention?.evidence.join(' ')).toContain('shadow space');
  });

  it('infers SysV x64 register-use patterns with medium confidence', () => {
    const analysis = buildProgramAnalysis([
      { address: 0xB000, mnemonic: 'push', operands: 'rdi', source: 'synthetic-test' },
      { address: 0xB001, mnemonic: 'push', operands: 'rsi', source: 'synthetic-test' },
      { address: 0xB002, mnemonic: 'mov', operands: 'rax, rdi', source: 'synthetic-test' },
      { address: 0xB005, mnemonic: 'ret', operands: '', source: 'synthetic-test' },
    ]);

    expect(analysis.functions[0]?.callingConvention).toMatchObject({
      name: 'sysv-x64',
      confidence: 'medium',
      source: 'sysv-register-use',
    });
  });

  it('uses an unknown low-confidence fallback when no calling-convention signal is present', () => {
    const analysis = buildProgramAnalysis([
      { address: 0xC000, mnemonic: 'nop', operands: '', source: 'synthetic-test' },
      { address: 0xC001, mnemonic: 'ret', operands: '', source: 'synthetic-test' },
    ]);

    expect(analysis.functions[0]?.callingConvention).toMatchObject({
      name: 'unknown',
      confidence: 'low',
      source: 'default-unknown',
    });
  });

  it('keeps conflicting calling-convention signals conservative instead of high-confidence', () => {
    const analysis = buildProgramAnalysis([
      { address: 0xD000, mnemonic: 'push', operands: 'rdi', source: 'synthetic-test' },
      { address: 0xD001, mnemonic: 'push', operands: 'rsi', source: 'synthetic-test' },
      { address: 0xD002, mnemonic: 'sub', operands: 'rsp, 0x28', source: 'synthetic-test' },
      { address: 0xD006, mnemonic: 'mov', operands: 'rcx, rdi', source: 'synthetic-test' },
      { address: 0xD009, mnemonic: 'ret', operands: '', source: 'synthetic-test' },
    ]);

    expect(analysis.functions[0]?.callingConvention?.confidence).not.toBe('high');
    expect(analysis.functions[0]?.callingConvention).toMatchObject({
      name: 'unknown',
      confidence: 'low',
      source: 'default-unknown',
    });
    expect(analysis.functions[0]?.callingConvention?.evidence.join(' ')).toContain('conflicting');
  });

  it('preserves function-boundary metadata while adding calling-convention metadata', () => {
    const analysis = buildProgramAnalysis([
      { address: 0xE000, mnemonic: 'call', operands: '0xE010', source: 'synthetic-test' },
      { address: 0xE005, mnemonic: 'ret', operands: '', source: 'synthetic-test' },
      { address: 0xE010, mnemonic: 'push', operands: 'rbp', source: 'synthetic-test' },
      { address: 0xE011, mnemonic: 'mov', operands: 'rbp, rsp', source: 'synthetic-test' },
      { address: 0xE014, mnemonic: 'mov', operands: 'rcx, rdx', source: 'synthetic-test' },
      { address: 0xE018, mnemonic: 'ret', operands: '', source: 'synthetic-test' },
    ]);
    const fn = analysis.functions.find(candidate => candidate.startAddress === 0xE010);

    expect(fn).toMatchObject({
      startSource: 'call-target',
      endReason: 'return',
      confidence: 'high',
    });
    expect(fn?.startReasons).toEqual(expect.arrayContaining(['known-call-target', 'call-target', 'prologue-pattern']));
    expect(fn?.callingConvention?.name).toBe('windows-x64');
  });


  it('uses honest ARM64 calling-convention limits instead of x86 heuristics', () => {
    const analysis = buildProgramAnalysis([
      { address: 0x4000, mnemonic: 'stp', operands: 'x29, x30, [sp, #-0x10]!', source: 'synthetic-test' },
      { address: 0x4004, mnemonic: 'mov', operands: 'x29, sp', source: 'synthetic-test' },
      { address: 0x4008, mnemonic: 'ret', operands: '', source: 'synthetic-test' },
    ], { architecture: 'arm64' });

    expect(analysis.arch).toBe('arm64');
    expect(analysis.functions[0]?.callingConvention).toMatchObject({
      name: 'arm64-unknown',
      confidence: 'low',
      source: 'arm64-limited',
    });
    expect(analysis.functions[0]?.callingConvention?.evidence.join(' ')).toContain('ARM64');
    expect(analysis.warnings.some(warning => warning.message.includes('ARM64 architecture detected'))).toBe(true);
  });

  it('keeps x86-64 calling-convention behavior unchanged when architecture is x86-64', () => {
    const analysis = buildProgramAnalysis([
      { address: 0xA000, mnemonic: 'push', operands: 'rbp', source: 'synthetic-test' },
      { address: 0xA001, mnemonic: 'mov', operands: 'rbp, rsp', source: 'synthetic-test' },
      { address: 0xA004, mnemonic: 'sub', operands: 'rsp, 0x28', source: 'synthetic-test' },
      { address: 0xA008, mnemonic: 'ret', operands: '', source: 'synthetic-test' },
    ], { architecture: 'x86-64' });

    expect(analysis.arch).toBe('x86-64');
    expect(analysis.functions[0]?.callingConvention).toMatchObject({
      name: 'windows-x64',
      confidence: 'medium',
      source: 'windows-x64-shadow-space',
    });
  });

});
