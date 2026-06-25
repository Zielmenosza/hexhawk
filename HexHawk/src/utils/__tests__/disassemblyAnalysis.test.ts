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

});
