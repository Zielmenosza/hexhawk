import { describe, expect, it } from 'vitest';
import {
  buildProgramAnalysis,
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
});
