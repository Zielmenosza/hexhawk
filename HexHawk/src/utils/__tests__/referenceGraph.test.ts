import { describe, expect, it } from 'vitest';
import { buildReferenceGraph, formatReferenceGraphMarkdown, exportReferenceGraphJson } from '../referenceGraph';
import type { ProgramAnalysis } from '../disassemblyModel';

function sampleProgram(): ProgramAnalysis {
  return {
    schema: 'hexhawk.disassembly_program.v1',
    advisoryOnly: true,
    authority: 'analysis_evidence_not_gyre_verdict',
    arch: 'x86-64',
    instructions: [
      { address: 0x1000, mnemonic: 'push', operands: 'rbp' },
      { address: 0x1001, mnemonic: 'mov', operands: 'rbp, rsp' },
      { address: 0x1004, mnemonic: 'lea', operands: 'rcx, [rip + 0x1ff5]' },
      { address: 0x100b, mnemonic: 'call', operands: '0x2000' },
      { address: 0x1010, mnemonic: 'cmp', operands: 'eax, 0x2a' },
      { address: 0x1015, mnemonic: 'jne', operands: '0x1030' },
    ],
    functions: [
      {
        id: 'fn_1000',
        name: 'entry',
        startAddress: 0x1000,
        endAddress: 0x1018,
        instructions: [],
        basicBlocks: [
          { id: 'bb_1000', startAddress: 0x1000, endAddress: 0x1015, instructions: [], predecessors: [], successors: [0x1030], confidence: 'high', warnings: [] },
        ],
        startReasons: ['entrypoint'],
        startSource: 'entrypoint',
        endReason: 'return',
        confidence: 'high',
        warnings: [],
      },
      {
        id: 'fn_2000',
        name: 'MessageBoxA',
        startAddress: 0x2000,
        endAddress: 0x2000,
        instructions: [],
        basicBlocks: [],
        startReasons: ['known-call-target'],
        startSource: 'call-target',
        endReason: 'unknown',
        confidence: 'medium',
        warnings: [],
      },
    ],
    basicBlocks: [
      { id: 'bb_1000', startAddress: 0x1000, endAddress: 0x1015, instructions: [], predecessors: [], successors: [0x1030], confidence: 'high', warnings: [] },
    ],
    xrefs: [
      { kind: 'call', from: 0x100b, to: 0x2000, confidence: 'high', evidence: 'call 0x2000' },
      { kind: 'conditional-jump', from: 0x1015, to: 0x1030, confidence: 'medium', evidence: 'jne 0x1030' },
      { kind: 'string', from: 0x1004, to: 0x3000, confidence: 'medium', evidence: 'rip-relative string' },
    ],
    importCalls: [
      { callAddress: 0x100b, targetAddress: 0x2000, importName: 'MessageBoxA', moduleName: 'USER32.dll', confidence: 'high', evidence: 'PE import thunk' },
    ],
    dataReferences: [
      { from: 0x1010, to: 0x4000, access: 'read', confidence: 'low', evidence: 'memory operand' },
    ],
    stringReferences: [
      { from: 0x1004, to: 0x3000, value: 'Hello HexHawk', confidence: 'medium', evidence: 'string table match' },
    ],
    jumpTableCandidates: [],
    callGraph: { nodes: [], edges: [{ from: 0x1000, to: 0x2000, callsite: 0x100b, confidence: 'high' }] },
    warnings: [],
  };
}

describe('referenceGraph', () => {
  it('connects functions, imports, strings, data refs, code blocks, constants, and selected addresses without verdict authority', () => {
    const graph = buildReferenceGraph(sampleProgram(), { selectedAddresses: [0x1010], nodeBudget: 64, edgeBudget: 96 });

    expect(graph.schema).toBe('hexhawk.reference_graph.v1');
    expect(graph.advisory_only).toBe(true);
    expect(graph.authority).toBe('reference_graph_not_gyre_verdict');
    expect(graph.summary.functions).toBeGreaterThanOrEqual(2);
    expect(graph.summary.imports).toBe(1);
    expect(graph.summary.strings).toBe(1);
    expect(graph.summary.basic_blocks).toBe(1);
    expect(graph.summary.data_references).toBe(1);
    expect(graph.summary.constants).toBeGreaterThanOrEqual(1);
    expect(graph.nodes.some(node => node.type === 'selected-address' && node.address === 0x1010)).toBe(true);
    expect(graph.edges.some(edge => edge.kind === 'calls' && edge.evidence.includes('MessageBoxA'))).toBe(true);
    expect(graph.edges.some(edge => edge.kind === 'references-string')).toBe(true);
    expect(graph.edges.some(edge => edge.kind === 'references-data')).toBe(true);
    expect(JSON.stringify(graph)).not.toContain('classification');
    expect(JSON.stringify(graph)).not.toContain('threatScore');
  });

  it('exports deterministic JSON and Markdown with declared limits', () => {
    const graph = buildReferenceGraph(sampleProgram(), { selectedAddresses: [0x1010], nodeBudget: 4, edgeBudget: 4 });
    const exported = exportReferenceGraphJson(graph);
    const markdown = formatReferenceGraphMarkdown(graph);

    expect(JSON.parse(exported)).toMatchObject({ schema: 'hexhawk.reference_graph.v1' });
    expect(markdown).toContain('## Reference Graph');
    expect(markdown).toContain('Advisory static-analysis graph');
    expect(markdown).toContain('Node budget');
    expect(graph.limits.truncated).toBe(true);
  });
});
