import { describe, expect, it } from 'vitest';
import { buildFunctionIntelligence, exportFunctionIntelligenceJSON } from '../utils/functionIntelligence';
import type { DebugSnapshot } from '../components/DebuggerPanel';
import type { DecompileResult } from '../utils/decompilerEngine';
import type { FunctionModel, ProgramAnalysis } from '../utils/disassemblyModel';

function fn(overrides: Partial<FunctionModel> = {}): FunctionModel {
  return {
    id: 'function_401000',
    name: 'sub_401000',
    startAddress: 0x401000,
    endAddress: 0x401040,
    instructions: [
      { address: 0x401000, mnemonic: 'push', operands: 'rbp' },
      { address: 0x401010, mnemonic: 'call', operands: '0x402000' },
      { address: 0x401018, mnemonic: 'call', operands: 'rax' },
      { address: 0x401020, mnemonic: 'ret', operands: '' },
    ],
    basicBlocks: [],
    startReasons: ['call-target'],
    startSource: 'call-target',
    endReason: 'return',
    confidence: 'high',
    callingConvention: { name: 'windows-x64', confidence: 'medium', source: 'windows-x64-shadow-space', evidence: ['rcx/rdx argument registers observed'] },
    warnings: [],
    ...overrides,
  };
}

function analysis(func = fn(), overrides: Partial<ProgramAnalysis> = {}): ProgramAnalysis {
  return {
    schema: 'hexhawk.disassembly_program.v1',
    advisoryOnly: true,
    authority: 'analysis_evidence_not_gyre_verdict',
    arch: 'x86-64',
    instructions: func.instructions,
    functions: [func],
    basicBlocks: [],
    xrefs: [],
    importCalls: [],
    dataReferences: [],
    stringReferences: [],
    jumpTableCandidates: [],
    callGraph: { nodes: [], edges: [] },
    warnings: [],
    ...overrides,
  };
}

function decompile(): DecompileResult {
  return {
    functionName: 'sub_401000', startAddress: 0x401000,
    lines: [{ indent: 0, text: 'CreateFileW(path, GENERIC_READ);', kind: 'stmt', address: 0x401010 }],
    varMap: new Map(),
    irBlocks: [{ id: 'b0', start: 0x401000, end: 0x401040, successors: [], allSuccessors: [], stmts: [
      { op: 'call', address: 0x401010, target: 0x402000, name: 'CreateFileW', args: [{ kind: 'expr', text: 'path' }, { kind: 'const', value: 0x80000000 }] },
      { op: 'call', address: 0x401014, target: 0x403000, name: 'VirtualAlloc', args: [{ kind: 'const', value: 0 }, { kind: 'const', value: 0x1000 }, { kind: 'const', value: 0x1000 }, { kind: 'const', value: 0x40 }] },
    ] }],
    structured: { kind: 'seq', nodes: [] }, logicRegions: [], recoveredStructs: [], warnings: [], instrCount: 4,
    maturity: {
      schemaVersion: '1.0.0', advisoryOnly: true, authorityBoundary: 'talon_veil_guidance_not_verdict_authority', architecture: 'x86_64',
      instructionSummary: { total: 4, lifted: 4, unknown: 0, unknownAddresses: [], failedDecodeRanges: [] },
      cfgSummary: { blockCount: 1, edgeCount: 0, backEdgeCount: 0, unreachableBlockCount: 0, unreachableBlocks: [], fallbackPartitioningUsed: false },
      callArgumentRecovery: { callCount: 2, recoveredCallCount: 2, unresolvedCallCount: 0, recoveredArgumentCount: 4, registerWindowCount: 1, stackWindowCount: 0, registerStackWindowCount: 1 },
      stackFrameSummary: { localCount: 0, stackArgCount: 0, registerParamCount: 0, localNames: [], stackArgNames: [], registerParamNames: [] },
      pseudocodeQuality: { uncertainLineCount: 0, warningCount: 0, conservativeRewriteCount: 0, logicRegionCount: 0 },
      explicitIrSummary: { schema: 'hexhawk.decompiler_maturity.explicit_ir.v1', advisoryOnly: true, authority: 'talon_decompiler_advisory_not_gyre_verdict', liftedInstructionCount: 4, unknownInstructionCount: 0, recoveredCallsCount: 2, recoveredArgsCount: 4, recoveredVariablesCount: 0, unresolvedIndirectJumps: 0, unresolvedCalls: 0, structuredBlockPercentage: 100, fallbackMode: 'structured', confidence: 'medium', warnings: [], proofLimits: [] },
      limitations: [],
    },
  };
}

function debugSnapshot(): DebugSnapshot {
  return {
    sessionId: 1, status: 'Paused', registers: { rax: 0, rbx: 0, rcx: 0, rdx: 0, rsi: 0, rdi: 0, rsp: 0, rbp: 0, rip: 0x401010, r8: 0, r9: 0, r10: 0, r11: 0, r12: 0, r13: 0, r14: 0, r15: 0, eflags: 0, cs: 0, ss: 0 },
    stack: [], callStack: [{ frameIndex: 0, returnAddress: 0x401018, framePointer: 0, symbolName: 'sub_401000' }],
    breakpoints: [{ address: 0x401010, enabled: true, condition: 'hit_count >= 1', hitCount: 2 }], stepCount: 1, exitCode: null, lastEvent: 'breakpoint', warnings: [],
  };
}

function keysDeep(value: unknown): string[] {
  if (!value || typeof value !== 'object') return [];
  if (Array.isArray(value)) return value.flatMap(keysDeep);
  return Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => [key, ...keysDeep(child)]);
}

function expectNoVerdictFields(value: unknown) {
  const keys = keysDeep(value);
  expect(keys).not.toContain('classification');
  expect(keys).not.toContain('threatScore');
}

describe('FunctionIntelligence regression corpus', () => {
  it('covers imports, direct calls, indirect limits, inferred boundaries, constants, debugger mapping, and export authority', () => {
    const main = fn({ startSource: 'prologue-pattern', startReasons: ['prologue-pattern'], confidence: 'medium' });
    const callee = fn({ id: 'function_401080', name: 'known_callee', startAddress: 0x401080, endAddress: 0x4010a0, instructions: [] });
    const program = analysis(main, {
      functions: [main, callee],
      xrefs: [
        { kind: 'call', from: 0x401010, to: 0x402000, confidence: 'high', evidence: 'direct import call' },
        { kind: 'call', from: 0x401024, to: 0x401080, confidence: 'high', evidence: 'direct known callee' },
      ],
      importCalls: [
        { callAddress: 0x401010, targetAddress: 0x402000, importName: 'CreateFileW', moduleName: 'kernel32.dll', confidence: 'high', evidence: 'PE import table' },
        { callAddress: 0x401014, targetAddress: 0x403000, importName: 'VirtualAlloc', moduleName: 'kernel32.dll', confidence: 'high', evidence: 'PE import table' },
      ],
    });

    const fi = buildFunctionIntelligence(main, program, decompile(), debugSnapshot());
    const exported = JSON.parse(exportFunctionIntelligenceJSON(fi));

    expect(fi.importCalls.map(entry => entry.importName)).toEqual(['CreateFileW', 'VirtualAlloc']);
    expect(fi.callees.map(edge => edge.targetName)).toContain('known_callee');
    expect(fi.callees.find(edge => edge.importName === 'CreateFileW')?.evidenceBasis).toBe('import-table-proven');
    expect(fi.limits.some(limit => limit.kind === 'indirect-call')).toBe(true);
    expect(fi.boundarySource).toBe('prologue-pattern');
    expect(fi.callingConvention?.abi).toBe('windows-x64');
    expect(fi.callingConvention?.analysisConfidence).toBe('medium');
    expect(fi.importCalls.flatMap(entry => entry.constantAnnotations)).toEqual(expect.arrayContaining(['GENERIC_READ', 'MEM_COMMIT', 'PAGE_EXECUTE_READWRITE']));
    expect(fi.debuggerCallStack?.[0].frames[0].symbolName).toBe('sub_401000');
    expect(fi.conditionalBreakpointHits?.[0]).toMatchObject({ address: 0x401010, hitCount: 2 });
    expect(exported.debugCorrelation.correlationBasis).toBe('symbol-name-match');
    expect(exported.gyre_is_sole_verdict_authority).toBe(true);
    expectNoVerdictFields(exported);
  });
});
