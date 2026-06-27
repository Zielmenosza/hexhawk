import { describe, expect, it } from 'vitest';
import {
  buildFunctionIntelligence,
  correlateDebuggerToFunctions,
  exportFunctionIntelligenceJSON,
  exportFunctionIntelligenceMarkdown,
} from '../functionIntelligence';
import type { DebugSnapshot } from '../../components/DebuggerPanel';
import type { DecompileResult } from '../decompilerEngine';
import type { FunctionModel, ProgramAnalysis } from '../disassemblyModel';

function makeFunction(overrides: Partial<FunctionModel> = {}): FunctionModel {
  return {
    id: 'function_401000',
    name: 'sub_401000',
    startAddress: 0x401000,
    endAddress: 0x401020,
    instructions: [
      { address: 0x401000, mnemonic: 'push', operands: 'rbp' },
      { address: 0x401005, mnemonic: 'call', operands: '0x402000' },
      { address: 0x40100a, mnemonic: 'ret', operands: '' },
    ],
    basicBlocks: [],
    startReasons: ['call-target'],
    startSource: 'call-target',
    endReason: 'return',
    confidence: 'high',
    callingConvention: {
      name: 'windows-x64',
      confidence: 'medium',
      source: 'windows-x64-shadow-space',
      evidence: ['early use of rcx'],
    },
    warnings: [],
    ...overrides,
  };
}

function makeAnalysis(fn = makeFunction(), overrides: Partial<ProgramAnalysis> = {}): ProgramAnalysis {
  return {
    schema: 'hexhawk.disassembly_program.v1',
    advisoryOnly: true,
    authority: 'analysis_evidence_not_gyre_verdict',
    arch: 'x86-64',
    instructions: fn.instructions,
    functions: [fn],
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

function makeDecompileResult(overrides: Partial<DecompileResult> = {}): DecompileResult {
  return {
    functionName: 'sub_401000',
    startAddress: 0x401000,
    lines: [{ indent: 0, text: 'return CreateFileW();', kind: 'stmt', address: 0x401005 }],
    varMap: new Map(),
    irBlocks: [],
    structured: { kind: 'seq', nodes: [] },
    logicRegions: [],
    recoveredStructs: [],
    warnings: [],
    instrCount: 3,
    maturity: {
      schemaVersion: '1.0.0',
      advisoryOnly: true,
      authorityBoundary: 'talon_veil_guidance_not_verdict_authority',
      architecture: 'x86_64',
      instructionSummary: { total: 3, lifted: 3, unknown: 0, unknownAddresses: [], failedDecodeRanges: [] },
      cfgSummary: { blockCount: 1, edgeCount: 0, backEdgeCount: 0, unreachableBlockCount: 0, unreachableBlocks: [], fallbackPartitioningUsed: false },
      callArgumentRecovery: { callCount: 1, recoveredCallCount: 1, unresolvedCallCount: 0, recoveredArgumentCount: 0, registerWindowCount: 0, stackWindowCount: 0, registerStackWindowCount: 0 },
      stackFrameSummary: { localCount: 0, stackArgCount: 0, registerParamCount: 0, localNames: [], stackArgNames: [], registerParamNames: [] },
      pseudocodeQuality: { uncertainLineCount: 0, warningCount: 0, conservativeRewriteCount: 0, logicRegionCount: 0 },
      explicitIrSummary: {
        schema: 'hexhawk.decompiler_maturity.explicit_ir.v1',
        advisoryOnly: true,
        authority: 'talon_decompiler_advisory_not_gyre_verdict',
        liftedInstructionCount: 3,
        unknownInstructionCount: 0,
        recoveredCallsCount: 1,
        recoveredArgsCount: 0,
        recoveredVariablesCount: 0,
        unresolvedIndirectJumps: 0,
        unresolvedCalls: 0,
        structuredBlockPercentage: 100,
        fallbackMode: 'structured',
        confidence: 'medium',
        warnings: [],
        proofLimits: [],
      },
      limitations: [],
    },
    ...overrides,
  };
}

function makeDebugSnapshot(): DebugSnapshot {
  return {
    sessionId: 1,
    status: 'Paused',
    registers: { rax: 0, rbx: 0, rcx: 0, rdx: 0, rsi: 0, rdi: 0, rsp: 0, rbp: 0, rip: 0x401005, r8: 0, r9: 0, r10: 0, r11: 0, r12: 0, r13: 0, r14: 0, r15: 0, eflags: 0, cs: 0, ss: 0 },
    stack: [],
    callStack: [{ frameIndex: 0, returnAddress: 0x401010, framePointer: 0, symbolName: 'sub_401000', moduleName: 'sample.exe' }],
    breakpoints: [{ address: 0x401005, enabled: true, condition: 'hit_count >= 1', hitCount: 1 }],
    stepCount: 1,
    exitCode: null,
    lastEvent: 'breakpoint',
    warnings: [],
  };
}

function keysDeep(value: unknown): string[] {
  if (!value || typeof value !== 'object') return [];
  if (Array.isArray(value)) return value.flatMap(keysDeep);
  return Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => [key, ...keysDeep(child)]);
}

describe('FunctionIntelligence builder', () => {
  it('builds a valid advisory object from only a function and analysis', () => {
    const fn = makeFunction();
    const fi = buildFunctionIntelligence(fn, makeAnalysis(fn));

    expect(fi.id).toBe('function_401000');
    expect(fi.address).toBe(0x401000);
    expect(fi.endAddress).toBe(0x401020);
    expect(fi.gyre_is_sole_verdict_authority).toBe(true);
    expect(fi.advisory_analysis_only).toBe(true);
    expect(fi.callers).toEqual([]);
    expect(fi.callees).toEqual([]);
    expect(fi.sources.hasDecompilerOutput).toBe(false);
  });

  it('populates pseudocode from a decompile result', () => {
    const fn = makeFunction();
    const fi = buildFunctionIntelligence(fn, makeAnalysis(fn), makeDecompileResult());

    expect(fi.pseudocode).toContain('CreateFileW');
    expect(fi.sources.hasDecompilerOutput).toBe(true);
  });

  it('populates debugger call stack from a debug snapshot', () => {
    const fn = makeFunction();
    const fi = buildFunctionIntelligence(fn, makeAnalysis(fn), undefined, makeDebugSnapshot());

    expect(fi.debuggerCallStack?.[0].frames[0].symbolName).toBe('sub_401000');
    expect(fi.conditionalBreakpointHits?.[0]).toMatchObject({ address: 0x401005, condition: 'hit_count >= 1', hitCount: 1 });
    expect(fi.sources.hasDebuggerCallStack).toBe(true);
    expect(fi.sources.hasConditionalBreakpointHit).toBe(true);
  });

  it('populates import calls with resolved constants when TALON IR exposes call args', () => {
    const fn = makeFunction();
    const analysis = makeAnalysis(fn, {
      importCalls: [{ callAddress: 0x401005, targetAddress: 0x402000, importName: 'CreateFileW', moduleName: 'kernel32.dll', confidence: 'high', evidence: 'PE import table' }],
    });
    const decompileResult = makeDecompileResult({
      irBlocks: [{
        id: 'block_401000',
        start: 0x401000,
        end: 0x401020,
        successors: [],
        allSuccessors: [],
        stmts: [{ op: 'call', address: 0x401005, target: 0x402000, name: 'CreateFileW', args: [{ kind: 'expr', text: 'path' }, { kind: 'const', value: 0x80000000 }] }],
      }],
    });

    const fi = buildFunctionIntelligence(fn, analysis, decompileResult);

    expect(fi.importCalls).toEqual([{ importName: 'CreateFileW', moduleName: 'kernel32.dll', callAddress: 0x401005, constantAnnotations: ['GENERIC_READ'] }]);
    expect(fi.sources.hasImportTableEntry).toBe(true);
    expect(fi.sources.hasConstantAnnotation).toBe(true);
  });

  it('always preserves GYRE sole authority and does not emit forbidden field names', () => {
    const fn = makeFunction();
    const fi = buildFunctionIntelligence(fn, makeAnalysis(fn), makeDecompileResult(), makeDebugSnapshot());

    expect(fi.gyre_is_sole_verdict_authority).toBe(true);
    expect(keysDeep(fi)).not.toContain('classification');
    expect(keysDeep(fi)).not.toContain('threatScore');
  });

  it('correlates frame addresses within known function ranges', () => {
    const fn = makeFunction();
    const analysis = makeAnalysis(fn);
    const correlation = correlateDebuggerToFunctions(analysis, makeDebugSnapshot()).get(fn.id);

    expect(correlation).toMatchObject({ observedInCallStack: true, callStackDepth: 0, correlationBasis: 'symbol-name-match' });
  });

  it('correlates frame symbols when addresses do not land in a function range', () => {
    const fn = makeFunction();
    const snapshot = makeDebugSnapshot();
    snapshot.callStack = [{ frameIndex: 0, returnAddress: 0x500000, framePointer: 0, symbolName: 'sub_401000' }];
    const correlation = correlateDebuggerToFunctions(makeAnalysis(fn), snapshot).get(fn.id);

    expect(correlation).toMatchObject({ observedInCallStack: true, callStackDepth: 0, correlationBasis: 'symbol-name-match' });
  });

  it('correlates frame addresses within known function ranges when symbol does not match', () => {
    const fn = makeFunction();
    const snapshot = makeDebugSnapshot();
    snapshot.callStack = [{ frameIndex: 0, returnAddress: 0x401010, framePointer: 0, symbolName: 'other_symbol' }];
    const correlation = correlateDebuggerToFunctions(makeAnalysis(fn), snapshot).get(fn.id);

    expect(correlation).toMatchObject({ observedInCallStack: true, callStackDepth: 0, correlationBasis: 'address-range-match' });
  });

  it('correlates import thunk frame addresses without fabricating symbol matches', () => {
    const fn = makeFunction({ id: 'function_402100', name: 'CreateFileW', startAddress: 0x402100, endAddress: 0x402120, instructions: [], startSource: 'linear-sweep' });
    const snapshot = makeDebugSnapshot();
    snapshot.callStack = [{ frameIndex: 0, returnAddress: 0x402000, framePointer: 0, symbolName: 'kernel32_stub' }];
    const analysis = makeAnalysis(fn, {
      importCalls: [{ callAddress: 0x401005, targetAddress: 0x402000, importName: 'CreateFileW', moduleName: 'kernel32.dll', confidence: 'high', evidence: 'PE import table' }],
    });
    const correlation = correlateDebuggerToFunctions(analysis, snapshot).get(fn.id);

    expect(correlation).toMatchObject({ observedInCallStack: true, callStackDepth: 0, correlationBasis: 'import-stub-match' });
  });

  it('does not fabricate correlation for frames outside all known functions', () => {
    const fn = makeFunction();
    const snapshot = makeDebugSnapshot();
    snapshot.callStack = [{ frameIndex: 0, returnAddress: 0x500000, framePointer: 0, symbolName: 'other_function' }];
    const correlation = correlateDebuggerToFunctions(makeAnalysis(fn), snapshot).get(fn.id);

    expect(correlation).toMatchObject({ observedInCallStack: false, correlationBasis: 'no-correlation' });
  });

  it('labels import-table call plus debugger frame as static-and-observed', () => {
    const caller = makeFunction();
    const imported = makeFunction({ id: 'function_402000', name: 'CreateFileW', startAddress: 0x402000, endAddress: 0x402010, instructions: [] });
    const analysis = makeAnalysis(caller, {
      functions: [caller, imported],
      xrefs: [{ kind: 'call', from: 0x401005, to: 0x402000, confidence: 'high', evidence: 'direct call' }],
      importCalls: [{ callAddress: 0x401005, targetAddress: 0x402000, importName: 'CreateFileW', moduleName: 'kernel32.dll', confidence: 'high', evidence: 'PE import table' }],
    });
    const snapshot = makeDebugSnapshot();
    snapshot.callStack = [{ frameIndex: 0, returnAddress: 0x402000, framePointer: 0, symbolName: 'CreateFileW' }];

    const fi = buildFunctionIntelligence(caller, analysis, undefined, snapshot);

    expect(fi.callees[0].evidenceBasis).toBe('static-and-observed');
  });

  it('labels import-table call without debugger frame as import-table-proven', () => {
    const caller = makeFunction();
    const analysis = makeAnalysis(caller, {
      xrefs: [{ kind: 'call', from: 0x401005, to: 0x402000, confidence: 'high', evidence: 'direct call' }],
      importCalls: [{ callAddress: 0x401005, targetAddress: 0x402000, importName: 'CreateFileW', moduleName: 'kernel32.dll', confidence: 'high', evidence: 'PE import table' }],
    });

    const fi = buildFunctionIntelligence(caller, analysis);

    expect(fi.callees[0].evidenceBasis).toBe('import-table-proven');
  });

  it('labels xref-only call edges as static-only', () => {
    const caller = makeFunction();
    const analysis = makeAnalysis(caller, {
      xrefs: [{ kind: 'call', from: 0x401005, to: 0x402000, confidence: 'high', evidence: 'direct call' }],
    });

    const fi = buildFunctionIntelligence(caller, analysis);

    expect(fi.callees[0].evidenceBasis).toBe('static-only');
  });

  it('adds debugger-observed callee when stack sees a function absent from static xrefs', () => {
    const caller = makeFunction();
    const observed = makeFunction({ id: 'function_403000', name: 'runtime_only', startAddress: 0x403000, endAddress: 0x403020, instructions: [] });
    const snapshot = makeDebugSnapshot();
    snapshot.callStack = [{ frameIndex: 0, returnAddress: 0x403010, framePointer: 0, symbolName: 'runtime_only' }];
    const fi = buildFunctionIntelligence(caller, makeAnalysis(caller, { functions: [caller, observed] }), undefined, snapshot);

    expect(fi.callees).toContainEqual(expect.objectContaining({ targetAddress: 0x403000, targetName: 'runtime_only', evidenceBasis: 'debugger-observed' }));
  });

  it('exports correlation basis with the function intelligence envelope', () => {
    const fi = buildFunctionIntelligence(makeFunction(), makeAnalysis(), makeDecompileResult(), makeDebugSnapshot());
    const parsed = JSON.parse(exportFunctionIntelligenceJSON(fi));

    expect(parsed.debugCorrelation.correlationBasis).toBe('symbol-name-match');
    expect(parsed.gyre_is_sole_verdict_authority).toBe(true);
  });


  it('surfaces ARM64 calling-convention limits in function intelligence', () => {
    const fn = makeFunction({
      callingConvention: { name: 'arm64-unknown', confidence: 'low', source: 'arm64-limited', evidence: ['ARM64 — calling convention inference not yet implemented'] },
    });
    const fi = buildFunctionIntelligence(fn, makeAnalysis(fn, { arch: 'arm64' }));

    expect(fi.callingConvention).toMatchObject({ abi: 'unknown', analysisConfidence: 'low' });
    expect(fi.callingConvention?.evidence).toContain('ARM64');
    expect(fi.limits.some(limit => limit.kind === 'architecture-limit' && limit.detail.includes('ARM64 architecture detected'))).toBe(true);
  });

  it('exports parseable JSON with schema and authority fields', () => {
    const fi = buildFunctionIntelligence(makeFunction(), makeAnalysis(), makeDecompileResult(), makeDebugSnapshot());
    const parsed = JSON.parse(exportFunctionIntelligenceJSON(fi));

    expect(parsed.export_schema).toBe('hexhawk.function_intelligence.v1');
    expect(parsed.gyre_is_sole_verdict_authority).toBe(true);
    expect(parsed.source_evidence_per_claim).toBe(true);
    expect(parsed.generated_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('exports Markdown with advisory disclaimer and all sections when empty', () => {
    const fi = buildFunctionIntelligence(makeFunction(), makeAnalysis());
    const markdown = exportFunctionIntelligenceMarkdown(fi);

    expect(markdown).toContain('*Advisory analysis only. GYRE is sole verdict authority.*');
    expect(markdown).toContain('## Identity');
    expect(markdown).toContain('## Callers');
    expect(markdown).toContain('## Callees');
    expect(markdown).toContain('## Import Calls');
    expect(markdown).toContain('## Pseudocode (advisory — not recovered source)');
    expect(markdown).toContain('## Runtime Observations');
    expect(markdown).toContain('## Analysis Limits');
    expect(markdown).toContain('None observed');
  });

  it('does not export forbidden verdict field names from FunctionIntelligence exports', () => {
    const fi = buildFunctionIntelligence(makeFunction(), makeAnalysis(), makeDecompileResult(), makeDebugSnapshot());
    const json = exportFunctionIntelligenceJSON(fi);
    const markdown = exportFunctionIntelligenceMarkdown(fi);

    expect(json).not.toContain('classification');
    expect(json).not.toContain('threatScore');
    expect(markdown).not.toContain('classification');
    expect(markdown).not.toContain('threatScore');
  });

});
