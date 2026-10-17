import { describe, expect, it } from 'vitest';
import { buildStructuredFunctionView } from '../utils/structuredFunctionView';
import { buildFunctionIntelligence } from '../utils/functionIntelligence';
import type { DecompileResult } from '../utils/decompilerEngine';
import type { FunctionModel, ProgramAnalysis } from '../utils/disassemblyModel';

function functionModel(): FunctionModel {
  return {
    id: 'function_401000',
    name: 'sub_401000',
    startAddress: 0x401000,
    endAddress: 0x401030,
    instructions: [
      { address: 0x401000, mnemonic: 'push', operands: 'rbp' },
      { address: 0x401010, mnemonic: 'call', operands: '0x402000' },
      { address: 0x401020, mnemonic: 'ret', operands: '' },
    ],
    basicBlocks: [],
    startReasons: ['call-target'],
    startSource: 'call-target',
    endReason: 'return',
    confidence: 'high',
    warnings: [],
  };
}

function program(fn = functionModel()): ProgramAnalysis {
  return {
    schema: 'hexhawk.disassembly_program.v1',
    advisoryOnly: true,
    authority: 'analysis_evidence_not_gyre_verdict',
    arch: 'x86-64',
    instructions: fn.instructions,
    functions: [fn],
    basicBlocks: [],
    xrefs: [{ kind: 'call', from: 0x401010, to: 0x402000, confidence: 'high', evidence: 'direct import call' }],
    importCalls: [{ callAddress: 0x401010, targetAddress: 0x402000, importName: 'CreateFileW', moduleName: 'kernel32.dll', confidence: 'high', evidence: 'PE import table' }],
    dataReferences: [],
    stringReferences: [],
    jumpTableCandidates: [],
    callGraph: { nodes: [], edges: [] },
    warnings: [],
  };
}

function decompile(): DecompileResult {
  return {
    functionName: 'sub_401000',
    startAddress: 0x401000,
    lines: [
      { indent: 0, text: 'CreateFileW(path);', kind: 'stmt', address: 0x401010 },
      { indent: 0, text: '// indirect tail unresolved', kind: 'uncertain', address: 0x401018, isUncertain: true },
    ],
    varMap: new Map(),
    irBlocks: [],
    structured: { kind: 'seq', nodes: [] },
    logicRegions: [],
    recoveredStructs: [],
    warnings: ['Indirect flow not fully structured.'],
    instrCount: 3,
    maturity: {
      schemaVersion: '1.0.0', advisoryOnly: true, authorityBoundary: 'talon_veil_guidance_not_verdict_authority', architecture: 'x86_64',
      instructionSummary: { total: 3, lifted: 3, unknown: 0, unknownAddresses: [], failedDecodeRanges: [] },
      cfgSummary: { blockCount: 1, edgeCount: 0, backEdgeCount: 0, unreachableBlockCount: 0, unreachableBlocks: [], fallbackPartitioningUsed: false },
      callArgumentRecovery: { callCount: 1, recoveredCallCount: 1, unresolvedCallCount: 0, recoveredArgumentCount: 1, registerWindowCount: 1, stackWindowCount: 0, registerStackWindowCount: 0 },
      stackFrameSummary: { localCount: 0, stackArgCount: 0, registerParamCount: 0, localNames: [], stackArgNames: [], registerParamNames: [] },
      pseudocodeQuality: { uncertainLineCount: 1, warningCount: 1, conservativeRewriteCount: 0, logicRegionCount: 0 },
      explicitIrSummary: { schema: 'hexhawk.decompiler_maturity.explicit_ir.v1', advisoryOnly: true, authority: 'talon_decompiler_advisory_not_gyre_verdict', liftedInstructionCount: 3, unknownInstructionCount: 0, recoveredCallsCount: 1, recoveredArgsCount: 1, recoveredVariablesCount: 0, unresolvedIndirectJumps: 0, unresolvedCalls: 0, structuredBlockPercentage: 75, fallbackMode: 'structured', confidence: 'medium', warnings: [], proofLimits: [] },
      limitations: [],
    },
  };
}

function keysDeep(value: unknown): string[] {
  if (!value || typeof value !== 'object') return [];
  if (Array.isArray(value)) return value.flatMap(keysDeep);
  return Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => [key, ...keysDeep(child)]);
}

describe('Structured Function View Phase 1 contract', () => {
  it('labels every claim as advisory/evidence-backed without verdict authority fields', () => {
    const fn = functionModel();
    const fi = buildFunctionIntelligence(fn, program(fn), decompile());
    const view = buildStructuredFunctionView(fi, decompile());

    expect(view.schema).toBe('hexhawk.structured_function_view.v1');
    expect(view.claims.length).toBeGreaterThan(3);
    expect(view.claims.every(claim => claim.gyre_is_sole_verdict_authority && claim.advisory_analysis_only)).toBe(true);
    expect(view.claims.every(claim => claim.evidenceBasis.length > 0)).toBe(true);
    expect(view.claims.some(claim => claim.label === 'inferred')).toBe(true);
    expect(view.claims.some(claim => claim.source === 'import-table')).toBe(true);
    expect(view.provenance.sourceEvidencePerClaim).toBe(true);
    expect(keysDeep(view)).not.toContain('classification');
    expect(keysDeep(view)).not.toContain('threatScore');
  });
});
