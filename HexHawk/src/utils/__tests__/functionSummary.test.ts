import { describe, expect, it } from 'vitest';
import { generateFunctionSummary, buildFunctionSummaryPrompt } from '../functionSummary';
import type { FunctionIntelligence } from '../functionIntelligence';

function fi(overrides: Partial<FunctionIntelligence> = {}): FunctionIntelligence {
  return {
    id: 'function_401000',
    address: 0x401000,
    endAddress: 0x401050,
    name: 'sub_401000',
    nameSource: 'heuristic',
    callingConvention: { abi: 'windows-x64', analysisConfidence: 'medium', evidence: 'uses rcx' },
    instructionCount: 12,
    boundarySource: 'call-target',
    callers: [{ targetAddress: 0x400100, targetName: 'main', evidenceBasis: 'static-only' }],
    callees: [{ targetAddress: 0x402000, targetName: 'CreateFileW', importName: 'CreateFileW', moduleName: 'kernel32.dll', constantAnnotations: ['GENERIC_READ'], evidenceBasis: 'import-table-proven' }],
    xrefCount: 2,
    importCalls: [{ importName: 'CreateFileW', moduleName: 'kernel32.dll', callAddress: 0x401010, constantAnnotations: ['GENERIC_READ', 'OPEN_EXISTING'] }],
    pseudocode: 'CreateFileW(path, GENERIC_READ);',
    sources: {
      hasImportTableEntry: true,
      hasXRefIndex: true,
      hasBoundaryHeuristic: true,
      hasConstantAnnotation: true,
      hasDecompilerOutput: true,
      hasDebuggerCallStack: false,
      hasConditionalBreakpointHit: false,
      hasCallingConvention: true,
      hasLibrarySignatureMatch: false,
    },
    limits: [],
    gyre_is_sole_verdict_authority: true,
    advisory_analysis_only: true,
    ...overrides,
  };
}

function textOf(value: unknown): string {
  return JSON.stringify(value).toLowerCase();
}

describe('generateFunctionSummary', () => {
  it('static fallback generates without LLM when patterns match', async () => {
    const summary = await generateFunctionSummary(fi());

    expect(summary.generatedBy).toBe('aetherframe-static-only');
    expect(summary.oneLiner).toBe('File read operation');
    expect(summary.keyOperations.join(' ')).toContain('CreateFileW');
    expect(summary.basis).toContain('pattern matches');
  });

  it('static fallback generates without LLM when no patterns match', async () => {
    const summary = await generateFunctionSummary(fi({ importCalls: [], callees: [], instructionCount: 20 }));

    expect(summary.generatedBy).toBe('aetherframe-static-only');
    expect(summary.oneLiner).toBe('No patterns matched');
    expect(summary.paragraphSummary).toMatch(/Insufficient data/i);
  });

  it('always has advisory authority envelope', async () => {
    const summary = await generateFunctionSummary(fi());

    expect(summary.advisory_only).toBe(true);
    expect(summary.gyre_is_sole_verdict_authority).toBe(true);
    expect(summary.not_a_verdict).toBe(true);
  });

  it('text fields never contain forbidden verdict or malware wording', async () => {
    const summary = await generateFunctionSummary(fi());
    const text = [
      summary.oneLiner,
      summary.paragraphSummary,
      summary.keyOperations.join(' '),
      summary.analystQuestions.join(' '),
      summary.basis,
    ].join(' ').toLowerCase();

    expect(text).not.toContain('malware');
    expect(text).not.toContain('classified');
    expect(text).not.toContain('verdict');
    expect(text).not.toContain('confirmed malware');
    expect(text).not.toContain('proven');
  });

  it('builds a bounded prompt with function evidence and authority rules', () => {
    const prompt = buildFunctionSummaryPrompt(fi(), []);

    expect(prompt).toContain('Function: sub_401000');
    expect(prompt).toContain('CreateFileW');
    expect(prompt).toContain('GYRE is the sole verdict authority');
    expect(prompt.length).toBeLessThan(2500);
  });
});
