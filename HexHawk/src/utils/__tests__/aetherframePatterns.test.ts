import { describe, expect, it } from 'vitest';
import { runAetherframePatterns } from '../aetherframePatterns';
import type { FunctionIntelligence, FunctionCallEdge } from '../functionIntelligence';

function edge(overrides: Partial<FunctionCallEdge> = {}): FunctionCallEdge {
  return {
    targetAddress: 0x402000,
    targetName: 'sub_402000',
    evidenceBasis: 'static-only',
    constantAnnotations: [],
    ...overrides,
  };
}

function fi(overrides: Partial<FunctionIntelligence> = {}): FunctionIntelligence {
  return {
    id: 'function_401000',
    address: 0x401000,
    endAddress: 0x401040,
    name: 'sub_401000',
    nameSource: 'generated',
    instructionCount: 24,
    boundarySource: 'prologue-pattern',
    callers: [edge({ targetAddress: 0x400100, targetName: 'caller' })],
    callees: [],
    xrefCount: 0,
    importCalls: [],
    pseudocode: '',
    sources: {
      hasImportTableEntry: false,
      hasXRefIndex: true,
      hasBoundaryHeuristic: true,
      hasConstantAnnotation: false,
      hasDecompilerOutput: false,
      hasDebuggerCallStack: false,
      hasConditionalBreakpointHit: false,
      hasCallingConvention: false,
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

describe('runAetherframePatterns', () => {
  it('matches VirtualAlloc plus PAGE_EXECUTE_READWRITE as shellcode staging', () => {
    const observations = runAetherframePatterns(fi({
      callees: [edge()],
      importCalls: [{ importName: 'VirtualAlloc', callAddress: 0x401010, constantAnnotations: ['MEM_COMMIT', 'PAGE_EXECUTE_READWRITE'] }],
    }));

    expect(observations).toEqual(expect.arrayContaining([
      expect.objectContaining({
        title: 'Executable memory allocation pattern',
        kind: 'suspicious-pattern',
        evidenceBasis: expect.stringContaining('VirtualAlloc'),
        analysisConfidence: 'medium',
      }),
    ]));
  });

  it('matches CreateFileW plus GENERIC_READ as file read operation', () => {
    const observations = runAetherframePatterns(fi({
      importCalls: [{ importName: 'CreateFileW', callAddress: 0x401018, constantAnnotations: ['GENERIC_READ', 'OPEN_EXISTING'] }],
    }));

    expect(observations).toEqual(expect.arrayContaining([
      expect.objectContaining({
        title: 'File read operation',
        kind: 'likely-purpose',
        evidenceBasis: expect.stringContaining('GENERIC_READ'),
        analysisConfidence: 'high',
      }),
    ]));
  });

  it('matches LoadLibraryW plus GetProcAddress as dynamic resolution', () => {
    const observations = runAetherframePatterns(fi({
      importCalls: [
        { importName: 'LoadLibraryW', callAddress: 0x401020, constantAnnotations: [] },
        { importName: 'GetProcAddress', callAddress: 0x401030, constantAnnotations: [] },
      ],
    }));

    expect(observations).toEqual(expect.arrayContaining([
      expect.objectContaining({
        title: 'Dynamic API resolution',
        kind: 'technique-hint',
        evidenceBasis: 'LoadLibraryW and GetProcAddress import calls observed',
        analysisConfidence: 'high',
      }),
    ]));
  });

  it('returns no observations when no pattern matches', () => {
    expect(runAetherframePatterns(fi({ instructionCount: 20, callers: [edge()], callees: [edge()], importCalls: [] }))).toEqual([]);
  });

  it('always returns advisory authority envelopes', () => {
    const observations = runAetherframePatterns(fi({
      importCalls: [{ importName: 'CreateFileA', callAddress: 0x401018, constantAnnotations: ['CREATE_ALWAYS', 'GENERIC_WRITE'] }],
    }));

    expect(observations.length).toBeGreaterThan(0);
    for (const observation of observations) {
      expect(observation.advisory_only).toBe(true);
      expect(observation.gyre_is_sole_verdict_authority).toBe(true);
    }
  });

  it('does not return classification or verdict language', () => {
    const observations = runAetherframePatterns(fi({
      importCalls: [
        { importName: 'LoadLibraryW', callAddress: 0x401020, constantAnnotations: [] },
        { importName: 'GetProcAddress', callAddress: 0x401030, constantAnnotations: [] },
      ],
    }));

    const text = textOf(observations);
    expect(text).not.toContain('classification');
    expect(text).not.toContain('classified as');
    expect(text).not.toContain('verdict:');
    expect(text).not.toContain('confirmed malware');
  });

  it('does not throw on empty FunctionIntelligence', () => {
    expect(() => runAetherframePatterns(fi({
      instructionCount: 0,
      callers: [],
      callees: [],
      importCalls: [],
      limits: [],
    }))).not.toThrow();
  });

  it('matches library-signature named functions as advisory known-library observations', () => {
    const observations = runAetherframePatterns(fi({
      name: 'memcpy',
      nameSource: 'library-signature',
      sources: { ...fi().sources, hasLibrarySignatureMatch: true },
    }));

    expect(observations).toEqual(expect.arrayContaining([
      expect.objectContaining({
        title: 'Known library function',
        body: expect.stringContaining('memcpy'),
        evidenceBasis: expect.stringContaining('library-signature'),
      }),
    ]));
  });
});
