import { describe, expect, it } from 'vitest';
import type { FunctionIntelligence } from '../functionIntelligence';
import { buildFunctionEvidenceDossier, validateFunctionEvidenceDossier } from '../functionDossier';
import { buildStructuredFunctionView } from '../structuredFunctionView';

function fixture(): FunctionIntelligence {
  return {
    id: 'function_401000',
    address: 0x401000,
    endAddress: 0x401030,
    name: 'sub_401000',
    nameSource: 'generated',
    instructionCount: 3,
    boundarySource: 'call-target',
    callers: [],
    callees: [{ targetAddress: 0x402000, targetName: 'CreateFileW', importName: 'CreateFileW', moduleName: 'kernel32.dll', evidenceBasis: 'import-table-proven' }],
    xrefCount: 1,
    importCalls: [{ importName: 'CreateFileW', moduleName: 'kernel32.dll', callAddress: 0x401010, constantAnnotations: ['GENERIC_READ'] }],
    pseudocode: 'void sub_401000() {\n  CreateFileW(path);\n}',
    sources: {
      hasImportTableEntry: true,
      hasXRefIndex: true,
      hasBoundaryHeuristic: true,
      hasConstantAnnotation: true,
      hasDecompilerOutput: true,
      hasDebuggerCallStack: false,
      hasConditionalBreakpointHit: false,
      hasCallingConvention: false,
      hasLibrarySignatureMatch: false,
    },
    limits: [{ kind: 'no-debugger-observation', detail: 'No debugger snapshot was attached.' }],
    gyre_is_sole_verdict_authority: true,
    advisory_analysis_only: true,
  };
}

describe('Function Evidence Dossier', () => {
  it('builds a deterministic, bounded dossier without verdict authority fields', () => {
    const fi = fixture();
    const dossier = buildFunctionEvidenceDossier(fi, buildStructuredFunctionView(fi));

    expect(dossier.schema).toBe('hexhawk.function_evidence_dossier.v1');
    expect(dossier.functionId).toBe(fi.id);
    expect(dossier.referencedImports[0]).toMatchObject({ importName: 'CreateFileW', moduleName: 'kernel32.dll' });
    expect(dossier.pseudocode).toMatchObject({ available: true, advisoryOnly: true, lineCount: 3 });
    expect(dossier.structuredClaims.total).toBeGreaterThan(0);
    expect(dossier.runtimeObservation.callStackObservations).toBe(0);
    expect(dossier.limitations).toContain('No runtime observation is attached to this function dossier.');
    expect(dossier.authority).toEqual({ advisoryOnly: true, gyreVerdictAuthorityUnaffected: true, doesNotClaimRecoveredSource: true });
    expect(validateFunctionEvidenceDossier(dossier)).toEqual({ ok: true, errors: [] });
    expect(JSON.stringify(dossier)).not.toContain('threatScore');
    expect(JSON.stringify(dossier)).not.toContain('classification');
  });

  it('is byte-stable for identical inputs', () => {
    const fi = fixture();
    const structured = buildStructuredFunctionView(fi);
    expect(JSON.stringify(buildFunctionEvidenceDossier(fi, structured))).toBe(JSON.stringify(buildFunctionEvidenceDossier(fi, structured)));
  });
});
