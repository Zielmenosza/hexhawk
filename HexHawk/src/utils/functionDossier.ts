import type { FunctionIntelligence } from './functionIntelligence';
import type { StructuredFunctionView } from './structuredFunctionView';

export type FunctionEvidenceDossier = {
  schema: 'hexhawk.function_evidence_dossier.v1';
  functionId: string;
  functionName: string;
  addressRange: { start: number; end: number };
  instructionCount: number;
  callers: Array<{ targetAddress: number; targetName?: string; evidenceBasis: string }>;
  callees: Array<{ targetAddress: number; targetName?: string; evidenceBasis: string }>;
  referencedImports: Array<{ importName: string; moduleName?: string; callAddress: number; constantAnnotations: string[] }>;
  pseudocode: {
    available: boolean;
    advisoryOnly: true;
    lineCount: number;
    limitations: string[];
  };
  structuredClaims: {
    observed: number;
    inferred: number;
    unresolved: number;
    advisory: number;
    total: number;
  };
  runtimeObservation: {
    callStackObservations: number;
    conditionalBreakpointHits: number;
    correlationBasis?: string;
  };
  limitations: string[];
  evidenceIds: string[];
  authority: {
    advisoryOnly: true;
    gyreVerdictAuthorityUnaffected: true;
    doesNotClaimRecoveredSource: true;
  };
};

function hex(address: number): string {
  return `0x${address.toString(16).toUpperCase()}`;
}

export function buildFunctionEvidenceDossier(
  fi: FunctionIntelligence,
  structuredView: StructuredFunctionView,
): FunctionEvidenceDossier {
  const claimCounts = structuredView.claims.reduce(
    (acc, claim) => ({ ...acc, [claim.label]: acc[claim.label] + 1, total: acc.total + 1 }),
    { observed: 0, inferred: 0, unresolved: 0, advisory: 0, total: 0 },
  );
  const runtimeHits = (fi.conditionalBreakpointHits ?? []).reduce((sum, hit) => sum + hit.hitCount, 0);
  const limitations = [
    ...fi.limits.map((limit) => `${limit.kind}${limit.address !== undefined ? ` @ ${hex(limit.address)}` : ''}: ${limit.detail}`),
    ...structuredView.unsupportedClaims,
  ];
  if (!fi.pseudocode) {
    limitations.push('No pseudocode is available for this function in the current analysis session.');
  }
  if (!fi.debuggerCallStack?.length && !fi.conditionalBreakpointHits?.length) {
    limitations.push('No runtime observation is attached to this function dossier.');
  }

  return {
    schema: 'hexhawk.function_evidence_dossier.v1',
    functionId: fi.id,
    functionName: fi.name,
    addressRange: { start: fi.address, end: fi.endAddress },
    instructionCount: fi.instructionCount,
    callers: fi.callers.map((edge) => ({
      targetAddress: edge.targetAddress,
      targetName: edge.targetName ?? edge.importName,
      evidenceBasis: edge.evidenceBasis,
    })),
    callees: fi.callees.map((edge) => ({
      targetAddress: edge.targetAddress,
      targetName: edge.targetName ?? edge.importName,
      evidenceBasis: edge.evidenceBasis,
    })),
    referencedImports: fi.importCalls.map((call) => ({ ...call, constantAnnotations: [...call.constantAnnotations] })),
    pseudocode: {
      available: Boolean(fi.pseudocode),
      advisoryOnly: true,
      lineCount: fi.pseudocode ? fi.pseudocode.split(/\r?\n/).filter(Boolean).length : 0,
      limitations: fi.pseudocode ? ['Pseudocode is advisory and not recovered source.'] : ['Pseudocode unavailable.'],
    },
    structuredClaims: claimCounts,
    runtimeObservation: {
      callStackObservations: fi.debuggerCallStack?.length ?? 0,
      conditionalBreakpointHits: runtimeHits,
      correlationBasis: fi.debugCorrelation?.correlationBasis,
    },
    limitations: Array.from(new Set(limitations)),
    evidenceIds: structuredView.claims.map((claim, index) => `${structuredView.functionId}:${claim.source}:${claim.label}:${claim.address ?? index}`),
    authority: {
      advisoryOnly: true,
      gyreVerdictAuthorityUnaffected: true,
      doesNotClaimRecoveredSource: true,
    },
  };
}

export function validateFunctionEvidenceDossier(dossier: FunctionEvidenceDossier): { ok: boolean; errors: string[] } {
  const errors: string[] = [];
  if (dossier.schema !== 'hexhawk.function_evidence_dossier.v1') errors.push('schema must be hexhawk.function_evidence_dossier.v1.');
  if (!dossier.functionId) errors.push('functionId is required.');
  if (dossier.addressRange.end < dossier.addressRange.start) errors.push('address range must be ordered.');
  if (dossier.authority.gyreVerdictAuthorityUnaffected !== true) errors.push('dossier must not affect GYRE verdict authority.');
  const serialized = JSON.stringify(dossier);
  if (serialized.includes('threatScore')) errors.push('dossier must not contain threatScore authority fields.');
  if (serialized.includes('classification')) errors.push('dossier must not contain classification authority fields.');
  return { ok: errors.length === 0, errors };
}
