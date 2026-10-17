import type { DebugSnapshot } from '../components/DebuggerPanel';
import type { DecompileResult, PseudoLine } from './decompilerEngine';
import type { FunctionIntelligence } from './functionIntelligence';

export type StructuredFunctionClaimLabel = 'observed' | 'inferred' | 'unresolved' | 'advisory';

export interface StructuredFunctionClaim {
  schema: 'hexhawk.structured_function_claim.v1';
  label: StructuredFunctionClaimLabel;
  text: string;
  address?: number;
  evidenceAddresses: number[];
  evidenceBasis: string[];
  source: 'disassembly' | 'decompiler-ir' | 'import-table' | 'runtime-trace' | 'analysis-limit';
  gyre_is_sole_verdict_authority: true;
  advisory_analysis_only: true;
}

export interface StructuredFunctionView {
  schema: 'hexhawk.structured_function_view.v1';
  functionId: string;
  functionName: string;
  addressRange: { start: number; end: number };
  claims: StructuredFunctionClaim[];
  provenance: {
    hasDecompilerOutput: boolean;
    hasRuntimeObservation: boolean;
    hasImportEvidence: boolean;
    hasAnalysisLimits: boolean;
    sourceEvidencePerClaim: true;
  };
  unsupportedClaims: string[];
  gyre_is_sole_verdict_authority: true;
  advisory_analysis_only: true;
}

function claimFromPseudoLine(line: PseudoLine): StructuredFunctionClaim {
  const label: StructuredFunctionClaimLabel = line.isUncertain || line.kind === 'uncertain'
    ? 'inferred'
    : line.kind === 'comment'
      ? 'advisory'
      : 'observed';
  return {
    schema: 'hexhawk.structured_function_claim.v1',
    label,
    text: line.text,
    address: line.address,
    evidenceAddresses: typeof line.address === 'number' ? [line.address] : [],
    evidenceBasis: [line.kind === 'comment' ? 'decompiler-comment' : 'lifted-instruction'],
    source: 'decompiler-ir',
    gyre_is_sole_verdict_authority: true,
    advisory_analysis_only: true,
  };
}

function runtimeClaims(fi: FunctionIntelligence, snapshot?: DebugSnapshot): StructuredFunctionClaim[] {
  const claims: StructuredFunctionClaim[] = [];
  for (const observation of fi.debuggerCallStack ?? []) {
    claims.push({
      schema: 'hexhawk.structured_function_claim.v1',
      label: 'observed',
      text: `Function observed in runtime call stack at 0x${observation.observedAt.toString(16).toUpperCase()}.`,
      address: observation.observedAt,
      evidenceAddresses: [observation.observedAt, ...observation.frames.map(frame => frame.returnAddress)],
      evidenceBasis: ['runtime-call-stack'],
      source: 'runtime-trace',
      gyre_is_sole_verdict_authority: true,
      advisory_analysis_only: true,
    });
  }
  for (const hit of fi.conditionalBreakpointHits ?? []) {
    claims.push({
      schema: 'hexhawk.structured_function_claim.v1',
      label: 'observed',
      text: `Conditional breakpoint hit ${hit.hitCount} time(s): ${hit.condition}`,
      address: hit.address,
      evidenceAddresses: [hit.address],
      evidenceBasis: ['conditional-breakpoint-hit'],
      source: 'runtime-trace',
      gyre_is_sole_verdict_authority: true,
      advisory_analysis_only: true,
    });
  }
  if (!claims.length && snapshot) {
    claims.push({
      schema: 'hexhawk.structured_function_claim.v1',
      label: 'unresolved',
      text: 'Runtime snapshot is present, but this function was not correlated to a call stack frame or breakpoint hit.',
      evidenceAddresses: [],
      evidenceBasis: ['runtime-snapshot-no-function-correlation'],
      source: 'runtime-trace',
      gyre_is_sole_verdict_authority: true,
      advisory_analysis_only: true,
    });
  }
  return claims;
}

export function buildStructuredFunctionView(
  fi: FunctionIntelligence,
  decompileResult?: DecompileResult,
  debugSnapshot?: DebugSnapshot,
): StructuredFunctionView {
  const claims: StructuredFunctionClaim[] = [];

  claims.push({
    schema: 'hexhawk.structured_function_claim.v1',
    label: fi.nameSource === 'symbol' || fi.nameSource === 'import-table' ? 'observed' : 'inferred',
    text: `Function identity: ${fi.name} (${fi.nameSource}).`,
    address: fi.address,
    evidenceAddresses: [fi.address],
    evidenceBasis: [`name-source:${fi.nameSource}`, `boundary-source:${fi.boundarySource}`],
    source: fi.nameSource === 'import-table' ? 'import-table' : 'disassembly',
    gyre_is_sole_verdict_authority: true,
    advisory_analysis_only: true,
  });

  for (const line of decompileResult?.lines ?? []) {
    claims.push(claimFromPseudoLine(line));
  }

  for (const call of fi.importCalls) {
    claims.push({
      schema: 'hexhawk.structured_function_claim.v1',
      label: 'observed',
      text: `Import call ${call.importName}${call.moduleName ? ` from ${call.moduleName}` : ''}${call.constantAnnotations.length ? ` with constants ${call.constantAnnotations.join(', ')}` : ''}.`,
      address: call.callAddress,
      evidenceAddresses: [call.callAddress],
      evidenceBasis: ['import-table', ...call.constantAnnotations.map(annotation => `constant:${annotation}`)],
      source: 'import-table',
      gyre_is_sole_verdict_authority: true,
      advisory_analysis_only: true,
    });
  }

  claims.push(...runtimeClaims(fi, debugSnapshot));

  for (const limit of fi.limits) {
    claims.push({
      schema: 'hexhawk.structured_function_claim.v1',
      label: 'unresolved',
      text: limit.detail,
      address: limit.address,
      evidenceAddresses: typeof limit.address === 'number' ? [limit.address] : [],
      evidenceBasis: [`limit:${limit.kind}`],
      source: 'analysis-limit',
      gyre_is_sole_verdict_authority: true,
      advisory_analysis_only: true,
    });
  }

  return {
    schema: 'hexhawk.structured_function_view.v1',
    functionId: fi.id,
    functionName: fi.name,
    addressRange: { start: fi.address, end: fi.endAddress },
    claims,
    provenance: {
      hasDecompilerOutput: Boolean(decompileResult),
      hasRuntimeObservation: Boolean(fi.debuggerCallStack?.length || fi.conditionalBreakpointHits?.length),
      hasImportEvidence: fi.importCalls.length > 0,
      hasAnalysisLimits: fi.limits.length > 0,
      sourceEvidencePerClaim: true,
    },
    unsupportedClaims: [
      'This is not recovered source code.',
      'Structured function claims are evidence/advisory surfaces only.',
      'Claims do not mutate GYRE verdict labels, verdict decisions, or base confidence.',
    ],
    gyre_is_sole_verdict_authority: true,
    advisory_analysis_only: true,
  };
}
