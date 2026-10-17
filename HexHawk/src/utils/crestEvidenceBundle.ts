import type { AnalysisSessionProvenance } from './analysisProvenance';
import type { EvidenceReplayManifest } from './evidenceJournal';
import { enforceNativeEvidenceContract, type NativeEvidenceContract } from './nativeEvidenceContract';
import type { ReferenceGraph } from './referenceGraph';
import type { LegacyRecordMetadata } from './legacyRecordMetadata';
import {
  buildCapabilityMatrix,
  buildEvidenceRecordsFromProvenance,
  buildSelectedAnalysisProvider,
  validateEvidenceRecords,
  type CapabilityMatrixV1,
  type EvidenceRecordV1,
  type SelectedAnalysisProviderV1,
} from './evidenceRecord';

export type CrestCfgBudget = {
  nodes: number;
  edges: number;
  nodeBudget?: number;
  edgeBudget?: number;
  omittedNodes?: number;
  omittedEdges?: number;
  truncated?: boolean;
} | null;

export type CrestFileIdentity = {
  path: string;
  sha256: string | null;
  size?: number;
  fileType?: string;
  architecture?: string;
};

export type CrestEvidenceBundle = {
  schema: 'hexhawk.crest_evidence_bundle.v1';
  bundle_id: string;
  exported_at: string;
  file_identity: CrestFileIdentity;
  native_evidence_contract: NativeEvidenceContract;
  selected_analysis_provider: SelectedAnalysisProviderV1;
  evidence_records: EvidenceRecordV1[];
  capability_matrix: CapabilityMatrixV1;
  evidence_provenance: AnalysisSessionProvenance;
  replay_manifest: EvidenceReplayManifest;
  analysis_artifacts: AnalysisSessionProvenance['artifacts'];
  cfg_budget: CrestCfgBudget;
  legacy_record_metadata?: LegacyRecordMetadata;
  reference_graph?: Pick<ReferenceGraph, 'schema' | 'advisory_only' | 'authority' | 'summary' | 'limits' | 'proof_limits'>;
  reproducibility: {
    same_sha256_across_bundle: boolean;
    replay_manifest_matches_file_identity: boolean;
    cfg_limits_declared_when_truncated: boolean;
    legacy_record_metadata_is_advisory: boolean;
    native_contract_can_claim_file_backed_evidence: boolean;
    evidence_records_have_identity: boolean;
  };
  authority_doctrine: {
    gyre_is_sole_verdict_authority: true;
    nest_role: 'evidence-lifecycle-authority';
    aetherframe_role: 'bounded-advisory-governance-only';
    crest_role: 'reproducible-evidence-packaging-only';
  };
  proof_limits: string[];
};

export type CrestEvidenceBundleInput = {
  exportedAt: string;
  fileIdentity: CrestFileIdentity;
  provenance: AnalysisSessionProvenance;
  replayManifest: EvidenceReplayManifest;
  cfgBudget: CrestCfgBudget;
  legacyRecordMetadata?: LegacyRecordMetadata | null;
  referenceGraph?: ReferenceGraph;
};

export type CrestEvidenceBundleValidation = {
  ok: boolean;
  errors: string[];
  warnings: string[];
};

function normalizedSha(value: string | null | undefined): string | null {
  return value ? value.toLowerCase() : null;
}

function allKnownHashesMatch(expected: string | null, hashes: Array<string | null | undefined>): boolean {
  const known = hashes.map(normalizedSha).filter((value): value is string => Boolean(value));
  if (!expected || known.length === 0) return false;
  return known.every((hash) => hash === expected.toLowerCase());
}

function replayManifestMatchesFileIdentity(fileSha256: string | null, replayManifest: EvidenceReplayManifest): boolean {
  const expected = normalizedSha(fileSha256);
  if (!expected || replayManifest.entries.length === 0) return false;
  return replayManifest.entries.every((entry) => normalizedSha(entry.binarySha256) === expected);
}

function cfgLimitsDeclaredWhenTruncated(cfgBudget: CrestCfgBudget): boolean {
  if (!cfgBudget?.truncated) return true;
  return typeof cfgBudget.nodeBudget === 'number'
    && typeof cfgBudget.edgeBudget === 'number'
    && typeof cfgBudget.omittedNodes === 'number'
    && typeof cfgBudget.omittedEdges === 'number';
}

export function buildCrestEvidenceBundle(input: CrestEvidenceBundleInput): CrestEvidenceBundle {
  const identity = input.provenance.binaryIdentity;
  const nativeContract = enforceNativeEvidenceContract({
    runtime: input.provenance.runtime,
    source: input.provenance.dataSource,
    artifactOrigin: identity.artifactOrigin,
    artifactKind: 'metadata',
    binaryPath: identity.path,
    sourceSha256: identity.sha256,
    boundSha256: input.fileIdentity.sha256,
    identityBindingSucceeded: input.provenance.artifacts.some(artifact => artifact.kind === 'metadata'),
  });
  const fileSha256 = normalizedSha(input.fileIdentity.sha256);
  const artifactHashes = input.provenance.artifacts.map((artifact) => artifact.binarySha256);
  const provenanceHashes = [input.provenance.binarySha256, input.provenance.binaryIdentity.sha256, ...artifactHashes];
  const evidenceRecords = buildEvidenceRecordsFromProvenance(input.provenance);
  const capabilityMatrix = buildCapabilityMatrix(input.provenance, evidenceRecords);

  return {
    schema: 'hexhawk.crest_evidence_bundle.v1',
    bundle_id: `crest-${(fileSha256 ?? 'unknown').slice(0, 12)}-${input.replayManifest.entries.length}`,
    exported_at: input.exportedAt,
    file_identity: { ...input.fileIdentity, sha256: fileSha256 },
    native_evidence_contract: nativeContract,
    selected_analysis_provider: buildSelectedAnalysisProvider(input.provenance),
    evidence_records: evidenceRecords,
    capability_matrix: capabilityMatrix,
    evidence_provenance: input.provenance,
    replay_manifest: input.replayManifest,
    analysis_artifacts: input.provenance.artifacts.map((artifact) => ({ ...artifact })),
    cfg_budget: input.cfgBudget ? { ...input.cfgBudget } : null,
    legacy_record_metadata: input.legacyRecordMetadata ? {
      ...input.legacyRecordMetadata,
      ranges: input.legacyRecordMetadata.ranges.map((range) => ({ ...range })),
      strings: input.legacyRecordMetadata.strings.map((string) => ({ ...string })),
      errors: [...input.legacyRecordMetadata.errors],
      warnings: [...input.legacyRecordMetadata.warnings],
      noExecution: true,
    } : undefined,
    reference_graph: input.referenceGraph ? {
      schema: input.referenceGraph.schema,
      advisory_only: true,
      authority: input.referenceGraph.authority,
      summary: { ...input.referenceGraph.summary },
      limits: { ...input.referenceGraph.limits },
      proof_limits: [...input.referenceGraph.proof_limits],
    } : undefined,
    reproducibility: {
      same_sha256_across_bundle: allKnownHashesMatch(fileSha256, provenanceHashes),
      replay_manifest_matches_file_identity: replayManifestMatchesFileIdentity(fileSha256, input.replayManifest),
      cfg_limits_declared_when_truncated: cfgLimitsDeclaredWhenTruncated(input.cfgBudget),
      legacy_record_metadata_is_advisory: input.legacyRecordMetadata
        ? input.legacyRecordMetadata.noExecution === true
          && input.legacyRecordMetadata.schema === 'hexhawk.legacy_record_metadata.v1'
          && /does not execute|no execution/i.test(input.legacyRecordMetadata.authorityBoundary)
          && /GYRE verdict authority/i.test(input.legacyRecordMetadata.authorityBoundary)
        : true,
      native_contract_can_claim_file_backed_evidence: nativeContract.canClaimFileBackedEvidence,
      evidence_records_have_identity: validateEvidenceRecords(evidenceRecords).ok,
    },
    authority_doctrine: {
      gyre_is_sole_verdict_authority: true,
      nest_role: 'evidence-lifecycle-authority',
      aetherframe_role: 'bounded-advisory-governance-only',
      crest_role: 'reproducible-evidence-packaging-only',
    },
    proof_limits: [
      'CREST evidence bundles package file identity, provenance, replay commands, artifact origins, and declared limits; the bundle does not prove verdict correctness.',
      'A matching SHA-256 chain proves identity consistency across this export, not that every possible analysis was complete.',
      'CFG coverage must be read with the exported cfg_budget; truncated CFG output must not be described as full CFG.',
      'Legacy record metadata, when present, is metadata-only text-record provenance. It does not execute content, emulate firmware, recover source, decompile, or assign GYRE verdict authority.',
      'Reference graph coverage must be read with the exported node/edge budgets; graph links are advisory xref evidence, not verdict authority.',
      'Evidence records and provider binding identify operation identity, producer, parameters, limitations, and capability availability; unavailable and partial states are evidence, not UI errors to hide.',
      'GYRE remains sole verdict authority. NEST remains evidence lifecycle authority. AETHERFRAME remains bounded advisory governance only.',
    ],
  };
}

export function validateCrestEvidenceBundle(bundle: CrestEvidenceBundle): CrestEvidenceBundleValidation {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (bundle.schema !== 'hexhawk.crest_evidence_bundle.v1') errors.push('schema must be hexhawk.crest_evidence_bundle.v1.');
  if (!bundle.file_identity.path) errors.push('file identity path is required.');
  if (!bundle.file_identity.sha256) errors.push('file identity SHA-256 is required.');
  if (!bundle.reproducibility.same_sha256_across_bundle) errors.push('SHA-256 mismatch across file identity, provenance, or artifacts.');
  if (!bundle.reproducibility.replay_manifest_matches_file_identity) errors.push('Replay manifest SHA-256 does not match file identity SHA-256.');
  if (!bundle.reproducibility.cfg_limits_declared_when_truncated) errors.push('CFG truncation requires explicit node/edge budgets and omitted counts.');
  if (!bundle.reproducibility.legacy_record_metadata_is_advisory) errors.push('Legacy record metadata must remain advisory, metadata-only, no-execution provenance.');
  if (!bundle.native_evidence_contract.canClaimFileBackedEvidence) errors.push('CREST native evidence bundle requires native backend evidence, not browser simulation or invalid sources.');
  const evidenceRecordValidation = validateEvidenceRecords(bundle.evidence_records ?? []);
  if (!evidenceRecordValidation.ok) errors.push(...evidenceRecordValidation.errors);
  if (!bundle.selected_analysis_provider || bundle.selected_analysis_provider.silentFallbackAllowed !== false) errors.push('Selected provider binding must fail closed and forbid silent fallback.');
  if (!bundle.capability_matrix || bundle.capability_matrix.schema !== 'hexhawk.capability_matrix.v1') errors.push('Capability matrix is required.');
  if (bundle.replay_manifest.schema !== 'hexhawk.evidence_replay_manifest.v1') errors.push('replay manifest schema is invalid.');
  if (bundle.replay_manifest.entries.length === 0) warnings.push('Replay manifest contains no entries.');

  const serialized = JSON.stringify({
    native_evidence_contract: bundle.native_evidence_contract,
    evidence_provenance: bundle.evidence_provenance,
    replay_manifest: bundle.replay_manifest,
    analysis_artifacts: bundle.analysis_artifacts,
    legacy_record_metadata: bundle.legacy_record_metadata,
    reference_graph: bundle.reference_graph,
    reproducibility: bundle.reproducibility,
    proof_limits: bundle.proof_limits,
  });
  if (serialized.includes('classification')) errors.push('Bundle evidence/provenance/replay structures must not contain classification authority fields.');
  if (serialized.includes('threatScore')) errors.push('Bundle evidence/provenance/replay structures must not contain threatScore authority fields.');

  return { ok: errors.length === 0, errors, warnings };
}
