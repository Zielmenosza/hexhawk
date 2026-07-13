import type { BinaryVerdictResult } from './correlationEngine';
import type { GyreRecordedVerdictSnapshot } from './gyreSnapshotClient';

export type ReportDetailAvailability = 'summary-only' | 'live-verdict';

export interface FinalVerdictSnapshotExport {
  verdict_snapshot_id: string | null;
  source_engine: 'gyre';
  gyre_is_sole_verdict_source: true;
  snapshot_identity_status: 'persisted-immutable' | 'live-unresolved';
  snapshot_schema_name: string | null;
  snapshot_schema_version: string | null;
  snapshot_provenance: GyreRecordedVerdictSnapshot['provenance'] | null;
  binary_sha256: string | null;
  gyre_build_id: string | null;
  gyre_schema_version: string | null;
  reasoning_chain_hash: string | null;
  snapshot_created_at: string | null;
  detail_availability: ReportDetailAvailability;
  detail_note: string;
  classification: BinaryVerdictResult['classification'];
  confidence: number;
  threat_score: number;
  summary: string;
  signal_count: number;
}

type ReportVerdictCore = Pick<
  BinaryVerdictResult,
  'classification' | 'confidence' | 'threatScore' | 'summary' | 'signalCount'
>;

export function buildFinalVerdictSnapshotExport(
  verdict: ReportVerdictCore,
  snapshot?: GyreRecordedVerdictSnapshot | null,
): FinalVerdictSnapshotExport {
  if (snapshot) {
    return {
      verdict_snapshot_id: snapshot.snapshotId,
      source_engine: 'gyre',
      gyre_is_sole_verdict_source: true,
      snapshot_identity_status: 'persisted-immutable',
      snapshot_schema_name: snapshot.schemaName,
      snapshot_schema_version: snapshot.schemaVersion,
      snapshot_provenance: snapshot.provenance,
      binary_sha256: snapshot.binarySha256,
      gyre_build_id: snapshot.gyreBuildId,
      gyre_schema_version: snapshot.gyreSchemaVersion,
      reasoning_chain_hash: snapshot.reasoningChainHash,
      snapshot_created_at: snapshot.createdAt,
      detail_availability: 'summary-only',
      detail_note: 'The immutable persisted GYRE snapshot preserves authoritative summary fields and hashes, but does not embed detailed signal or reasoning objects.',
      classification: snapshot.classification as BinaryVerdictResult['classification'],
      confidence: snapshot.baseConfidence,
      threat_score: snapshot.threatScore,
      summary: snapshot.summary,
      signal_count: snapshot.signalCount,
    };
  }

  return {
    verdict_snapshot_id: null,
    source_engine: 'gyre',
    gyre_is_sole_verdict_source: true,
    snapshot_identity_status: 'live-unresolved',
    snapshot_schema_name: null,
    snapshot_schema_version: null,
    snapshot_provenance: null,
    binary_sha256: null,
    gyre_build_id: null,
    gyre_schema_version: null,
    reasoning_chain_hash: null,
    snapshot_created_at: null,
    detail_availability: 'live-verdict',
    detail_note: 'This export uses the active live GYRE verdict; no immutable recorded snapshot identity was supplied to the report.',
    classification: verdict.classification,
    confidence: verdict.confidence,
    threat_score: verdict.threatScore,
    summary: verdict.summary,
    signal_count: verdict.signalCount,
  };
}
