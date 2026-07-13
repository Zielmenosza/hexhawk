import { describe, expect, it } from 'vitest';
import type { BinaryVerdictResult } from '../correlationEngine';
import type { GyreRecordedVerdictSnapshot } from '../gyreSnapshotClient';
import { buildFinalVerdictSnapshotExport } from '../reportAuthorityProvenance';

const liveVerdict = {
  classification: 'suspicious',
  confidence: 42,
  threatScore: 51,
  summary: 'Live renderer verdict.',
  signalCount: 3,
} as Pick<BinaryVerdictResult, 'classification' | 'confidence' | 'threatScore' | 'summary' | 'signalCount'>;

const persistedSnapshot: GyreRecordedVerdictSnapshot = {
  schemaName: 'gyre.recorded_verdict_snapshot',
  schemaVersion: '1.2.3',
  snapshotId: 'gyre_snapshot_immutable_001',
  provenance: 'renderer_gyre_backend_recorded',
  binarySha256: 'a'.repeat(64),
  classification: 'malicious',
  baseConfidence: 93,
  threatScore: 88,
  summary: 'Persisted immutable verdict summary.',
  signalCount: 7,
  contradictionCount: 2,
  reasoningChainHash: 'b'.repeat(64),
  gyreBuildId: '1.0.0+renderer-gyre',
  gyreSchemaVersion: '1.0.0',
  createdAt: '2026-07-13T19:30:00.000Z',
};

describe('report authority provenance', () => {
  it('uses immutable persisted GYRE identity and authoritative summary values', () => {
    const exported = buildFinalVerdictSnapshotExport(liveVerdict, persistedSnapshot);

    expect(exported.verdict_snapshot_id).toBe('gyre_snapshot_immutable_001');
    expect(exported.snapshot_identity_status).toBe('persisted-immutable');
    expect(exported.snapshot_schema_name).toBe('gyre.recorded_verdict_snapshot');
    expect(exported.snapshot_schema_version).toBe('1.2.3');
    expect(exported.snapshot_provenance).toBe('renderer_gyre_backend_recorded');
    expect(exported.binary_sha256).toBe('a'.repeat(64));
    expect(exported.gyre_build_id).toBe('1.0.0+renderer-gyre');
    expect(exported.gyre_schema_version).toBe('1.0.0');
    expect(exported.reasoning_chain_hash).toBe('b'.repeat(64));
    expect(exported.snapshot_created_at).toBe('2026-07-13T19:30:00.000Z');
    expect(exported.detail_availability).toBe('summary-only');
    expect(exported.classification).toBe('malicious');
    expect(exported.confidence).toBe(93);
    expect(exported.threat_score).toBe(88);
    expect(exported.summary).toBe('Persisted immutable verdict summary.');
    expect(exported.signal_count).toBe(7);
    expect(exported.gyre_is_sole_verdict_source).toBe(true);
  });

  it('does not fabricate immutable identity for a live verdict', () => {
    const exported = buildFinalVerdictSnapshotExport(liveVerdict, null);

    expect(exported.verdict_snapshot_id).toBeNull();
    expect(exported.snapshot_identity_status).toBe('live-unresolved');
    expect(exported.snapshot_schema_name).toBeNull();
    expect(exported.snapshot_schema_version).toBeNull();
    expect(exported.gyre_build_id).toBeNull();
    expect(exported.reasoning_chain_hash).toBeNull();
    expect(exported.detail_availability).toBe('live-verdict');
    expect(exported.classification).toBe('suspicious');
    expect(exported.confidence).toBe(42);
    expect(exported.threat_score).toBe(51);
    expect(exported.signal_count).toBe(3);
  });
});
