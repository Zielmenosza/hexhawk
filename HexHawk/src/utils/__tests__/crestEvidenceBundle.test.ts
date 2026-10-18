import { describe, expect, it } from 'vitest';
import { buildCrestEvidenceBundle, validateCrestEvidenceBundle } from '../crestEvidenceBundle';
import type { ReferenceGraph } from '../referenceGraph';
import type { AnalysisSessionProvenance } from '../analysisProvenance';
import { appendEvidenceJournalEntry, buildReplayManifestFromProvenance } from '../evidenceJournal';
import type { LegacyRecordMetadata } from '../legacyRecordMetadata';

const sha256 = '7b4a27599f48bc7edcbe52e7cad688c92b1a0241b0e5e95b94355a2d50607b28';

const legacyRecordMetadata: LegacyRecordMetadata = {
  schema: 'hexhawk.legacy_record_metadata.v1',
  format: 'intel-hex',
  recordCount: 3,
  dataRecordCount: 1,
  byteCount: 9,
  ranges: [{ start: 0x100, endInclusive: 0x108, byteLength: 9 }],
  strings: [{ address: 0x100, value: 'HELLO-HEX' }],
  errors: [],
  warnings: [],
  authorityBoundary: 'Metadata-first legacy record adapter: validates records and maps bytes only. It does not execute content, recover source, decompile, or assign GYRE verdict authority.',
  noExecution: true,
};

function nativeProvenance(overrides: Partial<AnalysisSessionProvenance> = {}): AnalysisSessionProvenance {
  const base: AnalysisSessionProvenance = {
    schema: 'hexhawk.analysis.provenance.v1',
    runtime: 'tauri-native',
    binaryPath: 'D:/Project/HexHawk/Challenges/sample.exe',
    binarySha256: sha256,
    dataSource: 'real-backend',
    binaryIdentity: {
      path: 'D:/Project/HexHawk/Challenges/sample.exe',
      sha256,
      source: 'real-backend',
      artifactOrigin: 'tauri.inspect_file_metadata',
      tauriCommand: 'inspect_file_metadata',
      cliCommand: 'nest_cli inspect "D:/Project/HexHawk/Challenges/sample.exe"',
    },
    commands: ['nest_cli inspect "D:/Project/HexHawk/Challenges/sample.exe"'],
    // Model actual operation receipts in this positive fixture. UI counts alone
    // must no longer manufacture replay proof; every existing assertion stays.
    operationJournal: appendEvidenceJournalEntry(appendEvidenceJournalEntry([], {
      action: 'inspect', binaryPath: 'D:/Project/HexHawk/Challenges/sample.exe', binarySha256: sha256,
      command: 'nest_cli inspect "D:/Project/HexHawk/Challenges/sample.exe"',
      timestamp: '2026-07-23T23:58:00.000Z', artifactSource: 'tauri.inspect_file_metadata',
      analysisLimits: { maxBytesRead: 8192 },
    }), {
      action: 'cfg', binaryPath: 'D:/Project/HexHawk/Challenges/sample.exe', binarySha256: sha256,
      command: 'nest_cli cfg "D:/Project/HexHawk/Challenges/sample.exe" 0 1024',
      timestamp: '2026-07-23T23:59:00.000Z', artifactSource: 'tauri.build_cfg',
      analysisLimits: { offset: 0, length: 1024, nodeBudget: 2000, edgeBudget: 4000, truncated: true, omittedNodes: 12, omittedEdges: 20 },
    }),
    artifacts: [
      {
        kind: 'metadata',
        source: 'real-backend',
        command: 'nest_cli inspect "D:/Project/HexHawk/Challenges/sample.exe"',
        binarySha256: sha256,
        artifactOrigin: 'tauri.inspect_file_metadata',
        tauriCommand: 'inspect_file_metadata',
        cliCommand: 'nest_cli inspect "D:/Project/HexHawk/Challenges/sample.exe"',
        count: 1,
      },
      {
        kind: 'cfg',
        source: 'real-backend',
        command: 'nest_cli cfg "D:/Project/HexHawk/Challenges/sample.exe" 0 1024',
        binarySha256: sha256,
        artifactOrigin: 'tauri.build_cfg',
        tauriCommand: 'build_cfg',
        cliCommand: 'nest_cli cfg "D:/Project/HexHawk/Challenges/sample.exe" 0 1024',
        count: 2000,
        truncated: true,
      },
    ],
    warnings: [],
  };
  return { ...base, ...overrides };
}

describe('CREST evidence bundle', () => {
  it('builds a reproducible authority-safe bundle tying file identity, provenance, replay, and CFG budgets together', () => {
    const provenance = nativeProvenance();
    const replay = buildReplayManifestFromProvenance(provenance, '2026-07-24T00:00:00.000Z');
    const bundle = buildCrestEvidenceBundle({
      exportedAt: '2026-07-24T00:00:00.000Z',
      fileIdentity: { path: provenance.binaryPath, sha256, size: 8192, fileType: 'PE32+ EXE', architecture: 'x86_64' },
      provenance,
      replayManifest: replay,
      cfgBudget: { nodes: 2000, edges: 4000, nodeBudget: 2000, edgeBudget: 4000, omittedNodes: 12, omittedEdges: 20, truncated: true },
    });

    expect(bundle.schema).toBe('hexhawk.crest_evidence_bundle.v1');
    expect(bundle.file_identity.sha256).toBe(sha256);
    expect(bundle.native_evidence_contract.kind).toBe('native');
    expect(bundle.selected_analysis_provider).toMatchObject({
      provider: 'hexhawk-native',
      fixedForRun: true,
      silentFallbackAllowed: false,
      failurePolicy: 'fail-closed-no-substitution',
    });
    expect(bundle.evidence_records.map((record) => record.operation)).toContain('inspect_file_metadata');
    expect(bundle.capability_matrix.entries.find((entry) => entry.capability === 'Control-flow graph')).toMatchObject({
      availability: 'partial',
    });
    expect(bundle.replay_manifest.entries[0].binarySha256).toBe(sha256);
    expect(bundle.cfg_budget).toMatchObject({ truncated: true, nodeBudget: 2000, edgeBudget: 4000, omittedNodes: 12, omittedEdges: 20 });
    expect(bundle.reproducibility.same_sha256_across_bundle).toBe(true);
    expect(bundle.reproducibility.replay_manifest_matches_file_identity).toBe(true);
    expect(bundle.reproducibility.cfg_limits_declared_when_truncated).toBe(true);
    expect(bundle.reproducibility.evidence_records_have_identity).toBe(true);
    expect(bundle.proof_limits.join(' ')).toMatch(/does not prove verdict correctness/i);
    expect(JSON.stringify(bundle)).not.toContain('threatScore');
    expect(JSON.stringify(bundle)).not.toContain('classification');
  });

  it('validation fails closed on SHA mismatch', () => {
    const provenance = nativeProvenance({ binarySha256: 'c'.repeat(64) });
    const bundle = buildCrestEvidenceBundle({
      exportedAt: '2026-07-24T00:00:00.000Z',
      fileIdentity: { path: 'sample.exe', sha256, size: 8192 },
      provenance,
      replayManifest: buildReplayManifestFromProvenance(provenance, '2026-07-24T00:00:00.000Z'),
      cfgBudget: null,
    });

    const validation = validateCrestEvidenceBundle(bundle);
    expect(validation.ok).toBe(false);
    expect(validation.errors.join(' ')).toMatch(/SHA-256/i);
  });

  it('packages an advisory reference graph summary without adding verdict authority fields', () => {
    const provenance = nativeProvenance();
    const referenceGraph: ReferenceGraph = {
      schema: 'hexhawk.reference_graph.v1',
      advisory_only: true,
      authority: 'reference_graph_not_gyre_verdict',
      generated_at: '2026-07-25T00:00:00.000Z',
      summary: { functions: 2, imports: 1, strings: 1, basic_blocks: 1, data_references: 1, constants: 1, selected_addresses: 1, nodes: 7, edges: 6 },
      limits: { nodeBudget: 256, edgeBudget: 512, omittedNodes: 0, omittedEdges: 0, truncated: false },
      nodes: [],
      edges: [],
      proof_limits: ['Reference graph is advisory static-analysis evidence; it does not prove verdict correctness.'],
    };
    const bundle = buildCrestEvidenceBundle({
      exportedAt: '2026-07-25T00:00:00.000Z',
      fileIdentity: { path: provenance.binaryPath, sha256, size: 8192 },
      provenance,
      replayManifest: buildReplayManifestFromProvenance(provenance, '2026-07-25T00:00:00.000Z'),
      cfgBudget: null,
      referenceGraph,
    });

    expect(bundle.reference_graph).toMatchObject({
      schema: 'hexhawk.reference_graph.v1',
      authority: 'reference_graph_not_gyre_verdict',
      summary: expect.objectContaining({ imports: 1, strings: 1, data_references: 1 }),
    });
    expect(validateCrestEvidenceBundle(bundle).ok).toBe(true);
    expect(JSON.stringify(bundle.reference_graph)).not.toContain('classification');
    expect(JSON.stringify(bundle.reference_graph)).not.toContain('threatScore');
  });

  it('packages legacy record metadata as no-execution provenance without verdict authority', () => {
    const provenance = nativeProvenance();
    const bundle = buildCrestEvidenceBundle({
      exportedAt: '2026-07-26T00:00:00.000Z',
      fileIdentity: { path: provenance.binaryPath, sha256, size: 58, fileType: 'Intel HEX firmware record', architecture: 'legacy firmware record (addressed bytes)' },
      provenance,
      replayManifest: buildReplayManifestFromProvenance(provenance, '2026-07-26T00:00:00.000Z'),
      cfgBudget: null,
      legacyRecordMetadata,
    });

    expect(bundle.legacy_record_metadata).toMatchObject({
      schema: 'hexhawk.legacy_record_metadata.v1',
      format: 'intel-hex',
      byteCount: 9,
      noExecution: true,
    });
    expect(bundle.legacy_record_metadata?.strings).toContainEqual({ address: 0x100, value: 'HELLO-HEX' });
    expect(bundle.reproducibility.legacy_record_metadata_is_advisory).toBe(true);
    expect(bundle.proof_limits.join(' ')).toMatch(/metadata-only text-record provenance/i);
    expect(validateCrestEvidenceBundle(bundle).ok).toBe(true);
    expect(JSON.stringify(bundle.legacy_record_metadata)).not.toContain('threatScore');
    expect(JSON.stringify(bundle.legacy_record_metadata)).not.toContain('classification');
  });

  it('validation rejects legacy record metadata that loses the no-execution authority boundary', () => {
    const provenance = nativeProvenance();
    const bundle = buildCrestEvidenceBundle({
      exportedAt: '2026-07-26T00:00:00.000Z',
      fileIdentity: { path: provenance.binaryPath, sha256, size: 58 },
      provenance,
      replayManifest: buildReplayManifestFromProvenance(provenance, '2026-07-26T00:00:00.000Z'),
      cfgBudget: null,
      legacyRecordMetadata: { ...legacyRecordMetadata, authorityBoundary: 'Parses firmware records.' },
    });

    const validation = validateCrestEvidenceBundle(bundle);
    expect(validation.ok).toBe(false);
    expect(validation.errors.join(' ')).toMatch(/Legacy record metadata/i);
  });

  it('validation rejects browser simulation as native CREST evidence', () => {
    const provenance = nativeProvenance({
      runtime: 'browser-simulation',
      dataSource: 'simulation',
      binaryIdentity: {
        path: 'sample.exe',
        sha256,
        source: 'simulation',
        artifactOrigin: 'browser.mock_metadata',
      },
      artifacts: [{ kind: 'metadata', source: 'simulation', binarySha256: sha256, artifactOrigin: 'browser.mock_metadata', count: 1 }],
    });
    const bundle = buildCrestEvidenceBundle({
      exportedAt: '2026-07-24T00:00:00.000Z',
      fileIdentity: { path: 'sample.exe', sha256, size: 8192 },
      provenance,
      replayManifest: buildReplayManifestFromProvenance(provenance, '2026-07-24T00:00:00.000Z'),
      cfgBudget: null,
    });

    expect(bundle.native_evidence_contract.kind).toBe('simulation');
    expect(validateCrestEvidenceBundle(bundle).ok).toBe(false);
  });

  it('validation requires CFG limits when CFG output is truncated', () => {
    const provenance = nativeProvenance();
    const bundle = buildCrestEvidenceBundle({
      exportedAt: '2026-07-24T00:00:00.000Z',
      fileIdentity: { path: provenance.binaryPath, sha256, size: 8192 },
      provenance,
      replayManifest: buildReplayManifestFromProvenance(provenance, '2026-07-24T00:00:00.000Z'),
      cfgBudget: { nodes: 2000, edges: 4000, truncated: true },
    });

    const validation = validateCrestEvidenceBundle(bundle);
    expect(validation.ok).toBe(false);
    expect(validation.errors.join(' ')).toMatch(/CFG/i);
  });
});
