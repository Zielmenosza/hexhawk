/**
 * nestEvidenceFixtures.ts
 *
 * Golden fixtures for NEST evidence bundle contract tests.
 *
 * These objects must remain valid against the validators defined in
 * src/types/nestEvidence.ts.  Update if the schema version changes.
 *
 * ID design:
 *   All stable IDs use a fixed Crockford base-32 ULID payload "ABCDE12345FGHJKMNPQRST0123"
 *   (26 chars, all in the valid alphabet [0-9A-HJKMNP-TV-Z]) so they are readable
 *   and trivially distinguishable from real production IDs.
 *
 * Hash design:
 *   SHA-256: 'a1b2c3d4e5f6' repeated to 64 chars
 *   SHA-1:   'a1b2c3d4e5f6' repeated to 40 chars
 *   MD5:     'a1b2c3d4e5f6' repeated to 32 chars
 *   All are lowercase hex, intentionally non-real.
 *
 *   A second binary uses 'b2c3...' so tests can distinguish two distinct binaries.
 */

import type {
  NestManifest,
  NestBinaryIdentity,
  NestSessionRecord,
  NestIterationsFile,
  NestDeltasFile,
  NestFinalVerdictSnapshot,
  NestRuntimeProof,
  NestAuditRefs,
  NestEvidenceBundle,
  NestActor,
  NestTimestamps,
  NestSessionConfig,
} from '../../types/nestEvidence';

// ── Stable test constants ──────────────────────────────────────────────────────

export const T = {
  // ULID payload — 26 Crockford base-32 chars, reused across all IDs
  ULID: 'ABCDE12345FGHJKMNPQRST0123',

  // Bundle/session/verdict IDs
  BUNDLE_ID:           'nestbundle_ABCDE12345FGHJKMNPQRST0123',
  SESSION_ID:          'nestsession_ABCDE12345FGHJKMNPQRST0123',
  VERDICT_SNAP_ID:     'gyresnap_ABCDE12345FGHJKMNPQRST0123',

  // Iteration IDs (4-digit zero-padded index suffix)
  ITER_ID_1:           'nestiter_ABCDE12345FGHJKMNPQRST0123_0001',
  ITER_ID_2:           'nestiter_ABCDE12345FGHJKMNPQRST0123_0002',
  ITER_ID_3:           'nestiter_ABCDE12345FGHJKMNPQRST0123_0003',

  // Delta IDs (from_index_to_index suffix)
  DELTA_ID_1_2:        'nestdelta_ABCDE12345FGHJKMNPQRST0123_0001_0002',
  DELTA_ID_2_3:        'nestdelta_ABCDE12345FGHJKMNPQRST0123_0002_0003',

  // Binary hashes for binary A
  SHA256_A:  'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
  SHA1_A:    'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
  MD5_A:     'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4',

  // Binary hashes for binary B (second binary — distinct from A)
  SHA256_B:  'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3',
  SHA1_B:    'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3',
  MD5_B:     'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5',

  // Timestamps (all RFC3339 UTC)
  T0:  '2026-04-29T16:49:00Z',
  T1:  '2026-04-29T16:49:02Z',
  T2:  '2026-04-29T16:49:25Z',
  T3:  '2026-04-29T16:49:48Z',
  T4:  '2026-04-29T16:50:12Z',
  T_EXPORT: '2026-04-29T16:51:00Z',
  T_REVIEW: '2026-04-29T17:10:00Z',

  // Build and policy info
  ENGINE_BUILD_ID: '1.0.0+abc123def456',
  GYRE_BUILD_ID:   '1.0.0+abc123def456',
  POLICY_VERSION:  '2026-04-29.1',
  GYRE_SCHEMA_VER: '1.0.0',
  CONFIG_VERSION:  '1.0.0',

  // Reasoning chain hash (sha256 of serialised chain)
  CHAIN_HASH: 'c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4',
} as const;

// ── Shared sub-objects ─────────────────────────────────────────────────────────

export const actorUser: NestActor = {
  id: 'user:alice',
  type: 'user',
  display_name: 'Alice',
};

export const actorServiceAccount: NestActor = {
  id: 'service-account:nest-regression-bot',
  type: 'service-account',
  display_name: 'NEST Regression Bot',
  tenant_id: 'hexhawk',
  team_id: 're-lab',
};

export const timestampsCompleted: NestTimestamps = {
  created_at:   T.T0,
  started_at:   T.T1,
  completed_at: T.T4,
  exported_at:  T.T_EXPORT,
};

export const defaultConfig: NestSessionConfig = {
  config_version:        T.CONFIG_VERSION,
  max_iterations:        5,
  min_iterations:        3,
  confidence_threshold:  80,
  plateau_threshold:     3,
  disasm_expansion:      512,
  aggressiveness:        'balanced',
  enable_talon:          true,
  enable_strike:         false,
  enable_echo:           true,
  auto_advance:          true,
  auto_advance_delay_ms: 600,
};

// ── Manifest fixture ───────────────────────────────────────────────────────────

export function makeManifest(overrides: Partial<NestManifest> = {}): NestManifest {
  const base: NestManifest = {
    schema_name:           'nest.manifest',
    schema_version:        '1.0.0',
    bundle_schema_version: '1.0.0',
    bundle_format_version: '1.0.0',
    bundle_id:             T.BUNDLE_ID,
    session_id:            T.SESSION_ID,
    binary_id:             `binary_sha256_${T.SHA256_A}`,
    binary_sha256:         T.SHA256_A,
    engine_build_id:       T.ENGINE_BUILD_ID,
    policy_version:        T.POLICY_VERSION,
    actor:                 actorUser,
    timestamps:            { created_at: T.T0, exported_at: T.T_EXPORT },
    files: [
      { name: 'manifest.json',             required: true,  sha256: T.SHA256_A, bytes: 1024, schema_name: 'nest.manifest',              schema_version: '1.0.0' },
      { name: 'binary_identity.json',      required: true,  sha256: T.SHA256_A, bytes: 512,  schema_name: 'nest.binary_identity',        schema_version: '1.0.0' },
      { name: 'session.json',              required: true,  sha256: T.SHA256_A, bytes: 2048, schema_name: 'nest.session',                schema_version: '1.0.0' },
      { name: 'iterations.json',           required: true,  sha256: T.SHA256_A, bytes: 4096, schema_name: 'nest.iterations',             schema_version: '1.0.0' },
      { name: 'deltas.json',               required: true,  sha256: T.SHA256_A, bytes: 2048, schema_name: 'nest.deltas',                 schema_version: '1.0.0' },
      { name: 'final_verdict_snapshot.json', required: true, sha256: T.SHA256_A, bytes: 1024, schema_name: 'nest.final_verdict_snapshot', schema_version: '1.0.0' },
      { name: 'audit_refs.json',           required: true,  sha256: T.SHA256_A, bytes: 512,  schema_name: 'nest.audit_refs',             schema_version: '1.0.0' },
    ],
    immutability: {
      bundle_locked:   true,
      locked_at:       T.T_EXPORT,
      mutation_policy: 'immutable-after-export',
    },
    replay: {
      replayable:            true,
      mode_supported:        ['local'],
      requires_binary_bytes: true,
    },
  };
  return { ...base, ...overrides };
}

// ── BinaryIdentity fixture ─────────────────────────────────────────────────────

export function makeBinaryIdentity(overrides: Partial<NestBinaryIdentity> = {}): NestBinaryIdentity {
  const base: NestBinaryIdentity = {
    schema_name:     'nest.binary_identity',
    schema_version:  '1.0.0',
    bundle_id:       T.BUNDLE_ID,
    session_id:      T.SESSION_ID,
    binary_id:       `binary_sha256_${T.SHA256_A}`,
    binary_sha256:   T.SHA256_A,
    hashes: {
      sha256: T.SHA256_A,
      sha1:   T.SHA1_A,
      md5:    T.MD5_A,
    },
    file_size_bytes:  184320,
    format:           'PE/MZ',
    architecture:     'x86_64',
    first_seen_at:    T.T0,
    identity_source:  'local-path',
    file_bound_proof: {
      proof_status:      'proven',
      proof_basis:       ['sha256-match', 'file-size-match'],
      binary_sha256:     T.SHA256_A,
      file_size_bytes:   184320,
      session_hash_lock: true,
    },
    original_path:   'D:\\Challenges\\FlareAuthenticator\\FlareAuthenticator.exe',
    file_name:       'FlareAuthenticator.exe',
  };
  return { ...base, ...overrides };
}

// ── SessionRecord fixture ──────────────────────────────────────────────────────

export function makeSessionRecord(overrides: Partial<NestSessionRecord> = {}): NestSessionRecord {
  const base: NestSessionRecord = {
    schema_name:            'nest.session',
    schema_version:         '1.0.0',
    bundle_id:              T.BUNDLE_ID,
    session_id:             T.SESSION_ID,
    binary_id:              `binary_sha256_${T.SHA256_A}`,
    binary_sha256:          T.SHA256_A,
    engine_build_id:        T.ENGINE_BUILD_ID,
    policy_version:         T.POLICY_VERSION,
    actor:                  actorUser,
    timestamps:             timestampsCompleted,
    status:                 'completed',
    execution_mode:         'local-tauri',
    config:                 defaultConfig,
    iteration_count:        2,
    delta_count:            1,
    final_iteration_index:  2,
    convergence: {
      has_converged:          true,
      reason:                 'confidence-threshold',
      confidence:             87,
      classification_stable:  true,
      signal_delta:           3,
      contradiction_burden:   0,
      stability_score:        0.91,
    },
    gyre_linkage: {
      verdict_snapshot_id:       T.VERDICT_SNAP_ID,
      gyre_schema_version:       T.GYRE_SCHEMA_VER,
      gyre_build_id:             T.GYRE_BUILD_ID,
      gyre_is_sole_verdict_source: true,
      nest_role:                 'iterative-enrichment-only',
    },
  };
  return { ...base, ...overrides };
}

// ── IterationsFile fixture ─────────────────────────────────────────────────────

export function makeIterationsFile(overrides: Partial<NestIterationsFile> = {}): NestIterationsFile {
  const base: NestIterationsFile = {
    schema_name:   'nest.iterations',
    schema_version: '1.0.0',
    bundle_id:     T.BUNDLE_ID,
    session_id:    T.SESSION_ID,
    binary_id:     `binary_sha256_${T.SHA256_A}`,
    binary_sha256: T.SHA256_A,
    count: 2,
    items: [
      {
        iteration_id:    T.ITER_ID_1,
        iteration_index: 1,
        session_id:      T.SESSION_ID,
        binary_sha256:   T.SHA256_A,
        started_at:      T.T1,
        completed_at:    T.T2,
        duration_ms:     23000,
        input_window:    { offset: 0, length: 4096 },
        executed_actions: [
          { type: 'expand-disasm-forward', priority: 'high', reason: 'Initial disassembly pass.' },
        ],
        verdict_snapshot: {
          classification:      'suspicious',
          confidence:          64,
          threat_score:        64,
          signal_count:        7,
          contradiction_count: 1,
          reasoning_chain_hash: T.CHAIN_HASH,
        },
        convergence_snapshot: {
          reason:                 'continue',
          has_converged:          false,
          stability_score:        0.55,
          classification_stable:  false,
          signal_delta:           7,
          contradiction_burden:   1,
        },
        file_identity_locked: true,
      },
      {
        iteration_id:    T.ITER_ID_2,
        iteration_index: 2,
        session_id:      T.SESSION_ID,
        binary_sha256:   T.SHA256_A,
        started_at:      T.T2,
        completed_at:    T.T3,
        duration_ms:     23000,
        input_window:    { offset: 0, length: 8192 },
        executed_actions: [
          { type: 'deep-echo', priority: 'high', reason: 'Low confidence after iteration 1.' },
          { type: 'expand-disasm-forward', priority: 'medium', reason: 'Extend disasm coverage.' },
        ],
        verdict_snapshot: {
          classification:      'malicious',
          confidence:          87,
          threat_score:        87,
          signal_count:        10,
          contradiction_count: 0,
          reasoning_chain_hash: T.CHAIN_HASH,
        },
        convergence_snapshot: {
          reason:                 'confidence-threshold',
          has_converged:          true,
          stability_score:        0.91,
          classification_stable:  true,
          signal_delta:           3,
          contradiction_burden:   0,
        },
        file_identity_locked: true,
      },
    ],
  };
  return { ...base, ...overrides };
}

// ── DeltasFile fixture ─────────────────────────────────────────────────────────

export function makeDeltasFile(overrides: Partial<NestDeltasFile> = {}): NestDeltasFile {
  const base: NestDeltasFile = {
    schema_name:   'nest.deltas',
    schema_version: '1.0.0',
    bundle_id:     T.BUNDLE_ID,
    session_id:    T.SESSION_ID,
    binary_id:     `binary_sha256_${T.SHA256_A}`,
    binary_sha256: T.SHA256_A,
    count: 1,
    items: [
      {
        delta_id:              T.DELTA_ID_1_2,
        from_iteration_id:     T.ITER_ID_1,
        to_iteration_id:       T.ITER_ID_2,
        from_iteration_index:  1,
        to_iteration_index:    2,
        binary_sha256:         T.SHA256_A,
        confidence_delta:      23,
        classification_changed: true,
        signal_delta_summary: {
          added_count:     3,
          removed_count:   0,
          unchanged_count: 7,
        },
        contradiction_delta:  -1,
        refinement_execution: {
          action_types:        ['deep-echo', 'expand-disasm-forward'],
          primary_action_type: 'deep-echo',
          executed:            true,
          primary_action_reason: 'Low confidence after iteration 1.',
        },
        projected_gain: 20,
        actual_gain:    23,
      },
    ],
  };
  return { ...base, ...overrides };
}

// ── FinalVerdictSnapshot fixture ───────────────────────────────────────────────

export function makeFinalVerdictSnapshot(overrides: Partial<NestFinalVerdictSnapshot> = {}): NestFinalVerdictSnapshot {
  const base: NestFinalVerdictSnapshot = {
    schema_name:          'nest.final_verdict_snapshot',
    schema_version:       '1.0.0',
    bundle_id:            T.BUNDLE_ID,
    session_id:           T.SESSION_ID,
    binary_id:            `binary_sha256_${T.SHA256_A}`,
    binary_sha256:        T.SHA256_A,
    verdict_snapshot_id:  T.VERDICT_SNAP_ID,
    source_engine:        'gyre',
    gyre_build_id:        T.GYRE_BUILD_ID,
    gyre_schema_version:  T.GYRE_SCHEMA_VER,
    classification:       'malicious',
    confidence:           87,
    threat_score:         87,
    summary:              'Binary exhibits process injection, anti-analysis evasion, and persistent C2 communication patterns confirmed across 2 NEST iterations.',
    signal_count:         10,
    contradiction_count:  0,
    reasoning_chain_hash: T.CHAIN_HASH,
    linked_iteration_id:  T.ITER_ID_2,
    nest_linkage: {
      session_id:               T.SESSION_ID,
      final_iteration_id:       T.ITER_ID_2,
      nest_enrichment_applied:  true,
      gyre_is_sole_verdict_source: true,
      nest_summary:             '2-iteration session; ECHO + TALON enabled; converged at confidence-threshold 87%.',
    },
  };
  return { ...base, ...overrides };
}

// ── RuntimeProof fixture ───────────────────────────────────────────────────────

export function makeRuntimeProof(overrides: Partial<NestRuntimeProof> = {}): NestRuntimeProof {
  const base: NestRuntimeProof = {
    schema_name:   'nest.runtime_proof',
    schema_version: '1.0.0',
    bundle_id:     T.BUNDLE_ID,
    session_id:    T.SESSION_ID,
    binary_id:     `binary_sha256_${T.SHA256_A}`,
    binary_sha256: T.SHA256_A,
    runtime_mode:  'tauri-runtime',
    proof_status:  'proven',
    has_tauri_runtime: true,
    browser_mode:  false,
    source_fidelity: {
      panel_fidelity_source:  'runtime-artifact',
      qa_subsystem_statuses:  ['NEST:pass', 'inspect:pass', 'plugins:pass'],
    },
    linked_runtime_artifacts: [
      { path: 'runtime-artifacts/runs/2026-04-29T16-49-02-396Z/gate-result.json', artifact_type: 'gate-result' },
      { path: 'runtime-artifacts/runs/2026-04-29T16-49-02-396Z/output.json',      artifact_type: 'output' },
      { path: 'runtime-artifacts/runs/2026-04-29T16-49-02-396Z/steps.jsonl',      artifact_type: 'steps-log' },
    ],
    run_id: '2026-04-29T16-49-02-396Z',
    page_url: 'http://localhost:1420',
  };
  return { ...base, ...overrides };
}

// ── AuditRefs fixture ──────────────────────────────────────────────────────────

export function makeAuditRefs(overrides: Partial<NestAuditRefs> = {}): NestAuditRefs {
  const base: NestAuditRefs = {
    schema_name:   'nest.audit_refs',
    schema_version: '1.0.0',
    bundle_id:     T.BUNDLE_ID,
    session_id:    T.SESSION_ID,
    binary_id:     `binary_sha256_${T.SHA256_A}`,
    binary_sha256: T.SHA256_A,
    actor:         actorUser,
    policy_version: T.POLICY_VERSION,
    audit_backend: 'local-append-log',
    events: [
      {
        event_id:   'evt_0001',
        event_type: 'nest.session.created',
        timestamp:  T.T0,
        actor_id:   'user:alice',
        actor_type: 'user',
        session_id: T.SESSION_ID,
        summary:    'Session created for FlareAuthenticator.exe.',
      },
      {
        event_id:   'evt_0002',
        event_type: 'nest.iteration.started',
        timestamp:  T.T1,
        actor_id:   'user:alice',
        actor_type: 'user',
        session_id: T.SESSION_ID,
        summary:    'Iteration 1 started.',
      },
      {
        event_id:   'evt_0003',
        event_type: 'nest.iteration.completed',
        timestamp:  T.T2,
        actor_id:   'user:alice',
        actor_type: 'user',
        session_id: T.SESSION_ID,
        summary:    'Iteration 1 completed. confidence=64.',
      },
      {
        event_id:   'evt_0004',
        event_type: 'nest.iteration.started',
        timestamp:  T.T2,
        actor_id:   'user:alice',
        actor_type: 'user',
        session_id: T.SESSION_ID,
        summary:    'Iteration 2 started.',
      },
      {
        event_id:   'evt_0005',
        event_type: 'nest.iteration.completed',
        timestamp:  T.T3,
        actor_id:   'user:alice',
        actor_type: 'user',
        session_id: T.SESSION_ID,
        summary:    'Iteration 2 completed. confidence=87.',
      },
      {
        event_id:   'evt_0006',
        event_type: 'nest.session.converged',
        timestamp:  T.T4,
        actor_id:   'user:alice',
        actor_type: 'user',
        session_id: T.SESSION_ID,
        summary:    'Session converged at confidence-threshold.',
      },
      {
        event_id:   'evt_0007',
        event_type: 'nest.session.exported',
        timestamp:  T.T_EXPORT,
        actor_id:   'user:alice',
        actor_type: 'user',
        session_id: T.SESSION_ID,
        summary:    'Bundle exported in local-tauri mode.',
      },
    ],
  };
  return { ...base, ...overrides };
}

// ── Complete bundle factories ──────────────────────────────────────────────────

/**
 * Minimal valid bundle — required files only, smallest permissible shapes.
 * Use this to verify that validation passes for a well-formed but sparse bundle.
 */
export function makeMinimalBundle(): NestEvidenceBundle {
  return {
    manifest:                makeManifest(),
    binary_identity:         makeBinaryIdentity(),
    session:                 makeSessionRecord(),
    iterations:              makeIterationsFile(),
    deltas:                  makeDeltasFile(),
    final_verdict_snapshot:  makeFinalVerdictSnapshot(),
    audit_refs:              makeAuditRefs(),
  };
}

/**
 * Realistic full bundle including runtime_proof, populated audit events,
 * and full optional fields.  Mirrors a local Tauri session that went through
 * the crossfile runtime test path.
 */
export function makeFullBundle(): NestEvidenceBundle {
  return {
    manifest:               makeManifest({
      export_mode: 'local-tauri',
      notes:       'FlareAuthenticator — crossfile validation session.',
    }),
    binary_identity:        makeBinaryIdentity({
      file_bound_proof: {
        proof_status:      'proven',
        proof_basis:       ['sha256-match', 'file-size-match', 'runtime-artifact-verified'],
        binary_sha256:     T.SHA256_A,
        file_size_bytes:   184320,
        runtime_proof_present: true,
        session_hash_lock: true,
      },
    }),
    session:                makeSessionRecord({
      runtime_proof_required: true,
      notes: ['Session ran under runtime test harness — crossfile validation mode.'],
    }),
    iterations:             makeIterationsFile(),
    deltas:                 makeDeltasFile(),
    final_verdict_snapshot: makeFinalVerdictSnapshot(),
    audit_refs:             makeAuditRefs(),
    runtime_proof:          makeRuntimeProof(),
  };
}

// ── Invalid fixtures ───────────────────────────────────────────────────────────

/**
 * All invalid fixtures are plain objects intentionally violating one rule each.
 * Cast to the target type so the validator can be called directly.
 */

/** Missing bundle_id in the manifest — should produce missing-field. */
export const invalidManifestMissingBundleId = (() => {
  const m = makeManifest();
  const { bundle_id: _removed, ...rest } = m;
  void _removed;
  return rest as NestManifest;
})();

/** Wrong schema_name — should produce invalid-schema-name. */
export const invalidManifestWrongSchemaName = makeManifest({
  schema_name: 'nest.wrong' as typeof import('../../types/nestEvidence').NEST_EVIDENCE_SCHEMA_NAMES.manifest,
});

/** Major schema version !== 1 — should produce unsupported-schema-version. */
export const invalidManifestBadSchemaVersion = makeManifest({
  schema_version: '2.0.0',
});

/** Malformed bundle_id (not nestbundle_ prefix) — should produce invalid-value. */
export const invalidManifestMalformedBundleId = makeManifest({
  bundle_id: 'bad-id-format',
});

/** bundle_id is missing the required files list entry — should produce missing-field. */
export const invalidManifestMissingRequiredFile = makeManifest({
  files: makeManifest().files.filter((f) => f.name !== 'audit_refs.json'),
});

/** binary_sha256 mismatch between binary_identity and session — replay-critical-error. */
export function makeSessionWithMismatchedSha256(): NestSessionRecord {
  return makeSessionRecord({ binary_sha256: T.SHA256_B });
}

/** file_bound_proof.binary_sha256 !== binary_sha256 — replay-critical-error. */
export function makeBinaryIdentityWithProofMismatch(): NestBinaryIdentity {
  return makeBinaryIdentity({
    file_bound_proof: {
      proof_status:    'proven',
      proof_basis:     ['sha256-match'],
      binary_sha256:   T.SHA256_B,    // wrong — should match SHA256_A
      file_size_bytes: 184320,
    },
  });
}

/** gyre_is_sole_verdict_source = false — replay-critical-error. */
export function makeSessionWithGyreViolation(): NestSessionRecord {
  return makeSessionRecord({
    gyre_linkage: {
      verdict_snapshot_id:       T.VERDICT_SNAP_ID,
      gyre_schema_version:       T.GYRE_SCHEMA_VER,
      gyre_build_id:             T.GYRE_BUILD_ID,
      gyre_is_sole_verdict_source: false as true,  // intentionally wrong
      nest_role:                 'iterative-enrichment-only',
    },
  });
}

/** source_engine !== 'gyre' in final verdict — replay-critical-error. */
export function makeFinalVerdictWithWrongSourceEngine(): NestFinalVerdictSnapshot {
  return makeFinalVerdictSnapshot({
    source_engine: 'nest' as 'gyre',  // intentionally wrong
  });
}

/** gyre_is_sole_verdict_source = false in nest_linkage — replay-critical-error. */
export function makeFinalVerdictWithNestLinkageViolation(): NestFinalVerdictSnapshot {
  return makeFinalVerdictSnapshot({
    nest_linkage: {
      session_id:              T.SESSION_ID,
      final_iteration_id:      T.ITER_ID_2,
      nest_enrichment_applied: true,
      gyre_is_sole_verdict_source: false as true,  // intentionally wrong
    },
  });
}

/** Malformed iteration_id (no 4-digit suffix) — should produce invalid-value. */
export function makeIterationsWithMalformedId(): NestIterationsFile {
  const f = makeIterationsFile();
  return {
    ...f,
    items: [
      { ...f.items[0], iteration_id: 'nestiter_ABCDE12345FGHJKMNPQRST0123_01' },  // 2 digits not 4
      f.items[1],
    ],
  };
}

/** Duplicate iteration_id — should produce consistency-error. */
export function makeIterationsWithDuplicateId(): NestIterationsFile {
  const f = makeIterationsFile();
  return {
    ...f,
    items: [
      f.items[0],
      { ...f.items[1], iteration_id: T.ITER_ID_1 },  // same id as item 0
    ],
  };
}

/** count !== items.length — should produce consistency-error. */
export function makeIterationsWithWrongCount(): NestIterationsFile {
  return makeIterationsFile({ count: 99 });
}

/** Delta references an iteration_id not in the iterations file — consistency-error. */
export function makeDeltasWithOrphanedRef(): NestDeltasFile {
  const f = makeDeltasFile();
  return {
    ...f,
    items: [
      {
        ...f.items[0],
        from_iteration_id: 'nestiter_ABCDE12345FGHJKMNPQRST0123_0009',  // does not exist
      },
    ],
  };
}

/** Duplicate delta_id — should produce consistency-error. */
export function makeDeltasWithDuplicateId(): NestDeltasFile {
  return makeDeltasFile({
    count: 2,
    items: [
      makeDeltasFile().items[0],
      { ...makeDeltasFile().items[0] },  // exact duplicate
    ],
  });
}

/** Delta where from_iteration_index >= to_iteration_index — should produce invalid-value. */
export function makeDeltasWithReverseIndexes(): NestDeltasFile {
  const f = makeDeltasFile();
  return {
    ...f,
    items: [
      { ...f.items[0], from_iteration_index: 3, to_iteration_index: 1 },
    ],
  };
}

/** Session whose gyre_linkage.verdict_snapshot_id does not match final verdict — consistency-error. */
export function makeBundleWithVerdictSnapMismatch(): NestEvidenceBundle {
  const bundle = makeMinimalBundle();
  return {
    ...bundle,
    session: makeSessionRecord({
      gyre_linkage: {
        ...bundle.session.gyre_linkage,
        verdict_snapshot_id: 'gyresnap_DIFFERENT12345FGHJKMNPQR',
      },
    }),
  };
}

/** runtime_proof_required = true but no runtime_proof in bundle — missing-field. */
export function makeBundleRequiringMissingRuntimeProof(): NestEvidenceBundle {
  const bundle = makeMinimalBundle();
  return {
    ...bundle,
    session: makeSessionRecord({ runtime_proof_required: true }),
  };
}
