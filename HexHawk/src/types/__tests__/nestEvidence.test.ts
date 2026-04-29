/**
 * nestEvidence.test.ts
 *
 * Vitest tests for the NEST evidence-plane contracts.
 * Covers: valid round-trips, missing required fields, malformed IDs/hashes,
 * schema version mismatch, immutability/replay-critical field preservation,
 * and cross-file consistency enforcement.
 */

import { describe, it, expect } from 'vitest';
import {
  validateNestManifest,
  validateNestBinaryIdentity,
  validateNestSessionRecord,
  validateNestIterationsFile,
  validateNestDeltasFile,
  validateNestFinalVerdictSnapshot,
  validateNestRuntimeProof,
  validateNestAuditRefs,
  validateNestEvidenceBundle,
  parseNestManifest,
  parseNestBinaryIdentity,
  parseNestSessionRecord,
  parseNestIterationsFile,
  parseNestDeltasFile,
  parseNestFinalVerdictSnapshot,
  parseNestRuntimeProof,
  parseNestAuditRefs,
} from '../../types/nestEvidence';

import {
  makeMinimalBundle,
  makeFullBundle,
  makeManifest,
  makeBinaryIdentity,
  makeSessionRecord,
  makeIterationsFile,
  makeDeltasFile,
  makeFinalVerdictSnapshot,
  makeRuntimeProof,
  makeAuditRefs,
  invalidManifestMissingBundleId,
  invalidManifestWrongSchemaName,
  invalidManifestBadSchemaVersion,
  invalidManifestMalformedBundleId,
  invalidManifestMissingRequiredFile,
  makeSessionWithMismatchedSha256,
  makeBinaryIdentityWithProofMismatch,
  makeSessionWithGyreViolation,
  makeFinalVerdictWithWrongSourceEngine,
  makeFinalVerdictWithNestLinkageViolation,
  makeIterationsWithMalformedId,
  makeIterationsWithDuplicateId,
  makeIterationsWithWrongCount,
  makeDeltasWithOrphanedRef,
  makeDeltasWithDuplicateId,
  makeDeltasWithReverseIndexes,
  makeBundleWithVerdictSnapMismatch,
  makeBundleRequiringMissingRuntimeProof,
  T,
} from '../../test/fixtures/nestEvidenceFixtures';

// ── Helpers ────────────────────────────────────────────────────────────────────

function issuesWith(issues: ReturnType<typeof validateNestManifest>, code: string): number {
  return issues.filter((i) => i.code === code).length;
}

function issuesAtPath(issues: ReturnType<typeof validateNestManifest>, path: string): number {
  return issues.filter((i) => i.path === path || i.path.startsWith(path)).length;
}

// ── 1. Valid round-trips ───────────────────────────────────────────────────────

describe('valid round-trips', () => {
  it('minimal bundle passes all validators', () => {
    const bundle = makeMinimalBundle();
    const issues = validateNestEvidenceBundle(bundle);
    expect(issues).toHaveLength(0);
  });

  it('full bundle with runtime_proof passes all validators', () => {
    const bundle = makeFullBundle();
    const issues = validateNestEvidenceBundle(bundle);
    expect(issues).toHaveLength(0);
  });

  it('manifest validates cleanly', () => {
    expect(validateNestManifest(makeManifest())).toHaveLength(0);
  });

  it('binary_identity validates cleanly', () => {
    expect(validateNestBinaryIdentity(makeBinaryIdentity())).toHaveLength(0);
  });

  it('session validates cleanly', () => {
    expect(validateNestSessionRecord(makeSessionRecord())).toHaveLength(0);
  });

  it('iterations validates cleanly', () => {
    expect(validateNestIterationsFile(makeIterationsFile())).toHaveLength(0);
  });

  it('deltas validates cleanly', () => {
    expect(validateNestDeltasFile(makeDeltasFile())).toHaveLength(0);
  });

  it('final_verdict_snapshot validates cleanly', () => {
    expect(validateNestFinalVerdictSnapshot(makeFinalVerdictSnapshot())).toHaveLength(0);
  });

  it('runtime_proof validates cleanly', () => {
    expect(validateNestRuntimeProof(makeRuntimeProof())).toHaveLength(0);
  });

  it('audit_refs validates cleanly', () => {
    expect(validateNestAuditRefs(makeAuditRefs())).toHaveLength(0);
  });

  it('parse* wrappers return ok=true for valid inputs', () => {
    expect(parseNestManifest(makeManifest()).ok).toBe(true);
    expect(parseNestBinaryIdentity(makeBinaryIdentity()).ok).toBe(true);
    expect(parseNestSessionRecord(makeSessionRecord()).ok).toBe(true);
    expect(parseNestIterationsFile(makeIterationsFile()).ok).toBe(true);
    expect(parseNestDeltasFile(makeDeltasFile()).ok).toBe(true);
    expect(parseNestFinalVerdictSnapshot(makeFinalVerdictSnapshot()).ok).toBe(true);
    expect(parseNestRuntimeProof(makeRuntimeProof()).ok).toBe(true);
    expect(parseNestAuditRefs(makeAuditRefs()).ok).toBe(true);
  });

  it('parse* wrappers return value when ok', () => {
    const result = parseNestManifest(makeManifest());
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.bundle_id).toBe(T.BUNDLE_ID);
    }
  });

  it('parse* returns ok=false with issues for non-object input', () => {
    const result = parseNestManifest('not an object');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.issues.length).toBeGreaterThan(0);
    }
  });
});

// ── 2. Missing required field rejection ───────────────────────────────────────

describe('missing required fields', () => {
  it('manifest missing bundle_id produces missing-field', () => {
    const issues = validateNestManifest(invalidManifestMissingBundleId);
    expect(issuesWith(issues, 'missing-field')).toBeGreaterThan(0);
    expect(issuesAtPath(issues, 'manifest.bundle_id')).toBeGreaterThan(0);
  });

  it('manifest missing required file entry produces missing-field', () => {
    const issues = validateNestManifest(invalidManifestMissingRequiredFile);
    const missingFileIssues = issues.filter(
      (i) => i.code === 'missing-field' && i.message.includes('audit_refs.json'),
    );
    expect(missingFileIssues.length).toBeGreaterThan(0);
  });

  it('binary_identity missing hashes.sha1 produces missing-field', () => {
    const bi = makeBinaryIdentity();
    const { sha1: _removed, ...hashesWithoutSha1 } = bi.hashes;
    void _removed;
    const invalid = { ...bi, hashes: hashesWithoutSha1 };
    const issues = validateNestBinaryIdentity(invalid as typeof bi);
    expect(issuesAtPath(issues, 'binary_identity.hashes.sha1')).toBeGreaterThan(0);
  });

  it('session missing gyre_linkage.verdict_snapshot_id produces missing-field', () => {
    const s = makeSessionRecord();
    const { verdict_snapshot_id: _removed, ...gyreWithout } = s.gyre_linkage;
    void _removed;
    const invalid = { ...s, gyre_linkage: gyreWithout } as typeof s;
    const issues = validateNestSessionRecord(invalid);
    expect(issuesAtPath(issues, 'session.gyre_linkage.verdict_snapshot_id')).toBeGreaterThan(0);
  });

  it('final_verdict_snapshot missing nest_linkage.session_id produces missing-field', () => {
    const fv = makeFinalVerdictSnapshot();
    const { session_id: _removed, ...linkageWithout } = fv.nest_linkage;
    void _removed;
    const invalid = { ...fv, nest_linkage: linkageWithout } as typeof fv;
    const issues = validateNestFinalVerdictSnapshot(invalid);
    expect(issuesAtPath(issues, 'final_verdict_snapshot.nest_linkage.session_id')).toBeGreaterThan(0);
  });

  it('audit_refs missing actor produces missing-field', () => {
    const ar = makeAuditRefs();
    const { actor: _removed, ...arWithout } = ar;
    void _removed;
    const invalid = arWithout as typeof ar;
    const issues = validateNestAuditRefs(invalid);
    expect(issuesAtPath(issues, 'audit_refs.actor')).toBeGreaterThan(0);
  });
});

// ── 3. Malformed ID/hash rejection ────────────────────────────────────────────

describe('malformed ID and hash rejection', () => {
  it('malformed bundle_id produces invalid-value', () => {
    const issues = validateNestManifest(invalidManifestMalformedBundleId);
    expect(issuesWith(issues, 'invalid-value')).toBeGreaterThan(0);
    expect(issuesAtPath(issues, 'manifest.bundle_id')).toBeGreaterThan(0);
  });

  it('binary_id not matching binary_sha256_<sha256> produces invalid-value', () => {
    const bi = makeBinaryIdentity({ binary_id: 'binary_sha256_badhash' });
    const issues = validateNestBinaryIdentity(bi);
    expect(issuesWith(issues, 'invalid-value')).toBeGreaterThan(0);
  });

  it('uppercase sha256 in hashes produces invalid-value', () => {
    const bi = makeBinaryIdentity({
      hashes: { sha256: T.SHA256_A.toUpperCase(), sha1: T.SHA1_A, md5: T.MD5_A },
    });
    const issues = validateNestBinaryIdentity(bi);
    expect(issuesWith(issues, 'invalid-value')).toBeGreaterThan(0);
  });

  it('iteration_id with 2-digit index produces invalid-value', () => {
    const issues = validateNestIterationsFile(makeIterationsWithMalformedId());
    expect(issuesWith(issues, 'invalid-value')).toBeGreaterThan(0);
  });

  it('verdict_snapshot_id not matching gyresnap_ pattern produces invalid-value', () => {
    const fv = makeFinalVerdictSnapshot({ verdict_snapshot_id: 'wrongprefix_ABCDE12345FGHJKMNPQRST0123' });
    const issues = validateNestFinalVerdictSnapshot(fv);
    expect(issuesAtPath(issues, 'final_verdict_snapshot.verdict_snapshot_id')).toBeGreaterThan(0);
  });

  it('non-RFC3339 timestamp in audit_refs.events produces invalid-value', () => {
    const ar = makeAuditRefs();
    const arInvalid = {
      ...ar,
      events: [{ ...ar.events[0], timestamp: '2026-04-29 16:49:00' }],  // missing T and Z
    };
    const issues = validateNestAuditRefs(arInvalid);
    expect(issuesWith(issues, 'invalid-value')).toBeGreaterThan(0);
  });
});

// ── 4. Schema version mismatch handling ───────────────────────────────────────

describe('schema version handling', () => {
  it('wrong schema_name produces invalid-schema-name', () => {
    const issues = validateNestManifest(invalidManifestWrongSchemaName);
    expect(issuesWith(issues, 'invalid-schema-name')).toBeGreaterThan(0);
  });

  it('unsupported major schema version produces unsupported-schema-version', () => {
    const issues = validateNestManifest(invalidManifestBadSchemaVersion);
    expect(issuesWith(issues, 'unsupported-schema-version')).toBeGreaterThan(0);
  });

  it('schema_version "1.2.0" passes (backward-compatible minor)', () => {
    const issues = validateNestManifest(makeManifest({ schema_version: '1.2.0' }));
    expect(issuesWith(issues, 'unsupported-schema-version')).toBe(0);
  });

  it('schema_version "1.0.9" passes (patch)', () => {
    const issues = validateNestManifest(makeManifest({ schema_version: '1.0.9' }));
    expect(issuesWith(issues, 'unsupported-schema-version')).toBe(0);
  });

  it('schema_version "0.9.0" produces unsupported-schema-version', () => {
    const issues = validateNestManifest(makeManifest({ schema_version: '0.9.0' }));
    expect(issuesWith(issues, 'unsupported-schema-version')).toBeGreaterThan(0);
  });

  it('non-semver schema_version produces invalid-value', () => {
    const issues = validateNestManifest(makeManifest({ schema_version: 'v1.0' }));
    expect(issuesWith(issues, 'invalid-value')).toBeGreaterThan(0);
  });

  it('file entry schema_version mismatch produces unsupported-schema-version', () => {
    const m = makeManifest();
    const files = m.files.map((f) => f.name === 'session.json' ? { ...f, schema_version: '2.0.0' } : f);
    const issues = validateNestManifest({ ...m, files });
    expect(issuesWith(issues, 'unsupported-schema-version')).toBeGreaterThan(0);
  });
});

// ── 5. Replay-critical and immutable field preservation ───────────────────────

describe('replay-critical field enforcement', () => {
  it('binary_sha256 mismatch between binary_identity and session produces replay-critical-error', () => {
    const bundle = makeMinimalBundle();
    const issues = validateNestEvidenceBundle({
      ...bundle,
      session: makeSessionWithMismatchedSha256(),
    });
    const criticalIssues = issues.filter((i) => i.code === 'replay-critical-error');
    expect(criticalIssues.length).toBeGreaterThan(0);
  });

  it('file_bound_proof.binary_sha256 mismatch produces replay-critical-error', () => {
    const issues = validateNestBinaryIdentity(makeBinaryIdentityWithProofMismatch());
    expect(issuesWith(issues, 'replay-critical-error')).toBeGreaterThan(0);
  });

  it('file_bound_proof.file_size_bytes mismatch produces replay-critical-error', () => {
    const bi = makeBinaryIdentity({
      file_bound_proof: {
        proof_status:    'proven',
        proof_basis:     ['sha256-match'],
        binary_sha256:   T.SHA256_A,
        file_size_bytes: 99999,          // wrong — does not match file_size_bytes: 184320
      },
    });
    const issues = validateNestBinaryIdentity(bi);
    expect(issuesWith(issues, 'replay-critical-error')).toBeGreaterThan(0);
  });

  it('iteration binary_sha256 mismatch produces replay-critical-error', () => {
    const f = makeIterationsFile();
    const invalid = {
      ...f,
      items: [{ ...f.items[0], binary_sha256: T.SHA256_B }, f.items[1]],
    };
    const bundle = { ...makeMinimalBundle(), iterations: invalid };
    const issues = validateNestEvidenceBundle(bundle);
    expect(issuesWith(issues, 'replay-critical-error')).toBeGreaterThan(0);
  });

  it('delta binary_sha256 mismatch produces replay-critical-error', () => {
    const f = makeDeltasFile();
    const invalid = {
      ...f,
      items: [{ ...f.items[0], binary_sha256: T.SHA256_B }],
    };
    const bundle = { ...makeMinimalBundle(), deltas: invalid };
    const issues = validateNestEvidenceBundle(bundle);
    expect(issuesWith(issues, 'replay-critical-error')).toBeGreaterThan(0);
  });

  it('gyre_is_sole_verdict_source=false in session.gyre_linkage produces replay-critical-error', () => {
    const issues = validateNestSessionRecord(makeSessionWithGyreViolation());
    expect(issuesWith(issues, 'replay-critical-error')).toBeGreaterThan(0);
  });

  it('source_engine != gyre in final_verdict_snapshot produces replay-critical-error', () => {
    const issues = validateNestFinalVerdictSnapshot(makeFinalVerdictWithWrongSourceEngine());
    expect(issuesWith(issues, 'replay-critical-error')).toBeGreaterThan(0);
  });

  it('gyre_is_sole_verdict_source=false in nest_linkage produces replay-critical-error', () => {
    const issues = validateNestFinalVerdictSnapshot(makeFinalVerdictWithNestLinkageViolation());
    expect(issuesWith(issues, 'replay-critical-error')).toBeGreaterThan(0);
  });
});

// ── 6. Cross-file consistency enforcement ─────────────────────────────────────

describe('cross-file consistency', () => {
  it('verdict_snapshot_id mismatch between session and final_verdict produces consistency-error', () => {
    const issues = validateNestEvidenceBundle(makeBundleWithVerdictSnapMismatch());
    expect(issuesWith(issues, 'consistency-error')).toBeGreaterThan(0);
  });

  it('duplicate iteration_id produces consistency-error', () => {
    const issues = validateNestIterationsFile(makeIterationsWithDuplicateId());
    expect(issuesWith(issues, 'consistency-error')).toBeGreaterThan(0);
  });

  it('iterations.count !== items.length produces consistency-error', () => {
    const issues = validateNestIterationsFile(makeIterationsWithWrongCount());
    expect(issuesWith(issues, 'consistency-error')).toBeGreaterThan(0);
  });

  it('delta referencing missing iteration_id produces consistency-error', () => {
    const bundle = { ...makeMinimalBundle(), deltas: makeDeltasWithOrphanedRef() };
    const issues = validateNestEvidenceBundle(bundle);
    expect(issuesWith(issues, 'consistency-error')).toBeGreaterThan(0);
  });

  it('duplicate delta_id produces consistency-error', () => {
    const issues = validateNestDeltasFile(makeDeltasWithDuplicateId());
    expect(issuesWith(issues, 'consistency-error')).toBeGreaterThan(0);
  });

  it('delta from_iteration_index >= to_iteration_index produces invalid-value', () => {
    const issues = validateNestDeltasFile(makeDeltasWithReverseIndexes());
    expect(issuesWith(issues, 'invalid-value')).toBeGreaterThan(0);
  });

  it('runtime_proof_required=true but no runtime_proof produces missing-field', () => {
    const issues = validateNestEvidenceBundle(makeBundleRequiringMissingRuntimeProof());
    const missingProofIssues = issues.filter(
      (i) => i.code === 'missing-field' && i.path === 'runtime_proof',
    );
    expect(missingProofIssues.length).toBeGreaterThan(0);
  });

  it('bundle with runtime_proof where binary_sha256 mismatches is rejected', () => {
    const bundle = makeFullBundle();
    const rp = makeRuntimeProof({ binary_sha256: T.SHA256_B });
    const issues = validateNestEvidenceBundle({ ...bundle, runtime_proof: rp });
    expect(issuesWith(issues, 'replay-critical-error')).toBeGreaterThan(0);
  });

  it('all session_ids across bundle files must match', () => {
    const bundle = makeMinimalBundle();
    const corruptedAudit = makeAuditRefs({ session_id: 'nestsession_DIFFERENT12345FGHJKMNPQR' });
    const issues = validateNestEvidenceBundle({ ...bundle, audit_refs: corruptedAudit });
    expect(issuesWith(issues, 'consistency-error')).toBeGreaterThan(0);
  });

  it('all bundle_ids across bundle files must match', () => {
    const bundle = makeMinimalBundle();
    const corruptedSession = makeSessionRecord({ bundle_id: 'nestbundle_DIFFERENT12345FGHJKMNPQ' });
    const issues = validateNestEvidenceBundle({ ...bundle, session: corruptedSession });
    expect(issuesWith(issues, 'consistency-error')).toBeGreaterThan(0);
  });

  it('final_verdict linked_iteration_id must match nest_linkage.final_iteration_id', () => {
    const fv = makeFinalVerdictSnapshot({
      linked_iteration_id: T.ITER_ID_1,
      nest_linkage: {
        session_id:              T.SESSION_ID,
        final_iteration_id:      T.ITER_ID_2,  // mismatch
        nest_enrichment_applied: true,
        gyre_is_sole_verdict_source: true,
      },
    });
    const bundle = { ...makeMinimalBundle(), final_verdict_snapshot: fv };
    const issues = validateNestEvidenceBundle(bundle);
    expect(issuesWith(issues, 'consistency-error')).toBeGreaterThan(0);
  });
});

// ── 7. GYRE sole-verdict-source invariant ─────────────────────────────────────

describe('GYRE sole verdict source invariant', () => {
  it('nest_role not containing "enrich" produces invalid-value on session.gyre_linkage.nest_role', () => {
    const s = makeSessionRecord({
      gyre_linkage: {
        ...makeSessionRecord().gyre_linkage,
        nest_role: 'verdict-owner',  // invalid: implies NEST owns verdict
      },
    });
    const issues = validateNestSessionRecord(s);
    const nestRoleIssues = issues.filter(
      (i) => i.path === 'session.gyre_linkage.nest_role' && i.code === 'invalid-value',
    );
    expect(nestRoleIssues.length).toBeGreaterThan(0);
  });

  it('valid nest_role "enrichment-only" is accepted', () => {
    const s = makeSessionRecord({
      gyre_linkage: { ...makeSessionRecord().gyre_linkage, nest_role: 'enrichment-only' },
    });
    const issues = validateNestSessionRecord(s);
    expect(issuesWith(issues, 'invalid-value')).toBe(0);
  });

  it('valid nest_role "iterative-enrichment-only" is accepted', () => {
    expect(validateNestSessionRecord(makeSessionRecord())).toHaveLength(0);
  });

  it('full bundle cannot have source_engine != gyre and still pass', () => {
    const bundle = makeFullBundle();
    const corrupt = makeFinalVerdictWithWrongSourceEngine();
    const issues = validateNestEvidenceBundle({ ...bundle, final_verdict_snapshot: corrupt });
    const critical = issues.filter((i) => i.code === 'replay-critical-error');
    expect(critical.length).toBeGreaterThan(0);
  });
});

// ── 8. Actor type validation ───────────────────────────────────────────────────

describe('actor validation', () => {
  it('valid actor types are accepted', () => {
    for (const type of ['user', 'reviewer', 'approver', 'service-account', 'system'] as const) {
      const m = makeManifest({ actor: { id: `${type}:test`, type } });
      expect(validateNestManifest(m)).toHaveLength(0);
    }
  });

  it('invalid actor type produces invalid-value', () => {
    const m = makeManifest({
      actor: { id: 'hacker:bob', type: 'hacker' as 'user' },
    });
    const issues = validateNestManifest(m);
    expect(issuesWith(issues, 'invalid-value')).toBeGreaterThan(0);
  });

  it('service-account actor with tenant/team passes', () => {
    const bundle = makeFullBundle();
    const issues = validateNestEvidenceBundle({
      ...bundle,
      manifest: makeManifest({ actor: { id: 'service-account:bot', type: 'service-account', tenant_id: 'acme', team_id: 're-lab' } }),
      session: makeSessionRecord({ actor: { id: 'service-account:bot', type: 'service-account', tenant_id: 'acme', team_id: 're-lab' } }),
      audit_refs: makeAuditRefs({ actor: { id: 'service-account:bot', type: 'service-account', tenant_id: 'acme', team_id: 're-lab' } }),
    });
    expect(issues).toHaveLength(0);
  });
});

// ── 9. Identity source validation ─────────────────────────────────────────────

describe('identity source validation', () => {
  it('all valid identity sources are accepted', () => {
    const validSources = ['local-path', 'dropped-file', 'imported-object', 'api-upload', 'corpus-entry'] as const;
    for (const source of validSources) {
      const bi = makeBinaryIdentity({ identity_source: source });
      expect(validateNestBinaryIdentity(bi)).toHaveLength(0);
    }
  });

  it('invalid identity source produces invalid-value', () => {
    const bi = makeBinaryIdentity({ identity_source: 'network-capture' as 'local-path' });
    const issues = validateNestBinaryIdentity(bi);
    expect(issuesWith(issues, 'invalid-value')).toBeGreaterThan(0);
  });
});

// ── 10. JSON parse boundaries ─────────────────────────────────────────────────

describe('JSON parse boundaries', () => {
  it('parse* handles JSON.parse round-trip correctly', () => {
    const manifest = makeManifest();
    const json = JSON.stringify(manifest);
    const parsed = JSON.parse(json) as unknown;
    const result = parseNestManifest(parsed);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.bundle_id).toBe(T.BUNDLE_ID);
      expect(result.value.binary_sha256).toBe(T.SHA256_A);
    }
  });

  it('parse* handles full bundle JSON round-trip without losing IDs', () => {
    const bundle = makeFullBundle();
    const json = JSON.stringify(bundle);
    const parsed = JSON.parse(json) as typeof bundle;
    expect(parsed.session.gyre_linkage.verdict_snapshot_id).toBe(T.VERDICT_SNAP_ID);
    expect(parsed.final_verdict_snapshot.nest_linkage.gyre_is_sole_verdict_source).toBe(true);
    expect(parsed.runtime_proof?.binary_sha256).toBe(T.SHA256_A);
  });

  it('parse* returns ok=false with issues array when input is null', () => {
    const result = parseNestSessionRecord(null);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.issues.length).toBeGreaterThan(0);
    }
  });

  it('parse* returns ok=false with issues array when input is an array', () => {
    const result = parseNestIterationsFile([]);
    expect(result.ok).toBe(false);
  });

  it('validate bundle produces no issues after full JSON serialization round-trip', () => {
    const bundle = makeFullBundle();
    const roundTripped = JSON.parse(JSON.stringify(bundle)) as typeof bundle;
    expect(validateNestEvidenceBundle(roundTripped)).toHaveLength(0);
  });
});
