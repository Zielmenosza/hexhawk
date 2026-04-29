# NEST Evidence Examples

Practical JSON examples derived from the golden fixtures in
`HexHawk/src/test/fixtures/nestEvidenceFixtures.ts`.

All IDs use the stable test constants defined in that file (`T.*`).
These examples show what each file looks like on disk inside a bundle directory.

---

## Shared Constants

| Constant | Value |
|----------|-------|
| `ULID` | `ABCDE12345FGHJKMNPQRST0123` |
| `BUNDLE_ID` | `nestbundle_ABCDE12345FGHJKMNPQRST0123` |
| `SESSION_ID` | `nestsession_ABCDE12345FGHJKMNPQRST0123` |
| `ITER_ID_1` | `nestiter_ABCDE12345FGHJKMNPQRST0123_0001` |
| `ITER_ID_2` | `nestiter_ABCDE12345FGHJKMNPQRST0123_0002` |
| `DELTA_ID_1_2` | `nestdelta_ABCDE12345FGHJKMNPQRST0123_0001_0002` |
| `VERDICT_SNAP_ID` | `gyresnap_ABCDE12345FGHJKMNPQRST0123` |
| `SHA256_A` | `a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2` |
| `BINARY_ID` | `binary_sha256_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2` |

---

## 1. Minimal Valid Bundle

The minimal bundle contains all 7 required files, no `runtime_proof`, and only the
mandatory fields populated.  Use `makeMinimalBundle()` in tests.

### `manifest.json`

```json
{
  "schema_name": "nest.manifest",
  "schema_version": "1.0.0",
  "bundle_schema_version": "1.0.0",
  "bundle_format_version": "1.0.0",
  "bundle_id": "nestbundle_ABCDE12345FGHJKMNPQRST0123",
  "session_id": "nestsession_ABCDE12345FGHJKMNPQRST0123",
  "binary_id": "binary_sha256_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "binary_sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "engine_build_id": "1.0.0+abc123def456",
  "policy_version": "2026-04-29.1",
  "actor": { "id": "user:alice", "type": "user", "display_name": "Alice" },
  "timestamps": {
    "created_at": "2026-04-29T16:49:00Z",
    "exported_at": "2026-04-29T16:51:00Z"
  },
  "files": [
    { "name": "manifest.json",              "required": true, "sha256": "<sha256>", "bytes": 1024, "schema_name": "nest.manifest",              "schema_version": "1.0.0" },
    { "name": "binary_identity.json",       "required": true, "sha256": "<sha256>", "bytes": 512,  "schema_name": "nest.binary_identity",       "schema_version": "1.0.0" },
    { "name": "session.json",               "required": true, "sha256": "<sha256>", "bytes": 2048, "schema_name": "nest.session",               "schema_version": "1.0.0" },
    { "name": "iterations.json",            "required": true, "sha256": "<sha256>", "bytes": 4096, "schema_name": "nest.iterations",            "schema_version": "1.0.0" },
    { "name": "deltas.json",                "required": true, "sha256": "<sha256>", "bytes": 2048, "schema_name": "nest.deltas",                "schema_version": "1.0.0" },
    { "name": "final_verdict_snapshot.json","required": true, "sha256": "<sha256>", "bytes": 1024, "schema_name": "nest.final_verdict_snapshot","schema_version": "1.0.0" },
    { "name": "audit_refs.json",            "required": true, "sha256": "<sha256>", "bytes": 512,  "schema_name": "nest.audit_refs",            "schema_version": "1.0.0" }
  ],
  "immutability": {
    "bundle_locked": true,
    "locked_at": "2026-04-29T16:51:00Z",
    "mutation_policy": "immutable-after-export"
  },
  "replay": {
    "replayable": true,
    "mode_supported": ["local"],
    "requires_binary_bytes": true
  }
}
```

### `binary_identity.json`

```json
{
  "schema_name": "nest.binary_identity",
  "schema_version": "1.0.0",
  "bundle_id": "nestbundle_ABCDE12345FGHJKMNPQRST0123",
  "session_id": "nestsession_ABCDE12345FGHJKMNPQRST0123",
  "binary_id": "binary_sha256_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "binary_sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "hashes": {
    "sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "sha1":   "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "md5":    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
  },
  "file_size_bytes": 184320,
  "format": "PE/MZ",
  "architecture": "x86_64",
  "first_seen_at": "2026-04-29T16:49:00Z",
  "identity_source": "local-path",
  "file_bound_proof": {
    "proof_status":   "proven",
    "proof_basis":    ["sha256-match", "file-size-match"],
    "binary_sha256":  "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "file_size_bytes": 184320,
    "session_hash_lock": true
  },
  "original_path": "D:\\Challenges\\FlareAuthenticator\\FlareAuthenticator.exe",
  "file_name": "FlareAuthenticator.exe"
}
```

### `session.json` (key GYRE linkage fields highlighted)

```json
{
  "schema_name": "nest.session",
  "schema_version": "1.0.0",
  "bundle_id": "nestbundle_ABCDE12345FGHJKMNPQRST0123",
  "session_id": "nestsession_ABCDE12345FGHJKMNPQRST0123",
  "binary_sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "status": "completed",
  "execution_mode": "local-tauri",
  "iteration_count": 2,
  "delta_count": 1,
  "final_iteration_index": 2,
  "convergence": {
    "has_converged": true,
    "reason": "confidence-threshold",
    "confidence": 87,
    "classification_stable": true,
    "signal_delta": 3,
    "contradiction_burden": 0,
    "stability_score": 0.91
  },
  "gyre_linkage": {
    "verdict_snapshot_id": "gyresnap_ABCDE12345FGHJKMNPQRST0123",
    "gyre_schema_version": "1.0.0",
    "gyre_build_id": "1.0.0+abc123def456",
    "gyre_is_sole_verdict_source": true,
    "nest_role": "iterative-enrichment-only"
  }
}
```

> **Invariant:** `gyre_is_sole_verdict_source` must always be `true`.
> `nest_role` must contain the string `"enrich"`.
> Any other value triggers a `replay-critical-error`.

### `final_verdict_snapshot.json`

```json
{
  "schema_name": "nest.final_verdict_snapshot",
  "schema_version": "1.0.0",
  "bundle_id": "nestbundle_ABCDE12345FGHJKMNPQRST0123",
  "session_id": "nestsession_ABCDE12345FGHJKMNPQRST0123",
  "binary_sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "verdict_snapshot_id": "gyresnap_ABCDE12345FGHJKMNPQRST0123",
  "source_engine": "gyre",
  "gyre_build_id": "1.0.0+abc123def456",
  "gyre_schema_version": "1.0.0",
  "classification": "malicious",
  "confidence": 87,
  "threat_score": 87,
  "summary": "Binary exhibits process injection, anti-analysis evasion, and persistent C2 communication patterns confirmed across 2 NEST iterations.",
  "signal_count": 10,
  "contradiction_count": 0,
  "reasoning_chain_hash": "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "linked_iteration_id": "nestiter_ABCDE12345FGHJKMNPQRST0123_0002",
  "nest_linkage": {
    "session_id": "nestsession_ABCDE12345FGHJKMNPQRST0123",
    "final_iteration_id": "nestiter_ABCDE12345FGHJKMNPQRST0123_0002",
    "nest_enrichment_applied": true,
    "gyre_is_sole_verdict_source": true,
    "nest_summary": "2-iteration session; ECHO + TALON enabled; converged at confidence-threshold 87%."
  }
}
```

> **Invariant:** `source_engine` must be `"gyre"` and `nest_linkage.gyre_is_sole_verdict_source`
> must be `true`.  `linked_iteration_id` must equal `nest_linkage.final_iteration_id`.

---

## 2. Realistic Full Bundle (Local Tauri + Runtime Proof)

The full bundle includes `runtime_proof` and represents a session that ran
under the Tauri runtime test harness.  Use `makeFullBundle()` in tests.

Additional fields on the manifest:

```json
{
  "export_mode": "local-tauri",
  "notes": "FlareAuthenticator — crossfile validation session."
}
```

Additional fields on `binary_identity.file_bound_proof`:

```json
{
  "proof_basis": ["sha256-match", "file-size-match", "runtime-artifact-verified"],
  "runtime_proof_present": true
}
```

Additional fields on `session`:

```json
{
  "runtime_proof_required": true,
  "notes": ["Session ran under runtime test harness — crossfile validation mode."]
}
```

### `runtime_proof.json`

```json
{
  "schema_name": "nest.runtime_proof",
  "schema_version": "1.0.0",
  "bundle_id": "nestbundle_ABCDE12345FGHJKMNPQRST0123",
  "session_id": "nestsession_ABCDE12345FGHJKMNPQRST0123",
  "binary_sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "runtime_mode": "tauri-runtime",
  "proof_status": "proven",
  "has_tauri_runtime": true,
  "browser_mode": false,
  "source_fidelity": {
    "panel_fidelity_source": "runtime-artifact",
    "qa_subsystem_statuses": ["NEST:pass", "inspect:pass", "plugins:pass"]
  },
  "linked_runtime_artifacts": [
    { "path": "runtime-artifacts/runs/2026-04-29T16-49-02-396Z/gate-result.json", "artifact_type": "gate-result" },
    { "path": "runtime-artifacts/runs/2026-04-29T16-49-02-396Z/output.json",      "artifact_type": "output" },
    { "path": "runtime-artifacts/runs/2026-04-29T16-49-02-396Z/steps.jsonl",      "artifact_type": "steps-log" }
  ],
  "run_id": "2026-04-29T16-49-02-396Z",
  "page_url": "http://localhost:1420"
}
```

> When `session.runtime_proof_required = true`, the bundle **must** include a
> `runtime_proof` object.  Absence triggers a `missing-field` issue.

---

## 3. Iterations and Deltas

### `iterations.json` (abbreviated, 2 items)

```json
{
  "schema_name": "nest.iterations",
  "schema_version": "1.0.0",
  "bundle_id": "nestbundle_ABCDE12345FGHJKMNPQRST0123",
  "session_id": "nestsession_ABCDE12345FGHJKMNPQRST0123",
  "binary_sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "count": 2,
  "items": [
    {
      "iteration_id": "nestiter_ABCDE12345FGHJKMNPQRST0123_0001",
      "iteration_index": 1,
      "session_id": "nestsession_ABCDE12345FGHJKMNPQRST0123",
      "binary_sha256": "a1b2c3d4e5f6...",
      "started_at": "2026-04-29T16:49:02Z",
      "completed_at": "2026-04-29T16:49:25Z",
      "duration_ms": 23000,
      "verdict_snapshot": {
        "classification": "suspicious",
        "confidence": 64,
        "threat_score": 64,
        "signal_count": 7,
        "contradiction_count": 1,
        "reasoning_chain_hash": "<sha256>"
      },
      "convergence_snapshot": {
        "has_converged": false,
        "reason": "continue",
        "stability_score": 0.55,
        "classification_stable": false,
        "signal_delta": 7,
        "contradiction_burden": 1
      },
      "file_identity_locked": true
    },
    {
      "iteration_id": "nestiter_ABCDE12345FGHJKMNPQRST0123_0002",
      "iteration_index": 2,
      "binary_sha256": "a1b2c3d4e5f6...",
      "verdict_snapshot": {
        "classification": "malicious",
        "confidence": 87
      },
      "convergence_snapshot": {
        "has_converged": true,
        "reason": "confidence-threshold"
      },
      "file_identity_locked": true
    }
  ]
}
```

**Iteration ID format:** `nestiter_<ULID>_<NNNN>` where `<NNNN>` is a
zero-padded 4-digit index starting at `0001`.

### `deltas.json`

```json
{
  "schema_name": "nest.deltas",
  "schema_version": "1.0.0",
  "bundle_id": "nestbundle_ABCDE12345FGHJKMNPQRST0123",
  "count": 1,
  "items": [
    {
      "delta_id": "nestdelta_ABCDE12345FGHJKMNPQRST0123_0001_0002",
      "from_iteration_id": "nestiter_ABCDE12345FGHJKMNPQRST0123_0001",
      "to_iteration_id":   "nestiter_ABCDE12345FGHJKMNPQRST0123_0002",
      "from_iteration_index": 1,
      "to_iteration_index":   2,
      "binary_sha256": "a1b2c3d4e5f6...",
      "confidence_delta": 23,
      "classification_changed": true,
      "signal_delta_summary": { "added_count": 3, "removed_count": 0, "unchanged_count": 7 },
      "contradiction_delta": -1,
      "refinement_execution": {
        "action_types": ["deep-echo", "expand-disasm-forward"],
        "primary_action_type": "deep-echo",
        "executed": true
      }
    }
  ]
}
```

**Delta ID format:** `nestdelta_<ULID>_<FROM_NNNN>_<TO_NNNN>`.
`from_iteration_index` must be strictly less than `to_iteration_index`.

---

## 4. Audit Refs

```json
{
  "schema_name": "nest.audit_refs",
  "schema_version": "1.0.0",
  "bundle_id": "nestbundle_ABCDE12345FGHJKMNPQRST0123",
  "session_id": "nestsession_ABCDE12345FGHJKMNPQRST0123",
  "binary_sha256": "a1b2c3d4e5f6...",
  "actor": { "id": "user:alice", "type": "user", "display_name": "Alice" },
  "policy_version": "2026-04-29.1",
  "audit_backend": "local-append-log",
  "events": [
    { "event_id": "evt_0001", "event_type": "nest.session.created",   "timestamp": "2026-04-29T16:49:00Z", "actor_id": "user:alice", "actor_type": "user", "session_id": "nestsession_...", "summary": "Session created for FlareAuthenticator.exe." },
    { "event_id": "evt_0002", "event_type": "nest.iteration.started",  "timestamp": "2026-04-29T16:49:02Z", "actor_id": "user:alice", "actor_type": "user", "session_id": "nestsession_...", "summary": "Iteration 1 started." },
    { "event_id": "evt_0003", "event_type": "nest.iteration.completed","timestamp": "2026-04-29T16:49:25Z", "actor_id": "user:alice", "actor_type": "user", "session_id": "nestsession_...", "summary": "Iteration 1 completed. confidence=64." },
    { "event_id": "evt_0004", "event_type": "nest.iteration.started",  "timestamp": "2026-04-29T16:49:25Z", "actor_id": "user:alice", "actor_type": "user", "session_id": "nestsession_...", "summary": "Iteration 2 started." },
    { "event_id": "evt_0005", "event_type": "nest.iteration.completed","timestamp": "2026-04-29T16:49:48Z", "actor_id": "user:alice", "actor_type": "user", "session_id": "nestsession_...", "summary": "Iteration 2 completed. confidence=87." },
    { "event_id": "evt_0006", "event_type": "nest.session.converged",  "timestamp": "2026-04-29T16:50:12Z", "actor_id": "user:alice", "actor_type": "user", "session_id": "nestsession_...", "summary": "Session converged at confidence-threshold." },
    { "event_id": "evt_0007", "event_type": "nest.session.exported",   "timestamp": "2026-04-29T16:51:00Z", "actor_id": "user:alice", "actor_type": "user", "session_id": "nestsession_...", "summary": "Bundle exported in local-tauri mode." }
  ]
}
```

---

## 5. Invalid Bundle Examples

Each example below deliberately violates one rule.  The expected validator output
is shown alongside.

### 5.1 Missing `bundle_id`

```json
{ "schema_name": "nest.manifest", "schema_version": "1.0.0", ... /* no bundle_id */ }
```

Expected issues:
```
[{ "path": "manifest.bundle_id", "code": "missing-field", "message": "..." }]
```

Fixture: `invalidManifestMissingBundleId`

---

### 5.2 Wrong `schema_name`

```json
{ "schema_name": "nest.wrong", ... }
```

Expected issues:
```
[{ "path": "manifest.schema_name", "code": "invalid-schema-name", ... }]
```

Fixture: `invalidManifestWrongSchemaName`

---

### 5.3 Unsupported Schema Major Version

```json
{ "schema_version": "2.0.0", ... }
```

Expected issues:
```
[{ "path": "manifest", "code": "unsupported-schema-version", ... }]
```

Fixture: `invalidManifestBadSchemaVersion`

---

### 5.4 `gyre_is_sole_verdict_source = false`

```json
"gyre_linkage": { "gyre_is_sole_verdict_source": false, ... }
```

Expected issues:
```
[{ "path": "session.gyre_linkage.gyre_is_sole_verdict_source", "code": "replay-critical-error", ... }]
```

Fixture: `makeSessionWithGyreViolation()`

---

### 5.5 `source_engine` ≠ `"gyre"`

```json
"source_engine": "nest"
```

Expected issues:
```
[{ "path": "final_verdict_snapshot.source_engine", "code": "replay-critical-error", ... }]
```

Fixture: `makeFinalVerdictWithWrongSourceEngine()`

---

### 5.6 Binary SHA-256 mismatch (cross-file)

`session.binary_sha256` uses SHA256_B while the manifest uses SHA256_A.

Expected issues:
```
[{ "path": "session", "code": "replay-critical-error", ... }]
```

Fixture: `makeSessionWithMismatchedSha256()`

---

### 5.7 Verdict snapshot ID mismatch (cross-file)

`session.gyre_linkage.verdict_snapshot_id` ≠ `final_verdict_snapshot.verdict_snapshot_id`.

Expected issues:
```
[{ "path": "final_verdict_snapshot.verdict_snapshot_id", "code": "consistency-error", ... }]
```

Fixture: `makeBundleWithVerdictSnapMismatch()`

---

### 5.8 Malformed Iteration ID

```json
{ "iteration_id": "nestiter_ABCDE12345FGHJKMNPQRST0123_01", ... }
```

The suffix `_01` has only 2 digits instead of the required 4 (`_0001`).

Expected issues:
```
[{ "path": "iterations.items[0].iteration_id", "code": "invalid-value", ... }]
```

Fixture: `makeIterationsWithMalformedId()`

---

### 5.9 `runtime_proof_required = true` but no `runtime_proof`

`session.runtime_proof_required = true` and `runtime_proof` is absent from the bundle.

Expected issues:
```
[{ "path": "runtime_proof", "code": "missing-field", ... }]
```

Fixture: `makeBundleRequiringMissingRuntimeProof()`

---

## 6. How to Use Fixtures in Tests

### Smoke test — validate bundle structure

```ts
import { validateNestEvidenceBundle } from '../../types/nestEvidence';
import { makeMinimalBundle } from '../../test/fixtures/nestEvidenceFixtures';

it('minimal bundle is valid', () => {
  expect(validateNestEvidenceBundle(makeMinimalBundle())).toHaveLength(0);
});
```

### Integration test — full bundle with runtime proof

```ts
import { makeFullBundle } from '../../test/fixtures/nestEvidenceFixtures';

it('full bundle with runtime_proof is valid', () => {
  expect(validateNestEvidenceBundle(makeFullBundle())).toHaveLength(0);
});
```

### Regression guard — replay-critical invariant

```ts
import { makeFinalVerdictWithWrongSourceEngine } from '../../test/fixtures/nestEvidenceFixtures';
import { validateNestFinalVerdictSnapshot } from '../../types/nestEvidence';

it('source_engine != gyre is always caught', () => {
  const issues = validateNestFinalVerdictSnapshot(makeFinalVerdictWithWrongSourceEngine());
  const critical = issues.filter(i => i.code === 'replay-critical-error');
  expect(critical.length).toBeGreaterThan(0);
});
```

### Import / export flow

When writing or reading a bundle from disk:

```ts
import { parseNestManifest, validateNestEvidenceBundle } from '../../types/nestEvidence';

// Reading from disk
const raw = JSON.parse(await readFile('bundle/manifest.json', 'utf-8'));
const result = parseNestManifest(raw);
if (!result.ok) {
  console.error('Manifest invalid:', result.issues);
  return;
}
const manifest = result.value;

// After assembling the full bundle object:
const bundleIssues = validateNestEvidenceBundle(bundle);
if (bundleIssues.length > 0) {
  throw new Error(`Bundle validation failed: ${JSON.stringify(bundleIssues)}`);
}
```

### Customising fixtures for edge-case tests

Every maker function accepts a `Partial<T>` override:

```ts
// Two-iteration session with minimum optional fields
const sparseSession = makeSessionRecord({ iteration_count: 1, delta_count: 0 });

// Session with a different convergence reason
const plateauSession = makeSessionRecord({
  convergence: { ...makeSessionRecord().convergence, reason: 'plateau-threshold' },
});
```

---

## 7. ID Format Reference

| Prefix | Format | Example |
|--------|--------|---------|
| `nestbundle_` | `nestbundle_<26-char ULID>` | `nestbundle_ABCDE12345FGHJKMNPQRST0123` |
| `nestsession_` | `nestsession_<26-char ULID>` | `nestsession_ABCDE12345FGHJKMNPQRST0123` |
| `nestiter_` | `nestiter_<26-char ULID>_<NNNN>` | `nestiter_ABCDE12345FGHJKMNPQRST0123_0001` |
| `nestdelta_` | `nestdelta_<26-char ULID>_<NNNN>_<NNNN>` | `nestdelta_ABCDE12345FGHJKMNPQRST0123_0001_0002` |
| `gyresnap_` | `gyresnap_<26-char ULID>` | `gyresnap_ABCDE12345FGHJKMNPQRST0123` |
| `binary_sha256_` | `binary_sha256_<64-char SHA-256>` | `binary_sha256_a1b2...` |

ULID alphabet (Crockford base-32): `0-9 A-H J K M N P-T V-Z` (excludes `I L O U`).

Hash formats: SHA-256 = 64 chars, SHA-1 = 40 chars, MD5 = 32 chars — all lowercase hex only.
