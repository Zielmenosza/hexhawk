# NEST Evidence Contract Status

**Last updated:** 2026-04-29
**Schema major version:** 1 (`NEST_EVIDENCE_SCHEMA_MAJOR = 1`)

---

## Summary

The NEST evidence-plane contract has been fully implemented in TypeScript and Rust,
with automated tests in both runtimes.  All 8 DTO types, per-file validators, a
cross-file bundle validator, and parse functions exist and are green.

---

## TypeScript Implementation

**File:** `HexHawk/src/types/nestEvidence.ts`

| Type | Status | Notes |
|------|--------|-------|
| `NestManifest` | ✅ implemented | Validates ID format, schema version, required files, immutability |
| `NestBinaryIdentity` | ✅ implemented | `file_bound_proof` sha256/size cross-check, identity_source enum |
| `NestSessionRecord` | ✅ implemented | GYRE linkage invariant, `nest_role` contains "enrich" check |
| `NestIterationsFile` | ✅ implemented | Unique IDs, count≡items.length, binary_sha256 per-item replay-critical check |
| `NestDeltasFile` | ✅ implemented | Unique IDs, forward index check, count≡items.length |
| `NestFinalVerdictSnapshot` | ✅ implemented | `source_engine="gyre"` invariant, `nest_linkage.gyre_is_sole_verdict_source` |
| `NestRuntimeProof` | ✅ implemented | Validated as part of bundle-level consistency |
| `NestAuditRefs` | ✅ implemented | Event timestamp RFC3339 check, actor type enum |
| `NestEvidenceBundle` | ✅ implemented | Cross-file bundle_id/session_id/binary_sha256, verdict_snap_id, orphaned delta refs, runtime_proof_required |

### Validation boundary functions

| Function | Description |
|----------|-------------|
| `validateNestManifest(m)` | Per-file validation for `manifest.json` |
| `validateNestBinaryIdentity(bi)` | Per-file validation for `binary_identity.json` |
| `validateNestSessionRecord(s)` | Per-file validation for `session.json` |
| `validateNestIterationsFile(f)` | Per-file validation for `iterations.json` |
| `validateNestDeltasFile(f)` | Per-file validation for `deltas.json` |
| `validateNestFinalVerdictSnapshot(fv)` | Per-file validation for `final_verdict_snapshot.json` |
| `validateNestRuntimeProof(rp)` | Per-file validation for `runtime_proof.json` |
| `validateNestAuditRefs(ar)` | Per-file validation for `audit_refs.json` |
| `validateNestEvidenceBundle(b)` | Cross-file consistency for assembled bundle |
| `parseNest*(raw)` | Parse unknown → `NestValidationResult<T>` for each file type |

### Issue codes

| Code | Meaning |
|------|---------|
| `missing-field` | Required field absent |
| `invalid-type` | Field present but wrong type |
| `invalid-value` | Field present and correct type but semantically invalid |
| `invalid-schema-name` | `schema_name` does not match expected value |
| `unsupported-schema-version` | Major schema version ≠ 1 |
| `consistency-error` | Cross-file value mismatch (IDs, session_id, etc.) |
| `replay-critical-error` | Violation of a replay-critical invariant (binary_sha256, GYRE sole verdict) |

### Test coverage

**File:** `HexHawk/src/types/__tests__/nestEvidence.test.ts`
**Fixtures:** `HexHawk/src/test/fixtures/nestEvidenceFixtures.ts`
**Run:** `npx vitest run src/types/__tests__/nestEvidence.test.ts`

| Test group | Tests |
|------------|-------|
| Valid round-trips | 13 |
| Missing required fields | 5 |
| Malformed ID/hash rejection | 5 |
| Schema version handling | 6 |
| Replay-critical field enforcement | 8 |
| Cross-file consistency | 10 |
| GYRE sole-verdict-source invariant | 4 |
| Actor type validation | 3 |
| Identity source validation | 2 |
| JSON parse boundaries | 5 |
| **Total** | **65 (all passing)** |

---

## Rust Implementation

**File:** `src-tauri/src/commands/nest_evidence.rs`

| Type | Status | Notes |
|------|--------|-------|
| `NestManifest` | ✅ implemented | `#[serde(deny_unknown_fields)]` |
| `NestBinaryIdentity` | ✅ implemented | `#[serde(deny_unknown_fields)]` |
| `NestSessionRecord` | ✅ implemented | `#[serde(deny_unknown_fields)]` |
| `NestIterationsFile` | ✅ implemented | `#[serde(deny_unknown_fields)]` |
| `NestDeltasFile` | ✅ implemented | `#[serde(deny_unknown_fields)]` |
| `NestFinalVerdictSnapshot` | ✅ implemented | `#[serde(deny_unknown_fields)]` |
| `NestRuntimeProof` | ✅ implemented | `#[serde(deny_unknown_fields)]` |
| `NestAuditRefs` | ✅ implemented | `#[serde(deny_unknown_fields)]` |
| `NestEvidenceBundle` | ✅ implemented | Outer wrapper; sub-objects forward-compatible |
| `validate_bundle(&NestEvidenceBundle)` | ✅ implemented | Returns `Vec<NestValidationIssue>` |

All enums use `#[serde(rename_all = "kebab-case")]` to match the JSON schema.
Sub-objects **do not** use `deny_unknown_fields` to allow forward-compatible extension.

**Rust tests:** 16 unit tests in `#[cfg(test)]` block, all passing.
**Run:** `cargo test -p hexhawk-backend nest_evidence`

---

## What Is NOT Enforced by In-Memory Validators

The following correctness properties require filesystem access or external systems
and are intentionally **out of scope** for the in-memory validators:

| Gap | Reason not enforced | Where to enforce |
|-----|--------------------|--------------------|
| Manifest `files[].sha256` vs actual file bytes on disk | Requires reading files | `nest_cli` export step, after bundle directory is written |
| `runtime_proof.linked_runtime_artifacts[].path` file existence | Requires filesystem | Tauri `nest_export_bundle` command |
| Actor authentication / identity verification | Requires auth subsystem | API gateway / Tauri stronghold |
| Policy version existence lookup | Requires policy registry | GYRE policy service |
| `binary_sha256` matches bytes of the binary file at export time | Requires file read | `nest_cli` or Tauri command at export point |
| Audit event completeness (all session lifecycle events present) | Subjective / extensible | Audit review step |

---

## Remaining Implementation Work

1. **Wire `validate_bundle` into `nest_cli` export path.**
   After the bundle directory is written, call `validate_bundle` and abort if any
   `replay-critical-error` or `missing-field` issues are found.

2. **Implement `nest_export_bundle` Tauri command.**
   Surface a `#[tauri::command]` that:
   a. Assembles the `NestEvidenceBundle` from the live session state.
   b. Calls `validate_bundle`.
   c. Writes the 8 JSON files to a timestamped output directory.
   d. Returns the `Vec<NestValidationIssue>` to the UI.

3. **File-hash verification at export.**
   After writing each file, hash the bytes and compare to `manifest.files[i].sha256`.
   This closes the last replay-critical gap listed above.

4. **Expose `validate_bundle` result in the NEST UI export modal.**
   Show issues as a blocking step before the user can confirm the export.

---

## Design Decisions and Rationale

### GYRE as sole verdict source (TypeScript literal type)

`gyre_is_sole_verdict_source` is typed as literal `true` (not `boolean`) in
TypeScript so the compiler rejects `false` without a cast.  Invalid test fixtures
use `as true` to bypass this.  In Rust it is a `bool` with runtime validation.

### Schema major version pinning

Both the TypeScript and Rust validators enforce `schema_version` major == 1.
Minor and patch versions are accepted to allow backward-compatible field additions.
A future breaking change bumps `NEST_EVIDENCE_SCHEMA_MAJOR` and the constant in both runtimes.

### Crockford base-32 ID format

IDs use the Crockford base-32 alphabet (`0-9 A-H J K M N P-T V-Z`, 32 chars, no
I/L/O/U) to avoid visual ambiguity.  All ID regex patterns are anchored.

### `deny_unknown_fields` scope

Applied only to the 8 outer file structs and the bundle wrapper — not to sub-objects.
This prevents typos in field names while allowing sub-object extension without a
schema version bump.

### `replay-critical-error` severity

`replay-critical-error` issues are separated from `consistency-error` to allow callers
to treat them as hard stops.  A `replay-critical-error` means the bundle cannot be
used to replay the session and must be rejected regardless of policy configuration.
