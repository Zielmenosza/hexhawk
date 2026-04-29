# NEST Evidence Schema Specification

Date: 2026-04-29
Project: HexHawk
Scope: evidence contract for NEST session exports in local Tauri mode and future enterprise API mode
Status: design specification only, no implementation yet

## Purpose

This document defines the evidence-plane contract for NEST session exports.

It covers these files inside a NEST evidence bundle:
- `manifest.json`
- `binary_identity.json`
- `session.json`
- `iterations.json`
- `deltas.json`
- `final_verdict_snapshot.json`
- `runtime_proof.json`
- `audit_refs.json`
- optional `review_summary.md`

This contract exists to make NEST evidence:
- file-bound
- replayable
- attributable
- exportable
- stable across local desktop mode and future API/service mode

This contract does **not** make NEST the verdict authority. GYRE remains the sole verdict source.

---

## 1. Bundle Model

A NEST evidence bundle is a directory or archive containing the files listed above.

Minimum required files for a valid bundle:
- `manifest.json`
- `binary_identity.json`
- `session.json`
- `iterations.json`
- `deltas.json`
- `final_verdict_snapshot.json`
- `audit_refs.json`

Conditionally required file:
- `runtime_proof.json`
  Required when the session was executed through a runtime-backed UI workflow and the product claims runtime-backed NEST fidelity for that session.

Optional file:
- `review_summary.md`

A bundle is valid only if:
1. every required file exists
2. every file hash listed in `manifest.json` matches the actual file bytes
3. all cross-file IDs link correctly
4. `binary_sha256` is identical everywhere it appears
5. `session_id` is identical everywhere it appears

---

## 2. Stable IDs and Hashes

### 2.1 Stable IDs

These IDs are stable within a bundle and must not be regenerated once exported.

#### `bundle_id`
- Required
- Type: string
- Format: `nestbundle_<ulid>`
- Stability: immutable for the lifetime of the bundle
- Purpose: identifies the exported evidence package

#### `session_id`
- Required
- Type: string
- Format: `nestsession_<ulid>`
- Stability: immutable for the lifetime of the NEST session
- Purpose: primary key for the NEST session

#### `iteration_id`
- Required per iteration
- Type: string
- Format: `nestiter_<session_ulid>_<zero_padded_index>`
- Example: `nestiter_01JSC..._0003`
- Stability: immutable once the iteration completes
- Purpose: stable handle for a single iteration snapshot

#### `delta_id`
- Required per delta
- Type: string
- Format: `nestdelta_<session_ulid>_<from_index>_<to_index>`
- Example: `nestdelta_01JSC..._0002_0003`
- Stability: immutable once generated
- Purpose: stable handle for an iteration-to-iteration delta

#### `binary_id`
- Required
- Type: string
- Format: `binary_sha256_<lowercase_sha256>`
- Stability: derived from bytes, therefore immutable
- Purpose: canonical file identity reference

#### `verdict_snapshot_id`
- Required
- Type: string
- Format: `gyresnap_<ulid>`
- Stability: immutable once exported
- Purpose: identifies the linked GYRE snapshot included in the bundle

#### `actor_id`
- Required
- Type: string
- Format: implementation-defined stable identity string
- Examples:
  - `user:alice`
  - `reviewer:daniel`
  - `service-account:nest-regression-bot`
- Stability: must represent the same principal across all bundle files

#### `policy_version`
- Required
- Type: string
- Format: semantic or dated version string
- Examples:
  - `2026-04-29.1`
  - `1.3.0`
- Stability: immutable for a session once created

#### `engine_build_id`
- Required
- Type: string
- Format: build identity string
- Recommended format: `<app-version>+<git-sha>`
- Example: `0.1.0+1a2b3c4d`
- Stability: immutable for the binary that produced the session

### 2.2 Hashes

Required hash algorithms for `binary_identity.json`:
- `sha256` required
- `sha1` required
- `md5` required

Required hash algorithm for bundle file integrity:
- `sha256` only

Hash rules:
- all hex hashes are lowercase
- hashes cover raw file bytes exactly
- `manifest.json` stores hashes for all other bundle files
- `manifest.json` may optionally include a self-hash field, but if present it must be excluded from its own hash calculation rules and documented by implementation

---

## 3. Schema Versioning Rules

### 3.1 File-level schema version

Every JSON file in the bundle must contain:
- `schema_name` required
- `schema_version` required

Example:
```json
{
  "schema_name": "nest.session",
  "schema_version": "1.0.0"
}
```

### 3.2 Compatibility rules

Versioning uses semantic versioning:
- major: breaking field changes
- minor: backward-compatible field additions
- patch: clarification or constraint tightening with no structural change

Compatibility rules:
- exporters may add optional fields only in minor or patch versions
- exporters must not rename or remove required fields without a major version bump
- importers/replayers must ignore unknown fields
- importers/replayers must reject unsupported major versions

### 3.3 Bundle version

`manifest.json` must contain:
- `bundle_schema_version` required
- `bundle_format_version` required

These represent the overall evidence bundle contract, separate from per-file schema versions.

---

## 4. Immutability Expectations

NEST evidence bundles are immutable after export.

Rules:
- `manifest.json` is immutable after export
- `iterations.json` is append-only during an active session, immutable after export
- `deltas.json` is append-only during an active session, immutable after export
- `session.json` may transition from `running` to `completed` before export; immutable after export
- `final_verdict_snapshot.json` is immutable after export
- `audit_refs.json` may reference an external append-only log; the reference file itself is immutable after export
- `review_summary.md` is the only file allowed to be added after the initial technical bundle export, but if added later the bundle must be re-exported as a new `bundle_id` or recorded as a reviewed derivative bundle

A bundle must never be silently edited in place.

If any content changes after export:
- create a new `bundle_id`
- preserve the original `session_id`
- record `derived_from_bundle_id` in the new `manifest.json`

---

## 5. Replay Requirements

A bundle is replayable only if it contains enough information to reproduce NEST session reasoning against the same bytes and configuration.

Required replay inputs:
- binary identity and hash set
- session config
- engine build id
- policy version
- iteration sequence
- executed refinement actions
- final GYRE linkage snapshot

Replay modes:

### 5.1 Local replay
- uses local file bytes referenced by `binary_identity.json`
- may rely on `original_path` if still available
- must verify `sha256` before replay begins

### 5.2 Imported replay
- uses bytes from an imported object store, evidence archive, or API-uploaded sample
- must verify `binary_sha256` before replay begins
- must not trust path strings alone

### 5.3 Deterministic replay expectation
- identical file bytes + identical session config + compatible engine build should reproduce materially equivalent NEST session structure
- minor non-determinism is acceptable only if the exporter explicitly marks a field as non-deterministic
- classification and GYRE linkage must not drift silently under the same build and policy version

Replay blockers must be explicit:
- `binary_not_found`
- `binary_hash_mismatch`
- `unsupported_schema_major`
- `unsupported_engine_build`
- `missing_required_artifact`
- `policy_version_unavailable`

---

## 6. Shared Common Field Definitions

These fields recur across multiple files.

### Required common fields
- `schema_name`: string
- `schema_version`: string
- `bundle_id`: string
- `session_id`: string
- `binary_id`: string
- `binary_sha256`: string
- `engine_build_id`: string
- `policy_version`: string
- `actor`: object
- `timestamps`: object

### Actor object

Required fields:
- `actor.id`: string
- `actor.type`: string enum
  Allowed values:
  - `user`
  - `reviewer`
  - `approver`
  - `service-account`
  - `system`

Optional fields:
- `actor.display_name`: string
- `actor.tenant_id`: string
- `actor.team_id`: string
- `actor.auth_subject`: string

### Timestamps object

Required fields:
- `timestamps.created_at`: RFC 3339 UTC string

Optional fields depending on file:
- `timestamps.started_at`
- `timestamps.completed_at`
- `timestamps.exported_at`
- `timestamps.reviewed_at`

---

## 7. File Specifications

## 7.1 `manifest.json`

Purpose:
- top-level bundle descriptor
- lists contents, hashes, compatibility, and immutability metadata

Required fields:
- `schema_name`: `nest.manifest`
- `schema_version`: string
- `bundle_schema_version`: string
- `bundle_format_version`: string
- `bundle_id`: string
- `session_id`: string
- `binary_id`: string
- `binary_sha256`: string
- `engine_build_id`: string
- `policy_version`: string
- `actor`: object
- `timestamps`: object
- `files`: array
- `immutability`: object
- `replay`: object

Optional fields:
- `derived_from_bundle_id`: string
- `export_mode`: enum `local-tauri` | `api` | `service` | `cli`
- `notes`: string

`files[]` entry required fields:
- `name`: string
- `required`: boolean
- `sha256`: string
- `bytes`: integer
- `schema_name`: string
- `schema_version`: string

`files[]` entry optional fields:
- `content_type`: string
- `optional_reason`: string

`immutability` required fields:
- `bundle_locked`: boolean
- `locked_at`: RFC 3339 UTC string
- `mutation_policy`: string

`replay` required fields:
- `replayable`: boolean
- `mode_supported`: array of strings
- `requires_binary_bytes`: boolean

Example file list names:
- `binary_identity.json`
- `session.json`
- `iterations.json`
- `deltas.json`
- `final_verdict_snapshot.json`
- `runtime_proof.json`
- `audit_refs.json`
- `review_summary.md`

Immutability rule:
- `manifest.json` is authoritative for bundle contents and must be generated last

---

## 7.2 `binary_identity.json`

Purpose:
- canonical binary identity and file-bound proof root

Required fields:
- `schema_name`: `nest.binary_identity`
- `schema_version`
- `bundle_id`
- `session_id`
- `binary_id`
- `binary_sha256`
- `hashes`: object
- `file_size_bytes`: integer
- `format`: string
- `architecture`: string
- `first_seen_at`: RFC 3339 UTC string
- `identity_source`: string enum
  Allowed values:
  - `local-path`
  - `dropped-file`
  - `imported-object`
  - `api-upload`
  - `corpus-entry`
- `file_bound_proof`: object

Optional fields:
- `original_path`: string
- `normalized_path`: string
- `corpus_entry_id`: string
- `import_object_id`: string
- `file_name`: string
- `source_host`: string

`hashes` required fields:
- `sha256`
- `sha1`
- `md5`

`file_bound_proof` required fields:
- `proof_status`: enum `proven` | `partial` | `not-available`
- `proof_basis`: array of strings
- `binary_sha256`: string
- `file_size_bytes`: integer

`file_bound_proof` optional fields:
- `runtime_proof_present`: boolean
- `session_hash_lock`: boolean
- `validation_notes`: array of strings

Embedding rule:
- the exact `binary_sha256` from this file must be repeated in `session.json`, each iteration row, each delta row, `final_verdict_snapshot.json`, and `runtime_proof.json` when present

---

## 7.3 `session.json`

Purpose:
- top-level NEST session record

Required fields:
- `schema_name`: `nest.session`
- `schema_version`
- `bundle_id`
- `session_id`
- `binary_id`
- `binary_sha256`
- `engine_build_id`
- `policy_version`
- `actor`
- `timestamps`
- `status`: enum `created` | `running` | `completed` | `failed` | `cancelled`
- `execution_mode`: enum `local-tauri` | `cli` | `api` | `service`
- `config`: object
- `iteration_count`: integer
- `delta_count`: integer
- `final_iteration_index`: integer or null
- `convergence`: object
- `gyre_linkage`: object

Optional fields:
- `error`: object
- `review_state`: object
- `notes`: array of strings
- `runtime_proof_required`: boolean

`config` required fields:
- `config_version`: string
- `max_iterations`: integer
- `min_iterations`: integer
- `confidence_threshold`: number
- `plateau_threshold`: number
- `disasm_expansion`: integer
- `aggressiveness`: string
- `enable_talon`: boolean
- `enable_strike`: boolean
- `enable_echo`: boolean
- `auto_advance`: boolean
- `auto_advance_delay_ms`: integer

`convergence` required fields:
- `has_converged`: boolean
- `reason`: string
- `confidence`: number
- `classification_stable`: boolean
- `signal_delta`: integer
- `contradiction_burden`: integer
- `stability_score`: number

`convergence` optional fields:
- `projected_loss`: number
- `confidence_variance`: number
- `diagnosis`: string

`gyre_linkage` required fields:
- `verdict_snapshot_id`: string
- `gyre_schema_version`: string
- `gyre_build_id`: string
- `gyre_is_sole_verdict_source`: boolean, must be `true`
- `nest_role`: string, must describe enrichment only

`gyre_linkage` optional fields:
- `gyre_summary`: string
- `linked_reasoning_chain_hash`: string

Rule:
- `session.json` must never imply that NEST emitted the final classification independently of GYRE

---

## 7.4 `iterations.json`

Purpose:
- immutable ledger of completed iteration snapshots in execution order

Top-level required fields:
- `schema_name`: `nest.iterations`
- `schema_version`
- `bundle_id`
- `session_id`
- `binary_id`
- `binary_sha256`
- `count`: integer
- `items`: array

Each `items[]` row required fields:
- `iteration_id`: string
- `iteration_index`: integer, 1-based
- `session_id`: string
- `binary_sha256`: string
- `started_at`: RFC 3339 UTC string
- `completed_at`: RFC 3339 UTC string
- `duration_ms`: integer
- `input_window`: object
- `executed_actions`: array
- `verdict_snapshot`: object
- `convergence_snapshot`: object
- `file_identity_locked`: boolean

Each `items[]` row optional fields:
- `annotations`: array
- `warnings`: array of strings
- `tool_inputs`: object
- `runtime_context_ref`: string

`input_window` required fields:
- `offset`: integer
- `length`: integer

`executed_actions[]` required fields:
- `type`: string
- `priority`: string
- `reason`: string

`executed_actions[]` optional fields:
- `offset`: integer
- `length`: integer
- `signal`: string

`verdict_snapshot` required fields:
- `classification`: string
- `confidence`: number
- `threat_score`: number
- `signal_count`: integer
- `contradiction_count`: integer
- `reasoning_chain_hash`: string

`verdict_snapshot` optional fields:
- `summary`: string
- `behavior_tags`: array of strings
- `negative_signal_count`: integer

`convergence_snapshot` required fields:
- `reason`: string
- `has_converged`: boolean
- `stability_score`: number
- `classification_stable`: boolean
- `signal_delta`: integer
- `contradiction_burden`: integer

Immutability rule:
- iteration rows are append-only while a session runs
- after export, `iterations.json` is immutable

---

## 7.5 `deltas.json`

Purpose:
- explicit iteration-to-iteration change ledger

Top-level required fields:
- `schema_name`: `nest.deltas`
- `schema_version`
- `bundle_id`
- `session_id`
- `binary_id`
- `binary_sha256`
- `count`: integer
- `items`: array

Each `items[]` row required fields:
- `delta_id`: string
- `from_iteration_id`: string
- `to_iteration_id`: string
- `from_iteration_index`: integer
- `to_iteration_index`: integer
- `binary_sha256`: string
- `confidence_delta`: number
- `classification_changed`: boolean
- `signal_delta_summary`: object
- `contradiction_delta`: integer
- `refinement_execution`: object
- `projected_gain`: number
- `actual_gain`: number

Each `items[]` row optional fields:
- `new_signal_ids`: array of strings
- `removed_signal_ids`: array of strings
- `new_behavior_tags`: array of strings
- `warnings`: array of strings
- `tool_runtime_inputs`: object

`signal_delta_summary` required fields:
- `added_count`: integer
- `removed_count`: integer
- `unchanged_count`: integer

`refinement_execution` required fields:
- `action_types`: array of strings
- `primary_action_type`: string or null
- `executed`: boolean

`refinement_execution` optional fields:
- `primary_action_reason`: string
- `target_offsets`: array of integers

Rule:
- `deltas.json` is the authoritative source for change between iterations
- consumers must not recompute deltas from `iterations.json` if `deltas.json` exists and validates

---

## 7.6 `final_verdict_snapshot.json`

Purpose:
- frozen GYRE-linked final output associated with the NEST session

Required fields:
- `schema_name`: `nest.final_verdict_snapshot`
- `schema_version`
- `bundle_id`
- `session_id`
- `binary_id`
- `binary_sha256`
- `verdict_snapshot_id`
- `source_engine`: string, must be `gyre`
- `gyre_build_id`: string
- `gyre_schema_version`: string
- `classification`: string
- `confidence`: number
- `threat_score`: number
- `summary`: string
- `signal_count`: integer
- `contradiction_count`: integer
- `reasoning_chain_hash`: string
- `linked_iteration_id`: string
- `nest_linkage`: object

Optional fields:
- `behaviors`: array
- `negative_signals`: array
- `amplifiers`: array
- `dismissals`: array
- `contradictions`: array
- `alternatives`: array
- `certainty_profile`: object

`nest_linkage` required fields:
- `session_id`: string
- `final_iteration_id`: string
- `nest_enrichment_applied`: boolean
- `gyre_is_sole_verdict_source`: boolean, must be `true`

`nest_linkage` optional fields:
- `nest_summary`: string
- `enriched_signal_ids`: array of strings

GYRE linkage rule:
- this file is where the bundle formally states that GYRE produced the final verdict
- NEST contribution is represented as enrichment and linkage metadata only

---

## 7.7 `runtime_proof.json`

Purpose:
- binds a NEST session executed through the UI/runtime path to a real runtime-backed evidence source

Required when:
- the session was initiated through Tauri runtime UI workflows and the export claims runtime-backed proof

Optional when:
- session was CLI-only or service-only and no runtime UI path was involved

Required fields when present:
- `schema_name`: `nest.runtime_proof`
- `schema_version`
- `bundle_id`
- `session_id`
- `binary_id`
- `binary_sha256`
- `runtime_mode`: enum `tauri-runtime` | `api-runtime` | `service-runtime`
- `proof_status`: enum `proven` | `partial` | `failed`
- `has_tauri_runtime`: boolean
- `browser_mode`: boolean
- `source_fidelity`: object
- `linked_runtime_artifacts`: array

Optional fields:
- `run_id`: string
- `page_url`: string
- `notes`: array of strings
- `nest_runtime_fields`: object

`source_fidelity` required fields:
- `panel_fidelity_source`: string
- `qa_subsystem_statuses`: array

`linked_runtime_artifacts[]` required fields:
- `path`: string
- `artifact_type`: string

Embedding rule:
- `runtime_proof.json` must repeat the same `binary_sha256` proven in `binary_identity.json`
- if runtime proof cannot verify the current binary identity, the file must declare `proof_status: failed` instead of being silently omitted when runtime proof was expected

---

## 7.8 `audit_refs.json`

Purpose:
- links the bundle to append-only audit records without requiring the full audit log to be embedded

Required fields:
- `schema_name`: `nest.audit_refs`
- `schema_version`
- `bundle_id`
- `session_id`
- `binary_id`
- `binary_sha256`
- `actor`
- `policy_version`
- `audit_backend`: string
- `events`: array

Optional fields:
- `log_stream_id`: string
- `tenant_id`: string
- `retention_policy_id`: string
- `integrity_proof`: object

Each `events[]` row required fields:
- `event_id`: string
- `event_type`: string
- `timestamp`: RFC 3339 UTC string
- `actor_id`: string
- `actor_type`: string
- `session_id`: string

Each `events[]` row optional fields:
- `external_ref`: string
- `hash`: string
- `summary`: string

Recommended minimum event types:
- `nest.session.created`
- `nest.iteration.started`
- `nest.iteration.completed`
- `nest.session.converged`
- `nest.session.exported`

Optional governance event types:
- `nest.corpus.entry.proposed`
- `nest.corpus.entry.approved`
- `nest.policy.override.requested`
- `nest.policy.override.approved`
- `nest.review.completed`

Rule:
- `audit_refs.json` references audit truth; it does not replace the append-only audit log

---

## 7.9 `review_summary.md`

Purpose:
- human-readable reviewer or approver narrative

Status:
- optional
- never authoritative over the JSON evidence files

Expected sections:
- session overview
- reviewer findings
- approval decision
- unresolved risks
- export notes

If present, the file must be listed in `manifest.json` with its hash and size.

---

## 8. Required vs Optional Matrix

### Always required
- `manifest.json`
- `binary_identity.json`
- `session.json`
- `iterations.json`
- `deltas.json`
- `final_verdict_snapshot.json`
- `audit_refs.json`

### Conditionally required
- `runtime_proof.json`
  Required if the session claims runtime-backed fidelity or was executed through a runtime UI flow that produced runtime evidence

### Always optional
- `review_summary.md`

---

## 9. Representation of Actor Identity, Policy Version, and Build ID

### Actor identity

Actor identity must be embedded in:
- `manifest.json`
- `session.json`
- `audit_refs.json`

It may be repeated in:
- `runtime_proof.json`
- iteration rows when per-iteration ownership differs in future multi-actor workflows

Representation:
```json
{
  "actor": {
    "id": "service-account:nest-regression-bot",
    "type": "service-account",
    "display_name": "NEST Regression Bot",
    "tenant_id": "acme",
    "team_id": "re-lab"
  }
}
```

### Policy version

`policy_version` must be embedded in:
- `manifest.json`
- `session.json`
- `audit_refs.json`

It may be repeated in:
- `final_verdict_snapshot.json`

This version identifies the rules in force for:
- run authorization
- approval requirements
- export behavior
- replay enforcement

### Build ID

`engine_build_id` must identify the NEST-producing build.

`gyre_build_id` must identify the GYRE-producing build when different.

Build IDs must be embedded in:
- `manifest.json`
- `session.json`
- `final_verdict_snapshot.json`

---

## 10. File-Bound Proof Embedding Rules

File-bound proof must be embedded at three levels.

### Level 1: canonical identity
- `binary_identity.json` is the root of binary identity truth

### Level 2: session lock
- `session.json` repeats `binary_sha256` and states that the session is bound to that identity

### Level 3: per-iteration enforcement
- every iteration row in `iterations.json` repeats `binary_sha256`
- every delta row in `deltas.json` repeats `binary_sha256`
- `runtime_proof.json` repeats `binary_sha256` when present

Validation rule:
- if any repeated `binary_sha256` differs from `binary_identity.json`, the bundle is invalid

Session continuation rule:
- implementations must stop the session if file identity changes mid-session
- such a stop must be recorded explicitly as a failure, not silently corrected

---

## 11. GYRE Linkage Representation

NEST must never claim verdict ownership.

The linkage model is:
- NEST produces iterative enrichment
- GYRE produces the final verdict snapshot
- the evidence bundle records both and how they relate

Required representation:
- `session.json.gyre_linkage`
- `final_verdict_snapshot.json.source_engine = "gyre"`
- `final_verdict_snapshot.json.nest_linkage.gyre_is_sole_verdict_source = true`

Recommended language:
- use `nest_enrichment_applied`
- use `linked_iteration_id`
- do not use fields like `nest_final_verdict` or `nest_classification_authority`

---

## 12. Practicality Rules for Local Tauri Mode and Future API Mode

### Local Tauri mode

Allowed:
- `original_path`
- runtime artifact paths
- local actor IDs
- local export mode `local-tauri`

Required:
- all core JSON files still use stable IDs and hashes
- path strings are never treated as sufficient identity

### Future enterprise API mode

Allowed:
- object-store IDs instead of local paths
- tenant/team-scoped actor fields
- external audit references
- service-account actors
- API export mode `api` or `service`

Required:
- same stable file names
- same top-level bundle structure
- same `session_id`, `binary_sha256`, `policy_version`, and `engine_build_id` semantics

Portability rule:
- a bundle exported in local Tauri mode must remain importable by a future API consumer
- a bundle exported by a future service must remain readable by the desktop client

---

## 13. Validation Rules

A schema-compliant bundle must pass these checks:

1. required files present
2. per-file `schema_name` and `schema_version` present
3. `bundle_id` consistent across all files
4. `session_id` consistent across all files
5. `binary_sha256` consistent across all files
6. file hashes in `manifest.json` match actual bytes
7. every `iteration_id` unique
8. every `delta_id` unique
9. every delta references valid iteration IDs
10. `final_verdict_snapshot.json.source_engine` equals `gyre`
11. `gyre_is_sole_verdict_source` equals `true`
12. if `runtime_proof.json` exists, it links back to the same binary identity and session id

---

## 14. Non-Goals

This schema does not define:
- transport protocol details for the future API
- database schema for the future session or corpus registry
- cryptographic signing implementation
- UI rendering model for reviewer workflows
- runtime harness implementation details

Those belong to later implementation documents.

---

## 15. Contract Statement

This schema is the NEST evidence contract.

If HexHawk exports a NEST evidence bundle that conforms to this specification, a reviewer must be able to answer:
- what binary was analyzed
- who ran the session
- under what policy and build
- what happened on each iteration
- what changed between iterations
- what GYRE concluded
- whether runtime proof exists
- where the audit trail lives
- whether the bundle is intact and replayable

Without relying on renderer state, screenshots, or informal explanation.