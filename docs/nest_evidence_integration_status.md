# NEST Evidence Integration Status

Last updated: 2026-07-14

## Current milestone addendum

HexHawk 1.0.0 now carries advisory NEST lifecycle linkage in versioned project persistence and revalidates session, final iteration, final verdict, binary identity, and immutable recorded GYRE snapshot linkage during reopen and recovery. NEST remains an evidence/lifecycle layer and does not issue or override authoritative classifications. The April integration details below remain historical implementation provenance. See [`CURRENT_STATUS.md`](CURRENT_STATUS.md).

Current provenance acceptance is backend-rooted: snapshot identifiers must be issued/resolved through the recorded GYRE path. Renderer/schema markers and golden fixtures are supporting test evidence, not proof of runtime authorship. NEXUS and AETHERFRAME cannot mutate the recorded state. Missing or mismatched authority must fail or degrade explicitly, with no stale or cross-binary fallback, and reports/exports must preserve resolved-snapshot provenance.

## Scope completed in this pass

This pass wired the NEST evidence contract into practical local artifact production
and consumption paths without introducing remote API surfaces.

## What now writes the bundle

1. `HexHawk/scripts/run-nest.ts`
- Still writes legacy artifacts for compatibility:
  - `session.log`
  - `result.json`
  - `iterations.json`
- Now also emits typed evidence files under:
  - `nest_tests/<binary-name>/evidence_bundle/`
  - `manifest.json`
  - `binary_identity.json`
  - `session.json`
  - `iterations.json`
  - `deltas.json`
  - `final_verdict_snapshot.json`
  - `audit_refs.json`
  - `runtime_proof.json` (optional)

2. Write finalization behavior
- Bundle is built with DTO-aligned shapes via `buildNestEvidenceBundleFromSession(...)`.
- Bundle is validated before write via `validateBuiltNestEvidenceBundle(...)`.
- If validation fails, write finalization aborts with a detailed error sample.

## What now reads/validates the bundle

1. TypeScript consumption path
- New utility: `HexHawk/src/utils/nestEvidenceIntegration.ts`
- Read/validation flow:
  - Parse each file with existing contract parsers (`parseNest*`).
  - Compose `NestEvidenceBundle`.
  - Run `validateNestEvidenceBundle(...)` cross-file checks.
- `run-nest.ts` now performs read-back validation immediately after write.

2. Rust consumption path
- `src-tauri/src/bin/nest_cli.rs` adds:
  - `nest_cli evidence_validate <bundle_dir>`
- Command behavior:
  - Reads JSON files from bundle dir.
  - Deserializes into Rust DTOs from `commands/nest_evidence.rs`.
  - Validates via `validate_bundle(&bundle)`.
  - Emits JSON summary:
    - `ok`
    - `issues`
    - `issue_count`
    - `replay_critical_count`
  - Exits with code `2` on validation failure.

## Tests added/updated

1. Existing contract suite remains green
- `HexHawk/src/types/__tests__/nestEvidence.test.ts` (65 tests)

2. New integration suite
- `HexHawk/src/types/__tests__/nestEvidence.integration.test.ts`
- Covers:
  - End-to-end bundle generation from a simulated NEST session
  - Read-back parsing and validation of generated files
  - Malformed bundle rejection
  - Schema version mismatch handling
  - Replay-critical field preservation
  - Golden fixture compatibility via file-map parser

3. Validation command compile path
- Rust tests and compile path pass with `nest_cli` including new `evidence_validate` command.

## What is still ad hoc

1. Legacy run artifacts
- `result.json` and legacy `iterations.json` from `run-nest.ts` remain ad hoc summary files.
- They are preserved intentionally for backward compatibility with existing local workflows.

2. Manifest file-hash entries
- `manifest.files[].sha256` and `bytes` currently reflect practical placeholders in this local path.
- Full per-file byte hashing of emitted evidence JSON files is not yet implemented in this pass.

3. Replay import UX wiring
- Evidence validation is available in CLI and TypeScript utilities, but not yet surfaced in a dedicated UI import/replay workflow command.

## Next implementation step

Implement strict file-byte finalization for bundle integrity:

1. Emit all evidence files first.
2. Hash each emitted file (`sha256`) and set accurate `bytes`.
3. Rewrite `manifest.json` with those exact values.
4. Re-run validation and fail export if any mismatch remains.

This closes the remaining ad hoc gap and makes bundle replay integrity deterministic for local Tauri mode.
