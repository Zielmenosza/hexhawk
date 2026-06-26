# HexHawk Tester Release Status

Date: 2026-06-26

## Recommendation

Source candidate: YES, for engineering/internal review after v1.30 Function Intelligence and v1.31 byte_counter validation.

Unsigned deployment candidate from the current source state: PENDING. A fresh release worktree build, artifact hashes, signing-status check, installer smoke, and Function Notebook/export smoke still need to pass before tagging a new unsigned deployment candidate.

Controlled external signed-tester gate: NO. Public-trusted Authenticode custody is not proven, updater metadata has not been validated against current exact artifacts, and signed-artifact native GUI/export parity has not been run.

Public release: NO.

## Current Source State

- Branch: `feature/re-workbench-core-next`.
- Function Intelligence source tag: `v1.30.0-function-intelligence-regression`.
- byte_counter clippy fix tag: `v1.31.0-byte-counter-clippy-fix`.
- Main has not yet been fast-forwarded in this docs update unless a later release-gate step reports it.
- Older June 20/21 installer evidence remains historical and must not be used as proof for current v1.30/v1.31 artifacts unless hashes match exactly.

## Current Validation Summary

Validated in this session before this docs update:

- `cargo test --workspace`: passed. Backend 85 tests passed; `nest_cli` 20 tests passed.
- `cargo clippy --workspace -- -D warnings`: passed after the byte_counter C string metadata fix.
- `npx tsc --noEmit`: passed.
- Full Vitest: passed, 59 files / 832 tests.
- `yarn build`: passed with existing Vite chunk-size/dynamic-import warnings.

## Function Intelligence Status

The current source unifies recent reverse-engineering slices into an advisory Function Intelligence workflow:

- PE import table parsing.
- Queryable xref index.
- Function-boundary recovery heuristics.
- Win32 constant semantic annotation.
- TALON pseudocode IR artefact cleanup.
- Debugger call-stack reconstruction.
- Conditional breakpoint expressions.
- Calling-convention inference.
- Canonical Function Intelligence model.
- Static/runtime debugger correlation.
- Function Intelligence JSON/Markdown export.
- Function Notebook UI and workflow wiring.
- Regression coverage for imports, calls, constants, debugger mapping, export authority fields, and forbidden verdict-field names.

Function Intelligence is advisory evidence only. It does not classify files, assign GYRE verdicts, or replace analyst review.

## Authority Boundaries

- GYRE remains the sole verdict/classification authority.
- NEST organizes and converges evidence; it does not replace GYRE.
- TALON/decompiler output is advisory reconstruction only.
- STRIKE/debugger output is runtime evidence only.
- Function Notebook exports must preserve `gyre_is_sole_verdict_authority: true`, `advisory_analysis_only: true`, and `source_evidence_per_claim: true`.

## Next Gate Before External Testers

- Fast-forward main only after docs and validation are clean.
- Build from a fresh release worktree.
- Verify exact artifact hashes and Authenticode status.
- Run MSI/NSIS installer smoke.
- Run Function Notebook / Function Intelligence export smoke.
- Configure real organization-trusted code signing before any signed/public tester claim.
- Publish updater/trust metadata only for exact validated artifacts.
