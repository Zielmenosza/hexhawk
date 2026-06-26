# HexHawk Roadmap

Last updated: 2026-06-26

This roadmap reflects the current HexHawk source state after the v1.30 Function Intelligence integration and v1.31 byte_counter clippy fix. It does not claim a fresh packaged deployment candidate until the release worktree, artifact, signing-status, installer-smoke, and Function Notebook export gates pass.

## Current Proven Baseline

HexHawk is a validated source candidate on `feature/re-workbench-core-next`. The current branch adds a coherent Function Intelligence layer over recent reverse-engineering foundations.

Validated in this session before docs:

- Rust workspace tests: passed, 85 backend tests + 20 `nest_cli` tests.
- `cargo clippy --workspace -- -D warnings`: passed after the byte_counter C string metadata fix.
- TypeScript `npx tsc --noEmit`: passed.
- Full frontend Vitest: passed, 59 files / 832 tests.
- Production frontend build: passed with existing Vite chunk/import warnings.

Completed source capabilities through v1.30/v1.31:

- v1.17.0 PE import table parsing.
- v1.18.0 queryable xref index.
- v1.19.0 function-boundary recovery heuristics.
- v1.20.0 Win32 constant semantic annotation.
- v1.21.0 TALON pseudocode IR artefact cleanup.
- v1.22.0 debugger call-stack reconstruction.
- v1.23.0 conditional breakpoint expressions.
- v1.24.0 calling-convention inference per function.
- v1.25.0 canonical Function Intelligence model and builder.
- v1.26.0 static/runtime debugger correlation.
- v1.27.0 Function Intelligence JSON and Markdown export.
- v1.28.0 Function Notebook UI.
- v1.29.0 Function Notebook workflow wiring.
- v1.30.0 Function Intelligence regression corpus.
- v1.31.0 byte_counter clippy metadata fix.

Current limitations:

- No public-trusted signature is proven on current artifacts.
- No updater-ready claim is made for this source state.
- Fresh packaged native GUI/export parity for Function Notebook still requires the deployment-candidate gate.
- Function Intelligence is advisory evidence only; it does not classify files or replace GYRE.

## Trust Hierarchy That Must Not Drift

1. GYRE owns final classification and base confidence.
2. NEST orchestrates and converges evidence; it does not become verdict authority.
3. AETHERFRAME/Forge may add bounded uplift/lineage/refinement metadata, but must not change GYRE classification.
4. CREST packages evidence and reports.
5. NEXUS consumes/assists and must not compute verdict truth.

## Near-Term Priorities

### P0 — Fresh v1.30/v1.31 unsigned deployment gate

Goal: prove the exact packaged artifacts from the current source state before any deployment-candidate tag.

- Build from a fresh release worktree.
- Rerun Rust, TypeScript, Vitest, production build, and Tauri build.
- Hash backend, CLI, MSI, NSIS, and WebView2Loader artifacts.
- Verify Authenticode status.
- Run MSI/NSIS smoke and Function Notebook JSON/Markdown export smoke.

Exit criteria:

- All gate steps pass on exact artifacts, or the candidate is reported failed without tagging.

### P0 — Real signing path

Goal: move from unsigned local/internal artifacts to a controlled signed internal tester candidate.

- Configure organization-trusted Windows code signing.
- Wire signing through `scripts/release/sign-windows-artifact.ps1` or a CI signing step.
- Rebuild MSI/NSIS artifacts from a clean tree.
- Verify Authenticode status on executable and installers.
- Record hashes, signer, timestamp, and trust-chain status in a new evidence JSON.

Exit criteria:

- Signed executable and installers.
- Hashes published.
- Signed-artifact native GUI export parity regenerated and passing or honestly documented.

### P0 — Updater metadata and signing

Goal: avoid updater overclaims until endpoint and signing are real.

- Keep updater artifacts disabled for local unsigned builds.
- Use the official release custody script only when updater signing key custody is present.
- Keep the configured metadata endpoint at `https://hexhawk.ke/releases/latest.json`, but replace stale hosted metadata and rerun expected artifact/signature validation before making endpoint-readiness claims.
- Continue validating platform URL/signature fields before upload or release claims.

### P0 — Investor / Board Demonstration Package

Goal: make the board/investor story match current proof without overclaiming.

- Maintain `docs/INVESTOR_ONE_PAGER.md`.
- Maintain `docs/INVESTOR_DILIGENCE_BRIEF.md`.
- Maintain `docs/BOARD_UPDATE_2026-05-31.md` or supersede it with a dated board update.
- Keep website copy aligned with current build, validation, licensing, signing, and updater status.

Exit criteria:

- Docs and website present HexHawk as internal-tester ready, not broadly public-release ready.
- Validation counts and artifact caveats match current command output.

### P1 — Native GUI artifact proof discipline

Goal: prove the exact packaged desktop GUI artifact intended for testers.

- Hash the MSI first.
- Run native GUI parity against that exact MSI.
- Prove `hasTauriRuntime: true`, `browserMode: false`, and native internals present.
- Run Open -> Inspect -> Analysis -> NEST -> Export.
- Compare exported report against authority-envelope expectations.

## Deferred / Backlog

- Full procurement-ready enterprise controls.
- Hosted team collaboration and server-side audit store.
- Full updater infrastructure.
- Additional external challenge/regression corpora.
- Broader platform packaging beyond Windows.
