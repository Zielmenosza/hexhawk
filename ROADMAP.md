# HexHawk Roadmap

Last updated: 2026-06-20

This roadmap reflects the current HexHawk source, documentation, and local installer state after the June 20 STRIKE provenance fix and unsigned deployment-candidate gate.

## Current Proven Baseline

HexHawk is an internal-tester Windows build candidate with a working native Tauri/Rust packaging path.

Validated in the June 20 deployment-candidate gate:

- STRIKE benchmark report provenance path normalization: fixed and committed.
- All discovered frontend tests: passing in a fresh release worktree (47 files, 736 passed, 1 skipped).
- TypeScript `npx tsc --noEmit`: passing.
- Production frontend build: passing, with existing Vite chunk/import warnings.
- Windows Tauri release build: passing, with existing Rust warnings.
- Fresh Windows MSI and NSIS artifacts were generated from post-fix HEAD `e625403`.
- Authenticode status for the rebuilt MSI/NSIS artifacts: `NotSigned`.
- MSI extraction GUI smoke: passed and rendered HexHawk onboarding UI.
- NSIS silent install GUI smoke: passed, included the real `WebView2Loader.dll`, and uninstalled cleanly.
- Current evidence file: `docs/release-evidence/unsigned_deployment_candidate_2026-06-20_215102.json`.
- Deployment candidate tag: `v1.2.0-unsigned-deployment-candidate-20260620`.

Current limitations:

- No public-trusted signature is present.
- No internal self-signed signature is present on the current target/release artifacts.
- Updater artifacts remain disabled for local unsigned builds (`createUpdaterArtifacts: false`).
- Hosted updater metadata was not regenerated/published for the June 20 unsigned candidate and must be validated against exact official signed artifacts before endpoint-readiness claims.
- Public-release distribution and procurement posture remain pending.

## Trust Hierarchy That Must Not Drift

1. GYRE owns final classification and base confidence.
2. NEST orchestrates and converges evidence; it does not become verdict authority.
3. AETHERFRAME/Forge may add bounded uplift/lineage/refinement metadata, but must not change GYRE classification.
4. CREST packages evidence and reports.
5. NEXUS consumes/assists and must not compute verdict truth.

## Near-Term Priorities

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
