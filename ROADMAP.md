# HexHawk Roadmap

Last updated: 2026-06-02

This roadmap reflects the current HexHawk source and installer state after the controlled external signing gate check.

## Current Proven Baseline

HexHawk is an internal-tester Windows build candidate with a working native Tauri/Rust packaging path.

Validated in the current pass:

- TypeScript typecheck: passing.
- Production frontend build: passing.
- Frontend tests: 40 files / 700 tests passing.
- Rust workspace tests: 71 backend tests + 14 `nest_cli` tests passing.
- Fresh Windows release executable, MSI, and NSIS artifacts were generated after stale artifacts were removed.
- Authenticode status for the current exe/MSI/NSIS artifacts: unsigned / not digitally signed.
- Native packaged GUI report/AETHERFRAME policy parity passed against the current MSI artifact hash `78bf99874acb9419525ab3012ac36252d2f8cc7605850aa773d36cc6865ec1e4`.
- Updater key custody is now GitHub Actions repository secrets; local official-path metadata validation passes, but public-trusted Authenticode custody is absent and hosted `https://hexhawk.ke/releases/latest.json` fetches but fails expected current-artifact/signature checks.
- Consolidated current evidence files: `docs/release-evidence/unsigned_rebuild_release_truth_2026-06-02_220000.json`, `docs/release-evidence/windows_release_truth_consolidation_2026-06-02_171415.json` and `docs/release-evidence/updater_metadata_dns_repair_2026-06-02_173000.json`, `docs/release-evidence/official_updater_custody_rehearsal_2026-06-02_181500.json`, and `docs/release-evidence/official_updater_custody_validation_2026-06-02_180900.json`, `docs/release-evidence/official_release_custody_final_validation_2026-06-02_203600.json` and `docs/release-evidence/hosted_updater_metadata_validation_2026-06-02_181100.json`.
- Current native probe: `gui-evidence/report_aetherframe_policy_native_gui_probe_2026-06-02_170827.json`.

Current limitations:

- No public-trusted signature is present.
- No internal self-signed signature is present on the current target/release artifacts.
- A prior historical evidence file recorded internal self-signed signatures for older artifact hashes; it must not be treated as current artifact proof.
- Updater artifacts remain disabled for local unsigned builds (`createUpdaterArtifacts: false`).
- Updater key custody is now configured as GitHub Actions repository secrets and the official scripted path can produce updater `.sig` sidecars; hosted endpoint readiness is not current proof because hosted metadata still points at older artifact/signature hashes, and Authenticode custody is not configured.
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
- Official updater key custody is now GitHub Actions repository secrets; keep local builds disabled and use `scripts/release/build-official-windows-release.ps1` for release builds.
- Keep the configured metadata endpoint at `https://hexhawk.ke/releases/latest.json`, but replace stale hosted metadata and rerun expected artifact/signature validation before making endpoint-readiness claims.
- Continue validating platform URL/signature fields before claiming public updater readiness.

### P0 — Investor / Board Demonstration Package

Goal: make the board/investor story match current proof without overclaiming.

- Maintain `docs/INVESTOR_ONE_PAGER.md`.
- Maintain `docs/INVESTOR_DILIGENCE_BRIEF.md`.
- Maintain `docs/BOARD_UPDATE_2026-05-31.md`.
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
