# HexHawk Roadmap

Last updated: 2026-06-01

This roadmap reflects the current HexHawk source and installer state after the Windows installer rebuild.

## Current Proven Baseline

HexHawk is an internal-tester Windows build candidate with a working native Tauri/Rust packaging path.

Validated in the latest pass:

- Report export authority regression test: passing (`IntelligenceReport` JSON envelope fields).
- Windows release executable, MSI, and NSIS artifacts: Authenticode-signed with an internal self-signed development certificate.
- Timestamp countersignature: present on exe/MSI/NSIS artifacts.
- Native packaged GUI parity probe: passing (`hasTauriRuntime: true`, `browserMode: false`, workflow through report export).
- Consolidated evidence file: `docs/release-evidence/windows_release_hardening_2026-06-01_204639.json`.

Current limitations:

- Internal signing trust only: Authenticode status is `UnknownError` because the signer chain terminates at an untrusted root.
- Updater path is enabled in config, but endpoint metadata validation failed in this pass (`releases.hexhawk.app` DNS resolution failure).
- Public-release distribution and procurement posture remain pending.

## Trust Hierarchy That Must Not Drift

1. GYRE owns final classification and base confidence.
2. NEST orchestrates and converges evidence; it does not become verdict authority.
3. AETHERFRAME/Forge may add bounded uplift/lineage/refinement metadata, but must not change GYRE classification.
4. CREST packages evidence and reports.
5. NEXUS consumes/assists and must not compute verdict truth.

## Near-Term Priorities

### P0 — Signed Internal Tester Build

Goal: move from unsigned local build to a controlled signed internal tester candidate.

- Replace internal self-signed development certificate with organization-trusted code-signing certificate.
- Keep updater signing artifacts enabled and validate against reachable production metadata endpoint.
- Rebuild MSI/NSIS artifacts.
- Verify Authenticode status on executable and installers.
- Run install, launch, CLI smoke, and native GUI export parity against installed/extracted artifacts.

Exit criteria:

- Signed executable and installers.
- Hashes published.
- Installed-artifact native GUI export parity regenerated and passing or honestly documented.

### P0 — Investor / Board Demonstration Package

Goal: make the board/investor story match current proof without overclaiming.

- Maintain `docs/INVESTOR_ONE_PAGER.md`.
- Maintain `docs/INVESTOR_DILIGENCE_BRIEF.md`.
- Maintain `docs/BOARD_UPDATE_2026-05-31.md`.
- Keep website copy aligned with current build, validation, licensing, and signing status.

Exit criteria:

- Docs and website present HexHawk as internal-tester ready, not broadly public-release ready.
- Validation counts and artifact caveats match current command output.

### P1 — Native GUI Installed-Artifact Proof

Goal: prove the packaged desktop GUI, not only source/dev build paths.

- Install or extract current MSI/NSIS artifacts.
- Launch real native Tauri/WebView2 runtime.
- Prove `hasTauriRuntime: true`, `browserMode: false`, and native internals present.
- Run Open → Inspect → Strings → Disassembly → GYRE/NEST → Export.
- Compare exported report against runtime evidence bundle semantics.

### P1 — Distribution and Support Readiness

- Publish signed checksums.
- Document installer warnings and troubleshooting.
- Finalize support mailbox/process.
- Decide pricing and pilot terms.
- Prepare paid pilot onboarding workflow.

## Deferred / Backlog

- Full procurement-ready enterprise controls.
- Hosted team collaboration and server-side audit store.
- Full updater infrastructure.
- Additional external challenge/regression corpora.
- Broader platform packaging beyond Windows.
