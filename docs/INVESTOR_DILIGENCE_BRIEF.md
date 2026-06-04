# HexHawk Investor Diligence Brief

Date: 2026-06-02

## Executive Summary

HexHawk has reached a meaningful engineering milestone: the Windows Tauri installer path builds, source validation passes, and packaged native GUI parity passes on the exact current MSI artifact. The current build is appropriate for internal/investor/board demonstration and controlled internal testing. It is not a signed public release.

## Architecture

- Frontend: React + TypeScript.
- Desktop/runtime: Tauri v2.
- Backend/commands: Rust.
- CLI: `nest_cli` for headless/runtime evidence operations.
- Packaging: Windows MSI and NSIS artifacts.

## Trust Model

HexHawk’s trust hierarchy is explicit:

- GYRE: sole verdict authority.
- NEST: evidence orchestration and convergence; not verdict authority.
- AETHERFRAME/Forge: optional bounded confidence uplift/refinement/lineage; cannot change classification.
- TALON/STRIKE/ECHO: evidence and analyst surfaces.
- CREST: report packaging.
- NEXUS: assistant/consumer layer.

This prevents AI/assistant features from silently becoming security truth.

## Current Validation Evidence

Commands run in the latest pass:

```bash
yarn typecheck
yarn build
yarn test --reporter=dot
cargo check --workspace
cargo test --workspace
yarn tauri:build
sha256sum target/release/hexhawk-backend.exe target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe
Get-AuthenticodeSignature <current exe/msi/nsis>
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/release/run-native-parity-probe.ps1 -MsiPath ./target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi -OutputPath ./gui-evidence/release_hardening_native_gui_probe_2026-06-01_234839.json
```

Observed results:

- Frontend tests: 40 passed files / 700 passed tests.
- Typecheck: passed.
- Frontend build: passed.
- Rust check: passed.
- Rust tests: 85 passed backend/CLI tests.
- Tauri release build: passed.
- MSI and NSIS installers: produced successfully.
- Authenticode: current artifacts are not digitally signed.
- Native GUI parity: passed on current MSI artifact.
- Updater metadata: GitHub Actions updater-key custody is configured and local official-path metadata validation passes, but hosted `https://hexhawk.ke/releases/latest.json` validation is blocked by stale hosted metadata and Authenticode is still absent.

## Current Artifact Hashes

Rebuilt locally on 2026-06-02 21:59 UTC with `yarn tauri:build`; Authenticode remains unsigned / not digitally signed.

- `hexhawk-backend.exe`: `caeb0c39abd9854d60745ff0f407744b7da4bc05312f01d2d346259037570377`.
- `HexHawk_1.0.0_x64_en-US.msi`: `78bf99874acb9419525ab3012ac36252d2f8cc7605850aa773d36cc6865ec1e4`.
- `HexHawk_1.0.0_x64-setup.exe`: `dbbd31edf328dc85bc40176fa19b3b5220cc62b85d74d1ab2f9969944c7fd246`.

## Historical Evidence Boundary

A prior evidence file recorded internal self-signed signatures for earlier artifact hashes. It remains historical provenance, but it is not current proof for the artifacts above.

## Commercial Readiness

Ready:

- Internal demonstration.
- Technical diligence walkthrough.
- Controlled local tester evaluation.
- Pilot packaging discussion with explicit unsigned/updater caveats.

Not ready until resolved:

- Signed public installer.
- Signed updater artifacts or explicitly disabled updater policy.
- Signed-artifact native GUI export parity revalidation.
- External support, privacy, procurement, and issue-intake process.

## Risks and Mitigations

| Risk | Status | Mitigation |
| --- | --- | --- |
| Windows SmartScreen warnings | Open | Code-sign executable/installers with organization-trusted certificate. |
| Updater distribution | Open | Configure signing key and reachable release metadata endpoint. |
| GUI parity after package extraction | Pass on current unsigned MSI | Rerun on the exact signed MSI/NSIS after public-trusted Authenticode signing before external release. |
| AI/verdict overclaiming | Controlled | Maintain GYRE/NEST/AETHERFRAME boundary tests/copy. |
| Enterprise procurement | Open | Prepare signing, SBOM/provenance, support docs. |

## Diligence Bottom Line

HexHawk is beyond concept stage: it builds, tests, packages, performs real file-bound workflows, and has packaged native GUI parity evidence for runtime/workflow/report authority export. The remaining work is release trust: real code signing, updater metadata/signing, procurement readiness, and commercial operations.
