# HexHawk Investor Diligence Brief

Date: 2026-05-31

## Executive Summary

HexHawk has reached a meaningful engineering milestone: the Windows Tauri installer path now builds successfully after repairing the WebView2 installer configuration. The current build is appropriate for internal/investor/board demonstration and controlled testing. It is not yet a signed public release.

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
yarn test --reporter=dot
yarn typecheck && yarn build && cargo check --workspace && cargo test --workspace
yarn tauri:build
sha256sum target/release/hexhawk-backend.exe target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe
msiexec.exe /a HexHawk_1.0.0_x64_en-US.msi /qn TARGETDIR=<extract-dir>
nest_cli.exe identify D:/Project/HexHawk/Challenges/ch76/keygenme.exe
```

Observed results:

- Frontend tests: 38 passed files / 683 passed tests.
- Typecheck: passed.
- Frontend build: passed.
- Rust check: passed.
- Rust tests: 85 passed backend/CLI tests.
- Tauri release build: passed.
- MSI and NSIS installers: produced successfully.
- Authenticode: not signed.
- MSI extraction: passed.
- Extracted CLI smoke: passed on a real PE sample.

## Artifact Hashes

- `hexhawk-backend.exe`: `aec86545b821cc42482d092857c4238fcf5ac23ffdde10119808964f25161677`.
- `HexHawk_1.0.0_x64_en-US.msi`: `8bf30818bbaff55b92037f716d1290f434d09b033f841257d970381f5c0870a4`.
- `HexHawk_1.0.0_x64-setup.exe`: `69378677d84d67fa96eccf6ee5be949c89ef98fa7f2e412e67fbbc503226b6dc`.

## Commercial Readiness

Ready:

- Internal demonstration.
- Technical diligence walkthrough.
- Controlled local tester evaluation.
- Pilot packaging discussion.

Not ready until resolved:

- Signed public installer.
- Signed updater artifacts.
- Signed-artifact native GUI export parity revalidation.
- External support, privacy, procurement, and issue-intake process.

## Risks and Mitigations

| Risk | Status | Mitigation |
| --- | --- | --- |
| Windows SmartScreen warnings | Open | Code-sign executable/installers |
| Updater distribution | Open | Configure signing key and re-enable updater artifacts |
| GUI parity after package extraction | Repaired / pass on unsigned tester artifact | Rerun on signed artifact before external release |
| AI/verdict overclaiming | Controlled | Maintain GYRE/NEST/AETHERFRAME boundary tests/copy |
| Enterprise procurement | Open | Prepare signing, SBOM/provenance, support docs |

## Diligence Bottom Line

HexHawk is beyond concept stage: it builds, tests, packages, extracts, performs real file-bound CLI analysis, and now has packaged native GUI parity evidence for runtime/workflow/report authority export. The remaining work is release hardening, signing, updater trust, and commercial operations.
