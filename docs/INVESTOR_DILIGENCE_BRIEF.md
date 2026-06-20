# HexHawk Investor Diligence Brief

Date: 2026-06-20

## Executive Summary

HexHawk has reached a stronger engineering milestone: the Windows Tauri installer path builds from post-fix HEAD, all discovered frontend tests pass in a fresh release worktree, MSI extraction and NSIS install launch smokes pass, and the release caveats remain explicit. The current build is appropriate for internal/investor/board demonstration and controlled internal testing. It is not a signed public release.

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
npx vitest run --reporter=verbose <all discovered test files>
npx tsc --noEmit
yarn build
yarn tauri:build
sha256sum target/release/hexhawk-backend.exe target/release/nest_cli.exe target/release/WebView2Loader.dll target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe
Get-AuthenticodeSignature <current msi/nsis>
MSI administrative extraction + GUI smoke
NSIS silent install + payload compare + GUI smoke + uninstall
```

Observed results:

- STRIKE provenance path normalization: fixed and pushed in `e625403`.
- All discovered frontend tests: passed, 47 files / 736 tests passed / 1 skipped.
- Typecheck: passed.
- Frontend build: passed with warnings.
- Tauri release build: passed.
- MSI and NSIS installers: produced successfully.
- MSI extraction and NSIS install launch/render smoke: passed.
- Authenticode: current MSI/NSIS artifacts are `NotSigned`.
- Hosted updater metadata: not refreshed/validated against the June 20 candidate NSIS hash.
- Full native GUI export parity: not rerun on the June 20 MSI/NSIS; prior proof is historical.

## Current Artifact Hashes

Rebuilt locally on 2026-06-20 with `yarn tauri:build`; Authenticode remains `NotSigned`.

- `target/release/hexhawk-backend.exe`: `48de54c39a0f06164ac82a2a6bd5dd9439aa90b53188efbcc5caa790c0657ad1`
- `target/release/nest_cli.exe`: `d4efba77ae2df7a6fa265ff37f051389a87192d3cc7da774862110ba1c723e0a`
- `target/release/WebView2Loader.dll`: `8427b1fc58ec707813e5c0a51eb5d69397bb333250a7b891be4d3b123f1e0f1c`
- `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi`: `0b6a8e885accd45b6c1633f5db79af839302d8c45311ab5d48ef4ddeefe0d14e`
- `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe`: `fae7b573054a3938bc38c7ae21f341b54a2772629526cbda1c829a663ce59c71`

## Historical Evidence Boundary

Prior evidence files recorded test counts, native GUI parity, updater rehearsals, and signing checks for older artifact hashes. They remain provenance, but they are not current proof for the June 20 artifacts above.

## Commercial Readiness

Ready:

- Internal demonstration.
- Technical diligence walkthrough.
- Controlled local tester evaluation.
- Pilot packaging discussion with explicit unsigned/updater caveats.

Not ready until resolved:

- Signed public installer.
- Signed updater artifacts or explicitly disabled updater policy.
- Exact-artifact native GUI export parity revalidation on the artifact intended for testers.
- External support, privacy, procurement, and issue-intake process.

## Risks and Mitigations

| Risk | Status | Mitigation |
| --- | --- | --- |
| Windows SmartScreen warnings | Open | Code-sign executable/installers with organization-trusted certificate. |
| Updater distribution | Open | Publish and validate metadata only for exact official artifacts. |
| GUI parity after package extraction | Launch/render smoke current for June 20 candidate; full export parity historical | Rerun full export parity on the exact MSI/NSIS intended for release. |
| AI/verdict overclaiming | Controlled | Maintain GYRE/NEST/AETHERFRAME boundary tests/copy. |
| Enterprise procurement | Open | Prepare signing, SBOM/provenance, support docs. |

## Diligence Bottom Line

HexHawk is beyond concept stage: it builds, packages, performs file-bound workflows, and has a trust model designed to prevent AI/verdict overreach. The remaining work is release trust: real code signing, updater metadata/signing, exact-artifact native GUI proof, procurement readiness, and commercial operations.
