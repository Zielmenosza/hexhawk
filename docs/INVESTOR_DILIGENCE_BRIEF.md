# HexHawk Investor Diligence Brief

Date: 2026-06-04

## Executive Summary

HexHawk has reached a meaningful engineering milestone: the Windows Tauri installer path builds, source validation gates run, and the public website now presents release caveats honestly. The current build is appropriate for internal/investor/board demonstration and controlled internal testing. It is not a signed public release.

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
rm stale target/release executable and installer outputs
yarn typecheck
yarn build
yarn tauri:build
sha256sum target/release/hexhawk-backend.exe target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe
Get-AuthenticodeSignature <current exe/msi/nsis>
fetch https://hexhawk.ke/releases/latest.json
```

Observed results:

- Typecheck: passed.
- Frontend build: passed with warnings.
- Tauri release build: passed.
- MSI and NSIS installers: produced successfully.
- Authenticode: current artifacts are `NotSigned`.
- Hosted updater metadata: fetches, but was not refreshed/validated against the June 4 rebuilt NSIS hash.
- Native GUI parity: not rerun on the June 4 rebuilt MSI/NSIS; prior proof is historical.

## Current Artifact Hashes

Rebuilt locally on 2026-06-04 with `yarn tauri:build`; Authenticode remains `NotSigned`.

- `hexhawk-backend.exe`: `cd1c3f3a43fa1d67d8ffb66890e7a9516a939207b9b6b4eb6a47cdbf6aee7431`.
- `HexHawk_1.0.0_x64_en-US.msi`: `a460902c47ce3a5bffae38006bad4e9938bb317ec7a9afb0c1381635ddc596a0`.
- `HexHawk_1.0.0_x64-setup.exe`: `8412322cc2d5646a5b08b390825440b1dfef29fe128dc8992c0c8df844f59512`.

## Historical Evidence Boundary

Prior evidence files recorded test counts, native GUI parity, updater rehearsals, and signing checks for older artifact hashes. They remain provenance, but they are not current proof for the June 4 artifacts above.

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
| GUI parity after package extraction | Historical proof only for older hashes | Rerun on the exact MSI/NSIS intended for release. |
| AI/verdict overclaiming | Controlled | Maintain GYRE/NEST/AETHERFRAME boundary tests/copy. |
| Enterprise procurement | Open | Prepare signing, SBOM/provenance, support docs. |

## Diligence Bottom Line

HexHawk is beyond concept stage: it builds, packages, performs file-bound workflows, and has a trust model designed to prevent AI/verdict overreach. The remaining work is release trust: real code signing, updater metadata/signing, exact-artifact native GUI proof, procurement readiness, and commercial operations.
