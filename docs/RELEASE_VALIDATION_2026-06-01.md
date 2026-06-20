# HexHawk Release Validation (rolling status, updated 2026-06-20)

## Canonical Status

HexHawk is an unsigned deployment candidate for controlled internal testing.

As of the June 20 deployment-candidate gate:

- STRIKE benchmark provenance path normalization was fixed and pushed in `e625403`.
- Fresh MSI/NSIS artifacts were generated from post-fix HEAD in a clean release worktree.
- All discovered frontend tests passed: 47 files, 736 tests passed, 1 skipped.
- `npx tsc --noEmit` passed.
- The current MSI/NSIS artifacts are `NotSigned` according to `Get-AuthenticodeSignature`.
- There is no current public-trusted signature posture.
- The no-op Tauri signing command remains removed.
- Tauri updater artifacts are disabled for local unsigned builds with `bundle.createUpdaterArtifacts: false`.
- Hosted updater metadata was not refreshed or validated against the June 20 unsigned candidate NSIS hash in this pass.
- MSI extraction and NSIS install launch/render smoke passed; full native export parity remains a separate exact-artifact gate.

## Current Evidence Artifacts

- Current unsigned deployment candidate evidence:
  - `docs/release-evidence/unsigned_deployment_candidate_2026-06-20_215102.json`

## Historical Evidence Boundary

Historical June 1-2 and June 4 evidence files remain useful provenance, but they do not prove the current artifacts unless the hash matches exactly.

## Commands Executed In Current Pass

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

## Current Artifact SHA-256

- `target/release/hexhawk-backend.exe`: `48de54c39a0f06164ac82a2a6bd5dd9439aa90b53188efbcc5caa790c0657ad1`
- `target/release/nest_cli.exe`: `d4efba77ae2df7a6fa265ff37f051389a87192d3cc7da774862110ba1c723e0a`
- `target/release/WebView2Loader.dll`: `8427b1fc58ec707813e5c0a51eb5d69397bb333250a7b891be4d3b123f1e0f1c`
- `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi`: `0b6a8e885accd45b6c1633f5db79af839302d8c45311ab5d48ef4ddeefe0d14e`
- `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe`: `fae7b573054a3938bc38c7ae21f341b54a2772629526cbda1c829a663ce59c71`

## Current Authenticode Outcome

- `HexHawk_1.0.0_x64_en-US.msi`: `NotSigned`.
- `HexHawk_1.0.0_x64-setup.exe`: `NotSigned`.

## Updater Validation Outcome

- `src-tauri/tauri.conf.json` has:
  - `bundle.createUpdaterArtifacts: false`
  - no no-op `bundle.windows.signCommand`
  - populated `plugins.updater.pubkey`
  - `plugins.updater.endpoints[0] = https://hexhawk.ke/releases/latest.json`
- Endpoint result in this pass:
  - Not refreshed or validated for the June 20 unsigned candidate.
  - Release-ready for June 20 candidate: no; hosted artifact/signature validation was not completed and release/trust endpoints were intentionally left untouched.

## Native Acceptance Flow Outcome

Launch/render smoke passed for MSI extraction and NSIS install. Before external tester distribution, rerun the full native packaged GUI probe on the exact MSI/NSIS artifact intended for testers and verify:

- Native runtime proof (`hasTauriRuntime=true`, `browserMode=false`, `tauriInternalsType=object`).
- Open -> Inspect -> Run Analysis -> NEST -> Report JSON export.
- Export authority markers present:
  - `source_engine`
  - `gyre_is_sole_verdict_source`
  - `final_verdict_snapshot`
  - truthful `nestEvidenceBundle` / `nest_evidence` status fields.

## Release Posture

- Source/package build validated in this pass: YES.
- Artifacts built: YES.
- Artifacts signed: NO.
- Public-trusted signature: NO.
- Updater metadata valid for current hosted release hashes: NO.
- Native GUI launch/render smoke passed for exact June 20 artifact: YES.
- Full native GUI export parity passed for exact June 20 artifact: NOT RERUN.
- Internal tester candidate: YES, with caveats.
- Controlled external signed-tester gate: NO.
- Public release candidate: NO.
