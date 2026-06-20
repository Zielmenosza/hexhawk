# HexHawk Tester Release Status

Date: 2026-06-20

## Recommendation

Unsigned deployment candidate: YES, for controlled internal testing with caveats.

Controlled external signed-tester gate: NO. Public-trusted Authenticode custody is absent, current artifacts are unsigned, hosted updater metadata was not refreshed/validated against the June 20 candidate NSIS hash, and full native export parity has not been rerun on any signed artifacts.

Public release: NO.

## Current Build

- Product version: 1.0.0.
- Current artifacts were rebuilt on 2026-06-20 from post-fix HEAD `e625403`.
- Current MSI/NSIS artifacts are not digitally signed according to `Get-AuthenticodeSignature`.
- The previous no-op `bundle.windows.signCommand` remains removed.
- `bundle.createUpdaterArtifacts` is currently `false` for local unsigned builds.
- Hosted `https://hexhawk.ke/releases/latest.json` was not regenerated or validated for the June 20 unsigned candidate.
- Packaged native GUI launch/render smoke passed for MSI extraction and NSIS install; full report/AETHERFRAME/NEST export parity remains a separate exact-artifact gate.
- Current release evidence file: `docs/release-evidence/unsigned_deployment_candidate_2026-06-20_215102.json`.
- Deployment candidate tag: `v1.2.0-unsigned-deployment-candidate-20260620`.

## Current Artifact Hashes

Rebuilt locally on 2026-06-20 with `yarn tauri:build`; Authenticode remains `NotSigned`.

- `target/release/hexhawk-backend.exe`: `48de54c39a0f06164ac82a2a6bd5dd9439aa90b53188efbcc5caa790c0657ad1`
- `target/release/nest_cli.exe`: `d4efba77ae2df7a6fa265ff37f051389a87192d3cc7da774862110ba1c723e0a`
- `target/release/WebView2Loader.dll`: `8427b1fc58ec707813e5c0a51eb5d69397bb333250a7b891be4d3b123f1e0f1c`
- `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi`: `0b6a8e885accd45b6c1633f5db79af839302d8c45311ab5d48ef4ddeefe0d14e`
- `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe`: `fae7b573054a3938bc38c7ae21f341b54a2772629526cbda1c829a663ce59c71`

## Historical Evidence Boundary

Prior June 1-2 and June 4 evidence recorded tests, updater custody rehearsals, hosted metadata checks, and native GUI parity for earlier artifact hashes. Those files remain historical provenance and must not be used as proof for the June 20 deployment candidate unless the exact hash matches.

## Validation Summary

- STRIKE provenance fix targeted test: passed.
- All discovered frontend tests: 47 files passed, 736 tests passed, 1 skipped.
- `npx tsc --noEmit`: passed.
- `yarn build`: passed with existing Vite warnings.
- `yarn tauri:build`: passed and produced current MSI/NSIS artifacts.
- `sha256sum`: recorded hashes above.
- `Get-AuthenticodeSignature`: current MSI/NSIS artifacts are `NotSigned`.
- MSI extraction and NSIS silent-install GUI smoke: passed.
- Hosted updater metadata: not refreshed/validated for this candidate.

## Decompiler/TALON Status

- Address-consistency fix between disassembly and CFG paths reduces false empty-decompile outcomes.
- Fallback IR block partitioning derives blocks from instruction flow for non-overlapping/sparse CFG cases.
- Call argument recovery includes ABI-aware recent register setup recovery for Windows x64 and SysV-style call sites.
- First-pass semantic naming heuristics cover loop counters/index/size/pointer variables.
- Regression tests include guarded real-binary checks through `nest_cli`.

## Next Gate Before External Testers

- Configure real organization-trusted code signing.
- Rebuild and verify signed artifacts.
- Publish hosted release/trust metadata only for exact signed artifacts.
- Rerun native parity on the exact signed artifact intended for testers.
- Confirm export retains GYRE sole verdict authority and truthful NEST evidence-bundle status.
