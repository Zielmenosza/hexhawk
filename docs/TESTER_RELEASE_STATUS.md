# HexHawk Tester Release Status

Date: 2026-06-04

## Recommendation

Internal tester candidate: YES, with caveats.

Controlled external signed-tester gate: NO. Public-trusted Authenticode custody is absent, current artifacts are unsigned, hosted updater metadata was not refreshed/validated against the June 4 rebuilt NSIS hash, and native proof has not been rerun on the June 4 rebuilt artifacts or any signed artifacts.

Public release: NO.

## Current Build

- Product version: 1.0.0.
- Current target/release artifacts were rebuilt on 2026-06-04 after stale local outputs were removed.
- Current target/release artifacts are not digitally signed according to `Get-AuthenticodeSignature`.
- The previous no-op `bundle.windows.signCommand` remains removed.
- `bundle.createUpdaterArtifacts` is currently `false` for local unsigned builds.
- Hosted `https://hexhawk.ke/releases/latest.json` fetches, but this pass did not publish or validate hosted release/trust endpoints against the rebuilt NSIS hash.
- Packaged native GUI report/AETHERFRAME policy parity was not rerun against the June 4 rebuilt MSI; prior proof is historical for its exact artifact hash.
- Current release evidence file: `docs/release-evidence/unsigned_installer_rebuild_2026-06-04_175600.json`.

## Current Artifact Hashes

Rebuilt locally on 2026-06-04 with `yarn tauri:build`; Authenticode remains `NotSigned`.

- `target/release/hexhawk-backend.exe`: `cd1c3f3a43fa1d67d8ffb66890e7a9516a939207b9b6b4eb6a47cdbf6aee7431`
- `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi`: `a460902c47ce3a5bffae38006bad4e9938bb317ec7a9afb0c1381635ddc596a0`
- `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe`: `8412322cc2d5646a5b08b390825440b1dfef29fe128dc8992c0c8df844f59512`

## Historical Evidence Boundary

Prior June 1-2 evidence recorded tests, updater custody rehearsals, hosted metadata checks, and native GUI parity for earlier artifact hashes. Those files remain historical provenance and must not be used as proof for the June 4 rebuilt artifacts unless the exact hash matches.

## Validation Summary

- `yarn typecheck`: passed.
- `yarn build`: passed with existing Vite warnings.
- `yarn tauri:build`: passed and produced current exe/MSI/NSIS artifacts.
- `sha256sum`/Python SHA-256: recorded hashes above.
- `Get-AuthenticodeSignature`: current artifacts are `NotSigned`.
- Hosted updater metadata fetch: HTTP 200, but not release-ready for the rebuilt artifact.
- Native GUI parity probe: not rerun for the June 4 artifact.

## Decompiler/TALON Status

- Address-consistency fix between disassembly and CFG paths reduces false empty-decompile outcomes.
- Fallback IR block partitioning derives blocks from instruction flow for non-overlapping/sparse CFG cases.
- Call argument recovery includes lookback 25 + cross-block recovery.
- First-pass semantic naming heuristics cover loop counters/index/size/pointer variables.
- Regression tests include guarded real-binary checks through `nest_cli`.

## Next Gate Before External Testers

- Configure real organization-trusted code signing.
- Rebuild and verify signed artifacts.
- Publish hosted release/trust metadata only for exact signed artifacts.
- Rerun native parity on the exact signed artifact intended for testers.
- Confirm export retains GYRE sole verdict authority and truthful NEST evidence-bundle status.
