# HexHawk Tester Release Status

Date: 2026-06-21

## Recommendation

Unsigned deployment candidate: YES, for controlled internal testing with caveats.

Controlled external signed-tester gate: NO. Public-trusted Authenticode custody is absent, current artifacts are unsigned, hosted updater metadata was not refreshed/validated against the June 21 candidate NSIS hash, and full native export parity has not been rerun on any signed artifacts.

Public release: NO.

## Current Build

- Product version: 1.0.0.
- Current deployment-candidate source tag: `v1.9.0-unsigned-deployment-candidate-20260621` at `ad2e752` (`[STRIKE] Add IL opcode-tree pattern matching API`).
- Current local runtime artifacts under `target/release/` reflect the June 21 source state for `hexhawk-backend.exe` and `nest_cli.exe`.
- Current MSI/NSIS installer copies under `target/release/bundle/` retain the June 20 smoke-passed installer payload hashes; they are unsigned local handoff artifacts and were not rebuilt by a fresh June 21 deployment gate.
- Current MSI/NSIS artifacts are not digitally signed according to the prior Authenticode gate; no public-trusted signing has been completed.
- The previous no-op `bundle.windows.signCommand` remains removed.
- `bundle.createUpdaterArtifacts` is currently `false` for local unsigned builds.
- Hosted `https://hexhawk.ke/releases/latest.json` was not regenerated or validated for the June 21 unsigned candidate.
- Packaged native GUI launch/render smoke passed for the June 20 MSI extraction and NSIS install; full report/AETHERFRAME/NEST export parity remains a separate exact-artifact gate.
- Current release evidence file for installer smoke remains `docs/release-evidence/unsigned_deployment_candidate_2026-06-20_215102.json`; the June 21 tag is a source deployment-candidate marker after additional tested TALON/NEST/STRIKE capability commits.
- Deployment candidate tag: `v1.9.0-unsigned-deployment-candidate-20260621`.

## Current Artifact Hashes

Recorded locally on 2026-06-21 from `D:/Project/HexHawk/target/release/`; Authenticode/public signing remains unproven and treated as unsigned.

- `target/release/hexhawk-backend.exe`: `6b3e5aa60e1ebcad6a055c7dec43795834f970485dc5ddd448ec51ed5739a8af`
- `target/release/nest_cli.exe`: `c8dd7dce7e774985671087963a944f480fda239fe3e9c05843e1b03863a8d2e5`
- `target/release/WebView2Loader.dll`: `8427b1fc58ec707813e5c0a51eb5d69397bb333250a7b891be4d3b123f1e0f1c`
- `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi`: `0b6a8e885accd45b6c1633f5db79af839302d8c45311ab5d48ef4ddeefe0d14e`
- `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe`: `fae7b573054a3938bc38c7ae21f341b54a2772629526cbda1c829a663ce59c71`

## Local Artifact Custody Note

The smoke-passed June 20 MSI/NSIS installer copies are currently present under `D:/Project/HexHawk/target/release/bundle/` for local handoff convenience. They retain the hashes above and remain unsigned local artifacts. The June 21 `v1.9.0-unsigned-deployment-candidate-20260621` tag records the source state after the tested TALON/NEST/STRIKE capability sprint; a new installer deployment-candidate gate still requires a fresh release worktree and rebuild.

## Historical Evidence Boundary

Prior June 1-2, June 4, and June 20 evidence recorded tests, updater custody rehearsals, hosted metadata checks, installer smoke, and native GUI parity for earlier artifact hashes. Those files remain historical provenance and must not be used as proof for the June 21 deployment candidate unless the exact hash matches.

## Validation Summary

- TALON/NEST/STRIKE capability sprint through v1.8.0 completed and pushed before the June 21 source candidate tag.
- All discovered frontend tests at the v1.9.0 source candidate: 49 files, 758 tests passed.
- `npx tsc --noEmit`: passed at the v1.9.0 source candidate.
- `cargo test`: 85 tests passed at the v1.9.0 source candidate.
- June 21 local `sha256sum`: recorded hashes above.
- Hosted updater metadata: not refreshed/validated for this candidate.

## Decompiler/TALON Status

- Address-consistency fix between disassembly and CFG paths reduces false empty-decompile outcomes.
- Fallback IR block partitioning derives blocks from instruction flow for non-overlapping/sparse CFG cases.
- Call argument recovery includes ABI-aware recent register setup recovery for Windows x64 and SysV-style call sites.
- First-pass semantic naming heuristics cover loop counters/index/size/pointer variables.
- TALON control-flow structuring covers if/else/while/for with goto fallback for irreducible CFGs.
- TALON SSA variable coalescing produces named locals from SSA versions.
- NEST Win32/libc import prototype resolution surfaces resolved call metadata.
- TALON switch and jump-table recovery handles multi-target dispatch and same-variable equality chains.
- STRIKE IL opcode-tree matching supports nested operands, wildcards, and named bindings.
- Regression tests include guarded real-binary checks through `nest_cli`.

## Next Gate Before External Testers

- Configure real organization-trusted code signing.
- Rebuild and verify signed artifacts.
- Publish hosted release/trust metadata only for exact signed artifacts.
- Rerun native parity on the exact signed artifact intended for testers.
- Confirm export retains GYRE sole verdict authority and truthful NEST evidence-bundle status.
