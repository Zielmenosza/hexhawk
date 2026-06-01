# HexHawk Tester Release Status

Date: 2026-06-01

## Recommendation

Internal tester candidate: YES, with caveats.

Limited external/public release: NOT YET.

## Current Build

- Product version: 1.0.0.
- Windows release executable, MSI installer, and NSIS installer were Authenticode-signed with an internal self-signed development certificate.
- Timestamp countersignature was applied to exe/MSI/NSIS.
- Packaged native GUI parity passed on the signed internal artifact via release probe: native runtime proof + Open/Inspect/Analysis/NEST/Report workflow + authority markers in exported report JSON.
- Consolidated evidence file: `docs/release-evidence/windows_release_hardening_2026-06-01_204639.json`.

## Caveats

- Signatures are internal-only and not publicly trusted (`UnknownError`: untrusted root), so this is not public-release signing posture.
- Updater signing path is enabled in config, but updater metadata endpoint validation failed in this pass because `releases.hexhawk.app` did not resolve.
- External pilot still requires organization-trusted signing + reachable updater endpoint, or explicit internal-evaluation exception.

## Validation Summary

- `yarn workspace hexhawk-ui test src/components/__tests__/IntelligenceReport.test.tsx`: passed (authority envelope regression gate).
- `powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/release/release-hardening.ps1 -UseSelfSignedDevCert`: passed with internal-signing caveat; emitted evidence JSON.
- `powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/release/run-native-parity-probe.ps1 -MsiPath ./target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi`: passed native packaged acceptance probe.

## Decompiler/TALON Status (Current Pass)

- Implemented address-consistency fix between disassembly and CFG paths to reduce false empty-decompile outcomes.
- Added fallback IR block partitioning from instruction flow for non-overlapping/sparse CFG cases.
- Enhanced call argument recovery (lookback 25 + cross-block recovery pass).
- Added first-pass semantic naming heuristics for loop counters/index/size/pointer variables.
- Added regression tests in `HexHawk/src/__tests__/decompilerRegressionRealBinaries.test.ts` including guarded real-binary checks.

## Next Gate Before External Testers

- Replace internal self-signed signer with organization-trusted certificate chain.
- Validate reachable updater metadata endpoint and platform signature fields.
- Rerun release-hardening and native parity probes on trusted-signed artifact.
- Confirm export retains GYRE sole verdict authority and validated NEST evidence bundle semantics.

## Current Installer Rebuild Note

- MSI/NSIS artifacts were regenerated in this pass from latest source.
- Tauri exits with non-zero status after bundle generation due missing `TAURI_SIGNING_PRIVATE_KEY` (updater artifact signing step).
- Internal build path currently uses a no-op sign command fallback to allow local installer bundling while signer-spawn path is being repaired.
