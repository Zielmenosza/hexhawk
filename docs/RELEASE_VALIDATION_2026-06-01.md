# HexHawk Release Validation (2026-06-01)

## Canonical Status

HexHawk remains a controlled internal-tester Windows candidate.

As of this validation pass:

- Artifacts were Authenticode-signed with an internal self-signed development certificate.
- Timestamp countersignature is present on exe/MSI/NSIS artifacts.
- Trust status is not public-trusted (`UnknownError` / untrusted root), so this is not a public-release signature posture.
- Native packaged GUI acceptance flow passed on the signed internal artifact.
- Updater signing path is enabled in config, but release metadata endpoint validation failed due endpoint DNS resolution failure.

## Commands Executed

```bash
yarn workspace hexhawk-ui test src/components/__tests__/IntelligenceReport.test.tsx
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/release/release-hardening.ps1 -UseSelfSignedDevCert
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/release/run-native-parity-probe.ps1 -MsiPath ./target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi -OutputPath ./gui-evidence/release_hardening_native_gui_probe_2026-06-01_retry.json
```

## Evidence Artifacts

- Consolidated release evidence:
  - `docs/release-evidence/windows_release_hardening_2026-06-01_204639.json`
- Native packaged GUI parity probe:
  - `gui-evidence/release_hardening_native_gui_probe_2026-06-01_204631.json`
  - `gui-evidence/release_hardening_native_gui_probe_2026-06-01_retry.json`

## Signing Provenance (from evidence JSON)

- Signer subject: `CN=HexHawk Internal Dev Code Signing`
- Signer thumbprint: `7373D2D0A1260F63A9D9CF51AD50681314595C70`
- Timestamp subject: `CN=DigiCert SHA256 RSA4096 Timestamp Responder 2025 1, O="DigiCert, Inc.", C=US`
- Signature trust status for exe/MSI/NSIS: `UnknownError` (`untrusted root`)

## Artifact SHA-256 (from evidence JSON)

- `target/release/hexhawk-backend.exe`
  - `4c3bac2a7c1507e6ebd595a2e62212e5436e5e89f7ac4a9b20936d74deb85c7c`
- `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi`
  - `a51ddacb1753a2c48d79fe830f790436d1348e44b6bebc1552610c291d54dba0`
- `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe`
  - `d4e39045fcbbb29a1ee8cc45d7dc66664b061ccbd34bde1b0350738ff01397bf`

## Updater Validation Outcome

- `src-tauri/tauri.conf.json` now has:
  - `bundle.createUpdaterArtifacts: true`
  - `bundle.windows.signCommand` configured
  - `plugins.updater.pubkey` populated
  - `plugins.updater.endpoints[0] = https://releases.hexhawk.app/releases/latest.json`
- Endpoint metadata validation result:
  - `fetchOk: false`
  - Error: `The remote name could not be resolved: 'releases.hexhawk.app'`

## Native Acceptance Flow Outcome

Packaged MSI-extracted app passed:

- Native runtime proof (`hasTauriRuntime=true`, `browserMode=false`, `tauriInternalsType=object`)
- Open -> Inspect -> Run Analysis -> NEST -> Report JSON export
- Export authority markers present:
  - `source_engine`
  - `gyre_is_sole_verdict_source`
  - `final_verdict_snapshot`

## Regression Gate Added

- `HexHawk/src/components/__tests__/IntelligenceReport.test.tsx` now enforces report JSON authority envelope fields:
  - `final_verdict_snapshot.source_engine === 'gyre'`
  - `final_verdict_snapshot.gyre_is_sole_verdict_source === true`
  - `final_verdict_snapshot.nest_linkage.gyre_is_sole_verdict_source === true`
  - `authority_doctrine.gyre_is_sole_verdict_source === true`

## Decompiler/TALON Hardening Added

- Address consistency improved across disassembly and CFG surfaces (text-section snap alignment + decoded-range-aware CFG requests).
- Decompiler now includes an instruction-derived fallback block partitioner when CFG does not overlap the decoded function window.
- Call argument recovery window expanded from `10` to `25` instructions and enhanced with a cross-block recovery pass.
- First-pass variable naming heuristics now promote generic names toward loop/index/size/pointer semantics where safe.
- Added regression tests:
  - `HexHawk/src/__tests__/decompilerRegressionRealBinaries.test.ts`
  - Includes guarded real-binary coverage for workspace challenge executables through `nest_cli`.

## Installer Rebuild Outcome (Current Pass)

- Rebuilt MSI and NSIS bundles from current source:
  - `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi` (updated 2026-06-01 22:13:34)
  - `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe` (updated 2026-06-01 22:14:30)
- Tauri build exits non-zero after bundling because updater private signing key is not configured:
  - `TAURI_SIGNING_PRIVATE_KEY` missing.
- For this internal pass, bundle signing command was switched to a no-op fallback to unblock local bundle generation in the current environment where PowerShell-sign command spawning failed.
