# HexHawk Release Signing and Updater Plan

Date: 2026-06-02
Status: local unsigned packaging path corrected; updater key custody configured in GitHub Actions secrets; controlled external signing gate blocked because public-trusted Authenticode custody is absent and hosted updater metadata is stale against current hashes

## Current config facts

- `src-tauri/tauri.conf.json` currently has `bundle.createUpdaterArtifacts: false` for local unsigned builds.
- `src-tauri/tauri.conf.json` no longer has the no-op `bundle.windows.signCommand` value `cmd /C echo signed`.
- `src-tauri/tauri.conf.json` has a populated `plugins.updater.pubkey` for the rotated official updater key. The private key was uploaded to GitHub Actions repository secrets (`TAURI_SIGNING_PRIVATE_KEY` plus password secret) and local scratch material was removed.
- `src-tauri/tauri.conf.json` updater endpoint is set to `https://hexhawk.ke/releases/latest.json`.
- Current local generated metadata validation passes. Hosted endpoint fetch passes, but `https://hexhawk.ke/releases/latest.json` failed expected current artifact/signature checks, including the controlled-release-gate rerun in `docs/release-evidence/hosted_updater_metadata_validation_rebuilt_unsigned_2026-06-02_220500.json`.
- Current exe/MSI/NSIS artifacts are unsigned according to `Get-AuthenticodeSignature`.

## Required signing outputs

| Output | Required proof |
|---|---|
| `target/release/hexhawk-backend.exe` | Authenticode signature present; signer subject, thumbprint, timestamp, and SHA-256 captured in evidence JSON. |
| `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi` | Authenticode signature present; signer subject, thumbprint, timestamp, and SHA-256 captured in evidence JSON. |
| `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe` | Authenticode signature present; signer subject, thumbprint, timestamp, and SHA-256 captured in evidence JSON. |
| Updater artifacts | Tauri updater signature generated and verified against configured public key and reachable release metadata. |

## Latest current evidence

- `docs/release-evidence/unsigned_rebuild_release_truth_2026-06-02_220000.json`
- `docs/release-evidence/windows_release_truth_consolidation_2026-06-02_171415.json`
- `docs/release-evidence/updater_metadata_dns_repair_2026-06-02_173000.json`, `docs/release-evidence/official_updater_custody_rehearsal_2026-06-02_181500.json`, and `docs/release-evidence/official_updater_custody_validation_2026-06-02_180900.json`, `docs/release-evidence/official_release_custody_final_validation_2026-06-02_203600.json` and `docs/release-evidence/hosted_updater_metadata_validation_2026-06-02_181100.json`
- `gui-evidence/report_aetherframe_policy_native_gui_probe_2026-06-02_170827.json`

## Historical evidence boundary

`docs/release-evidence/windows_release_hardening_2026-06-01_204639.json` recorded internal self-signed signatures for earlier artifacts. It does not describe the current target/release artifacts.

## Real Authenticode checklist

1. Obtain an organization code-signing certificate appropriate for Windows distribution.
2. Store the certificate in a secure location or Windows certificate store.
3. Choose signing mechanism:
   - Tauri `bundle.windows.signCommand` calling `scripts/release/sign-windows-artifact.ps1`, or
   - CI signing step after Tauri build.
4. Configure signing without committing secrets.
5. Include a trusted timestamp server.
6. Rebuild artifacts from a clean release build.
7. Verify with PowerShell Authenticode verification.
8. Record signer, timestamp, SHA-256, artifact sizes, and build provenance in release evidence.

## Tauri updater checklist

1. Maintain the rotated official Tauri updater signing key in GitHub Actions repository secrets and keep local scratch keys out of the repository.
2. Configure secret environment for official builds:
   - `TAURI_SIGNING_PRIVATE_KEY`
   - `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` if the key is password-protected
3. Keep `bundle.createUpdaterArtifacts: false` for local unsigned builds.
4. Set `bundle.createUpdaterArtifacts: true` only for official updater builds where signing keys are available.
5. Keep `plugins.updater.endpoints` pointed at `https://hexhawk.ke/releases/latest.json`, but do not claim it current-release ready until a signed GitHub Actions release generates the exact artifacts, the website-release-payload is published, and expected artifact/signature validation passes against hosted metadata.
6. Verify platform URL/signature fields before upload or release claims.

## Do not do

- Do not commit signing keys, passwords, PFX files, or updater private keys.
- Do not use a no-op sign command for release-looking builds.
- Do not call artifacts signed unless Authenticode verification passes on the exact artifacts.
- Do not call updater ready unless official release metadata is published and endpoint DNS/fetch plus metadata/signature checks pass.
