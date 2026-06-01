# HexHawk Release Signing and Updater Plan

Date: 2026-06-01
Status: pipeline implemented; public-trust gap remains

## Current config facts

- `src-tauri/tauri.conf.json` has `bundle.createUpdaterArtifacts: true`.
- `src-tauri/tauri.conf.json` has `bundle.windows.signCommand` wired to `scripts/release/sign-windows-artifact.ps1`.
- `src-tauri/tauri.conf.json` has a populated `plugins.updater.pubkey`.
- `src-tauri/tauri.conf.json` updater endpoint is set to `https://releases.hexhawk.app/releases/latest.json`.
- `scripts/release/release-hardening.ps1` signs exe/MSI/NSIS, records hashes + signer/timestamp provenance, validates updater metadata endpoint, and runs native parity probe.

## Required signing outputs

| Output | Required proof |
|---|---|
| `target/release/hexhawk-backend.exe` | Authenticode signature present; signer subject, thumbprint, timestamp, and SHA-256 captured in evidence JSON. |
| `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi` | Authenticode signature present; signer subject, thumbprint, timestamp, and SHA-256 captured in evidence JSON. |
| `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe` | Authenticode signature present; signer subject, thumbprint, timestamp, and SHA-256 captured in evidence JSON. |
| Updater artifacts | Tauri updater signature generated and verified against configured public key. |

Current caveat: latest pass used an internal self-signed development certificate, so trust status is not public-trusted.

## Latest evidence

- `docs/release-evidence/windows_release_hardening_2026-06-01_204639.json`
- `gui-evidence/release_hardening_native_gui_probe_2026-06-01_204631.json`
- `docs/RELEASE_VALIDATION_2026-06-01.md`

## Authenticode checklist

1. Obtain an organization code-signing certificate appropriate for Windows distribution.
2. Store the certificate in a secure location or Windows certificate store.
3. Choose signing mechanism:
   - Tauri `bundle.windows.signCommand`, or
   - CI signing step after Tauri build.
4. Configure signing without committing secrets.
5. Include a trusted timestamp server.
6. Rebuild artifacts from a clean release build.
7. Verify with PowerShell Authenticode verification:
   - `Get-AuthenticodeSignature target/release/hexhawk-backend.exe`
   - `Get-AuthenticodeSignature target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi`
   - `Get-AuthenticodeSignature target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe`
8. Record signer, timestamp, SHA-256, and build provenance in release notes.

## Tauri updater checklist

1. Generate or recover the Tauri updater signing private key.
2. Configure secret environment for builds:
   - `TAURI_SIGNING_PRIVATE_KEY`
   - `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` if the key is password-protected
3. Put the public updater key in `plugins.updater.pubkey`.
4. Set `bundle.createUpdaterArtifacts: true` for official updater builds.
5. Ensure `plugins.updater.endpoints` points at the real release metadata service.
6. Run `yarn tauri:build`.
7. Verify updater artifact signatures and release metadata before upload.

## Do not do

- Do not commit signing keys, passwords, PFX files, or updater private keys.
- Do not fake or bypass signing for public release claims.
- Do not call artifacts signed unless Authenticode and updater verification pass.
