# HexHawk Release Signing and Updater Plan

Date: 2026-06-20
Status: unsigned deployment-candidate packaging path works; controlled external signing gate blocked because public-trusted Authenticode custody is absent and hosted updater metadata was not refreshed/validated against the June 20 candidate NSIS hash

## Current config facts

- `src-tauri/tauri.conf.json` currently has `bundle.createUpdaterArtifacts: false` for local unsigned builds.
- `src-tauri/tauri.conf.json` no longer has the no-op `bundle.windows.signCommand` value `cmd /C echo signed`.
- `src-tauri/tauri.conf.json` has a populated `plugins.updater.pubkey`.
- `src-tauri/tauri.conf.json` updater endpoint is set to `https://hexhawk.ke/releases/latest.json`.
- Hosted endpoint was not refreshed or validated against the June 20 unsigned candidate NSIS artifact.
- Current MSI/NSIS artifacts are `NotSigned` according to `Get-AuthenticodeSignature`.

## Required signing outputs

| Output | Required proof |
|---|---|
| `target/release/hexhawk-backend.exe` | Authenticode signature present; signer subject, thumbprint, timestamp, and SHA-256 captured in evidence JSON. |
| `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi` | Authenticode signature present; signer subject, thumbprint, timestamp, and SHA-256 captured in evidence JSON. |
| `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe` | Authenticode signature present; signer subject, thumbprint, timestamp, and SHA-256 captured in evidence JSON. |
| Updater artifacts | Tauri updater signature generated and verified against configured public key and reachable release metadata for exact hosted artifact hashes. |

## Latest current evidence

- `docs/release-evidence/unsigned_deployment_candidate_2026-06-20_215102.json`

## Historical evidence boundary

June 1-2 and June 4 evidence files recorded previous rebuilds, updater rehearsals, hosted metadata checks, and native GUI proof for their exact artifact hashes. They do not describe the June 20 deployment-candidate artifacts unless the hash matches exactly.

## Real Authenticode checklist

1. Obtain an organization code-signing certificate appropriate for Windows distribution.
2. Store the certificate in a secure location or Windows certificate store.
3. Choose signing mechanism:
   - Tauri `bundle.windows.signCommand` calling `scripts/release/sign-windows-artifact.ps1`, or
   - CI signing step after Tauri build.
4. Configure signing without committing secrets. The GitHub Actions Windows release job supports:
   - `HEXHAWK_CODESIGN_THUMBPRINT` when a public/organization-trusted certificate with private key is already installed on the runner;
   - `HEXHAWK_CODESIGN_PFX_BASE64` plus `HEXHAWK_CODESIGN_PFX_PASSWORD` for GitHub-hosted runners, where the workflow materializes the PFX only under `$RUNNER_TEMP`;
   - `HEXHAWK_CODESIGN_PFX_PATH` plus `HEXHAWK_CODESIGN_PFX_PASSWORD` only for controlled runners where that path already exists.
5. Include a trusted timestamp server.
6. Rebuild artifacts from a clean release build.
7. Verify with PowerShell Authenticode verification.
8. Record signer, timestamp, SHA-256, artifact sizes, and build provenance in release evidence.

## Tauri updater checklist

1. Maintain updater signing key custody in a secure official release environment.
2. Configure secret environment for official builds:
   - `TAURI_SIGNING_PRIVATE_KEY`
   - `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` if the key is password-protected
3. Keep `bundle.createUpdaterArtifacts: false` for local unsigned builds.
4. Set `bundle.createUpdaterArtifacts: true` only for official updater builds where signing keys are available.
5. Keep `plugins.updater.endpoints` pointed at `https://hexhawk.ke/releases/latest.json`, but do not claim it current-release ready until a signed release generates exact artifacts, the website-release-payload is published, and expected artifact/signature validation passes against hosted metadata.
6. Verify platform URL/signature fields before upload or release claims.

## Do not do

- Do not commit signing keys, passwords, PFX files, or updater private keys.
- Do not use a no-op sign command for release-looking builds.
- Do not call artifacts signed unless Authenticode verification passes on the exact artifacts.
- Do not call the updater path release-ready unless official release metadata is published and endpoint DNS/fetch plus metadata/signature checks pass.
