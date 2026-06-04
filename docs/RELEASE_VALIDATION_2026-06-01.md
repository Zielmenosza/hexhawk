# HexHawk Release Validation (2026-06-01)

## Canonical Status

HexHawk remains a controlled internal-tester Windows candidate.

As of the current release-truth pass:

- Fresh target/release artifacts were generated after stale artifacts were deleted.
- The current exe/MSI/NSIS artifacts are unsigned / not digitally signed according to `Get-AuthenticodeSignature`.
- There is no current public-trusted signature posture.
- The no-op Tauri signing command was removed.
- Tauri updater artifacts are disabled for local unsigned builds with `bundle.createUpdaterArtifacts: false`.
- Updater endpoint validation failed because `releases.hexhawk.app` did not resolve.
- Native packaged GUI acceptance flow passed on the exact current MSI artifact.

## Current Evidence Artifacts

- Current consolidated release evidence:
  - `docs/release-evidence/windows_release_hardening_2026-06-01_235000.json`
- Current native packaged GUI parity probe:
  - `gui-evidence/release_hardening_native_gui_probe_2026-06-01_234839.json`

## Historical Evidence Boundary

- Historical consolidated release evidence:
  - `docs/release-evidence/windows_release_hardening_2026-06-01_204639.json`
- Historical native GUI parity probe:
  - `gui-evidence/release_hardening_native_gui_probe_2026-06-01_retry.json`

That historical pass recorded internal self-signed signatures and native parity for older artifact hashes. It remains useful provenance, but it is not current proof for the freshly rebuilt artifacts listed below.

## Commands Executed In Current Pass

```bash
rm stale target/release artifacts
yarn typecheck
yarn build
yarn test --reporter=dot
cargo check --workspace
cargo test --workspace
yarn tauri:build
sha256sum target/release/hexhawk-backend.exe target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe
Get-AuthenticodeSignature <current exe/msi/nsis>
python DNS/fetch check for https://releases.hexhawk.app/releases/latest.json
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/release/run-native-parity-probe.ps1 -MsiPath ./target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi -OutputPath ./gui-evidence/release_hardening_native_gui_probe_2026-06-01_234839.json
```

## Current Artifact SHA-256

- `target/release/hexhawk-backend.exe`
  - `6e1f2521480af887f2b79efa3f302912938a46c1d1fe30f3c4cd96912691bad3`
- `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi`
  - `e0c12587befda246c39cc21e7f65ae5c36bd21abd1c9bfd74030f2626b17e220`
- `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe`
  - `3eec437b01488efc09c10e0eb3f3f88cf0f8ba9c0a5d6a09234467bee95394c6`

## Current Authenticode Outcome

- `hexhawk-backend.exe`: not digitally signed.
- `HexHawk_1.0.0_x64_en-US.msi`: not digitally signed.
- `HexHawk_1.0.0_x64-setup.exe`: not digitally signed.

## Updater Validation Outcome

- `src-tauri/tauri.conf.json` now has:
  - `bundle.createUpdaterArtifacts: false`
  - no `bundle.windows.signCommand`
  - populated `plugins.updater.pubkey`
  - `plugins.updater.endpoints[0] = https://releases.hexhawk.app/releases/latest.json`
- Endpoint metadata validation result:
  - DNS: failed
  - Fetch: failed
  - Metadata valid: false

## Native Acceptance Flow Outcome

The packaged MSI-extracted app passed:

- Native runtime proof (`hasTauriRuntime=true`, `browserMode=false`, `tauriInternalsType=object`).
- Open -> Inspect -> Run Analysis -> NEST -> Report JSON export.
- Export authority markers present:
  - `source_engine`
  - `gyre_is_sole_verdict_source`
  - `final_verdict_snapshot`
  - `nestEvidenceBundle` / `nest_evidence` status fields.

## Release Posture

- Source validated: YES.
- Artifacts built: YES.
- Artifacts signed: NO.
- Public-trusted signature: NO.
- Updater metadata valid for current hosted release hashes: NO.
- Native GUI parity passed for exact artifact: YES.
- Internal tester candidate: YES.
- Controlled external signed-tester gate: NO, blocked by absent public-trusted Authenticode custody, unsigned artifacts, stale hosted updater metadata, and no signed-artifact native GUI proof.
- Public release candidate: NO.
