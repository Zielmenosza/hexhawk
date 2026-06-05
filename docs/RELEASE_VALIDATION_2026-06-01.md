# HexHawk Release Validation (rolling status, updated 2026-06-04)

## Canonical Status

HexHawk remains a controlled internal-tester Windows candidate.

As of the June 4 docs/rebuild pass:

- Fresh target/release artifacts were generated after stale executable/MSI/NSIS outputs were deleted.
- The current exe/MSI/NSIS artifacts are `NotSigned` according to `Get-AuthenticodeSignature`.
- There is no current public-trusted signature posture.
- The no-op Tauri signing command remains removed.
- Tauri updater artifacts are disabled for local unsigned builds with `bundle.createUpdaterArtifacts: false`.
- Hosted updater metadata at `https://hexhawk.ke/releases/latest.json` fetches, but release/trust endpoints were not refreshed or validated against the June 4 rebuilt NSIS hash in this pass.
- Native packaged GUI acceptance flow was not rerun on the June 4 rebuilt MSI; previous native evidence is historical for exact older hashes.

## Current Evidence Artifacts

- Current unsigned rebuild evidence:
  - `docs/release-evidence/unsigned_installer_rebuild_2026-06-04_175600.json`

## Historical Evidence Boundary

Historical June 1-2 evidence files remain useful provenance, but they do not prove the current artifacts unless the hash matches exactly.

## Commands Executed In Current Pass

```bash
rm stale target/release executable and installer outputs
yarn typecheck
yarn build
yarn tauri:build
sha256sum target/release/hexhawk-backend.exe target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe
Get-AuthenticodeSignature <current exe/msi/nsis>
fetch https://hexhawk.ke/releases/latest.json
```

## Current Artifact SHA-256

- `target/release/hexhawk-backend.exe`
  - `cd1c3f3a43fa1d67d8ffb66890e7a9516a939207b9b6b4eb6a47cdbf6aee7431`
- `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi`
  - `a460902c47ce3a5bffae38006bad4e9938bb317ec7a9afb0c1381635ddc596a0`
- `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe`
  - `8412322cc2d5646a5b08b390825440b1dfef29fe128dc8992c0c8df844f59512`

## Current Authenticode Outcome

- `hexhawk-backend.exe`: `NotSigned`.
- `HexHawk_1.0.0_x64_en-US.msi`: `NotSigned`.
- `HexHawk_1.0.0_x64-setup.exe`: `NotSigned`.

## Updater Validation Outcome

- `src-tauri/tauri.conf.json` has:
  - `bundle.createUpdaterArtifacts: false`
  - no no-op `bundle.windows.signCommand`
  - populated `plugins.updater.pubkey`
  - `plugins.updater.endpoints[0] = https://hexhawk.ke/releases/latest.json`
- Endpoint fetch result in this pass:
  - HTTP: 200
  - Metadata JSON parsed: yes
  - Release-ready for June 4 rebuilt artifact: no; hosted artifact/signature validation was not completed and release/trust endpoints were intentionally left untouched.

## Native Acceptance Flow Outcome

Not rerun for the June 4 rebuilt artifact. Before external tester distribution, rerun the native packaged GUI probe on the exact MSI/NSIS artifact intended for testers and verify:

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
- Native GUI parity passed for exact June 4 artifact: NOT RERUN.
- Internal tester candidate: YES, with caveats.
- Controlled external signed-tester gate: NO.
- Public release candidate: NO.
