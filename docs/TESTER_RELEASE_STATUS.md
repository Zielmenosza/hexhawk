# HexHawk Tester Release Status

Date: 2026-06-02

## Recommendation

Internal tester candidate: YES, with caveats.

Controlled external signed-tester gate: NO. Public-trusted Authenticode custody is absent, current artifacts are unsigned, hosted updater metadata is stale against current artifact/signature hashes, and native proof has not been rerun on signed artifacts.

Public release: NO.

## Current Build

- Product version: 1.0.0.
- Current target/release artifacts were rebuilt in this pass after stale artifacts were removed.
- Current target/release artifacts are not digitally signed according to `Get-AuthenticodeSignature`.
- The previous no-op `bundle.windows.signCommand` (`cmd /C echo signed`) was removed.
- `bundle.createUpdaterArtifacts` is currently `false` for local unsigned builds.
- Local generated updater metadata validation passes for the official custody path; hosted `https://hexhawk.ke/releases/latest.json` fetches, but failed expected current artifact/signature checks and is not current endpoint proof. Rerun evidence: `docs/release-evidence/hosted_updater_metadata_validation_rebuilt_unsigned_2026-06-02_220500.json`.
- Updater signing key custody is present in GitHub Actions repository secrets (`TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`); Authenticode code-signing secrets (`HEXHAWK_CODESIGN_THUMBPRINT` or `HEXHAWK_CODESIGN_PFX_PATH`/`HEXHAWK_CODESIGN_PFX_PASSWORD`) are not present. Hosted metadata publication/update is not current proof because the live endpoint still serves older artifact/signature hashes.
- Packaged native GUI report/AETHERFRAME policy parity passed against the exact current MSI artifact.
- Current release evidence files: `docs/release-evidence/unsigned_rebuild_release_truth_2026-06-02_220000.json`, `docs/release-evidence/windows_release_truth_consolidation_2026-06-02_171415.json` and `docs/release-evidence/updater_metadata_dns_repair_2026-06-02_173000.json`, `docs/release-evidence/official_updater_custody_rehearsal_2026-06-02_181500.json`, and `docs/release-evidence/official_updater_custody_validation_2026-06-02_180900.json`, `docs/release-evidence/official_release_custody_final_validation_2026-06-02_203600.json` and `docs/release-evidence/hosted_updater_metadata_validation_2026-06-02_181100.json`.
- Current native GUI policy evidence: `gui-evidence/report_aetherframe_policy_native_gui_probe_2026-06-02_170827.json`.

## Current Artifact Hashes

Rebuilt locally on 2026-06-02 21:59 UTC with `yarn tauri:build`; Authenticode remains unsigned / not digitally signed.

- `target/release/hexhawk-backend.exe`: `caeb0c39abd9854d60745ff0f407744b7da4bc05312f01d2d346259037570377`
- `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi`: `78bf99874acb9419525ab3012ac36252d2f8cc7605850aa773d36cc6865ec1e4`
- `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe`: `dbbd31edf328dc85bc40176fa19b3b5220cc62b85d74d1ab2f9969944c7fd246`

## Historical Evidence Boundary

Prior evidence in `docs/release-evidence/windows_release_hardening_2026-06-01_204639.json` recorded internal self-signed Authenticode signatures and native packaged GUI parity for older artifact hashes. That evidence is historical and must not be used to describe the current target/release artifacts.

## Validation Summary

- `yarn typecheck`: passed.
- `yarn build`: passed.
- `yarn test --reporter=dot`: passed, 40 files / 700 tests.
- `cargo check --workspace`: passed with warnings.
- `cargo test --workspace`: passed, 71 backend tests + 14 `nest_cli` tests.
- `yarn tauri:build`: passed and produced current exe/MSI/NSIS artifacts.
- `sha256sum`: recorded hashes above.
- `Get-AuthenticodeSignature`: current artifacts are not digitally signed.
- Local updater metadata validation: passed for generated official-custody metadata. Hosted endpoint validation: fetch passed, but expected current artifact/signature checks failed, including the controlled-release-gate rerun.
- Native GUI parity probe: passed on current MSI.

## Decompiler/TALON Status

- Address-consistency fix between disassembly and CFG paths reduces false empty-decompile outcomes.
- Fallback IR block partitioning derives blocks from instruction flow for non-overlapping/sparse CFG cases.
- Call argument recovery includes lookback 25 + cross-block recovery.
- First-pass semantic naming heuristics cover loop counters/index/size/pointer variables.
- Regression tests include guarded real-binary checks through `nest_cli`.

## Next Gate Before External Testers

- Configure real organization-trusted code signing.
- Rebuild and verify signed artifacts.
- Add real public-trusted Authenticode custody to the release runner or GitHub secrets, then run a real GitHub Actions tag release with updater and Authenticode secrets, publish the generated website-release-payload, validate hosted metadata against exact hashes, and rerun native GUI proof before treating external tester distribution as ready.
- Rerun native parity on the signed artifact intended for testers.
- Confirm export retains GYRE sole verdict authority and truthful NEST evidence-bundle status.
