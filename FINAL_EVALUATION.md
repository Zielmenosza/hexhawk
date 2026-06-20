# HexHawk Current Evaluation

Date: 2026-06-20

## Executive Summary

HexHawk has a working unsigned Windows deployment-candidate path for controlled internal testing. The June 20 gate proves the post-GYRE-call-argument and STRIKE-provenance-fix HEAD builds MSI/NSIS artifacts, passes all discovered frontend tests, launches from both MSI-extracted and NSIS-installed payloads, and retains explicit unsigned-build caveats.

This is not a signed public release. It is suitable for board/investor demonstration, technical diligence, and controlled internal testing with explicit unsigned-build and updater caveats. Full signed-artifact export parity and hosted updater validation remain future gates.

## Verified Engineering Status

Latest validated results recorded in `docs/release-evidence/unsigned_deployment_candidate_2026-06-20_215102.json`:

- STRIKE benchmark provenance path normalization: fixed in `e625403`.
- Frontend tests: 47 files passed; 736 tests passed; 1 skipped.
- Frontend typecheck: passing.
- Frontend production build: passing with existing Vite warnings.
- Tauri Windows release build: passing with existing Rust warnings.
- MSI artifact: produced successfully.
- NSIS artifact: produced successfully.
- Current Authenticode status: MSI and NSIS artifacts are `NotSigned`.
- MSI extraction GUI smoke: passed; HexHawk onboarding UI rendered.
- NSIS silent-install GUI smoke: passed; `WebView2Loader.dll` was present with the expected DLL hash; HexHawk onboarding UI rendered; uninstall succeeded.
- Hosted updater metadata: not regenerated or validated for this unsigned deployment candidate.
- Native packaged GUI parity: launch/render smoke passed for both installers; full Open -> Inspect -> NEST -> Export authority parity remains a separate exact-artifact gate.

## Current Build Artifacts

Current artifacts rebuilt locally on 2026-06-20 from `e625403`:

- Release executable: `target/release/hexhawk-backend.exe`.
- CLI: `target/release/nest_cli.exe`.
- Runtime loader: `target/release/WebView2Loader.dll`.
- MSI: `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi`.
- NSIS: `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe`.

Current hashes:

- `hexhawk-backend.exe`: `48de54c39a0f06164ac82a2a6bd5dd9439aa90b53188efbcc5caa790c0657ad1`.
- `nest_cli.exe`: `d4efba77ae2df7a6fa265ff37f051389a87192d3cc7da774862110ba1c723e0a`.
- `WebView2Loader.dll`: `8427b1fc58ec707813e5c0a51eb5d69397bb333250a7b891be4d3b123f1e0f1c`.
- `HexHawk_1.0.0_x64_en-US.msi`: `0b6a8e885accd45b6c1633f5db79af839302d8c45311ab5d48ef4ddeefe0d14e`.
- `HexHawk_1.0.0_x64-setup.exe`: `fae7b573054a3938bc38c7ae21f341b54a2772629526cbda1c829a663ce59c71`.

## Product Assessment

Strengths:

- Strong local-first desktop architecture.
- Evidence-first reverse-engineering workflow.
- GYRE/NEST/AETHERFRAME authority boundaries are explicit and testable.
- Native Windows installer build path is working; current MSI and NSIS launch smokes passed.
- Rust CLI and packaged GUI evidence discipline exist for controlled internal testing.
- Public website copy now presents release/trust caveats without claiming public readiness.

Remaining gaps:

- Current artifacts are unsigned and will trigger Windows trust warnings.
- No current internal self-signed signature is present; prior self-signed evidence applies only to older artifact hashes.
- Local unsigned builds keep updater artifacts disabled.
- Hosted updater metadata must be refreshed and revalidated against exact official artifacts before endpoint-readiness claims.
- Full exact-artifact GUI export parity must be rerun for every signed/public tester artifact; June 20 launch/render smoke is current for installer health only.
- Public download/payment/support operations need final release-process proof.

## Conclusion

HexHawk is credible for controlled internal testing, investor/board demonstration, and technical diligence with explicit caveats. The next release-readiness step is not stronger marketing language; it is public-trusted code signing, current hosted updater validation, signed-artifact native GUI parity proof, and a clean external tester release process.
