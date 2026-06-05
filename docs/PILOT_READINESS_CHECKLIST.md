# HexHawk Pilot Readiness Checklist

Date: 2026-06-04
Status: controlled external signing gate blocked; local unsigned package rebuild present; public-trusted Authenticode custody is absent; hosted updater endpoint was not refreshed for the rebuilt hash
Current classification: internal-tester Windows product candidate
Market readiness: controlled only; not broad public release

## Stage definitions

| Stage | Meaning | Current status |
|---|---|---|
| Internal tester candidate | Source validates, artifacts build, caveats documented. | PASS with unsigned/updater/native-proof caveats |
| Controlled external pilot candidate | Native workflow proven and support intake ready; signing/updater constraints accepted or fixed. | NO for the stronger signed external-tester gate |
| Signed public release | Windows executable, MSI, NSIS, and updater artifacts are signed and verified with publicly trusted chain. | FAIL / not proven |
| Enterprise/procurement-ready release | Signed artifacts, update policy, support SLA, procurement docs, security questionnaire, and rollback plan complete. | NOT READY |

## Release-hardening gate status

| Gate | Status | Evidence | Next action |
|---|---|---|---|
| TypeScript typecheck | PASS | `yarn typecheck` passed in June 4 pass. | Keep required. |
| Production frontend build | PASS | `yarn build` passed with warnings. | Keep required. |
| Rust/Tauri package build | PASS | `yarn tauri:build` rebuilt release exe, MSI, and NSIS. | Keep required. |
| Artifact hashes | PASS | See `docs/release-evidence/unsigned_installer_rebuild_2026-06-04_175600.json`. | Publish only after signed release artifacts and matching hosted metadata are generated. |
| Authenticode signing | FAIL | Current artifacts are `NotSigned`. | Configure real signing. |
| Updater metadata | NOT READY | Endpoint fetches but was not refreshed/validated against the rebuilt NSIS hash. | Publish only after signed release artifacts and website-release-payload are generated. |
| Packaged native GUI runtime | NOT CURRENT FOR JUNE 4 HASHES | Prior proof exists for older exact artifact hashes. | Repeat for every rebuilt/signed artifact. |
| Report authority export | HISTORICAL PROOF ONLY | Prior JSON exports preserved GYRE authority markers. | Rerun on exact current artifact before external tester release. |
| External support intake | DOC READY | See `docs/PILOT_SUPPORT_AND_INTAKE.md`. | Assign owner and response windows. |

## Current decision

HexHawk remains suitable for internal tester use with explicit unsigned-artifact caveats. It is not suitable for the stronger controlled external signed-tester gate until real public-trusted Authenticode custody is configured, a release produces signed artifacts, hosted updater metadata matches the exact release hashes, and native GUI proof is rerun on the exact signed MSI/NSIS. It is not a public release candidate.
