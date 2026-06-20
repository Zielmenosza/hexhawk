# HexHawk Pilot Readiness Checklist

Date: 2026-06-20
Status: controlled external signing gate blocked; unsigned deployment candidate tagged; public-trusted Authenticode custody is absent; hosted updater endpoint was not refreshed for the candidate hash
Current classification: unsigned deployment candidate for controlled internal testing
Market readiness: controlled only; not broad public release

## Stage definitions

| Stage | Meaning | Current status |
|---|---|---|
| Internal tester candidate | Source validates, artifacts build, caveats documented. | PASS with unsigned/updater/full-export-parity caveats |
| Controlled external pilot candidate | Native workflow proven and support intake ready; signing/updater constraints accepted or fixed. | NO for the stronger signed external-tester gate |
| Signed public release | Windows executable, MSI, NSIS, and updater artifacts are signed and verified with publicly trusted chain. | FAIL / not proven |
| Enterprise/procurement-ready release | Signed artifacts, update policy, support SLA, procurement docs, security questionnaire, and rollback plan complete. | NOT READY |

## Release-hardening gate status

| Gate | Status | Evidence | Next action |
|---|---|---|---|
| TypeScript typecheck | PASS | `npx tsc --noEmit` passed in June 20 gate. | Keep required. |
| Production frontend build | PASS | `yarn build` passed with warnings. | Keep required. |
| Rust/Tauri package build | PASS | `yarn tauri:build` rebuilt MSI and NSIS from post-fix HEAD. | Keep required. |
| Artifact hashes | PASS | See `docs/release-evidence/unsigned_deployment_candidate_2026-06-20_215102.json`. | Publish only after signed release artifacts and matching hosted metadata are generated. |
| Authenticode signing | FAIL | Current artifacts are `NotSigned`. | Configure real signing. |
| Updater metadata | NOT READY | Endpoint was not refreshed/validated against the June 20 unsigned candidate NSIS hash. | Publish only after signed release artifacts and website-release-payload are generated. |
| Packaged native GUI runtime | PASS FOR LAUNCH/RENDER | MSI extraction and NSIS install launch/render smoke passed for June 20 candidate. | Repeat full export parity for every signed/external artifact. |
| Report authority export | HISTORICAL PROOF ONLY | Prior JSON exports preserved GYRE authority markers; June 20 gate did not rerun export parity. | Rerun on exact current artifact before external tester release. |
| External support intake | DOC READY | See `docs/PILOT_SUPPORT_AND_INTAKE.md`. | Assign owner and response windows. |

## Current decision

HexHawk is suitable as an unsigned deployment candidate for controlled internal testing with explicit caveats. It is not suitable for the stronger controlled external signed-tester gate until real public-trusted Authenticode custody is configured, a release produces signed artifacts, hosted updater metadata matches the exact release hashes, and full native export parity is rerun on the exact signed MSI/NSIS. It is not a public release candidate.
