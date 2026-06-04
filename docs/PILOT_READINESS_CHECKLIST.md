# HexHawk Pilot Readiness Checklist

Date: 2026-06-02
Status: controlled external signing gate blocked; source/package/native unsigned artifact proof present; updater key custody exists in GitHub Actions secrets; public-trusted Authenticode custody is absent; hosted updater endpoint remains stale against current artifact/signature hashes
Current classification: internal-tester Windows product candidate
Market readiness: controlled only; not broad public release

## Stage definitions

| Stage | Meaning | Current status |
|---|---|---|
| Internal tester candidate | Source validates, artifacts build, native packaged GUI parity passes on exact artifact, caveats documented. | PASS |
| Controlled external pilot candidate | Native workflow proven and support intake ready; signing/updater constraints accepted or fixed. | NO for the stronger signed external-tester gate / public-trusted Authenticode custody is absent, current artifacts are unsigned, hosted updater metadata is stale, and native proof has not been rerun on signed artifacts. |
| Signed public release | Windows executable, MSI, NSIS, and updater artifacts are signed and verified with publicly trusted chain. | FAIL / not proven |
| Enterprise/procurement-ready release | Signed artifacts, update policy, support SLA, procurement docs, security questionnaire, and rollback plan complete. | NOT READY |

## Release-hardening gate status

| Gate | Status | Evidence | Next action |
|---|---|---|---|
| Frontend tests | PASS | 40 files / 700 tests in current pass. | Keep in CI before release. |
| TypeScript typecheck | PASS | `yarn typecheck` passed. | Keep required. |
| Production frontend build | PASS | `yarn build` passed. | Keep required. |
| Rust workspace | PASS | 71 backend tests + 14 `nest_cli` tests passed. | Keep required. |
| Tauri package build | PASS | `yarn tauri:build` rebuilt release exe, MSI, and NSIS. | Keep required. |
| Artifact hashes | PASS | See rebuilt artifact evidence `docs/release-evidence/unsigned_rebuild_release_truth_2026-06-02_220000.json`. | Publish only after signed release artifacts and matching hosted metadata are generated. |
| Authenticode signing | FAIL | Current artifacts are not digitally signed. | Configure real signing. |
| Updater metadata | FAIL FOR CURRENT RELEASE HASHES | `https://hexhawk.ke/releases/latest.json` fetches, but the hosted artifact/signature hashes do not match the current local NSIS artifact/signature. Evidence: `docs/release-evidence/hosted_updater_metadata_validation_rebuilt_unsigned_2026-06-02_220500.json`. | Publish only after a signed GitHub Actions release produces exact artifacts and website-release-payload. |
| Packaged native GUI runtime | PASS | `gui-evidence/release_hardening_native_gui_probe_2026-06-01_234839.json` against current MSI hash `78bf99874acb9419525ab3012ac36252d2f8cc7605850aa773d36cc6865ec1e4`. | Repeat for every release artifact. |
| Packaged GUI workflow | PASS | Probe loaded binary, inspected, ran analysis, navigated NEST, exported report. | Keep as release gate. |
| Report authority export | PASS | JSON export contains GYRE authority markers and NEST status fields. | Keep test/probe checks. |
| External support intake | DOC READY | See `docs/PILOT_SUPPORT_AND_INTAKE.md`. | Assign owner and response windows. |

## Current decision

HexHawk remains suitable for internal tester use with explicit unsigned-artifact caveats. It is not suitable for the stronger controlled external signed-tester gate until real public-trusted Authenticode custody is configured, a GitHub Actions tag release produces signed artifacts, hosted updater metadata matches the exact release hashes, and native GUI proof is rerun on the exact signed MSI/NSIS. It is not a public release candidate.
