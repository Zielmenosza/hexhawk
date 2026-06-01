# HexHawk Pilot Readiness Checklist

Date: 2026-06-01
Status: release-hardening gap report
Current classification: internal-tester Windows product candidate
Market readiness: controlled only; not broad public release

## Stage definitions

| Stage | Meaning | Current status |
|---|---|---|
| Internal tester candidate | Built, packaged, validated locally; acceptable for founder/team/board demo and controlled internal testers. | PASS |
| Controlled external pilot candidate | Native installed-artifact workflow proven, support intake ready, pilot scope bounded, and signing/updater plan accepted. | CONDITIONAL / native proof passed, but signing trust chain and updater endpoint validation remain open. |
| Signed public release | Windows executable, MSI, NSIS, and updater artifacts are signed and verified with publicly trusted chain. | FAIL / not proven |
| Enterprise/procurement-ready release | Signed artifacts, update policy, support SLA, procurement docs, security questionnaire, and rollback plan complete. | NOT READY |

## Release-hardening gate status

| Gate | Status | Evidence | Next action |
|---|---|---|---|
| Frontend tests | PASS | 683 tests previously reported; focused report-export test passed in this pass. | Keep in CI before release. |
| TypeScript typecheck | PASS | `yarn typecheck` passed. | Keep required. |
| Production frontend build | PASS | `yarn build` passed. | Keep required. |
| Rust workspace | PASS in prior release pass | 85 backend/CLI tests previously reported. | Rerun full cargo check/test before signed pilot. |
| Tauri package build | PASS | `yarn tauri:build` rebuilt release exe, MSI, and NSIS. | Keep required. |
| MSI extraction | PASS | Admin extraction to temp path succeeded. | Keep required. |
| Extracted CLI smoke | PASS | Extracted `nest_cli.exe identify` on `Challenges/ch76/keygenme.exe` returned PE/MZ metadata. | Add to repeatable smoke script. |
| Packaged native GUI runtime | PASS | Native parity probe passed on latest signed-internal artifact (`gui-evidence/release_hardening_native_gui_probe_2026-06-01_204631.json`). | Keep CDP probe as release evidence. |
| Packaged GUI workflow | PASS | Packaged app loaded binary, inspected, ran analysis, navigated NEST, exported report in latest probe. | Keep as release gate for each target artifact. |
| Report authority export | PASS | JSON export contains `source_engine: gyre`, `gyre_is_sole_verdict_source: true`, `final_verdict_snapshot`; regression test added in `IntelligenceReport.test.tsx`. | Keep test and probe checks required in release flow. |
| Authenticode signing | PARTIAL | exe/MSI/NSIS are signed + timestamped, but trust status is `UnknownError` (untrusted root). | Replace internal self-signed cert with organization-trusted code-signing certificate. |
| Tauri updater signing | PARTIAL | Updater signing path enabled in config; pubkey set; endpoint metadata validation failed due DNS resolution failure. | Publish reachable updater metadata endpoint and validate platform/signature fields. |
| External support intake | DOC READY | See `docs/PILOT_SUPPORT_AND_INTAKE.md`. | Assign owner and response windows. |

## Current decision

HexHawk is stronger than the previous internal-tester state because packaged native GUI parity and report authority export now pass. It is still not a signed public release candidate. Controlled external pilot use should remain gated on signing/updater acceptance by the pilot sponsor, or explicitly documented as an unsigned private evaluation build.
