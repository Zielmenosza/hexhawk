# HexHawk for Dummies Validation Report

Date: 2026-07-09

> **Historical snapshot.** This report records the 2026-07-09 documentation/screenshot validation and retains its original evidence and counts. It is not the current HexHawk 1.0.0 project-persistence or Windows release-candidate validation statement. See [`CURRENT_STATUS.md`](CURRENT_STATUS.md) for the 2026-07-14 milestone evidence and open installer-acceptance gates.

This report documents validation performed for:

- `docs/HEXHAWK_FOR_DUMMIES_CAPABILITY_INVENTORY.md`
- `docs/HEXHAWK_FOR_DUMMIES.md`
- `docs/HEXHAWK_FOR_DUMMIES_SOURCE_MAP.md`
- 2026-07-09 consumer/product website and competitive-landscape refresh

## Repository inspection performed

Read or inspected:

- `README.md`
- `ROADMAP.md`
- `docs/ENGINE_BOUNDARY_DOCTRINE.md`
- `docs/HIGH_ASSURANCE_GUIDE.md`
- `docs/INVESTOR_ONE_PAGER.md`
- `docs/INVESTOR_DILIGENCE_BRIEF.md`
- `docs/TESTER_RELEASE_STATUS.md`
- `docs/nest_evidence_schema_spec.md`
- `docs/nest_evidence_examples.md`
- `docs/m10_ai_backbone.md`
- `docs/m11_byok_ai.md`
- `package.json`
- `HexHawk/package.json`
- `Cargo.toml`
- `src-tauri/Cargo.toml`
- `src-tauri/tauri.conf.json`
- `src-tauri/src/main.rs`
- `src-tauri/src/bin/nest_cli.rs`
- representative backend command files
- `plugin-api/src/lib.rs`
- `plugins/byte_counter/src/lib.rs`
- `HexHawk/src/App.tsx`
- tier/config and selected frontend files through source scanning

Not present:

- `docs/PERSONA_VALIDATION_REPORT_2026-05-16.md` was requested but was not found.

Not read:

- `docs/credentials.md` was deliberately not read because this documentation task did not require credentials.

## Commands run for current validation

```bash
git status --short
./target/release/nest_cli.exe
./target/release/nest_cli.exe identify Challenges/ch76/keygenme.exe
./target/release/nest_cli.exe inspect Challenges/ch76/keygenme.exe
```

Observed `nest_cli identify` output:

```json
{"format":"PE/MZ","magic_hex":"4D 5A 90 00","file_size":2804697,"entropy_header_4kb":4.617667586433138}
```

The `inspect` command returned JSON metadata beginning with `file_type`, `architecture`, `entry_point`, `file_size`, `image_base`, and section records. Output was intentionally truncated in the terminal capture.

## Current-session UI/build validation update

After the workspace-tab UI pass, these commands were run from `D:/Project/HexHawk`:

```bash
yarn typecheck
yarn test --reporter=dot --run
yarn build
rm -rf target/release/bundle/msi target/release/bundle/nsis && yarn tauri:build
sha256sum target/release/hexhawk-backend.exe target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe
./target/release/nest_cli.exe identify Challenges/ch76/keygenme.exe
MSYS_NO_PATHCONV=1 powershell.exe -NoProfile -Command '<Get-AuthenticodeSignature over exe/msi/nsis artifacts>'
```

Observed current-session results:

- TypeScript typecheck: passed.
- Frontend tests: 40 files / 700 tests passed in the 2026-06-02 website-alignment validation pass.
- Frontend production build: passed.
- Tauri release/installer build: passed.
- MSI artifact produced: `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi`.
- NSIS artifact produced: `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe`.
- `nest_cli identify Challenges/ch76/keygenme.exe`: passed and returned PE/MZ identity JSON.
- Authenticode status: signatures present, with trust-chain validation reported as `UnknownError` (untrusted-root chain) for `hexhawk-backend.exe`, MSI, and NSIS setup executable.

Current artifact hashes after the latest installer rebuild:

- `target/release/hexhawk-backend.exe`: `4c3bac2a7c1507e6ebd595a2e62212e5436e5e89f7ac4a9b20936d74deb85c7c`.
- `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi`: `a51ddacb1753a2c48d79fe830f790436d1348e44b6bebc1552610c291d54dba0`.
- `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe`: `d4e39045fcbbb29a1ee8cc45d7dc66664b061ccbd34bde1b0350738ff01397bf`.

Not rerun in this update:

- `cargo check --workspace` as a standalone command.
- `cargo test --workspace`.
- MSI administrative extraction.
- Native packaged GUI parity probe.
- Install/uninstall smoke.

## Pre-existing repository state

Before creating these docs, `git status --short` showed multiple modified files and untracked directories/files, including README/ROADMAP/source/static-site changes and untracked docs. This publication only intentionally adds the HexHawk-for-Dummies docs listed above.

## Known doc inconsistency handled conservatively

- `README.md` and `ROADMAP.md` now state packaged native GUI export parity passed for the current unsigned MSI artifact.
- `docs/TESTER_RELEASE_STATUS.md` and investor docs state packaged native GUI parity passed for the current unsigned MSI artifact and must be rerun on a signed artifact before external/public release.

The new publication treats native GUI parity as artifact-specific and says it must be rerun for each artifact that will be trusted.

## Overclaim scan results

The final validation pass searched the publication, inventory, source map, and this validation report for the requested terms.

Results:

- `guarantee`: 2 hits. One says frontend correlation is "not a guarantee"; one is this validation checklist context.
- `proves exploitability`: 1 hit in this validation checklist context only.
- `detonates`: 1 hit in this validation checklist context only.
- `bypasses`: 1 hit in this validation checklist context only.
- `AI decides`: 1 hit in this validation checklist context only.
- `always`: 1 hit in this validation checklist context only.
- `fully automated`: 1 hit in this validation checklist context only.
- `public release ready`: 1 hit in this validation checklist context only.
- `signed`: reviewed after the release-truth pass; current canonical release docs state the live artifacts are unsigned and distinguish historical internal self-signed evidence from current artifact state.
- `shell`: 3 hits. One is "Developer shell" in the capability matrix; one is the PowerShell Authenticode validation command in this report; one is this validation checklist context.
- `flag`: 1 hit in this validation checklist context only.
- `malware proven`: 1 hit in this validation checklist context only.

No unsafe positive overclaim was found in the generated publication during this scan.

## Formatting/git validation

Command run:

```bash
git diff --check -- docs/HEXHAWK_FOR_DUMMIES.md docs/HEXHAWK_FOR_DUMMIES_CAPABILITY_INVENTORY.md docs/HEXHAWK_FOR_DUMMIES_SOURCE_MAP.md docs/HEXHAWK_FOR_DUMMIES_VALIDATION_REPORT.md
```

Result: passed with no whitespace errors reported.

Generated file line counts:

- `HEXHAWK_FOR_DUMMIES.md`: 1046 lines
- `HEXHAWK_FOR_DUMMIES_CAPABILITY_INVENTORY.md`: 53 lines
- `HEXHAWK_FOR_DUMMIES_SOURCE_MAP.md`: 85 lines
- `HEXHAWK_FOR_DUMMIES_VALIDATION_REPORT.md`: 119 lines before this update

## Current unvalidated areas

- Exact current GUI behavior in a launched native app.
- Exact current packaged artifact signing state beyond source/docs.
- Full NEST typed bundle export parity on a fresh artifact.
- Full plugin install/run through the live GUI.
- Full BYOK provider calls to external services.
- Full debugger/STRIKE runtime behavior on a live target.

## Result

Documentation was grounded in inspected source/docs and a small CLI smoke. Release/build/test/native GUI claims remain historical unless clearly described as source-backed or command-smoked in this report.

## Real screenshot capture update (2026-06-01)

This pass now completes all previously flagged TODO visual placeholders using a combination of browser/dev-mode captures and source-backed rendered evidence cards. The pass also created the requested manual helper script:

- `scripts/capture_hexhawk_screenshots.py`

Additional automation used for this non-native capture pass:

- `scripts/automate_browser_dev_screenshots.cjs`
- temporary Playwright dependency installed outside the repo under the system temp directory

Capture manifest and review artifacts:

- `docs/assets/hexhawk-for-dummies/capture_manifest.json`
- `docs/assets/hexhawk-for-dummies/contact-sheet.png`

Runtime mode used:

- Browser/dev mode only.
- Native Tauri/WebView2 was not proven.
- Runtime diagnostic screenshot reported `hasTauriRuntime: false` and `browserMode: true`.

Sample used:

- `Challenges/ch76/keygenme.exe` / `D:/Project/HexHawk/Challenges/ch76/keygenme.exe`

Screenshots captured or generated from real output:

- `01-launch-home.png` — browser/dev first-run onboarding screen.
- `02-open-safe-sample.png` — Load Binary panel.
- `03-analysis-workspace.png` — safe sample path entered in Load Binary.
- `04-strings-view.png` — Strings panel in browser/dev mode after applying the path.
- `05-disassembly-view.png` — Disassembly workspace in browser/dev mode.
- `06-gyre-verdict.png` — Verdict panel visible state in browser/dev mode.
- `07-nest-evidence.png` — NEST browser simulation state.
- `09-report-export.png` — Report panel in browser/dev mode.
- `10-authority-fields.png` — report/authority area visible in browser/dev mode; typed export fields were not validated.
- `11-cli-identify.png` — rendered image from real `nest_cli identify Challenges/ch76/keygenme.exe` output; not an OS terminal-window screenshot.
- `12-gated-state.png` — NEST simulation/state view in browser/dev mode.
- `13-troubleshooting-native-runtime.png` — runtime diagnostic rendered from page evaluation showing native runtime was not proven.

Previously missing screenshots now completed in this revision:

- `08-aetherframe-lineage.png` is now a rendered evidence card sourced from current authority-doctrine fields (`source_engine`, `gyre_is_sole_verdict_source`, `aetherframe_role`).
- `00-unsigned-windows-warning-not-captured.png` is now a rendered evidence card sourced from real `Get-AuthenticodeSignature` output over current tester artifacts.

Note: these two images are source-backed evidence cards, not native SmartScreen or native runtime UI captures.

Privacy/secrets review:

- A generated contact sheet was visually reviewed.
- No credentials, tokens, license keys, customer data, unrelated browser tabs, or `docs/credentials.md` content were observed.
- Screenshot surfaces now use sanitized sample path display (`C:/Samples/keygenme.exe`) for public-release friendliness.

Validation scope for this screenshot pass:

- Verified Markdown image paths referenced by `docs/HEXHAWK_FOR_DUMMIES.md` exist.
- Verified referenced PNG files are nonzero-size and PIL-openable.
- Ran `python -m py_compile scripts/capture_hexhawk_screenshots.py` successfully.
- Ran `node scripts/automate_browser_dev_screenshots.cjs` successfully after starting the Vite dev server.
- Ran a risky-term scan over the changed docs for `guarantee`, `proves exploitability`, `detonates`, `bypasses`, `AI decides`, `always`, `fully automated`, `malware proven`, `shell`, and `flag`.
- Ran `git diff --check`; it exited 0. Git also reported pre-existing/unrelated working-copy line-ending warnings outside this screenshot pass.

Authority-boundary review:

- Captions preserve GYRE as sole verdict authority.
- Captions describe NEST as evidence convergence/orchestration, not a verdict replacement.
- Captions describe AETHERFRAME/Forge as optional and non-authoritative where mentioned.
- Captions describe CREST/report export as evidence packaging, not new verdict authority.
- Browser/dev screenshots are explicitly labeled as visual orientation only and not native Tauri/WebView2 proof.

Remaining unproven:

- Native packaged Tauri/WebView2 GUI operation.
- Installed-artifact GUI export parity.
- Exact report/export JSON authority fields from a packaged native run.
- Typed NEST evidence bundle export parity.
- Native SmartScreen warning UX from a specific installed artifact on a target endpoint policy.


## 2026-07-09 consumer/product validation update

Files intentionally refreshed in this update:

- `docs/HEXHAWK_FOR_DUMMIES.md`
- `docs/HIGH_ASSURANCE_GUIDE.md`
- `docs/INVESTOR_ONE_PAGER.md`
- `docs/INVESTOR_DILIGENCE_BRIEF.md`
- `docs/TESTER_RELEASE_STATUS.md`
- `docs/HEXHAWK_FOR_DUMMIES_SOURCE_MAP.md`
- `docs/HEXHAWK_FOR_DUMMIES_CAPABILITY_INVENTORY.md`
- `docs/HEXHAWK_FOR_DUMMIES_ENGINEERING_REVIEW.md`
- `README.md`
- `competitive_landscape.html`
- `site-build/index.html`
- `site-build/features/index.html`
- `site-build/products/index.html`
- `site-build/docs/index.html`
- `site-build/competitive_landscape.html`

Validation performed for this update:

```bash
python - <<'PY'
from html.parser import HTMLParser
from pathlib import Path
for rel in ['site-build/index.html','site-build/features/index.html','site-build/products/index.html','site-build/docs/index.html','competitive_landscape.html','site-build/competitive_landscape.html']:
    HTMLParser().feed(Path(rel).read_text(encoding='utf-8'))
    print('html-ok', rel)
PY

python - <<'PY'
# local site-build href target check
PY
```

Observed results: HTML parser checks passed for the edited website/competitive pages, and the local `site-build` href check reported `missing_count 0`. No source build, packaged installer smoke, signing verification, updater verification, or native GUI parity was rerun for this copy/docs update.
