# AetherFrame/Hermes Factory Cycle 0002 — Unsigned Early Access After Report

Generated: 2026-07-01 00:48:22 SAST
Repo: D:/Project/HexHawk
Cycle target: Unsigned Early Access packaging path
Factory classification: After docs/script validation and local package creation

## Summary

HexHawk was passed through a bounded AetherFrame/Hermes factory cycle to create a safe, honest unsigned paid early-access path.

This cycle created policy docs, buyer/install docs, an unsigned early-access gate, a release-notes template, a local-only PowerShell package script, and factory lessons/runbook/reporter improvements.

The local package was created for inspection only. Nothing was published, uploaded, deployed, signed, charged, or released publicly.

## Candidate classification

Unsigned early-access local package created; not published.

This is not a signed release, not Microsoft verified, not public/world-ready, and not auto-updating.

## Starting evidence

- Starting HEAD: `f513fb6` / `f513fb619f871c7b20597e47cde05942a901e429`.
- Latest main CI at intake: run 28478161801, conclusion `success`, same HEAD.
- Intake report: `docs/aetherframe-runs/factory-cycle-unsigned-early-access-20260701-004047.md`.
- Factory reporter report A: `docs/aetherframe-runs/factory-cycle-20260701-004617.md`.
- Factory reporter report B: `docs/aetherframe-runs/factory-cycle-20260701-004929.md`.

## Files created

- `docs/UNSIGNED_EARLY_ACCESS_POLICY.md`
- `docs/EARLY_ACCESS_INSTALL_README.md`
- `docs/EARLY_ACCESS_BUYER_NOTE.md`
- `docs/UNSIGNED_EARLY_ACCESS_GATE.md`
- `docs/EARLY_ACCESS_RELEASE_NOTES_TEMPLATE.md`
- `scripts/release/build_unsigned_early_access_package.ps1`
- `docs/aetherframe-runs/factory-cycle-unsigned-early-access-20260701-004047.md`
- `docs/aetherframe-runs/factory-cycle-20260701-004617.md`
- `docs/aetherframe-runs/factory-cycle-unsigned-early-access-after-20260701-004822.md`

## Files updated

- `docs/AETHERFRAME_FACTORY_RUNBOOK.md`
- `docs/AETHERFRAME_FACTORY_LESSONS.md`
- `scripts/aetherframe_factory_cycle.py`

## Package script validation

Commands run:

```text
powershell.exe -NoProfile -Command "Get-Command ./scripts/release/build_unsigned_early_access_package.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command '$ErrorActionPreference="Stop"; $null = [scriptblock]::Create((Get-Content -Raw "./scripts/release/build_unsigned_early_access_package.ps1")); "PowerShell parse OK"'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/release/build_unsigned_early_access_package.ps1 -WorktreePath . -OutputDir 'D:\Project\HexHawk-early-access-packages' -Version '1.0.0' -Stamp '20260701' -IncludeNestCli -DryRun
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/release/build_unsigned_early_access_package.ps1 -WorktreePath . -OutputDir 'D:\Project\HexHawk-early-access-packages' -Version '1.0.0' -Stamp '20260701' -IncludeNestCli
```

Results:

- `Get-Command` found the package script.
- PowerShell parse check passed after replacing non-ASCII punctuation in the script with ASCII-safe strings.
- Dry-run passed for MSI, NSIS, and `nest_cli.exe`.
- Real local package creation passed.
- A deliberate dry-run including `-IncludeWebView2Loader` failed because `WebView2Loader.dll` reported Authenticode `Valid`, and the unsigned channel script correctly refuses signed artifacts when `RequireNotSigned` is true. The final package therefore included MSI, NSIS, and `nest_cli.exe`, not `WebView2Loader.dll` as a separate top-level file.

## Local package created

Package zip:

`D:/Project/HexHawk-early-access-packages/HexHawk_Early_Access_UNSIGNED_v1.0.0_20260701.zip`

Package SHA256:

`77716e5fbd04830a06ad987a88fa647fa57266b9866b2f47d82b315a0bf8d4b8`

Package staging directory:

`D:/Project/HexHawk-early-access-packages/HexHawk_Early_Access_UNSIGNED_v1.0.0_20260701/`

Manifest:

`D:/Project/HexHawk-early-access-packages/HexHawk_Early_Access_UNSIGNED_v1.0.0_20260701/EVIDENCE_MANIFEST.json`

SHA256 sums:

`D:/Project/HexHawk-early-access-packages/HexHawk_Early_Access_UNSIGNED_v1.0.0_20260701/SHA256SUMS.txt`

Package contents verified by zip listing:

- `EARLY_ACCESS_BUYER_NOTE.md`
- `EARLY_ACCESS_INSTALL_README.md`
- `EARLY_ACCESS_RELEASE_NOTES.md`
- `EVIDENCE_MANIFEST.json`
- `HexHawk_1.0.0_x64-setup.exe`
- `HexHawk_1.0.0_x64_en-US.msi`
- `nest_cli.exe`
- `PACKAGE_CONTENTS.txt`
- `SHA256SUMS.txt`
- `UNSIGNED_EARLY_ACCESS_POLICY.md`

## Artifact hashes and Authenticode status

From the generated `EVIDENCE_MANIFEST.json`:

- MSI: `NotSigned`, SHA256 `0b6a8e885accd45b6c1633f5db79af839302d8c45311ab5d48ef4ddeefe0d14e`
- NSIS: `NotSigned`, SHA256 `fae7b573054a3938bc38c7ae21f341b54a2772629526cbda1c829a663ce59c71`
- `nest_cli.exe`: `NotSigned`, SHA256 `c4be723b6aaffafac18d04ea06928177bea0b5d46ee13f8ef65d51621225beb9`

Manifest fields verified:

- `classification`: `Unsigned early-access local package; not published.`
- `signed_release`: `false`
- `microsoft_verified`: `false`
- `public_world_ready`: `false`
- `auto_update_enabled_by_package`: `false`

## Factory improvements made

Runbook:

- Added an `Unsigned Early Access Factory Cycle` section with steps for CI, clean main, artifacts, hashes, Authenticode `NotSigned`, installer smoke, Function Notebook/export proof, package docs, buyer limitations, and stop conditions.

Lessons:

- Unsigned early access is a commercial/testing channel, not a public trust claim.
- NotSigned artifacts may be packaged for technical testers only when clearly labeled and hash-verified.
- Payment/private distribution must not be confused with signed/public release readiness.
- Auto-update remains disabled until updater signing is proven.
- Early-access gates preserve GYRE authority and advisory-only AI/AETHERFRAME boundaries.
- Packaging scripts must not publish/upload/deploy/use credentials/sign artifacts/modify updater metadata.
- Factory improvement means better process, gates, reports, and evidence, not uncontrolled self-modification.

Reporter:

- Added release-channel awareness: `source/dev`, `unsigned early access`, `unsigned deployment candidate`, `signed public release`.
- Added unsigned early-access checklist output.
- Added the new package script to validation-script discovery.
- Reporter remains read-only and non-destructive.

## Validation run

Commands run:

```text
git diff --check
python -m py_compile scripts/aetherframe_factory_cycle.py
python scripts/aetherframe_factory_cycle.py --run-checks --stdout
powershell.exe -NoProfile -Command "Get-Command ./scripts/release/build_unsigned_early_access_package.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command '$ErrorActionPreference="Stop"; $null = [scriptblock]::Create((Get-Content -Raw "./scripts/release/build_unsigned_early_access_package.ps1")); "PowerShell parse OK"'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/release/build_unsigned_early_access_package.ps1 -WorktreePath . -OutputDir 'D:\Project\HexHawk-early-access-packages' -Version '1.0.0' -Stamp '20260701' -IncludeNestCli -DryRun
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/release/build_unsigned_early_access_package.ps1 -WorktreePath . -OutputDir 'D:\Project\HexHawk-early-access-packages' -Version '1.0.0' -Stamp '20260701' -IncludeNestCli
```

Current validation result at this report point:

- `git diff --check`: passed, with line-ending warnings only.
- Python reporter compile: passed.
- Factory reporter run: passed and wrote `docs/aetherframe-runs/factory-cycle-20260701-004617.md`.
- PowerShell `Get-Command`: passed.
- PowerShell parse: passed.
- Package dry-run: passed for MSI/NSIS/`nest_cli.exe`.
- Package real run: passed and created a local zip.
- Package manifest verification: passed for unsigned/local/non-public fields.

## Stop point

Stop before public release claims. The unsigned early-access local package exists for controlled private review only. It was not published, uploaded, deployed, signed, charged, or attached to a GitHub Release.

## Remaining blockers before public signed release

- Authenticode signing.
- Tauri updater signing and hosted metadata proof.
- Signed exact-artifact release gate.
- Public download/trust page.
- Payment/distribution workflow.
- Fresh exact-artifact installer smoke and Function Notebook/export proof for any package claimed beyond this local unsigned early-access scope.
