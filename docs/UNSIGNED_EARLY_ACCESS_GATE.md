# HexHawk Unsigned Early Access Gate

Status: gate definition for controlled paid early-access technical preview
Channel: HexHawk Early Access — Unsigned Founder Build

This gate decides whether a local unsigned early-access package may be created and privately reviewed. It does not approve public/world-ready release, signed release, Microsoft verification, auto-update, deployment, upload, or publication.

## Required state

- [ ] main is clean.
- [ ] current HEAD is pushed to origin/main.
- [ ] latest CI on main is green.
- [ ] no release-candidate/public-release tag is being created by accident.
- [ ] package version/date are explicit.
- [ ] fresh build or known current artifact path is recorded.

## Required artifacts

- [ ] MSI exists.
- [ ] NSIS setup executable exists.
- [ ] `nest_cli.exe` exists if included.
- [ ] `WebView2Loader.dll` exists if included or relevant to the package.
- [ ] SHA256 hashes are generated.
- [ ] Authenticode status is recorded for every packaged executable/installer.
- [ ] Authenticode status is `NotSigned` for this unsigned channel when `RequireNotSigned` is true.
- [ ] `EVIDENCE_MANIFEST.json` is created.
- [ ] `SHA256SUMS.txt` is created.
- [ ] `PACKAGE_CONTENTS.txt` is created.
- [ ] `EARLY_ACCESS_RELEASE_NOTES.md` is generated.

## Required docs inside package

- [ ] `UNSIGNED_EARLY_ACCESS_POLICY.md`.
- [ ] `EARLY_ACCESS_INSTALL_README.md`.
- [ ] `EARLY_ACCESS_BUYER_NOTE.md`.

## Required smoke/proof evidence

- [ ] Installer smoke passed, or the package manifest explicitly says installer smoke is not current for this package.
- [ ] Function Notebook/export proof passed, or the package manifest explicitly says it is historical/not current for this exact package.
- [ ] No updater is enabled unless Tauri updater signatures and hosted metadata are correctly configured and proven.

## Required claim checks

- [ ] No signed-release claim.
- [ ] No Microsoft-verified claim.
- [ ] No public/world-ready claim.
- [ ] No auto-update claim.
- [ ] No instruction to disable system security globally.
- [ ] No SmartScreen bypass instructions beyond explaining that unsigned software may be warned or blocked.
- [ ] No AI/AETHERFRAME verdict mutation claim.
- [ ] Payment/private distribution is not confused with signed/public release readiness.

## Factory requirements

- [ ] Factory cycle report updated before and after package work.
- [ ] Factory lessons updated if reusable lessons were learned.
- [ ] GYRE authority boundary preserved.
- [ ] AETHERFRAME remains advisory/factory orchestration only.
- [ ] NEXUS/Hermes/AI remain assistant/proposal/workflow helpers only.
- [ ] No deployment/publish/upload happened without explicit approval.

## Gate outcomes

### PASS — unsigned early-access local package

Allowed wording:

`Unsigned early-access local package created; not published.`

This is only allowed when the package exists, hashes and manifest exist, Authenticode `NotSigned` is recorded, docs are included, and overclaim scans pass.

### PARTIAL — path defined, no package

Allowed wording:

`Unsigned early-access packaging path defined; no package published.`

Use this when docs/scripts/gates are ready but exact local artifacts are missing or the package script was only parse/dry-run validated.

### FAIL / STOP

Stop if CI is red, main is dirty, expected artifacts are missing without explicit partial classification, Authenticode status is not recorded, a public/signed/verified claim appears, updater claims are introduced without proof, or the factory authority boundaries drift.

## Public signed release remains blocked until

- Authenticode signing is configured and proven on exact artifacts.
- Updater signing and metadata are configured and proven.
- Signed exact-artifact release gate passes.
- Public download/trust page is approved and validated.
- Payment/distribution workflow is approved.
