# Repository Tree Cleanup Report — 2026-06-06

> **Historical snapshot.** This document preserves the 2026-06-06 cleanup record. It does not describe current HexHawk 1.0.0 persistence, packaging, or Bridge-era cleanup status. See [`CURRENT_STATUS.md`](CURRENT_STATUS.md).

Status: inventory/report pass before destructive cleanup. Generated from a clean working tree checkpoint branch `backup/pre-repo-cleanup-clean-baseline-20260606`.

## Current git state at report creation
```
## main...origin/main [ahead 7]
```

## Tree overview
| Path | Kind | Classification / purpose |
| --- | --- | --- |
| `.github` | dir | KEEP_WORKFLOW - GitHub workflows and automation. |
| `.gitignore` | file | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |
| `.tmp` | dir | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |
| `.venv` | dir | GENERATED_SAFE_TO_DELETE - local Python virtualenv. |
| `.vscode` | dir | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |
| `.yarn` | dir | GENERATED/CONFIG MIX - Yarn metadata; cache/install-state ignored, releases/config require review. |
| `.yarnrc.yml` | file | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |
| `AetherframeGuard` | dir | KEEP_SOURCE - separate AetherFrameGuard app; App.js generated-adjacent REVIEW_REQUIRED. |
| `archive` | dir | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |
| `Cargo.lock` | file | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |
| `Cargo.toml` | file | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |
| `Challenges` | dir | REVIEW_REQUIRED - ignored challenge/test corpus; not cleanup-delete blindly. |
| `competitive_landscape.html` | file | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |
| `docs` | dir | KEEP_DOCS/KEEP_RELEASE_EVIDENCE - docs, evidence JSON, trust/release posture; credentials never touch. |
| `ENTERPRISE_ROADMAP.md` | file | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |
| `FINAL_EVALUATION.md` | file | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |
| `gui-evidence` | dir | KEEP_RELEASE_EVIDENCE - GUI validation evidence/provenance. |
| `HexHawk` | dir | KEEP_SOURCE - main HexHawk frontend workspace/source. |
| `hexhawk_assistant.py` | file | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |
| `KEYBOARD_SHORTCUTS.md` | file | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |
| `LICENSE` | file | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |
| `nest_tests` | dir | REVIEW_REQUIRED - ignored NEST sessions/analysis output; inspect before cleanup. |
| `nexus-assistant` | dir | REVIEW_REQUIRED - adjacent assistant project ignored; out of scope unless authorized. |
| `node_modules` | dir | GENERATED_SAFE_TO_DELETE - dependency install output if untracked/ignored. |
| `package.json` | file | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |
| `packages` | dir | KEEP_SOURCE - shared packages including @hexhawk/aetherframe-core. |
| `plugin-api` | dir | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |
| `PLUGIN_QUICK_REFERENCE.md` | file | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |
| `plugins` | dir | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |
| `prepare-release.ps1` | file | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |
| `README.md` | file | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |
| `ROADMAP.md` | file | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |
| `run.ps1` | file | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |
| `run.sh` | file | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |
| `scripts` | dir | KEEP_SOURCE/CONFIG - release and utility scripts; generated subdir ignored. |
| `site-build` | dir | KEEP_SITE_PUBLIC - static public website and protected release/trust endpoints. |
| `src-tauri` | dir | KEEP_SOURCE - main Tauri/Rust backend. |
| `target` | dir | GENERATED_SAFE_TO_DELETE - Rust build output if untracked/ignored. |
| `website` | dir | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |
| `yarn.lock` | file | REVIEW_REQUIRED - inspect before cleanup or broad ignore/delete. |

## Likely source folders
- `HexHawk/`
- `src-tauri/`
- `packages/`
- `AetherframeGuard/`
- `scripts/`

## Likely generated/cache/temp folders
- `AetherframeGuard/dist/` — frontend build output; ignored/reproducible
- `AetherframeGuard/src-tauri/target/` — dependency/build output directory; ignored; not vendored unless proven otherwise
- `HexHawk/dist/` — frontend build output; ignored/reproducible
- `HexHawk/node_modules/` — dependency/build output directory; ignored; not vendored unless proven otherwise
- `nest_tests/1 - DrillBabyDrill/session.log` — matches temp pattern *.log
- `nest_tests/10000/session.log` — matches temp pattern *.log
- `nest_tests/4 - UnholyDragon/session.log` — matches temp pattern *.log
- `nest_tests/DrillBabyDrill/session.log` — matches temp pattern *.log
- `nest_tests/FlareAuthenticator/session.log` — matches temp pattern *.log
- `nest_tests/Gujian3/session.log` — matches temp pattern *.log
- `nest_tests/UnholyDragon-150/session.log` — matches temp pattern *.log
- `nest_tests/chat_client/session.log` — matches temp pattern *.log
- `nest_tests/cmd/session.log` — matches temp pattern *.log
- `nest_tests/crackme_shroud/session.log` — matches temp pattern *.log
- `nest_tests/hopeanddreams/session.log` — matches temp pattern *.log
- `nest_tests/keygenme/session.log` — matches temp pattern *.log
- `nest_tests/notepad/session.log` — matches temp pattern *.log
- `nest_tests/ntfsm/session.log` — matches temp pattern *.log
- `nest_tests/pretty_devilish_file/session.log` — matches temp pattern *.log
- `nest_tests/project_chimera/session.log` — matches temp pattern *.log
- `nest_tests/pwn109-1644300507645/session.log` — matches temp pattern *.log
- `nest_tests/pwn110-1644300525386/session.log` — matches temp pattern *.log
- `nest_tests/run/session.log` — matches temp pattern *.log
- `nest_tests/strike_benchmarks/pwn_workflow_20260514_003723.log` — matches temp pattern *.log
- `nest_tests/strike_benchmarks/pwn_workflow_20260514_003939.log` — matches temp pattern *.log
- `nest_tests/strike_benchmarks/pwn_workflow_20260514_004931.log` — matches temp pattern *.log
- `nest_tests/winlogon/session.log` — matches temp pattern *.log
- `nexus-assistant/src/nexus_assistant/__pycache__/` — cache directory
- `nexus-assistant/src/nexus_assistant/__pycache__/__init__.cpython-314.pyc` — Python bytecode
- `nexus-assistant/src/nexus_assistant/__pycache__/app.cpython-314.pyc` — Python bytecode
- `nexus-assistant/src/nexus_assistant/__pycache__/cli.cpython-314.pyc` — Python bytecode
- `node_modules/` — dependency/build output directory; ignored; not vendored unless proven otherwise
- `packages/aetherframe-core/dist/` — frontend build output; ignored/reproducible
- `packages/aetherframe-core/node_modules/` — dependency/build output directory; ignored; not vendored unless proven otherwise
- `scripts/__pycache__/` — cache directory
- `scripts/__pycache__/native_gui_parity_probe.cpython-311.pyc` — Python bytecode
- `target/` — dependency/build output directory; ignored; not vendored unless proven otherwise

## Release/deployment/evidence folders
- `site-build/` — protected/review-required; do not delete blindly.
- `site-build/releases/` — protected/review-required; do not delete blindly.
- `site-build/trust/` — protected/review-required; do not delete blindly.
- `site-build/.well-known/` — protected/review-required; do not delete blindly.
- `docs/release-evidence/` — protected/review-required; do not delete blindly.
- `gui-evidence/` — protected/review-required; do not delete blindly.
- `scripts/release/` — protected/review-required; do not delete blindly.

## File classification table
| Path / Pattern | Classification | Reason / decision |
| --- | --- | --- |
| `.git/**` | NEVER_TOUCH_WITHOUT_APPROVAL | Git object database and refs. |
| `docs/credentials.md` | NEVER_TOUCH_WITHOUT_APPROVAL | Sensitive credentials; not read during cleanup. |
| `**/.env*; **/*.key; **/*.pem; **/*.pfx; **/id_rsa*; *token*; *secret*; *credential*` | NEVER_TOUCH_WITHOUT_APPROVAL | Credential-like paths. |
| `README.md; ROADMAP.md; docs/**/*.md` | KEEP_DOCS | Docs are source-of-truth unless duplicate/temp generated. |
| `docs/release-evidence/**/*.json; gui-evidence/**/*.json` | KEEP_RELEASE_EVIDENCE | Release/native GUI provenance; do not delete without specific audit. |
| `site-build/**` | KEEP_SITE_PUBLIC | Public static website; release/trust subpaths protected. |
| `site-build/releases/**; site-build/trust/**; site-build/.well-known/**` | NEVER_TOUCH_WITHOUT_APPROVAL | Release/trust/updater endpoints protected. |
| `.github/workflows/**` | KEEP_WORKFLOW | CI/release automation; review before changes. |
| `package.json; yarn.lock; Cargo.toml; Cargo.lock when tracked; package lockfiles` | KEEP_LOCKFILE | Do not remove lockfiles; note root .gitignore ignores Cargo.lock and deserves policy review. |
| `HexHawk/**; src-tauri/**; packages/**; AetherframeGuard/**` | KEEP_SOURCE | Current source folders. AetherframeGuard/src/App.js is REVIEW_REQUIRED generated-adjacent. |
| `**/tests/**; **/*.test.*; **/*_test.rs` | KEEP_TESTS | Tests are protected even if old. |
| `**/node_modules/**` | GENERATED_SAFE_TO_DELETE | Dependency installs, if untracked/ignored and reproducible. |
| `**/target/**` | GENERATED_SAFE_TO_DELETE | Rust build outputs, if untracked/ignored. |
| `**/dist/**; **/build/** except site-build` | GENERATED_SAFE_TO_DELETE | Build outputs, if untracked/ignored and reproducible. |
| `**/__pycache__/**; **/*.pyc; .pytest_cache/; .ruff_cache/; .mypy_cache/` | CACHE_SAFE_TO_DELETE | Python cache output. |
| `*.tmp; *.bak; *.old; *.log; .DS_Store; Thumbs.db; .~lock.*; *.wixobj` | TEMP_SAFE_TO_DELETE | Local temporary files/intermediates. |
| `*.sig.sig` | DUPLICATE_CANDIDATE | Duplicate signature extension candidate; protect release/trust context. |
| `_cleanup_quarantine/**` | TEMP_SAFE_TO_DELETE | Local cleanup quarantine; must stay ignored. |
| `AetherframeGuard/src/App.js` | REVIEW_REQUIRED | Tracked JS generated-adjacent from App.tsx; do not delete without separate proof/commit. |
| `Challenges/; nest_tests/; nexus-assistant/` | REVIEW_REQUIRED | Ignored local corpora/adjacent projects; not cleanup-delete blindly. |

## Never-touch list
- `.git/**` — Git metadata
- `docs/credentials.md` — Credentials
- `any .env/.key/.pem/.pfx/id_rsa/token/secret/credential file` — Secrets
- `site-build/releases/**` — Release endpoints
- `site-build/trust/**` — Trust endpoints
- `site-build/.well-known/**` — Well-known endpoints
- `docs/release-evidence/**` — Release evidence
- `gui-evidence/**` — Native GUI evidence
- `current source folders` — Active product source
- `current tests` — Protected tests
- `lockfiles` — Dependency reproducibility
- `.github/workflows/**` — CI/release workflows

## Safe junk candidates detected before deletion
| Candidate | Classification | Reason | Tracked? |
| --- | --- | --- | --- |
| `AetherframeGuard/dist/` | GENERATED_SAFE_TO_DELETE | frontend build output; ignored/reproducible | no/dir/untracked-or-ignored |
| `AetherframeGuard/src-tauri/target/` | GENERATED_SAFE_TO_DELETE | dependency/build output directory; ignored; not vendored unless proven otherwise | no/dir/untracked-or-ignored |
| `HexHawk/dist/` | GENERATED_SAFE_TO_DELETE | frontend build output; ignored/reproducible | no/dir/untracked-or-ignored |
| `HexHawk/node_modules/` | GENERATED_SAFE_TO_DELETE | dependency/build output directory; ignored; not vendored unless proven otherwise | no/dir/untracked-or-ignored |
| `nest_tests/1 - DrillBabyDrill/session.log` | TEMP_SAFE_TO_DELETE | matches temp pattern *.log | no/dir/untracked-or-ignored |
| `nest_tests/10000/session.log` | TEMP_SAFE_TO_DELETE | matches temp pattern *.log | no/dir/untracked-or-ignored |
| `nest_tests/4 - UnholyDragon/session.log` | TEMP_SAFE_TO_DELETE | matches temp pattern *.log | no/dir/untracked-or-ignored |
| `nest_tests/DrillBabyDrill/session.log` | TEMP_SAFE_TO_DELETE | matches temp pattern *.log | no/dir/untracked-or-ignored |
| `nest_tests/FlareAuthenticator/session.log` | TEMP_SAFE_TO_DELETE | matches temp pattern *.log | no/dir/untracked-or-ignored |
| `nest_tests/Gujian3/session.log` | TEMP_SAFE_TO_DELETE | matches temp pattern *.log | no/dir/untracked-or-ignored |
| `nest_tests/UnholyDragon-150/session.log` | TEMP_SAFE_TO_DELETE | matches temp pattern *.log | no/dir/untracked-or-ignored |
| `nest_tests/chat_client/session.log` | TEMP_SAFE_TO_DELETE | matches temp pattern *.log | no/dir/untracked-or-ignored |
| `nest_tests/cmd/session.log` | TEMP_SAFE_TO_DELETE | matches temp pattern *.log | no/dir/untracked-or-ignored |
| `nest_tests/crackme_shroud/session.log` | TEMP_SAFE_TO_DELETE | matches temp pattern *.log | no/dir/untracked-or-ignored |
| `nest_tests/hopeanddreams/session.log` | TEMP_SAFE_TO_DELETE | matches temp pattern *.log | no/dir/untracked-or-ignored |
| `nest_tests/keygenme/session.log` | TEMP_SAFE_TO_DELETE | matches temp pattern *.log | no/dir/untracked-or-ignored |
| `nest_tests/notepad/session.log` | TEMP_SAFE_TO_DELETE | matches temp pattern *.log | no/dir/untracked-or-ignored |
| `nest_tests/ntfsm/session.log` | TEMP_SAFE_TO_DELETE | matches temp pattern *.log | no/dir/untracked-or-ignored |
| `nest_tests/pretty_devilish_file/session.log` | TEMP_SAFE_TO_DELETE | matches temp pattern *.log | no/dir/untracked-or-ignored |
| `nest_tests/project_chimera/session.log` | TEMP_SAFE_TO_DELETE | matches temp pattern *.log | no/dir/untracked-or-ignored |
| `nest_tests/pwn109-1644300507645/session.log` | TEMP_SAFE_TO_DELETE | matches temp pattern *.log | no/dir/untracked-or-ignored |
| `nest_tests/pwn110-1644300525386/session.log` | TEMP_SAFE_TO_DELETE | matches temp pattern *.log | no/dir/untracked-or-ignored |
| `nest_tests/run/session.log` | TEMP_SAFE_TO_DELETE | matches temp pattern *.log | no/dir/untracked-or-ignored |
| `nest_tests/strike_benchmarks/pwn_workflow_20260514_003723.log` | TEMP_SAFE_TO_DELETE | matches temp pattern *.log | no/dir/untracked-or-ignored |
| `nest_tests/strike_benchmarks/pwn_workflow_20260514_003939.log` | TEMP_SAFE_TO_DELETE | matches temp pattern *.log | no/dir/untracked-or-ignored |
| `nest_tests/strike_benchmarks/pwn_workflow_20260514_004931.log` | TEMP_SAFE_TO_DELETE | matches temp pattern *.log | no/dir/untracked-or-ignored |
| `nest_tests/winlogon/session.log` | TEMP_SAFE_TO_DELETE | matches temp pattern *.log | no/dir/untracked-or-ignored |
| `nexus-assistant/src/nexus_assistant/__pycache__/` | CACHE_SAFE_TO_DELETE | cache directory | no/dir/untracked-or-ignored |
| `nexus-assistant/src/nexus_assistant/__pycache__/__init__.cpython-314.pyc` | CACHE_SAFE_TO_DELETE | Python bytecode | no/dir/untracked-or-ignored |
| `nexus-assistant/src/nexus_assistant/__pycache__/app.cpython-314.pyc` | CACHE_SAFE_TO_DELETE | Python bytecode | no/dir/untracked-or-ignored |
| `nexus-assistant/src/nexus_assistant/__pycache__/cli.cpython-314.pyc` | CACHE_SAFE_TO_DELETE | Python bytecode | no/dir/untracked-or-ignored |
| `node_modules/` | GENERATED_SAFE_TO_DELETE | dependency/build output directory; ignored; not vendored unless proven otherwise | no/dir/untracked-or-ignored |
| `packages/aetherframe-core/dist/` | GENERATED_SAFE_TO_DELETE | frontend build output; ignored/reproducible | no/dir/untracked-or-ignored |
| `packages/aetherframe-core/node_modules/` | GENERATED_SAFE_TO_DELETE | dependency/build output directory; ignored; not vendored unless proven otherwise | no/dir/untracked-or-ignored |
| `scripts/__pycache__/` | CACHE_SAFE_TO_DELETE | cache directory | no/dir/untracked-or-ignored |
| `scripts/__pycache__/native_gui_parity_probe.cpython-311.pyc` | CACHE_SAFE_TO_DELETE | Python bytecode | no/dir/untracked-or-ignored |
| `target/` | GENERATED_SAFE_TO_DELETE | dependency/build output directory; ignored; not vendored unless proven otherwise | no/dir/untracked-or-ignored |

## Ignored/generated-looking preview
```
!! .venv/
!! .vscode/
!! AetherframeGuard/dist/
!! AetherframeGuard/src-tauri/Cargo.lock
!! AetherframeGuard/src-tauri/target/
!! Cargo.lock
!! Challenges/
!! HexHawk/dist/
!! HexHawk/node_modules/
!! nest_tests/
!! nexus-assistant/
!! node_modules/
!! packages/aetherframe-core/dist/
!! packages/aetherframe-core/node_modules/
!! scripts/__pycache__/
!! scripts/release/.generated/
!! site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe.sig
!! site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi.sig
!! target/
```

## Duplicate groups by SHA256
### Duplicate group 1
- SHA256: `42c5bc223cbd28835a4978907faf3ac1d8cb18af51c209709b7cb9998fb4f428`
- Size: 128808 bytes
- Classification: source duplicate: REVIEW_REQUIRED
  - `src-tauri/gen/schemas/desktop-schema.json`
  - `src-tauri/gen/schemas/windows-schema.json`

### Duplicate group 2
- SHA256: `f68a9c570ecff07ac6826145d33b966d6fc02f7d680967f44437268b08a6ba78`
- Size: 116049 bytes
- Classification: source duplicate: REVIEW_REQUIRED
  - `AetherframeGuard/src-tauri/gen/schemas/desktop-schema.json`
  - `AetherframeGuard/src-tauri/gen/schemas/windows-schema.json`

### Duplicate group 3
- SHA256: `67bdaaaa85ac2035c178f827fe4804b96afa371a2e02cbfbe988f7b97776af61`
- Size: 92730 bytes
- Classification: docs duplicate: REVIEW_REQUIRED
  - `docs/assets/hexhawk-for-dummies/09-report-export.png`
  - `docs/assets/hexhawk-for-dummies/10-authority-fields.png`

### Duplicate group 4
- SHA256: `76ba34f111c7bd6967f4bb48ca4855c1dbf79a4975b874364ddb875ad93b2ba0`
- Size: 4525 bytes
- Classification: source duplicate: REVIEW_REQUIRED
  - `src-tauri/icons/ios/AppIcon-40x40@3x.png`
  - `src-tauri/icons/ios/AppIcon-60x60@2x.png`

### Duplicate group 5
- SHA256: `6af8655e1b3c60c7a84f65d36a3c75f2f1537f23f5dd131b146698b409f9cce1`
- Size: 3137 bytes
- Classification: source duplicate: REVIEW_REQUIRED
  - `src-tauri/icons/ios/AppIcon-40x40@2x-1.png`
  - `src-tauri/icons/ios/AppIcon-40x40@2x.png`

### Duplicate group 6
- SHA256: `abab23f3a894db84cd5310af20747f21abc3838503c9bf4501a9c2b23bd54062`
- Size: 2290 bytes
- Classification: source duplicate: REVIEW_REQUIRED
  - `src-tauri/icons/ios/AppIcon-29x29@2x-1.png`
  - `src-tauri/icons/ios/AppIcon-29x29@2x.png`

### Duplicate group 7
- SHA256: `e44299bd27819325c9e7e4b503c42b21848c516924974ddd6b1c6718587c02ba`
- Size: 2129 bytes
- Classification: release/site duplicate: NEVER_TOUCH_WITHOUT_APPROVAL
  - `site-build/trust/signatures/latest/signatures.json`
  - `site-build/trust/signatures/v1.0.0/signatures.json`

### Duplicate group 8
- SHA256: `d94d0ec1d090bd331bd369fe40e2f1d25832476a6c0fd8cae5a74f11fc35f2ba`
- Size: 1602 bytes
- Classification: source duplicate: REVIEW_REQUIRED
  - `src-tauri/icons/ios/AppIcon-20x20@2x-1.png`
  - `src-tauri/icons/ios/AppIcon-20x20@2x.png`
  - `src-tauri/icons/ios/AppIcon-40x40@1x.png`

### Duplicate group 9
- SHA256: `c9994fe172f68b939a8dc6f822dd3565a54d5719f5d24530b54943c29aae9f91`
- Size: 256 bytes
- Classification: release/site duplicate: NEVER_TOUCH_WITHOUT_APPROVAL
  - `site-build/trust/signatures/latest/HexHawk_1.0.0_x64-setup.exe.sig`
  - `site-build/trust/signatures/v1.0.0/HexHawk_1.0.0_x64-setup.exe.sig`

### Duplicate group 10
- SHA256: `941be0650e80606e7678e43dc883e05ea0e70130bd1f4772a38333d252adacb5`
- Size: 256 bytes
- Classification: release/site duplicate: NEVER_TOUCH_WITHOUT_APPROVAL
  - `site-build/trust/signatures/latest/HexHawk_1.0.0_x64_en-US.msi.sig`
  - `site-build/trust/signatures/v1.0.0/HexHawk_1.0.0_x64_en-US.msi.sig`

### Duplicate group 11
- SHA256: `e9c09835a10fc10f92fb5f6b8e179bd9bd8f0813f2193f85c239d6b2310338c9`
- Size: 256 bytes
- Classification: release/site duplicate: NEVER_TOUCH_WITHOUT_APPROVAL
  - `site-build/trust/signatures/latest/SHA256SUMS.txt.sig`
  - `site-build/trust/signatures/v1.0.0/SHA256SUMS.txt.sig`

## Duplicate deletion decisions
- No duplicate files are approved for deletion solely from this report. Generated/cache duplicates may be removed only when they are within reviewed generated/cache directories.
- Documentation, source, site public, release/trust, and evidence duplicates remain REVIEW_REQUIRED / NEVER_TOUCH_WITHOUT_APPROVAL as applicable.

## Orphan candidates
- `AetherframeGuard/src/App.js` — REVIEW_REQUIRED generated-adjacent tracked file; requires separate proof before source-hygiene removal.
- Ignored local corpora/adjacent projects (`Challenges/`, `nest_tests/`, `nexus-assistant/`) — REVIEW_REQUIRED; leave untouched unless user approves scope.
- No tracked non-cache orphan is approved for deletion in this pass.

## Cleanup recommendations
1. Add `_cleanup_quarantine/` and missing common local-cache/temp patterns to `.gitignore` without broadly ignoring docs/source/site-build.
2. Delete only obvious untracked ignored cache/build directories after preview: Python caches, Rust `target/`, Node `node_modules/`, frontend `dist/`, local virtualenv, generated release script scratch. Do not touch site-build release/trust endpoints.
3. Leave AetherFrameGuard `src/App.js` for a separate source-hygiene commit if proven safe.
4. Do not quarantine active source/tests/docs/release evidence. No uncertain tracked file is recommended for quarantine yet.

## Validation plan after cleanup
- `git status --porcelain=v1`
- `git diff --check`
- `yarn install`
- `yarn typecheck`
- `yarn test`
- `yarn build`
- `cargo test --workspace`
- `cd AetherframeGuard && npm --package-lock=false run build`
- `cargo test --manifest-path AetherframeGuard/src-tauri/Cargo.toml`
- `yarn workspace @hexhawk/aetherframe-core test`
- `yarn workspace @hexhawk/aetherframe-core build`

## Cleanup execution log

### Deleted as explicit reviewed ignored generated/cache output

These paths were untracked/ignored and were deleted after an existence/tracked check. No source, docs, tests, credentials, release evidence, or site-build trust/release endpoints were deleted.

- `.venv/` — local Python virtualenv.
- `AetherframeGuard/dist/` — reproducible frontend build output.
- `AetherframeGuard/src-tauri/target/` — Rust build output.
- `HexHawk/dist/` — reproducible frontend build output.
- `HexHawk/node_modules/` — dependency install output.
- `node_modules/` — dependency install output.
- `packages/aetherframe-core/dist/` — initially deleted as reproducible package build output, then regenerated because `yarn typecheck` currently requires `@hexhawk/aetherframe-core/browser`; final state: kept ignored/generated, not treated as removable in this pass.
- `packages/aetherframe-core/node_modules/` — dependency install output.
- `scripts/__pycache__/` — Python bytecode cache.
- `scripts/release/.generated/` — generated release-script scratch output.
- `target/` — Rust workspace build output.

### Explicitly left untouched

- `.vscode/` — local IDE config; ignored but not cleanup-critical.
- `Cargo.lock` and `AetherframeGuard/src-tauri/Cargo.lock` — ignored lockfiles; policy review required before any change.
- `Challenges/`, `nest_tests/`, `nexus-assistant/` — ignored local corpora/adjacent projects; REVIEW_REQUIRED.
- `site-build/releases/v1.0.0/assets/*.sig` — release-adjacent signatures; NEVER_TOUCH_WITHOUT_APPROVAL.
- `_cleanup_quarantine/2026-06-06/MANIFEST.md` — local ignored quarantine manifest; no quarantined files yet.

### Quarantine status

No files were moved to quarantine in this pass. No uncertain active source/docs/tests/release evidence were moved.

### Validation correction

Initial validation failed at `yarn typecheck` because deleting `packages/aetherframe-core/dist/` removed the generated `@hexhawk/aetherframe-core/browser` entry consumed by the HexHawk UI. The cleanup candidate was undone by running `yarn workspace @hexhawk/aetherframe-core build`, regenerating the ignored dist output. This path remains generated, but it is required by the current workspace validation order and should not be deleted in general cleanup unless the package/build wiring is changed first.

### Final cleanup state after validation

The required validation commands regenerated several ignored build/dependency outputs. Final actually-removed local paths are:

- `.venv/` — local Python virtualenv; remains removed.
- `scripts/__pycache__/` — Python bytecode cache; remains removed.
- `scripts/release/.generated/` — release-script generated scratch output; remains removed.

The following reviewed generated outputs were deleted, then regenerated by install/build/test validation and therefore remain present as ignored local build/dependency state:

- `node_modules/`
- `HexHawk/node_modules/`
- `packages/aetherframe-core/node_modules/`
- `HexHawk/dist/`
- `AetherframeGuard/dist/`
- `target/`
- `AetherframeGuard/src-tauri/target/`
- `packages/aetherframe-core/dist/`

No tracked generated/cache file was removed. No release/trust/site-build endpoint was changed.
