# AetherFrame Dirty Worktree Decommission Plan

Generated: 2026-07-01 20:17:49

Status: read-only custody/decommission planning. No cleanup execution, movement, compression, deployment, publishing, cleaning, or git worktree unregistration was performed.

Authority note: GYRE remains the sole HexHawk verdict/classification authority. AetherFrame is advisory custody-planning support only.

## Summary

- Starting HEAD: `66a8e7e`.
- Dirty registered worktrees inspected: 9.
- Total dirty registered worktree size: **57.23 GB**.
- Main repo was otherwise clean except for untracked `docs/aetherframe-runs/factory-cycle-20260701-195521.md`.

## Custody Table

| Path | Size GB | HEAD | Reachable | Dirty Type | Unique Source? | Evidence? | Artifacts? | Risk | Recommendation |
|---|---:|---|---|---|---|---|---|---|---|
| `D:/Project/HexHawk-ai-overhaul-gate-20260627` | 7.05 | `d2a7d3f` | main=yes; origin=yes; tags=8 | EVIDENCE_ONLY; Yarn install state, generated Tauri schemas, line-ending/status noise in snapshots, line-ending/status noise in Cargo.toml | no | yes | yes | Medium | REMOVED_AFTER_EVIDENCE_PRESERVATION |
| `D:/Project/HexHawk-release-candidate-v2.1-20260627-190731` | 6.95 | `ad8e3cf` | main=yes; origin=yes; tags=19 | EVIDENCE_ONLY; Yarn install state, generated Tauri schemas, line-ending/status noise in snapshots, line-ending/status noise in Cargo.toml | no | yes | yes | Medium | REMOVED_AFTER_EVIDENCE_PRESERVATION |
| `D:/Project/HexHawk-ai-overhaul-gate` | 6.82 | `8947ab6` | main=yes; origin=yes; tags=8 | EVIDENCE_ONLY; Yarn install state, generated Tauri schemas, line-ending/status noise in snapshots, line-ending/status noise in Cargo.toml | no | yes | yes | Medium | REMOVED_AFTER_EVIDENCE_PRESERVATION |
| `D:/Project/HexHawk-release-candidate-v2.1-20260627-194604` | 6.82 | `6ae9f2b` | main=yes; origin=yes; tags=18 | EVIDENCE_ONLY; Yarn install state, generated Tauri schemas, line-ending/status noise in snapshots, line-ending/status noise in Cargo.toml | no | yes | yes | Medium | REMOVED_AFTER_EVIDENCE_PRESERVATION |
| `D:/Project/HexHawk-release-candidate-v2.1-20260627-133346` | 6.82 | `5c6d814` | main=yes; origin=yes; tags=21 | EVIDENCE_ONLY; Yarn install state, generated Tauri schemas, line-ending/status noise in snapshots, line-ending/status noise in Cargo.toml | no | yes | yes | Medium | REMOVED_AFTER_EVIDENCE_PRESERVATION |
| `D:/Project/HexHawk-release-candidate-v2.1-20260627-151143` | 6.82 | `e677543` | main=yes; origin=yes; tags=20 | EVIDENCE_ONLY; Yarn install state, generated Tauri schemas, line-ending/status noise in snapshots, line-ending/status noise in Cargo.toml | no | yes | yes | Medium | REMOVED_AFTER_EVIDENCE_PRESERVATION |
| `D:/Project/HexHawk-release-candidate-v2.0-20260627-122322` | 6.81 | `3310d0c` | main=yes; origin=yes; tags=28 | EVIDENCE_ONLY; Yarn install state, generated Tauri schemas, line-ending/status noise in snapshots, line-ending/status noise in Cargo.toml | no | yes | yes | Medium | REMOVED_AFTER_EVIDENCE_PRESERVATION |
| `D:/Project/HexHawk-rc-20260626-192557` | 6.81 | `3bbf1ac` | main=yes; origin=yes; tags=29 | SOURCE_CHANGES_PRESENT; Yarn install state, generated Tauri schemas, line-ending/status noise in snapshots, line-ending/status noise in Cargo.toml, untracked helper scripts | yes | yes | yes | High | NEEDS_SOURCE_REVIEW |
| `D:/Project/HexHawk-release-candidate-currenthead-postfeatures-20260621-123026` | 2.32 | `ad2e752` | main=yes; origin=yes; tags=52 | EVIDENCE_ONLY; Yarn install state, generated Tauri schemas, line-ending/status noise in snapshots, line-ending/status noise in Cargo.toml | no | yes | yes | Medium | REMOVED_AFTER_EVIDENCE_PRESERVATION |

## Key finding

Eight of nine worktrees have no content-changing source diff beyond `.yarn/install-state.gz` and generated `src-tauri/gen/schemas/*.json`; their apparent Cargo.toml/snapshot dirt is line-ending/status noise. They still contain release/evidence/artifact provenance, so they belong in W2, not immediate W1. `D:/Project/HexHawk-rc-20260626-192557` additionally has untracked helper scripts and therefore remains W3/source-review first.

## Per-worktree findings

### `D:/Project/HexHawk-ai-overhaul-gate`
- Size / modified: 6.82 GB / 2026-06-29 18:50:19
- Branch/HEAD: `(detached HEAD)` / `8947ab61bfcd6dc87d19893c4448a249dbabb821`
- Reachability: main=yes, origin/main=yes, tags=v2.1.13-aetherframe-factory-integration, v2.1.14-workspace-cleanup-classification, v2.1.4-ai-workflow-cdp-probe, v2.1.5-competitive-landscape-current-posture, v2.1.6-aetherframe-factory-docs, v2.1.7-aetherframe-factory-cycle-reporter, v2.1.8-unsigned-early-access-packaging, v2.1.9-unsigned-early-access-packaging
- Classification: **B. EVIDENCE_ONLY**
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Actual dirty content appears generated/status noise, but release/evidence/artifact provenance exists and should be summarized before approval-based worktree removal.
- Dirty categories: Yarn install state, generated Tauri schemas, line-ending/status noise in snapshots, line-ending/status noise in Cargo.toml
- Actual content-changing diff paths: .yarn/install-state.gz, src-tauri/gen/schemas/acl-manifests.json, src-tauri/gen/schemas/desktop-schema.json, src-tauri/gen/schemas/windows-schema.json
- Status-only line-ending/no-content paths: yarn/install-state.gz, HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap, HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap, src-tauri/Cargo.toml
- Untracked files: none
- Unique commits not on main: 0
- Recent log:
```text
8947ab6 [AI] Clarify Agent Gate note-only boundary
d2a7d3f [AI] Stabilize AI workflow state wiring
dac9926 [AI] Wire AI observations into analysis workflow
70a553c [QA] Keep Rust test helpers clippy-clean
6e57de5 [AI] Add AI features explanation to Help panel
```
- `git status --short`:
```text
M .yarn/install-state.gz
 M HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap
 M HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap
 M src-tauri/Cargo.toml
 M src-tauri/gen/schemas/acl-manifests.json
 M src-tauri/gen/schemas/desktop-schema.json
 M src-tauri/gen/schemas/windows-schema.json
```
- `git diff --stat`:
```text
.yarn/install-state.gz                    | Bin 360196 -> 364283 bytes
 src-tauri/gen/schemas/acl-manifests.json  |   2 +-
 src-tauri/gen/schemas/desktop-schema.json |  60 +++++++++++++++++++++++++++---
 src-tauri/gen/schemas/windows-schema.json |  60 +++++++++++++++++++++++++++---
 4 files changed, 109 insertions(+), 13 deletions(-)
```
- Evidence/artifact counts: named evidence=1, release markdown=8, screenshots=15, MSI/setup/zip=5.
| Kind | Relative path | Size | Modified | SHA256 / equivalence |
|---|---|---:|---|---|
| md | `docs/HEXHAWK_FOR_DUMMIES_VALIDATION_REPORT.md` | 11676 | 2026-06-29 18:36:58 | 2ed366eb2f139965… / hash match in main: docs/HEXHAWK_FOR_DUMMIES_VALIDATION_REPORT.md |
| md | `docs/nest_evidence_contract_status.md` | 8222 | 2026-06-29 18:36:58 | 62703cd3edab0580… / hash match in main: docs/nest_evidence_contract_status.md |
| md | `docs/nest_evidence_examples.md` | 20128 | 2026-06-29 18:36:58 | 8ed46a5e726afd5f… / hash match in main: docs/nest_evidence_examples.md |
| md | `docs/nest_evidence_integration_status.md` | 3591 | 2026-06-29 18:36:58 | 2ba8da12f7c64eff… / hash match in main: docs/nest_evidence_integration_status.md |
| md | `docs/nest_evidence_schema_spec.md` | 26856 | 2026-06-29 18:36:58 | c20835001116d4ff… / hash match in main: docs/nest_evidence_schema_spec.md |
| md | `docs/RELEASE_SIGNING_AND_UPDATER_PLAN.md` | 4476 | 2026-06-29 18:36:58 | 87e42b8b0e9abaf9… / hash match in main: docs/RELEASE_SIGNING_AND_UPDATER_PLAN.md |
| md | `docs/RELEASE_VALIDATION_2026-06-01.md` | 4347 | 2026-06-29 18:36:58 | e92af9bb50a0316c… / hash match in main: docs/RELEASE_VALIDATION_2026-06-01.md |
| md | `docs/TESTER_RELEASE_STATUS.md` | 3389 | 2026-06-29 18:36:58 | a11a42bfdda29d25… / hash match in main: docs/TESTER_RELEASE_STATUS.md |
| evidence | `site-build/releases/v1.0.0/SHA256SUMS.txt` | 190 | 2026-06-29 18:36:58 | eb0d101f79989778… / hash match in main: site-build/releases/v1.0.0/SHA256SUMS.txt |
| artifact | `site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe` | 14881361 | 2026-06-29 18:36:58 | fae7b573054a3938… / hash match in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe |
| artifact | `site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi` | 21291008 | 2026-06-29 18:36:58 | 0b6a8e885accd45b… / hash match in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi |
| artifact | `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi` | 21348352 | 2026-06-29 18:48:40 | f4d7cf447793ea61… / same basename in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi |
| artifact | `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe` | 14941686 | 2026-06-29 18:49:07 | a633ade56e0d581f… / same basename in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe |
| artifact | `target/release/wix/x64/MicrosoftEdgeWebview2Setup.exe` | 1688792 | 2026-06-29 18:48:32 | f91077e2c116dcf6… / not matched in main |
| png | `docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png` | 77337 | 2026-06-29 18:36:58 |  / same basename in main: docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png |
| png | `docs/assets/hexhawk-for-dummies/01-launch-home.png` | 161259 | 2026-06-29 18:36:58 |  / same basename in main: docs/assets/hexhawk-for-dummies/01-launch-home.png |
| png | `docs/assets/hexhawk-for-dummies/02-open-safe-sample.png` | 58333 | 2026-06-29 18:36:58 |  / same basename in main: docs/assets/hexhawk-for-dummies/02-open-safe-sample.png |
| png | `docs/assets/hexhawk-for-dummies/03-analysis-workspace.png` | 49084 | 2026-06-29 18:36:58 |  / same basename in main: docs/assets/hexhawk-for-dummies/03-analysis-workspace.png |
| png | `docs/assets/hexhawk-for-dummies/04-strings-view.png` | 53920 | 2026-06-29 18:36:58 |  / same basename in main: docs/assets/hexhawk-for-dummies/04-strings-view.png |
| png | `docs/assets/hexhawk-for-dummies/05-disassembly-view.png` | 57462 | 2026-06-29 18:36:58 |  / same basename in main: docs/assets/hexhawk-for-dummies/05-disassembly-view.png |
| png | `docs/assets/hexhawk-for-dummies/06-gyre-verdict.png` | 68078 | 2026-06-29 18:36:58 |  / same basename in main: docs/assets/hexhawk-for-dummies/06-gyre-verdict.png |
| png | `docs/assets/hexhawk-for-dummies/07-nest-evidence.png` | 73962 | 2026-06-29 18:36:58 |  / same basename in main: docs/assets/hexhawk-for-dummies/07-nest-evidence.png |

### `D:/Project/HexHawk-ai-overhaul-gate-20260627`
- Size / modified: 7.05 GB / 2026-06-27 23:50:29
- Branch/HEAD: `(detached HEAD)` / `d2a7d3f2b89307705e8b656b2b1c8f42c3d2f158`
- Reachability: main=yes, origin/main=yes, tags=v2.1.13-aetherframe-factory-integration, v2.1.14-workspace-cleanup-classification, v2.1.4-ai-workflow-cdp-probe, v2.1.5-competitive-landscape-current-posture, v2.1.6-aetherframe-factory-docs, v2.1.7-aetherframe-factory-cycle-reporter, v2.1.8-unsigned-early-access-packaging, v2.1.9-unsigned-early-access-packaging
- Classification: **B. EVIDENCE_ONLY**
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Actual dirty content appears generated/status noise, but release/evidence/artifact provenance exists and should be summarized before approval-based worktree removal.
- Dirty categories: Yarn install state, generated Tauri schemas, line-ending/status noise in snapshots, line-ending/status noise in Cargo.toml
- Actual content-changing diff paths: .yarn/install-state.gz, src-tauri/gen/schemas/acl-manifests.json, src-tauri/gen/schemas/desktop-schema.json, src-tauri/gen/schemas/windows-schema.json
- Status-only line-ending/no-content paths: yarn/install-state.gz, HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap, HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap, src-tauri/Cargo.toml
- Untracked files: none
- Unique commits not on main: 0
- Recent log:
```text
d2a7d3f [AI] Stabilize AI workflow state wiring
dac9926 [AI] Wire AI observations into analysis workflow
70a553c [QA] Keep Rust test helpers clippy-clean
6e57de5 [AI] Add AI features explanation to Help panel
ed5178a [AI] Add contextual analyst question prompts
```
- `git status --short`:
```text
M .yarn/install-state.gz
 M HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap
 M HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap
 M src-tauri/Cargo.toml
 M src-tauri/gen/schemas/acl-manifests.json
 M src-tauri/gen/schemas/desktop-schema.json
 M src-tauri/gen/schemas/windows-schema.json
```
- `git diff --stat`:
```text
.yarn/install-state.gz                    | Bin 360196 -> 364281 bytes
 src-tauri/gen/schemas/acl-manifests.json  |   2 +-
 src-tauri/gen/schemas/desktop-schema.json |  60 +++++++++++++++++++++++++++---
 src-tauri/gen/schemas/windows-schema.json |  60 +++++++++++++++++++++++++++---
 4 files changed, 109 insertions(+), 13 deletions(-)
```
- Evidence/artifact counts: named evidence=1, release markdown=8, screenshots=15, MSI/setup/zip=5.
| Kind | Relative path | Size | Modified | SHA256 / equivalence |
|---|---|---:|---|---|
| md | `docs/HEXHAWK_FOR_DUMMIES_VALIDATION_REPORT.md` | 11676 | 2026-06-27 23:16:41 | 2ed366eb2f139965… / hash match in main: docs/HEXHAWK_FOR_DUMMIES_VALIDATION_REPORT.md |
| md | `docs/nest_evidence_contract_status.md` | 8222 | 2026-06-27 23:16:41 | 62703cd3edab0580… / hash match in main: docs/nest_evidence_contract_status.md |
| md | `docs/nest_evidence_examples.md` | 20128 | 2026-06-27 23:16:41 | 8ed46a5e726afd5f… / hash match in main: docs/nest_evidence_examples.md |
| md | `docs/nest_evidence_integration_status.md` | 3591 | 2026-06-27 23:16:41 | 2ba8da12f7c64eff… / hash match in main: docs/nest_evidence_integration_status.md |
| md | `docs/nest_evidence_schema_spec.md` | 26856 | 2026-06-27 23:16:41 | c20835001116d4ff… / hash match in main: docs/nest_evidence_schema_spec.md |
| md | `docs/RELEASE_SIGNING_AND_UPDATER_PLAN.md` | 4476 | 2026-06-27 23:16:41 | 87e42b8b0e9abaf9… / hash match in main: docs/RELEASE_SIGNING_AND_UPDATER_PLAN.md |
| md | `docs/RELEASE_VALIDATION_2026-06-01.md` | 4347 | 2026-06-27 23:16:41 | e92af9bb50a0316c… / hash match in main: docs/RELEASE_VALIDATION_2026-06-01.md |
| md | `docs/TESTER_RELEASE_STATUS.md` | 3389 | 2026-06-27 23:16:41 | a11a42bfdda29d25… / hash match in main: docs/TESTER_RELEASE_STATUS.md |
| evidence | `site-build/releases/v1.0.0/SHA256SUMS.txt` | 190 | 2026-06-27 23:16:41 | eb0d101f79989778… / hash match in main: site-build/releases/v1.0.0/SHA256SUMS.txt |
| artifact | `site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe` | 14881361 | 2026-06-27 23:16:41 | fae7b573054a3938… / hash match in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe |
| artifact | `site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi` | 21291008 | 2026-06-27 23:16:41 | 0b6a8e885accd45b… / hash match in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi |
| artifact | `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi` | 21348352 | 2026-06-27 23:49:55 | 2b71e3b57e8a44dd… / same basename in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi |
| artifact | `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe` | 14939734 | 2026-06-27 23:50:29 | 504ab94c7f754809… / same basename in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe |
| artifact | `target/release/wix/x64/MicrosoftEdgeWebview2Setup.exe` | 1688792 | 2026-06-27 23:49:47 | f91077e2c116dcf6… / not matched in main |
| png | `docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png` | 77337 | 2026-06-27 23:16:41 |  / same basename in main: docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png |
| png | `docs/assets/hexhawk-for-dummies/01-launch-home.png` | 161259 | 2026-06-27 23:16:41 |  / same basename in main: docs/assets/hexhawk-for-dummies/01-launch-home.png |
| png | `docs/assets/hexhawk-for-dummies/02-open-safe-sample.png` | 58333 | 2026-06-27 23:16:41 |  / same basename in main: docs/assets/hexhawk-for-dummies/02-open-safe-sample.png |
| png | `docs/assets/hexhawk-for-dummies/03-analysis-workspace.png` | 49084 | 2026-06-27 23:16:41 |  / same basename in main: docs/assets/hexhawk-for-dummies/03-analysis-workspace.png |
| png | `docs/assets/hexhawk-for-dummies/04-strings-view.png` | 53920 | 2026-06-27 23:16:41 |  / same basename in main: docs/assets/hexhawk-for-dummies/04-strings-view.png |
| png | `docs/assets/hexhawk-for-dummies/05-disassembly-view.png` | 57462 | 2026-06-27 23:16:41 |  / same basename in main: docs/assets/hexhawk-for-dummies/05-disassembly-view.png |
| png | `docs/assets/hexhawk-for-dummies/06-gyre-verdict.png` | 68078 | 2026-06-27 23:16:41 |  / same basename in main: docs/assets/hexhawk-for-dummies/06-gyre-verdict.png |
| png | `docs/assets/hexhawk-for-dummies/07-nest-evidence.png` | 73962 | 2026-06-27 23:16:41 |  / same basename in main: docs/assets/hexhawk-for-dummies/07-nest-evidence.png |

### `D:/Project/HexHawk-rc-20260626-192557`
- Size / modified: 6.81 GB / 2026-06-26 19:41:21
- Branch/HEAD: `(detached HEAD)` / `3bbf1ac92273c1024b12db1da6b3e80b2d3be326`
- Reachability: main=yes, origin/main=yes, tags=v1.32.0-docs-function-intelligence-status, v1.33.0-nest-cli-help-exit, v2.0.0-unsigned-deployment-candidate-20260627, v2.1.0-function-intelligence-correlation, v2.1.0-unsigned-deployment-candidate-20260627, v2.1.1-function-intelligence-export-correlation-basis, v2.1.13-aetherframe-factory-integration, v2.1.14-workspace-cleanup-classification ...
- Classification: **C. SOURCE_CHANGES_PRESENT**
- Recommendation: **NEEDS_SOURCE_REVIEW** — Untracked helper scripts, unique commits, or actual source/config content changes require review.
- Dirty categories: Yarn install state, generated Tauri schemas, line-ending/status noise in snapshots, line-ending/status noise in Cargo.toml, untracked helper scripts
- Actual content-changing diff paths: .yarn/install-state.gz, src-tauri/gen/schemas/acl-manifests.json, src-tauri/gen/schemas/desktop-schema.json, src-tauri/gen/schemas/windows-schema.json
- Status-only line-ending/no-content paths: yarn/install-state.gz, HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap, HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap, src-tauri/Cargo.toml
- Untracked files: check-authenticode.ps1, installer-smoke.ps1
- Unique commits not on main: 0
- Recent log:
```text
3bbf1ac [DOCS] Update workbench status to Function Intelligence candidate
bce625e [PLUGINS] Fix byte_counter C string metadata
4ed0c54 [INTEL] Add FunctionIntelligence regression corpus
a4e7d0b [INTEL] Wire Function Notebook into main app workflow
4ddacd4 [UI] Add Function Notebook panel
```
- `git status --short`:
```text
M .yarn/install-state.gz
 M HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap
 M HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap
 M src-tauri/Cargo.toml
 M src-tauri/gen/schemas/acl-manifests.json
 M src-tauri/gen/schemas/desktop-schema.json
 M src-tauri/gen/schemas/windows-schema.json
?? check-authenticode.ps1
?? installer-smoke.ps1
```
- `git diff --stat`:
```text
.yarn/install-state.gz                    | Bin 360196 -> 363986 bytes
 src-tauri/gen/schemas/acl-manifests.json  |   2 +-
 src-tauri/gen/schemas/desktop-schema.json |  60 +++++++++++++++++++++++++++---
 src-tauri/gen/schemas/windows-schema.json |  60 +++++++++++++++++++++++++++---
 4 files changed, 109 insertions(+), 13 deletions(-)
```
- Evidence/artifact counts: named evidence=1, release markdown=8, screenshots=15, MSI/setup/zip=5.
| Kind | Relative path | Size | Modified | SHA256 / equivalence |
|---|---|---:|---|---|
| md | `docs/HEXHAWK_FOR_DUMMIES_VALIDATION_REPORT.md` | 11676 | 2026-06-26 19:25:57 | 2ed366eb2f139965… / hash match in main: docs/HEXHAWK_FOR_DUMMIES_VALIDATION_REPORT.md |
| md | `docs/nest_evidence_contract_status.md` | 8222 | 2026-06-26 19:25:57 | 62703cd3edab0580… / hash match in main: docs/nest_evidence_contract_status.md |
| md | `docs/nest_evidence_examples.md` | 20128 | 2026-06-26 19:25:57 | 8ed46a5e726afd5f… / hash match in main: docs/nest_evidence_examples.md |
| md | `docs/nest_evidence_integration_status.md` | 3591 | 2026-06-26 19:25:57 | 2ba8da12f7c64eff… / hash match in main: docs/nest_evidence_integration_status.md |
| md | `docs/nest_evidence_schema_spec.md` | 26856 | 2026-06-26 19:25:57 | c20835001116d4ff… / hash match in main: docs/nest_evidence_schema_spec.md |
| md | `docs/RELEASE_SIGNING_AND_UPDATER_PLAN.md` | 4476 | 2026-06-26 19:25:57 | 87e42b8b0e9abaf9… / hash match in main: docs/RELEASE_SIGNING_AND_UPDATER_PLAN.md |
| md | `docs/RELEASE_VALIDATION_2026-06-01.md` | 4347 | 2026-06-26 19:25:57 | e92af9bb50a0316c… / hash match in main: docs/RELEASE_VALIDATION_2026-06-01.md |
| md | `docs/TESTER_RELEASE_STATUS.md` | 3389 | 2026-06-26 19:25:57 | a11a42bfdda29d25… / hash match in main: docs/TESTER_RELEASE_STATUS.md |
| evidence | `site-build/releases/v1.0.0/SHA256SUMS.txt` | 190 | 2026-06-26 19:25:57 | eb0d101f79989778… / hash match in main: site-build/releases/v1.0.0/SHA256SUMS.txt |
| artifact | `site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe` | 14881361 | 2026-06-26 19:25:57 | fae7b573054a3938… / hash match in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe |
| artifact | `site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi` | 21291008 | 2026-06-26 19:25:57 | 0b6a8e885accd45b… / hash match in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi |
| artifact | `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi` | 21327872 | 2026-06-26 19:38:20 | 81da3c7cbc55875a… / same basename in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi |
| artifact | `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe` | 14932567 | 2026-06-26 19:38:47 | e1571ac658eeaced… / same basename in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe |
| artifact | `target/release/wix/x64/MicrosoftEdgeWebview2Setup.exe` | 1688792 | 2026-06-26 19:38:13 | f91077e2c116dcf6… / not matched in main |
| png | `docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png` | 77337 | 2026-06-26 19:25:57 |  / same basename in main: docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png |
| png | `docs/assets/hexhawk-for-dummies/01-launch-home.png` | 161259 | 2026-06-26 19:25:57 |  / same basename in main: docs/assets/hexhawk-for-dummies/01-launch-home.png |
| png | `docs/assets/hexhawk-for-dummies/02-open-safe-sample.png` | 58333 | 2026-06-26 19:25:57 |  / same basename in main: docs/assets/hexhawk-for-dummies/02-open-safe-sample.png |
| png | `docs/assets/hexhawk-for-dummies/03-analysis-workspace.png` | 49084 | 2026-06-26 19:25:57 |  / same basename in main: docs/assets/hexhawk-for-dummies/03-analysis-workspace.png |
| png | `docs/assets/hexhawk-for-dummies/04-strings-view.png` | 53920 | 2026-06-26 19:25:57 |  / same basename in main: docs/assets/hexhawk-for-dummies/04-strings-view.png |
| png | `docs/assets/hexhawk-for-dummies/05-disassembly-view.png` | 57462 | 2026-06-26 19:25:57 |  / same basename in main: docs/assets/hexhawk-for-dummies/05-disassembly-view.png |
| png | `docs/assets/hexhawk-for-dummies/06-gyre-verdict.png` | 68078 | 2026-06-26 19:25:57 |  / same basename in main: docs/assets/hexhawk-for-dummies/06-gyre-verdict.png |
| png | `docs/assets/hexhawk-for-dummies/07-nest-evidence.png` | 73962 | 2026-06-26 19:25:57 |  / same basename in main: docs/assets/hexhawk-for-dummies/07-nest-evidence.png |

### `D:/Project/HexHawk-release-candidate-currenthead-postfeatures-20260621-123026`
- Size / modified: 2.32 GB / 2026-06-21 12:37:31
- Branch/HEAD: `(detached HEAD)` / `ad2e7522dfad286180bfed2d15887749dca9194c`
- Reachability: main=yes, origin/main=yes, tags=v1.10.0-strike-headless-batch, v1.11.0-gyre-midlevel-ir, v1.12.0-nest-type-propagation, v1.13.0-nest-struct-recovery, v1.14.0-talon-output-modes, v1.15.0-strike-plugin-hooks, v1.17.0-disasm-pe-imports, v1.18.0-disasm-xref-index ...
- Classification: **B. EVIDENCE_ONLY**
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Actual dirty content appears generated/status noise, but release/evidence/artifact provenance exists and should be summarized before approval-based worktree removal.
- Dirty categories: Yarn install state, generated Tauri schemas, line-ending/status noise in snapshots, line-ending/status noise in Cargo.toml
- Actual content-changing diff paths: .yarn/install-state.gz, src-tauri/gen/schemas/acl-manifests.json, src-tauri/gen/schemas/desktop-schema.json, src-tauri/gen/schemas/windows-schema.json
- Status-only line-ending/no-content paths: yarn/install-state.gz, HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap, HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap, src-tauri/Cargo.toml
- Untracked files: none
- Unique commits not on main: 0
- Recent log:
```text
ad2e752 [STRIKE] Add IL opcode-tree pattern matching API
3bc62d5 [TALON] Recover switch statements from jump-tables and if-chains
9f83831 [NEST] Add Win32/libc import prototype resolution
767c419 [TALON] Coalesce SSA variables to named locals
c383316 [TALON] Implement control-flow structuring for reducible CFGs
```
- `git status --short`:
```text
M .yarn/install-state.gz
 M HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap
 M HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap
 M src-tauri/Cargo.toml
 M src-tauri/gen/schemas/acl-manifests.json
 M src-tauri/gen/schemas/desktop-schema.json
 M src-tauri/gen/schemas/windows-schema.json
```
- `git diff --stat`:
```text
.yarn/install-state.gz                    | Bin 360196 -> 363986 bytes
 src-tauri/gen/schemas/acl-manifests.json  |   2 +-
 src-tauri/gen/schemas/desktop-schema.json |  60 +++++++++++++++++++++++++++---
 src-tauri/gen/schemas/windows-schema.json |  60 +++++++++++++++++++++++++++---
 4 files changed, 109 insertions(+), 13 deletions(-)
```
- Evidence/artifact counts: named evidence=1, release markdown=8, screenshots=15, MSI/setup/zip=5.
| Kind | Relative path | Size | Modified | SHA256 / equivalence |
|---|---|---:|---|---|
| md | `docs/HEXHAWK_FOR_DUMMIES_VALIDATION_REPORT.md` | 11676 | 2026-06-21 12:30:26 | 2ed366eb2f139965… / hash match in main: docs/HEXHAWK_FOR_DUMMIES_VALIDATION_REPORT.md |
| md | `docs/nest_evidence_contract_status.md` | 8222 | 2026-06-21 12:30:26 | 62703cd3edab0580… / hash match in main: docs/nest_evidence_contract_status.md |
| md | `docs/nest_evidence_examples.md` | 20128 | 2026-06-21 12:30:26 | 8ed46a5e726afd5f… / hash match in main: docs/nest_evidence_examples.md |
| md | `docs/nest_evidence_integration_status.md` | 3591 | 2026-06-21 12:30:26 | 2ba8da12f7c64eff… / hash match in main: docs/nest_evidence_integration_status.md |
| md | `docs/nest_evidence_schema_spec.md` | 26856 | 2026-06-21 12:30:26 | c20835001116d4ff… / hash match in main: docs/nest_evidence_schema_spec.md |
| md | `docs/RELEASE_SIGNING_AND_UPDATER_PLAN.md` | 4476 | 2026-06-21 12:30:26 | 87e42b8b0e9abaf9… / hash match in main: docs/RELEASE_SIGNING_AND_UPDATER_PLAN.md |
| md | `docs/RELEASE_VALIDATION_2026-06-01.md` | 4347 | 2026-06-21 12:30:26 | e92af9bb50a0316c… / hash match in main: docs/RELEASE_VALIDATION_2026-06-01.md |
| md | `docs/TESTER_RELEASE_STATUS.md` | 4280 | 2026-06-21 12:30:26 | 67a2c44b79ed21ee… / same basename in main: docs/TESTER_RELEASE_STATUS.md |
| evidence | `site-build/releases/v1.0.0/SHA256SUMS.txt` | 190 | 2026-06-21 12:30:27 | eb0d101f79989778… / hash match in main: site-build/releases/v1.0.0/SHA256SUMS.txt |
| artifact | `site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe` | 14881361 | 2026-06-21 12:30:27 | fae7b573054a3938… / hash match in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe |
| artifact | `site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi` | 21291008 | 2026-06-21 12:30:27 | 0b6a8e885accd45b… / hash match in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi |
| artifact | `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi` | 21299200 | 2026-06-21 12:37:02 | 042f671cdcfa357d… / same basename in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi |
| artifact | `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe` | 14903903 | 2026-06-21 12:37:31 | 9ed2196b34eb5e95… / same basename in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe |
| artifact | `target/release/wix/x64/MicrosoftEdgeWebview2Setup.exe` | 1688792 | 2026-06-21 12:36:54 | f91077e2c116dcf6… / not matched in main |
| png | `docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png` | 77337 | 2026-06-21 12:30:26 |  / same basename in main: docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png |
| png | `docs/assets/hexhawk-for-dummies/01-launch-home.png` | 161259 | 2026-06-21 12:30:26 |  / same basename in main: docs/assets/hexhawk-for-dummies/01-launch-home.png |
| png | `docs/assets/hexhawk-for-dummies/02-open-safe-sample.png` | 58333 | 2026-06-21 12:30:26 |  / same basename in main: docs/assets/hexhawk-for-dummies/02-open-safe-sample.png |
| png | `docs/assets/hexhawk-for-dummies/03-analysis-workspace.png` | 49084 | 2026-06-21 12:30:26 |  / same basename in main: docs/assets/hexhawk-for-dummies/03-analysis-workspace.png |
| png | `docs/assets/hexhawk-for-dummies/04-strings-view.png` | 53920 | 2026-06-21 12:30:26 |  / same basename in main: docs/assets/hexhawk-for-dummies/04-strings-view.png |
| png | `docs/assets/hexhawk-for-dummies/05-disassembly-view.png` | 57462 | 2026-06-21 12:30:26 |  / same basename in main: docs/assets/hexhawk-for-dummies/05-disassembly-view.png |
| png | `docs/assets/hexhawk-for-dummies/06-gyre-verdict.png` | 68078 | 2026-06-21 12:30:26 |  / same basename in main: docs/assets/hexhawk-for-dummies/06-gyre-verdict.png |
| png | `docs/assets/hexhawk-for-dummies/07-nest-evidence.png` | 73962 | 2026-06-21 12:30:26 |  / same basename in main: docs/assets/hexhawk-for-dummies/07-nest-evidence.png |

### `D:/Project/HexHawk-release-candidate-v2.0-20260627-122322`
- Size / modified: 6.81 GB / 2026-06-27 12:37:04
- Branch/HEAD: `(detached HEAD)` / `3310d0cb67e39ce67bccb9279e3fc89a83bee7cc`
- Reachability: main=yes, origin/main=yes, tags=v1.33.0-nest-cli-help-exit, v2.0.0-unsigned-deployment-candidate-20260627, v2.1.0-function-intelligence-correlation, v2.1.0-unsigned-deployment-candidate-20260627, v2.1.1-function-intelligence-export-correlation-basis, v2.1.13-aetherframe-factory-integration, v2.1.14-workspace-cleanup-classification, v2.1.2-installer-smoke-window-proof ...
- Classification: **B. EVIDENCE_ONLY**
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Actual dirty content appears generated/status noise, but release/evidence/artifact provenance exists and should be summarized before approval-based worktree removal.
- Dirty categories: Yarn install state, generated Tauri schemas, line-ending/status noise in snapshots, line-ending/status noise in Cargo.toml
- Actual content-changing diff paths: .yarn/install-state.gz, src-tauri/gen/schemas/acl-manifests.json, src-tauri/gen/schemas/desktop-schema.json, src-tauri/gen/schemas/windows-schema.json
- Status-only line-ending/no-content paths: yarn/install-state.gz, HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap, HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap, src-tauri/Cargo.toml
- Untracked files: none
- Unique commits not on main: 0
- Recent log:
```text
3310d0c [STRIKE] Fix nest_cli help exit behavior
3bbf1ac [DOCS] Update workbench status to Function Intelligence candidate
bce625e [PLUGINS] Fix byte_counter C string metadata
4ed0c54 [INTEL] Add FunctionIntelligence regression corpus
a4e7d0b [INTEL] Wire Function Notebook into main app workflow
```
- `git status --short`:
```text
M .yarn/install-state.gz
 M HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap
 M HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap
 M src-tauri/Cargo.toml
 M src-tauri/gen/schemas/acl-manifests.json
 M src-tauri/gen/schemas/desktop-schema.json
 M src-tauri/gen/schemas/windows-schema.json
```
- `git diff --stat`:
```text
.yarn/install-state.gz                    | Bin 360196 -> 363986 bytes
 src-tauri/gen/schemas/acl-manifests.json  |   2 +-
 src-tauri/gen/schemas/desktop-schema.json |  60 +++++++++++++++++++++++++++---
 src-tauri/gen/schemas/windows-schema.json |  60 +++++++++++++++++++++++++++---
 4 files changed, 109 insertions(+), 13 deletions(-)
```
- Evidence/artifact counts: named evidence=1, release markdown=8, screenshots=15, MSI/setup/zip=5.
| Kind | Relative path | Size | Modified | SHA256 / equivalence |
|---|---|---:|---|---|
| md | `docs/HEXHAWK_FOR_DUMMIES_VALIDATION_REPORT.md` | 11676 | 2026-06-27 12:23:22 | 2ed366eb2f139965… / hash match in main: docs/HEXHAWK_FOR_DUMMIES_VALIDATION_REPORT.md |
| md | `docs/nest_evidence_contract_status.md` | 8222 | 2026-06-27 12:23:22 | 62703cd3edab0580… / hash match in main: docs/nest_evidence_contract_status.md |
| md | `docs/nest_evidence_examples.md` | 20128 | 2026-06-27 12:23:22 | 8ed46a5e726afd5f… / hash match in main: docs/nest_evidence_examples.md |
| md | `docs/nest_evidence_integration_status.md` | 3591 | 2026-06-27 12:23:22 | 2ba8da12f7c64eff… / hash match in main: docs/nest_evidence_integration_status.md |
| md | `docs/nest_evidence_schema_spec.md` | 26856 | 2026-06-27 12:23:22 | c20835001116d4ff… / hash match in main: docs/nest_evidence_schema_spec.md |
| md | `docs/RELEASE_SIGNING_AND_UPDATER_PLAN.md` | 4476 | 2026-06-27 12:23:22 | 87e42b8b0e9abaf9… / hash match in main: docs/RELEASE_SIGNING_AND_UPDATER_PLAN.md |
| md | `docs/RELEASE_VALIDATION_2026-06-01.md` | 4347 | 2026-06-27 12:23:22 | e92af9bb50a0316c… / hash match in main: docs/RELEASE_VALIDATION_2026-06-01.md |
| md | `docs/TESTER_RELEASE_STATUS.md` | 3389 | 2026-06-27 12:23:22 | a11a42bfdda29d25… / hash match in main: docs/TESTER_RELEASE_STATUS.md |
| evidence | `site-build/releases/v1.0.0/SHA256SUMS.txt` | 190 | 2026-06-27 12:23:22 | eb0d101f79989778… / hash match in main: site-build/releases/v1.0.0/SHA256SUMS.txt |
| artifact | `site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe` | 14881361 | 2026-06-27 12:23:22 | fae7b573054a3938… / hash match in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe |
| artifact | `site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi` | 21291008 | 2026-06-27 12:23:22 | 0b6a8e885accd45b… / hash match in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi |
| artifact | `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi` | 21327872 | 2026-06-27 12:36:38 | 1057837f625ce40d… / same basename in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi |
| artifact | `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe` | 14926322 | 2026-06-27 12:37:04 | 813fa16051035228… / same basename in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe |
| artifact | `target/release/wix/x64/MicrosoftEdgeWebview2Setup.exe` | 1688792 | 2026-06-27 12:36:31 | f91077e2c116dcf6… / not matched in main |
| png | `docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png` | 77337 | 2026-06-27 12:23:22 |  / same basename in main: docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png |
| png | `docs/assets/hexhawk-for-dummies/01-launch-home.png` | 161259 | 2026-06-27 12:23:22 |  / same basename in main: docs/assets/hexhawk-for-dummies/01-launch-home.png |
| png | `docs/assets/hexhawk-for-dummies/02-open-safe-sample.png` | 58333 | 2026-06-27 12:23:22 |  / same basename in main: docs/assets/hexhawk-for-dummies/02-open-safe-sample.png |
| png | `docs/assets/hexhawk-for-dummies/03-analysis-workspace.png` | 49084 | 2026-06-27 12:23:22 |  / same basename in main: docs/assets/hexhawk-for-dummies/03-analysis-workspace.png |
| png | `docs/assets/hexhawk-for-dummies/04-strings-view.png` | 53920 | 2026-06-27 12:23:22 |  / same basename in main: docs/assets/hexhawk-for-dummies/04-strings-view.png |
| png | `docs/assets/hexhawk-for-dummies/05-disassembly-view.png` | 57462 | 2026-06-27 12:23:22 |  / same basename in main: docs/assets/hexhawk-for-dummies/05-disassembly-view.png |
| png | `docs/assets/hexhawk-for-dummies/06-gyre-verdict.png` | 68078 | 2026-06-27 12:23:22 |  / same basename in main: docs/assets/hexhawk-for-dummies/06-gyre-verdict.png |
| png | `docs/assets/hexhawk-for-dummies/07-nest-evidence.png` | 73962 | 2026-06-27 12:23:22 |  / same basename in main: docs/assets/hexhawk-for-dummies/07-nest-evidence.png |

### `D:/Project/HexHawk-release-candidate-v2.1-20260627-133346`
- Size / modified: 6.82 GB / 2026-06-27 13:46:48
- Branch/HEAD: `(detached HEAD)` / `5c6d8143506a58b36d32339473d28ae2223c7229`
- Reachability: main=yes, origin/main=yes, tags=v2.1.0-unsigned-deployment-candidate-20260627, v2.1.1-function-intelligence-export-correlation-basis, v2.1.13-aetherframe-factory-integration, v2.1.14-workspace-cleanup-classification, v2.1.2-installer-smoke-window-proof, v2.1.3-ui-inspect-path-fix, v2.1.4-ai-workflow-cdp-probe, v2.1.5-competitive-landscape-current-posture ...
- Classification: **B. EVIDENCE_ONLY**
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Actual dirty content appears generated/status noise, but release/evidence/artifact provenance exists and should be summarized before approval-based worktree removal.
- Dirty categories: Yarn install state, generated Tauri schemas, line-ending/status noise in snapshots, line-ending/status noise in Cargo.toml
- Actual content-changing diff paths: .yarn/install-state.gz, src-tauri/gen/schemas/acl-manifests.json, src-tauri/gen/schemas/desktop-schema.json, src-tauri/gen/schemas/windows-schema.json
- Status-only line-ending/no-content paths: yarn/install-state.gz, HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap, HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap, src-tauri/Cargo.toml
- Untracked files: none
- Unique commits not on main: 0
- Recent log:
```text
5c6d814 [UI] Add first-run welcome panel with drag-and-drop
e64f990 [STRIKE] Add in-app STRIKE API reference and schema doc
6514cce [DISASM] Add FLIRT-style library signature matching
73a10fc [DISASM] Add ARM64 architecture recognition with honest limits
2660b92 [PERF] Add disassembly load time baseline
```
- `git status --short`:
```text
M .yarn/install-state.gz
 M HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap
 M HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap
 M src-tauri/Cargo.toml
 M src-tauri/gen/schemas/acl-manifests.json
 M src-tauri/gen/schemas/desktop-schema.json
 M src-tauri/gen/schemas/windows-schema.json
```
- `git diff --stat`:
```text
.yarn/install-state.gz                    | Bin 360196 -> 363986 bytes
 src-tauri/gen/schemas/acl-manifests.json  |   2 +-
 src-tauri/gen/schemas/desktop-schema.json |  60 +++++++++++++++++++++++++++---
 src-tauri/gen/schemas/windows-schema.json |  60 +++++++++++++++++++++++++++---
 4 files changed, 109 insertions(+), 13 deletions(-)
```
- Evidence/artifact counts: named evidence=1, release markdown=8, screenshots=15, MSI/setup/zip=5.
| Kind | Relative path | Size | Modified | SHA256 / equivalence |
|---|---|---:|---|---|
| md | `docs/HEXHAWK_FOR_DUMMIES_VALIDATION_REPORT.md` | 11676 | 2026-06-27 13:33:47 | 2ed366eb2f139965… / hash match in main: docs/HEXHAWK_FOR_DUMMIES_VALIDATION_REPORT.md |
| md | `docs/nest_evidence_contract_status.md` | 8222 | 2026-06-27 13:33:47 | 62703cd3edab0580… / hash match in main: docs/nest_evidence_contract_status.md |
| md | `docs/nest_evidence_examples.md` | 20128 | 2026-06-27 13:33:47 | 8ed46a5e726afd5f… / hash match in main: docs/nest_evidence_examples.md |
| md | `docs/nest_evidence_integration_status.md` | 3591 | 2026-06-27 13:33:47 | 2ba8da12f7c64eff… / hash match in main: docs/nest_evidence_integration_status.md |
| md | `docs/nest_evidence_schema_spec.md` | 26856 | 2026-06-27 13:33:47 | c20835001116d4ff… / hash match in main: docs/nest_evidence_schema_spec.md |
| md | `docs/RELEASE_SIGNING_AND_UPDATER_PLAN.md` | 4476 | 2026-06-27 13:33:47 | 87e42b8b0e9abaf9… / hash match in main: docs/RELEASE_SIGNING_AND_UPDATER_PLAN.md |
| md | `docs/RELEASE_VALIDATION_2026-06-01.md` | 4347 | 2026-06-27 13:33:47 | e92af9bb50a0316c… / hash match in main: docs/RELEASE_VALIDATION_2026-06-01.md |
| md | `docs/TESTER_RELEASE_STATUS.md` | 3389 | 2026-06-27 13:33:47 | a11a42bfdda29d25… / hash match in main: docs/TESTER_RELEASE_STATUS.md |
| evidence | `site-build/releases/v1.0.0/SHA256SUMS.txt` | 190 | 2026-06-27 13:33:47 | eb0d101f79989778… / hash match in main: site-build/releases/v1.0.0/SHA256SUMS.txt |
| artifact | `site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe` | 14881361 | 2026-06-27 13:33:47 | fae7b573054a3938… / hash match in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe |
| artifact | `site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi` | 21291008 | 2026-06-27 13:33:47 | 0b6a8e885accd45b… / hash match in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi |
| artifact | `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi` | 21340160 | 2026-06-27 13:46:19 | ca24b7dd311bf9d0… / same basename in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi |
| artifact | `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe` | 14938374 | 2026-06-27 13:46:48 | a7bc92fa63704427… / same basename in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe |
| artifact | `target/release/wix/x64/MicrosoftEdgeWebview2Setup.exe` | 1688792 | 2026-06-27 13:46:11 | f91077e2c116dcf6… / not matched in main |
| png | `docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png` | 77337 | 2026-06-27 13:33:47 |  / same basename in main: docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png |
| png | `docs/assets/hexhawk-for-dummies/01-launch-home.png` | 161259 | 2026-06-27 13:33:47 |  / same basename in main: docs/assets/hexhawk-for-dummies/01-launch-home.png |
| png | `docs/assets/hexhawk-for-dummies/02-open-safe-sample.png` | 58333 | 2026-06-27 13:33:47 |  / same basename in main: docs/assets/hexhawk-for-dummies/02-open-safe-sample.png |
| png | `docs/assets/hexhawk-for-dummies/03-analysis-workspace.png` | 49084 | 2026-06-27 13:33:47 |  / same basename in main: docs/assets/hexhawk-for-dummies/03-analysis-workspace.png |
| png | `docs/assets/hexhawk-for-dummies/04-strings-view.png` | 53920 | 2026-06-27 13:33:47 |  / same basename in main: docs/assets/hexhawk-for-dummies/04-strings-view.png |
| png | `docs/assets/hexhawk-for-dummies/05-disassembly-view.png` | 57462 | 2026-06-27 13:33:47 |  / same basename in main: docs/assets/hexhawk-for-dummies/05-disassembly-view.png |
| png | `docs/assets/hexhawk-for-dummies/06-gyre-verdict.png` | 68078 | 2026-06-27 13:33:47 |  / same basename in main: docs/assets/hexhawk-for-dummies/06-gyre-verdict.png |
| png | `docs/assets/hexhawk-for-dummies/07-nest-evidence.png` | 73962 | 2026-06-27 13:33:47 |  / same basename in main: docs/assets/hexhawk-for-dummies/07-nest-evidence.png |

### `D:/Project/HexHawk-release-candidate-v2.1-20260627-151143`
- Size / modified: 6.82 GB / 2026-06-27 15:25:16
- Branch/HEAD: `(detached HEAD)` / `e677543a199d3ff292b5832231d1e7be70ab120c`
- Reachability: main=yes, origin/main=yes, tags=v2.1.0-unsigned-deployment-candidate-20260627, v2.1.1-function-intelligence-export-correlation-basis, v2.1.13-aetherframe-factory-integration, v2.1.14-workspace-cleanup-classification, v2.1.2-installer-smoke-window-proof, v2.1.3-ui-inspect-path-fix, v2.1.4-ai-workflow-cdp-probe, v2.1.5-competitive-landscape-current-posture ...
- Classification: **B. EVIDENCE_ONLY**
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Actual dirty content appears generated/status noise, but release/evidence/artifact provenance exists and should be summarized before approval-based worktree removal.
- Dirty categories: Yarn install state, generated Tauri schemas, line-ending/status noise in snapshots, line-ending/status noise in Cargo.toml
- Actual content-changing diff paths: .yarn/install-state.gz, src-tauri/gen/schemas/acl-manifests.json, src-tauri/gen/schemas/desktop-schema.json, src-tauri/gen/schemas/windows-schema.json
- Status-only line-ending/no-content paths: yarn/install-state.gz, HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap, HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap, src-tauri/Cargo.toml
- Untracked files: none
- Unique commits not on main: 0
- Recent log:
```text
e677543 [INTEL] Export no-correlation basis for unobserved functions
5c6d814 [UI] Add first-run welcome panel with drag-and-drop
e64f990 [STRIKE] Add in-app STRIKE API reference and schema doc
6514cce [DISASM] Add FLIRT-style library signature matching
73a10fc [DISASM] Add ARM64 architecture recognition with honest limits
```
- `git status --short`:
```text
M .yarn/install-state.gz
 M HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap
 M HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap
 M src-tauri/Cargo.toml
 M src-tauri/gen/schemas/acl-manifests.json
 M src-tauri/gen/schemas/desktop-schema.json
 M src-tauri/gen/schemas/windows-schema.json
```
- `git diff --stat`:
```text
.yarn/install-state.gz                    | Bin 360196 -> 363986 bytes
 src-tauri/gen/schemas/acl-manifests.json  |   2 +-
 src-tauri/gen/schemas/desktop-schema.json |  60 +++++++++++++++++++++++++++---
 src-tauri/gen/schemas/windows-schema.json |  60 +++++++++++++++++++++++++++---
 4 files changed, 109 insertions(+), 13 deletions(-)
```
- Evidence/artifact counts: named evidence=1, release markdown=8, screenshots=15, MSI/setup/zip=5.
| Kind | Relative path | Size | Modified | SHA256 / equivalence |
|---|---|---:|---|---|
| md | `docs/HEXHAWK_FOR_DUMMIES_VALIDATION_REPORT.md` | 11676 | 2026-06-27 15:11:43 | 2ed366eb2f139965… / hash match in main: docs/HEXHAWK_FOR_DUMMIES_VALIDATION_REPORT.md |
| md | `docs/nest_evidence_contract_status.md` | 8222 | 2026-06-27 15:11:43 | 62703cd3edab0580… / hash match in main: docs/nest_evidence_contract_status.md |
| md | `docs/nest_evidence_examples.md` | 20128 | 2026-06-27 15:11:43 | 8ed46a5e726afd5f… / hash match in main: docs/nest_evidence_examples.md |
| md | `docs/nest_evidence_integration_status.md` | 3591 | 2026-06-27 15:11:43 | 2ba8da12f7c64eff… / hash match in main: docs/nest_evidence_integration_status.md |
| md | `docs/nest_evidence_schema_spec.md` | 26856 | 2026-06-27 15:11:43 | c20835001116d4ff… / hash match in main: docs/nest_evidence_schema_spec.md |
| md | `docs/RELEASE_SIGNING_AND_UPDATER_PLAN.md` | 4476 | 2026-06-27 15:11:43 | 87e42b8b0e9abaf9… / hash match in main: docs/RELEASE_SIGNING_AND_UPDATER_PLAN.md |
| md | `docs/RELEASE_VALIDATION_2026-06-01.md` | 4347 | 2026-06-27 15:11:43 | e92af9bb50a0316c… / hash match in main: docs/RELEASE_VALIDATION_2026-06-01.md |
| md | `docs/TESTER_RELEASE_STATUS.md` | 3389 | 2026-06-27 15:11:43 | a11a42bfdda29d25… / hash match in main: docs/TESTER_RELEASE_STATUS.md |
| evidence | `site-build/releases/v1.0.0/SHA256SUMS.txt` | 190 | 2026-06-27 15:11:43 | eb0d101f79989778… / hash match in main: site-build/releases/v1.0.0/SHA256SUMS.txt |
| artifact | `site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe` | 14881361 | 2026-06-27 15:11:43 | fae7b573054a3938… / hash match in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe |
| artifact | `site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi` | 21291008 | 2026-06-27 15:11:43 | 0b6a8e885accd45b… / hash match in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi |
| artifact | `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi` | 21340160 | 2026-06-27 15:24:46 | 687c9b2555b0d6cd… / same basename in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi |
| artifact | `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe` | 14932683 | 2026-06-27 15:25:16 | 1b9267e4c2d1de06… / same basename in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe |
| artifact | `target/release/wix/x64/MicrosoftEdgeWebview2Setup.exe` | 1688792 | 2026-06-27 15:24:39 | f91077e2c116dcf6… / not matched in main |
| png | `docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png` | 77337 | 2026-06-27 15:11:43 |  / same basename in main: docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png |
| png | `docs/assets/hexhawk-for-dummies/01-launch-home.png` | 161259 | 2026-06-27 15:11:43 |  / same basename in main: docs/assets/hexhawk-for-dummies/01-launch-home.png |
| png | `docs/assets/hexhawk-for-dummies/02-open-safe-sample.png` | 58333 | 2026-06-27 15:11:43 |  / same basename in main: docs/assets/hexhawk-for-dummies/02-open-safe-sample.png |
| png | `docs/assets/hexhawk-for-dummies/03-analysis-workspace.png` | 49084 | 2026-06-27 15:11:43 |  / same basename in main: docs/assets/hexhawk-for-dummies/03-analysis-workspace.png |
| png | `docs/assets/hexhawk-for-dummies/04-strings-view.png` | 53920 | 2026-06-27 15:11:43 |  / same basename in main: docs/assets/hexhawk-for-dummies/04-strings-view.png |
| png | `docs/assets/hexhawk-for-dummies/05-disassembly-view.png` | 57462 | 2026-06-27 15:11:43 |  / same basename in main: docs/assets/hexhawk-for-dummies/05-disassembly-view.png |
| png | `docs/assets/hexhawk-for-dummies/06-gyre-verdict.png` | 68078 | 2026-06-27 15:11:43 |  / same basename in main: docs/assets/hexhawk-for-dummies/06-gyre-verdict.png |
| png | `docs/assets/hexhawk-for-dummies/07-nest-evidence.png` | 73962 | 2026-06-27 15:11:43 |  / same basename in main: docs/assets/hexhawk-for-dummies/07-nest-evidence.png |

### `D:/Project/HexHawk-release-candidate-v2.1-20260627-190731`
- Size / modified: 6.95 GB / 2026-06-27 19:22:47
- Branch/HEAD: `(detached HEAD)` / `ad8e3cf1de136efa85d187d296b43659e36ce940`
- Reachability: main=yes, origin/main=yes, tags=v2.1.0-unsigned-deployment-candidate-20260627, v2.1.13-aetherframe-factory-integration, v2.1.14-workspace-cleanup-classification, v2.1.2-installer-smoke-window-proof, v2.1.3-ui-inspect-path-fix, v2.1.4-ai-workflow-cdp-probe, v2.1.5-competitive-landscape-current-posture, v2.1.6-aetherframe-factory-docs ...
- Classification: **B. EVIDENCE_ONLY**
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Actual dirty content appears generated/status noise, but release/evidence/artifact provenance exists and should be summarized before approval-based worktree removal.
- Dirty categories: Yarn install state, generated Tauri schemas, line-ending/status noise in snapshots, line-ending/status noise in Cargo.toml
- Actual content-changing diff paths: .yarn/install-state.gz, src-tauri/gen/schemas/acl-manifests.json, src-tauri/gen/schemas/desktop-schema.json, src-tauri/gen/schemas/windows-schema.json
- Status-only line-ending/no-content paths: yarn/install-state.gz, HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap, HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap, src-tauri/Cargo.toml
- Untracked files: none
- Unique commits not on main: 0
- Recent log:
```text
ad8e3cf [QA] Harden installer GUI smoke window detection
e677543 [INTEL] Export no-correlation basis for unobserved functions
5c6d814 [UI] Add first-run welcome panel with drag-and-drop
e64f990 [STRIKE] Add in-app STRIKE API reference and schema doc
6514cce [DISASM] Add FLIRT-style library signature matching
```
- `git status --short`:
```text
M .yarn/install-state.gz
 M HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap
 M HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap
 M src-tauri/Cargo.toml
 M src-tauri/gen/schemas/acl-manifests.json
 M src-tauri/gen/schemas/desktop-schema.json
 M src-tauri/gen/schemas/windows-schema.json
```
- `git diff --stat`:
```text
.yarn/install-state.gz                    | Bin 360196 -> 363986 bytes
 src-tauri/gen/schemas/acl-manifests.json  |   2 +-
 src-tauri/gen/schemas/desktop-schema.json |  60 +++++++++++++++++++++++++++---
 src-tauri/gen/schemas/windows-schema.json |  60 +++++++++++++++++++++++++++---
 4 files changed, 109 insertions(+), 13 deletions(-)
```
- Evidence/artifact counts: named evidence=1, release markdown=8, screenshots=15, MSI/setup/zip=5.
| Kind | Relative path | Size | Modified | SHA256 / equivalence |
|---|---|---:|---|---|
| md | `docs/HEXHAWK_FOR_DUMMIES_VALIDATION_REPORT.md` | 11676 | 2026-06-27 19:07:31 | 2ed366eb2f139965… / hash match in main: docs/HEXHAWK_FOR_DUMMIES_VALIDATION_REPORT.md |
| md | `docs/nest_evidence_contract_status.md` | 8222 | 2026-06-27 19:07:31 | 62703cd3edab0580… / hash match in main: docs/nest_evidence_contract_status.md |
| md | `docs/nest_evidence_examples.md` | 20128 | 2026-06-27 19:07:31 | 8ed46a5e726afd5f… / hash match in main: docs/nest_evidence_examples.md |
| md | `docs/nest_evidence_integration_status.md` | 3591 | 2026-06-27 19:07:31 | 2ba8da12f7c64eff… / hash match in main: docs/nest_evidence_integration_status.md |
| md | `docs/nest_evidence_schema_spec.md` | 26856 | 2026-06-27 19:07:31 | c20835001116d4ff… / hash match in main: docs/nest_evidence_schema_spec.md |
| md | `docs/RELEASE_SIGNING_AND_UPDATER_PLAN.md` | 4476 | 2026-06-27 19:07:31 | 87e42b8b0e9abaf9… / hash match in main: docs/RELEASE_SIGNING_AND_UPDATER_PLAN.md |
| md | `docs/RELEASE_VALIDATION_2026-06-01.md` | 4347 | 2026-06-27 19:07:31 | e92af9bb50a0316c… / hash match in main: docs/RELEASE_VALIDATION_2026-06-01.md |
| md | `docs/TESTER_RELEASE_STATUS.md` | 3389 | 2026-06-27 19:07:31 | a11a42bfdda29d25… / hash match in main: docs/TESTER_RELEASE_STATUS.md |
| evidence | `site-build/releases/v1.0.0/SHA256SUMS.txt` | 190 | 2026-06-27 19:07:31 | eb0d101f79989778… / hash match in main: site-build/releases/v1.0.0/SHA256SUMS.txt |
| artifact | `site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe` | 14881361 | 2026-06-27 19:07:31 | fae7b573054a3938… / hash match in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe |
| artifact | `site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi` | 21291008 | 2026-06-27 19:07:32 | 0b6a8e885accd45b… / hash match in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi |
| artifact | `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi` | 21340160 | 2026-06-27 19:15:48 | dc1a45e09cff2628… / same basename in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi |
| artifact | `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe` | 14931899 | 2026-06-27 19:16:29 | b0430013651b1595… / same basename in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe |
| artifact | `target/release/wix/x64/MicrosoftEdgeWebview2Setup.exe` | 1688792 | 2026-06-27 19:15:36 | f91077e2c116dcf6… / not matched in main |
| png | `docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png` | 77337 | 2026-06-27 19:07:31 |  / same basename in main: docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png |
| png | `docs/assets/hexhawk-for-dummies/01-launch-home.png` | 161259 | 2026-06-27 19:07:31 |  / same basename in main: docs/assets/hexhawk-for-dummies/01-launch-home.png |
| png | `docs/assets/hexhawk-for-dummies/02-open-safe-sample.png` | 58333 | 2026-06-27 19:07:31 |  / same basename in main: docs/assets/hexhawk-for-dummies/02-open-safe-sample.png |
| png | `docs/assets/hexhawk-for-dummies/03-analysis-workspace.png` | 49084 | 2026-06-27 19:07:31 |  / same basename in main: docs/assets/hexhawk-for-dummies/03-analysis-workspace.png |
| png | `docs/assets/hexhawk-for-dummies/04-strings-view.png` | 53920 | 2026-06-27 19:07:31 |  / same basename in main: docs/assets/hexhawk-for-dummies/04-strings-view.png |
| png | `docs/assets/hexhawk-for-dummies/05-disassembly-view.png` | 57462 | 2026-06-27 19:07:31 |  / same basename in main: docs/assets/hexhawk-for-dummies/05-disassembly-view.png |
| png | `docs/assets/hexhawk-for-dummies/06-gyre-verdict.png` | 68078 | 2026-06-27 19:07:31 |  / same basename in main: docs/assets/hexhawk-for-dummies/06-gyre-verdict.png |
| png | `docs/assets/hexhawk-for-dummies/07-nest-evidence.png` | 73962 | 2026-06-27 19:07:31 |  / same basename in main: docs/assets/hexhawk-for-dummies/07-nest-evidence.png |

### `D:/Project/HexHawk-release-candidate-v2.1-20260627-194604`
- Size / modified: 6.82 GB / 2026-06-27 20:00:18
- Branch/HEAD: `(detached HEAD)` / `6ae9f2b3ac9b549ed17c9d0bc7a2be737937d4be`
- Reachability: main=yes, origin/main=yes, tags=v2.1.0-unsigned-deployment-candidate-20260627, v2.1.13-aetherframe-factory-integration, v2.1.14-workspace-cleanup-classification, v2.1.3-ui-inspect-path-fix, v2.1.4-ai-workflow-cdp-probe, v2.1.5-competitive-landscape-current-posture, v2.1.6-aetherframe-factory-docs, v2.1.7-aetherframe-factory-cycle-reporter ...
- Classification: **B. EVIDENCE_ONLY**
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Actual dirty content appears generated/status noise, but release/evidence/artifact provenance exists and should be summarized before approval-based worktree removal.
- Dirty categories: Yarn install state, generated Tauri schemas, line-ending/status noise in snapshots, line-ending/status noise in Cargo.toml
- Actual content-changing diff paths: .yarn/install-state.gz, src-tauri/gen/schemas/acl-manifests.json, src-tauri/gen/schemas/desktop-schema.json, src-tauri/gen/schemas/windows-schema.json
- Status-only line-ending/no-content paths: yarn/install-state.gz, HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap, HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap, src-tauri/Cargo.toml
- Untracked files: none
- Unique commits not on main: 0
- Recent log:
```text
6ae9f2b [UI] Fix file path type passed to inspect command
ad8e3cf [QA] Harden installer GUI smoke window detection
e677543 [INTEL] Export no-correlation basis for unobserved functions
5c6d814 [UI] Add first-run welcome panel with drag-and-drop
e64f990 [STRIKE] Add in-app STRIKE API reference and schema doc
```
- `git status --short`:
```text
M .yarn/install-state.gz
 M HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap
 M HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap
 M src-tauri/Cargo.toml
 M src-tauri/gen/schemas/acl-manifests.json
 M src-tauri/gen/schemas/desktop-schema.json
 M src-tauri/gen/schemas/windows-schema.json
```
- `git diff --stat`:
```text
.yarn/install-state.gz                    | Bin 360196 -> 363986 bytes
 src-tauri/gen/schemas/acl-manifests.json  |   2 +-
 src-tauri/gen/schemas/desktop-schema.json |  60 +++++++++++++++++++++++++++---
 src-tauri/gen/schemas/windows-schema.json |  60 +++++++++++++++++++++++++++---
 4 files changed, 109 insertions(+), 13 deletions(-)
```
- Evidence/artifact counts: named evidence=1, release markdown=8, screenshots=15, MSI/setup/zip=5.
| Kind | Relative path | Size | Modified | SHA256 / equivalence |
|---|---|---:|---|---|
| md | `docs/HEXHAWK_FOR_DUMMIES_VALIDATION_REPORT.md` | 11676 | 2026-06-27 19:46:04 | 2ed366eb2f139965… / hash match in main: docs/HEXHAWK_FOR_DUMMIES_VALIDATION_REPORT.md |
| md | `docs/nest_evidence_contract_status.md` | 8222 | 2026-06-27 19:46:04 | 62703cd3edab0580… / hash match in main: docs/nest_evidence_contract_status.md |
| md | `docs/nest_evidence_examples.md` | 20128 | 2026-06-27 19:46:04 | 8ed46a5e726afd5f… / hash match in main: docs/nest_evidence_examples.md |
| md | `docs/nest_evidence_integration_status.md` | 3591 | 2026-06-27 19:46:04 | 2ba8da12f7c64eff… / hash match in main: docs/nest_evidence_integration_status.md |
| md | `docs/nest_evidence_schema_spec.md` | 26856 | 2026-06-27 19:46:04 | c20835001116d4ff… / hash match in main: docs/nest_evidence_schema_spec.md |
| md | `docs/RELEASE_SIGNING_AND_UPDATER_PLAN.md` | 4476 | 2026-06-27 19:46:04 | 87e42b8b0e9abaf9… / hash match in main: docs/RELEASE_SIGNING_AND_UPDATER_PLAN.md |
| md | `docs/RELEASE_VALIDATION_2026-06-01.md` | 4347 | 2026-06-27 19:46:04 | e92af9bb50a0316c… / hash match in main: docs/RELEASE_VALIDATION_2026-06-01.md |
| md | `docs/TESTER_RELEASE_STATUS.md` | 3389 | 2026-06-27 19:46:04 | a11a42bfdda29d25… / hash match in main: docs/TESTER_RELEASE_STATUS.md |
| evidence | `site-build/releases/v1.0.0/SHA256SUMS.txt` | 190 | 2026-06-27 19:46:04 | eb0d101f79989778… / hash match in main: site-build/releases/v1.0.0/SHA256SUMS.txt |
| artifact | `site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe` | 14881361 | 2026-06-27 19:46:04 | fae7b573054a3938… / hash match in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe |
| artifact | `site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi` | 21291008 | 2026-06-27 19:46:04 | 0b6a8e885accd45b… / hash match in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi |
| artifact | `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi` | 21340160 | 2026-06-27 19:54:20 | 736bd0ead68098bc… / same basename in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi |
| artifact | `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe` | 14930390 | 2026-06-27 19:54:49 | 167e10d7ba4766cc… / same basename in main: site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe |
| artifact | `target/release/wix/x64/MicrosoftEdgeWebview2Setup.exe` | 1688792 | 2026-06-27 19:54:11 | f91077e2c116dcf6… / not matched in main |
| png | `docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png` | 77337 | 2026-06-27 19:46:04 |  / same basename in main: docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png |
| png | `docs/assets/hexhawk-for-dummies/01-launch-home.png` | 161259 | 2026-06-27 19:46:04 |  / same basename in main: docs/assets/hexhawk-for-dummies/01-launch-home.png |
| png | `docs/assets/hexhawk-for-dummies/02-open-safe-sample.png` | 58333 | 2026-06-27 19:46:04 |  / same basename in main: docs/assets/hexhawk-for-dummies/02-open-safe-sample.png |
| png | `docs/assets/hexhawk-for-dummies/03-analysis-workspace.png` | 49084 | 2026-06-27 19:46:04 |  / same basename in main: docs/assets/hexhawk-for-dummies/03-analysis-workspace.png |
| png | `docs/assets/hexhawk-for-dummies/04-strings-view.png` | 53920 | 2026-06-27 19:46:04 |  / same basename in main: docs/assets/hexhawk-for-dummies/04-strings-view.png |
| png | `docs/assets/hexhawk-for-dummies/05-disassembly-view.png` | 57462 | 2026-06-27 19:46:04 |  / same basename in main: docs/assets/hexhawk-for-dummies/05-disassembly-view.png |
| png | `docs/assets/hexhawk-for-dummies/06-gyre-verdict.png` | 68078 | 2026-06-27 19:46:04 |  / same basename in main: docs/assets/hexhawk-for-dummies/06-gyre-verdict.png |
| png | `docs/assets/hexhawk-for-dummies/07-nest-evidence.png` | 73962 | 2026-06-27 19:46:04 |  / same basename in main: docs/assets/hexhawk-for-dummies/07-nest-evidence.png |

## Proposed batches — proposal only, no commands executed

These batches are not approval. Do not run cleanup or worktree-removal commands without explicit user approval naming exact paths.

### Batch W1 — generated dirt only, reachable HEAD, no unique evidence

No W1 worktrees. All large worktrees contain release/evidence/artifact provenance or helper-script review items.

### Batch W2 — evidence/artifacts only; preserve evidence summary first

Estimated recovery after preservation and explicit approval: **50.41 GB**.
- `D:/Project/HexHawk-ai-overhaul-gate` — preserve compact evidence/artifact summary first, then propose exact worktree removal for approval.
- `D:/Project/HexHawk-ai-overhaul-gate-20260627` — preserve compact evidence/artifact summary first, then propose exact worktree removal for approval.
- `D:/Project/HexHawk-release-candidate-currenthead-postfeatures-20260621-123026` — preserve compact evidence/artifact summary first, then propose exact worktree removal for approval.
- `D:/Project/HexHawk-release-candidate-v2.0-20260627-122322` — preserve compact evidence/artifact summary first, then propose exact worktree removal for approval.
- `D:/Project/HexHawk-release-candidate-v2.1-20260627-133346` — preserve compact evidence/artifact summary first, then propose exact worktree removal for approval.
- `D:/Project/HexHawk-release-candidate-v2.1-20260627-151143` — preserve compact evidence/artifact summary first, then propose exact worktree removal for approval.
- `D:/Project/HexHawk-release-candidate-v2.1-20260627-190731` — preserve compact evidence/artifact summary first, then propose exact worktree removal for approval.
- `D:/Project/HexHawk-release-candidate-v2.1-20260627-194604` — preserve compact evidence/artifact summary first, then propose exact worktree removal for approval.
### Batch W3 — source changes, helper scripts, or unique commits

Estimated size requiring review: **6.81 GB**.
- `D:/Project/HexHawk-rc-20260626-192557` — Untracked helper scripts, unique commits, or actual source/config content changes require review.
### Batch W4 — credential risk

No credential-risk dirty paths were identified by path-name scan. Credentials were not read.

## Main untracked validation report decision

- Path: `docs/aetherframe-runs/factory-cycle-20260701-195521.md`
- Metadata: 4438 bytes, sha256 a498cbb248beedec0359b85bacb751a6138711115c70eb251d420ad907e48723
- Recommendation: **keep local / do not stage by default; it captured pre-commit validation from the prior cleanup cycle and is useful but stale versus current HEAD.**
- Do not delete it in this run. If the user wants all validation artifacts tracked, stage it in a separate docs-only commit; otherwise leave it local or include it in a later explicit cleanup approval.

## W2 Worktree Cleanup Execution

- Removal date/time: 2026-07-02 00:21:42.
- Commit before removal: `6d81450` (`v2.1.16-w2-evidence-preservation`).
- Method requested: `git worktree remove --force` exact paths only.
- Execution note: Git unregistered the worktrees but left non-empty ignored/untracked residual folders; those exact approved residual paths were then deleted with Python `shutil.rmtree` after each path was no longer registered. No wildcard deletion was used.
- Authority note: GYRE remains the sole HexHawk verdict/classification authority. AetherFrame remains advisory cleanup planning only.

| Path | Prior Size GB | Evidence Summary | Final Status |
|---|---:|---|---|
| `D:/Project/HexHawk-ai-overhaul-gate` | 6.82 | `docs/preserved-evidence/hexhawk-ai-overhaul-gate.md` | REMOVED_AFTER_EVIDENCE_PRESERVATION |
| `D:/Project/HexHawk-ai-overhaul-gate-20260627` | 7.05 | `docs/preserved-evidence/hexhawk-ai-overhaul-gate-20260627.md` | REMOVED_AFTER_EVIDENCE_PRESERVATION |
| `D:/Project/HexHawk-release-candidate-currenthead-postfeatures-20260621-123026` | 2.32 | `docs/preserved-evidence/hexhawk-release-candidate-currenthead-postfeatures-20260621-123026.md` | REMOVED_AFTER_EVIDENCE_PRESERVATION |
| `D:/Project/HexHawk-release-candidate-v2.0-20260627-122322` | 6.81 | `docs/preserved-evidence/hexhawk-release-candidate-v2.0-20260627-122322.md` | REMOVED_AFTER_EVIDENCE_PRESERVATION |
| `D:/Project/HexHawk-release-candidate-v2.1-20260627-133346` | 6.82 | `docs/preserved-evidence/hexhawk-release-candidate-v2.1-20260627-133346.md` | REMOVED_AFTER_EVIDENCE_PRESERVATION |
| `D:/Project/HexHawk-release-candidate-v2.1-20260627-151143` | 6.82 | `docs/preserved-evidence/hexhawk-release-candidate-v2.1-20260627-151143.md` | REMOVED_AFTER_EVIDENCE_PRESERVATION |
| `D:/Project/HexHawk-release-candidate-v2.1-20260627-190731` | 6.95 | `docs/preserved-evidence/hexhawk-release-candidate-v2.1-20260627-190731.md` | REMOVED_AFTER_EVIDENCE_PRESERVATION |
| `D:/Project/HexHawk-release-candidate-v2.1-20260627-194604` | 6.82 | `docs/preserved-evidence/hexhawk-release-candidate-v2.1-20260627-194604.md` | REMOVED_AFTER_EVIDENCE_PRESERVATION |

- Estimated recovered space from approved W2 paths: **50.41 GB**.
- Excluded path not touched: `D:/Project/HexHawk-rc-20260626-192557`.


## W2 Evidence Preservation Status

Updated: 2026-07-01 20:39:46

The eight W2 worktrees now have compact evidence summaries under `docs/preserved-evidence/` and are indexed in `docs/AETHERFRAME_PRESERVED_EVIDENCE_INDEX.md`. They are marked `EVIDENCE_PRESERVED_PENDING_REMOVAL_APPROVAL`; this does not approve or record cleanup execution.

- `D:/Project/HexHawk-ai-overhaul-gate` — preserved summary: `docs/preserved-evidence/hexhawk-ai-overhaul-gate.md`
- `D:/Project/HexHawk-ai-overhaul-gate-20260627` — preserved summary: `docs/preserved-evidence/hexhawk-ai-overhaul-gate-20260627.md`
- `D:/Project/HexHawk-release-candidate-currenthead-postfeatures-20260621-123026` — preserved summary: `docs/preserved-evidence/hexhawk-release-candidate-currenthead-postfeatures-20260621-123026.md`
- `D:/Project/HexHawk-release-candidate-v2.0-20260627-122322` — preserved summary: `docs/preserved-evidence/hexhawk-release-candidate-v2.0-20260627-122322.md`
- `D:/Project/HexHawk-release-candidate-v2.1-20260627-133346` — preserved summary: `docs/preserved-evidence/hexhawk-release-candidate-v2.1-20260627-133346.md`
- `D:/Project/HexHawk-release-candidate-v2.1-20260627-151143` — preserved summary: `docs/preserved-evidence/hexhawk-release-candidate-v2.1-20260627-151143.md`
- `D:/Project/HexHawk-release-candidate-v2.1-20260627-190731` — preserved summary: `docs/preserved-evidence/hexhawk-release-candidate-v2.1-20260627-190731.md`
- `D:/Project/HexHawk-release-candidate-v2.1-20260627-194604` — preserved summary: `docs/preserved-evidence/hexhawk-release-candidate-v2.1-20260627-194604.md`


## Future approval language

Any future worktree decommission command must be copied into a new approval-bound execution plan and rechecked immediately before use. This document does not approve or execute that action.
