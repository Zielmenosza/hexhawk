# AetherFrame Workspace Cleanup Decision Table

Generated: 2026-07-01 19:55:02

Status: classification/proposal only. Nothing was deleted, moved, compressed, deployed, or unregistered. Do not execute any cleanup command without explicit user approval naming exact paths.

Authority note: GYRE remains the sole verdict/classification authority for HexHawk. AetherFrame is advisory process support only; this table is a custody cleanup classification, not a release verdict.

## Summary

- Starting inspected HEAD: `2764146` (main was clean at Phase 0).
- Total matched cleanup candidates: **58.40 GB** across 29 folders.
- Registered git worktree candidates: **57.23 GB**.
- Batch A safest non-worktree folders: **0.12 GB** (proposal only).
- Batch B registered worktrees that appear safe: **0.00 GB** (proposal only; none if all are dirty or need review).

## Decision Table

| Path | Size GB | Type | Git Worktree | Dirty | Evidence | Artifacts | Risk | Recommendation | Reason |
|---|---:|---|---|---|---|---|---|---|---|
| `D:/Project/HexHawk-ai-overhaul-gate-20260627` | 7.05 | registered git worktree | yes | yes | 1 named files; 76 screenshots/images | 15 installer/zip artifacts | High | DO_NOT_TOUCH | Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval. |
| `D:/Project/HexHawk-release-candidate-v2.1-20260627-190731` | 6.95 | registered git worktree | yes | yes | 1 named files; 76 screenshots/images | 15 installer/zip artifacts | High | DO_NOT_TOUCH | Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval. |
| `D:/Project/HexHawk-ai-overhaul-gate` | 6.82 | registered git worktree | yes | yes | 1 named files; 76 screenshots/images | 15 installer/zip artifacts | High | DO_NOT_TOUCH | Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval. |
| `D:/Project/HexHawk-release-candidate-v2.1-20260627-194604` | 6.82 | registered git worktree | yes | yes | 1 named files; 76 screenshots/images | 15 installer/zip artifacts | High | DO_NOT_TOUCH | Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval. |
| `D:/Project/HexHawk-release-candidate-v2.1-20260627-133346` | 6.82 | registered git worktree | yes | yes | 1 named files; 76 screenshots/images | 14 installer/zip artifacts | High | DO_NOT_TOUCH | Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval. |
| `D:/Project/HexHawk-release-candidate-v2.1-20260627-151143` | 6.82 | registered git worktree | yes | yes | 1 named files; 76 screenshots/images | 14 installer/zip artifacts | High | DO_NOT_TOUCH | Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval. |
| `D:/Project/HexHawk-release-candidate-v2.0-20260627-122322` | 6.81 | registered git worktree | yes | yes | 1 named files; 76 screenshots/images | 14 installer/zip artifacts | High | DO_NOT_TOUCH | Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval. |
| `D:/Project/HexHawk-rc-20260626-192557` | 6.81 | registered git worktree | yes | yes | 1 named files; 76 screenshots/images | 15 installer/zip artifacts | High | DO_NOT_TOUCH | Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval. |
| `D:/Project/HexHawk-release-candidate-currenthead-postfeatures-20260621-123026` | 2.32 | registered git worktree | yes | yes | 1 named files; 74 screenshots/images | 11 installer/zip artifacts | High | DO_NOT_TOUCH | Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval. |
| `D:/Project/HexHawk-smoke-20260627-152540` | 0.13 | non-worktree smoke/probe folder | no | no | 1 named files; 10 screenshots/images | 6 installer/zip artifacts | Medium | PRESERVE_EVIDENCE_THEN_REMOVE | Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion. |
| `D:/Project/HexHawk-smoke-20260627-134843` | 0.13 | non-worktree smoke/probe folder | no | no | 2 named files; 6 screenshots/images | 3 installer/zip artifacts | Medium | PRESERVE_EVIDENCE_THEN_REMOVE | Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion. |
| `D:/Project/HexHawk-smoke-currenthead-postfeatures-20260621-123026` | 0.13 | non-worktree smoke/probe folder | no | no | 2 screenshots/images | 3 installer/zip artifacts | Medium | PRESERVE_EVIDENCE_THEN_REMOVE | Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion. |
| `D:/Project/HexHawk-smoke-20260627-123927` | 0.07 | non-worktree smoke/probe folder | no | no | 2 named files; 5 screenshots/images | 7 installer/zip artifacts | Medium | PRESERVE_EVIDENCE_THEN_REMOVE | Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion. |
| `D:/Project/HexHawk-ai-overhaul-smoke-20260627-final` | 0.07 | non-worktree smoke/probe folder | no | no | 1 named files; 2 screenshots/images | 3 installer/zip artifacts | Medium | PRESERVE_EVIDENCE_THEN_REMOVE | Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion. |
| `D:/Project/HexHawk-ai-overhaul-smoke-20260627-final2` | 0.07 | non-worktree smoke/probe folder | no | no | 1 named files; 2 screenshots/images | 3 installer/zip artifacts | Medium | PRESERVE_EVIDENCE_THEN_REMOVE | Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion. |
| `D:/Project/HexHawk-smoke-v212-final-20260627-192342` | 0.07 | non-worktree smoke/probe folder | no | no | 1 named files; 2 screenshots/images | 3 installer/zip artifacts | Medium | PRESERVE_EVIDENCE_THEN_REMOVE | Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion. |
| `D:/Project/HexHawk-smoke-robust-existing-20260627c` | 0.07 | non-worktree smoke/probe folder | no | no | 1 named files; 2 screenshots/images | 3 installer/zip artifacts | Medium | PRESERVE_EVIDENCE_THEN_REMOVE | Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion. |
| `D:/Project/HexHawk-smoke-robust-existing-20260627b` | 0.07 | non-worktree smoke/probe folder | no | no | 1 named files; 2 screenshots/images | 3 installer/zip artifacts | Medium | PRESERVE_EVIDENCE_THEN_REMOVE | Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion. |
| `D:/Project/HexHawk-smoke-robust-existing-20260627` | 0.07 | non-worktree smoke/probe folder | no | no | 1 named files; 2 screenshots/images | 3 installer/zip artifacts | Medium | PRESERVE_EVIDENCE_THEN_REMOVE | Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion. |
| `D:/Project/HexHawk-smoke-v213-installer-20260627-200021` | 0.07 | non-worktree smoke/probe folder | no | no | 1 named files; 2 screenshots/images | 3 installer/zip artifacts | Medium | PRESERVE_EVIDENCE_THEN_REMOVE | Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion. |
| `D:/Project/HexHawk-ai-overhaul-smoke` | 0.07 | non-worktree smoke/probe folder | no | no | 1 named files; 2 screenshots/images | 3 installer/zip artifacts | Medium | PRESERVE_EVIDENCE_THEN_REMOVE | Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion. |
| `D:/Project/HexHawk-ai-overhaul-smoke-20260627` | 0.07 | non-worktree smoke/probe folder | no | no | 1 named files; 2 screenshots/images | 3 installer/zip artifacts | Medium | PRESERVE_EVIDENCE_THEN_REMOVE | Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion. |
| `D:/Project/HexHawk-smoke-phase0-9400` | 0.06 | non-worktree smoke/probe folder | no | no | none detected | none detected | Low | SAFE_REMOVE_AFTER_APPROVAL | No registered worktree and no named compact evidence detected; exact-path approval still required. |
| `D:/Project/HexHawk-ai-probe-install` | 0.06 | non-worktree smoke/probe folder | no | no | none detected | none detected | Low | SAFE_REMOVE_AFTER_APPROVAL | No registered worktree and no named compact evidence detected; exact-path approval still required. |
| `D:/Project/HexHawk-ai-probe-results` | 0.00 | non-worktree smoke/probe folder | no | no | 2 named files; 2 screenshots/images | none detected | Medium | PRESERVE_EVIDENCE_THEN_REMOVE | Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion. |
| `D:/Project/HexHawk-smoke-v213-function-notebook` | 0.00 | non-worktree smoke/probe folder | no | no | 1 named files; 1 screenshots/images | none detected | Medium | PRESERVE_EVIDENCE_THEN_REMOVE | Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion. |
| `D:/Project/HexHawk-smoke-v213-function-notebook-clean` | 0.00 | non-worktree smoke/probe folder | no | no | 1 named files; 1 screenshots/images | none detected | Medium | PRESERVE_EVIDENCE_THEN_REMOVE | Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion. |
| `D:/Project/HexHawk-smoke-v212-function-notebook` | 0.00 | non-worktree smoke/probe folder | no | no | 1 screenshots/images | 1 installer/zip artifacts | Medium | PRESERVE_EVIDENCE_THEN_REMOVE | Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion. |
| `D:/Project/HexHawk-smoke-v212-dom` | 0.00 | non-worktree smoke/probe folder | no | no | none detected | none detected | Low | SAFE_REMOVE_AFTER_APPROVAL | Empty/tiny stale non-worktree folder with no named evidence detected. |

## Registered Worktree Detail

### `D:/Project/HexHawk-ai-overhaul-gate`
- Size / last modified: 6.82 GB / 2026-06-29 18:50:19
- Branch/HEAD: `(detached HEAD) @ 8947ab6`
- HEAD present in main/origin main: main=yes, origin/main=yes; tags at HEAD: none
- Dirty: yes; untracked files: no
- Git status sample:
```text
M .yarn/install-state.gz
 M HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap
 M HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap
 M src-tauri/Cargo.toml
 M src-tauri/gen/schemas/acl-manifests.json
 M src-tauri/gen/schemas/desktop-schema.json
 M src-tauri/gen/schemas/windows-schema.json
```
- Evidence examples: site-build/releases/v1.0.0/SHA256SUMS.txt, docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png, docs/assets/hexhawk-for-dummies/01-launch-home.png, docs/assets/hexhawk-for-dummies/02-open-safe-sample.png, docs/assets/hexhawk-for-dummies/03-analysis-workspace.png
- Artifact examples: docs/release-evidence/unsigned_installer_rebuild_2026-06-04_175600.json, node_modules/typescript/lib/typingsInstaller.js, node_modules/typescript/lib/_typingsInstaller.js, scripts/release/installer-smoke.ps1, site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe, site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi, target/debug/build/libsodium-sys-stable-8ac152aeda22db2f/out/source/libsodium-stable/test/check-version-consistency.sh, target/debug/build/libsodium-sys-stable-b4b0e4ea380b462d/out/source/libsodium-stable/test/check-version-consistency.sh
- Recommendation: **DO_NOT_TOUCH** — Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval.

### `D:/Project/HexHawk-ai-overhaul-gate-20260627`
- Size / last modified: 7.05 GB / 2026-06-27 23:50:29
- Branch/HEAD: `(detached HEAD) @ d2a7d3f`
- HEAD present in main/origin main: main=yes, origin/main=yes; tags at HEAD: none
- Dirty: yes; untracked files: no
- Git status sample:
```text
M .yarn/install-state.gz
 M HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap
 M HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap
 M src-tauri/Cargo.toml
 M src-tauri/gen/schemas/acl-manifests.json
 M src-tauri/gen/schemas/desktop-schema.json
 M src-tauri/gen/schemas/windows-schema.json
```
- Evidence examples: site-build/releases/v1.0.0/SHA256SUMS.txt, docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png, docs/assets/hexhawk-for-dummies/01-launch-home.png, docs/assets/hexhawk-for-dummies/02-open-safe-sample.png, docs/assets/hexhawk-for-dummies/03-analysis-workspace.png
- Artifact examples: docs/release-evidence/unsigned_installer_rebuild_2026-06-04_175600.json, node_modules/typescript/lib/typingsInstaller.js, node_modules/typescript/lib/_typingsInstaller.js, scripts/release/installer-smoke.ps1, site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe, site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi, target/debug/build/libsodium-sys-stable-8ac152aeda22db2f/out/source/libsodium-stable/test/check-version-consistency.sh, target/debug/build/libsodium-sys-stable-b4b0e4ea380b462d/out/source/libsodium-stable/test/check-version-consistency.sh
- Recommendation: **DO_NOT_TOUCH** — Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval.

### `D:/Project/HexHawk-rc-20260626-192557`
- Size / last modified: 6.81 GB / 2026-06-26 19:41:21
- Branch/HEAD: `v1.32.0-docs-function-intelligence-status @ 3bbf1ac`
- HEAD present in main/origin main: main=yes, origin/main=yes; tags at HEAD: v1.32.0-docs-function-intelligence-status
- Dirty: yes; untracked files: yes
- Git status sample:
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
- Evidence examples: site-build/releases/v1.0.0/SHA256SUMS.txt, docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png, docs/assets/hexhawk-for-dummies/01-launch-home.png, docs/assets/hexhawk-for-dummies/02-open-safe-sample.png, docs/assets/hexhawk-for-dummies/03-analysis-workspace.png
- Artifact examples: installer-smoke.ps1, docs/release-evidence/unsigned_installer_rebuild_2026-06-04_175600.json, node_modules/typescript/lib/typingsInstaller.js, node_modules/typescript/lib/_typingsInstaller.js, site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe, site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi, target/debug/build/libsodium-sys-stable-8ac152aeda22db2f/out/source/libsodium-stable/test/check-version-consistency.sh, target/debug/build/libsodium-sys-stable-b4b0e4ea380b462d/out/source/libsodium-stable/test/check-version-consistency.sh
- Recommendation: **DO_NOT_TOUCH** — Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval.

### `D:/Project/HexHawk-release-candidate-currenthead-postfeatures-20260621-123026`
- Size / last modified: 2.32 GB / 2026-06-21 12:37:31
- Branch/HEAD: `v1.8.0-strike-il-pattern @ ad2e752`
- HEAD present in main/origin main: main=yes, origin/main=yes; tags at HEAD: v1.8.0-strike-il-pattern, v1.9.0-unsigned-deployment-candidate-20260621
- Dirty: yes; untracked files: no
- Git status sample:
```text
M .yarn/install-state.gz
 M HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap
 M HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap
 M src-tauri/Cargo.toml
 M src-tauri/gen/schemas/acl-manifests.json
 M src-tauri/gen/schemas/desktop-schema.json
 M src-tauri/gen/schemas/windows-schema.json
```
- Evidence examples: site-build/releases/v1.0.0/SHA256SUMS.txt, docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png, docs/assets/hexhawk-for-dummies/01-launch-home.png, docs/assets/hexhawk-for-dummies/02-open-safe-sample.png, docs/assets/hexhawk-for-dummies/03-analysis-workspace.png
- Artifact examples: docs/release-evidence/unsigned_installer_rebuild_2026-06-04_175600.json, node_modules/typescript/lib/typingsInstaller.js, node_modules/typescript/lib/_typingsInstaller.js, site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe, site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi, target/release/build/libsodium-sys-stable-0fd17edefd0bdf07/out/source/libsodium-stable/test/check-version-consistency.sh, target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi, target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe
- Recommendation: **DO_NOT_TOUCH** — Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval.

### `D:/Project/HexHawk-release-candidate-v2.0-20260627-122322`
- Size / last modified: 6.81 GB / 2026-06-27 12:37:04
- Branch/HEAD: `v1.33.0-nest-cli-help-exit @ 3310d0c`
- HEAD present in main/origin main: main=yes, origin/main=yes; tags at HEAD: v1.33.0-nest-cli-help-exit, v2.0.0-unsigned-deployment-candidate-20260627
- Dirty: yes; untracked files: no
- Git status sample:
```text
M .yarn/install-state.gz
 M HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap
 M HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap
 M src-tauri/Cargo.toml
 M src-tauri/gen/schemas/acl-manifests.json
 M src-tauri/gen/schemas/desktop-schema.json
 M src-tauri/gen/schemas/windows-schema.json
```
- Evidence examples: site-build/releases/v1.0.0/SHA256SUMS.txt, docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png, docs/assets/hexhawk-for-dummies/01-launch-home.png, docs/assets/hexhawk-for-dummies/02-open-safe-sample.png, docs/assets/hexhawk-for-dummies/03-analysis-workspace.png
- Artifact examples: docs/release-evidence/unsigned_installer_rebuild_2026-06-04_175600.json, node_modules/typescript/lib/typingsInstaller.js, node_modules/typescript/lib/_typingsInstaller.js, site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe, site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi, target/debug/build/libsodium-sys-stable-8ac152aeda22db2f/out/source/libsodium-stable/test/check-version-consistency.sh, target/debug/build/libsodium-sys-stable-b4b0e4ea380b462d/out/source/libsodium-stable/test/check-version-consistency.sh, target/debug/deps/hexhawk_backend-51095d72b3beb7c4.exe
- Recommendation: **DO_NOT_TOUCH** — Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval.

### `D:/Project/HexHawk-release-candidate-v2.1-20260627-133346`
- Size / last modified: 6.82 GB / 2026-06-27 13:46:48
- Branch/HEAD: `v2.6.0-ui-first-run @ 5c6d814`
- HEAD present in main/origin main: main=yes, origin/main=yes; tags at HEAD: v2.6.0-ui-first-run
- Dirty: yes; untracked files: no
- Git status sample:
```text
M .yarn/install-state.gz
 M HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap
 M HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap
 M src-tauri/Cargo.toml
 M src-tauri/gen/schemas/acl-manifests.json
 M src-tauri/gen/schemas/desktop-schema.json
 M src-tauri/gen/schemas/windows-schema.json
```
- Evidence examples: site-build/releases/v1.0.0/SHA256SUMS.txt, docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png, docs/assets/hexhawk-for-dummies/01-launch-home.png, docs/assets/hexhawk-for-dummies/02-open-safe-sample.png, docs/assets/hexhawk-for-dummies/03-analysis-workspace.png
- Artifact examples: docs/release-evidence/unsigned_installer_rebuild_2026-06-04_175600.json, node_modules/typescript/lib/typingsInstaller.js, node_modules/typescript/lib/_typingsInstaller.js, site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe, site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi, target/debug/build/libsodium-sys-stable-8ac152aeda22db2f/out/source/libsodium-stable/test/check-version-consistency.sh, target/debug/build/libsodium-sys-stable-b4b0e4ea380b462d/out/source/libsodium-stable/test/check-version-consistency.sh, target/debug/deps/hexhawk_backend-51095d72b3beb7c4.exe
- Recommendation: **DO_NOT_TOUCH** — Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval.

### `D:/Project/HexHawk-release-candidate-v2.1-20260627-151143`
- Size / last modified: 6.82 GB / 2026-06-27 15:25:16
- Branch/HEAD: `v2.1.1-function-intelligence-export-correlation-basis @ e677543`
- HEAD present in main/origin main: main=yes, origin/main=yes; tags at HEAD: v2.1.1-function-intelligence-export-correlation-basis
- Dirty: yes; untracked files: no
- Git status sample:
```text
M .yarn/install-state.gz
 M HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap
 M HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap
 M src-tauri/Cargo.toml
 M src-tauri/gen/schemas/acl-manifests.json
 M src-tauri/gen/schemas/desktop-schema.json
 M src-tauri/gen/schemas/windows-schema.json
```
- Evidence examples: site-build/releases/v1.0.0/SHA256SUMS.txt, docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png, docs/assets/hexhawk-for-dummies/01-launch-home.png, docs/assets/hexhawk-for-dummies/02-open-safe-sample.png, docs/assets/hexhawk-for-dummies/03-analysis-workspace.png
- Artifact examples: docs/release-evidence/unsigned_installer_rebuild_2026-06-04_175600.json, node_modules/typescript/lib/typingsInstaller.js, node_modules/typescript/lib/_typingsInstaller.js, site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe, site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi, target/debug/build/libsodium-sys-stable-8ac152aeda22db2f/out/source/libsodium-stable/test/check-version-consistency.sh, target/debug/build/libsodium-sys-stable-b4b0e4ea380b462d/out/source/libsodium-stable/test/check-version-consistency.sh, target/debug/deps/hexhawk_backend-51095d72b3beb7c4.exe
- Recommendation: **DO_NOT_TOUCH** — Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval.

### `D:/Project/HexHawk-release-candidate-v2.1-20260627-190731`
- Size / last modified: 6.95 GB / 2026-06-27 19:22:47
- Branch/HEAD: `v2.1.2-installer-smoke-window-proof @ ad8e3cf`
- HEAD present in main/origin main: main=yes, origin/main=yes; tags at HEAD: v2.1.2-installer-smoke-window-proof
- Dirty: yes; untracked files: no
- Git status sample:
```text
M .yarn/install-state.gz
 M HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap
 M HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap
 M src-tauri/Cargo.toml
 M src-tauri/gen/schemas/acl-manifests.json
 M src-tauri/gen/schemas/desktop-schema.json
 M src-tauri/gen/schemas/windows-schema.json
```
- Evidence examples: site-build/releases/v1.0.0/SHA256SUMS.txt, docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png, docs/assets/hexhawk-for-dummies/01-launch-home.png, docs/assets/hexhawk-for-dummies/02-open-safe-sample.png, docs/assets/hexhawk-for-dummies/03-analysis-workspace.png
- Artifact examples: docs/release-evidence/unsigned_installer_rebuild_2026-06-04_175600.json, node_modules/typescript/lib/typingsInstaller.js, node_modules/typescript/lib/_typingsInstaller.js, scripts/release/installer-smoke.ps1, site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe, site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi, target/debug/build/libsodium-sys-stable-8ac152aeda22db2f/out/source/libsodium-stable/test/check-version-consistency.sh, target/debug/build/libsodium-sys-stable-b4b0e4ea380b462d/out/source/libsodium-stable/test/check-version-consistency.sh
- Recommendation: **DO_NOT_TOUCH** — Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval.

### `D:/Project/HexHawk-release-candidate-v2.1-20260627-194604`
- Size / last modified: 6.82 GB / 2026-06-27 20:00:18
- Branch/HEAD: `v2.1.0-unsigned-deployment-candidate-20260627 @ 6ae9f2b`
- HEAD present in main/origin main: main=yes, origin/main=yes; tags at HEAD: v2.1.0-unsigned-deployment-candidate-20260627, v2.1.3-ui-inspect-path-fix, v2.3.0-disasm-library-signatures
- Dirty: yes; untracked files: no
- Git status sample:
```text
M .yarn/install-state.gz
 M HexHawk/src/__tests__/__snapshots__/talonEngine.test.ts.snap
 M HexHawk/src/components/tests/__snapshots__/AuthorityBanner.test.tsx.snap
 M src-tauri/Cargo.toml
 M src-tauri/gen/schemas/acl-manifests.json
 M src-tauri/gen/schemas/desktop-schema.json
 M src-tauri/gen/schemas/windows-schema.json
```
- Evidence examples: site-build/releases/v1.0.0/SHA256SUMS.txt, docs/assets/hexhawk-for-dummies/00-unsigned-windows-warning-not-captured.png, docs/assets/hexhawk-for-dummies/01-launch-home.png, docs/assets/hexhawk-for-dummies/02-open-safe-sample.png, docs/assets/hexhawk-for-dummies/03-analysis-workspace.png
- Artifact examples: docs/release-evidence/unsigned_installer_rebuild_2026-06-04_175600.json, node_modules/typescript/lib/typingsInstaller.js, node_modules/typescript/lib/_typingsInstaller.js, scripts/release/installer-smoke.ps1, site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe, site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi, target/debug/build/libsodium-sys-stable-8ac152aeda22db2f/out/source/libsodium-stable/test/check-version-consistency.sh, target/debug/build/libsodium-sys-stable-b4b0e4ea380b462d/out/source/libsodium-stable/test/check-version-consistency.sh
- Recommendation: **DO_NOT_TOUCH** — Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval.

## Non-worktree Smoke/Probe Detail

### `D:/Project/HexHawk-ai-overhaul-smoke`
- Size / last modified: 0.07 GB / 2026-06-29 18:49:50; files: 19
- Evidence present: 1 named files; 2 screenshots/images; examples: installer-smoke-result.json, msi-gui.png, nsis-gui.png
- Artifacts: 3 installer/zip artifacts; examples: installer-smoke-result.json, nsis-gui.png, msi-admin/HexHawk_1.0.0_x64_en-US.msi
- Duplicate/stale assessment: Historical smoke/probe folder; current repo manifest/report already summarize the folder at a path level, but compact evidence content should be preserved before deleting if evidence is present.
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.

### `D:/Project/HexHawk-ai-overhaul-smoke-20260627`
- Size / last modified: 0.07 GB / 2026-06-27 23:32:35; files: 19
- Evidence present: 1 named files; 2 screenshots/images; examples: installer-smoke-result.json, msi-gui.png, nsis-gui.png
- Artifacts: 3 installer/zip artifacts; examples: installer-smoke-result.json, nsis-gui.png, msi-admin/HexHawk_1.0.0_x64_en-US.msi
- Duplicate/stale assessment: Historical smoke/probe folder; current repo manifest/report already summarize the folder at a path level, but compact evidence content should be preserved before deleting if evidence is present.
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.

### `D:/Project/HexHawk-ai-overhaul-smoke-20260627-final`
- Size / last modified: 0.07 GB / 2026-06-27 23:51:48; files: 21
- Evidence present: 1 named files; 2 screenshots/images; examples: installer-smoke-result.json, msi-gui.png, nsis-gui.png
- Artifacts: 3 installer/zip artifacts; examples: installer-smoke-result.json, nsis-gui.png, msi-admin/HexHawk_1.0.0_x64_en-US.msi
- Duplicate/stale assessment: Historical smoke/probe folder; current repo manifest/report already summarize the folder at a path level, but compact evidence content should be preserved before deleting if evidence is present.
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.

### `D:/Project/HexHawk-ai-overhaul-smoke-20260627-final2`
- Size / last modified: 0.07 GB / 2026-06-27 23:52:19; files: 20
- Evidence present: 1 named files; 2 screenshots/images; examples: installer-smoke-result.json, msi-gui.png, nsis-gui.png
- Artifacts: 3 installer/zip artifacts; examples: installer-smoke-result.json, nsis-gui.png, msi-admin/HexHawk_1.0.0_x64_en-US.msi
- Duplicate/stale assessment: Historical smoke/probe folder; current repo manifest/report already summarize the folder at a path level, but compact evidence content should be preserved before deleting if evidence is present.
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.

### `D:/Project/HexHawk-ai-probe-install`
- Size / last modified: 0.06 GB / 2026-06-29 19:04:39; files: 7
- Evidence present: none detected; examples: none detected
- Artifacts: none detected; examples: none detected
- Duplicate/stale assessment: No named compact evidence detected; appears empty/tiny/stale or artifact-only duplicate, but exact-path approval is still required.
- Recommendation: **SAFE_REMOVE_AFTER_APPROVAL** — No registered worktree and no named compact evidence detected; exact-path approval still required.

### `D:/Project/HexHawk-ai-probe-results`
- Size / last modified: 0.00 GB / 2026-06-29 22:10:47; files: 4
- Evidence present: 2 named files; 2 screenshots/images; examples: function-notebook-export.json, probe-result.json, ai-insight-panel.png, function-notebook-summary.png
- Artifacts: none detected; examples: none detected
- Duplicate/stale assessment: Historical smoke/probe folder; current repo manifest/report already summarize the folder at a path level, but compact evidence content should be preserved before deleting if evidence is present.
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.

### `D:/Project/HexHawk-smoke-20260627-123927`
- Size / last modified: 0.07 GB / 2026-06-27 12:56:18; files: 30
- Evidence present: 2 named files; 5 screenshots/images; examples: installer-smoke-result.json, function-notebook-manual/function-notebook-export.json, msi-gui.png, nsis-gui.png, nsis-standalone-gui.png, function-notebook/function-notebook-cdp.png
- Artifacts: 7 installer/zip artifacts; examples: installer-smoke-result.json, nsis-close-uninstall.json, nsis-gui.png, nsis-standalone-gui.png, function-notebook/nsis-relaunch.json, function-notebook-small/nsis-relaunch.json, msi-admin/HexHawk_1.0.0_x64_en-US.msi
- Duplicate/stale assessment: Historical smoke/probe folder; current repo manifest/report already summarize the folder at a path level, but compact evidence content should be preserved before deleting if evidence is present.
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.

### `D:/Project/HexHawk-smoke-20260627-134843`
- Size / last modified: 0.13 GB / 2026-06-27 15:08:51; files: 35
- Evidence present: 2 named files; 6 screenshots/images; examples: installer-smoke-result.json, manual-v21e/function-notebook-export.json, msi-gui.png, nsis-gui.png, function-notebook-v21/function-notebook-cdp.png, manual-v21/v21-smoke-cdp.png
- Artifacts: 3 installer/zip artifacts; examples: installer-smoke-result.json, nsis-gui.png, msi-admin/HexHawk_1.0.0_x64_en-US.msi
- Duplicate/stale assessment: Historical smoke/probe folder; current repo manifest/report already summarize the folder at a path level, but compact evidence content should be preserved before deleting if evidence is present.
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.

### `D:/Project/HexHawk-smoke-20260627-152540`
- Size / last modified: 0.13 GB / 2026-06-27 19:01:29; files: 34
- Evidence present: 1 named files; 10 screenshots/images; examples: installer-smoke-result.json, msi-gui.png, nsis-gui.png, window-repro/msi-cwd-exe-selected.png, window-repro/msi-cwd-repo-selected.png
- Artifacts: 6 installer/zip artifacts; examples: installer-smoke-result.json, nsis-gui.png, msi-admin/HexHawk_1.0.0_x64_en-US.msi, window-repro2/nsis-cwd-exe-selected.png, window-repro2/nsis-cwd-repo-selected.png, window-repro2/nsis-cwd-temp-selected.png
- Duplicate/stale assessment: Historical smoke/probe folder; current repo manifest/report already summarize the folder at a path level, but compact evidence content should be preserved before deleting if evidence is present.
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.

### `D:/Project/HexHawk-smoke-currenthead-postfeatures-20260621-123026`
- Size / last modified: 0.13 GB / 2026-06-21 12:43:15; files: 18
- Evidence present: 2 screenshots/images; examples: screenshots/msi-admin-hexhawk-printwindow.png, screenshots/nsis-install-hexhawk-printwindow.png
- Artifacts: 3 installer/zip artifacts; examples: msi-admin/HexHawk_1.0.0_x64_en-US.msi, msi-admin-exit0/HexHawk_1.0.0_x64_en-US.msi, screenshots/nsis-install-hexhawk-printwindow.png
- Duplicate/stale assessment: Historical smoke/probe folder; current repo manifest/report already summarize the folder at a path level, but compact evidence content should be preserved before deleting if evidence is present.
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.

### `D:/Project/HexHawk-smoke-phase0-9400`
- Size / last modified: 0.06 GB / 2026-06-27 19:39:38; files: 8
- Evidence present: none detected; examples: none detected
- Artifacts: none detected; examples: none detected
- Duplicate/stale assessment: No named compact evidence detected; appears empty/tiny/stale or artifact-only duplicate, but exact-path approval is still required.
- Recommendation: **SAFE_REMOVE_AFTER_APPROVAL** — No registered worktree and no named compact evidence detected; exact-path approval still required.

### `D:/Project/HexHawk-smoke-robust-existing-20260627`
- Size / last modified: 0.07 GB / 2026-06-27 19:03:49; files: 19
- Evidence present: 1 named files; 2 screenshots/images; examples: installer-smoke-result.json, msi-gui.png, nsis-gui.png
- Artifacts: 3 installer/zip artifacts; examples: installer-smoke-result.json, nsis-gui.png, msi-admin/HexHawk_1.0.0_x64_en-US.msi
- Duplicate/stale assessment: Historical smoke/probe folder; current repo manifest/report already summarize the folder at a path level, but compact evidence content should be preserved before deleting if evidence is present.
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.

### `D:/Project/HexHawk-smoke-robust-existing-20260627b`
- Size / last modified: 0.07 GB / 2026-06-27 19:04:49; files: 19
- Evidence present: 1 named files; 2 screenshots/images; examples: installer-smoke-result.json, msi-gui.png, nsis-gui.png
- Artifacts: 3 installer/zip artifacts; examples: installer-smoke-result.json, nsis-gui.png, msi-admin/HexHawk_1.0.0_x64_en-US.msi
- Duplicate/stale assessment: Historical smoke/probe folder; current repo manifest/report already summarize the folder at a path level, but compact evidence content should be preserved before deleting if evidence is present.
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.

### `D:/Project/HexHawk-smoke-robust-existing-20260627c`
- Size / last modified: 0.07 GB / 2026-06-27 19:05:41; files: 19
- Evidence present: 1 named files; 2 screenshots/images; examples: installer-smoke-result.json, msi-gui.png, nsis-gui.png
- Artifacts: 3 installer/zip artifacts; examples: installer-smoke-result.json, nsis-gui.png, msi-admin/HexHawk_1.0.0_x64_en-US.msi
- Duplicate/stale assessment: Historical smoke/probe folder; current repo manifest/report already summarize the folder at a path level, but compact evidence content should be preserved before deleting if evidence is present.
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.

### `D:/Project/HexHawk-smoke-v212-dom`
- Size / last modified: 0.00 GB / 2026-06-27 19:32:32; files: 0
- Evidence present: none detected; examples: none detected
- Artifacts: none detected; examples: none detected
- Duplicate/stale assessment: No named compact evidence detected; appears empty/tiny/stale or artifact-only duplicate, but exact-path approval is still required.
- Recommendation: **SAFE_REMOVE_AFTER_APPROVAL** — Empty/tiny stale non-worktree folder with no named evidence detected.

### `D:/Project/HexHawk-smoke-v212-final-20260627-192342`
- Size / last modified: 0.07 GB / 2026-06-27 19:23:58; files: 19
- Evidence present: 1 named files; 2 screenshots/images; examples: installer-smoke-result.json, msi-gui.png, nsis-gui.png
- Artifacts: 3 installer/zip artifacts; examples: installer-smoke-result.json, nsis-gui.png, msi-admin/HexHawk_1.0.0_x64_en-US.msi
- Duplicate/stale assessment: Historical smoke/probe folder; current repo manifest/report already summarize the folder at a path level, but compact evidence content should be preserved before deleting if evidence is present.
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.

### `D:/Project/HexHawk-smoke-v212-function-notebook`
- Size / last modified: 0.00 GB / 2026-06-27 19:27:36; files: 3
- Evidence present: 1 screenshots/images; examples: function-notebook/function-notebook-cdp.png
- Artifacts: 1 installer/zip artifacts; examples: nsis-launch.json
- Duplicate/stale assessment: Historical smoke/probe folder; current repo manifest/report already summarize the folder at a path level, but compact evidence content should be preserved before deleting if evidence is present.
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.

### `D:/Project/HexHawk-smoke-v213-function-notebook`
- Size / last modified: 0.00 GB / 2026-06-27 20:04:16; files: 4
- Evidence present: 1 named files; 1 screenshots/images; examples: function-notebook-proof/function-notebook-export.json, function-notebook-proof/function-notebook-panel.png
- Artifacts: none detected; examples: none detected
- Duplicate/stale assessment: Historical smoke/probe folder; current repo manifest/report already summarize the folder at a path level, but compact evidence content should be preserved before deleting if evidence is present.
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.

### `D:/Project/HexHawk-smoke-v213-function-notebook-clean`
- Size / last modified: 0.00 GB / 2026-06-27 20:06:03; files: 4
- Evidence present: 1 named files; 1 screenshots/images; examples: function-notebook-proof/function-notebook-export.json, function-notebook-proof/function-notebook-panel.png
- Artifacts: none detected; examples: none detected
- Duplicate/stale assessment: Historical smoke/probe folder; current repo manifest/report already summarize the folder at a path level, but compact evidence content should be preserved before deleting if evidence is present.
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.

### `D:/Project/HexHawk-smoke-v213-installer-20260627-200021`
- Size / last modified: 0.07 GB / 2026-06-27 20:00:37; files: 19
- Evidence present: 1 named files; 2 screenshots/images; examples: installer-smoke-result.json, msi-gui.png, nsis-gui.png
- Artifacts: 3 installer/zip artifacts; examples: installer-smoke-result.json, nsis-gui.png, msi-admin/HexHawk_1.0.0_x64_en-US.msi
- Duplicate/stale assessment: Historical smoke/probe folder; current repo manifest/report already summarize the folder at a path level, but compact evidence content should be preserved before deleting if evidence is present.
- Recommendation: **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.

## Proposed Deletion Batches — proposals only

No batch below is approved for execution by this document. Do not run proposed commands without explicit user approval.

### Batch A — safest non-worktree folders only

Estimated recovery: **0.12 GB**.
| Exact path | Size GB | Proposed manual action after approval | Reason |
|---|---:|---|---|
| `D:/Project/HexHawk-ai-probe-install` | 0.06 | Delete exact folder only after approval; no command executed here. | No registered worktree and no named compact evidence detected; exact-path approval still required. |
| `D:/Project/HexHawk-smoke-phase0-9400` | 0.06 | Delete exact folder only after approval; no command executed here. | No registered worktree and no named compact evidence detected; exact-path approval still required. |
| `D:/Project/HexHawk-smoke-v212-dom` | 0.00 | Delete exact folder only after approval; no command executed here. | Empty/tiny stale non-worktree folder with no named evidence detected. |

### Batch B — registered worktrees requiring explicit approval

Estimated recovery if approved after review: **0.00 GB**.
No registered worktree qualifies for Batch B. The inspected registered worktrees are dirty and stay in Batch C / DO_NOT_TOUCH.

### Batch C — do not touch / needs review / preserve evidence first

- `D:/Project/HexHawk-ai-overhaul-gate` — 6.82 GB — **DO_NOT_TOUCH** — Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval.
- `D:/Project/HexHawk-ai-overhaul-gate-20260627` — 7.05 GB — **DO_NOT_TOUCH** — Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval.
- `D:/Project/HexHawk-ai-overhaul-smoke` — 0.07 GB — **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.
- `D:/Project/HexHawk-ai-overhaul-smoke-20260627` — 0.07 GB — **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.
- `D:/Project/HexHawk-ai-overhaul-smoke-20260627-final` — 0.07 GB — **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.
- `D:/Project/HexHawk-ai-overhaul-smoke-20260627-final2` — 0.07 GB — **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.
- `D:/Project/HexHawk-ai-probe-results` — 0.00 GB — **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.
- `D:/Project/HexHawk-rc-20260626-192557` — 6.81 GB — **DO_NOT_TOUCH** — Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval.
- `D:/Project/HexHawk-release-candidate-currenthead-postfeatures-20260621-123026` — 2.32 GB — **DO_NOT_TOUCH** — Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval.
- `D:/Project/HexHawk-release-candidate-v2.0-20260627-122322` — 6.81 GB — **DO_NOT_TOUCH** — Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval.
- `D:/Project/HexHawk-release-candidate-v2.1-20260627-133346` — 6.82 GB — **DO_NOT_TOUCH** — Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval.
- `D:/Project/HexHawk-release-candidate-v2.1-20260627-151143` — 6.82 GB — **DO_NOT_TOUCH** — Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval.
- `D:/Project/HexHawk-release-candidate-v2.1-20260627-190731` — 6.95 GB — **DO_NOT_TOUCH** — Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval.
- `D:/Project/HexHawk-release-candidate-v2.1-20260627-194604` — 6.82 GB — **DO_NOT_TOUCH** — Registered dirty git worktree; preserve/review dirt and release provenance before any explicit approval.
- `D:/Project/HexHawk-smoke-20260627-123927` — 0.07 GB — **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.
- `D:/Project/HexHawk-smoke-20260627-134843` — 0.13 GB — **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.
- `D:/Project/HexHawk-smoke-20260627-152540` — 0.13 GB — **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.
- `D:/Project/HexHawk-smoke-currenthead-postfeatures-20260621-123026` — 0.13 GB — **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.
- `D:/Project/HexHawk-smoke-robust-existing-20260627` — 0.07 GB — **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.
- `D:/Project/HexHawk-smoke-robust-existing-20260627b` — 0.07 GB — **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.
- `D:/Project/HexHawk-smoke-robust-existing-20260627c` — 0.07 GB — **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.
- `D:/Project/HexHawk-smoke-v212-final-20260627-192342` — 0.07 GB — **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.
- `D:/Project/HexHawk-smoke-v212-function-notebook` — 0.00 GB — **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.
- `D:/Project/HexHawk-smoke-v213-function-notebook` — 0.00 GB — **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.
- `D:/Project/HexHawk-smoke-v213-function-notebook-clean` — 0.00 GB — **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.
- `D:/Project/HexHawk-smoke-v213-installer-20260627-200021` — 0.07 GB — **PRESERVE_EVIDENCE_THEN_REMOVE** — Non-worktree smoke/probe evidence exists; preserve compact summaries/manifests before approval-based deletion.

## Deletion-language guardrail

Any command examples in this file are proposed/manual commands only and must not be executed without explicit user approval. This run performed classification only.
