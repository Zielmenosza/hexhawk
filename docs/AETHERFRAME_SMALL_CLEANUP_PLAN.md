# AetherFrame Small Cleanup Plan

Generated: 2026-07-02 19:13:49 +0200

Status: read-only small-housekeeping plan. This document does not approve deletion. No folders were deleted, moved, compressed, cleaned, unregistered, deployed, published, or modified by this plan.

Authority note: GYRE remains the sole HexHawk verdict/classification authority. AetherFrame is advisory cleanup-planning support only and is not a verdict authority.

## Final large cleanup status

Large registered worktree cleanup is closed:

- W2 registered worktree cleanup recovered: **about 50.41 GB**.
- RC registered worktree cleanup recovered: **about 6.81 GiB**.
- Total large worktree cleanup recovered: **about 57.22 GB**.
- Current registered worktrees: only `D:/Project/HexHawk`.
- Final cleanup docs:
  - `docs/AETHERFRAME_CLEANUP_MANIFEST.md`
  - `docs/AETHERFRAME_WORKTREE_DECOMMISSION_PLAN.md`
  - `docs/aetherframe-runs/w2-worktree-removal-20260702-002142.md`
  - `docs/aetherframe-runs/rc-worktree-removal-20260702-185724.md`

## Remaining small cleanup candidates

These remaining folders are not registered git worktrees. They are small smoke/probe/package remnants and require separate evidence review plus explicit user approval before any removal.

Estimated remaining non-main HexHawk folder size listed here: **1.27 GiB**.

| Path | Size GiB | Registered worktree | Category | Recommended next action |
|---|---:|---|---|---|
| `D:/Project/HexHawk-ai-overhaul-smoke` | 0.07 | false | smoke | preserve evidence then remove after explicit approval |
| `D:/Project/HexHawk-ai-overhaul-smoke-20260627` | 0.07 | false | smoke | preserve evidence then remove after explicit approval |
| `D:/Project/HexHawk-ai-overhaul-smoke-20260627-final` | 0.07 | false | smoke | preserve evidence then remove after explicit approval |
| `D:/Project/HexHawk-ai-overhaul-smoke-20260627-final2` | 0.07 | false | smoke | preserve evidence then remove after explicit approval |
| `D:/Project/HexHawk-ai-probe-install` | 0.06 | false | probe | preserve evidence then remove after explicit approval |
| `D:/Project/HexHawk-ai-probe-results` | 0.00 | false | probe | safe delete after approval after confirming no unique evidence |
| `D:/Project/HexHawk-early-access-packages` | 0.09 | false | early-access package | keep until package custody review |
| `D:/Project/HexHawk-smoke-20260627-123927` | 0.07 | false | smoke | preserve evidence then remove after explicit approval |
| `D:/Project/HexHawk-smoke-20260627-134843` | 0.13 | false | smoke | preserve evidence then remove after explicit approval |
| `D:/Project/HexHawk-smoke-20260627-152540` | 0.13 | false | smoke | preserve evidence then remove after explicit approval |
| `D:/Project/HexHawk-smoke-currenthead-postfeatures-20260621-123026` | 0.13 | false | smoke | preserve evidence then remove after explicit approval |
| `D:/Project/HexHawk-smoke-phase0-9400` | 0.06 | false | smoke | preserve evidence then remove after explicit approval |
| `D:/Project/HexHawk-smoke-robust-existing-20260627` | 0.07 | false | smoke | preserve evidence then remove after explicit approval |
| `D:/Project/HexHawk-smoke-robust-existing-20260627b` | 0.07 | false | smoke | preserve evidence then remove after explicit approval |
| `D:/Project/HexHawk-smoke-robust-existing-20260627c` | 0.07 | false | smoke | preserve evidence then remove after explicit approval |
| `D:/Project/HexHawk-smoke-v212-dom` | 0.00 | false | smoke | safe delete after approval after confirming no unique evidence |
| `D:/Project/HexHawk-smoke-v212-final-20260627-192342` | 0.07 | false | smoke | preserve evidence then remove after explicit approval |
| `D:/Project/HexHawk-smoke-v212-function-notebook` | 0.00 | false | smoke | safe delete after approval after confirming no unique evidence |
| `D:/Project/HexHawk-smoke-v213-function-notebook` | 0.00 | false | smoke | safe delete after approval after confirming no unique evidence |
| `D:/Project/HexHawk-smoke-v213-function-notebook-clean` | 0.00 | false | smoke | safe delete after approval after confirming no unique evidence |
| `D:/Project/HexHawk-smoke-v213-installer-20260627-200021` | 0.07 | false | smoke | preserve evidence then remove after explicit approval |
| `D:/Project/HexHawk-workbench-backups` | 0.00 | false | other | safe delete after approval after confirming no unique evidence |


## Recommended next housekeeping batch

1. Preserve or summarize evidence first for smoke/probe folders that contain installer-smoke JSON, Function Notebook exports, probe outputs, screenshots, package checksums, or other run proof.
2. Keep `D:/Project/HexHawk-early-access-packages` until package custody is reviewed; it may contain the current unsigned early-access package record.
3. Treat zero-size or near-empty smoke/probe folders as safe-delete candidates only after an exact-path listing confirms no unique evidence.
4. Require a future explicit approval-gated cleanup run naming exact paths before deleting anything.
5. Use no wildcards; do not touch `D:/Project/HexHawk`; do not touch credentials, release signing material, website deployment files, or package zips unless explicitly approved.

## Local generated validation reports

Local generated validation/custody reports remain untracked under `docs/aetherframe-runs/` and were not staged as part of prior cleanup execution docs unless specifically allowlisted. They can be cleaned later in a separate approval-gated housekeeping run.

Current untracked reports recorded for this plan:

- `docs/aetherframe-runs/factory-cycle-20260701-195521.md`
- `docs/aetherframe-runs/factory-cycle-20260701-201811.md`
- `docs/aetherframe-runs/factory-cycle-20260701-204011.md`
- `docs/aetherframe-runs/factory-cycle-20260702-002155.md`
- `docs/aetherframe-runs/factory-cycle-20260702-181939.md`
- `docs/aetherframe-runs/factory-cycle-20260702-183305.md`
- `docs/aetherframe-runs/factory-cycle-20260702-183337.md`
- `docs/aetherframe-runs/factory-cycle-20260702-185844.md`
- `docs/aetherframe-runs/worktree-custody-20260701-201449.md`


## Explicit non-actions

- No deletion.
- No folder removal.
- No `git clean`.
- No PowerShell folder-removal command.
- No deploy or publish.
- No credential access.
- No product code change.
