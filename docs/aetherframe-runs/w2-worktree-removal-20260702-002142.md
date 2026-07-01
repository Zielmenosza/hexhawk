# W2 Worktree Removal Execution Report

Generated: 2026-07-02 00:21:42

This was an approved exact-path cleanup run for the preserved W2 registered worktrees only.

## Pre-removal checks

- Starting HEAD: `6d81450` (`[DOCS] Preserve W2 worktree evidence summaries`).
- Required tag at starting HEAD: `v2.1.16-w2-evidence-preservation`.
- Latest CI before removal: success, run `28539763424`.
- Preserved evidence index and all eight per-worktree summaries existed before removal.
- Decommission plan marked approved paths as `EVIDENCE_PRESERVED_PENDING_REMOVAL_APPROVAL` before removal.
- Final exact-path safety check passed for all eight approved paths.

## Exact removed paths

| Path | Prior Size GB | Evidence Summary | Final status |
|---|---:|---|---|
| `D:/Project/HexHawk-ai-overhaul-gate` | 6.82 | `docs/preserved-evidence/hexhawk-ai-overhaul-gate.md` | removed; not registered; path absent |
| `D:/Project/HexHawk-ai-overhaul-gate-20260627` | 7.05 | `docs/preserved-evidence/hexhawk-ai-overhaul-gate-20260627.md` | removed; not registered; path absent |
| `D:/Project/HexHawk-release-candidate-currenthead-postfeatures-20260621-123026` | 2.32 | `docs/preserved-evidence/hexhawk-release-candidate-currenthead-postfeatures-20260621-123026.md` | removed; not registered; path absent |
| `D:/Project/HexHawk-release-candidate-v2.0-20260627-122322` | 6.81 | `docs/preserved-evidence/hexhawk-release-candidate-v2.0-20260627-122322.md` | removed; not registered; path absent |
| `D:/Project/HexHawk-release-candidate-v2.1-20260627-133346` | 6.82 | `docs/preserved-evidence/hexhawk-release-candidate-v2.1-20260627-133346.md` | removed; not registered; path absent |
| `D:/Project/HexHawk-release-candidate-v2.1-20260627-151143` | 6.82 | `docs/preserved-evidence/hexhawk-release-candidate-v2.1-20260627-151143.md` | removed; not registered; path absent |
| `D:/Project/HexHawk-release-candidate-v2.1-20260627-190731` | 6.95 | `docs/preserved-evidence/hexhawk-release-candidate-v2.1-20260627-190731.md` | removed; not registered; path absent |
| `D:/Project/HexHawk-release-candidate-v2.1-20260627-194604` | 6.82 | `docs/preserved-evidence/hexhawk-release-candidate-v2.1-20260627-194604.md` | removed; not registered; path absent |

## Removal method

- First attempted the requested exact command pattern: `git worktree remove --force "<exact path>"`.
- `git worktree remove` unregistered paths but reported `Directory not empty` because ignored/untracked build outputs remained.
- Continued with exact-path `git worktree remove --force --force` for registered paths; Git still left residual directories after unregistration.
- After each path was confirmed no longer registered, deleted only that exact approved residual path via Python `shutil.rmtree`. No wildcard deletion and no `Remove-Item` were used.

## Post-removal worktree list summary

```text
D:/Project/HexHawk                    6d81450 [main]
D:/Project/HexHawk-rc-20260626-192557 3bbf1ac (detached HEAD)
```

## Recovered GB estimate

- Estimated recovered from approved W2 paths: **50.41 GB**.
- Remaining cleanup candidate estimate: **7.99 GB**.

## Excluded path confirmation

- `D:/Project/HexHawk-rc-20260626-192557` exists and remains registered.
- It was not touched because untracked helper scripts require source review.

## Remaining cleanup candidates

| Path | Size GB | Registered Worktree | Status |
|---|---:|---|---|
| `D:/Project/HexHawk-rc-20260626-192557` | 6.81 | True | dirty |
| `D:/Project/HexHawk-smoke-20260627-152540` | 0.13 | False | not a git worktree |
| `D:/Project/HexHawk-smoke-20260627-134843` | 0.13 | False | not a git worktree |
| `D:/Project/HexHawk-smoke-currenthead-postfeatures-20260621-123026` | 0.13 | False | not a git worktree |
| `D:/Project/HexHawk-smoke-20260627-123927` | 0.07 | False | not a git worktree |
| `D:/Project/HexHawk-ai-overhaul-smoke-20260627-final` | 0.07 | False | not a git worktree |
| `D:/Project/HexHawk-ai-overhaul-smoke-20260627-final2` | 0.07 | False | not a git worktree |
| `D:/Project/HexHawk-smoke-v212-final-20260627-192342` | 0.07 | False | not a git worktree |
| `D:/Project/HexHawk-smoke-robust-existing-20260627c` | 0.07 | False | not a git worktree |
| `D:/Project/HexHawk-smoke-robust-existing-20260627b` | 0.07 | False | not a git worktree |
| `D:/Project/HexHawk-smoke-robust-existing-20260627` | 0.07 | False | not a git worktree |
| `D:/Project/HexHawk-smoke-v213-installer-20260627-200021` | 0.07 | False | not a git worktree |
| `D:/Project/HexHawk-ai-overhaul-smoke` | 0.07 | False | not a git worktree |
| `D:/Project/HexHawk-ai-overhaul-smoke-20260627` | 0.07 | False | not a git worktree |
| `D:/Project/HexHawk-smoke-phase0-9400` | 0.06 | False | not a git worktree |
| `D:/Project/HexHawk-ai-probe-install` | 0.06 | False | not a git worktree |
| `D:/Project/HexHawk-ai-probe-results` | 0.00 | False | not a git worktree |
| `D:/Project/HexHawk-smoke-v213-function-notebook` | 0.00 | False | not a git worktree |
| `D:/Project/HexHawk-smoke-v213-function-notebook-clean` | 0.00 | False | not a git worktree |
| `D:/Project/HexHawk-smoke-v212-function-notebook` | 0.00 | False | not a git worktree |
| `D:/Project/HexHawk-smoke-v212-dom` | 0.00 | False | not a git worktree |

## Safety confirmations

- No credentials were read or touched.
- No deploy or publish action was performed.
- No product code was changed.
- No release artifacts were staged in the main repo.
- No unapproved folder was removed.
- The main repository `D:/Project/HexHawk` was not removed.
- The excluded rc worktree was not removed.
- GYRE remains the sole HexHawk verdict/classification authority; AetherFrame is advisory cleanup planning only.
