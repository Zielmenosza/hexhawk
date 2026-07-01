# AetherFrame Cleanup Manifest

Status: dry-run cleanup plan only — no deletion performed
Generated: 2026-07-01 19:29:31

## Scope

This manifest separates small repo Factory/AetherFrame docs/scripts from large external smoke/release/probe folders under `D:/Project`.

No files or folders were deleted. No git worktrees were removed. No credentials were touched. No artifacts were moved, compressed, uploaded, or published.

## Tiny repo docs/scripts

Factory docs/scripts are not the main disk-space problem. They are small git-tracked process files and should be shrunk/redirected in git, not deleted for disk recovery.

Current handling:

- `docs/AETHERFRAME_FACTORY.md` is now legacy/redirect scaffolding.
- `docs/AETHERFRAME_FACTORY_RUNBOOK.md` is now legacy/redirect scaffolding.
- `docs/AETHERFRAME_FACTORY_LESSONS.md` is now legacy/redirect scaffolding.
- `scripts/aetherframe_factory_cycle.py` remains as a compatibility reporter.
- AetherFrame-native replacements now live in `docs/AETHERFRAME_ADVANCEMENT_MODEL.md`, `docs/AETHERFRAME_ADVANCEMENT_RUNBOOK.md`, and `docs/AETHERFRAME_LESSONS.md`.

## Large external folders

| Path | Size GB | Last modified | Git worktree | Git status | Artifact examples | Evidence examples | Recommended action |
|---|---:|---|---|---|---:|---:|---|
| `D:/Project/HexHawk-ai-overhaul-gate-20260627` | 7.05 | 2026-06-27 23:19:20 | True | dirty | 5 | 1 | do not touch — registered dirty git worktree |
| `D:/Project/HexHawk-release-candidate-v2.1-20260627-190731` | 6.95 | 2026-06-27 19:08:49 | True | dirty | 5 | 1 | do not touch — registered dirty git worktree |
| `D:/Project/HexHawk-ai-overhaul-gate` | 6.82 | 2026-06-29 18:38:44 | True | dirty | 5 | 1 | do not touch — registered dirty git worktree |
| `D:/Project/HexHawk-release-candidate-v2.1-20260627-133346` | 6.82 | 2026-06-27 13:34:52 | True | dirty | 5 | 1 | do not touch — registered dirty git worktree |
| `D:/Project/HexHawk-release-candidate-v2.1-20260627-151143` | 6.82 | 2026-06-27 15:12:43 | True | dirty | 5 | 1 | do not touch — registered dirty git worktree |
| `D:/Project/HexHawk-release-candidate-v2.1-20260627-194604` | 6.82 | 2026-06-27 19:47:37 | True | dirty | 5 | 1 | do not touch — registered dirty git worktree |
| `D:/Project/HexHawk-rc-20260626-192557` | 6.81 | 2026-06-26 19:40:22 | True | dirty | 5 | 1 | do not touch — registered dirty git worktree |
| `D:/Project/HexHawk-release-candidate-v2.0-20260627-122322` | 6.81 | 2026-06-27 12:24:11 | True | dirty | 5 | 1 | do not touch — registered dirty git worktree |
| `D:/Project/HexHawk-release-candidate-currenthead-postfeatures-20260621-123026` | 2.32 | 2026-06-21 12:31:56 | True | dirty | 5 | 1 | do not touch — registered dirty git worktree |
| `D:/Project/HexHawk-smoke-20260627-134843` | 0.13 | 2026-06-27 15:08:43 | False | not a git worktree | 1 | 2 | archive/summarize then delete after approval |
| `D:/Project/HexHawk-smoke-20260627-152540` | 0.13 | 2026-06-27 19:01:09 | False | not a git worktree | 1 | 1 | archive/summarize then delete after approval |
| `D:/Project/HexHawk-smoke-currenthead-postfeatures-20260621-123026` | 0.13 | 2026-06-21 12:42:48 | False | not a git worktree | 2 | 0 | archive/summarize then delete after approval |
| `D:/Project/HexHawk-ai-overhaul-smoke` | 0.07 | 2026-06-29 18:49:50 | False | not a git worktree | 1 | 1 | archive/summarize then delete after approval |
| `D:/Project/HexHawk-ai-overhaul-smoke-20260627` | 0.07 | 2026-06-27 23:32:35 | False | not a git worktree | 1 | 1 | archive/summarize then delete after approval |
| `D:/Project/HexHawk-ai-overhaul-smoke-20260627-final` | 0.07 | 2026-06-27 23:45:32 | False | not a git worktree | 1 | 1 | archive/summarize then delete after approval |
| `D:/Project/HexHawk-ai-overhaul-smoke-20260627-final2` | 0.07 | 2026-06-27 23:52:19 | False | not a git worktree | 1 | 1 | archive/summarize then delete after approval |
| `D:/Project/HexHawk-smoke-20260627-123927` | 0.07 | 2026-06-27 12:56:18 | False | not a git worktree | 1 | 2 | archive/summarize then delete after approval |
| `D:/Project/HexHawk-smoke-robust-existing-20260627` | 0.07 | 2026-06-27 19:03:49 | False | not a git worktree | 1 | 1 | archive/summarize then delete after approval |
| `D:/Project/HexHawk-smoke-robust-existing-20260627b` | 0.07 | 2026-06-27 19:04:49 | False | not a git worktree | 1 | 1 | archive/summarize then delete after approval |
| `D:/Project/HexHawk-smoke-robust-existing-20260627c` | 0.07 | 2026-06-27 19:05:41 | False | not a git worktree | 1 | 1 | archive/summarize then delete after approval |
| `D:/Project/HexHawk-smoke-v212-final-20260627-192342` | 0.07 | 2026-06-27 19:23:58 | False | not a git worktree | 1 | 1 | archive/summarize then delete after approval |
| `D:/Project/HexHawk-smoke-v213-installer-20260627-200021` | 0.07 | 2026-06-27 20:00:37 | False | not a git worktree | 1 | 1 | archive/summarize then delete after approval |
| `D:/Project/HexHawk-ai-probe-install` | 0.06 | 2026-06-29 19:04:39 | False | not a git worktree | 0 | 0 | safe delete after approval if empty/redundant |
| `D:/Project/HexHawk-smoke-phase0-9400` | 0.06 | 2026-06-27 19:39:38 | False | not a git worktree | 0 | 0 | safe delete after approval if empty/redundant |
| `D:/Project/HexHawk-ai-probe-results` | 0.0 | 2026-06-29 19:29:30 | False | not a git worktree | 0 | 2 | archive/summarize then delete after approval |
| `D:/Project/HexHawk-smoke-v212-dom` | 0.0 | 2026-06-27 19:32:32 | False | not a git worktree | 0 | 0 | safe delete after approval if empty/redundant |
| `D:/Project/HexHawk-smoke-v212-function-notebook` | 0.0 | 2026-06-27 19:27:36 | False | not a git worktree | 0 | 0 | safe delete after approval if empty/redundant |
| `D:/Project/HexHawk-smoke-v213-function-notebook` | 0.0 | 2026-06-27 20:04:16 | False | not a git worktree | 0 | 1 | archive/summarize then delete after approval |
| `D:/Project/HexHawk-smoke-v213-function-notebook-clean` | 0.0 | 2026-06-27 20:06:03 | False | not a git worktree | 0 | 1 | archive/summarize then delete after approval |

## Evidence preservation rules

Preserve latest/current evidence before any deletion approval:

- latest `EVIDENCE_MANIFEST.json`;
- latest `SHA256SUMS.txt`;
- latest installer smoke JSON;
- latest Function Notebook/export proof;
- package hashes;
- commit/tag references;
- any unique buyer/release gate evidence.

Do not preserve every duplicate screenshot forever once a manifest/report captures the useful evidence, but do not delete unique proof blindly.

## Proposed deletion batch — requires explicit approval

These are candidates only. They are not approved for deletion in this run.

Estimated recoverable GB from non-worktree candidates listed below: **1.21 GB**.

| Exact path | Size GB | Proposed action | Required preservation before deletion |
|---|---:|---|---|
| `D:/Project/HexHawk-smoke-20260627-134843` | 0.13 | archive/summarize then delete after approval | Preserve/summarize evidence first: installer-smoke-result.json, manual-v21e/function-notebook-export.json |
| `D:/Project/HexHawk-smoke-20260627-152540` | 0.13 | archive/summarize then delete after approval | Preserve/summarize evidence first: installer-smoke-result.json |
| `D:/Project/HexHawk-smoke-currenthead-postfeatures-20260621-123026` | 0.13 | archive/summarize then delete after approval | Preserve/summarize evidence first: none detected |
| `D:/Project/HexHawk-ai-overhaul-smoke` | 0.07 | archive/summarize then delete after approval | Preserve/summarize evidence first: installer-smoke-result.json |
| `D:/Project/HexHawk-ai-overhaul-smoke-20260627` | 0.07 | archive/summarize then delete after approval | Preserve/summarize evidence first: installer-smoke-result.json |
| `D:/Project/HexHawk-ai-overhaul-smoke-20260627-final` | 0.07 | archive/summarize then delete after approval | Preserve/summarize evidence first: installer-smoke-result.json |
| `D:/Project/HexHawk-ai-overhaul-smoke-20260627-final2` | 0.07 | archive/summarize then delete after approval | Preserve/summarize evidence first: installer-smoke-result.json |
| `D:/Project/HexHawk-smoke-20260627-123927` | 0.07 | archive/summarize then delete after approval | Preserve/summarize evidence first: installer-smoke-result.json, function-notebook-manual/function-notebook-export.json |
| `D:/Project/HexHawk-smoke-robust-existing-20260627` | 0.07 | archive/summarize then delete after approval | Preserve/summarize evidence first: installer-smoke-result.json |
| `D:/Project/HexHawk-smoke-robust-existing-20260627b` | 0.07 | archive/summarize then delete after approval | Preserve/summarize evidence first: installer-smoke-result.json |
| `D:/Project/HexHawk-smoke-robust-existing-20260627c` | 0.07 | archive/summarize then delete after approval | Preserve/summarize evidence first: installer-smoke-result.json |
| `D:/Project/HexHawk-smoke-v212-final-20260627-192342` | 0.07 | archive/summarize then delete after approval | Preserve/summarize evidence first: installer-smoke-result.json |
| `D:/Project/HexHawk-smoke-v213-installer-20260627-200021` | 0.07 | archive/summarize then delete after approval | Preserve/summarize evidence first: installer-smoke-result.json |
| `D:/Project/HexHawk-ai-probe-install` | 0.06 | safe delete after approval if empty/redundant | Preserve/summarize evidence first: none detected |
| `D:/Project/HexHawk-smoke-phase0-9400` | 0.06 | safe delete after approval if empty/redundant | Preserve/summarize evidence first: none detected |

## Worktree caution

Registered dirty worktrees are large, but they are **not** safe deletion targets until they are reviewed, summarized, and explicitly approved for `git worktree remove` or other exact-path cleanup. Current dirty registered worktrees include multiple release-candidate and AI-overhaul worktrees around 6–7 GB each.

## Approval gate

A cleanup execution cycle must receive explicit user approval naming exact paths. Until then, all cleanup tooling remains dry-run only.
