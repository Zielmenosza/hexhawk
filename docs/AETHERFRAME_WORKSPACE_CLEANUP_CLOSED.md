# HexHawk Workspace Cleanup Chapter Closed

Generated: 2026-07-02 23:22:05 +0200

Status: closure note for the large workspace cleanup cycle. This document records final state only. It does not approve deletion and does not perform cleanup.

Authority note: GYRE remains the sole HexHawk verdict/classification authority. AetherFrame is advisory cleanup-planning support only and is not a verdict authority.

## Final large cleanup result

The large registered-worktree cleanup cycle is closed.

- Total large worktree recovery: **about 57.22 GB**.
- W2 registered worktrees recovered: **about 50.41 GB**.
- RC registered worktree recovered: **about 6.81 GiB**.
- Current registered worktrees: only `D:/Project/HexHawk`.

## What was closed

### W2 worktrees

The W2 registered worktrees were removed only after evidence preservation.

Evidence/provenance references:

- `docs/AETHERFRAME_PRESERVED_EVIDENCE_INDEX.md`
- `docs/AETHERFRAME_WORKTREE_DECOMMISSION_PLAN.md`
- `docs/aetherframe-runs/w2-worktree-removal-20260702-002142.md`

### RC worktree

The remaining RC registered worktree was removed only after helper-script review and evidence preservation.

Removed path recorded in provenance docs:

- `D:/Project/HexHawk-rc-20260626-192557`

Evidence/provenance references:

- `docs/preserved-evidence/hexhawk-rc-20260626-192557.md`
- `docs/aetherframe-runs/rc-worktree-helper-review-20260702-183049.md`
- `docs/aetherframe-runs/rc-worktree-removal-20260702-185724.md`

## Final CI state

The small cleanup plan commit was verified green:

- Commit: `383849e72490de1eeaaa77dc38c5967614225195` (`[DOCS] Record remaining small cleanup plan`)
- Tag: `v2.1.20-small-cleanup-plan`
- CI run: `28608418208`
- CI result: completed / success

## Remaining optional small cleanup

Remaining small cleanup candidates are non-registered smoke/probe/package folders, estimated at about **1.27 GiB** total in the final local inventory.

Recommendation:

- Do not chase the small folders unless disk pressure returns.
- Keep `D:/Project/HexHawk-early-access-packages` until package custody/release process is settled.
- Preserve evidence before removing any smoke/probe folder that contains installer smoke results, probe outputs, screenshots, package hashes, Function Notebook exports, or release notes.
- Treat local untracked validation reports under `docs/aetherframe-runs/` as a separate small housekeeping concern; they can be handled later in an approval-gated housekeeping run.
- Any future cleanup must name exact paths and receive explicit approval before deletion.

The detailed small-candidate plan is tracked in:

- `docs/AETHERFRAME_SMALL_CLEANUP_PLAN.md`

## Safety confirmations

- No credentials were touched during the cleanup documentation/closure runs.
- No deploy or publish action was performed.
- No product code was changed.
- Evidence summaries were preserved before large worktree removal.
- No additional registered worktrees remain.
- No deletion is authorized by this closure note.
