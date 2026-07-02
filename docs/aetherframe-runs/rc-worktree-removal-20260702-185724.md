# RC Worktree Removal Execution Report

Generated: 2026-07-02 18:57:24 +0200

Status: documentation/provenance record for the completed RC worktree cleanup. This documentation run performed no deletion, no worktree removal, no `git clean`, no folder move/compression, no credential access, no deploy, and no publish action.

Authority note: GYRE remains the sole HexHawk verdict/classification authority. AetherFrame is advisory cleanup-planning support only and is not a verdict authority.

## Starting state before RC removal

- Starting HEAD: `975339c` (`[DOCS] Preserve RC worktree helper review`).
- Tag at starting HEAD: `v2.1.18-rc-worktree-helper-review`.
- Latest CI before removal: run `28605967862`, success, SHA `975339c08bf7f1ad8df085707abd9dcb2d63e4e2`, URL `https://github.com/Zielmenosza/hexhawk/actions/runs/28605967862`.
- Main repo existed: yes, `D:/Project/HexHawk`.
- Target path before removal: `D:/Project/HexHawk-rc-20260626-192557`.
- Target existed before removal: yes.
- Target was registered before removal: yes.
- Target HEAD: `3bbf1ac92273c1024b12db1da6b3e80b2d3be326`.
- Target HEAD reachable from `main`: yes.
- Target HEAD reachable from `origin/main`: yes.
- Preserved evidence summary existed before removal: `docs/preserved-evidence/hexhawk-rc-20260626-192557.md`.
- Helper review report existed before removal: `docs/aetherframe-runs/rc-worktree-helper-review-20260702-183049.md`.

## Removal method used

```text
git worktree remove --force "D:/Project/HexHawk-rc-20260626-192557"
```

Git unregistered the worktree but reported that the directory was not empty. The remaining directory was treated as a non-git residual only after confirming:

- it was no longer listed by `git worktree list`;
- no `.git` directory remained at the target path;
- the residual cleanup used only the exact path `D:/Project/HexHawk-rc-20260626-192557`;
- no wildcard deletion was used.

## Post-removal verification

- Target path absent: yes.
- Target no longer registered: yes.
- Current registered worktrees after removal:

```text
D:/Project/HexHawk 975339c [main]
```

- Estimated recovered space: **about 6.81 GiB**.
- Total large worktree cleanup recovered: **about 57.22 GB** (W2 50.41 GB + RC 6.81 GB).

## Local generated validation reports

Local generated validation reports remain untracked and were not staged. They can be cleaned later in a separate approval-gated housekeeping run.

Untracked reports recorded at the start of this documentation run:

- `docs/aetherframe-runs/factory-cycle-20260701-195521.md`
- `docs/aetherframe-runs/factory-cycle-20260701-201811.md`
- `docs/aetherframe-runs/factory-cycle-20260701-204011.md`
- `docs/aetherframe-runs/factory-cycle-20260702-002155.md`
- `docs/aetherframe-runs/factory-cycle-20260702-181939.md`
- `docs/aetherframe-runs/factory-cycle-20260702-183305.md`
- `docs/aetherframe-runs/factory-cycle-20260702-183337.md`
- `docs/aetherframe-runs/worktree-custody-20260701-201449.md`


## Safety confirmations

- Nothing was deleted in this documentation/provenance run.
- No additional git worktree was removed in this documentation/provenance run.
- No `git clean` was run.
- No PowerShell folder-removal command was run.
- No folders were moved or compressed.
- No credentials were touched.
- No deploy or publish action was performed.
- No product code was changed.
- No website files, release artifacts, binaries, screenshots, zips, credentials, or unrelated generated validation reports were staged.
- No unapproved folder was removed by the recorded RC cleanup; the only removed path was `D:/Project/HexHawk-rc-20260626-192557`.
