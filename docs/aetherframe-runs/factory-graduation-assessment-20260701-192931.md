# Factory Graduation Assessment

Generated: 2026-07-01 19:29:31
Starting HEAD: c43b5b9

## State audit

- main clean: yes, from `git status --short --branch`.
- current HEAD pushed: yes, `main...origin/main`.
- latest CI on main: success, run `28533695500`, head `c43b5b9803e23db10ca66ed968db140f3953407f`.
- website early-access path: present in `site-build/index.html`, `pricing`, `downloads`, `payments`.
- unsigned early-access package path: present in `docs/UNSIGNED_EARLY_ACCESS_POLICY.md`, `docs/UNSIGNED_EARLY_ACCESS_GATE.md`, and release package script.
- Factory docs and reporter: present before this migration.
- AetherFrame boundaries: preserved in docs and site language.

## Is HexHawk mature enough that the Factory can be retired today?

**No.** HexHawk has a truthful early-access channel and green CI, but public signed release trust remains blocked by Authenticode signing, updater proof, signed exact-artifact release gate, public download/trust workflow, and first paid tester feedback.

## Is AetherFrame mature enough that Hermes can use it directly today?

**Partially yes.** Hermes can now use AetherFrame Advancement Cycle wording and the AetherFrame-native runbook/template. The reporter still has legacy Factory naming and should be treated as a compatibility wrapper.

## Which Factory responsibilities have been absorbed?

- Bounded cycle structure.
- Authority-boundary checklist.
- Evidence-first inspection discipline.
- Release trust and unsigned early-access gates.
- Lessons ledger.
- Stop conditions and human approval gates.
- Project-neutral template for reuse beyond HexHawk.

## Which responsibilities still depend on Factory docs/tools?

- `scripts/aetherframe_factory_cycle.py` still writes `factory-cycle-*` reports.
- Historical run reports remain under `docs/aetherframe-runs/`.
- Some existing references and habits still say Factory instead of AetherFrame Advancement.

## What exact work remains before archival?

1. Build `scripts/aetherframe_advancement_cycle.py` or make the current reporter a thin compatibility wrapper.
2. Preserve/summarize current Factory run evidence.
3. Confirm no docs/scripts still require Factory wording for active workflows.
4. Run one more normal improvement cycle using only AetherFrame Advancement terminology.
5. Get explicit user approval for archival/removal.

## Is deletion safe?

**No.** Deletion is not safe today. Factory files still preserve historical context, reports, and compatibility.

## Is archival safe?

**Partially.** Shrinking docs into redirects is safe and was performed. Physical removal/deletion should wait for explicit approval.

## Disk cleanup candidates observed

- `D:/Project/HexHawk-ai-overhaul-gate-20260627` — 7.05 GB, worktree=True, status=dirty, recommendation=do not touch — registered dirty git worktree
- `D:/Project/HexHawk-release-candidate-v2.1-20260627-190731` — 6.95 GB, worktree=True, status=dirty, recommendation=do not touch — registered dirty git worktree
- `D:/Project/HexHawk-ai-overhaul-gate` — 6.82 GB, worktree=True, status=dirty, recommendation=do not touch — registered dirty git worktree
- `D:/Project/HexHawk-release-candidate-v2.1-20260627-133346` — 6.82 GB, worktree=True, status=dirty, recommendation=do not touch — registered dirty git worktree
- `D:/Project/HexHawk-release-candidate-v2.1-20260627-151143` — 6.82 GB, worktree=True, status=dirty, recommendation=do not touch — registered dirty git worktree
- `D:/Project/HexHawk-release-candidate-v2.1-20260627-194604` — 6.82 GB, worktree=True, status=dirty, recommendation=do not touch — registered dirty git worktree
- `D:/Project/HexHawk-rc-20260626-192557` — 6.81 GB, worktree=True, status=dirty, recommendation=do not touch — registered dirty git worktree
- `D:/Project/HexHawk-release-candidate-v2.0-20260627-122322` — 6.81 GB, worktree=True, status=dirty, recommendation=do not touch — registered dirty git worktree
- `D:/Project/HexHawk-release-candidate-currenthead-postfeatures-20260621-123026` — 2.32 GB, worktree=True, status=dirty, recommendation=do not touch — registered dirty git worktree
- `D:/Project/HexHawk-smoke-20260627-134843` — 0.13 GB, worktree=False, status=not a git worktree, recommendation=archive/summarize then delete after approval
- `D:/Project/HexHawk-smoke-20260627-152540` — 0.13 GB, worktree=False, status=not a git worktree, recommendation=archive/summarize then delete after approval
- `D:/Project/HexHawk-smoke-currenthead-postfeatures-20260621-123026` — 0.13 GB, worktree=False, status=not a git worktree, recommendation=archive/summarize then delete after approval

## Recommended decision

**Begin migration.**

Do not destroy the Factory. Use AetherFrame Advancement Cycle wording going forward. Keep legacy Factory files as redirects/historical continuity. Use the dry-run cleanup manifest to request exact-path deletion approval later.
