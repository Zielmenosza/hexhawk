# AetherFrame Evidence Preservation Plan

Generated: 2026-07-01 19:55:02

Status: preservation plan only. Nothing was deleted, moved, compressed, uploaded, published, or unregistered.

Authority note: GYRE remains the sole HexHawk verdict/classification authority. AetherFrame is advisory cleanup-planning support only.

## Preserve before any approved cleanup

- One compact per-folder evidence summary containing path, size, last modified, associated commit/HEAD, artifact hashes if available, and whether the folder was a registered worktree.
- Named JSON evidence files: `installer-smoke-result.json`, `probe-result.json`, `function-notebook-export.json`, and `EVIDENCE_MANIFEST.json`.
- Hash manifests such as `SHA256SUMS.txt` and any package manifest that ties MSI/NSIS/ZIP artifacts to hashes and dates.
- A small screenshot contact sheet or manifest for unique screenshots only; duplicate installer smoke screenshots can be discarded later after their JSON/hash evidence is preserved.
- Git worktree dirty-state summaries before any future worktree removal approval: branch/HEAD, `git status --short`, untracked paths, and proof that needed commits are reachable from `main`/`origin/main` or intentionally abandoned.

## Preservation location

- Store compact summaries in `docs/aetherframe-runs/` with timestamped names, e.g. `workspace-cleanup-classification-<timestamp>.md`.
- Keep release-level hashes/manifests in existing release-evidence or AetherFrame run docs, not inside disposable smoke folders.
- Do not copy full installer trees, zips, screenshots, or binaries into git. Preserve only compact textual summaries/manifests unless the user explicitly approves an external evidence archive path.

## Latest proof pointers from this classification

- Latest installer smoke proof: `D:/Project/HexHawk-ai-overhaul-smoke/installer-smoke-result.json` (mtime 2026-06-29 18:49:50).
- Latest Function Notebook export proof: `D:/Project/HexHawk-ai-probe-results/function-notebook-export.json` (mtime 2026-06-29 22:10:47).
- Latest probe proof: `D:/Project/HexHawk-ai-probe-results/probe-result.json` (mtime 2026-06-29 22:10:47).
- Latest package/hash manifest: `D:/Project/HexHawk-ai-overhaul-gate/site-build/releases/v1.0.0/SHA256SUMS.txt` (mtime 2026-06-29 18:36:58).
- Latest evidence manifest: not found in matched cleanup folders during this read-only scan.
- Latest unsigned early-access zip hash: preserve from the latest committed package/hash manifest if present; no zip hash was promoted from disposable folders in this classification.
- Latest website deployment proof: preserve existing committed deployment/run evidence; do not use disposable worktree `site-build` copies as live deployment proof without separate verification.
- Latest CI green run: `https://github.com/Zielmenosza/hexhawk/actions/runs/28536082466` for `27641469cb73a4c9567c26835f6387ec34b0db03`, conclusion success.

## Duplicate evidence that can be discarded later after preservation and explicit approval

- `D:/Project/HexHawk-ai-overhaul-smoke` — preserve compact summaries for 1 named files; 2 screenshots/images; later discard duplicate screenshots/results only after exact-path approval.
- `D:/Project/HexHawk-ai-overhaul-smoke-20260627` — preserve compact summaries for 1 named files; 2 screenshots/images; later discard duplicate screenshots/results only after exact-path approval.
- `D:/Project/HexHawk-ai-overhaul-smoke-20260627-final` — preserve compact summaries for 1 named files; 2 screenshots/images; later discard duplicate screenshots/results only after exact-path approval.
- `D:/Project/HexHawk-ai-overhaul-smoke-20260627-final2` — preserve compact summaries for 1 named files; 2 screenshots/images; later discard duplicate screenshots/results only after exact-path approval.
- `D:/Project/HexHawk-ai-probe-results` — preserve compact summaries for 2 named files; 2 screenshots/images; later discard duplicate screenshots/results only after exact-path approval.
- `D:/Project/HexHawk-smoke-20260627-123927` — preserve compact summaries for 2 named files; 5 screenshots/images; later discard duplicate screenshots/results only after exact-path approval.
- `D:/Project/HexHawk-smoke-20260627-134843` — preserve compact summaries for 2 named files; 6 screenshots/images; later discard duplicate screenshots/results only after exact-path approval.
- `D:/Project/HexHawk-smoke-20260627-152540` — preserve compact summaries for 1 named files; 10 screenshots/images; later discard duplicate screenshots/results only after exact-path approval.
- `D:/Project/HexHawk-smoke-currenthead-postfeatures-20260621-123026` — preserve compact summaries for 2 screenshots/images; later discard duplicate screenshots/results only after exact-path approval.
- `D:/Project/HexHawk-smoke-robust-existing-20260627` — preserve compact summaries for 1 named files; 2 screenshots/images; later discard duplicate screenshots/results only after exact-path approval.
- `D:/Project/HexHawk-smoke-robust-existing-20260627b` — preserve compact summaries for 1 named files; 2 screenshots/images; later discard duplicate screenshots/results only after exact-path approval.
- `D:/Project/HexHawk-smoke-robust-existing-20260627c` — preserve compact summaries for 1 named files; 2 screenshots/images; later discard duplicate screenshots/results only after exact-path approval.
- `D:/Project/HexHawk-smoke-v212-final-20260627-192342` — preserve compact summaries for 1 named files; 2 screenshots/images; later discard duplicate screenshots/results only after exact-path approval.
- `D:/Project/HexHawk-smoke-v212-function-notebook` — preserve compact summaries for 1 screenshots/images; later discard duplicate screenshots/results only after exact-path approval.
- `D:/Project/HexHawk-smoke-v213-function-notebook` — preserve compact summaries for 1 named files; 1 screenshots/images; later discard duplicate screenshots/results only after exact-path approval.
- `D:/Project/HexHawk-smoke-v213-function-notebook-clean` — preserve compact summaries for 1 named files; 1 screenshots/images; later discard duplicate screenshots/results only after exact-path approval.
- `D:/Project/HexHawk-smoke-v213-installer-20260627-200021` — preserve compact summaries for 1 named files; 2 screenshots/images; later discard duplicate screenshots/results only after exact-path approval.

## Do-not-touch evidence/provenance

- `D:/Project/HexHawk-ai-overhaul-gate` — dirty registered worktree; do not alter until human review resolves dirty files and provenance.
- `D:/Project/HexHawk-ai-overhaul-gate-20260627` — dirty registered worktree; do not alter until human review resolves dirty files and provenance.
- `D:/Project/HexHawk-rc-20260626-192557` — dirty registered worktree; do not alter until human review resolves dirty files and provenance.
- `D:/Project/HexHawk-release-candidate-currenthead-postfeatures-20260621-123026` — dirty registered worktree; do not alter until human review resolves dirty files and provenance.
- `D:/Project/HexHawk-release-candidate-v2.0-20260627-122322` — dirty registered worktree; do not alter until human review resolves dirty files and provenance.
- `D:/Project/HexHawk-release-candidate-v2.1-20260627-133346` — dirty registered worktree; do not alter until human review resolves dirty files and provenance.
- `D:/Project/HexHawk-release-candidate-v2.1-20260627-151143` — dirty registered worktree; do not alter until human review resolves dirty files and provenance.
- `D:/Project/HexHawk-release-candidate-v2.1-20260627-190731` — dirty registered worktree; do not alter until human review resolves dirty files and provenance.
- `D:/Project/HexHawk-release-candidate-v2.1-20260627-194604` — dirty registered worktree; do not alter until human review resolves dirty files and provenance.

## Manual cleanup command safety language

If future approval is granted, commands such as `git worktree remove "<exact path>"` or Windows folder deletion commands must be copied into a new execution plan and revalidated immediately before use. They are not approved by this plan.
