# AetherFrameGuard AF Exercise Report

Status date: 2026-07-03
Scope: AetherFrameGuard only

## Mission

Use AetherFrame on AetherFrameGuard to find safe improvements for AFG and identify how AFG pressure-tests AetherFrame itself.

## Baseline observed

- Parent repository: `D:/Project/HexHawk`
- AFG path: `AetherframeGuard/`
- Baseline HEAD: `4f09824c7cb7f6610048f791010159c37fe1031d`
- Baseline tag at HEAD: `v2.1.24-aetherframe-commercial-ops`
- Latest main CI at start: `28674775171` completed successfully
- Worktree: only parent main worktree was registered

Existing untracked parent reports under `docs/aetherframe-runs/` were observed and intentionally left untouched.

## What AF improved in AFG

### 1. Clearer product posture

AFG is now documented as a separate Windows utility with advisory AETHERFRAME-style optimization scores only. The new status dashboard makes the boundary explicit: AFG does not own HexHawk verdicts, does not replace GYRE, and does not prove FPS uplift without repeated gameplay-like measurement.

### 2. Measure-vs-Apply operating rule

The most important AFG improvement is the explicit rule that applying settings is not the same as proving improvement. The docs now direct future work to keep `Measure/Re-test` separate from `Apply`, and to require gameplay-like evidence before improvement claims.

### 3. Measurement provenance focus

AFG needs stronger source labeling for manual measurements, passive snapshots, boot cycles, auto-monitor samples, and apply-before/apply-after samples. AF now records this as a product improvement lane instead of treating all benchmark-like samples as equivalent.

### 4. Privileged host-action gates

AFG touches a riskier domain than HexHawk docs work: Windows settings, Steam cfg files, scheduled tasks, ProgramData, PresentMon, and possible launch/focus behavior. The new plan adds explicit gates for these host actions.

### 5. Tester cycle readiness

The new tester cycle gives AFG a safer first-user feedback path: technical Windows/CS2 testers, repeated measurements, clear restart/relaunch expectations, and no guaranteed FPS/anti-cheat/malware-verdict claims.

## What AFG improved in AF

AetherFrame needs a desktop-utility lane, not just a repo/docs/release lane. AFG revealed five AF gates that should be reused for similar apps:

1. Focus-theft gate: passive analysis must not launch visible tools, console windows, games, or helper GUIs unexpectedly.
2. Provenance gate: manual user-triggered measurements must be separated from passive/background/boot samples before making improvement claims.
3. Privilege gate: registry, scheduled-task, power, Steam cfg, and ProgramData writes require explicit user action and visible rollback/removal information.
4. Restart gate: app/game/Windows restart requirements must be captured before judging outcomes.
5. External-tool gate: PresentMon, NVIDIA tools, Steam, and game-launch interactions need explicit status, failure handling, and log paths.

## Files created/updated

Created:

- `AetherframeGuard/docs/AETHERFRAME_GUARD_STATUS_DASHBOARD.md`
- `AetherframeGuard/docs/AETHERFRAME_GUARD_IMPROVEMENT_PLAN.md`
- `AetherframeGuard/docs/AETHERFRAME_GUARD_TESTER_CYCLE.md`
- `AetherframeGuard/docs/AETHERFRAME_GUARD_AF_EXERCISE_REPORT.md`

Updated:

- `AetherframeGuard/README.md`

## Validation

Commands run:

```bash
git diff --check
cd AetherframeGuard && npx tsc --noEmit
cd AetherframeGuard/src-tauri && cargo check
grep -RniE "guaranteed FPS|guarantee a.*FPS|anti-cheat bypass|cheat detector|malware verdict|replace GYRE|public-ready|Microsoft verified|auto-update|deploy automatically|delete automatically|use credentials" AetherframeGuard/README.md AetherframeGuard/docs 2>/dev/null || true
```

Observed result:

- `git diff --check`: pass
- `npx tsc --noEmit`: pass
- `cargo check`: pass
- unsafe wording search: hits were negative/guardrail wording only

## Stop conditions preserved

This exercise did not:

- delete anything;
- run cleanup;
- deploy or publish;
- touch credentials;
- launch CS2 or PresentMon;
- change Windows registry, scheduled tasks, power settings, Steam cfg, or ProgramData;
- stage package artifacts, binaries, screenshots, or ZIPs;
- claim guaranteed FPS improvement;
- claim Microsoft verification, public readiness, signed release, anti-cheat bypass, cheat detection, or malware verdict authority.

## Recommended next AFG action

Run a focused AFG UI/code audit for Apply-vs-Measure wording and benchmark provenance. Only make a code/UI change if a clear mismatch is found and validation can prove it.
