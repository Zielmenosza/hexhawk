# AetherFrameGuard Improvement Plan Using AetherFrame

Status: initial AF-guided plan
Scope: AetherFrameGuard inside `AetherframeGuard/`

## Purpose

Use AetherFrame as a bounded product-improvement method for AetherFrameGuard without turning AF into product authority or an autonomous loop.

AetherFrame should improve AetherFrameGuard by making each optimization step evidence-backed, reversible where possible, and explicit about missing proof.

AetherFrameGuard should improve AetherFrame by exposing desktop-utility-specific gates that HexHawk did not stress as strongly: focus theft, passive-vs-manual measurements, privileged host actions, and game-restart requirements.

## AFG authority boundaries

- AetherFrameGuard is a host/game optimization utility.
- AETHERFRAME-style scores are advisory optimization/ranking signals only.
- AFG does not make malware verdicts.
- AFG does not replace HexHawk GYRE/NEST/CREST authority.
- AFG does not prove FPS uplift without repeated gameplay-like measurements.

## AFG improvement lanes

### 1. Measure vs Apply clarity

Problem:
Users can confuse applying a setting with proving that the setting improved FPS.

AFG rule:
- Apply changes only when the user clicks an apply action.
- Measure impact only when the user clicks a measure/re-test action or when an explicitly labeled capture cycle runs.
- UI should state when CS2 restart/relaunch is required before judging impact.

Evidence needed:
- UI copy review;
- code path review for apply buttons;
- benchmark history provenance check.

### 2. Measurement provenance

Problem:
Passive/background samples can pollute Latest/Best/Baseline comparisons.

AFG rule:
Every benchmark-like record should carry provenance such as:

- `manual_measure`
- `manual_retest`
- `apply_before`
- `apply_after`
- `boot`
- `auto_monitor`
- `passive_snapshot`

User-facing improvement claims should prefer valid manual gameplay/practice-map samples.

### 3. Safe CS2 cfg custody

Problem:
CS2 config changes need exact custody and restart expectations.

AFG rule:
- Managed cfg path should remain the game cfg path, not Steam userdata.
- App should show which cfg file changed.
- App should state whether CS2 must be relaunched or `exec aetherframeguard_cs2` must be run.
- Invalid/unknown cvars should be removed at source, not only live files.

### 4. Privileged host-action gates

Problem:
Scheduled tasks, registry changes, power actions, and background monitors can surprise users.

AFG rule:
- Privileged/background actions must be explicit install choices.
- Warn-only mode should exist where possible.
- UI must expose remove/disable actions and log paths.
- Any restart/shutdown automation must show delay and cancellation command.

### 5. Single-instance/backend custody

Problem:
Duplicate backend processes can create stale/conflicting UI cards.

AFG rule:
- Engineering target should be a real single-instance guard.
- Prefer named mutex plus path-verified leftover cleanup and ProgramData logging.
- UI should distinguish stale backend state from current capture evidence.

## AetherFrame improvements learned from AFG

AF should add or preserve a desktop-utility lane with these gates:

- Focus theft gate: passive review must not launch visible tools or steal focus.
- Provenance gate: manual vs passive data must be separated before making improvement claims.
- Privilege gate: registry/tasks/power/ProgramData writes require explicit user action.
- Restart gate: game/app/Windows restart requirements must be reported before judging outcomes.
- External tool gate: PresentMon/NVIDIA/Steam interactions must be explicit, logged, and failure-tolerant.

## First practical AFG cycle

Recommended next cycle:

1. Run `npm run build` or `npx tsc --noEmit` in `AetherframeGuard/`.
2. Run `cargo check` in `AetherframeGuard/src-tauri/`.
3. Audit UI copy for Apply-vs-Measure confusion.
4. Audit benchmark provenance in frontend/backend data structures.
5. Produce one narrow fix or a NO SAFE NEXT PROMPT outcome if product behavior needs user confirmation.

## Stop conditions

Stop before:

- changing registry/task/power behavior;
- launching CS2 or PresentMon;
- changing package/release artifacts;
- deleting build outputs;
- making guaranteed performance claims;
- making HexHawk verdict/classification claims.
