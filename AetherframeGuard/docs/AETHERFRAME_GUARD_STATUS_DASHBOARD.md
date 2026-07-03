# AetherFrameGuard AF Status Dashboard

Status date: 2026-07-03
Scope: AetherFrameGuard only. This is separate from HexHawk verdict/classification behavior.

## Current active focus

Make AetherFrameGuard safer and clearer as a CS2/Windows optimization assistant by separating:

- measure vs apply;
- passive/background observations vs user-triggered benchmark evidence;
- advisory AETHERFRAME-style ranking vs proof of FPS improvement;
- manual safe changes vs privileged boot/auto-monitor automation.

## Current green baseline

Repository baseline observed from the parent HexHawk repo:

- HEAD: `4f09824c7cb7f6610048f791010159c37fe1031d`
- Tag at HEAD: `v2.1.24-aetherframe-commercial-ops`
- Latest main CI: `28674775171` completed successfully.
- AetherFrameGuard path: `AetherframeGuard/`

## Product posture

AetherFrameGuard is a separate Windows utility. It is not HexHawk, not GYRE, and not a malware verdict authority.

Current useful capability lane:

- CS2/PC optimization guidance;
- PresentMon-backed measurement when available;
- managed CS2 cfg generation under the game cfg path;
- safe/reversible Windows gaming-profile changes;
- diagnostic logging under `C:\ProgramData\AetherframeGuard`;
- advisory ranking of next safe optimization steps.

## Next gate

Before deeper product changes, run a focused AFG evidence cycle:

1. Build/type-check AFG without modifying release artifacts.
2. Inspect UI wording around Apply vs Measure.
3. Inspect provenance handling for Latest/Best/Baseline cards.
4. Confirm docs do not imply guaranteed FPS uplift.
5. Identify one small code/UI change only if validation shows a clear mismatch.

## Do-not-cross lines

- Do not conflate AetherFrameGuard with HexHawk verdict/classification authority.
- Do not claim guaranteed FPS increase.
- Do not claim anti-cheat bypass, cheat detection, or malware verdict capability.
- Do not silently launch CS2, PresentMon, NVIDIA tools, or privileged tasks during passive review.
- Do not change Windows registry, scheduled tasks, Steam cfg, or ProgramData state without explicit user action.
- Do not treat passive/background snapshots as proof that an applied setting improved gameplay.
- Do not delete build artifacts or cleanup folders without exact-path approval.

## Recommended immediate action

Use the AFG Measurement/Apply separation plan to audit the installed-app wording and implementation path. Prefer a narrow docs/UI clarity change before touching backend optimization logic.
