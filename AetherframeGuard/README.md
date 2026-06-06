# AetherframeGuard

AetherframeGuard is a separate Windows utility that uses bounded AETHERFRAME-style confidence ranking
for host hardening, low-latency gaming, and game-performance recommendations.

It is intentionally isolated from HexHawk runtime behavior. Its AETHERFRAME-style scores are advisory
host-optimization signals only; they are not malware verdicts, do not replace GYRE, and do not change
HexHawk classification, base confidence, or security truth.

## Features

- Guided CS2/PC optimizer flow: measure repeatedly, classify likely menu/lobby vs gameplay samples, review stability/1% lows, apply safe settings, restart/relaunch if needed, and re-test.
- Host signal collection: firewall, Defender realtime, power plan, process load, baseline ping.
- Bounded AETHERFRAME-style promotion/ranking model for advisory optimization only.
- Ranked recommendations for security, latency, and performance.
- **Apply Suggested FPS Settings** button: backs up config, applies safe CS2/profile recommendations, records a change set, and captures before/after benchmark snapshots.
- Steam Counter-Strike profile sync: maintains a managed CS2 autoexec hook for configured Steam accounts.
- Counter-Strike FPS/frametime capture through PresentMon when PresentMon is installed in a configured tools folder or on PATH.
- Defensive security scan: checks local risky process names, suspicious startup/scheduled-task patterns, overlay/capture tools, Windows security misconfiguration, and review-worthy CS2 config lines.
- Silent scheduled/background optimization mode for boot and auto-monitor tasks.
- Tauri desktop app with Windows installer support.

## Simple use

1. Click **Step 1: Measure Current FPS / PC State**.
2. Review the recommendations and warnings.
3. Click **Apply Suggested FPS Settings** only if you accept the listed changes.
4. Relaunch CS2 when the app says a CS2 restart is required. Restart Windows only when a Windows-level action says so.
5. Click **Re-test Now** and compare **Baseline**, **Latest**, and **Best observed**. Prefer gameplay/practice-map captures over menu FPS.

AetherframeGuard does not promise a 100% FPS increase. It records measured signals and keeps using the best
observed safe state as the comparison point. If a new result is worse, the app reports a guardrail note and suggests
rollback/manual review instead of pretending the change worked.


## CS2 iterative optimizer model

The CS2 path now scores more than raw average FPS. Each PresentMon-backed sample records:

- average FPS and frametime;
- estimated 1% low and 0.1% low FPS from frame-time samples;
- frame-pacing stability and stutter-spike candidates;
- a conservative scene classifier: `gameplay_candidate`, `menu_or_lobby`, or `unknown`;
- PC/network/system latency context when available.

Menu/lobby FPS can be much higher than real gameplay FPS, so AetherframeGuard penalizes likely menu-only samples when choosing the best observed state. The best result is the safest observed gameplay-like trial, not necessarily the highest average FPS number.

## Apply Suggested FPS Settings button

The main CS2 button is intentionally conservative. It can:

- Back up existing CS2 config files before editing.
- Write or refresh `aetherframeguard_cs2.cfg` with safe, reversible CS2 recommendations such as `fps_max 0`, high network rate, visible telemetry, and low-latency sleep-after-client-tick.
- Append an `exec aetherframeguard_cs2` hook to `autoexec.cfg` only after backup, without removing user custom lines.
- Save a Windows profile snapshot before changing Game DVR / app capture settings.
- Apply the supported Game profile settings that reduce Windows capture-overlay contention.
- Record the change set under `C:\ProgramData\AetherframeGuard`.
- Mark that CS2 must be relaunched before FPS should be judged.

It does **not** modify CS2 memory, bypass anti-cheat, install cheats, or apply unguarded registry tweaks. If a setting
cannot be safely applied automatically, it remains a manual recommendation.

## Counter-Strike telemetry requirements

AetherframeGuard cannot read reliable CS2 FPS directly from Steam or the game config files. Live FPS,
frametime, and PC-latency capture depends on PresentMon.

Supported PresentMon discovery locations:

- `C:\Users\Ziel\Desktop\Tools\PresentMon`
- `C:\Program Files\PresentMon`
- `C:\Program Files (x86)\PresentMon`
- `C:\Program Files\Intel\PresentMon`
- `C:\Program Files\Intel\PresentMon\x64`
- `C:\Program Files\Intel\PresentMon\PresentMonConsoleApplication`
- any directory on `PATH`

Recognized PresentMon executable names include `PresentMon-64bit.exe`, `PresentMon64.exe`, `PresentMon.exe`,
`presentmon.exe`, `PresentMon-2.4.1-x64.exe`, and `PresentMon_x64.exe`.

If PresentMon is missing, CS2 profile sync and Windows tuning can still run, but benchmark history will
show `avgFps`, `avgFrametimeMs`, and `pcLatencyMs` as `null` and the CS2 readiness panel will report
that no FPS capture source is available.

## Scheduled/background behavior

- Boot task: applies guarded boot optimizations using the backend with `--boot-optimize`.
- Auto-monitor task: runs a silent SYSTEM cycle every 5 minutes with `--auto-cycle` after the task is reinstalled.
- Background cycles do not open NVIDIA Profile Inspector GUI. If the CLI importer is unavailable, the cycle logs
  that the GUI was skipped. Use the manual NVIDIA tuning button in the app when GUI review/import is needed.
- CS2 relaunch handling is primarily through the managed Steam `autoexec.cfg` hook: when CS2 starts, the managed
  profile is executed by the game. The auto-monitor cycle then re-measures and repairs drift periodically.

AetherframeGuard targets iterative improvement toward the best safe observed state. It does not guarantee a 100% FPS
increase or a perfect optimization score. Use benchmark history and PresentMon telemetry to verify actual
machine-specific changes.

## Repair/update boundaries

AetherframeGuard can perform host-optimization repairs when explicitly invoked: profile application/restoration,
Steam Counter-Strike profile sync, benchmark capture, NVIDIA tuning cycles, network optimization, and scheduled-task
install/remove actions. These actions may write Windows settings, ProgramData state, Steam profile files, diagnostics,
or scheduled tasks.

AETHERFRAME-style scoring ranks and records these changes as advisory optimization signals only. It does not make
malware verdicts, does not replace HexHawk GYRE/NEST/CREST authority, and does not prove FPS/latency uplift without
live telemetry and benchmark evidence.


## Backups, rollback, and security notes

- CS2 config backups are written under `C:\ProgramData\AetherframeGuard\backups\...` before the suggested settings flow edits existing files.
- Windows profile snapshots are saved with the same change set so the last profile can be restored from the UI.
- Security findings redact the current user profile path where possible and avoid collecting credentials or secrets.
- CS2 config review flags risky-looking lines for user review only; it is not a cheat detector, malware verdict, or anti-cheat bypass.
- Background/boot tasks are advanced features because they run with high Windows privileges. Prefer the manual button until the behavior is verified on your machine.

## Run

```bash
npm run tauri:dev
```

## Build installer (Windows)

```bash
npm run tauri:build
```
