# HexHawk External Tester Known Issues

Date: 2026-06-01
Current audience: internal testers and controlled pilot candidates only

## Release blockers

1. Windows artifacts are signed with an internal self-signed development certificate (not publicly trusted).
   - Expected effect: SmartScreen or enterprise endpoint controls may still warn or block due untrusted root.
   - Status: unresolved for public distribution.

2. Updater signing path is enabled in config, but endpoint metadata validation failed.
   - Current config has `createUpdaterArtifacts: true` and non-empty updater pubkey.
   - Endpoint validation failed in latest pass because `releases.hexhawk.app` did not resolve.
   - Status: unresolved until production endpoint is reachable and returns valid platform/signature metadata.

3. Full enterprise procurement package is not complete.
   - Support intake exists.
   - SLA, DPA/security questionnaire, procurement vendor packet, and signed release provenance remain pending.

## Non-blocking warnings observed

- Tauri warns that identifier `com.hexhawk.app` ends with `.app`; this is not recommended for macOS bundle naming. Current pilot target is Windows.
- Vite warns that the main JavaScript chunk is larger than 500 kB. This is a polish/performance item, not a current correctness blocker.
- Rust build emits existing unused/dead-code warnings. Current build/test gates pass, but cleanup should be scheduled.

## Recently repaired

- Packaged native GUI runtime proof now passes from an MSI-extracted app path.
- Report JSON export now preserves GYRE authority markers:
  - `source_engine: gyre`
  - `gyre_is_sole_verdict_source: true`
  - `final_verdict_snapshot`
- Tauri WebView2 bootstrapper config is under `bundle.windows.webviewInstallMode` rather than the invalid NSIS subkey.

## Tester copy limits

Do not claim:
- publicly trusted signed release
- public release ready
- production ready
- updater ready
- enterprise ready

Acceptable wording:
- internal-tester Windows product candidate
- controlled external pilot candidate only after pilot sponsor accepts internal-signing/updater-endpoint constraints or organization-trusted signing and updater endpoint validation are completed
- market readiness: controlled only
