# HexHawk External Tester Known Issues

Date: 2026-06-02
Current audience: internal testers and controlled pilot candidates only

## Release blockers

1. Current Windows artifacts are unsigned.
   - `Get-AuthenticodeSignature` reports the current exe/MSI/NSIS artifacts as not digitally signed.
   - Expected effect: SmartScreen or enterprise endpoint controls may warn or block.
   - Status: unresolved for public distribution.

2. Previous internal self-signed evidence is historical only.
   - `docs/release-evidence/windows_release_hardening_2026-06-01_204639.json` recorded internal self-signed signatures for older artifact hashes.
   - Current artifact hashes are recorded in `docs/release-evidence/windows_release_truth_consolidation_2026-06-02_171415.json` and are unsigned.

3. Updater metadata is reachable but key custody is not yet public-release ready.
   - `bundle.createUpdaterArtifacts` is currently false for local unsigned builds.
   - Configured endpoint `https://hexhawk.ke/releases/latest.json` resolves, fetches, and returns Tauri-style `windows-x86_64` URL/signature metadata.
   - Status: acceptable for internal tester proof with caveat; unresolved for public release until updater signing key custody is moved into a secure official release environment or rotated there.

4. Full enterprise procurement package is not complete.
   - Support intake exists.
   - SLA, DPA/security questionnaire, procurement vendor packet, and signed release provenance remain pending.

## Non-blocking warnings observed

- Tauri warns that identifier `com.hexhawk.app` ends with `.app`; this is not recommended for macOS bundle naming. Current pilot target is Windows.
- Vite warns that the main JavaScript chunk is larger than 500 kB. This is a polish/performance item, not a current correctness blocker.
- Rust build emits existing unused/dead-code warnings. Current build/test gates pass, but cleanup should be scheduled.

## Recently proven in current pass

- Fresh artifacts were built after stale artifacts were removed.
- Packaged native GUI runtime proof passed from an MSI-extracted app path for current MSI hash `78bf99874acb9419525ab3012ac36252d2f8cc7605850aa773d36cc6865ec1e4`.
- Report JSON export preserves GYRE authority markers:
  - `source_engine: gyre`
  - `gyre_is_sole_verdict_source: true`
  - `final_verdict_snapshot`
- Report JSON includes NEST evidence-bundle status fields without fabricating typed NEST evidence.

## Tester copy limits

Do not claim:

- publicly trusted signed release
- signed current artifacts
- public release ready
- production ready
- updater public-release ready
- enterprise ready

Acceptable wording:

- internal-tester Windows product candidate
- controlled external pilot candidate only after pilot sponsor accepts unsigned/updater-key-custody constraints or organization-trusted signing and official updater key custody are completed
- market readiness: controlled only
