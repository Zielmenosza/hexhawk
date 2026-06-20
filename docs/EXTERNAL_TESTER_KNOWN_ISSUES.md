# HexHawk External Tester Known Issues

Date: 2026-06-20
Current audience: internal testers and controlled pilot candidates only

## Release blockers

1. Current Windows artifacts are unsigned.
   - `Get-AuthenticodeSignature` reports the June 20 deployment-candidate MSI/NSIS artifacts as `NotSigned`.
   - Expected effect: SmartScreen or enterprise endpoint controls may warn or block.
   - Status: unresolved for public distribution.

2. Previous internal self-signed or native GUI evidence is historical only.
   - Prior evidence files apply only to their recorded artifact hashes.
   - Current artifact hashes are recorded in `docs/release-evidence/unsigned_deployment_candidate_2026-06-20_215102.json` and are unsigned.
   - Exact-artifact launch/render smoke passed for MSI extraction and NSIS install; full Open -> Inspect -> NEST -> Export parity remains a separate signed/public gate.

3. Updater metadata is reachable but not release-ready for the rebuilt artifact.
   - `bundle.createUpdaterArtifacts` is currently false for local unsigned builds.
   - Configured endpoint `https://hexhawk.ke/releases/latest.json` fetches.
   - This pass did not publish or validate hosted release/trust metadata against the June 20 unsigned candidate NSIS hash.

4. Full enterprise procurement package is not complete.
   - Support intake exists.
   - SLA, DPA/security questionnaire, procurement vendor packet, and signed release provenance remain pending.

## Non-blocking warnings observed

- Tauri warns that identifier `com.hexhawk.app` ends with `.app`; this is not recommended for macOS bundle naming. Current pilot target is Windows.
- Vite warns that the main JavaScript chunk is larger than 500 kB.
- Vite warns that `talonLLMPass` is both dynamically and statically imported.
- Rust build emits existing unused/dead-code warnings. Current build gates pass, but cleanup should be scheduled.

## Recently proven in current pass

- STRIKE benchmark provenance path normalization was fixed and pushed in `e625403`.
- All discovered frontend tests passed in a fresh release worktree: 47 files, 736 passed, 1 skipped.
- `npx tsc --noEmit` passed.
- `yarn build` passed.
- `yarn tauri:build` produced June 20 MSI and NSIS artifacts from post-fix HEAD.
- Artifact hashes and `NotSigned` Authenticode status were recorded.
- MSI extraction and NSIS silent-install launch smokes passed; NSIS included the real `WebView2Loader.dll` and uninstalled cleanly.

## Tester copy limits

Do not claim:

- publicly trusted signed release
- signed current artifacts
- broad public distribution readiness
- production distribution readiness
- updater readiness for public distribution
- enterprise/procurement distribution readiness
- full native GUI export parity for the June 20 artifacts; only launch/render smoke was rerun on those exact hashes

Acceptable wording:

- internal-tester Windows product candidate
- unsigned deployment candidate tagged `v1.2.0-unsigned-deployment-candidate-20260620`
- controlled external pilot candidate only after pilot sponsor accepts unsigned/updater constraints or organization-trusted signing and hosted updater validation are completed
- market readiness: controlled only
