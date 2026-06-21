# HexHawk External Tester Known Issues

Date: 2026-06-21
Current audience: internal testers and controlled pilot candidates only

## Release blockers

1. Current Windows artifacts are unsigned.
   - The June 21 deployment-candidate source tag is `v1.9.0-unsigned-deployment-candidate-20260621` at `ad2e752`.
   - Public-trusted Authenticode signing has not been completed for the current local artifacts.
   - Expected effect: SmartScreen or enterprise endpoint controls may warn or block.
   - Status: unresolved for public distribution.

2. Previous internal self-signed or native GUI evidence is historical only.
   - Prior evidence files apply only to their recorded artifact hashes.
   - Current June 21 local artifact hashes are recorded in `docs/TESTER_RELEASE_STATUS.md`; the last installer-smoke evidence file remains `docs/release-evidence/unsigned_deployment_candidate_2026-06-20_215102.json`.
   - Exact-artifact launch/render smoke passed for the June 20 MSI extraction and NSIS install; full Open -> Inspect -> NEST -> Export parity remains a separate signed/public gate.

3. Updater metadata is reachable but not release-ready for the current candidate.
   - `bundle.createUpdaterArtifacts` is currently false for local unsigned builds.
   - Configured endpoint `https://hexhawk.ke/releases/latest.json` has been historically reachable.
   - This pass did not publish or validate hosted release/trust metadata against the June 21 unsigned candidate NSIS hash.

4. Full enterprise procurement package is not complete.
   - Support intake exists.
   - SLA, DPA/security questionnaire, procurement vendor packet, and signed release provenance remain pending.

## Non-blocking warnings observed

- Tauri warns that identifier `com.hexhawk.app` ends with `.app`; this is not recommended for macOS bundle naming. Current pilot target is Windows.
- Vite warns that the main JavaScript chunk is larger than 500 kB.
- Vite warns that `talonLLMPass` is both dynamically and statically imported.
- Rust build emits existing unused/dead-code warnings. Current build gates pass, but cleanup should be scheduled.

## Recently proven in current pass

- Source candidate tag `v1.9.0-unsigned-deployment-candidate-20260621` points at `ad2e752`.
- TALON/NEST/STRIKE capability sprint through v1.8.0 was tested and pushed before the June 21 source candidate tag.
- All discovered frontend tests passed at the v1.9.0 source candidate: 49 files, 758 passed.
- `npx tsc --noEmit` passed.
- `cargo test` passed: 85 tests.
- June 21 local artifact hashes were recorded in `docs/TESTER_RELEASE_STATUS.md`.
- MSI extraction and NSIS silent-install launch smokes remain proven for the June 20 installer hashes; they were not rerun as a new June 21 installer gate.

## Tester copy limits

Do not claim:

- publicly trusted signed release
- signed current artifacts
- broad public distribution readiness
- production distribution readiness
- updater readiness for public distribution
- enterprise/procurement distribution readiness
- full native GUI export parity for the June 21 artifacts
- fresh June 21 installer deployment gate; only the source candidate and local hashes were updated

Acceptable wording:

- internal-tester Windows source candidate
- unsigned deployment candidate tagged `v1.9.0-unsigned-deployment-candidate-20260621`
- controlled external pilot candidate only after pilot sponsor accepts unsigned/updater constraints or organization-trusted signing and hosted updater validation are completed
- market readiness: controlled only
