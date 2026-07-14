# HexHawk Roadmap

Last updated: 2026-07-14

This roadmap separates shipped source capability from unpassed release gates. Current evidence and caveats are summarized in [docs/CURRENT_STATUS.md](docs/CURRENT_STATUS.md).

## Completed in the 1.0.0 project-persistence milestone

- Versioned project manifests.
- Project save and reliable reopen.
- Persistent linkage among project, imported binary, NEST session, and immutable recorded GYRE verdict snapshot.
- GYRE as sole authoritative source of classification and recorded base-verdict state.
- Advisory NEST lifecycle linkage without independent classification authority.
- Binary-identity verification and cross-binary evidence-isolation rejection.
- Cache-clear and process-restart recovery.
- Persisted verdict hydration.
- Report and export provenance tied to the recorded snapshot.
- Honest summary-only reporting when authoritative evidence is unavailable.
- Rejection of missing, malformed, unsupported, stale, mismatched, and cross-binary persisted authority data.
- Two-binary persistence coverage without identity crossover.
- Windows MSVC release build producing MSI and NSIS HexHawk 1.0.0 candidates.
- Installer hashes, package metadata, and unsigned status verified.

## Current validated baseline

Milestone branch: `feature/project-persistence-e2e`
Milestone commit: `ebbd068bd8d30f68bedc2940ed9b0c5bfc80b586`

- 124 Rust backend tests passed.
- 29 `nest_cli` tests passed.
- 153 total Rust tests passed.
- 22 focused frontend persistence/provenance tests passed across 7 files.
- TypeScript `--noEmit`, Vite production build, and `cargo check --release` passed.
- MSI and NSIS were produced and remain Authenticode `NotSigned`.

This baseline does not claim all historical frontend suites were rerun or hosted CI is green.

## Trust hierarchy that must not drift

1. GYRE owns classification and recorded base-verdict authority.
2. NEST organizes evidence and lifecycle context; it does not issue or override classification.
3. AETHERFRAME/Forge is optional, bounded, replayable, auditable, disableable, and non-authoritative.
4. NEXUS assists and consumes; it must not mutate authoritative verdict state.
5. Reports and exports distinguish recorded authority from advisory, incomplete, or unavailable evidence.
6. Stale and cross-binary verdict data are rejected rather than silently reused.

## P0 — Controlled installation and functional acceptance

- Controlled NSIS installation test.
- Installed application launch test.
- Installed two-binary persistence and identity-isolation test.
- Installed restart/cache-clear recovery test.
- Installed report-provenance and export-provenance test.
- Uninstall and reinstall validation.
- User-data retention-policy validation.

Exit criterion: every check passes against the exact candidate artifacts, with hashes and failure evidence recorded. Packaging success alone is not acceptance.

## P0 — Signing and exact-artifact updater validation

- Configure organization-trusted Windows code signing.
- Rebuild and verify signed executable, MSI, and NSIS artifacts.
- Record hashes, signer identity, trusted timestamp, and trust-chain result.
- Validate updater metadata and signatures against those exact signed artifacts.
- Keep unsigned local artifacts out of public-trusted release positioning.

## P0 — Hosted release and support readiness

- Verify hosted CI for the intended release commit; do not infer it from local validation.
- Publish only after exact-artifact acceptance, signing, updater, and custody gates pass.
- Finalize support, issue intake, release provenance, and rollback operations.

## P1 — Analysis depth

- Broader decompiler maturity and architecture coverage.
- Broader debugger maturity and reproducible runtime evidence.
- Plugin ecosystem maturity and compatibility policy.
- Additional external challenge and regression corpora.
- Exploitability Mode remains planned/backlog unless source and tests independently prove shipment.
- Do not present manual or external-tool exploit success as native HexHawk capability.

## P1 — Commercial maturity

- Controlled pilot onboarding and support operations.
- Procurement and policy documentation after technical release gates pass.
- Case studies with evidence-scoped claims and no sensitive samples.
- Broader platform packaging beyond Windows.

## Historical baseline note

Earlier Function Intelligence, June installer, benchmark, and release-candidate documents remain useful dated evidence. Their test counts, hashes, smoke results, and tags describe those historical source states only and do not supersede the 2026-07-14 milestone status.
