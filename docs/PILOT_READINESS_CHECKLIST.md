# HexHawk Pilot Readiness Checklist

Last updated: 2026-07-14

Current classification: Windows 1.0.0 release candidate ready for controlled local installation testing.
Market readiness: controlled evaluation only; not signed, production ready, procurement ready, enterprise ready, or public-release ready.

## Candidate identity

- Branch: `feature/project-persistence-e2e`
- Commit: `ebbd068bd8d30f68bedc2940ed9b0c5bfc80b586`
- MSI SHA-256: `A6A298CCFD39F8C53346D23A1BC7EC7795E3251E34031678735BE9C116E09BDB`
- NSIS SHA-256: `9FCC206AA60774F9CFD43E44994967517F8209B842FF266EE047346B5CE3AD61`
- Authenticode: MSI `NotSigned`; NSIS `NotSigned`

## Proven before installation

- [x] Versioned project persistence implemented.
- [x] Immutable recorded GYRE authority and advisory NEST linkage implemented.
- [x] Binary identity/cross-binary isolation implemented.
- [x] Restart/cache-clear hydration and report/export provenance implemented.
- [x] 153 Rust tests passed.
- [x] 22 focused frontend persistence/provenance tests passed across 7 files.
- [x] TypeScript `--noEmit`, Vite production build, and `cargo check --release` passed.
- [x] MSI and NSIS built; hashes, metadata, and unsigned status verified.

These are local source/package checks, not hosted CI or installer acceptance.

## Controlled acceptance gate — all open

- [ ] Controlled NSIS installation.
- [ ] Installed application launch.
- [ ] Installed two-binary project save/reopen without identity crossover.
- [ ] Installed rejection of changed or cross-binary input.
- [ ] Installed process-restart recovery.
- [ ] Installed cache-clear recovery.
- [ ] Installed report provenance tied to recorded GYRE snapshot.
- [ ] Installed export provenance tied to recorded GYRE snapshot.
- [ ] Honest rejection/degradation for missing or invalid authority data.
- [ ] Uninstall.
- [ ] Reinstall.
- [ ] User-data retention-policy validation.

Do not use stale smoke folders or historical installer evidence as proof for these exact artifacts.

## Trusted distribution gate — open

- [ ] Organization-trusted Authenticode signing.
- [ ] Signer certificate and trusted timestamp verified.
- [ ] Updater metadata validated against exact signed artifacts.
- [ ] Hosted CI verified for intended release commit.
- [ ] Hosted publication, rollback, support, and issue intake ready.

## Decision

The candidate may enter a controlled local installation test. It must not be described as accepted, signed, procurement ready, production ready, updater ready, or public release ready until the corresponding exact-artifact gates pass.
