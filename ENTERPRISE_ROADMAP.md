# HexHawk Enterprise and Commercial Roadmap

Last updated: 2026-07-14

## Board-level status

HexHawk 1.0.0 is a working local-first desktop binary-intelligence product with persistent projects, immutable recorded-verdict provenance, cross-binary identity isolation, and reproducible report/export lineage. Windows MSI and NSIS release-candidate installers now build; their hashes and package metadata were verified, and both are unsigned.

This reduces product risk but does not establish commercial readiness. HexHawk is not production ready, procurement ready, enterprise ready, publicly trusted, or fully installer validated. Controlled installation and functional acceptance testing remains the next gate.

See [docs/CURRENT_STATUS.md](docs/CURRENT_STATUS.md) for the canonical evidence statement.

## Current proof

- Branch `feature/project-persistence-e2e`, milestone commit `ebbd068bd8d30f68bedc2940ed9b0c5bfc80b586`.
- Versioned project save/reopen with persisted binary, NEST lifecycle, and immutable recorded GYRE snapshot linkage.
- Binary mismatch and cross-binary crossover rejection.
- Restart/cache-clear recovery and persisted verdict hydration.
- Recorded-snapshot provenance for reports and exports, with honest degraded output when authority is unavailable.
- 153 total Rust tests passed: 124 backend and 29 `nest_cli`.
- 22 focused frontend persistence/provenance tests passed across 7 files.
- TypeScript `--noEmit`, Vite production build, and `cargo check --release` passed.
- MSI `A6A298CCFD39F8C53346D23A1BC7EC7795E3251E34031678735BE9C116E09BDB`.
- NSIS `9FCC206AA60774F9CFD43E44994967517F8209B842FF266EE047346B5CE3AD61`.
- Both installers: Authenticode `NotSigned`; no signer certificate or trusted timestamp.

Local validation is not hosted-CI proof. No controlled installation or installed-artifact acceptance test has passed for these exact artifacts.

## Product-risk reduction

- Persistent projects reduce loss of investigation state and enable reliable reopen.
- Immutable recorded GYRE snapshots preserve classification authority across restart and cache loss.
- Binary identity and cross-binary rejection reduce evidence-crossover risk.
- Persisted NEST linkage preserves lifecycle context without turning NEST into verdict authority.
- Report/export provenance makes authority and lineage auditable.
- Honest summary-only degradation prevents unavailable authority from being presented as proven.

## Market position

HexHawk's near-term wedge is local-first evidence custody, persistent case/project state, explicit authority boundaries, bounded AI, and reproducible report/export handoff. Mature tools remain ahead in decompiler, debugger, architecture, automation, and plugin-ecosystem depth.

## Commercial gates

### Gate 1 — Controlled candidate acceptance

- Install and launch the exact NSIS candidate.
- Exercise installed two-binary persistence and identity isolation.
- Exercise restart/cache-clear recovery.
- Verify installed report/export provenance.
- Verify uninstall/reinstall and user-data retention behavior.

### Gate 2 — Trusted distribution

- Code-sign exact executable and installer artifacts.
- Verify signer, timestamp, and trust chain.
- Validate updater metadata against exact signed artifacts.
- Verify hosted CI and publish evidence without equating local checks to hosted checks.

### Gate 3 — Pilot and support readiness

- Define onboarding, issue intake, support boundaries, rollback, and release custody.
- Run controlled pilots only after technical acceptance and signing gates pass.
- Produce evidence-scoped case studies.

### Gate 4 — Procurement maturity

- Security, privacy, licensing, support, update, vulnerability-response, and audit materials.
- Procurement claims only after the underlying controls and evidence exist.

## Authority and Bridge boundaries

GYRE remains sole classification and recorded base-verdict authority. NEST is evidence/lifecycle context. AETHERFRAME/Forge is optional and non-authoritative. NEXUS cannot mutate authoritative state.

The Bridge improved engineering continuity, repository custody, evidence preservation, timeout recovery, and packaging discipline. It is not part of HexHawk's engine, did not change classification logic, and is not required to run the product.
