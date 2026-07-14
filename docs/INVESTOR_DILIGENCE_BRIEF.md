# HexHawk Investor Diligence Brief

Last updated: 2026-07-14

## Executive summary

HexHawk 1.0.0 is beyond concept stage: it implements persistent versioned projects, reliable reopen, immutable recorded-verdict authority, cross-binary identity isolation, restart/cache-clear recovery, and report/export provenance. A Windows MSVC release build produced verified MSI and NSIS candidates.

This is product-risk reduction and technical evidence, not commercial readiness. Both installers are unsigned and no controlled installation acceptance has passed for the exact current artifacts. HexHawk is not production ready, procurement ready, enterprise ready, updater ready, or public-release ready.

Canonical status: [CURRENT_STATUS.md](CURRENT_STATUS.md).

## Architecture and trust model

- React/TypeScript frontend, Tauri v2 desktop runtime, Rust backend, and `nest_cli` headless operations.
- GYRE is sole classification and recorded base-verdict authority.
- NEST supplies evidence and lifecycle context; it does not independently classify or override GYRE.
- AETHERFRAME/Forge is optional, bounded, replayable, auditable, disableable, and non-authoritative.
- NEXUS assists/consumes and cannot mutate authoritative verdict state.
- Reports and exports bind authority provenance to the immutable recorded GYRE snapshot.

## Product milestone

- Versioned project save/reopen.
- Persistent binary, NEST-session, and recorded GYRE-snapshot linkage.
- Binary mismatch and cross-binary crossover rejection.
- Cache-clear/process-restart hydration.
- Missing, malformed, unsupported, stale, and mismatched authority rejection.
- Honest summary-only reporting when authoritative evidence is unavailable.

## Validation and packaging evidence

- 124 backend tests and 29 `nest_cli` tests passed; 153 total Rust tests.
- 22 focused frontend persistence/provenance tests passed across 7 files.
- TypeScript `--noEmit`, Vite production build, and `cargo check --release` passed.
- MSI SHA-256: `A6A298CCFD39F8C53346D23A1BC7EC7795E3251E34031678735BE9C116E09BDB`.
- NSIS SHA-256: `9FCC206AA60774F9CFD43E44994967517F8209B842FF266EE047346B5CE3AD61`.
- Package metadata identifies HexHawk 1.0.0.
- MSI and NSIS Authenticode status: `NotSigned`; no signer certificate or trusted timestamp.

The validation is local and does not establish hosted-CI status. Historical test counts and installer smokes apply only to their recorded source/artifact hashes.

## Commercial diligence posture

Ready for:

- internal demonstration;
- technical diligence;
- controlled source evaluation; and
- controlled local installation testing under an approved acceptance plan.

Not yet ready for:

- external signed tester distribution;
- public download;
- procurement or enterprise rollout;
- automatic updater distribution; or
- claims that the installer is fully validated.

## Remaining gates

1. Controlled install and installed launch.
2. Installed two-binary persistence and identity isolation.
3. Installed restart/cache-clear and report/export provenance.
4. Uninstall/reinstall and user-data retention policy.
5. Organization-trusted code signing.
6. Updater validation against exact signed artifacts.
7. Hosted CI/release publication evidence.
8. Support, security, privacy, and procurement operations.
9. Continued decompiler, debugger, architecture, and plugin depth.

## Bridge boundary

The Bridge improved engineering continuity, exact context handoff, repository custody, timeout recovery, evidence preservation, and controlled packaging. It is not an analysis engine, does not alter GYRE or classification accuracy, does not produce verdicts, and is not required to run HexHawk.
