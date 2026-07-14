# HexHawk Investor One-Pager

Last updated: 2026-07-14

## What HexHawk is

HexHawk 1.0.0 is a local-first desktop reverse-engineering and binary-intelligence workbench for analysts who need persistent investigation state, evidence they can review, explicit authority boundaries, and reproducible report/export provenance.

## Product-risk reduction now implemented

- Persistent versioned projects and reliable reopen.
- Immutable recorded GYRE verdict snapshots as sole classification/base-verdict authority.
- Binary-identity verification and cross-binary evidence-isolation rejection.
- Persisted NEST lifecycle context without making NEST verdict authority.
- Cache-clear and process-restart recovery.
- Reports and exports tied to recorded-snapshot provenance.
- Honest degraded output when authoritative evidence is unavailable.
- Strong rejection of missing, malformed, unsupported, stale, or mismatched persisted evidence.

These capabilities reduce investigation-state loss, evidence crossover, stale-verdict reuse, and provenance ambiguity.

## Current proof

- Milestone branch `feature/project-persistence-e2e`, commit `ebbd068bd8d30f68bedc2940ed9b0c5bfc80b586`.
- 153 total Rust tests passed: 124 backend and 29 `nest_cli`.
- 22 focused frontend persistence/provenance tests passed across 7 files.
- TypeScript `--noEmit`, Vite production build, and `cargo check --release` passed.
- Windows MSI and NSIS installers built.
- Exact hashes and package metadata verified.
- Both installers are Authenticode `NotSigned` with no signer certificate or trusted timestamp.

MSI SHA-256: `A6A298CCFD39F8C53346D23A1BC7EC7795E3251E34031678735BE9C116E09BDB`
NSIS SHA-256: `9FCC206AA60774F9CFD43E44994967517F8209B842FF266EE047346B5CE3AD61`

Local validation does not establish hosted-CI status.

## Market wedge

HexHawk's differentiated job is local-first evidence custody, persistent case state, explicit authority boundaries, bounded AI, integrated evidence/report workflow, cross-binary isolation, and auditable recorded-verdict lineage. Established platforms remain ahead in mature decompiler, debugger, architecture, automation, and plugin-ecosystem depth.

## Commercial status

The current package is a Windows release candidate ready for controlled local installation testing. It is not production ready, procurement ready, enterprise ready, public-release ready, signed, updater ready, or fully installer validated.

No controlled installation, installed launch, installed two-binary persistence, restart/cache-clear, report/export provenance, uninstall, or reinstall acceptance test has passed for these exact artifacts.

## Next use of capital and effort

1. Controlled exact-artifact installation and functional acceptance.
2. Organization-trusted code signing and release provenance.
3. Updater validation against exact signed artifacts.
4. Hosted CI/release publication evidence.
5. Pilot onboarding, support, and issue-response ownership.
6. Procurement/security documentation after technical gates pass.
7. Broader decompiler, debugger, and plugin maturity.

## Authority and Bridge boundaries

GYRE is sole classification authority; NEST is evidence/lifecycle context; AETHERFRAME/Forge and NEXUS are non-authoritative.

The Bridge improved engineering continuity, exact context handoff, repository custody, evidence preservation, timeout recovery, and controlled packaging. It is not part of HexHawk's analysis engine, did not improve classification accuracy, does not produce verdicts, and is not required to run the product.
