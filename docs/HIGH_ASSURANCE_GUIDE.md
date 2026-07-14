# HexHawk High-Assurance Guide

Last updated: 2026-07-14

## Goal

High-assurance HexHawk workflows prioritize verified binary identity, immutable recorded authority, deterministic evidence, explicit policy gates, restart-safe persistence, and replayable exports over convenience or AI-driven shortcuts.

## Required behavior

- GYRE remains the sole classification and recorded base-verdict authority.
- Projects resolve immutable recorded GYRE snapshots rather than trusting mutable renderer state.
- NEST bundles and lifecycle records preserve binary identity, session/iteration linkage, and the exact recorded snapshot reference; NEST remains advisory.
- AETHERFRAME/Forge is optional, bounded, replayable, auditable, disableable, and non-authoritative.
- NEXUS cannot mutate authoritative verdict state.
- High-assurance operation must retain deterministic/replayable paths with AETHERFRAME disabled.
- Save/reopen must verify binary identity and reject stale, malformed, unsupported, missing, mismatched, or cross-binary authority data.
- Cache-clear and process-restart recovery must reconstruct authority from persisted records.
- Reports and exports must identify the resolved recorded snapshot and distinguish authoritative, advisory, incomplete, and unavailable evidence.
- Missing authority must produce honest summary-only output, never silent fallback to stale or cross-binary verdict data.

The authoritative snapshot identifier must originate from the backend-recorded GYRE path. Renderer/schema markers can support consistency checks but do not prove backend provenance, and fixture values prove only the fixture's scenario. Reports/exports must resolve to that same immutable recorded snapshot or state that authoritative provenance is unavailable.

## Current 1.0.0 evidence

Milestone commit `ebbd068bd8d30f68bedc2940ed9b0c5bfc80b586` implements versioned projects, save/reopen, immutable recorded-verdict linkage, binary isolation, restart/cache-clear hydration, NEST lifecycle-to-project linkage, and report/export provenance.

Local milestone validation recorded 124 backend tests, 29 `nest_cli` tests, 153 total Rust tests, and 22 focused frontend persistence/provenance tests across 7 files. TypeScript `--noEmit`, the Vite production build, and `cargo check --release` passed. This does not establish hosted-CI status or prove every historical frontend suite was rerun.

## Release guidance

Current HexHawk 1.0.0 MSI and NSIS candidates were built and hash/metadata checked. Both are Authenticode `NotSigned`; no signer certificate or trusted timestamp is present.

Do not call the candidate high-assurance externally validated until the exact installed artifacts pass:

1. controlled installation and application launch;
2. two-binary persistence and identity isolation;
3. restart/cache-clear recovery;
4. report/export provenance;
5. uninstall/reinstall and user-data retention checks;
6. trusted code signing; and
7. updater validation against exact signed artifacts.

Packaging success is not installer acceptance. Local validation is not hosted-CI proof.

## Bridge boundary

The Bridge improved continuity, repository custody, evidence preservation, and recovery discipline. It is not an analysis engine, verdict source, or runtime dependency of HexHawk.
