# HexHawk

HexHawk is a native desktop reverse-engineering and binary-intelligence platform built with Rust, Tauri, React, and TypeScript.

It combines local static analysis, disassembly, decompiler assistance, debugger/trace evidence, signature correlation, NEST evidence convergence, GYRE verdict synthesis, and CREST-style reporting in one analyst workflow.

## Current State (2026-06-20 unsigned deployment candidate)

HexHawk has a current unsigned Windows deployment candidate for controlled internal testing. It is not a publicly trusted signed release, not an updater-ready public release, and not yet an enterprise/procurement-ready distribution.

Current evidence from the June 20 post-fix deployment-candidate gate:

- STRIKE benchmark report provenance paths were fixed to normalize to stable project-relative paths instead of leaking absolute checkout paths in release worktrees.
- All discovered frontend tests passed in a fresh release worktree: 47 test files, 736 passed, 1 skipped.
- `npx tsc --noEmit` passed.
- `yarn build` passed with existing Vite chunk/import warnings.
- `yarn tauri:build` passed with existing Rust warnings and produced MSI/NSIS artifacts.
- `Get-AuthenticodeSignature` reports the rebuilt MSI/NSIS artifacts as `NotSigned`.
- MSI extraction smoke passed and rendered the HexHawk onboarding UI.
- NSIS silent install smoke passed, included the real `WebView2Loader.dll`, rendered the HexHawk onboarding UI, and uninstalled cleanly.
- Deployment candidate tag: `v1.2.0-unsigned-deployment-candidate-20260620`.
- Current release evidence: `docs/release-evidence/unsigned_deployment_candidate_2026-06-20_215102.json`.

### Current artifact SHA-256

- `target/release/hexhawk-backend.exe`: `48de54c39a0f06164ac82a2a6bd5dd9439aa90b53188efbcc5caa790c0657ad1`
- `target/release/nest_cli.exe`: `d4efba77ae2df7a6fa265ff37f051389a87192d3cc7da774862110ba1c723e0a`
- `target/release/WebView2Loader.dll`: `8427b1fc58ec707813e5c0a51eb5d69397bb333250a7b891be4d3b123f1e0f1c`
- `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi`: `0b6a8e885accd45b6c1633f5db79af839302d8c45311ab5d48ef4ddeefe0d14e`
- `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe`: `fae7b573054a3938bc38c7ae21f341b54a2772629526cbda1c829a663ce59c71`

### Historical evidence boundary

Prior release evidence remains useful provenance, but it does not describe the June 20 deployment-candidate artifacts unless the hash matches exactly. GUI launch smoke for this candidate proves rendering and installer payload health; full Open -> Inspect -> NEST -> Export authority parity still must be rerun for any signed/public tester artifact.

## Engine Stack and Authority Boundaries

- GYRE: sole verdict authority for classification and base confidence.
- NEST: evidence orchestrator/convergence layer; selects and packages GYRE-linked evidence but does not replace GYRE.
- AETHERFRAME/Forge: optional bounded confidence uplift, refinement, and lineage metadata; never changes GYRE classification. Standalone AetherFrame core is product-agnostic and adapter-driven; HexHawk is one adapter/proving ground, not the conceptual owner.
- TALON: decompiler and structured pseudocode/evidence surface.
- STRIKE: debugger/trace timeline intelligence and behavioral deltas.
- ECHO: exact/fuzzy signature and cross-binary correlation surface.
- CREST: report packaging/export surface.
- NEXUS: assistant/consumer layer; it does not own classification truth.

## Highlights Shipped

- Native Tauri desktop shell with Rust backend commands.
- Binary identity, metadata, strings, disassembly, CFG, evidence, and report workflows.
- NEST evidence bundle validation with GYRE sole-verdict-source checks.
- Optional AETHERFRAME report packaging/lineage that is policy-gated and non-authoritative.
- Stable native GUI selectors and export-parity probes for workflow validation.
- Offline/local-first analysis with optional BYOK AI paths where configured.
- License activation flow for full builds and trial-mode support at the binary feature level.
- Windows MSI/NSIS packaging builds with WebView2 bootstrapper configuration.
- TALON/decompiler hardening for CFG/disassembly range alignment, fallback block partitioning, cross-block argument recovery, and first-pass semantic naming heuristics.

## Quick Start for Internal Testers

### Prerequisites

- Windows 10/11.
- WebView2 Runtime is bundled via installer bootstrapper configuration.
- Unsigned-build caution: expect Windows security warnings until an organization-trusted signing path is configured and verified.

### Build locally

```bash
yarn install
npx tsc --noEmit
yarn build
npx vitest run --reporter=verbose $(find src -name '*.test.ts' -o -name '*.test.tsx' | sort)
cargo check --workspace
cargo test --workspace
yarn tauri:build
```

## Validation Commands Used for Current Claims

```bash
npx vitest run --reporter=verbose <all discovered test files>
npx tsc --noEmit
yarn build
yarn tauri:build
sha256sum target/release/hexhawk-backend.exe target/release/nest_cli.exe target/release/WebView2Loader.dll target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe
Get-AuthenticodeSignature <rebuilt msi/nsis>
MSI administrative extraction + GUI smoke
NSIS silent install + payload compare + GUI smoke + uninstall
```

## Release Posture

- Internal tester candidate: YES, with unsigned-artifact caveats.
- Controlled external signed-tester gate: NO.
- Public release candidate: NO.
- Public-trusted signing: NO.
- Updater readiness: NO.
- Enterprise/procurement-ready release: NO.
