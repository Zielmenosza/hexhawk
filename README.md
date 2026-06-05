# HexHawk

HexHawk is a native desktop reverse-engineering and binary-intelligence platform built with Rust, Tauri, React, and TypeScript.

It combines local static analysis, disassembly, decompiler assistance, debugger/trace evidence, signature correlation, NEST evidence convergence, GYRE verdict synthesis, and CREST-style reporting in one analyst workflow.

## Current State (2026-06-04 unsigned installer rebuild)

HexHawk is a controlled internal-tester Windows build candidate. It is not a publicly trusted signed release, not an updater-ready public release, and not yet an enterprise/procurement-ready distribution.

Current evidence from the June 4 docs/rebuild pass:

- `yarn typecheck` passed.
- `yarn build` passed with existing Vite chunk/import warnings.
- `yarn tauri:build` passed after stale local bundle outputs were removed.
- Windows executable, MSI, and NSIS artifacts were rebuilt locally.
- `Get-AuthenticodeSignature` reports the rebuilt exe/MSI/NSIS artifacts as `NotSigned`.
- Hosted updater metadata at `https://hexhawk.ke/releases/latest.json` fetches, but this pass did not publish or validate hosted release/trust endpoints against the rebuilt NSIS hash.
- Exact-artifact native GUI parity was not rerun for the June 4 rebuilt MSI/NSIS; prior native GUI evidence is historical for older artifact hashes.
- Current release evidence: `docs/release-evidence/unsigned_installer_rebuild_2026-06-04_175600.json`.

### Current artifact SHA-256

- `target/release/hexhawk-backend.exe`: `cd1c3f3a43fa1d67d8ffb66890e7a9516a939207b9b6b4eb6a47cdbf6aee7431`
- `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi`: `a460902c47ce3a5bffae38006bad4e9938bb317ec7a9afb0c1381635ddc596a0`
- `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe`: `8412322cc2d5646a5b08b390825440b1dfef29fe128dc8992c0c8df844f59512`

### Historical evidence boundary

Prior release evidence from June 1-2 remains useful provenance, but it does not describe the June 4 rebuilt artifacts above unless the hash matches exactly. Native GUI parity, updater validation, and signing conclusions must always be tied to the exact artifact hash under review.

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
yarn typecheck
yarn build
yarn test --reporter=dot
cargo check --workspace
cargo test --workspace
yarn tauri:build
```

## Validation Commands Used for Current Claims

```bash
rm stale target/release executable and installer outputs
yarn typecheck
yarn build
yarn tauri:build
sha256sum target/release/hexhawk-backend.exe target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe
Get-AuthenticodeSignature <rebuilt exe/msi/nsis>
fetch https://hexhawk.ke/releases/latest.json
```

## Release Posture

- Internal tester candidate: YES, with unsigned-artifact caveats.
- Controlled external signed-tester gate: NO.
- Public release candidate: NO.
- Public-trusted signing: NO.
- Updater readiness: NO.
- Enterprise/procurement-ready release: NO.
