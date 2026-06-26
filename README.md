# HexHawk

HexHawk is a native desktop reverse-engineering and binary-intelligence platform built with Rust, Tauri, React, and TypeScript.

It combines local static analysis, disassembly, decompiler assistance, debugger/trace evidence, signature correlation, NEST evidence convergence, GYRE verdict synthesis, and CREST-style reporting in one analyst workflow.

## Current State (2026-06-26 Function Intelligence source candidate)

HexHawk is currently a validated source candidate on `feature/re-workbench-core-next` after the v1.30 Function Intelligence integration and v1.31 byte_counter clippy fix. It is not yet a freshly packaged unsigned deployment candidate from this source state, not a publicly trusted signed release, not updater-ready, and not enterprise/procurement-ready distribution.

Current source validation from this session:

- Branch: `feature/re-workbench-core-next`.
- Function Intelligence source tag at the prior HEAD: `v1.30.0-function-intelligence-regression`.
- byte_counter clippy fix tag: `v1.31.0-byte-counter-clippy-fix`.
- Rust workspace tests passed: 85 backend tests + 20 `nest_cli` tests, plus 0-test plugin/doc-test crates.
- `cargo clippy --workspace -- -D warnings` passed after the byte_counter C string metadata fix.
- `npx tsc --noEmit` passed.
- Full frontend Vitest passed: 59 files, 832 tests.
- `yarn build` passed with existing Vite chunk-size/dynamic-import warnings.

Current Function Intelligence work now unifies recent reverse-engineering slices into one advisory function evidence layer:

- v1.17.0 PE import table parsing.
- v1.18.0 queryable xref index.
- v1.19.0 function-boundary recovery heuristics.
- v1.20.0 Win32 constant semantic annotation.
- v1.21.0 TALON pseudocode IR artefact cleanup.
- v1.22.0 debugger call-stack reconstruction.
- v1.23.0 conditional breakpoint expressions.
- v1.24.0 calling-convention inference per function.
- v1.25-v1.30 Function Intelligence model, static/runtime correlation, JSON/Markdown export, Function Notebook UI, workflow wiring, and regression coverage.

Function Intelligence and Function Notebook are advisory evidence surfaces. GYRE remains the sole verdict/classification authority. NEST organizes evidence; TALON/decompiler output is advisory reconstruction; STRIKE/debugger output is runtime evidence only.

### Historical artifact boundary

Older June 20/21 release evidence remains useful provenance, but it does not prove the current v1.30/v1.31 source state as a packaged candidate unless a fresh release worktree rebuild, artifact hashes, signing checks, installer smoke, and Function Notebook/export smoke are completed for the exact artifacts.

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
- PE import table parsing, queryable xrefs, function boundary recovery, Win32 constant annotation, and calling-convention inference.
- Function Intelligence model and Function Notebook UI for selected-function imports, calls, pseudocode, runtime observations, limits, and JSON/Markdown export.
- NEST evidence bundle validation with GYRE sole-verdict-source checks.
- Optional AETHERFRAME report packaging/lineage that is policy-gated and non-authoritative.
- Stable native GUI selectors and export-parity probes for workflow validation.
- Offline/local-first analysis with optional BYOK AI paths where configured.
- License activation flow for full builds and trial-mode support at the binary feature level.
- Windows MSI/NSIS packaging builds with WebView2 bootstrapper configuration, pending a fresh v1.30/v1.31 deployment gate.
- TALON/decompiler hardening for CFG/disassembly range alignment, fallback block partitioning, cross-block argument recovery, first-pass semantic naming heuristics, and IR artefact cleanup.

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

## Validation Commands Used for Current Source Claims

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
cd HexHawk
npx tsc --noEmit
TEST_FILES=$(find src \( -name '*.test.ts' -o -name '*.test.tsx' \) | grep -v node_modules | sort | tr '\n' ' ')
npx vitest run --reporter=dot $TEST_FILES
yarn build
```

Packaging, signing, installer smoke, and Function Notebook export smoke are still separate release-gate checks for the current source state.

## Release Posture

- Source candidate: YES, validated through v1.30/v1.31 source checks.
- Fresh unsigned deployment candidate from this source state: pending release gate.
- Controlled external signed-tester gate: NO.
- Public release candidate: NO.
- Public-trusted signing: NO unless Authenticode proves otherwise on exact artifacts.
- Updater readiness: NO.
- Enterprise/procurement-ready release: NO.
