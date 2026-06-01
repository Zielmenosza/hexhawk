# HexHawk

HexHawk is a native desktop reverse-engineering and binary-intelligence platform built with Rust, Tauri, React, and TypeScript.

It combines local static analysis, disassembly, decompiler assistance, debugger/trace evidence, signature correlation, NEST evidence convergence, GYRE verdict synthesis, and CREST-style reporting in one analyst workflow.

## Current State (2026-06-01)

HexHawk is a controlled internal-tester Windows build candidate. It is not yet a publicly trusted signed release.

Current evidence from the latest local validation pass:

- Frontend report-export regression test passes, including authority envelope assertions (`source_engine`, `gyre_is_sole_verdict_source`).
- Windows release artifacts were Authenticode-signed with an internal self-signed development certificate.
- Timestamp countersignature is present on exe/MSI/NSIS artifacts.
- Native packaged GUI acceptance flow passed on the signed internal artifact (Open -> Inspect -> Analysis -> NEST -> Report export).
- Release evidence was written to `docs/release-evidence/windows_release_hardening_2026-06-01_204639.json`.

Release caveats:

- Signature trust status is not public-trusted (`UnknownError`: untrusted root), so this is not a public-release signing posture.
- Updater signing path is enabled in config, but endpoint metadata validation currently fails because `releases.hexhawk.app` did not resolve in this pass.
- Public release readiness still requires organization-trusted certificate chain, reachable updater metadata endpoint, and signed-artifact rerun in external-like conditions.

## Engine Stack and Authority Boundaries

- GYRE: sole verdict authority for classification and base confidence.
- NEST: evidence orchestrator/convergence layer; selects and packages GYRE-linked evidence but does not replace GYRE.
- AETHERFRAME/Forge: optional bounded confidence uplift, refinement, and lineage metadata; never changes GYRE classification.
- TALON: decompiler and structured pseudocode/evidence surface.
- STRIKE: debugger/trace timeline intelligence and behavioral deltas.
- ECHO: exact/fuzzy signature and cross-binary correlation surface.
- CREST: report packaging/export surface.
- NEXUS: assistant/consumer layer, not verdict authority.

## Highlights Shipped

- Native Tauri desktop shell with Rust backend commands.
- Binary identity, metadata, strings, disassembly, CFG, evidence, and report workflows.
- NEST evidence bundle validation with GYRE sole-verdict-source checks.
- Stable native GUI selectors and export-parity repair paths for NEST workflow validation.
- Offline/local-first analysis with optional BYOK AI paths where configured.
- License activation flow for full builds and trial-mode support at the binary feature level.
- Windows MSI/NSIS packaging now builds after WebView2 installer configuration repair.

## Decompiler/TALON Quality Hardening (2026-06-01)

- Address-consistency alignment between disassembly and CFG build paths to reduce non-overlapping range failures.
- Decompile fallback block partitioner now derives basic blocks directly from instruction flow when CFG coverage is missing/sparse.
- Cross-block call-argument recovery improved with a wider lookback window (`25`) and recovery pass over ordered IR statements.
- First-pass variable naming heuristics added for loop counters, index-like registers, size arguments, and pointer-like registers.
- Regression coverage expanded with:
	- synthetic tests for cross-block call argument recovery and naming heuristics,
	- guarded real-binary tests against workspace challenge executables when `nest_cli` is available.

## Quick Start for Internal Testers

### Prerequisites

- Windows 10/11.
- WebView2 Runtime is bundled via installer bootstrapper configuration.
- Unsigned-build caution: expect Windows security warnings until signing is configured.

### Build locally

```bash
yarn install
yarn typecheck
yarn build
cargo check --workspace
cargo test --workspace
yarn tauri:build
```

### Current release artifacts

After a successful local Windows build:

- `target/release/hexhawk-backend.exe`
- `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi`
- `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe`

## Validation Commands Used for Current Claims

```bash
yarn workspace hexhawk-ui test src/components/__tests__/IntelligenceReport.test.tsx
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/release/release-hardening.ps1 -UseSelfSignedDevCert
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/release/run-native-parity-probe.ps1 -MsiPath ./target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi -OutputPath ./gui-evidence/release_hardening_native_gui_probe_2026-06-01_retry.json
```

## What Is Still Needed Before Public Release

- Code-sign Windows executable and installers.
- Re-enable and sign updater artifacts.
- Run installed-artifact native GUI export parity.
- Perform a clean external-tester install/uninstall smoke pass.
- Update public download hosting with signed artifacts and checksums.
- Finish release provenance, privacy, support, and procurement documentation.
