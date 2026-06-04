# HexHawk

HexHawk is a native desktop reverse-engineering and binary-intelligence platform built with Rust, Tauri, React, and TypeScript.

It combines local static analysis, disassembly, decompiler assistance, debugger/trace evidence, signature correlation, NEST evidence convergence, GYRE verdict synthesis, and CREST-style reporting in one analyst workflow.

## Current State (2026-06-02 controlled external signing gate blocked)

HexHawk is a controlled internal-tester Windows build candidate. It is not a publicly trusted signed release.

Current evidence from the controlled external signing gate and updater custody rehearsal passes:

- Frontend validation passed: 40 test files / 700 tests.
- Rust validation passed: 71 backend tests + 14 `nest_cli` tests.
- TypeScript typecheck and production frontend build passed.
- `yarn tauri:build` produced fresh Windows executable, MSI, and NSIS artifacts after stale artifacts were removed.
- The no-op Tauri `bundle.windows.signCommand` was removed.
- `bundle.createUpdaterArtifacts` remains `false` in committed config for local unsigned builds; the official release script temporarily enables updater artifacts only when `TAURI_SIGNING_PRIVATE_KEY` is present in release custody.
- Current target/release artifacts are unsigned according to `Get-AuthenticodeSignature`.
- Updater key custody is present in GitHub Actions repository secrets and the official scripted path can produce MSI/NSIS `.sig` sidecars locally; public-trusted Authenticode custody is absent, and hosted endpoint validation currently fetches but serves stale metadata that fails expected current-artifact/signature checks.
- Native packaged GUI parity passed against the exact current MSI artifact recorded below.
- Current release evidence: `docs/release-evidence/unsigned_rebuild_release_truth_2026-06-02_220000.json`, `docs/release-evidence/windows_release_truth_consolidation_2026-06-02_171415.json` and `docs/release-evidence/updater_metadata_dns_repair_2026-06-02_173000.json`, `docs/release-evidence/official_updater_custody_rehearsal_2026-06-02_181500.json`, and `docs/release-evidence/official_updater_custody_validation_2026-06-02_180900.json`, `docs/release-evidence/official_release_custody_final_validation_2026-06-02_203600.json` and `docs/release-evidence/hosted_updater_metadata_validation_2026-06-02_181100.json`.
- Current native GUI report/AETHERFRAME policy evidence: `gui-evidence/report_aetherframe_policy_native_gui_probe_2026-06-02_170827.json`.

### Current artifact SHA-256

- `target/release/hexhawk-backend.exe`: `caeb0c39abd9854d60745ff0f407744b7da4bc05312f01d2d346259037570377`
- `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi`: `78bf99874acb9419525ab3012ac36252d2f8cc7605850aa773d36cc6865ec1e4`
- `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe`: `dbbd31edf328dc85bc40176fa19b3b5220cc62b85d74d1ab2f9969944c7fd246`

### Historical evidence boundary

A prior evidence file, `docs/release-evidence/windows_release_hardening_2026-06-01_204639.json`, recorded internal self-signed Authenticode signatures and a native packaged GUI probe for earlier artifact hashes. That evidence remains historical, but it does not describe the current target/release artifacts listed above.

## Engine Stack and Authority Boundaries

- GYRE: sole verdict authority for classification and base confidence.
- NEST: evidence orchestrator/convergence layer; selects and packages GYRE-linked evidence but does not replace GYRE.
- AETHERFRAME/Forge: optional bounded confidence uplift, refinement, and lineage metadata; never changes GYRE classification. Standalone AetherFrame core is product-agnostic and adapter-driven; HexHawk is one adapter/proving ground, not the conceptual owner.
- TALON: decompiler and structured pseudocode/evidence surface.
- STRIKE: debugger/trace timeline intelligence and behavioral deltas.
- ECHO: exact/fuzzy signature and cross-binary correlation surface.
- CREST: report packaging/export surface.
- NEXUS: assistant/consumer layer, not verdict authority.

## Highlights Shipped

- Native Tauri desktop shell with Rust backend commands.
- Binary identity, metadata, strings, disassembly, CFG, evidence, and report workflows.
- NEST evidence bundle validation with GYRE sole-verdict-source checks.
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
yarn typecheck
yarn build
yarn test --reporter=dot
cargo check --workspace
cargo test --workspace
yarn tauri:build
sha256sum target/release/hexhawk-backend.exe target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe
Get-AuthenticodeSignature <exe/msi/nsis>
powershell updater metadata validation for local generated metadata; hosted https://hexhawk.ke/releases/latest.json currently fetches but fails expected current artifact/signature validation
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/release/run-native-parity-probe.ps1 -MsiPath ./target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi -OutputPath ./gui-evidence/release_hardening_native_gui_probe_2026-06-01_234839.json
```

## What Is Still Needed Before Public Release

- Configure a real Windows code-signing path using an organization/public-trusted certificate in release custody (`HEXHAWK_CODESIGN_THUMBPRINT` or `HEXHAWK_CODESIGN_PFX_PATH` plus password).
- Rebuild and verify signed executable/MSI/NSIS artifacts.
- Complete a real GitHub Actions tag release using the configured updater secrets, then regenerate/publish updater metadata from that environment after hosted access is repaired.
- Rerun native GUI parity on the signed artifact intended for testers/public release.
- Perform a clean external-tester install/uninstall smoke pass.
- Publish checksums and signed provenance through the chosen release channel.
