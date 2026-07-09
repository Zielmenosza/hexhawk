# HexHawk Investor Diligence Brief

Date: 2026-07-09

## Executive Summary

HexHawk has reached a stronger source milestone: the v1.30 Function Intelligence layer turns recent reverse-engineering foundations into one advisory selected-function workflow, and the v1.31 byte_counter clippy blocker is fixed. Current source validation passed Rust tests, Rust clippy with `-D warnings`, TypeScript, full frontend Vitest, and production frontend build.

This is appropriate for engineering, investor, and board demonstration as a source candidate. It is not yet a newly packaged unsigned deployment candidate from this source state, and it is not a signed public release.

## Architecture

- Frontend: React + TypeScript.
- Desktop/runtime: Tauri v2.
- Backend/commands: Rust.
- CLI: `nest_cli` for headless/runtime evidence operations.
- Packaging: Windows MSI and NSIS artifacts.


## Product-Friendly Buyer Narrative

The simplest buyer narrative is: “HexHawk turns a local binary into a reviewable evidence package.” A buyer should not need to decode internal engine names first. The public/product explanation should lead with:

- what file or artifact the user opens;
- what evidence HexHawk extracts or organizes;
- which module is responsible for verdict authority;
- which helper outputs are advisory;
- what report/export the buyer can hand to a reviewer;
- what release/trust gates are still not satisfied.

This keeps the product friendlier than traditional RE jargon while preserving the high-assurance boundary that AI or helper layers do not own security truth.

## Trust Model

HexHawk’s trust hierarchy is explicit:

- GYRE: sole verdict authority.
- NEST: evidence orchestration and convergence; not verdict authority.
- AETHERFRAME/Forge: optional bounded confidence uplift/refinement/lineage; cannot change classification.
- TALON/STRIKE/ECHO: evidence and analyst surfaces.
- CREST: report packaging.
- NEXUS: assistant/consumer layer.

This prevents AI/assistant features from silently becoming security truth.

## Current Validation Evidence

Commands run in the latest source-validation pass:

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
cd HexHawk
npx tsc --noEmit
TEST_FILES=$(find src \( -name '*.test.ts' -o -name '*.test.tsx' \) | grep -v node_modules | sort | tr '\n' ' ')
npx vitest run --reporter=dot $TEST_FILES
yarn build
```

Observed results:

- Function Intelligence model/export/UI/wiring/regression work completed through `v1.30.0-function-intelligence-regression`.
- byte_counter C string metadata clippy blocker fixed in `v1.31.0-byte-counter-clippy-fix`.
- Rust tests: passed, 85 backend tests + 20 `nest_cli` tests.
- Rust clippy: passed with `-D warnings`.
- Typecheck: passed.
- Full frontend tests: passed, 59 files / 832 tests.
- Frontend build: passed with existing Vite warnings.
- Fresh Tauri build, artifact hashes, signing-status checks, installer smoke, and Function Notebook export smoke remain pending for this source state.

## Function Intelligence Milestone

The current source adds an advisory function evidence notebook over PE imports, xrefs, recovered function boundaries, Win32 constants, TALON pseudocode, debugger call stacks, conditional breakpoint hits, and calling-convention inference. Exports preserve GYRE authority markers and are not verdict outputs.

## Commercial Readiness

Ready:

- Internal demonstration.
- Technical diligence walkthrough.
- Controlled local source evaluation.
- Pilot packaging discussion with explicit unsigned/updater caveats.

Not ready until resolved:

- Signed public installer.
- Signed updater artifacts or explicitly disabled updater policy.
- Fresh exact-artifact native GUI and Function Notebook export parity revalidation on the artifact intended for testers.
- External support, privacy, procurement, and issue-intake process.

## Risks and Mitigations

| Risk | Status | Mitigation |
| --- | --- | --- |
| Windows SmartScreen warnings | Open | Code-sign executable/installers with organization-trusted certificate. |
| Updater distribution | Open | Publish and validate metadata only for exact official artifacts. |
| GUI parity after package extraction | Launch/render smoke current for June 20 candidate; full export parity historical | Rerun full export parity on the exact MSI/NSIS intended for release. |
| AI/verdict overclaiming | Controlled | Maintain GYRE/NEST/AETHERFRAME boundary tests/copy. |
| Enterprise procurement | Open | Prepare signing, SBOM/provenance, support docs. |

## Diligence Bottom Line

HexHawk is beyond concept stage: it builds, packages, performs file-bound workflows, and has a trust model designed to prevent AI/verdict overreach. The remaining work is release trust: real code signing, updater metadata/signing, exact-artifact native GUI proof, procurement readiness, and commercial operations.
