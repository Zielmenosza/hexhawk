# HexHawk Investor One-Pager

Date: 2026-06-20

## What HexHawk Is

HexHawk is a local-first desktop reverse-engineering and binary-intelligence platform for malware analysts, incident responders, SOC teams, and security researchers.

It helps analysts inspect binaries, extract evidence, reason over disassembly/decompiler views, correlate signals, and export structured reports without relying on opaque cloud detonation or unverifiable AI claims.

## Why Now

Security teams face more suspicious binaries, packed installers, commodity malware, internal tools, and supply-chain artifacts than they can manually triage. Existing workflows often jump between disassemblers, string tools, sandboxes, notes, and report templates.

HexHawk’s wedge is an integrated analyst workstation that keeps evidence, confidence, verdict boundaries, and report output in one local workflow.

## Current Proof

Latest local validation and packaging pass proves:

- STRIKE benchmark provenance path fix committed and pushed.
- All discovered frontend tests passed in a fresh release worktree: 47 files, 736 passed, 1 skipped.
- Typecheck and production frontend build passing.
- MSI and NSIS installers build from post-fix HEAD.
- MSI extraction and NSIS install launch/render smoke passed.
- Current artifacts are unsigned according to Authenticode checks.
- Hosted updater metadata has not been refreshed/validated against the June 20 unsigned candidate NSIS hash.
- Current release evidence: `docs/release-evidence/unsigned_deployment_candidate_2026-06-20_215102.json`.

## Current Product Status

- Status: unsigned Windows deployment candidate for controlled internal testing.
- Good for: board demos, investor demos, controlled internal testing, technical diligence.
- Not yet for the stronger controlled external signed-tester gate: real public-trusted Authenticode custody, signed artifacts, hosted metadata validation, and exact signed-artifact native GUI proof are still required.
- Not yet for: broad public download, procurement-ready enterprise rollout, automatic updater distribution.

## Differentiation

- Local-first: core workflows run on the analyst machine.
- Evidence-grade: outputs tie back to file identity, strings, metadata, disassembly, and evidence bundles.
- Trust-safe AI: GYRE remains verdict authority; NEST orchestrates evidence; AETHERFRAME/Forge is optional bounded uplift/lineage metadata.
- Native desktop: Rust/Tauri backend with React/TypeScript UI.
- Commercial path: Windows installer, license activation flow, paid pilot packaging, and enterprise roadmap are in place, but release trust gates remain.

## Near-Term Ask / Use of Capital

1. Code signing and release provenance.
2. Updater signing and release metadata.
3. Paid pilot onboarding and support ownership.
4. Procurement/security documentation.
5. Focused analyst case studies and sales collateral.

## Key Caveats

- Current installer artifacts are unsigned.
- Updater metadata generation has an official-path plan, but hosted endpoint readiness remains blocked until exact hosted artifact/signature validation passes.
- Full native GUI export parity must be rerun on the exact artifact intended for testers before external/public release; June 20 launch/render smoke covers installer health only.
- HexHawk does not claim to detonate malware, bypass protections, prove exploitability, or let AI replace deterministic verdict authority.
