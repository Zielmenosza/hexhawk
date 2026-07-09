# HexHawk Investor One-Pager

Date: 2026-07-09

## What HexHawk Is

HexHawk is a local-first desktop reverse-engineering and binary-intelligence platform for malware analysts, incident responders, SOC teams, security researchers, and technical evaluators who need evidence they can explain to another person.

It helps analysts inspect binaries, extract evidence, reason over disassembly/decompiler views, correlate signals, and export structured reports without relying on opaque cloud detonation or unverifiable AI claims.

## Why Now

Security teams face more suspicious binaries, packed installers, commodity malware, internal tools, and supply-chain artifacts than they can manually triage. Existing workflows often jump between disassemblers, string tools, sandboxes, notes, and report templates.

HexHawk’s wedge is an integrated analyst workstation that keeps evidence, confidence, verdict boundaries, and report output in one local workflow.

## Current Proof

Latest source validation proves:

- Function Intelligence integration completed through v1.30: model, static/runtime correlation, JSON/Markdown export, Function Notebook UI, workflow wiring, and regression corpus.
- byte_counter clippy blocker fixed in v1.31 without relaxing `-D warnings`.
- Rust workspace tests passed: 85 backend tests + 20 `nest_cli` tests.
- Rust clippy passed with `-D warnings`.
- Typecheck and production frontend build passed.
- Full frontend Vitest passed: 59 files, 832 tests.
- Fresh packaging, signing-status checks, installer smoke, and Function Notebook export smoke remain pending before a new unsigned deployment-candidate tag.

## Current Product Status

- Status: validated Function Intelligence source candidate; fresh unsigned deployment-candidate gate pending.
- Good for: board demos, investor demos, controlled source review, technical diligence.
- Not yet for the stronger controlled external signed-tester gate: real public-trusted Authenticode custody, signed artifacts, hosted metadata validation, and exact signed-artifact native GUI/export proof are still required.
- Not yet for: broad public download, procurement-ready enterprise rollout, automatic updater distribution.


## Consumer/Product Wedge

HexHawk should be explained as a product, not a pile of engine names:

1. **Input:** open a suspicious or unknown binary locally.
2. **Evidence:** inspect hashes, metadata, imports, strings, code, function notes, signatures, and approved runtime observations.
3. **Authority:** GYRE owns classification; NEST organizes evidence; helper/AI layers remain labelled.
4. **Output:** export a report that a manager, reviewer, or second analyst can follow.

The commercial wedge is evidence-to-report continuity with explicit authority boundaries. Mature RE tools remain stronger for broad decompiler/debugger ecosystem depth; HexHawk should win when the buyer cares about local custody, labelled evidence, uncertainty, and handoff quality.

## Differentiation

- Local-first: core workflows run on the analyst machine.
- Evidence-grade: outputs tie back to file identity, strings, metadata, disassembly, selected-function evidence, and evidence bundles.
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

- Current source state still needs a fresh packaged release gate before a new unsigned deployment-candidate tag.
- Public-trusted signing is not proven until Authenticode validates exact artifacts.
- Updater metadata generation has an official-path plan, but hosted endpoint readiness remains blocked until exact hosted artifact/signature validation passes.
- Full native GUI and Function Notebook export parity must be rerun on the exact artifact intended for testers before external/public release.
- HexHawk does not claim to detonate malware, bypass protections, prove exploitability, or let AI replace deterministic verdict authority.
