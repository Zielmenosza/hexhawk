# HexHawk High-Assurance Guide

> **Bounded Windows first-release candidate — RC HOLD.** Qualification scope is authorized PE32/x86 and PE32+/x64 EXE/DLL static inspection (up to 64 MiB), GYRE-owned verdict/evidence/limitations and identity-consistent JSON/Markdown export, with NEST/CREST evidence custody. Inputs are data, never executed. No safety certificate, accuracy calibration, trusted signing or release approval is implied.
>
> Broader features described below remain historical/out of scope: scripting/REPL, plugins, live debugging/memory editing, sandboxing, patching, comparison, saved-history restoration, function/decompiler/advisory-AI workspaces, online AI, updates and other formats/platforms. Native scope restrictions do not grant entitlements. Dependency/security, notices/legal and independent release-owner gates remain open.

**Updated:** 2026-08-20

## Purpose

High-assurance use means “show your work”: preserve the exact input identity, use deterministic evidence where possible, keep authority boundaries explicit, record uncertainty and stop conditions, and export enough context for another analyst to review or replay the work.

It does not mean HexHawk certifies a file as safe.

## Required authority boundaries

- **GYRE is the sole verdict and base-confidence authority.**
- **NEST stores and manages evidence through its lifecycle.** It may identify, collect, validate, group, iterate, export, and retain GYRE-linked evidence; it does not create or replace the verdict.
- **AETHERFRAME is bounded advisory governance.** It may attach lineage, budgets, uncertainty, proof limits, checkpoints, stop conditions, and suggested next actions. It cannot alter GYRE verdict fields or NEST evidence.
- **TALON, STRIKE, ECHO, plugins, decompiler output, debugger observations, comparison output, and AI observations are supporting or advisory surfaces.**
- **CREST/report packaging preserves evidence for handoff.** Packaging does not create authority.
- **NEXUS/AI assistance remains labelled and human-reviewed.**

AetherFrame core is product-agnostic and adapter-driven. AetherFrameGuard is a separate application and must not be treated as the HexHawk implementation container.

## Operator workflow

1. Record the exact HexHawk binary/installer hash and runtime mode.
2. Record authorization and the SHA-256 of every input.
3. Begin with **Start inspection** and deterministic local evidence.
4. Separate observations from inferences while using **Find readable text**, **Read program instructions**, **See possible code paths**, and **Examine one function**.
5. Review **Overall assessment** and **Reasons behind the result**. Preserve the GYRE source marker and base confidence.
6. Use **Repeat and organize checks** only as an evidence-lifecycle step. Record iteration changes and validation failures.
7. If advisory systems are used, record provider/source, approval, inputs, outputs, lineage, uncertainty, and proof limits.
8. Use **Create a report** and verify the exported authority envelope against the visible result.
9. Record untested branches, unsupported formats, truncation, runtime gaps, and stop conditions.
10. Hash the final export and preserve it with the input identity and tool-build identity.

## Runtime safety

**Live Debugger** executes the selected file. High-assurance runtime work requires an approved isolated lab, trusted or controlled samples, a defined containment policy, and explicit authorization. HexHawk is not itself a containment boundary or cloud malware sandbox.

**Run inspection scripts** is a helper-script surface, not malware isolation.

## Report requirements

A high-assurance report should include:

- input SHA-256, size, format, and acquisition context;
- HexHawk build or artifact identity;
- tools and configuration used;
- direct observations with source references;
- analyst and AI interpretations clearly labelled;
- the GYRE-owned verdict and base confidence;
- NEST evidence-lifecycle state and validation outcome, if used;
- AETHERFRAME advisory lineage and blocked mutations, if used;
- runtime-environment identity, if runtime evidence is claimed;
- truncation, unsupported paths, contradictions, unknowns, and proof limits;
- export hash and review sign-off.

If required authority fields are missing, do not repair the export manually. Reproduce and fix the source path.

## Exact-artifact release gate

The current test deliverable is an unsigned NSIS installer named `HexHawk_1.0.0_x64-setup.exe`. Its expected SHA-256 belongs in the adjacent checksum sidecar and release handoff, not inside these packaged docs; embedding it would create a self-referential hash that changes whenever the docs are rebuilt into the installer.

The corrected native payload passed repeated clean-profile cold starts without Refresh. This is evidence for the tested payload only.

Before external high-assurance or public-release claims, require:

- exact source-to-artifact custody;
- complete Rust/frontend validation;
- signed Windows artifacts using an approved, trusted process;
- checksum and signature publication for the exact payload;
- controlled installer and uninstall smoke tests;
- clean-profile native startup evidence;
- installed-app workflow and export parity;
- authority-envelope and evidence-lifecycle validation;
- updater disabled or separately signed and tested;
- documented known limits and release decision.

## Validation commands

```bash
yarn typecheck
yarn test --reporter=dot
npm --prefix HexHawk run build
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

A passing source suite is not installer proof. A browser preview is not native Tauri proof. A prior build's hash is not evidence for a rebuilt artifact.

## Stop conditions

Stop and escalate rather than claiming success when:

- input identity changes;
- the GYRE authority marker is absent or contradictory;
- NEST validation fails or silently defaults to success;
- advisory output appears to mutate protected verdict/evidence fields;
- runtime containment or authorization is unclear;
- exports omit required evidence or limitations;
- exact artifact hashes do not match custody records;
- signing or updater state differs from the release claim.
