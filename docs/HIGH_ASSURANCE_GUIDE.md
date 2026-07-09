# HexHawk High-Assurance Guide

Date: 2026-07-09

## Goal

High-assurance HexHawk workflows prioritize deterministic evidence, explicit policy gates, and replayable exports over convenience or AI-driven shortcuts.


## Consumer-safe explanation

High-assurance mode is the “show your work” version of HexHawk. It should make clear what file was reviewed, what evidence was collected, which engine produced each statement, what GYRE decided, what NEST grouped, whether AETHERFRAME/Forge or NEXUS helped with wording/context, and what remains unproven.

For buyers and testers, the promise is not “trust the AI.” The promise is “trust the chain of custody enough to review it”: input identity, deterministic evidence, labelled helper output, replayable exports, and visible stop conditions.

## Required Behavior

- GYRE remains final verdict authority.
- NEST evidence bundles must preserve file identity and GYRE linkage.
- AETHERFRAME/Forge uplift must be explicitly policy-gated.
- Standalone AetherFrame core must remain product-agnostic and adapter-driven; AetherFrameGuard is a separate application, not the core implementation container.
- High-assurance mode must be able to disable uplift and present base GYRE/NEST outputs directly.
- Reports must disclose whether uplift/lineage metadata was applied.
- AETHERFRAME report Markdown packaging must be disabled or left package-only in high-assurance contexts; disabled policy must leave the report body unchanged and record disabled lineage only in adapter metadata/tests, not in exported verdict truth. The report panel exposes this as an analyst-controlled Markdown/copy export toggle.

## Release Guidance

For external high-assurance testers, do not ship until:

- Windows artifacts are signed.
- Updater artifacts are signed or explicitly disabled and documented.
- Installed native GUI export parity is rerun.
- Exported reports preserve `source_engine: gyre` and `gyre_is_sole_verdict_source: true`.
- Evidence bundle validation does not silently default to success.

## Current Status

The current source state is a v1.30/v1.31 Function Intelligence source candidate on `feature/re-workbench-core-next`. Source validation in this session passed Rust tests, Rust clippy with `-D warnings`, TypeScript noEmit, full Vitest (59 files / 832 tests), and production frontend build.

Function Intelligence and Function Notebook provide advisory selected-function evidence: imports, xrefs, function boundaries, constants, pseudocode, calling conventions, debugger observations, limits, and JSON/Markdown export. They do not become verdict authority.

A fresh exact-artifact deployment gate is still required before calling this source state an unsigned deployment candidate. Public-trusted signing, updater readiness, and high-assurance external release status remain unproven until exact artifacts pass signing/status, installer smoke, and export authority-envelope checks.
