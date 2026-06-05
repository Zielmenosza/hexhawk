# HexHawk High-Assurance Guide

Date: 2026-06-04

## Goal

High-assurance HexHawk workflows prioritize deterministic evidence, explicit policy gates, and replayable exports over convenience or AI-driven shortcuts.

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

The current Windows build is an unsigned internal tester candidate. The June 4 rebuilt artifacts are Authenticode NotSigned, and exact-artifact native GUI parity has not been rerun for those hashes. It is not yet a high-assurance external release.
