# HexHawk

HexHawk is a native desktop reverse engineering platform built with Rust, Tauri, React, and TypeScript.

It combines static analysis, decompilation, dynamic timeline analysis, signature correlation, and evidence-grade reporting in one workflow.

## Current State (May 2026)

HexHawk is in an actively shippable state with the following core status:

- Frontend tests: 34 files, 670 tests passing
- Frontend production build: passing
- Competitive capability posture:
  - Disassembly Depth: 10/10
  - Decompiler Quality: 9/10
  - Debugger / Dynamic: 9/10
  - Evidence and Reporting: 10/10

## Engine Stack

- TALON: decompiler and structured pseudocode pipeline
- STRIKE: debugger timeline intelligence and behavioral deltas
- ECHO: signatures and fuzzy similarity matching
- NEST: iterative analysis and convergence
- GYRE: final verdict synthesis from correlated evidence
- KITE: relationship graphing and analyst context
- CREST: report generation and export
- QUILL: plugin extension surface
- IMP: patching workflow

## Highlights Shipped

### Decompiler improvements

- Natural loop header recovery
- While/for reconstruction in structured output
- For-loop promotion when step patterns are recoverable from IR

### Disassembly intelligence

- Instruction annotation engine with severity levels
- API behavior annotation (30+ Windows APIs)
- Crypto constant recognition (including MD5, SHA families, AES/TEA-related markers)
- PEB/anti-analysis indicators, stack-depth tracking, boundary hints

### Dynamic analysis depth

- Call-stack reconstruction from timeline events
- Hot-block profiling by execution concentration
- Repeated execution loop detection for unpacking/decode loops

### Evidence and reporting depth

- MITRE ATT&CK mapping from behavioral tags and runtime signals
- IOC extraction from strings (network, hashes, paths, registry indicators)
- Enriched evidence payload suitable for CREST report sections

## Repository Layout

- HexHawk/: React + TypeScript frontend application
- src-tauri/: Rust backend (desktop runtime + commands)
- plugin-api/: plugin API contracts
- plugins/: built-in and sample plugin implementations
- nest_tests/: analysis run artifacts and benchmark captures
- Challenges/: challenge/sample binaries and datasets

## Quick Start

### Prerequisites

- Rust stable
- Node.js 20+
- Yarn

### Install

```bash
yarn install
```

### Run frontend tests

```bash
cd HexHawk
yarn vitest --run
```

### Build frontend

```bash
cd HexHawk
yarn build
```

### Run STRIKE benchmark gate

```bash
cd HexHawk
yarn strike:benchmark --stability-runs 3 --max-score-drop 5
```

This writes review artifacts to `nest_tests/strike_benchmarks/latest.json` and `nest_tests/strike_benchmarks/latest.md`.

### Refresh STRIKE baseline after an intentional improvement

```bash
cd HexHawk
yarn strike:benchmark:update-baseline
```

### Run desktop app (dev)

```bash
yarn tauri:dev
```

## Notes

- Competitive and roadmap-facing status is maintained in ROADMAP.md and FINAL_EVALUATION.md.
- STRIKE benchmark workflow details live in `HexHawk/scripts/strike-benchmarks/README.md`.
- The current docs intentionally reflect the shipped capability baseline, not historical milestone logs.

## License

MIT
