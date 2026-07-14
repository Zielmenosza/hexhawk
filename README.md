# HexHawk

Last updated: 2026-07-14

HexHawk 1.0.0 is a local-first native desktop reverse-engineering and binary-intelligence workbench built with Rust, Tauri, React, and TypeScript. It combines binary identity, static and runtime evidence, disassembly and decompiler assistance, persistent investigation projects, explicit authority boundaries, and reviewable report/export provenance.

For the complete evidence-scoped milestone statement, see [docs/CURRENT_STATUS.md](docs/CURRENT_STATUS.md).

## Current product shape

HexHawk can save a versioned project and reopen it after process restart or cache clearing. A project persistently links:

- the imported binary and its verified identity;
- the associated NEST lifecycle session, when present; and
- the immutable recorded GYRE verdict snapshot that supplies classification authority.

Open operations reject missing, malformed, unsupported, stale, mismatched, and cross-binary persisted authority records. Paths and display names are location metadata, not binary identity. Two distinct binaries remain isolated through persistence and cache clearing. Reports and exports bind provenance to the resolved recorded snapshot and fall back honestly to summary-only output when authoritative evidence is unavailable.

## Authority boundaries

- **GYRE** is the sole authoritative source of classification and recorded base-verdict state.
- **NEST** organizes evidence and lifecycle context. It may link a session to a recorded verdict snapshot but does not independently issue, rewrite, replace, or override classification.
- **AETHERFRAME/Forge** is optional, bounded, replayable, auditable, disableable, and non-authoritative for classification.
- **NEXUS** assists and consumes evidence; it must not mutate authoritative verdict state.
- **TALON** provides advisory decompiler and pseudocode evidence.
- **STRIKE** provides runtime/debugger evidence.
- **ECHO** provides signature and correlation evidence.
- **CREST** packages reports and exports without becoming verdict authority.

High-assurance use retains deterministic and replayable paths without requiring AETHERFRAME uplift. No AI layer may silently become verdict authority, and stale or cross-binary verdict data must never be silently reused.

## Shipped capabilities

- Native Tauri desktop shell and Rust backend commands.
- Binary identity, metadata, strings, disassembly, CFG, evidence, and report workflows.
- Project save and reliable reopen using versioned manifests.
- Persisted binary, NEST-session, and immutable GYRE-snapshot linkage.
- Cache-clear and process-restart recovery with persisted verdict hydration.
- Binary-identity mismatch and cross-binary evidence-isolation enforcement.
- Report and export provenance tied to the recorded verdict snapshot.
- PE imports, queryable xrefs, function-boundary recovery, Win32 constants, calling-convention inference, and Function Intelligence/Notebook evidence surfaces.
- Local/offline analysis with optional BYOK assistance where configured.
- Windows MSI and NSIS packaging for the current 1.0.0 release candidate.

Function Intelligence, TALON, STRIKE, NEST, AETHERFRAME, and NEXUS remain evidence or assistant surfaces; none replaces GYRE classification authority.

## Milestone validation

Locally recorded validation for milestone commit `ebbd068bd8d30f68bedc2940ed9b0c5bfc80b586`:

- Rust backend suite: 124 passed.
- `nest_cli` suite: 29 passed.
- Total Rust tests: 153 passed.
- Focused frontend persistence/provenance tests: 22 passed across 7 files.
- TypeScript `--noEmit`: passed.
- Vite production build: passed.
- `cargo check --release`: passed.

Known non-blocking warnings are the Vite mixed dynamic/static import warning involving `talonLLMPass.ts`, the Vite large-chunk warning, and libsodium LNK4099 missing-PDB warnings during Windows linking.

This is local evidence. It does not claim that all historical frontend suites were rerun, hosted GitHub CI is currently green, or local validation is equivalent to hosted CI.

## Windows 1.0.0 release candidate

| Package | SHA-256 | Authenticode |
| --- | --- | --- |
| `HexHawk_1.0.0_x64_en-US.msi` | `A6A298CCFD39F8C53346D23A1BC7EC7795E3251E34031678735BE9C116E09BDB` | NotSigned |
| `HexHawk_1.0.0_x64-setup.exe` | `9FCC206AA60774F9CFD43E44994967517F8209B842FF266EE047346B5CE3AD61` | NotSigned |

Verified package metadata identifies HexHawk 1.0.0. The MSI ProductCode is `{CAF8CE99-C0B1-4114-AE21-3DE17CE20503}` and UpgradeCode is `{3D3A0671-FEE4-5C55-9D52-7D09A186D1E4}`. Neither installer has a signer certificate or trusted timestamp.

The current package is a Windows release candidate ready for controlled local installation testing. It is not a public-trusted, procurement-ready, production-ready, signed, fully installer-validated, or updater-ready release.

## Next release gate

Controlled installation and functional acceptance testing must still prove:

1. NSIS installation and installed-application launch.
2. Installed two-binary project persistence and identity isolation.
3. Installed restart and cache-clear recovery.
4. Installed report and export provenance.
5. Uninstall/reinstall behavior and user-data retention policy.
6. Code signing and updater validation against the exact signed artifacts.
7. Hosted publication and support readiness.

No installer was installed or acceptance tested by the packaging milestone alone.

## Engineering workflow note

The Bridge improved engineering continuity by preserving branch, commit, evidence, validation, stop-point, and worktree-custody context and supporting bounded packaging recovery. It is not part of HexHawk's analysis engine, did not alter GYRE logic or classification accuracy, does not produce verdicts, and is not required to run HexHawk.

## Start here

- Beginner and evaluator guide: [docs/HEXHAWK_FOR_DUMMIES.md](docs/HEXHAWK_FOR_DUMMIES.md)
- Current engineering status: [docs/CURRENT_STATUS.md](docs/CURRENT_STATUS.md)
- Roadmap: [ROADMAP.md](ROADMAP.md)
- Competitive job-fit positioning: [competitive_landscape.html](competitive_landscape.html)
