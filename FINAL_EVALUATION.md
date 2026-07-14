# HexHawk Current Evaluation

Last updated: 2026-07-14

## Executive summary

HexHawk 1.0.0 has reached a Windows release-candidate milestone with persistent projects, reliable reopen, immutable recorded GYRE verdict authority, binary-identity isolation, restart/cache-clear recovery, and report/export provenance. The Windows MSVC build produced verified MSI and NSIS artifacts.

The candidate is ready for controlled local installation and functional acceptance testing. It is not signed, public-trusted, production ready, procurement ready, updater ready, or fully installer validated. No controlled installation test has passed for the exact current artifacts.

Canonical details: [docs/CURRENT_STATUS.md](docs/CURRENT_STATUS.md).

## Engineering milestone

- Branch: `feature/project-persistence-e2e`.
- Commit: `ebbd068bd8d30f68bedc2940ed9b0c5bfc80b586`.
- Project save/reopen and versioned manifests implemented.
- Projects persistently link binary identity, optional NEST lifecycle context, and immutable recorded GYRE snapshot authority.
- Missing, malformed, unsupported, stale, mismatched, and cross-binary authority data are rejected.
- Cache-clear and process-restart hydration recover the recorded authority state.
- Reports and exports carry recorded-snapshot provenance and degrade honestly when authority is unavailable.

## Authority assessment

GYRE is the sole classification and recorded base-verdict authority. NEST organizes evidence and lifecycle state but does not issue or override classifications. AETHERFRAME/Forge is optional and non-authoritative. NEXUS assists and consumes but cannot mutate authoritative state. No stale or cross-binary verdict may be silently reused.

## Validation evidence

- Rust backend: 124 passed.
- `nest_cli`: 29 passed.
- Total Rust: 153 passed.
- Focused frontend persistence/provenance: 22 passed across 7 files.
- TypeScript `--noEmit`: passed.
- Vite production build: passed.
- `cargo check --release`: passed.

Known non-blocking warnings: Vite mixed dynamic/static import involving `talonLLMPass.ts`, Vite large chunk, and libsodium LNK4099 missing-PDB warnings.

The evidence is local. It does not prove that all historical frontend suites were rerun or that hosted GitHub CI is green.

## Current Windows artifacts

- MSI: `HexHawk_1.0.0_x64_en-US.msi`
  - SHA-256: `A6A298CCFD39F8C53346D23A1BC7EC7795E3251E34031678735BE9C116E09BDB`
  - ProductName `HexHawk`, ProductVersion `1.0.0`, Manufacturer `hexhawk`
  - ProductCode `{CAF8CE99-C0B1-4114-AE21-3DE17CE20503}`
  - UpgradeCode `{3D3A0671-FEE4-5C55-9D52-7D09A186D1E4}`
- NSIS: `HexHawk_1.0.0_x64-setup.exe`
  - SHA-256: `9FCC206AA60774F9CFD43E44994967517F8209B842FF266EE047346B5CE3AD61`
  - ProductName/FileDescription `HexHawk`; ProductVersion/FileVersion `1.0.0`

Both are Authenticode `NotSigned`, with no signer certificate or trusted timestamp.

## Product assessment

Strengths:

- Local-first evidence custody and persistent investigation state.
- Explicit, testable authority doctrine.
- Immutable recorded-verdict provenance through restart and cache clearing.
- Cross-binary evidence-isolation protections.
- Auditable report/export lineage and honest degraded output.
- Working Windows MSI and NSIS packaging with verified hashes and metadata.

Remaining limitations:

- No exact-artifact controlled installation, installed launch, persistence, restart/cache-clear, report/export, uninstall, or reinstall acceptance pass.
- No code signing.
- No updater proof against exact signed artifacts.
- No hosted-CI-green claim.
- Decompiler, debugger, architecture, and plugin depth remain behind established mature reverse-engineering ecosystems.
- Public release operations and support readiness remain open.

## Bridge versus product improvement

The Bridge improved engineering continuity, worktree separation, evidence custody, timeout recovery, and controlled packaging. It did not become part of the engine or improve classification accuracy.

HexHawk improved through persistence, provenance, authority preservation, identity isolation, expanded focused tests, and successful Windows packaging.

## Conclusion

The next step is controlled installation and functional acceptance testing of the exact candidate artifacts—not stronger release language. Signing, updater validation, hosted release evidence, and support readiness follow only after that gate passes.
