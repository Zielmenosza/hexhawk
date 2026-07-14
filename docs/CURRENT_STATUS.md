# HexHawk 1.0.0 Engineering Status

Last updated: 2026-07-14

This is the canonical current-status summary for first-party HexHawk engineering documentation. Dated validation records and preserved evidence remain historical snapshots and must not be read as replacements for this status.

## Milestone custody

- Product: HexHawk 1.0.0
- Engineering branch: `feature/project-persistence-e2e`
- Milestone commit: `ebbd068bd8d30f68bedc2940ed9b0c5bfc80b586`
- Commit title: `[GYRE/NEST] Bind NEST to immutable recorded verdict snapshots`
- The feature branch and remote milestone commit were verified at the same commit.
- The engineering worktree was clean after packaging and recovery.

## Current product shape

HexHawk now supports versioned project manifests, project save and reliable reopen, persistent binary and NEST-session linkage, and persistent linkage to immutable recorded GYRE verdict snapshots. Open operations verify binary identity and reject stale, malformed, unsupported, missing, mismatched, or cross-binary authority data. Persisted verdict hydration survives process restart and cache clearing. Reports and exports bind provenance to the resolved recorded snapshot and degrade honestly to summary-only output when authoritative evidence is unavailable.

Two distinct persisted binaries can survive cache clearing without identity crossover. Path or display name is not treated as binary identity.

## Authority doctrine

- GYRE is the sole authoritative source of classification and recorded base-verdict state.
- NEST orchestrates evidence and lifecycle context. Its project linkage is advisory unless backed by the immutable recorded GYRE snapshot; NEST does not issue, rewrite, replace, or override classification.
- AETHERFRAME/Forge is optional, bounded, replayable, auditable, disableable, and non-authoritative for classification.
- NEXUS is an assistant and consumer layer and must not mutate authoritative verdict state.
- High-assurance workflows retain deterministic and replayable paths without requiring AETHERFRAME uplift.
- Reports and exports distinguish authoritative recorded evidence from advisory, incomplete, or unavailable evidence.
- No AI layer may silently become verdict authority. Stale or cross-binary verdict data must never be reused silently.

## Validation evidence for this milestone

Locally executed validation recorded for the milestone:

- Rust backend suite: 124 passed.
- `nest_cli` suite: 29 passed.
- Total Rust tests: 153 passed.
- Focused frontend persistence/provenance validation: 22 passed across 7 test files.
- TypeScript `--noEmit`: passed.
- Frontend Vite production build: passed.
- `cargo check --release`: passed.

Known non-blocking warnings were the Vite mixed dynamic/static import warning involving `talonLLMPass.ts`, the Vite large-chunk warning, and libsodium LNK4099 missing-PDB warnings during Windows linking.

These results are local evidence. They do not prove that all historical frontend suites were rerun, that hosted GitHub CI is currently green, or that local validation is equivalent to hosted CI.

## Windows release-candidate evidence

The Windows MSVC release build produced:

| Package | File | SHA-256 | Signing status |
| --- | --- | --- | --- |
| MSI | `HexHawk_1.0.0_x64_en-US.msi` | `A6A298CCFD39F8C53346D23A1BC7EC7795E3251E34031678735BE9C116E09BDB` | NotSigned |
| NSIS | `HexHawk_1.0.0_x64-setup.exe` | `9FCC206AA60774F9CFD43E44994967517F8209B842FF266EE047346B5CE3AD61` | NotSigned |

Verified MSI metadata: ProductName `HexHawk`, ProductVersion `1.0.0`, Manufacturer `hexhawk`, ProductCode `{CAF8CE99-C0B1-4114-AE21-3DE17CE20503}`, and UpgradeCode `{3D3A0671-FEE4-5C55-9D52-7D09A186D1E4}`.

Verified NSIS metadata: ProductName `HexHawk`, ProductVersion `1.0.0`, FileVersion `1.0.0`, and FileDescription `HexHawk`.

Neither installer has a signer certificate or trusted timestamp. The artifacts have not been installed or acceptance tested.

## Release posture and next gate

This package is a Windows release candidate ready for controlled local installation and functional acceptance testing. It is not a public-trusted, procurement-ready, production-ready, fully installer-validated, or signed release.

The next release gate is controlled installation and functional acceptance testing covering:

1. NSIS installation and installed-application launch.
2. Installed two-binary project persistence and identity isolation.
3. Installed restart and cache-clear recovery.
4. Installed report and export provenance.
5. Uninstall and reinstall behavior, including user-data retention policy.
6. Code signing.
7. Updater validation against the exact signed artifacts.
8. Hosted release publication and support readiness.

No item in that gate is marked passed by the packaging evidence alone.

## Bridge workflow versus HexHawk product improvements

The Bridge is an engineering-continuity mechanism, not part of the HexHawk analysis engine. It preserved branch, commit, validation, stop-point, and repository-custody context; improved website/engineering separation; reduced repeated investigation; supported bounded recovery after command timeouts; and preserved packaging evidence. It did not change GYRE logic, improve malware-classification accuracy, produce verdicts, or become required to run HexHawk.

HexHawk itself improved through persistent projects, reliable reopen, immutable recorded GYRE authority, binary-identity isolation, cross-binary mismatch rejection, persisted NEST lifecycle linkage, restart/cache-clear recovery, report/export provenance, honest degraded reporting, stronger malformed/stale evidence rejection, expanded persistence/provenance tests, and successful MSI/NSIS packaging with verified hashes, metadata, unsigned status, and explicit remaining release gates.
