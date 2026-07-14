# HexHawk External Tester Known Issues

Last updated: 2026-07-14

Audience: internal evaluators preparing controlled acceptance of the HexHawk 1.0.0 Windows release candidate.

## Current blockers

1. **The current MSI and NSIS installers are unsigned.**
   - Both Authenticode results are `NotSigned`.
   - No signer certificate or trusted timestamp is present.
   - SmartScreen or enterprise endpoint controls may warn or block.

2. **No controlled installation acceptance has passed for the exact current artifacts.**
   - Installation, installed launch, two-binary persistence, restart/cache-clear recovery, report/export provenance, uninstall, and reinstall remain open.
   - Historical smoke results apply only to their recorded hashes and are not proof for this candidate.

3. **Updater readiness is not proven.**
   - Updater metadata has not been validated against exact signed versions of these artifacts.
   - Packaging success does not imply updater readiness.

4. **Hosted CI status is not claimed.**
   - Current validation evidence is local and is not equivalent to hosted CI.

5. **Commercial operations remain incomplete.**
   - Support, rollback, security/privacy, procurement, and public release custody remain open.

## Known non-blocking build warnings

- Vite mixed dynamic/static import warning involving `talonLLMPass.ts`.
- Vite large-chunk warning.
- libsodium LNK4099 missing-PDB warnings during Windows linking.

## Current milestone evidence

- 153 total Rust tests passed: 124 backend and 29 `nest_cli`.
- 22 focused frontend persistence/provenance tests passed across 7 files.
- TypeScript `--noEmit`, Vite production build, and `cargo check --release` passed.
- MSI SHA-256: `A6A298CCFD39F8C53346D23A1BC7EC7795E3251E34031678735BE9C116E09BDB`.
- NSIS SHA-256: `9FCC206AA60774F9CFD43E44994967517F8209B842FF266EE047346B5CE3AD61`.

## Authority and persistence limits

GYRE is sole classification and recorded base-verdict authority. NEST lifecycle linkage is advisory. AETHERFRAME/Forge and NEXUS are non-authoritative. Projects must reject stale, malformed, missing, unsupported, mismatched, and cross-binary authority data; unavailable authority must not silently fall back to stale output.

## Allowed wording

- Windows 1.0.0 release candidate.
- Ready for controlled local installation testing.
- Unsigned MSI and NSIS with verified hashes and metadata.
- Persistent projects and provenance are implemented and locally validated.

Do not claim signed, public release ready, production ready, procurement ready, updater ready, hosted CI green, or fully validated installer.
