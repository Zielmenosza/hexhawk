# HexHawk Tester Release Status

Last updated: 2026-07-14

## Recommendation

- Source milestone: implemented and locally validated at `ebbd068bd8d30f68bedc2940ed9b0c5bfc80b586` on `feature/project-persistence-e2e`.
- Windows release candidate: produced and ready for controlled local installation testing.
- Controlled installation acceptance: **not passed**.
- Controlled external signed-tester gate: **not passed**.
- Public release: **not ready**.

See [CURRENT_STATUS.md](CURRENT_STATUS.md) for the canonical current evidence.

## Candidate artifacts

| Artifact | SHA-256 | Authenticode |
| --- | --- | --- |
| `HexHawk_1.0.0_x64_en-US.msi` | `A6A298CCFD39F8C53346D23A1BC7EC7795E3251E34031678735BE9C116E09BDB` | NotSigned |
| `HexHawk_1.0.0_x64-setup.exe` | `9FCC206AA60774F9CFD43E44994967517F8209B842FF266EE047346B5CE3AD61` | NotSigned |

The package metadata identifies HexHawk 1.0.0. Neither installer has a signer certificate or trusted timestamp. Do not install outside a controlled test plan and do not interpret packaging as acceptance.

## Product capability under test

- Versioned project save and reliable reopen.
- Persisted binary, NEST lifecycle, and immutable recorded GYRE snapshot linkage.
- Binary-identity verification and cross-binary mismatch rejection.
- Cache-clear and process-restart recovery.
- Persisted verdict hydration.
- Report and export provenance tied to the recorded snapshot.
- Honest summary-only output and rejection behavior when authority is unavailable or invalid.

GYRE remains sole classification and recorded base-verdict authority. NEST is advisory lifecycle/evidence context. AETHERFRAME/Forge and NEXUS are non-authoritative.

## Local source validation

- Rust backend: 124 passed.
- `nest_cli`: 29 passed.
- Total Rust: 153 passed.
- Focused frontend persistence/provenance: 22 passed across 7 files.
- TypeScript `--noEmit`: passed.
- Vite production build: passed.
- `cargo check --release`: passed.

Known non-blocking warnings: Vite mixed dynamic/static import involving `talonLLMPass.ts`, Vite large chunk, and libsodium LNK4099 missing-PDB warnings.

No hosted-CI-green claim is made, and all historical frontend suites are not claimed rerun.

## Required controlled acceptance checklist

Leave every item open until observed against the exact candidate hashes:

- [ ] NSIS installation completes under the approved controlled procedure.
- [ ] Installed HexHawk launches successfully.
- [ ] Two distinct binaries save and reopen without identity crossover.
- [ ] Changed and cross-binary inputs are rejected.
- [ ] Restart and cache-clear recovery preserve the exact recorded authority linkage.
- [ ] Reports and exports identify the immutable recorded GYRE snapshot.
- [ ] Missing/malformed/unsupported/stale authority degrades or rejects honestly.
- [ ] Uninstall completes.
- [ ] Reinstall completes.
- [ ] User-data retention behavior matches the approved policy.
- [ ] Exact artifacts are code-signed and trust-verified before any signed claim.
- [ ] Updater metadata is validated against exact signed artifacts.

Do not use stale smoke folders or prior installer hashes as proof for this candidate.
