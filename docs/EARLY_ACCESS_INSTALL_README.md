# HexHawk 1.0.0 Controlled Installation README

Last updated: 2026-07-14

Audience: authorized technical testers performing controlled local acceptance of the unsigned Windows release candidate. Do not install either artifact outside the approved test procedure.

## Candidate identity

- MSI: `HexHawk_1.0.0_x64_en-US.msi`
  - SHA-256: `A6A298CCFD39F8C53346D23A1BC7EC7795E3251E34031678735BE9C116E09BDB`
- NSIS: `HexHawk_1.0.0_x64-setup.exe`
  - SHA-256: `9FCC206AA60774F9CFD43E44994967517F8209B842FF266EE047346B5CE3AD61`

Both installers are Authenticode `NotSigned`; no signer certificate or trusted timestamp is present. Hash equality confirms artifact identity, not publisher trust or safety.

## Before installation

1. Use an approved Windows test environment and benign test binaries.
2. Recalculate the installer SHA-256 and compare it with the value above and the artifact manifest.
3. Verify Authenticode still reports `NotSigned`.
4. Record Windows version, tester, date, candidate hash, and chosen installer.
5. Do not disable endpoint security globally. Stop and report unexpected warnings.

## Controlled acceptance sequence

Use one installer path per test cycle.

- [ ] Install the NSIS candidate under the approved procedure.
- [ ] Launch the installed application.
- [ ] Import two distinct benign binaries.
- [ ] Save and reopen separate projects without identity crossover.
- [ ] Confirm changed/cross-binary input is rejected.
- [ ] Restart the process and reopen.
- [ ] Exercise the approved cache-clear seam and reopen.
- [ ] Verify report provenance identifies the immutable recorded GYRE snapshot.
- [ ] Verify export provenance identifies the same recorded snapshot.
- [ ] Verify missing/malformed/unsupported/stale authority rejects or degrades honestly.
- [ ] Uninstall.
- [ ] Reinstall.
- [ ] Verify user-data retention behavior against the approved policy.

Leave every item unpassed until directly observed on the exact installer hash. Do not use stale smoke folders as evidence.

## Product authority reminder

GYRE is the sole classification and recorded base-verdict authority. NEST supplies advisory lifecycle/evidence context. AETHERFRAME/Forge and NEXUS are non-authoritative. No stale or cross-binary verdict may be silently reused.

## Known warnings and limitations

- Windows may show unknown-publisher or SmartScreen warnings because the artifacts are unsigned.
- Current package evidence does not establish production, procurement, enterprise, updater, or public-release readiness.
- Hosted CI status is not claimed.
- Known non-blocking build warnings include Vite mixed import/chunk warnings and libsodium LNK4099 missing-PDB warnings.

## Issue report fields

Record installer filename/hash, Windows version, exact step, expected/observed behavior, screenshots or exact text, project/binary identities without sensitive content, report/export provenance result, uninstall/reinstall result, and whether user data was retained.
