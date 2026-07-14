# HexHawk Release Signing and Updater Plan

Last updated: 2026-07-14

Status: HexHawk 1.0.0 MSI and NSIS release-candidate packages build, but both are Authenticode `NotSigned`. Updater readiness has not been proven for these exact artifacts.

## Current artifacts

- MSI: `HexHawk_1.0.0_x64_en-US.msi`
  - SHA-256: `A6A298CCFD39F8C53346D23A1BC7EC7795E3251E34031678735BE9C116E09BDB`
  - Authenticode: `NotSigned`
- NSIS: `HexHawk_1.0.0_x64-setup.exe`
  - SHA-256: `9FCC206AA60774F9CFD43E44994967517F8209B842FF266EE047346B5CE3AD61`
  - Authenticode: `NotSigned`

No signer certificate or trusted timestamp is present. The installers have not passed controlled installation acceptance.

## Required signing evidence

For the executable, MSI, and NSIS artifact record:

- exact SHA-256 and size;
- source branch and commit;
- signer subject and certificate thumbprint;
- trusted timestamp and timestamp authority;
- Authenticode status and trust chain;
- build and release-custody provenance.

Never commit private keys, PFX material, passwords, or updater private keys.

## Signing procedure

1. Obtain an organization-controlled Windows code-signing certificate.
2. Keep private material in an approved secret store or controlled runner.
3. Build from clean, reviewed source custody.
4. Sign the executable and both installers with a trusted timestamp.
5. Recalculate hashes after signing.
6. Verify Authenticode on the exact distribution files.
7. Run the complete installed-artifact acceptance gate against the signed files.
8. Preserve human-readable and machine-readable evidence.

## Updater gate

1. Generate updater artifacts only in the approved signing environment.
2. Validate the updater signature against the configured public key.
3. Publish metadata only for exact signed artifact URLs, hashes, and signatures.
4. Fetch hosted metadata independently and verify every platform field.
5. Prove download, signature verification, install/update behavior, rollback/failure behavior, and version transition.
6. Do not claim updater readiness until those checks pass for the exact signed artifacts.

## Acceptance dependency

Before signing/publication, the current unsigned candidate must first undergo controlled install, installed launch, two-binary persistence, restart/cache-clear, report/export provenance, uninstall, reinstall, and user-data retention tests. Packaging and source tests do not replace that acceptance evidence.

## Historical evidence boundary

June release, signing, updater, and smoke records remain historical snapshots tied to their recorded hashes. They must not be used as evidence for the 2026-07-14 candidate unless the exact artifact hash matches.
