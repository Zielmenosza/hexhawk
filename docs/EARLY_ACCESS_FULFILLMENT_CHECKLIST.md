# Early-Access Fulfillment Checklist

## Exact HexHawk 1.0.0 candidate boundary (2026-07-14)

This workflow applies only to the two unsigned Windows release-candidate artifacts at `D:/Project/HexHawk/.local/releases/HexHawk-1.0.0-ebbd068-20260714-001856`:

- MSI: `HexHawk_1.0.0_x64_en-US.msi` — SHA-256 `A6A298CCFD39F8C53346D23A1BC7EC7795E3251E34031678735BE9C116E09BDB`
- NSIS: `HexHawk_1.0.0_x64-setup.exe` — SHA-256 `9FCC206AA60774F9CFD43E44994967517F8209B842FF266EE047346B5CE3AD61`

Both artifacts are Authenticode `NotSigned`, with no signer certificate and no trusted timestamp. Neither artifact has passed controlled installation, installed launch, installed project save/reopen, two-binary identity-isolation, restart/cache-clear recovery, report/export provenance, uninstall/reinstall, or user-data-retention acceptance. Do not describe or deliver them as production ready, procurement ready, enterprise ready, signed, updater ready, public-release ready, or fully installer validated. Every result below starts as **not tested** and must be recorded for the exact installer and SHA-256 used.

Use one checklist per paid tester. Keep buyer PII/payment proof in private business records, not in the public repo.

## Buyer and payment

- [ ] Confirm buyer identity/contact.
- [ ] Confirm payment manually.
- [ ] Confirm buyer accepted unsigned early-access limits.
- [ ] Confirm target machine is test/non-production.

## Delivery

- [ ] Re-run exact package verification immediately before sending.
- [ ] Send package privately.
- [ ] Send `SHA256SUMS.txt`.
- [ ] Send install README.
- [ ] Send buyer note.
- [ ] Record package version, hash, delivery date, and tester contact in private fulfillment records.

## Follow-up

- [ ] Request install result.
- [ ] Request first feedback.
- [ ] Log issues.
- [ ] Do not promise signed/public release date.

## Guardrails

- [ ] Do not claim signed release.
- [ ] Do not claim Microsoft verified.
- [ ] Do not claim public/world-ready.
- [ ] Do not enable or claim auto-update.
- [ ] Do not instruct buyer to disable Windows security globally.
- [ ] Do not publish package or payment/download links without explicit approval.
