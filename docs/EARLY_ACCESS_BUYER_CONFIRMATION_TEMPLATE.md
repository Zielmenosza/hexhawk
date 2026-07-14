# Early-Access Buyer Confirmation Template

## Exact HexHawk 1.0.0 candidate boundary (2026-07-14)

This workflow applies only to the two unsigned Windows release-candidate artifacts at `D:/Project/HexHawk/.local/releases/HexHawk-1.0.0-ebbd068-20260714-001856`:

- MSI: `HexHawk_1.0.0_x64_en-US.msi` — SHA-256 `A6A298CCFD39F8C53346D23A1BC7EC7795E3251E34031678735BE9C116E09BDB`
- NSIS: `HexHawk_1.0.0_x64-setup.exe` — SHA-256 `9FCC206AA60774F9CFD43E44994967517F8209B842FF266EE047346B5CE3AD61`

Both artifacts are Authenticode `NotSigned`, with no signer certificate and no trusted timestamp. Neither artifact has passed controlled installation, installed launch, installed project save/reopen, two-binary identity-isolation, restart/cache-clear recovery, report/export provenance, uninstall/reinstall, or user-data-retention acceptance. Do not describe or deliver them as production ready, procurement ready, enterprise ready, signed, updater ready, public-release ready, or fully installer validated. Every result below starts as **not tested** and must be recorded for the exact installer and SHA-256 used.

Buyer-facing text for email/WhatsApp. Replace bracketed placeholders before sending.

---

Hi [NAME],

Thank you for supporting HexHawk Early Access.

You are buying private early access to the HexHawk Unsigned Founder Build: a technical preview for Windows testers who understand unsigned software and want to help shape the product before the signed public channel exists.

Important limits before delivery:

- The current package is unsigned.
- It is not Microsoft verified.
- It is not a signed/public/world-ready release.
- It does not include auto-update.
- Windows SmartScreen or endpoint-security warnings may appear.
- Please use a test/non-production machine.
- Please do not disable Windows security globally to run it.

Delivery is manual. After payment is confirmed, I will privately send:

- the package file;
- SHA256 hashes;
- install README;
- buyer note;
- feedback template.

Before installing, please verify the package SHA256 against the provided hashes. Hash verification confirms file custody; it does not make an unsigned file signed or Microsoft verified.

Support contact: [SUPPORT CONTACT]
Support/refund terms: [SUPPORT / REFUND TERMS]
Private delivery channel: [PRIVATE DELIVERY CHANNEL]

After install, please send back:

- whether MSI or NSIS worked better;
- SmartScreen/warning behavior;
- launch success/failure;
- one analysis workflow result;
- Function Notebook/export result if tested;
- the top 3 fixes or confusing parts.

Thanks again. Your feedback directly funds and guides signing, updater proof, release hardening, and product polish.

---
