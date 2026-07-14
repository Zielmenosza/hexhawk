# HexHawk Pilot Support and Intake

## Exact HexHawk 1.0.0 candidate boundary (2026-07-14)

This workflow applies only to the two unsigned Windows release-candidate artifacts at `D:/Project/HexHawk/.local/releases/HexHawk-1.0.0-ebbd068-20260714-001856`:

- MSI: `HexHawk_1.0.0_x64_en-US.msi` — SHA-256 `A6A298CCFD39F8C53346D23A1BC7EC7795E3251E34031678735BE9C116E09BDB`
- NSIS: `HexHawk_1.0.0_x64-setup.exe` — SHA-256 `9FCC206AA60774F9CFD43E44994967517F8209B842FF266EE047346B5CE3AD61`

Both artifacts are Authenticode `NotSigned`, with no signer certificate and no trusted timestamp. Neither artifact has passed controlled installation, installed launch, installed project save/reopen, two-binary identity-isolation, restart/cache-clear recovery, report/export provenance, uninstall/reinstall, or user-data-retention acceptance. Do not describe or deliver them as production ready, procurement ready, enterprise ready, signed, updater ready, public-release ready, or fully installer validated. Every result below starts as **not tested** and must be recorded for the exact installer and SHA-256 used.

Original document date: 2026-05-31

Audience: controlled pilot sponsors, board members, internal support operators

## Pilot intake scope

HexHawk may be offered only as a controlled evaluation with named users, named sponsor, bounded test corpus, and explicit acknowledgement that current Windows artifacts are unsigned until the signing gate is complete.

## Required intake fields

- Sponsor organization and point of contact
- Pilot owner at HexHawk
- Authorized testers and email addresses
- Windows version and WebView2 state
- Test corpus class: benignware, internal tools, malware zoo, CTF/keygenme, or proprietary samples
- Data handling requirements
- Whether unsigned internal build is acceptable
- Whether updater is disabled or signed updater artifacts are required
- Export/report requirements
- Expected pilot duration
- Escalation contact

## Support lanes

| Lane | Scope | Target handling |
|---|---|---|
| Installation | MSI/NSIS install, WebView2 bootstrapper, Windows Defender/SmartScreen friction | Same business day for controlled pilots |
| Analysis correctness | GYRE classification questions, evidence review, false positives/false negatives | Collect binary hash, export JSON, screenshots, exact workflow |
| Export/evidence | Report JSON, NEST evidence bundle, authority lineage | Confirm `source_engine: gyre` and `gyre_is_sole_verdict_source: true` |
| Licensing | Test key entry, tier display, activation behavior | Never paste keys into tickets unless secure channel exists |
| Security/procurement | Signing, updater, data handling, trust doctrine | Route to release owner and CISO-facing review |

## Required bug report bundle

- HexHawk version
- Installer used: MSI or NSIS
- Artifact SHA-256
- Signing state observed by tester
- Windows version
- Whether app shows native runtime or browser/dev mode
- Binary path or sample hash
- Exported report JSON when available
- Reproduction steps
- Expected result
- Actual result

## Authority doctrine for support

Support must not describe NEST, AETHERFRAME/Forge, NEXUS, TALON, or any assistant layer as verdict authority. GYRE is the sole verdict source. NEST may orchestrate evidence and convergence. AETHERFRAME/Forge may supply bounded lineage/uplift metadata. NEXUS may explain or assist but does not classify.
