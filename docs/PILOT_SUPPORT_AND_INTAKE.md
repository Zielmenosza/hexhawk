# HexHawk Pilot Support and Intake

Date: 2026-05-31
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
