# HexHawk Early-Access Tester Feedback Template

## Exact HexHawk 1.0.0 candidate boundary (2026-07-14)

This workflow applies only to the two unsigned Windows release-candidate artifacts at `D:/Project/HexHawk/.local/releases/HexHawk-1.0.0-ebbd068-20260714-001856`:

- MSI: `HexHawk_1.0.0_x64_en-US.msi` — SHA-256 `A6A298CCFD39F8C53346D23A1BC7EC7795E3251E34031678735BE9C116E09BDB`
- NSIS: `HexHawk_1.0.0_x64-setup.exe` — SHA-256 `9FCC206AA60774F9CFD43E44994967517F8209B842FF266EE047346B5CE3AD61`

Both artifacts are Authenticode `NotSigned`, with no signer certificate and no trusted timestamp. Neither artifact has passed controlled installation, installed launch, installed project save/reopen, two-binary identity-isolation, restart/cache-clear recovery, report/export provenance, uninstall/reinstall, or user-data-retention acceptance. Do not describe or deliver them as production ready, procurement ready, enterprise ready, signed, updater ready, public-release ready, or fully installer validated. Every result below starts as **not tested** and must be recorded for the exact installer and SHA-256 used.

## Tester

- Tester name/company:
- Contact:
- Permission to quote testimonial: yes/no

## Exact artifact and environment

- Installer used (MSI or NSIS; exact filename):
- Exact installer SHA-256:
- SHA-256 matches the candidate value above: not tested / yes / no
- Windows version/build:
- Machine type (physical / VM):
- CPU/RAM notes:
- Endpoint security or EDR present:
- Test/non-production machine confirmed: not tested / yes / no
- Security warning observed (SmartScreen, unknown publisher, endpoint control, or none): not tested / details
- Did tester avoid disabling Windows security globally: not tested / yes / no

## Installed-artifact acceptance results

Do not pre-mark any result as passed. Use `not tested`, `pass`, `fail`, or `blocked`, and attach evidence for any claimed pass.

- Installation result:
- Installed application launch result:
- Project save/reopen result:
- Two-binary identity-isolation result:
- Restart/cache-clear recovery result:
- Report/export recorded-snapshot provenance result:
- Uninstall result:
- Reinstall result:
- User-data retention result:
- Analysis workflow and sample/input type used:
- Crash/error notes:

## UX and value

- UX confusion:
- Missing docs:
- Top 3 fixes requested:
  1.
  2.
  3.
- Would they pay again/upgrade: yes/no/unsure
- What would make the signed public release worth buying:

## Follow-up

- Issues logged:
- Support follow-up needed:
- Next contact date:
