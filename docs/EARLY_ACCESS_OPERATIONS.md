# HexHawk Early-Access Operations

## Exact HexHawk 1.0.0 candidate boundary (2026-07-14)

This workflow applies only to the two unsigned Windows release-candidate artifacts at `D:/Project/HexHawk/.local/releases/HexHawk-1.0.0-ebbd068-20260714-001856`:

- MSI: `HexHawk_1.0.0_x64_en-US.msi` — SHA-256 `A6A298CCFD39F8C53346D23A1BC7EC7795E3251E34031678735BE9C116E09BDB`
- NSIS: `HexHawk_1.0.0_x64-setup.exe` — SHA-256 `9FCC206AA60774F9CFD43E44994967517F8209B842FF266EE047346B5CE3AD61`

Both artifacts are Authenticode `NotSigned`, with no signer certificate and no trusted timestamp. Neither artifact has passed controlled installation, installed launch, installed project save/reopen, two-binary identity-isolation, restart/cache-clear recovery, report/export provenance, uninstall/reinstall, or user-data-retention acceptance. Do not describe or deliver them as production ready, procurement ready, enterprise ready, signed, updater ready, public-release ready, or fully installer validated. Every result below starts as **not tested** and must be recorded for the exact installer and SHA-256 used.

Status: operating guide for manual paid early access. This is not a release gate, public launch approval, payment processor setup, or deployment instruction.

Authority note: GYRE remains the sole HexHawk verdict/classification authority. NEST is advisory evidence/lifecycle context. AETHERFRAME is advisory operations/process support only. NEXUS/Hermes/AI are assistant/proposal/workflow helpers only and cannot mutate authoritative verdict state.

## Goal

Recruit the first small cohort of paid technical testers, deliver the unsigned package privately after manual payment confirmation, collect installation/workflow feedback, and use that evidence to fund and guide signing, updater, support, and product hardening.

## First testers

Best-fit first testers:

- reverse engineers comfortable with unsigned Windows tools;
- malware analysts or security researchers using a test/non-production machine;
- technical founders or consultants willing to give structured feedback;
- trusted contacts who understand SmartScreen/endpoint-security warnings;
- buyers who accept manual updates and private fulfillment.

Avoid first selling to non-technical consumers, regulated enterprise procurement teams, or anyone expecting Microsoft verification, auto-update, or a broadly trusted public release.

## What testers receive

- Private access to the current unsigned HexHawk early-access package.
- SHA256 hashes and package manifest.
- Install README and buyer note.
- Manual support/contact channel placeholder.
- Request for install/workflow feedback.
- Upgrade-credit/future-path wording only if confirmed in the buyer conversation.

## What testers do not receive

- A signed release.
- A Microsoft-verified application.
- A public/world-ready consumer release.
- An enterprise/procurement-ready package.
- Auto-update.
- Guaranteed detection results.
- A promise that Windows or endpoint security will trust the package automatically.
- A public download link.

## Manual payment flow

1. Buyer requests Founder access through the website/contact channel.
2. Confirm buyer identity, use case, and target test machine.
3. Send unsigned early-access limitations before accepting payment.
4. Confirm support/refund placeholders in plain language.
5. User provides or confirms the real payment/invoice link manually. Do not invent a payment link.
6. Confirm payment manually outside the repo.
7. Record payment confirmation reference in private business records, not in this repo.
8. Only then prepare private package delivery.

## Manual package delivery flow

1. Re-run exact package verification immediately before sending.
2. Confirm the package filename, version/date, size, SHA256, and included manifest/docs.
3. Send package privately through the approved channel.
4. Send `SHA256SUMS.txt`, install README, buyer note, and feedback template.
5. Ask buyer to verify SHA256 before install.
6. Ask buyer not to disable Windows security globally.
7. Record which package and hash were sent to which tester/date in private fulfillment records.

## Support expectations

- Support is manual and best-effort unless a paid support term is separately agreed.
- Support should prioritize install failures, hash verification, crash/error collection, and unclear wording.
- Support should not instruct the tester to weaken system-wide security.
- Support should escalate repeated package trust problems into signing/updater/release-gate work.

## Refund/support placeholders

Before any real payment, replace placeholders with the actual terms the user approves:

- support contact: `[SUPPORT CONTACT]`;
- response window: `[SUPPORT RESPONSE WINDOW]`;
- refund window/conditions: `[REFUND POLICY]`;
- delivery channel: `[PRIVATE DELIVERY CHANNEL]`.

Do not state a guaranteed refund unless those terms are approved and operationally true.

## Feedback expectations

Ask every tester for:

- install warnings or blocks;
- MSI vs NSIS behavior;
- SHA256 verification result;
- launch success/failure;
- analysis workflow tested;
- Function Notebook/export result;
- crash/error notes;
- confusing UI wording;
- top fixes requested;
- whether they would pay again or upgrade.

## Update cadence placeholder

Update cadence is manual and TBD. Suggested placeholder:

`Early-access updates are manual. We will notify testers when a new verified package is ready; no auto-update is included in the unsigned channel.`

## Safety wording

Use these boundaries consistently:

- This is unsigned early access for technical testers only.
- Verify SHA256 before running installers or executables.
- Do not disable Windows security globally.
- Windows SmartScreen or endpoint-security warnings are expected for unsigned software.
- This is not Microsoft verified.
- This is not public/world-ready.
- No auto-update is included.
- Payment/private delivery is not signed release readiness.
