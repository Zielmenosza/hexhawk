# HexHawk Early-Access Tester Acquisition

## Exact HexHawk 1.0.0 candidate boundary (2026-07-14)

This workflow applies only to the two unsigned Windows release-candidate artifacts at `D:/Project/HexHawk/.local/releases/HexHawk-1.0.0-ebbd068-20260714-001856`:

- MSI: `HexHawk_1.0.0_x64_en-US.msi` — SHA-256 `A6A298CCFD39F8C53346D23A1BC7EC7795E3251E34031678735BE9C116E09BDB`
- NSIS: `HexHawk_1.0.0_x64-setup.exe` — SHA-256 `9FCC206AA60774F9CFD43E44994967517F8209B842FF266EE047346B5CE3AD61`

Both artifacts are Authenticode `NotSigned`, with no signer certificate and no trusted timestamp. Neither artifact has passed controlled installation, installed launch, installed project save/reopen, two-binary identity-isolation, restart/cache-clear recovery, report/export provenance, uninstall/reinstall, or user-data-retention acceptance. Do not describe or deliver them as production ready, procurement ready, enterprise ready, signed, updater ready, public-release ready, or fully installer validated. Every result below starts as **not tested** and must be recorded for the exact installer and SHA-256 used.

Status: practical outreach/qualification plan. This document does not create payment links, deploy website changes, publish packages, deliver ZIPs, or approve release readiness.

## Goal

Recruit the first 3-5 technical testers for paid early access while keeping payment, delivery, and package handling manual and approval-gated.

## Target tester

Prioritize people who can evaluate HexHawk as a technical early-access build:

- reverse engineering, malware-analysis, security tooling, or binary-analysis users;
- comfortable with unsigned Windows software warnings;
- able to test on a non-production machine;
- willing to verify SHA256 hashes;
- willing to send install result, first workflow feedback, and top fixes requested.

## Qualification questions

1. What binary-analysis or security workflow would you test first?
2. Are you comfortable testing an unsigned early-access Windows build?
3. Can you test on a non-production machine?
4. Can you verify SHA256 hashes before installing?
5. Are you willing to report install result, launch result, workflow tested, and top 3 fixes?
6. Do you understand this is not Microsoft verified, not signed/public-ready, and has no auto-update?

## Outreach draft

Hi <name>,

I am opening a small paid technical-tester round for HexHawk, a local-first binary-analysis workbench focused on reviewable evidence and practical analysis workflows.

This is unsigned early access for technical testers only. It is not Microsoft verified, not a signed/public-ready release, and does not auto-update. Testers should use a non-production machine, verify SHA256 hashes, and expect manual private delivery/support.

The goal is to get honest install/workflow feedback from 3-5 people before expanding access. If you are interested, I can send the current limits, price, and tester checklist before any payment.

Useful first feedback would be:

- install and launch result;
- SmartScreen/warning behavior;
- SHA256 verification result;
- first analysis workflow tested;
- Function Notebook/export feedback;
- top 3 fixes or confusing areas.

Would you be a fit for a technical early-access test?

## Response handling

If interested:

1. Send limits/expectations first.
2. Confirm non-production machine.
3. Confirm unsigned early-access acceptance.
4. Confirm payment only through the user-approved payment/invoice mechanism.
5. Do not send packages until payment is manually confirmed and package verification is rerun.

If not a fit:

- thank them;
- optionally ask what blocker prevented participation;
- do not pressure or overclaim readiness.

## Stop conditions

Stop before:

- creating payment links or accounts;
- using credentials;
- deploying website changes;
- delivering package files;
- exposing ZIPs publicly;
- promising signed release, Microsoft verification, public/world-ready status, auto-update, guaranteed refund, or guaranteed detection.
