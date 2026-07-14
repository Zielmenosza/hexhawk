# AetherFrame Commercial Operations Lane

> **Historical operations snapshot with current boundary (2026-07-14).** The current HexHawk package is an unsigned Windows 1.0.0 release candidate awaiting controlled installation acceptance, not production, procurement, enterprise, updater, or public-release readiness. The Bridge/AetherFrame process supports continuity and bounded operations only; it is not an analysis engine or verdict source. See [`CURRENT_STATUS.md`](CURRENT_STATUS.md).

Status: advisory lane for paid early-access operations. This document does not create payment links, use credentials, deploy, publish, deliver packages, or approve release readiness.

## Purpose

Keep AetherFrame pointed at practical commercial progress while preserving HexHawk safety and trust boundaries. The lane tracks payment, support/refund terms, delivery, tester recruitment, feedback, and package custody as explicit gates.

## Authority boundaries

- GYRE remains the sole verdict/classification authority.
- AETHERFRAME remains advisory advancement/process support only.
- Hermes/AI remains an assistant/proposal/workflow helper only.
- User approval is required for payment links, deployment, package delivery, public claims, and release movement.

## Commercial readiness checklist

| Area | Current state | Gate before action |
| --- | --- | --- |
| Payment link/invoice | Missing from repo-approved inputs | User supplies real public payment/invoice URL |
| Support/refund terms | Placeholder/manual | User approves exact wording |
| Private delivery method | Placeholder/manual | User approves channel and custody process |
| Website payment CTA | Not wired to real payment URL by this lane | User supplies URL and approves website edit |
| Deployment | Not approved by this lane | Explicit deploy approval |
| Package delivery | Private only, unsigned | Re-verify exact package immediately before each delivery |
| Tester recruitment | Ready for manual outreach | Use technical-tester qualification criteria |
| Feedback capture | Template exists | Request install result and first workflow feedback |

## First tester profile

Good first testers are technical users who:

- understand unsigned Windows early-access warnings;
- can test on a non-production machine;
- can verify SHA256 hashes or follow a verification guide;
- can report install/launch/workflow results clearly;
- are comfortable with manual support and private delivery;
- will not treat the build as public/world-ready, signed, or Microsoft verified.

Avoid testers who need:

- Microsoft-verified installers;
- enterprise procurement paperwork immediately;
- auto-update;
- public binary download links;
- production-machine guarantees;
- guaranteed detection or guaranteed refund terms that have not been approved.

## Manual commercial flow

1. Qualify tester fit.
2. Confirm buyer identity/contact.
3. Confirm they accept unsigned early-access limits.
4. Confirm payment manually after the user supplies an approved payment/invoice mechanism.
5. Re-verify the exact package and hashes immediately before delivery.
6. Deliver package privately using the approved method.
7. Send SHA256SUMS, install README, and buyer note.
8. Record package version/hash/date/contact in private fulfillment records, not in this repo.
9. Request install result and first feedback.
10. Log issues without promising signed/public release dates.

## Metrics to track outside this repo when buyers exist

- Prospects contacted.
- Qualified technical testers.
- Payments confirmed.
- Packages delivered privately.
- Install successes/failures.
- First feedback received.
- Top blockers.
- Would-pay-again/upgrade responses.

Do not store buyer PII, payment details, private delivery links, or secrets in this repo.

## Stop conditions

Stop before:

- creating a real payment link without user-supplied/approved payment mechanism;
- website deployment without explicit deploy approval;
- package delivery without fresh verification and approved private channel;
- public release claims without signed release gates;
- any credentials or secret handling.
