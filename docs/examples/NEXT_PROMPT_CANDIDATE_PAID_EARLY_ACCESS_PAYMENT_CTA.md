# Example NEXT PROMPT CANDIDATE — Paid Early Access Payment CTA

Status: example only. This is inert text. Do not execute it automatically.

## NEXT PROMPT CANDIDATE

Title: Verify CI and wire paid early-access payment CTA only if a real public payment/invoice URL is supplied

Mission:
Verify the current HexHawk CI/repo state and, only if the user supplies a real public payment or invoice URL plus approved support/refund terms and private delivery method, prepare a narrow website CTA update for paid early access. Do not deploy unless explicitly approved.

Current known state:
- Cleanup chapter is closed.
- Paid Early Access Operations is the active focus.
- Latest known operations commit: `b9b377a [DOCS] Prepare paid early access operations`.
- Tag: `v2.1.22-paid-early-access-operations`.
- Early access is unsigned and technical-tester-only.
- Payment and fulfillment are manual.
- Public signed release remains blocked by signing/updater/exact-artifact gates.

Evidence from this run:
- Use the latest `git status`, `git rev-parse HEAD`, `git rev-parse origin/main`, `git tag --points-at HEAD`, `gh run list --branch main --limit 3 --json databaseId,status,conclusion,headSha,url`, and `git worktree list` output from the current run.
- Cite any files changed and validation commands actually run.

Hard rules:
- Do not execute this generated prompt automatically.
- Do not assume user approval.
- If the payment URL is still a placeholder, do not change the website.
- Do not create accounts.
- Do not create payment links.
- Do not use secrets.
- Do not expose the ZIP publicly.
- Do not deploy without approval.
- Do not claim signed release.
- Do not claim Microsoft verified.
- Do not claim public/world-ready.
- Do not enable or claim auto-update.
- Preserve authority boundaries: GYRE is sole verdict/classification authority; AETHERFRAME is advisory advancement/process support only; Hermes/AI is assistant/proposal/workflow helper only.

Required user inputs:
- Payment/invoice URL: `<PASTE_REAL_PUBLIC_PAYMENT_OR_INVOICE_URL_HERE>`
- Approved support/refund terms: `<APPROVED_SUPPORT_REFUND_TERMS_HERE>`
- Approved private delivery method: `<APPROVED_PRIVATE_DELIVERY_METHOD_HERE>`

External approvals required:
- User approval to edit website CTA text.
- User approval before deploy/publish.
- User approval before any package delivery.

Readiness flags:
- Safe to run as-is: no, unless the real public payment/invoice URL, support/refund terms, and private delivery method are supplied.
- Requires user edits first: yes.
- Requires external information first: yes.
- Requires destructive approval: no.
- Requires deployment approval: yes, if website changes are to go live.
- Requires payment/credential input: public payment URL only, no secrets.
- Requires package/release approval: no public package upload; package delivery remains private and approval-gated.

Phases:
1. State check:
   - `git status --short --branch`
   - `git rev-parse HEAD`
   - `git rev-parse origin/main`
   - `git tag --points-at HEAD`
   - `gh run list --branch main --limit 3 --json databaseId,status,conclusion,headSha,url`
   - `git worktree list`
2. Input gate:
   - If any placeholder remains, stop and report missing input.
   - Do not edit website files unless the payment/invoice URL is real and public-safe.
3. Website CTA preparation, only after input gate passes:
   - Update only the narrow approved CTA/copy files.
   - Keep unsigned/tester-only language visible.
   - Keep payment/manual-delivery expectations clear.
4. Validation:
   - `git diff --check`
   - route/link scan or local website validation used by the repo
   - unsafe-claim scan for signed/Microsoft verified/public-ready/world-ready/auto-update overclaims
5. Commit/tag, only if files changed and validation passes:
   - Commit message should be docs/site scoped.
   - Tag only if the user requested a milestone tag.
6. Deployment gate:
   - Stop before deploy unless explicit deploy approval is present in the prompt/session.

Validation:
- `git diff --check`
- Run the repo's website validation command if available.
- Search for unsafe claims and confirm all hits are negative/guardrail wording.

Commit/tag instructions, only if needed:
- Commit only narrow website/docs changes after validation.
- Do not stage release artifacts, package zips, binaries, screenshots, credentials, or unrelated generated reports.

Stop conditions:
- Stop if the payment URL is a placeholder.
- Stop if support/refund terms are not approved.
- Stop if private delivery method is not approved.
- Stop before deploy without explicit approval.
- Stop before public package upload.
- Stop after final report.

Final report requirements:
- Starting HEAD.
- CI state.
- User inputs supplied or missing, without exposing secrets.
- Files changed.
- Validation run.
- Whether deploy was skipped or explicitly approved.
- Guardrail confirmations.
- Recommended next action.
- NEXT PROMPT CANDIDATE if another major run is appropriate.
