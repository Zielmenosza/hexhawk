# AetherFrame Next Prompt Protocol Run — 20260703-183546

## Why this protocol was added

Hermes/AetherFrame runs already ended with evidence and recommended next actions, but they did not have a formal, review-gated way to draft the next logical prompt. This protocol adds a safe handoff pattern so major runs can preserve momentum without creating an autonomous loop.

The `NEXT PROMPT CANDIDATE` is inert text only. It requires human review, edit, rejection, or later use by the user.

## Current repo state at start

- Branch: `main`.
- Starting HEAD: `b9b377a577d189350853e048ee6bf7d10b04781a`.
- `origin/main`: `b9b377a577d189350853e048ee6bf7d10b04781a`.
- Tag at starting HEAD: `v2.1.22-paid-early-access-operations`.
- Latest CI on `main`: success, run `28625778006`, head SHA `b9b377a577d189350853e048ee6bf7d10b04781a`.
- Registered worktrees: only `D:/Project/HexHawk`.
- Existing untracked validation/report files under `docs/aetherframe-runs/` were observed and left untouched.

Observed untracked reports at start:

- `docs/aetherframe-runs/factory-cycle-20260701-195521.md`
- `docs/aetherframe-runs/factory-cycle-20260701-201811.md`
- `docs/aetherframe-runs/factory-cycle-20260701-204011.md`
- `docs/aetherframe-runs/factory-cycle-20260702-002155.md`
- `docs/aetherframe-runs/factory-cycle-20260702-181939.md`
- `docs/aetherframe-runs/factory-cycle-20260702-183305.md`
- `docs/aetherframe-runs/factory-cycle-20260702-183337.md`
- `docs/aetherframe-runs/factory-cycle-20260702-185844.md`
- `docs/aetherframe-runs/factory-cycle-20260702-191430.md`
- `docs/aetherframe-runs/factory-cycle-20260702-232237.md`
- `docs/aetherframe-runs/factory-cycle-20260703-003216.md`
- `docs/aetherframe-runs/factory-cycle-20260703-182631.md`
- `docs/aetherframe-runs/worktree-custody-20260701-201449.md`

## Files created/updated

Created:

- `docs/AETHERFRAME_NEXT_PROMPT_PROTOCOL.md`
- `docs/examples/NEXT_PROMPT_CANDIDATE_PAID_EARLY_ACCESS_PAYMENT_CTA.md`
- `docs/aetherframe-runs/next-prompt-protocol-20260703-183546.md`

Updated:

- `docs/AETHERFRAME_ADVANCEMENT_RUNBOOK.md`
- `docs/AETHERFRAME_PROJECT_TEMPLATE.md`
- `docs/AETHERFRAME_ADVANCEMENT_MODEL.md`
- `scripts/aetherframe_factory_cycle.py`

## Reporter behavior

The reporter was changed narrowly and safely. It now adds a non-destructive `NEXT PROMPT CANDIDATE GUIDANCE` section to reports/stdout. The guidance is only text. It does not generate a full dynamic prompt, run Hermes, recurse, deploy, delete, publish, sign, upload, use credentials, or deliver packages.

## How this avoids autonomous loops

- The protocol states that generated prompts are inert text only.
- Human review remains the boundary between cycles.
- The reporter only reminds Hermes what to include; it does not execute or schedule anything.
- Readiness flags make missing approvals explicit.
- Stop conditions require stopping before approval-gated actions.

## How this helps Hermes continue work safely

The protocol gives future runs a consistent handoff shape:

1. report evidence;
2. recommend the next action;
3. draft a reviewable next prompt when safe;
4. mark required inputs and approvals;
5. stop.

This preserves momentum while keeping deployment, deletion, payment, credentials, package delivery, and release operations gated by the user.

## Likely next user-reviewed prompt

The next actual user-reviewed prompt should likely be:

`Verify CI and wire paid early-access payment CTA only if a real public payment/invoice URL is supplied.`

It should require these placeholders to be replaced before website changes:

- `<PASTE_REAL_PUBLIC_PAYMENT_OR_INVOICE_URL_HERE>`
- `<APPROVED_SUPPORT_REFUND_TERMS_HERE>`
- `<APPROVED_PRIVATE_DELIVERY_METHOD_HERE>`

It should stop if the URL or approvals are missing, and it should not deploy without explicit deploy approval.

## Authority boundaries

- GYRE remains the sole HexHawk verdict/classification authority.
- AETHERFRAME remains advisory advancement/process support only.
- Hermes/AI remains an assistant/proposal/workflow helper only.
