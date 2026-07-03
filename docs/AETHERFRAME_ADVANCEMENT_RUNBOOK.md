# AetherFrame Advancement Runbook

Status: preferred runbook replacing temporary Factory framing

Every AetherFrame Advancement Cycle follows the same outer shape:

1. intake;
2. boundaries;
3. research/evidence gathering;
4. implementation;
5. validation;
6. evidence report;
7. lesson capture;
8. next prompt candidate handoff when safe;
9. stop condition.

AetherFrame does not deploy, delete, publish, sign, charge money, use credentials, or claim release readiness without explicit human approval and a separate gate.

## AetherFrame Advancement Cycle

### Intake
Define the artifact and one improvement target.

### Boundaries
List protected truths, authority boundaries, forbidden actions, and approval gates.

### Research
Inspect repository state first. Use web/official docs only when needed and label them.

### Implementation
Make the smallest safe change.

### Validation
Run the narrowest relevant checks plus `git diff --check`.

### Evidence
Record commands, outputs, artifacts, blockers, proof limits, and changed files.

### Lessons
Capture durable lessons in `docs/AETHERFRAME_LESSONS.md`.

### Stop condition
Stop after validation/reporting, or earlier if a blocker or approval gate is reached.

## Next Prompt Candidate Handoff

Major AetherFrame Advancement Cycles should end with a review-gated `NEXT PROMPT CANDIDATE` when a safe next prompt can be drafted. The candidate is inert text only. It must not be executed by the cycle that generated it, scheduled automatically, or used to assume user approval.

Generate the handoff after major release/package, website/payment, cleanup/provenance, CI/fix, or AetherFrame advancement cycles. Do not force it after a preflight failure, a narrow verification-only task, a run where the safest next step is simply waiting for user input, or any case where drafting the prompt would encourage deletion, deployment, payment, package delivery, release, or credential use without approval.

To decide the next step:

- use current repo evidence first: `git status`, `git rev-parse`, tags, worktrees, changed files, and CI state;
- cite the completed run's concrete evidence: commits, tags, reports, validation commands, package hashes, routes, or blockers;
- choose one bounded next mission, not a multi-run program;
- mark every missing user input as a placeholder or explicit blocker;
- put approval-gated actions behind stop conditions.

Every candidate should include the section name and fields defined in `docs/AETHERFRAME_NEXT_PROMPT_PROTOCOL.md`, especially readiness flags:

- Safe to run as-is: yes/no
- Requires user edits first: yes/no
- Requires external information first: yes/no
- Requires destructive approval: yes/no
- Requires deployment approval: yes/no
- Requires payment/credential input: yes/no
- Requires package/release approval: yes/no

Automation-loop prevention:

- never tell Hermes to execute the generated prompt automatically;
- never call Hermes recursively or schedule the prompt from the reporter;
- keep human review as the boundary between cycles;
- if approvals or inputs are missing, make that visible in the readiness flags and stop.

Safe stop pattern:

1. Final report.
2. Recommended next action.
3. `NEXT PROMPT CANDIDATE`, if safe to draft.
4. Readiness flags.
5. Stop.

## CI Stabilization Cycle

Allowed actions:
- inspect current GitHub Actions logs;
- reproduce locally if practical;
- edit CI/test code narrowly;
- run targeted tests and watch rerun.

Forbidden actions:
- unrelated product features;
- hiding failures by deleting meaningful tests;
- broad workflow rewrites without evidence.

Validation gates:
- local targeted reproducer when practical;
- `git diff --check`;
- final GitHub Actions result.

Evidence requirements:
- failing run/job/step;
- root cause;
- command output;
- rerun URL and result.

Stop condition:
- CI green, or current blocker recorded for next cycle.

## Release Trust Cycle

Allowed actions:
- update release gates/docs/scripts;
- hash artifacts;
- check Authenticode;
- run smoke/export proofs.

Forbidden actions:
- signed/public claims without exact proof;
- release-candidate tags without full gate;
- publishing/uploading packages without explicit approval.

Validation gates:
- CI green;
- exact artifact path/hash/signing status;
- installer smoke;
- Function Notebook/export proof where claimed;
- updater proof if auto-update is claimed.

Evidence requirements:
- commit/tag/artifact paths;
- SHA256 and Authenticode output;
- smoke/probe result files;
- release blocker list.

Stop condition:
- go/no-go classification with no unsafe escalation.

## Unsigned Early Access Cycle

Allowed actions:
- create local package path;
- write policy/install/buyer docs;
- generate hashes/manifests;
- present private/manual buyer flow.

Forbidden actions:
- claim signed, Microsoft verified, public/world-ready, auto-updating, or production-ready;
- instruct users to disable security globally;
- publish/upload/deploy packages without approval.

Validation gates:
- CI green;
- `NotSigned` recorded when unsigned channel requires it;
- package docs included;
- overclaim scan.

Evidence requirements:
- package name, paths, hashes, manifest, and limitations.

Stop condition:
- “path defined” or “local package created; not published.”

## Website/Commercial Cycle

Allowed actions:
- update static copy;
- add pricing research memo;
- prepare manual buyer flow;
- validate routes/claims locally.

Forbidden actions:
- deploy without approval;
- public checkout or download without approval;
- signing/public-ready claims without gates.

Validation gates:
- route/link scan;
- unsafe-claim scan;
- source research notes;
- live verification only when deployment is approved.

Evidence requirements:
- files changed;
- research sources;
- route markers;
- deployment exclusions if deployed.

Stop condition:
- site payload ready, or deployment completed only if approved.

## Evidence Export Cycle

Allowed actions:
- inspect/export reports;
- repair authority metadata;
- validate typed evidence only when generated by the correct path.

Forbidden actions:
- fabricating NEST evidence bundles;
- letting AetherFrame/AI mutate GYRE classification;
- claiming native proof from browser-only simulation.

Validation gates:
- parse exported JSON/Markdown;
- assert authority fields;
- compare exact runtime/probe evidence.

Evidence requirements:
- export path;
- authority fields;
- proof-limit statement.

Stop condition:
- export passes, or missing typed proof is recorded as a blocker.

## Cleanup/Provenance Cycle

Allowed actions:
- inventory folders;
- compute sizes;
- detect worktrees and evidence files;
- write cleanup manifest and dry-run report.

Forbidden actions:
- deleting, moving, compressing, uploading, or unregistering worktrees without explicit approval;
- touching credentials;
- deleting latest release provenance.

Validation gates:
- dry-run-only script parse;
- dry-run report generation;
- exact paths listed.

Evidence requirements:
- size, mtime, worktree status, dirty state, artifact/evidence examples, recommendation.

Stop condition:
- approval-ready deletion batch or preservation list.

## Cross-Project Advancement Cycle

Allowed actions:
- apply AetherFrame template to another project;
- define boundaries and evidence sources;
- run bounded changes.

Forbidden actions:
- assuming HexHawk authority names apply to other projects;
- skipping project-specific gates;
- using AetherFrame as truth authority.

Validation gates:
- project-specific tests and release/deploy rules.

Evidence requirements:
- project brief, validation output, lessons, and approval-needed next steps.

Stop condition:
- one completed bounded improvement or a blocker report.
