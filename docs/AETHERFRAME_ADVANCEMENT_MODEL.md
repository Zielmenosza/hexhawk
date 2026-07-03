# AetherFrame Advancement Model

Status: preferred model
Date: 2026-07-01

## What AetherFrame is

AetherFrame is the long-term advancement system for bounded, evidence-backed improvement. It takes an artifact — code, docs, release process, website copy, validation output, pricing research, or a project plan — and moves it through a controlled improvement cycle.

AetherFrame is reusable beyond HexHawk. HexHawk is the first proving ground, not the owner of the method.

## What AetherFrame is not

AetherFrame is not a magical self-improving AI. It is not a verdict engine. It is not a release authority. It does not deploy, delete, publish, sign, charge money, use credentials, or bypass security without explicit human approval and a separate gate.

AetherFrame may advise, compare, refine, package, validate, report, and recommend. It must not override GYRE or mutate malware verdict authority.

## Advancement cycle

1. **Input artifact** — define the exact artifact: file, folder, report, site page, test failure, release gate, or plan.
2. **Boundary doctrine** — state protected truths, authority boundaries, forbidden actions, and approval gates.
3. **Research/context gathering** — inspect repo evidence first; use official docs/web research only as labeled external context.
4. **Improvement hypothesis** — state one narrow expected improvement and how it will be proven.
5. **Small change** — edit only the minimum safe scope.
6. **Validation** — run targeted tests, syntax checks, CI checks, link scans, package checks, or evidence probes.
7. **Evidence report** — record commands, outputs, artifacts, hashes, blockers, and proof limits.
8. **Lesson capture** — migrate reusable findings into `docs/AETHERFRAME_LESSONS.md`.
9. **Promotion, retry, or stop** — decide whether to commit/promote, retry narrowly, revert, or stop for user approval.
10. **Human approval gates** — require explicit approval for deploy, publish, deletion, signing, charging money, credentials, or release-candidate tags.

Every cycle ends with evidence, lessons when applicable, and a stop condition.

AetherFrame cycles may propose a `NEXT PROMPT CANDIDATE` for the next logical user-reviewed run. The candidate is inert text only. AetherFrame cycles must not execute their own proposed next prompt, schedule it, or treat it as approval. Human review remains the boundary between cycles.

## Protected authority boundaries

- GYRE remains the sole verdict/classification authority.
- NEST remains evidence orchestration/convergence only.
- TALON remains advisory reconstruction only.
- STRIKE remains runtime/debugger evidence only.
- Function Intelligence remains an advisory evidence notebook only.
- AETHERFRAME remains advancement/refinement/orchestration only.
- Hermes/AI/NEXUS remain assistant/proposal/workflow helpers only.

## Evidence use

AetherFrame prioritizes current source and command evidence over memory, old docs, or marketing language. Evidence can include:

- git status, diff, log, tags, CI runs;
- local test output;
- package hashes and Authenticode status;
- installer smoke and GUI/export proof;
- web research from official/primary sources, clearly labeled;
- comparison tables and buyer-facing positioning, clearly separated from release proof.

## Web research rules

- Repo evidence comes first.
- Prefer official/primary documentation.
- Do not use competitor marketing to make public claims.
- Do not treat web findings as current repo truth.
- Record source URLs and retrieval date when research affects pricing, support, or public copy.

## Tests and validation

AetherFrame chooses validation based on the artifact:

- docs: `git diff --check`, overclaim scan, authority-boundary scan;
- Python scripts: syntax check and dry-run;
- PowerShell scripts: parse check and dry-run;
- Rust: focused `cargo test` or workspace checks as scope requires;
- TypeScript/UI: typecheck and Vitest as scope requires;
- release packages: hash, Authenticode, manifest, smoke, exact artifact proof;
- website: local route/link scan, unsafe-claim scan, live verification only when deployment is approved.

## Reusable examples

### Software release hardening

Input: release gate docs and current artifact evidence.
Output: exact blockers, hash/signing status, installer smoke proof, and a go/no-go report.
Stop: before signed/public claims unless the signed exact-artifact gate passes.

### Website positioning

Input: current site pages plus release truth docs.
Output: clearer buyer copy, no signed/public overclaims, pricing/research notes, route validation.
Stop: before deployment unless explicitly approved.

### Pricing research

Input: competitor official pricing pages and HexHawk trust state.
Output: current Founder pricing, planned post-signing tiers, and a research memo.
Stop: before public checkout or automatic package delivery unless approved.

### CI stabilization

Input: failed GitHub Actions logs and local reproducer.
Output: smallest fix, targeted test, CI rerun result, lesson.
Stop: when CI is green or root cause needs user decision.

### Documentation improvement

Input: docs with stale language or missing gates.
Output: current truth, authority boundaries, and validation scans.
Stop: after docs are aligned and checked.

### Binary-analysis workflow refinement

Input: specific HexHawk analysis/export workflow evidence.
Output: bounded UX or evidence improvement without changing verdict authority.
Stop: before claiming malware verdict or exploit proof beyond validated output.

### Report/export validation

Input: exported JSON/Markdown and current runtime/probe evidence.
Output: authority fields, NEST/GYRE consistency, proof-limit report.
Stop: if typed evidence is missing; do not fabricate it.

### Future non-HexHawk project use

Input: another project's goal, boundaries, evidence sources, tests, and release gates.
Output: project-specific AetherFrame advancement report and lessons.
Stop: at that project's human approval gates.
