# AetherFrame Advancement Factory — Runbook

Date: 2026-06-30
Status: Active

---

## One Factory Cycle, Step by Step

---

### Step 1 — Select one improvement target

Choose from current blockers only. Do not invent new features.

Priority order:
1. CI failures blocking main (no new work until main CI is green)
2. Release gate gaps (signing, installer smoke, CDP proof, updater)
3. Authority boundary drift in docs, GUI, or exports
4. Product capability gaps with existing test coverage
5. Test coverage gaps for existing shipped code

Record the target before starting. If you cannot state the target in one sentence, narrow it.

---

### Step 2 — Research

Research order is mandatory. Do not skip steps.

1. **Repo evidence first**
   - `git status`, `git log`, `git diff`
   - Read the exact files that will change
   - Read existing tests that cover this area
   - Check CI logs if the failure is CI-related: `gh run view <id> --log-failed`

2. **Official docs / primary sources** (when needed)
   - docs.rs for Rust crate API changes
   - GitHub Actions documentation for CI workflow issues
   - Tauri docs for build/configuration issues
   - MDN / TypeScript docs for TS/JS issues

3. **Competitor / public research** (only for positioning or design decisions, not fixes)

Label every external reference explicitly. Do not treat web findings as repo truth.

---

### Step 3 — Design a narrow change

Define before writing code:
- Exact files to change (no more than needed)
- Exact lines or functions affected
- What will be different after the change
- What test will prove it works
- What could go wrong
- What is explicitly out of scope for this cycle

If the design touches more than 3-4 files, consider splitting into two cycles.

---

### Step 4 — Implement one slice

Rules:
- Change only what the design says
- Do not "improve" adjacent code unless it is blocking the primary change
- Do not refactor while fixing — separate cycles
- Preserve authority boundary language in comments and docs
- If a change touches GYRE/NEST/AETHERFRAME boundary code, re-read ENGINE_BOUNDARY_DOCTRINE.md first

---

### Step 5 — Validate with relevant tests

Minimum validation for each cycle type:

| Cycle type | Minimum validation |
|---|---|
| Rust code change | cargo test --workspace (or targeted crate test) |
| TypeScript code change | tsc --noEmit + vitest run (app directory) |
| CI config change | git diff --check, review workflow YAML manually |
| Docs change | git diff --check, scan for authority-boundary drift |
| Script change | python -m py_compile + dry run |

Do not claim a cycle passed if only one layer was checked.
Report exactly what passed, what was skipped, and what remains unknown.

---

### Step 6 — Run broader gate if needed

If the change touches a release gate area (signing, installer, CI, publish), run the relevant gate:

- `cargo clippy --workspace -- -D warnings`
- `yarn workspace hexhawk-ui exec tsc --noEmit`
- `yarn workspace hexhawk-ui exec vitest run`
- `python -m py_compile scripts/aetherframe_factory_cycle.py`
- `git diff --check`

Stop if a gate fails. Record the failure as a blocker for the next cycle.

---

### Step 7 — Record evidence

Before committing, record:
- Commands run
- Exact output (pass or fail, not paraphrase)
- Artifacts produced (hashes if release-relevant)
- What was NOT validated in this cycle

Write the evidence to docs/aetherframe-runs/factory-cycle-YYYYMMDD-HHMMSS.md.

---

### Step 8 — Record lessons

If this cycle produced a finding that would change how future cycles work:
- Add it to docs/AETHERFRAME_FACTORY_LESSONS.md
- Tag it [PREVENTION] if it prevents a class of repeated mistakes
- Tag it [CI] if it affects CI configuration
- Tag it [BOUNDARY] if it affects authority boundary handling
- Tag it [VALIDATION] if it affects what to test or how

Keep lessons brief. One lesson = one actionable conclusion.

---

### Step 9 — Decide

After evidence is recorded, make exactly one decision:

| Decision | Condition |
|---|---|
| **Continue** — commit and push, select next target | Evidence passes, no blockers |
| **Revert** — undo changes, record lesson | Evidence fails or introduces new failures |
| **Promote to release gate** | CI is green, all release gates pass |
| **Stop** — leave a known-state note | Blocker found that requires user decision |

Do not continue past a failing gate. Do not revert without recording the reason.

---

## Commit Style

One commit per logical change. Do not bundle CI fix with product feature.

```
[FIX] Repair Yarn workspace protocol in CI (Yarn 4 corepack)
[FIX] Fix ptrace::write type in Rust Linux debugger
[DOCS] Define AetherFrame advancement factory
[TOOLS] Add AetherFrame factory cycle reporter
[LESSONS] Record CI stabilization lessons
```

---

## Tags

Advisory/milestone tags:
```
v2.1.6-aetherframe-factory-docs
v2.1.7-aetherframe-factory-cycle-reporter
```

Release-candidate tags: NEVER from a factory cycle. Require full release gate first.

---

## Example: CI Stabilization Cycle

**Target:** CI is red on main due to Yarn workspace protocol failure and Rust ptrace::write type mismatch.

**Research:**
- gh run view 28400567992 --log-failed
- Finding 1: TypeScript jobs fail at "yarn install --frozen-lockfile" — Yarn 4 workspace:* protocol not recognized because CI runner uses system yarn 1; fix is to add corepack enable step before yarn install.
- Finding 2: Rust test-rust job fails to compile hexhawk-backend — ptrace::write in nix 0.29 expects c_long as third arg, not *mut _; fix is to cast to c_long.

**Design:**
- ci.yml: add corepack enable before yarn install in TS jobs
- src-tauri/src/commands/debugger.rs: cast patched/restored to libc::c_long in ptrace::write calls (Linux-only cfg)
- No product logic changes, no new features

**Validate:** local cargo check (Windows, Rust part skipped — Linux-only), diff review

**Evidence:** CI push, watch run, record result

**Lesson:** CI Yarn version must be pinned with corepack; workspace:* requires Yarn 2+
