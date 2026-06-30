# AetherFrame Advancement Factory

Date: 2026-06-30
Status: Active

---

## What the factory is

A disciplined engineering workflow where Hermes plans and executes bounded improvement cycles
against HexHawk, with AetherFrame recording reusable patterns, evaluation rubrics, mistakes,
and lessons.

The factory produces:
- One improvement slice per cycle (code fix, test addition, doc update, CI repair)
- Evidence: test output, build logs, CI result, diff
- A go/no-go report before any tag or promotion
- A lessons entry for each non-trivial cycle

---

## What the factory is NOT

- Not an autonomous self-improvement loop
- Not an AI that rewrites itself without human review
- Not a replacement for human go/no-go decisions
- Not a shortcut around validation gates
- Not a vehicle for bypassing authority boundaries
- Not a release pipeline (tagging and signing require explicit approval)

---

## Authority Boundaries

These are fixed. No cycle may change them.

| Role | Authority |
|------|-----------|
| GYRE | Sole verdict/classification authority |
| NEST | Evidence orchestration and convergence only |
| TALON | Decompiler/pseudocode advisory reconstruction only |
| STRIKE | Debugger/runtime evidence only |
| Function Intelligence | Advisory evidence notebook only |
| AETHERFRAME | Advancement/refinement/factory orchestration only |
| NEXUS / Hermes | Assistant/proposal/workflow helper only |

---

## Forbidden in all factory cycles

- No autonomous public release
- No automatic deployment to any public endpoint
- No credential use unless explicitly approved for that cycle
- No website deployment unless explicitly approved
- No release-candidate tag unless a full gate passes
- No claiming signed/public release unless Authenticode proves it
- No malware detonation, exploit proof, ransomware unlocking, shell access
- No AI-modified GYRE verdicts
- No "self-improvement" claims beyond repository-level workflow/tooling improvements

---

## Factory Roles

**Hermes** — Lead engineer / factory foreman
- Plans each cycle
- Executes changes
- Runs validation
- Writes the cycle report
- Records lessons
- Decides: continue / revert / promote / stop

**AetherFrame** — Factory process recorder
- Records reusable improvement patterns
- Records evaluation rubrics and scoring
- Records mistakes and lessons
- Scores candidates (advisory only, never verdict)
- May advise, compare, summarize, score, package, and recommend
- Must not become a verdict authority

**HexHawk** — The product being manufactured
- Receives bounded, reviewable improvements
- Each improvement slice validated before acceptance
- Release posture changes require explicit evidence gates

**Factory machines** — Existing tools used as inspection instruments
- Rust tests: cargo test --workspace
- Clippy: cargo clippy --workspace
- TypeScript noEmit: tsc --noEmit
- Vitest: vitest run
- Tauri build: yarn tauri:build
- Installer smoke: scripts/release/
- CDP probe: scripts/run_ai_workflow_cdp_probe.py
- Function Notebook export proof: scripts/
- Release-candidate gate scripts: scripts/release/

---

## Allowed Inputs per Cycle

- Repo evidence (git status, diff, log, existing code)
- Local validation output (test results, build logs, compiler errors)
- Official documentation from primary sources (docs.rs, MDN, MSDN, GitHub Actions docs)
- Competitor/public research for positioning and design inspiration only
- GitHub Actions CI logs via gh CLI

---

## Allowed Outputs per Cycle

- Source code changes narrowly scoped to the chosen improvement target
- Test additions or fixes for the changed code
- Docs updates when behavior or authority boundaries change
- A timestamped factory-cycle report under docs/aetherframe-runs/
- A lessons entry if the cycle produced a non-trivial finding
- A commit (reviewed, narrowly staged)
- An annotated tag (advisory/milestone only, not release-candidate)

---

## Release Gates (unchanged from prior doctrine)

A release-candidate tag requires ALL of the following:
1. CI is green on main
2. Authenticode signing is proven (not just referenced in config)
3. Installer smoke passes (MSI + NSIS, GUI visible, CLI works)
4. Native GUI export parity proven through CDP
5. Updater metadata hosted and reachable with correct hashes
6. No secrets or excluded paths in the staged index
7. GYRE/NEST authority boundary language clean in docs and GUI

---

## How Hermes uses web research

Web research is an input machine, not a verdict machine.

Rules:
- Repo evidence comes first — inspect actual files before searching the web
- Use official primary sources (docs.rs, language reference, GitHub Actions docs) for API details
- Use competitor/public research for positioning or design inspiration only
- Never trust a web claim without verifying it against actual repo state
- Never report a web finding as "current repo truth" — label it "external source, unverified"
- Web research cannot override what a test, build, or compiler actually produced

---

## How Lessons Become Process Improvements

1. After each factory cycle, Hermes records what was learned in docs/AETHERFRAME_FACTORY_LESSONS.md
2. If the lesson affects a reusable pattern, Hermes updates the relevant skill reference
3. If the lesson reveals a gap in validation, Hermes adds or repairs the relevant test/script
4. If the lesson reveals a CI configuration mistake, Hermes files a factory cycle targeting that CI item
5. AetherFrame scores the lesson for reuse value — high-reuse lessons are promoted to the runbook
6. Lessons that prevent repeated mistakes are marked [PREVENTION] in the lessons file
7. No lesson may override an authority boundary — lessons are engineering process notes only

---

## Factory Cycle Cadence

- Cycles are unbounded in number but each is bounded in scope
- One improvement target per cycle (never two)
- A cycle ends in evidence, tests, and a go/no-go report — always
- If a cycle produces no passing tests, it is not promoted
- If CI is red, the first factory target must be CI stabilization — no new features until CI is green
