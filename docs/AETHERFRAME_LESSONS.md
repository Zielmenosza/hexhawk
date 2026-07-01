# AetherFrame Lessons

Status: active AetherFrame-native lessons ledger
Migrated from: docs/AETHERFRAME_FACTORY_LESSONS.md

Each lesson includes why it matters, what to do next time, origin, and whether it is HexHawk-specific or generalizable.

## CI and validation

### Repo state is ground truth
- Why it matters: previous docs and session memory can be stale.
- Next time: inspect actual files, git status, diffs, and command output before reporting.
- Origin: pre-factory repeated pattern.
- Scope: generalizable.

### Red CI blocks public trust
- Why it matters: a failing main branch invalidates release confidence.
- Next time: stabilize CI before new product or release work.
- Origin: Factory Cycle 0001.
- Scope: generalizable.

### CI root causes must come from current logs
- Why it matters: stale failure explanations can misdirect fixes.
- Next time: use `gh run view <run-id> --log-failed` and inspect the exact failing job.
- Origin: Factory Cycle 0001 follow-up.
- Scope: generalizable.

### Yarn 4 workspace projects require Corepack in CI
- Why it matters: system Yarn 1 cannot resolve modern workspace protocols.
- Next time: enable Corepack before Yarn install in CI jobs using Yarn 4 lockfiles.
- Origin: Factory Cycle 0001.
- Scope: generalizable for Yarn Berry workspaces.

### Cross-platform CI exposes hidden compile paths
- Why it matters: OS-specific debugger/build paths can fail outside the developer host.
- Next time: keep Linux, Windows, and macOS jobs in release-facing CI.
- Origin: Factory Cycle 0001.
- Scope: generalizable.

### Smoke probes need hard timeouts and path-verified cleanup
- Why it matters: GUI/CDP probes can hang or kill unrelated processes.
- Next time: add explicit timeouts and kill only processes launched from verified paths.
- Origin: installed GUI and smoke proof cycles.
- Scope: generalizable.

## Release trust

### Unsigned artifacts are not public-ready
- Why it matters: unsigned MSI/NSIS artifacts trigger real Windows trust warnings.
- Next time: require Authenticode proof before signed/public release wording.
- Origin: release truth correction and unsigned early-access cycle.
- Scope: generalizable.

### Green unsigned CI proves buildability, not public release readiness
- Why it matters: CI artifacts still need signing, updater, installer smoke, and exact-artifact proof.
- Next time: separate buildability from release trust in reports and public copy.
- Origin: Factory Cycle 0001.
- Scope: generalizable.

### Updater readiness is a separate gate
- Why it matters: hosted metadata and Tauri signatures can fail independently of installer build.
- Next time: keep updates manual until updater signing and hosted metadata are proven.
- Origin: unsigned early-access cycle.
- Scope: generalizable.

## Unsigned early access

### Unsigned early access is a commercial/testing channel, not a public trust claim
- Why it matters: payment does not create signing or Microsoft verification.
- Next time: label paid unsigned packages as technical-tester/private/manual only.
- Origin: Factory Cycle 0002.
- Scope: generalizable.

### NotSigned artifacts can be packaged only with clear limits and hashes
- Why it matters: testers need exact custody and risk visibility.
- Next time: include SHA256SUMS, EVIDENCE_MANIFEST, package docs, Authenticode status, and exact commit/path references.
- Origin: unsigned package script and gate.
- Scope: generalizable.

### Packaging scripts must not publish, upload, charge, use credentials, sign, or mutate product behavior
- Why it matters: local packaging must not become a hidden release/deploy pipeline.
- Next time: keep package scripts local-only and evidence-producing.
- Origin: `scripts/release/build_unsigned_early_access_package.ps1`.
- Scope: generalizable.

## Website/payment positioning

### Private payment must not be confused with public release readiness
- Why it matters: a checkout or invoice can imply trust that has not been proven.
- Next time: explain what buyers are buying and what they are not buying.
- Origin: buyer note and website pricing refresh.
- Scope: generalizable.

### Pricing needs current public research plus release-trust humility
- Why it matters: HexHawk should not price or speak like mature signed tools while unsigned.
- Next time: cite official price anchors and mark planned tiers as after-signing targets.
- Origin: `docs/WEBSITE_PRICING_RESEARCH_2026-07-01.md`.
- Scope: generalizable.

## GUI/probe automation

### Installed artifact proof is different from source tests
- Why it matters: source tests cannot prove packaged WebView2/install behavior.
- Next time: require installer smoke and native GUI/export proof for release gates.
- Origin: release-hardening and Function Notebook proof cycles.
- Scope: generalizable.

### GUI probes must not wait forever on live desktop apps
- Why it matters: app windows and background processes can outlive the probe.
- Next time: use hard timeouts and verify cleanup by path, PID, and launch ownership.
- Origin: installer smoke window proof pattern.
- Scope: generalizable.

## Authority boundaries

### AetherFrame stays advisory
- Why it matters: product trust depends on preserving GYRE/NEST authority.
- Next time: scan docs, UI, and exports for any AetherFrame/AI verdict implication.
- Origin: ENGINE_BOUNDARY_DOCTRINE.md and Factory doctrine.
- Scope: HexHawk-specific wording; generalizable principle.

### Function Intelligence exports must preserve GYRE authority fields
- Why it matters: advisory notebooks must not mutate classification truth.
- Next time: validate `source_engine`, `gyre_is_sole_verdict_source`, and classification fields.
- Origin: Function Notebook/export gate.
- Scope: HexHawk-specific.

## Evidence/export integrity

### Do not fabricate typed evidence bundles
- Why it matters: report/export parity must reflect actual runtime evidence.
- Next time: explicitly mark typed NEST evidence as absent when absent.
- Origin: native report/export repair cycles.
- Scope: generalizable.

### Exact-artifact proof must name the artifact under test
- Why it matters: old hashes and smoke folders can mislead release decisions.
- Next time: record commit, path, hash, Authenticode status, and mtime for each artifact.
- Origin: release provenance drift audits.
- Scope: generalizable.

## Cleanup/provenance

### Old smoke and release-candidate folders are evidence/provenance, not runtime requirements
- Why it matters: they consume disk but may contain unique proof.
- Next time: inventory exact paths, sizes, git worktree status, artifacts, and evidence before deletion.
- Origin: world-distribution readiness and cleanup custody patterns.
- Scope: generalizable.

### Registered dirty worktrees are not safe deletion targets
- Why it matters: `git worktree remove` can fail or discard unreviewed work.
- Next time: preserve or summarize dirt, then ask for explicit approval before removal.
- Origin: top-level project tidy and cleanup patterns.
- Scope: generalizable.

## Factory/process discipline

### Factory improvement means process improvement, not uncontrolled self-modification
- Why it matters: the factory must not become an infinite autonomous loop.
- Next time: improve docs, gates, reports, templates, lessons, and validation; end with a stop point.
- Origin: Factory Cycle 0002.
- Scope: generalizable.

### Factory scaffolding should graduate into AetherFrame
- Why it matters: temporary process layers become bureaucracy if left separate forever.
- Next time: migrate durable behavior into AetherFrame docs/templates/reporter behavior, then archive legacy files only with approval.
- Origin: Factory graduation/integration cycle.
- Scope: generalizable.

## Cross-project advancement

### AetherFrame must be project-neutral at the method layer
- Why it matters: HexHawk is only the first adapter/proving ground.
- Next time: start every new project with product goal, protected truths, evidence sources, allowed actions, forbidden actions, validation gates, lessons, and stop conditions.
- Origin: AetherFrame advancement model and project template.
- Scope: generalizable.
