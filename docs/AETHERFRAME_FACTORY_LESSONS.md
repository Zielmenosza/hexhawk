# AetherFrame Advancement Factory — Lessons Learned

Date started: 2026-06-30
Format: [TAG] Lesson. Source: <context>.

Tags: [PREVENTION] [CI] [BOUNDARY] [VALIDATION] [CUSTODY] [BUILD]

---

## Foundation Lessons (pre-factory, carried forward)

[VALIDATION] Do not trust claims without checking actual file state.
File contents and git status are ground truth. Docs, comments, and logs from previous sessions
may be stale. Always inspect the actual file before reporting on its content.
Source: repeated pattern across multiple sessions.

[VALIDATION] Stale release worktrees can mislead.
Old worktrees left in the repo directory may contain outdated installers, evidence JSON, and
hash files. Do not treat them as current build output. Verify mtime and git log.
Source: deployment-custody-clean-main-rc-build pattern.

[VALIDATION] Smoke probes must have hard timeouts.
A smoke probe waiting for a GUI to open or a CDP connection to appear can hang the terminal
indefinitely if the app fails to launch. Every probe must have an explicit timeout and a
non-zero exit on timeout.
Source: native-gui-cdp-probe-qa-tooling pattern.

[VALIDATION] GUI probes must not wait forever on a live desktop app.
Installed app processes may remain resident after smoke completes. Kill only path-verified
smoke-launched processes. Do not kill by name alone.
Source: installer-smoke-window-proof pattern.

[VALIDATION] Installed artifact proof is different from source tests.
Passing Vitest and cargo test in source does not prove the packaged installer works.
Installed-artifact native GUI export parity is a separate, harder gate.
Source: release-hardening-packaged-gui-parity pattern.

[CI] Red CI blocks public trust.
A package cannot be recommended to any external party while main CI is failing.
CI stabilization must be the first factory target whenever CI is red.
Source: factory operating doctrine, CI stabilization cycle.

[BOUNDARY] Unsigned artifacts are not public-ready.
MSI/NSIS without Authenticode is an internal tester artifact only. Do not call it
"public-ready" or "release-ready." Authenticode must be independently proven.
Source: release-truth-correction pattern.

[BOUNDARY] AetherFrame must stay advisory.
AetherFrame may score, rank, summarize, package, and recommend.
It must not issue verdicts, modify GYRE classification, or override NEST evidence bundles.
This applies in code, docs, GUI copy, and marketing language.
Source: ENGINE_BOUNDARY_DOCTRINE.md, factory operating doctrine.

[BOUNDARY] Function Intelligence exports must preserve GYRE authority fields.
When exporting Function Intelligence data (JSON, Markdown, Function Notebook), the export
must preserve source_engine, gyre_is_sole_verdict_source, and classification fields.
AetherFrame lineage may be appended but must not replace or mutate these fields.
Source: function-intelligence-source-candidate-release-gate pattern.

---

## Factory Cycle 0001 — CI Stabilization (2026-06-30)

[CI] Yarn 4 workspace protocol requires corepack to be enabled in CI.
CI ubuntu runners ship with Yarn 1 as the system yarn. Yarn 4 lockfiles (version 8 metadata)
with workspace:* dependency references will fail on "yarn install --frozen-lockfile" if corepack
is not enabled first. Fix: add "corepack enable" before "yarn install" in all CI jobs that
use yarn.
Source: gh run view 28400567992 --log-failed, TypeScript Engine Tests / Install dependencies.

[CI] [PREVENTION] The CI yaml must be tested for compatibility with the yarn version in yarn.lock.
If yarn.lock has __metadata: version: 8, the repo uses Yarn 4 (Berry).
CI must run "corepack enable" and must have a "packageManager" field in root package.json
to ensure consistent pinning. Without this, workspace:* packages resolve as npm packages
and fail immediately.
Source: factory cycle 0001 root cause analysis.

[CI] Linux ptrace::write data argument type changed across nix crate versions.
nix 0.29 signature: ptrace::write(pid, addr: AddressType, data: c_long).
Code that passes data as *mut _ (raw pointer) will fail with E0308 mismatched types on Linux.
Fix: cast data argument to c_long (or libc::c_long). This is Linux/cfg(target_os="linux") only.
Source: gh run view 28400567992 --log-failed, Rust Tests / Run Rust tests.

[VALIDATION] CI log extraction via "gh run view <id> --log-failed" is the fastest way to
diagnose CI failures without browsing GitHub UI. Filter the output for "error", "Error",
"FAILED", "mismatched", and "workspace" to surface the root cause quickly.
Source: factory cycle 0001 investigation.
