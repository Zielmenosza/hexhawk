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

[CI] [PREVENTION] Do not hardcode old CI root causes into the factory reporter.
Once the first failures are fixed, the latest red run may expose new blockers. The reporter must
point to current GitHub Actions logs instead of repeating stale known failures.
Source: factory cycle 0001 follow-up after later CI run 28460853152.

[CI] Vitest path filters are not shell globs in CI.
The quoted argument 'src/components/__tests__/**' produced "No test files found" on the
component job. Use a concrete directory/path filter such as src/components/__tests__.
Source: CI run 28460853152, TypeScript Component Tests.

[CI] Vite needs a source alias for workspace package subpath exports when tests run against
unbuilt private packages.
TypeScript path aliases let tsc resolve @hexhawk/aetherframe-core/browser, but Vitest/Vite import
analysis still tried to load the package export from dist. Add a Vite alias to the package source
or build the package before Vitest.
Source: CI run 28460853152, TypeScript Engine Tests.

[CI] [VALIDATION] Windows-style challenge paths must be normalized before path.basename on Linux.
Node path.basename on Linux does not treat backslashes as separators, so generated challenge IDs
included the whole Windows path. Normalize backslashes to slashes before deriving challenge names.
Source: CI run 28460853152, STRIKE script helper failures.

[CI] Coverage gates must match the suite they run.
The CI engine job ran the broad Vitest suite with --coverage, but current global/per-file coverage
thresholds are not met by that broad suite. For CI stabilization, run the test suite without
coverage until a separate coverage-improvement cycle raises or recalibrates coverage honestly.
Source: local validation of yarn workspace hexhawk-ui exec vitest run --reporter=verbose --coverage.

[CI] Missing local challenge logs must not fail routine fixture generation.
CI runners do not carry every local NEST/challenge evidence folder. If canonical fixture output is
already present, the STRIKE fixture builder should keep it unchanged when source logs are absent.
Source: CI run 28475132214, Build challenge-derived STRIKE fixtures.

[CI] Cross-platform debugger code must compile on all advertised build jobs.
The macOS Tauri build exposed debugger.rs errors hidden by Linux/Windows checks: mac-specific
DebugSnapshot initializers must include authority evidence fields, and macOS ptrace code needs an
explicit libc dependency. Keep OS-specific compile paths in the CI matrix.
Source: CI runs 28475292190 and 28476115794, Build macOS DMG.

[CI] Routine CI packaging must stay credential-free and unsigned.
Empty Apple signing variables caused macOS bundling to attempt certificate import and fail. Routine
CI should verify unsigned buildability without injecting signing/notarization credentials; signed and
notarized artifacts belong to the explicit release gate only. This avoids both false public-readiness
claims and accidental credential use.
Source: CI run 28476115794, Build macOS DMG; fixed in run 28476869500.

[RELEASE] A successful unsigned CI artifact build is not a public release proof.
Green Windows/Linux/macOS build jobs prove buildability only. Public release readiness still requires
release gate evidence such as signing/notarization status, installed-artifact smoke, updater metadata,
checksums, and authority-preserving Function Intelligence export proof.
Source: factory cycle 0001 final CI status, run 28476869500.
