# HexHawk GitHub Security Remediation

**Prepared:** 2026-08-31; hosted follow-up 2026-09-01
**Branch:** `security/github-dependency-remediation`
**Clean baseline:** `origin/main` at `91c4912cc56c6b64aef27cff7ea8f0e0aedd1121`
**Remote:** `https://github.com/Zielmenosza/hexhawk.git`
**Scope:** dependency security and release reproducibility only; no product-feature transplant from the inherited dirty worktree.

## Custody baseline

Before the clean worktree was created, the historical/dirty checkout was `fix/gyre-nest-snapshot-boundary` at `c6d78dc60fefc2aa034d8fd16092d108fa1019af`. Its exact `git status --porcelain=v1 --branch -uall` was preserved at `%LOCALAPPDATA%/Temp/hexhawk-dirty-presecurity.status`; it was not reset, cleaned, stashed, staged or copied wholesale.

The dirty HEAD and current remote default branch diverge from merge base `2fca878e7fe3ad131dad2df6d04d4aef8af624f6`: dirty HEAD has one unique commit and `origin/main` has four unique commits. The remediation branch therefore starts from the authoritative remote baseline, not from the dirty checkout.

## Alert-count interpretation

- **User-visible GitHub alert count:** 53 individual alerts.
- **Locally reproducible Yarn findings at the clean baseline:** the configured root workspaces produced 45 vulnerability advisories plus 2 deprecation notices; the separately tracked, out-of-workspace AetherframeGuard project produced 4 additional vulnerability findings. Combined: 49 vulnerability findings and 2 deprecations.
- **Underlying locally reproduced vulnerable package families:** 12 (`@babel/core`, `brace-expansion`, `esbuild`, `fast-uri`, `ip-address`, `nanoid`, `postcss`, `tar`, `undici`, `vite`, `vitest`, `ws`).
- **GitHub alert inventory:** authenticated readback is now available. GitHub reports 45 `yarn.lock` records plus eight direct-manifest records (four `HexHawk/package.json`, three `AetherframeGuard/package.json`, one `packages/aetherframe-core/package.json`). The numeric values in the family table below remain Yarn/npm advisory IDs, not GitHub repository alert numbers.
- The four-record difference between GitHub's 53 records and the 49 locally reproduced vulnerability findings is a counting-dimension difference across lockfile and direct-manifest records; it is not an unmapped vulnerability family.

Thus, “53 alerts” must not be treated as 53 independent defects. The clean graph has zero Yarn advisories after remediation, but GitHub must rescan the pushed branch before closure counts are asserted.

## Remediated dependency graph

All JavaScript findings are development/build/test dependencies in this repository; they are not bundled application runtime dependencies. They are still security-relevant because local/CI developer services process repository-controlled input and run with developer/runner authority.

| Family | Baseline findings (advisory IDs) | Highest severity | Affected manifest/lock | Direct/transitive and reachability | Vulnerable version(s) | Clean remediation | Dependency path / local proof | Expected result |
|---|---|---:|---|---|---|---|---|---|
| Vitest | `1139528` | Critical | `packages/aetherframe-core/package.json`, `HexHawk/package.json`, `yarn.lock` | Direct dev/test tool; UI server arbitrary file read/execution | 2.1.9 | 3.2.6 in both workspaces | workspace -> `vitest@3.2.6`; `yarn why vitest` | closes locally; GitHub confirmation required |
| node-tar | `1120782`, `1123939`, `1123940`, `1123941`, `1123942`, `1145647` | Critical | `yarn.lock`; root resolution | Transitive build tool via `node-gyp`; archive parser DoS/smuggling/crash | 7.5.13 | 7.5.22 | `node-gyp -> tar@7.5.22`; `yarn why tar` | closes locally; GitHub confirmation required |
| Vite | `1116229`, `1120784`, `1123525` (present in both the root and AetherframeGuard baseline graphs) | High | `AetherframeGuard/package.json`, `AetherframeGuard/yarn.lock`, `HexHawk/package.json`, `yarn.lock` | Direct dev/build server; Windows path/UNC and optimized-deps disclosure | 5.4.21 | 6.4.3 direct; root Vitest tree resolves Vite 7.3.6 | root and AetherframeGuard audits/builds; `yarn why vite` | closes locally; GitHub confirmation required |
| nanoid | `1138811`, `1139427` | High | `yarn.lock` | Transitive build CSS tooling via PostCSS | 3.3.11 | 3.3.18 | `postcss@8.5.26 -> nanoid@3.3.18` | closes locally; GitHub confirmation required |
| ws | `1119108`, `1123259` | High | `yarn.lock` | Transitive test DOM WebSocket implementation via happy-dom | 8.20.0 | 8.21.3 | `happy-dom@20.12.0 -> ws@8.21.3` | closes locally; GitHub confirmation required |
| undici | `1121187`, `1121241`, `1121244`, `1121247`, `1121254`, `1121428`, `1130715`, `1130718`, `1130726`, `1130729`, `1130731`, `1137242` | High | `HexHawk/package.json`, `yarn.lock` | Transitive test DOM HTTP/WebSocket client via jsdom | 7.25.0 | jsdom 30.0.1 -> undici 8.10.1 | `yarn why undici` | closes locally; GitHub confirmation required |
| brace-expansion | `1120311`, `1123896`, `1123898`, `1130589`, `1130591`, `1130734`, `1130736` | High | `yarn.lock`; root resolutions | Transitive build glob matching | 2.1.0 and 5.0.5 | 2.x resolution 2.1.2 plus final graph 5.0.9; final audit is authoritative for new later advisories | `minimatch -> brace-expansion@5.0.9`; `yarn why brace-expansion` | closes locally at current advisory DB; GitHub confirmation required |
| PostCSS | `1117015`, `1124252`, `1130709`, `1139510` | High | `yarn.lock` | Transitive Vite build CSS processing; source-map/path disclosure | 8.5.9 | 8.5.26 | Vite -> `postcss@8.5.26`; `yarn why postcss` | closes locally; GitHub confirmation required |
| ip-address | `1118827`, `1130722` | High | `yarn.lock`; root resolutions | Transitive development network/proxy parser via socks | 10.1.0 | 10.3.1 | `socks -> ip-address@10.3.1`; `yarn why ip-address` | closes locally; GitHub confirmation required |
| fast-uri | `1124064`, `1130720`, `1147878` | High | `yarn.lock`; root resolution | Transitive schema-validation URI parser via AJV; potential trust-boundary relevance in tooling | 3.1.2 | 4.1.3 | `ajv -> fast-uri@4.1.3`; `yarn why fast-uri` | closes locally; GitHub confirmation required |
| esbuild | `1102341` in both root and AetherframeGuard baseline graphs; `1120680` in the root graph | Moderate/Low | `yarn.lock`, `AetherframeGuard/yarn.lock`; Vite/Vitest/tsx paths | Transitive dev server/build transformer | 0.21.5 and 0.27.7 | direct Vite 6 tree 0.25.12; Vite 7/tsx tree 0.28.2 | root and AetherframeGuard audits; `yarn why esbuild` | closes locally; GitHub confirmation required |
| `@babel/core` | `1123528` | Low | `yarn.lock`; root resolution | Transitive React build transform via `@vitejs/plugin-react`; not packaged runtime | 7.29.0 | 7.29.7 | plugin-react -> `@babel/core@7.29.7` | closes locally; GitHub confirmation required |

### Non-vulnerability audit notices

- `@types/react-window@2.0.0` deprecation disappeared because the unused stub root dev dependency was removed; `react-window` provides its own types.
- `glob@10.5.0` deprecation disappeared after the regenerated graph/resolution. These notices are not counted as vulnerabilities.

## Rust vulnerability remediation

The clean baseline had no committed root `Cargo.lock`, so `cargo generate-lockfile` was run from the clean manifests. The first clean audit found `RUSTSEC-2026-0187` in direct runtime parser `lopdf 0.33.0` (unbounded nested-object recursion and process-aborting stack overflow). `src-tauri/Cargo.toml` now selects compatible `lopdf 0.42`, the lock pins `0.42.0`, and two small source compatibility changes use the current byte-name API. The final Rust audit reports zero vulnerabilities.

The regenerated graph independently resolves `tauri-plugin-log 2.9.1`, which removes the prior `rkyv 0.7.x` chain without changing the broad `tauri-plugin-log = "2"` manifest constraint. It also resolves `event-listener 5.4.2`, `chacha20 0.10.2`, and Rhai 1.26.0. Verification commands:

```text
cargo metadata --locked --format-version 1
cargo tree --locked -i tauri-plugin-log
cargo tree --locked -i rkyv                 # expected: no matching package
cargo tree --locked -i lopdf
cargo tree --locked -i event-listener@5.4.2
cargo tree --locked -i chacha20@0.10.2
cargo audit --json
```

Warnings remain separate from vulnerabilities: final audit has 20 unmaintained plus 1 unsound warning. The main groups are Linux GTK3/glib, Stronghold `bincode`/`paste`, Rhai `smartstring`, lopdf's `ttf-parser`, and Tauri build-chain UNIC crates. None is silently waived.

## Local before/after summary

| Measure | Clean baseline | Remediated graph |
|---|---:|---:|
| Yarn vulnerability advisories across root workspaces + AetherframeGuard | 49 | 0 |
| Yarn deprecation notices | 2 | 0 |
| Yarn total audit findings including 2 root deprecations | 51 | 0 |
| Rust vulnerabilities after clean lock generation | 1 (`lopdf`) | 0 |
| Rust warnings | 19 unmaintained + 1 unsound before lopdf update | 20 unmaintained + 1 unsound after (`ttf-parser` added through lopdf 0.42) |

## Hosted follow-up and residual risk

PR #3 is open at `https://github.com/Zielmenosza/hexhawk/pull/3`. CI run `33534749634` and CodeQL run `33534749690` completed successfully at historical branch commit `6bfbbd5e1dea73978962686b305a098ed82d4d84`; all four configured CodeQL language jobs passed, and authenticated readback reported zero open code-scanning alerts and zero open secret-scanning alerts. Those runs do not validate the current PR head.

Authenticated Dependabot readback still reports the original **53 open default-branch alerts** (4 critical, 24 high, 21 medium, 4 low), all npm. This is expected while PR #3 remains unmerged because Dependabot alerts are evaluated against the default branch; a clean PR graph does not close default-branch alerts. The prior four-record difference from the 49 locally reproduced audit findings is now attributable to counting semantics rather than an unknown family: GitHub reports 45 `yarn.lock` records plus eight duplicate direct-manifest records (four `HexHawk/package.json`, three `AetherframeGuard/package.json`, one `packages/aetherframe-core/package.json`). All records map to the already identified vulnerable families.

A fresh local audit on 2026-09-01 found two newer high-severity Browserslist advisories (`GHSA-c83g-rgw3-j3cx` and `GHSA-73wf-gq98-2v4g`) against `browserslist 4.28.2`. The narrow `4.28.8` follow-up was independently accepted, committed as `611c5c9b03707848e432e34622b148708e3be2bd`, pushed, and verified as the exact PR head. Immutable install, recursive audit (zero findings), dependency-path inspection, and the 927-pass/1-skip frontend suite all pass. Current-head CI run `33560620534` and CodeQL run `33560620530` are still in progress, so merge readiness is not yet established.

## GitHub prediction and uncertainty

The clean branch is expected to close all **53 authenticated default-branch alert records** after merge and dependency-graph refresh: 45 lockfile records plus eight duplicate direct-manifest records. This remains a prediction until merge because PR branches do not close default-branch Dependabot alerts.

Predicted remaining dependency vulnerabilities locally after the Browserslist follow-up: **zero**. Current GitHub residual count: **53 open on `main`** until merge/rescan. Any remaining Critical/High alert after that refresh must be mapped and explained before release use.

## Commands used for verification

```text
node C:/Program Files/nodejs/node_modules/corepack/dist/yarn.js --version
yarn install --immutable
yarn npm audit --all --recursive --json
yarn why <package>
yarn typecheck
yarn test
yarn build
cargo metadata --locked --format-version 1
cargo audit --json
cargo test --locked --bin hexhawk-backend
cargo clippy --locked --bin hexhawk-backend -- -D warnings
cargo build --locked --release --bin hexhawk-backend
git diff --check
```

## Completed verification and commits

Verification completed on the clean branch:

- Yarn/Corepack package-manager version: 4.13.0.
- `yarn install --immutable`: exit 0; pre-existing React peer warnings only.
- recursive Yarn audit: exit 0 with zero output findings.
- frontend typecheck: exit 0.
- frontend suite: 72 files passed; 927 tests passed and 1 skipped.
- frontend production build: exit 0; bundle-size/dynamic-import warnings remain non-security build warnings.
- AetherFrame Core: 27 tests passed; build exit 0.
- AetherframeGuard independent Yarn project: immutable install passed; audit returned zero findings; Vite 6.4.3 production build passed. Generated JS/dist/install-state outputs were excluded.
- locked backend suite: 94 tests passed.
- strict backend Clippy with warnings denied: exit 0.
- locked release backend build: exit 0.
- cargo-audit: exit 0; zero vulnerabilities, 20 unmaintained and 1 unsound warning.
- `git diff --check`: exit 0.
- committed path allowlist: 13/13 exact after the independent AetherframeGuard lock/remediation; no generated schemas, snapshots, install state, build output or target files committed.

Logical commits:

1. `df9558d25e6491ff0fd52271777114f3278af15b` — JavaScript dependency security remediation; parent `91c4912cc56c6b64aef27cff7ea8f0e0aedd1121`; files `package.json`, `HexHawk/package.json`, `packages/aetherframe-core/package.json`, `yarn.lock`.
2. `326a59a3991d813450fbd15bfd0b07e364340bd0` — Rust lock/parser dependency remediation; parent `df9558d25e6491ff0fd52271777114f3278af15b`; files `.gitignore`, `Cargo.lock`, `src-tauri/Cargo.toml`, `src-tauri/src/commands/document.rs`.
3. `adb4ab3f2c7d7f2a6384f058d0ddd9f6b5ed68d7` — release reproducibility and initial GitHub handoff documentation; parent `326a59a3991d813450fbd15bfd0b07e364340bd0`; files `.github/workflows/release.yml`, `HEXHAWK_GITHUB_SECURITY_REMEDIATION.md`, `HEXHAWK_GITHUB_SECURITY_PR.md`.
4. `59f148c36c5e58aae8524d6bf166f38ffb7eaa49` — independently lock and remediate AetherframeGuard build tooling; parent `adb4ab3f2c7d7f2a6384f058d0ddd9f6b5ed68d7`; files `AetherframeGuard/package.json`, `AetherframeGuard/yarn.lock`.

Important lock hashes:

- `yarn.lock`: `42e81ebb3bf678b43bc9fe499901a932eed076d7aa05938657f75236dc23c5a4` (after Browserslist follow-up)
- `Cargo.lock`: `2b1273f86b8cc81db88157d61777a187b5172afe7cdb14905c63f79c6c8c59fa`
- `AetherframeGuard/yarn.lock`: `6a5909d1ecb13d6e7af0e0f293c44aae47ec768794ce33a4cac0acd86cc9f622`
