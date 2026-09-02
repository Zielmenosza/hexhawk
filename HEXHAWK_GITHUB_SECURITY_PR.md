# Proposed GitHub Security Pull Request

## Title

`fix(security): remediate dependency alerts and bind release lockfiles`

## Description

### Baseline and custody

This branch is reconstructed from clean `origin/main` commit `91c4912cc56c6b64aef27cff7ea8f0e0aedd1121`. It does not copy the inherited dirty checkout at `c6d78dc60fefc2aa034d8fd16092d108fa1019af`. Each manifest change was applied narrowly and lockfiles were regenerated from the clean manifest state.

### Vulnerability families addressed

The clean baseline reproduced 49 Yarn vulnerability findings across 12 package families when the configured root workspaces and separately tracked AetherframeGuard project are both audited, plus two non-vulnerability root deprecation notices. Families include Vitest, Vite, node-tar, undici, ws, nanoid, PostCSS, esbuild, brace-expansion, ip-address, fast-uri and `@babel/core`.

The Rust clean-lock baseline reproduced `RUSTSEC-2026-0187` in `lopdf 0.33.0`; `lopdf 0.42.0` removes it. The regenerated graph also resolves `tauri-plugin-log 2.9.1` and removes the previously observed `rkyv 0.7.x` chain.

Full family mapping and GitHub-count uncertainty are in `HEXHAWK_GITHUB_SECURITY_REMEDIATION.md`.

### Dependency changes

- Vitest and companion packages: 3.2.6 in both test workspaces.
- Vite: 6.4.3 for the HexHawk UI.
- AetherframeGuard: independent `yarn.lock` with Vite 6.4.3; its separate audit/build now participates in the security gate.
- jsdom: 30.0.1; happy-dom resolves 20.12.0.
- Compatible root Yarn resolutions for Babel 7.29.7, esbuild 0.28.2 where the vulnerable 0.27 range applies, brace-expansion, fast-uri, glob, ip-address, minimatch and node-tar.
- Root `Cargo.lock` is now committed for the Rust application workspace.
- `lopdf`: 0.33.0 -> 0.42.0, with two byte-name API compatibility changes.
- Release jobs enable Corepack and use Yarn 4 `yarn install --immutable`.

### Local before/after

| Measure | Before | After |
|---|---:|---:|
| Yarn vulnerability findings across root + AetherframeGuard | 49 | 0 |
| Yarn deprecation notices | 2 | 0 |
| Rust vulnerabilities | 1 after clean lock generation | 0 |
| Rust informational warnings | 19 unmaintained + 1 unsound | 20 unmaintained + 1 unsound (`ttf-parser` added via lopdf 0.42) |

### Verification

Completed locally on the clean branch:

- Yarn 4.13.0 and immutable install.
- Yarn recursive audit: zero advisories.
- Dependency-path checks for all mapped families.
- TypeScript typecheck; full frontend tests: 72 files, 927 passed, 1 skipped; production build passed.
- AetherFrame Core: 27 tests passed and build passed because its test dependency changed.
- AetherframeGuard independent immutable install, zero-advisory audit and Vite 6.4.3 production build passed.
- Locked Cargo metadata and cargo-audit: zero vulnerabilities.
- Full backend tests: 94 passed; strict Clippy and release backend build passed.
- `git diff --check` and exact 13-path inventory passed before the narrow follow-up. Current lock hashes: `yarn.lock` `42e81ebb3bf678b43bc9fe499901a932eed076d7aa05938657f75236dc23c5a4`; `AetherframeGuard/yarn.lock` `6a5909d1ecb13d6e7af0e0f293c44aae47ec768794ce33a4cac0acd86cc9f622`; `Cargo.lock` `2b1273f86b8cc81db88157d61777a187b5172afe7cdb14905c63f79c6c8c59fa`.

### Hosted follow-up

PR #3 is open. Historical CI run `33534749634` and CodeQL run `33534749690` passed at commit `6bfbbd5e1dea73978962686b305a098ed82d4d84`; authenticated readback reports zero open code-scanning alerts and zero open secret-scanning alerts. Those runs do not validate the current PR head. Dependabot still reports 53 open alerts on the default branch because this PR is not merged. GitHub's 53 records comprise 45 `yarn.lock` records plus eight duplicate direct-manifest records; all map to the locally identified vulnerable families.

A fresh local audit subsequently disclosed two new high-severity Browserslist advisories affecting `4.28.2`. The narrow `4.28.8` follow-up was independently accepted and pushed as current PR head `611c5c9b03707848e432e34622b148708e3be2bd`. Current-head CI run `33560620534` and CodeQL run `33560620530` are still in progress; both must pass before merge readiness can be assessed.

### Remaining warnings and blockers

Rust informational warnings remain explicitly open and are not dismissed or represented as vulnerabilities. The previous billing lock is no longer blocking Actions, as demonstrated by the successful CI and CodeQL runs above. PR #3 remains unmerged and is not a release-readiness claim.

### Rollback

Each logical commit can be reverted independently: JavaScript dependency graph, Rust lock/parser dependency, and release reproducibility/docs. Reverting the lockfile/security commits reintroduces locally demonstrated advisories and must not be used for a release without a replacement remediation.

## Remaining sequence

1. Verify current-head CI run `33560620534` and CodeQL run `33560620530` complete successfully.
2. Independently accept, commit, and push only the hosted-evidence documentation updates.
3. Verify the documentation push and resulting checks at the exact remote head.
4. Do not merge without separate approval.
5. After an approved merge, wait for the default-branch dependency graph to refresh and reconcile all residual Dependabot alerts.
