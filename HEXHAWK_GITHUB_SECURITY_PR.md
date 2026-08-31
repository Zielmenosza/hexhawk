# Proposed GitHub Security Pull Request

## Title

`fix(security): remediate dependency alerts and bind release lockfiles`

## Description

### Baseline and custody

This branch is reconstructed from clean `origin/main` commit `91c4912cc56c6b64aef27cff7ea8f0e0aedd1121`. It does not copy the inherited dirty checkout at `c6d78dc60fefc2aa034d8fd16092d108fa1019af`. Each manifest change was applied narrowly and lockfiles were regenerated from the clean manifest state.

### Vulnerability families addressed

The clean baseline reproduced 45 Yarn vulnerability advisories across 12 package families, plus two non-vulnerability deprecation notices. Families include Vitest, Vite, node-tar, undici, ws, nanoid, PostCSS, esbuild, brace-expansion, ip-address, fast-uri and `@babel/core`.

The Rust clean-lock baseline reproduced `RUSTSEC-2026-0187` in `lopdf 0.33.0`; `lopdf 0.42.0` removes it. The regenerated graph also resolves `tauri-plugin-log 2.9.1` and removes the previously observed `rkyv 0.7.x` chain.

Full family mapping and GitHub-count uncertainty are in `HEXHAWK_GITHUB_SECURITY_REMEDIATION.md`.

### Dependency changes

- Vitest and companion packages: 3.2.6 in both test workspaces.
- Vite: 6.4.3 for the HexHawk UI.
- jsdom: 30.0.1; happy-dom resolves 20.12.0.
- Compatible root Yarn resolutions for Babel 7.29.7, esbuild 0.28.2 where the vulnerable 0.27 range applies, brace-expansion, fast-uri, glob, ip-address, minimatch and node-tar.
- Root `Cargo.lock` is now committed for the Rust application workspace.
- `lopdf`: 0.33.0 -> 0.42.0, with two byte-name API compatibility changes.
- Release jobs enable Corepack and use Yarn 4 `yarn install --immutable`.

### Local before/after

| Measure | Before | After |
|---|---:|---:|
| Yarn vulnerability advisories | 45 | 0 |
| Yarn deprecation notices | 2 | 0 |
| Rust vulnerabilities | 1 after clean lock generation | 0 |
| Rust informational warnings | 20 unmaintained + 1 unsound | 20 unmaintained + 1 unsound |

### Verification

Completed locally on the clean branch:

- Yarn 4.13.0 and immutable install.
- Yarn recursive audit: zero advisories.
- Dependency-path checks for all mapped families.
- TypeScript typecheck; full frontend tests: 72 files, 927 passed, 1 skipped; production build passed.
- AetherFrame Core: 27 tests passed and build passed because its test dependency changed.
- Locked Cargo metadata and cargo-audit: zero vulnerabilities.
- Full backend tests: 94 passed; strict Clippy and release backend build passed.
- `git diff --check` and exact 11-path inventory passed. Lock hashes: `yarn.lock` `8191b3ebf148f94e73ebfde77e767b76202a213c9edc320da9f99a85369a8500`; `Cargo.lock` `2b1273f86b8cc81db88157d61777a187b5172afe7cdb14905c63f79c6c8c59fa`.

### Expected Dependabot result

All 45 locally reproduced Yarn vulnerability advisories across 12 families should close. The GitHub UI reportedly shows 53 alerts; eight visible records are not independently mappable without authenticated Dependabot access and may be duplicate manifest records or snapshot differences. Do not promise zero hosted alerts until Dependabot rescans this pushed branch and authenticated inventory is compared against the matrix.

### Remaining warnings and blockers

Rust informational warnings remain explicitly open and are not dismissed or represented as vulnerabilities. CodeQL run `33145594202` previously failed before runner startup because the GitHub account was billing-locked. Hosted code-scanning, Dependabot and secret-scanning inventories require authenticated read access after the account issue is resolved.

### Rollback

Each logical commit can be reverted independently: JavaScript dependency graph, Rust lock/parser dependency, and release reproducibility/docs. Reverting the lockfile/security commits reintroduces locally demonstrated advisories and must not be used for a release without a replacement remediation.

## Post-account-recovery sequence — not executed

1. Resolve the GitHub billing/account lock in GitHub account or organization billing settings.
2. Authenticate locally with normal web login: `gh auth login --hostname github.com --git-protocol https --web`.
3. Refresh the read-only security scope if required: `gh auth refresh -h github.com -s security_events`.
4. With explicit push approval, push `security/github-dependency-remediation`.
5. Open or update this PR.
6. Wait for Dependabot dependency-graph rescan.
7. Rerun CodeQL and verify jobs actually acquire runners and upload databases.
8. Export authenticated Dependabot, code-scanning and secret-scanning inventories without dismissing alerts.
9. Compare residual alerts, one by one, to `HEXHAWK_GITHUB_SECURITY_REMEDIATION.md`.
