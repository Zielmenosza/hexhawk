# HexHawk Enterprise and Commercial Roadmap

Last updated: 2026-05-31

## Board-Level Status

HexHawk is now a working native desktop binary-intelligence product with a rebuilt Windows installer path. It is suitable for controlled demos and internal tester distribution, but not yet a signed public enterprise release.

Current proof points:

- 38 frontend test files / 683 tests passing.
- Rust workspace validation passing with 85 backend/CLI tests.
- Production frontend build passing.
- Windows Tauri release executable builds.
- MSI and NSIS installer artifacts build.
- MSI extracts expected executable, CLI, and WebView2 loader payloads.
- Extracted CLI can identify a real PE challenge file.
- Packaged native GUI parity passes on an MSI-extracted app path, including native runtime proof and report JSON authority markers.

Current blockers to enterprise/public distribution:

- Code signing is not configured; artifacts are unsigned.
- Updater artifacts are disabled for the local tester build because signing credentials are not present.
- Packaged GUI parity has passed on the unsigned tester artifact; it must be rerun on signed artifacts before external release.
- External release provenance, support, and procurement materials need finalization.

## Market Position

HexHawk targets malware analysts, incident response teams, SOC teams, reverse engineers, and security researchers who need a local-first desktop workflow with evidence-grade reporting.

The near-term commercial wedge is paid pilot access for teams that need:

- local binary triage;
- repeatable evidence reports;
- analyst-friendly disassembly/decompiler views;
- explicit confidence and lineage metadata;
- local/offline operation with optional BYOK AI;
- controlled validation rather than opaque cloud detonation claims.

## Product Differentiators

- Evidence-first workflow: findings are tied to observable metadata, strings, disassembly, signatures, and NEST evidence bundles.
- Trust-safe AI positioning: AETHERFRAME/Forge can refine confidence and lineage but cannot change GYRE classification.
- Local-first architecture: core analysis runs on the analyst workstation.
- Native desktop UX: Tauri/Rust backend with React/TypeScript frontend.
- Controlled extensibility: plugins and report/export surfaces can be expanded without changing verdict authority.

## Pricing Direction

Suggested pilot packaging:

| Tier | Audience | Positioning |
| --- | --- | --- |
| Internal / Board Demo | Founders, board, investors | Unsigned local tester build, proof-of-product only |
| Paid Pilot | Small analyst teams | Signed Windows build, guided onboarding, limited support |
| Professional | Individual analysts | Local-first desktop license with report export |
| Team | SOC / IR team | Shared process, support, onboarding, policy templates |
| Enterprise | Regulated teams | Procurement support, SSO/activation roadmap, audit/export requirements |

## Next Commercial Milestones

### M1 — Signed Controlled Tester Build

- Configure signing keys.
- Re-enable updater artifacts.
- Rebuild MSI/NSIS.
- Publish checksums and signing state.
- Rerun installed-artifact GUI export parity on signed artifacts.

### M2 — Investor / Board Package

- Maintain one-pager, diligence brief, board update, and website copy.
- Keep claims evidence-scoped and current.
- Avoid claiming public-release readiness until signing and updater trust-chain proof pass; packaged native GUI parity now has release-hardening evidence, but distribution trust remains incomplete.

### M3 — Paid Pilot Readiness

- Define pilot onboarding steps.
- Define support and issue intake.
- Define license activation operations.
- Produce signed installer and checksums.
- Capture 2-3 real-world case-study demos without exposing sensitive samples.

## Risk Register

| Risk | Current status | Mitigation |
| --- | --- | --- |
| Unsigned installer | Open | Configure code signing before external release |
| Updater signing | Open | Provide `TAURI_SIGNING_PRIVATE_KEY` and re-enable updater artifacts |
| GUI installed parity | Pass on unsigned tester artifact | Rerun native installed-artifact export parity on signed artifact |
| Overclaiming AI/verdict authority | Controlled | Preserve GYRE/NEST/AETHERFRAME boundaries in docs/UI/export |
| Support burden | Open | Pilot-only release until support path is defined |
