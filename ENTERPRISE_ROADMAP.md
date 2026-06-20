# HexHawk Enterprise and Commercial Roadmap

Last updated: 2026-06-20

## Board-Level Status

HexHawk is a working native desktop binary-intelligence product with a repeatable Windows installer build and smoke-tested unsigned deployment-candidate path. It is suitable for controlled demos and internal tester distribution, but not yet a signed public enterprise release.

Current proof points:

- STRIKE benchmark provenance path fix committed and pushed in `e625403`.
- All discovered frontend tests passed in a fresh release worktree: 47 files, 736 passed, 1 skipped.
- TypeScript typecheck passing.
- Production frontend build passing with existing chunk/import warnings.
- Windows Tauri MSI and NSIS artifacts build from post-fix HEAD.
- Current rebuilt artifacts are Authenticode `NotSigned`.
- MSI extraction and NSIS install launch/render smoke passed; NSIS includes the real `WebView2Loader.dll` and uninstalls cleanly.
- Deployment candidate tag: `v1.2.0-unsigned-deployment-candidate-20260620`.
- Live public site was not redeployed in this pass.

Current blockers to enterprise/public distribution:

- Public-trusted code signing is not configured; current artifacts are unsigned.
- Updater artifacts are disabled for local unsigned builds; hosted metadata must be refreshed and revalidated against exact official artifacts before endpoint-readiness claims.
- Full packaged GUI export parity must be rerun on the exact artifact intended for external testers, especially after signing; June 20 launch/render smoke is current for installer health.
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
| Paid Pilot | Small analyst teams | Planned signed Windows build, guided onboarding, limited support after release gates |
| Professional | Individual analysts | Local-first desktop license with report export |
| Team | SOC / IR team | Shared process, support, onboarding, policy templates |
| Enterprise | Regulated teams | Procurement support, SSO/activation roadmap, audit/export requirements |

## Next Commercial Milestones

### M1 — Signed Controlled Tester Build

- Configure signing keys.
- Keep updater artifacts disabled until official signing custody is present.
- Rebuild MSI/NSIS.
- Publish checksums and signing state.
- Rerun installed-artifact GUI export parity on signed artifacts.

### M2 — Investor / Board Package

- Maintain one-pager, diligence brief, board update, competitive landscape, and website copy.
- Keep claims evidence-scoped and current.
- Avoid claiming public-release readiness until signing and updater trust-chain proof pass.

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
| Updater signing/metadata | Open | Use official release custody, refresh hosted metadata, and validate exact artifact/signature fields before readiness claims |
| GUI installed parity | Launch/render smoke current for June 20 unsigned candidate; full export parity still historical | Rerun native installed-artifact export parity on the exact rebuilt/signed artifact |
| Overclaiming AI/verdict authority | Controlled | Preserve GYRE/NEST/AETHERFRAME boundaries in docs/UI/export |
| Support burden | Open | Pilot-only release until support path is defined |
