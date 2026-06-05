# HexHawk Enterprise and Commercial Roadmap

Last updated: 2026-06-04

## Board-Level Status

HexHawk is a working native desktop binary-intelligence product with a repeatable Windows installer build path. It is suitable for controlled demos and internal tester distribution, but not yet a signed public enterprise release.

Current proof points:

- TypeScript typecheck passing in the June 4 rebuild pass.
- Production frontend build passing with existing chunk/import warnings.
- Windows Tauri release executable builds.
- MSI and NSIS installer artifacts build.
- Current rebuilt artifacts are Authenticode `NotSigned`.
- Prior packaged native GUI parity evidence exists, but exact-artifact GUI proof was not rerun for the June 4 rebuilt hashes.
- Live public site was deployed separately with current internal-tester caveats; this docs/rebuild pass did not redeploy it.

Current blockers to enterprise/public distribution:

- Public-trusted code signing is not configured; current artifacts are unsigned.
- Updater artifacts are disabled for local unsigned builds; hosted metadata must be refreshed and revalidated against exact official artifacts before endpoint-readiness claims.
- Packaged GUI parity must be rerun on the exact artifact intended for external testers, especially after signing.
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
| GUI installed parity | Historical proof only for older hashes | Rerun native installed-artifact export parity on the exact rebuilt/signed artifact |
| Overclaiming AI/verdict authority | Controlled | Preserve GYRE/NEST/AETHERFRAME boundaries in docs/UI/export |
| Support burden | Open | Pilot-only release until support path is defined |
