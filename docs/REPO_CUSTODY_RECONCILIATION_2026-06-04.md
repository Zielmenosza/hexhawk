# HexHawk Repo Custody Reconciliation (2026-06-04)

> **Historical snapshot.** This document preserves the 2026-06-04 custody record. It is not current product, validation, packaging, or release-readiness evidence. See [`CURRENT_STATUS.md`](CURRENT_STATUS.md).

## Scope

- Repository: `D:/Project/HexHawk`.
- Purpose: classify and reconcile dirty source, docs, release/trust artifacts, credentials, generated files, AETHERFRAME core work, NEXUS local work, and updater/signing metadata without deploying or publishing anything.
- Website refresh is already committed/pushed/deployed; this pass does not redeploy or refresh live endpoints.
- `docs/credentials.md` was not read.

## Authority and release-truth constraints

- GYRE remains sole verdict authority.
- NEST remains evidence orchestrator.
- AETHERFRAME remains optional, bounded, policy-gated confidence/lineage/refinement support and must not mutate classification.
- NEXUS remains advisory/assistant only.
- No public release readiness or public-trusted signing is claimed by this reconciliation.
- `site-build/releases/**`, `site-build/trust/**`, and `site-build/.well-known/**` are not staged in this pass.

## Path classification before cleanup

| Git state | Path | Classification | Decision rationale |
| --- | --- | --- | --- |
| `M ` | `github/workflows/release.yml` | needs user review | No automatic custody rule matched; leave unstaged until reviewed. |
| ` M` | `.gitignore` | keep and stage | Source-hygiene rules for credentials, pycache/temp/Wix outputs, local projects, and generated release binaries. |
| ` M` | `.yarn/install-state.gz` | restore to HEAD | Generated package-manager state; not an intended dependency change. |
| ` M` | `HexHawk/package.json` | keep and stage | Useful product-agnostic AETHERFRAME core/report adapter source work; must preserve GYRE/NEST authority and validate. |
| ` M` | `HexHawk/src/components/IntelligenceReport.tsx` | keep and stage | Useful report-export policy/lineage integration with tests; must keep AETHERFRAME optional and non-authoritative. |
| ` M` | `HexHawk/src/components/__tests__/IntelligenceReport.test.tsx` | keep and stage | Useful report-export policy/lineage integration with tests; must keep AETHERFRAME optional and non-authoritative. |
| `D ` | `docs/.~lock.HEXHAWK_FOR_DUMMIES.docx#` | keep and stage | Clearly disposable/generated tracked artifact deletion; pair with .gitignore hygiene. |
| ` M` | `docs/EXTERNAL_TESTER_KNOWN_ISSUES.md` | keep and stage | Docs alignment to unsigned/updater-gated release truth; verify no public-release overclaim. |
| ` M` | `docs/HEXHAWK_FOR_DUMMIES.md` | keep and stage | Docs alignment to unsigned/updater-gated release truth; verify no public-release overclaim. |
| ` M` | `docs/HEXHAWK_FOR_DUMMIES_CAPABILITY_INVENTORY.md` | keep and stage | Docs alignment to unsigned/updater-gated release truth; verify no public-release overclaim. |
| ` M` | `docs/HEXHAWK_FOR_DUMMIES_SOURCE_MAP.md` | keep and stage | Docs alignment to unsigned/updater-gated release truth; verify no public-release overclaim. |
| ` M` | `docs/RELEASE_SIGNING_AND_UPDATER_PLAN.md` | keep and stage | Docs alignment to unsigned/updater-gated release truth; verify no public-release overclaim. |
| ` M` | `docs/RELEASE_VALIDATION_2026-06-01.md` | keep and stage | Docs alignment to unsigned/updater-gated release truth; verify no public-release overclaim. |
| `D ` | `docs/credentials.md` | unsafe to commit | Do not stage deletion because deletion diff exposes credential file content; restore to HEAD without reading and handle future removal by secret-rotation/history-scrub process. |
| `D ` | `hexhawk-enterprise.wixobj` | keep and stage | Clearly disposable/generated tracked artifact deletion; pair with .gitignore hygiene. |
| ` M` | `prepare-release.ps1` | keep and stage | Release/signing/updater validation source/script work; does not publish endpoints by itself and should be reviewed with conservative release claims. |
| `D ` | `scripts/__pycache__/capture_hexhawk_screenshots.cpython-311.pyc` | keep and stage | Clearly disposable/generated tracked artifact deletion; pair with .gitignore hygiene. |
| `D ` | `scripts/__pycache__/export_dummies_docx.cpython-311.pyc` | keep and stage | Clearly disposable/generated tracked artifact deletion; pair with .gitignore hygiene. |
| ` M` | `scripts/native_gui_parity_probe.py` | keep and stage | Release/signing/updater validation source/script work; does not publish endpoints by itself and should be reviewed with conservative release claims. |
| ` M` | `scripts/release/refresh-trust-artifacts.ps1` | keep and stage | Release/signing/updater validation source/script work; does not publish endpoints by itself and should be reviewed with conservative release claims. |
| ` M` | `scripts/release/run-native-parity-probe.ps1` | keep and stage | Release/signing/updater validation source/script work; does not publish endpoints by itself and should be reviewed with conservative release claims. |
| `D ` | `scripts/validation/native-gui/__pycache__/native_gui_e2e.cpython-311.pyc` | keep and stage | Clearly disposable/generated tracked artifact deletion; pair with .gitignore hygiene. |
| `D ` | `scripts/validation/native-gui/__pycache__/native_gui_export_parity_gate.cpython-311.pyc` | keep and stage | Clearly disposable/generated tracked artifact deletion; pair with .gitignore hygiene. |
| ` M` | `site-build/.well-known/hexhawk-trust.json` | restore to HEAD | Release/trust/updater/static endpoint artifact; stale/unverified in this task and live endpoints must not be refreshed or represented as current proof. |
| ` M` | `site-build/downloads/checksums.txt` | restore to HEAD | Release/trust/updater/static endpoint artifact; stale/unverified in this task and live endpoints must not be refreshed or represented as current proof. |
| ` M` | `site-build/releases/latest.json` | restore to HEAD | Release/trust/updater/static endpoint artifact; stale/unverified in this task and live endpoints must not be refreshed or represented as current proof. |
| ` M` | `site-build/releases/v1.0.0/SHA256SUMS.txt` | restore to HEAD | Release/trust/updater/static endpoint artifact; stale/unverified in this task and live endpoints must not be refreshed or represented as current proof. |
| `D ` | `site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64-setup.exe` | restore to HEAD | Release/trust/updater/static endpoint artifact; stale/unverified in this task and live endpoints must not be refreshed or represented as current proof. |
| `D ` | `site-build/releases/v1.0.0/assets/HexHawk_1.0.0_x64_en-US.msi` | restore to HEAD | Release/trust/updater/static endpoint artifact; stale/unverified in this task and live endpoints must not be refreshed or represented as current proof. |
| ` M` | `site-build/trust/key-rotations.json` | restore to HEAD | Release/trust/updater/static endpoint artifact; stale/unverified in this task and live endpoints must not be refreshed or represented as current proof. |
| ` M` | `site-build/trust/keys.json` | restore to HEAD | Release/trust/updater/static endpoint artifact; stale/unverified in this task and live endpoints must not be refreshed or represented as current proof. |
| ` M` | `site-build/trust/revocations.json` | restore to HEAD | Release/trust/updater/static endpoint artifact; stale/unverified in this task and live endpoints must not be refreshed or represented as current proof. |
| ` M` | `site-build/trust/signatures/latest/HexHawk_1.0.0_x64-setup.exe.sig` | restore to HEAD | Release/trust/updater/static endpoint artifact; stale/unverified in this task and live endpoints must not be refreshed or represented as current proof. |
| ` M` | `site-build/trust/signatures/latest/HexHawk_1.0.0_x64_en-US.msi.sig` | restore to HEAD | Release/trust/updater/static endpoint artifact; stale/unverified in this task and live endpoints must not be refreshed or represented as current proof. |
| ` M` | `site-build/trust/signatures/latest/SHA256SUMS.txt.sig` | restore to HEAD | Release/trust/updater/static endpoint artifact; stale/unverified in this task and live endpoints must not be refreshed or represented as current proof. |
| ` M` | `site-build/trust/signatures/latest/signatures.json` | restore to HEAD | Release/trust/updater/static endpoint artifact; stale/unverified in this task and live endpoints must not be refreshed or represented as current proof. |
| ` M` | `site-build/trust/signatures/v1.0.0/HexHawk_1.0.0_x64-setup.exe.sig` | restore to HEAD | Release/trust/updater/static endpoint artifact; stale/unverified in this task and live endpoints must not be refreshed or represented as current proof. |
| ` M` | `site-build/trust/signatures/v1.0.0/HexHawk_1.0.0_x64_en-US.msi.sig` | restore to HEAD | Release/trust/updater/static endpoint artifact; stale/unverified in this task and live endpoints must not be refreshed or represented as current proof. |
| ` M` | `site-build/trust/signatures/v1.0.0/SHA256SUMS.txt.sig` | restore to HEAD | Release/trust/updater/static endpoint artifact; stale/unverified in this task and live endpoints must not be refreshed or represented as current proof. |
| ` M` | `site-build/trust/signatures/v1.0.0/signatures.json` | restore to HEAD | Release/trust/updater/static endpoint artifact; stale/unverified in this task and live endpoints must not be refreshed or represented as current proof. |
| ` M` | `site-build/trust/signed-timestamps.json` | restore to HEAD | Release/trust/updater/static endpoint artifact; stale/unverified in this task and live endpoints must not be refreshed or represented as current proof. |
| ` M` | `src-tauri/tauri.conf.json` | keep and stage | Release/signing/updater validation source/script work; does not publish endpoints by itself and should be reviewed with conservative release claims. |
| ` M` | `website/tools/prepare-release.ps1` | keep and stage | Release/signing/updater validation source/script work; does not publish endpoints by itself and should be reviewed with conservative release claims. |
| ` M` | `yarn.lock` | keep and stage | Useful product-agnostic AETHERFRAME core/report adapter source work; must preserve GYRE/NEST authority and validate. |
| `??` | `HexHawk/src/utils/__tests__/aetherframeReportRefinementAdapter.test.ts` | keep and stage | Useful product-agnostic AETHERFRAME core/report adapter source work; must preserve GYRE/NEST authority and validate. |
| `??` | `HexHawk/src/utils/aetherframeReportRefinementAdapter.ts` | keep and stage | Useful product-agnostic AETHERFRAME core/report adapter source work; must preserve GYRE/NEST authority and validate. |
| `??` | `docs/AETHERFRAME_CORE.md` | keep and stage | Useful product-agnostic AETHERFRAME core/report adapter source work; must preserve GYRE/NEST authority and validate. |
| `??` | `docs/plans/` | needs user review | Agent plan artifact; useful context but not required for source-custody commit. |
| `??` | `docs/release-evidence/controlled_release_gate_blocked_2026-06-02_213700.json` | archive as evidence | Historical/current validation evidence; preserve as evidence but review for sensitive fields and do not treat as public release proof. |
| `??` | `docs/release-evidence/controlled_release_gate_hosted_validation_2026-06-02_204500.json` | archive as evidence | Historical/current validation evidence; preserve as evidence but review for sensitive fields and do not treat as public release proof. |
| `??` | `docs/release-evidence/controlled_release_gate_hosted_validation_rerun_2026-06-02_214500.json` | archive as evidence | Historical/current validation evidence; preserve as evidence but review for sensitive fields and do not treat as public release proof. |
| `??` | `docs/release-evidence/hosted_updater_metadata_validation_2026-06-02_181100.json` | archive as evidence | Historical/current validation evidence; preserve as evidence but review for sensitive fields and do not treat as public release proof. |
| `??` | `docs/release-evidence/hosted_updater_metadata_validation_rebuilt_unsigned_2026-06-02_220500.json` | archive as evidence | Historical/current validation evidence; preserve as evidence but review for sensitive fields and do not treat as public release proof. |
| `??` | `docs/release-evidence/official_release_custody_final_validation_2026-06-02_203600.json` | archive as evidence | Historical/current validation evidence; preserve as evidence but review for sensitive fields and do not treat as public release proof. |
| `??` | `docs/release-evidence/official_updater_custody_rehearsal_2026-06-02_181500.json` | archive as evidence | Historical/current validation evidence; preserve as evidence but review for sensitive fields and do not treat as public release proof. |
| `??` | `docs/release-evidence/official_updater_custody_validation_2026-06-02_180900.json` | archive as evidence | Historical/current validation evidence; preserve as evidence but review for sensitive fields and do not treat as public release proof. |
| `??` | `docs/release-evidence/unsigned_rebuild_release_truth_2026-06-02_220000.json` | archive as evidence | Historical/current validation evidence; preserve as evidence but review for sensitive fields and do not treat as public release proof. |
| `??` | `docs/release-evidence/updater_metadata_dns_repair_2026-06-02_173000.json` | archive as evidence | Historical/current validation evidence; preserve as evidence but review for sensitive fields and do not treat as public release proof. |
| `??` | `docs/release-evidence/windows_release_hardening_2026-06-01_235000.json` | archive as evidence | Historical/current validation evidence; preserve as evidence but review for sensitive fields and do not treat as public release proof. |
| `??` | `docs/release-evidence/windows_release_truth_consolidation_2026-06-02_171415.json` | archive as evidence | Historical/current validation evidence; preserve as evidence but review for sensitive fields and do not treat as public release proof. |
| `??` | `gui-evidence/controlled_release_gate_unsigned_native_gui_probe_2026-06-02_213600.json` | archive as evidence | Historical/current validation evidence; preserve as evidence but review for sensitive fields and do not treat as public release proof. |
| `??` | `gui-evidence/official_updater_custody_native_gui_probe_2026-06-02_181500.json` | archive as evidence | Historical/current validation evidence; preserve as evidence but review for sensitive fields and do not treat as public release proof. |
| `??` | `gui-evidence/release_hardening_native_gui_probe_2026-06-01_234839.json` | archive as evidence | Historical/current validation evidence; preserve as evidence but review for sensitive fields and do not treat as public release proof. |
| `??` | `gui-evidence/report_aetherframe_policy_native_gui_probe_2026-06-02_170827.json` | archive as evidence | Historical/current validation evidence; preserve as evidence but review for sensitive fields and do not treat as public release proof. |
| `??` | `nexus-assistant/` | ignore/local-only | Nested/adjacent assistant project; not HexHawk release-custody source state unless explicitly scoped. |
| `??` | `packages/aetherframe-core/` | keep and stage | Useful product-agnostic AETHERFRAME core/report adapter source work; must preserve GYRE/NEST authority and validate. |
| `??` | `scripts/release/build-official-windows-release.ps1` | keep and stage | Release/signing/updater validation source/script work; does not publish endpoints by itself and should be reviewed with conservative release claims. |
| `??` | `scripts/release/validate-updater-metadata.ps1` | keep and stage | Release/signing/updater validation source/script work; does not publish endpoints by itself and should be reviewed with conservative release claims. |
| `??` | `site-build/trust/keys/HXK-UPDATER-2026-06.minisign.pub` | unsafe to commit | Release/trust/updater/static endpoint artifact; stale/unverified in this task and live endpoints must not be refreshed or represented as current proof. |
| `??` | `site-build/trust/signatures/latest/HexHawk_1.0.0_x64-setup.exe.sig.sig` | unsafe to commit | Release/trust/updater/static endpoint artifact; stale/unverified in this task and live endpoints must not be refreshed or represented as current proof. |
| `??` | `site-build/trust/signatures/latest/HexHawk_1.0.0_x64_en-US.msi.sig.sig` | unsafe to commit | Release/trust/updater/static endpoint artifact; stale/unverified in this task and live endpoints must not be refreshed or represented as current proof. |
| `??` | `site-build/trust/signatures/v1.0.0/HexHawk_1.0.0_x64-setup.exe.sig.sig` | unsafe to commit | Release/trust/updater/static endpoint artifact; stale/unverified in this task and live endpoints must not be refreshed or represented as current proof. |
| `??` | `site-build/trust/signatures/v1.0.0/HexHawk_1.0.0_x64_en-US.msi.sig.sig` | unsafe to commit | Release/trust/updater/static endpoint artifact; stale/unverified in this task and live endpoints must not be refreshed or represented as current proof. |

## Cleanup plan

1. Unstage and restore `docs/credentials.md` without reading it; do not commit a deletion diff that would expose credential contents.
2. Restore tracked `site-build/releases/**`, `site-build/trust/**`, `site-build/.well-known/**`, `site-build/downloads/checksums.txt`, and `.yarn/install-state.gz` to HEAD because they are generated/stale release or package-manager artifacts for this task.
3. Remove only explicit untracked stale/generated trust sidecars under `site-build/trust/**` (`*.sig.sig` and generated updater public key) after recording this classification; do not remove broad paths.
4. Keep tracked deletions of disposable generated artifacts (`__pycache__`, `*.pyc`, LibreOffice lock file, Wix object) and stage them with `.gitignore` hygiene.
5. Keep source/docs work for AETHERFRAME core, report policy, release scripts, and evidence docs narrow and reviewable; leave `nexus-assistant/` local-only/ignored unless separately scoped.

## Evidence/archive handling

- Untracked `docs/release-evidence/*.json` and `gui-evidence/*.json` are classified as evidence, not public-release proof. They may be staged only after sensitive-field review; otherwise preserve locally.
- Generated release/trust endpoint artifacts are not archived into committed docs because that could preserve stale signatures/metadata as source truth. Their path-level classification in this artifact is the review record.

## Validation required after reconciliation

- `git diff --check`
- `yarn typecheck`
- `yarn test`
- `yarn build`
- `cargo test --workspace`
