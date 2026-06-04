# HexHawk Five-Star Upgrade Agent Prompt

Date: 2026-06-02
Purpose: reusable implementation prompt for a slow, careful, methodical HexHawk upgrade pass.
Status: prompt/agent brief only; it does not claim that signing, updater, DNS, GUI fixes, or repo inclusion decisions have been completed.

## Strategy note

This prompt is intentionally strict. HexHawk can only “pull ahead” if the implementation agent improves real product quality while preserving the trust model and release truth:

- GYRE remains the sole verdict authority.
- NEST remains evidence orchestration/convergence only.
- AETHERFRAME remains optional, bounded, product-agnostic/language-agnostic advisory uplift/refinement/lineage only.
- NEXUS remains assistant/consumer/proposal layer only.
- High-assurance mode must retain deterministic AETHERFRAME-disabled GYRE + NEST paths.
- Release claims must be proven by exact artifacts, signatures, endpoint checks, and native GUI evidence, not by historical docs.

Use this prompt in a fresh agent session from the HexHawk repo root: `D:/Project/HexHawk`.

---

## Final prompt

You are the HexHawk engineering agent. Work from `D:/Project/HexHawk` on Windows through Git Bash/MSYS unless told otherwise.

Your mission is to perform a slow, careful, methodical “five-star hotel” upgrade pass on HexHawk: raise product polish, release trust, AETHERFRAME clarity, GUI quality, and analyst workflow efficiency without overclaiming or violating HexHawk authority boundaries.

Treat this as a real engineering/release-readiness task, not a branding rewrite. Do not stop at a plan if you have permission and tools to implement. Do not fabricate outputs. If a credential, signing certificate, DNS setting, updater key, or official release environment is missing, report the blocker and produce the exact checklist/evidence requirement instead of pretending it is done.

### Non-negotiable trust boundaries

Preserve these in code, UI, docs, tests, reports, website copy, release notes, and evidence JSON:

1. GYRE owns final classification and base confidence.
2. NEST orchestrates/converges/packages evidence and may select final GYRE-linked output; it does not replace GYRE.
3. AETHERFRAME/Forge is optional bounded advisory uplift/refinement/lineage metadata. It may improve confidence packaging or recommendations only when policy permits. It must not mutate classification, source_engine, verdict truth, malware family, or GYRE sole-authority markers.
4. NEXUS is assistant/consumer/proposal/UI layer only. It must not compute security truth or final verdicts.
5. High-assurance workflows must be able to disable AETHERFRAME and present deterministic GYRE + NEST outputs directly.
6. Exports must preserve `source_engine: gyre`, `gyre_is_sole_verdict_source: true`, base/promoted confidence separation where uplift applies, and explicit null/status fields when a typed NEST evidence bundle is not embedded in a general report export.

Forbidden claims unless proven in the current session:

- “public trusted signed release”
- “updater ready”
- “native GUI parity passed”
- “AETHERFRAME decides/proves/classifies”
- “NEXUS verdict”
- “malware detonation”
- “exploitability proven”
- “better than IDA/Ghidra/Binary Ninja/x64dbg/angr” as a blanket claim

Allowed language:

- evidence-grade workflows
- local-first binary intelligence
- GYRE-linked verdicts
- NEST evidence convergence
- optional AETHERFRAME advisory uplift/refinement/lineage
- analyst-approved NEXUS proposals
- measurable workflow targets against peer tools

### Required first reads

Before editing, read these if present:

- `README.md`
- `ROADMAP.md`
- `docs/ENGINE_BOUNDARY_DOCTRINE.md`
- `docs/HIGH_ASSURANCE_GUIDE.md`
- `docs/INVESTOR_ONE_PAGER.md`
- `docs/INVESTOR_DILIGENCE_BRIEF.md`
- `docs/PERSONA_VALIDATION_REPORT_2026-05-16.md`
- `docs/RELEASE_SIGNING_AND_UPDATER_PLAN.md`
- `docs/RELEASE_VALIDATION_2026-06-01.md`
- `docs/TESTER_RELEASE_STATUS.md`
- `src-tauri/tauri.conf.json`
- `scripts/release/sign-windows-artifact.ps1`
- `scripts/release/release-hardening.ps1`
- `scripts/release/run-native-parity-probe.ps1`
- current `docs/release-evidence/*.json`
- current `gui-evidence/*.json`

Also inspect likely GUI files:

- `HexHawk/src/App.tsx`
- `HexHawk/src/styles.css`
- `HexHawk/src/components/WorkflowNav.tsx`
- `HexHawk/src/components/TopBar.tsx`
- `HexHawk/src/components/ActionBar.tsx`
- `HexHawk/src/components/DisassemblyList.tsx`
- `HexHawk/src/components/EnhancedInstructionRow.tsx`
- `HexHawk/src/components/FunctionBrowser.tsx`
- `HexHawk/src/components/IntelligenceReport.tsx`
- `HexHawk/src/components/NestView.tsx`
- `HexHawk/src/components/SettingsPanel.tsx`
- `packages/ui-components/src/HexViewer.tsx`
- `packages/ui-components/src/HexViewerEnhanced.tsx`

Inspect adjacent/local projects only for boundary decisions; do not stage them blindly:

- `AetherframeGuard/`
- `nexus-assistant/`

Never read or print `docs/credentials.md` unless the task explicitly requires live hosting/deployment credentials and the user authorizes that scope.

### Pre-change report required

Before making changes, output 3-6 lines covering:

1. What you are about to improve.
2. Likely files to touch.
3. Trust-boundary risks.
4. Validation risks.
5. Docs/release-sync risks.

Then proceed with inspection and implementation.

### Phase 1 — Current-state audit

Run a current-state audit before edits:

- `git status --short`
- Identify modified, deleted, and untracked files.
- Explicitly classify `AetherframeGuard/` and `nexus-assistant/` as release-branch decisions, not automatic HexHawk source changes.
- Inspect root `package.json` and `Cargo.toml` workspace membership.
- Inspect Tauri config signing/updater fields:
  - `bundle.createUpdaterArtifacts`
  - `bundle.windows.signCommand`
  - `plugins.updater.pubkey`
  - `plugins.updater.endpoints`
- Inspect release evidence JSON and GUI evidence JSON; treat historical evidence as historical unless artifact hashes match current live artifacts.

Current known baseline from prior inspection:

- Current docs say HexHawk is an internal-tester Windows build candidate, not a public trusted signed release.
- Current artifacts were reported unsigned in `docs/release-evidence/windows_release_hardening_2026-06-01_235000.json`.
- `src-tauri/tauri.conf.json` currently had `bundle.createUpdaterArtifacts: false` and endpoint `https://releases.hexhawk.app/releases/latest.json`.
- Prior updater validation failed because `releases.hexhawk.app` did not resolve.
- Prior native GUI parity passed only for an unsigned MSI hash recorded in `gui-evidence/release_hardening_native_gui_probe_2026-06-01_234839.json`.
- Do not reuse that as proof for a newly rebuilt/signed artifact.

### Phase 2 — Five-star GUI polish and tiny-bug pass

Goal: make HexHawk feel meticulous, responsive, and trustworthy like a premium analyst workstation. Prefer narrow, testable changes over a broad redesign.

Investigate and fix, where confirmed:

1. Mojibake/corrupt glyphs
   - Search for replacement glyphs and broken punctuation in `HexHawk/src/**`, docs, and visible UI strings.
   - Fix visible mojibake first; comment cleanup is secondary.
   - Validate with typecheck/tests.

2. Hex viewer alignment and CSS drift
   - Inspect duplicate/conflicting `.hex-cell` and related CSS in `HexHawk/src/styles.css`.
   - Consolidate into one canonical layout if duplication causes override drift.
   - Preserve 16-byte row alignment, selected/highlight/search result states, virtualization row heights, copy toolbar, and type interpreter behavior.

3. Disassembly row alignment
   - Inspect `EnhancedInstructionRow.tsx`, `DisassemblyList.tsx`, and CSS.
   - Consider a stable grid layout: address / reference strength / type / mnemonic / operands / warnings / actions.
   - Align mnemonics and operands vertically in monospace.
   - Keep virtualization height stable.

4. Runtime labeling accuracy
   - Remove misleading labels such as “Debugger (Browser Simulation)” if the code actually supports native debugger paths.
   - Use runtime-sensitive badges: Native, Browser/dev simulation, Unproven, Locked, Requires binary, Requires inspection.
   - Never claim native proof from browser/Vite tests.

5. Duplicate/unstable test IDs
   - Search for duplicate `data-testid`, especially `panel-nest`.
   - Make selectors stable and unique for native parity probes.

6. Address formatting consistency
   - Introduce or use a shared formatter for visible addresses.
   - Keep export schemas stable unless intentionally changing them.

7. Focus, keyboard, and accessibility polish
   - Add clear `:focus-visible` states for tabs, hex cells, instruction buttons, patch buttons, and major actions.
   - Add accessible names for icon-only buttons.
   - Provide Escape/outside-click close behavior for overlays/context menus.
   - Preserve analyst speed: keyboard routes should complement mouse flows.

8. Visual hierarchy
   - Each high-traffic panel should have a unique, large, plain-language heading and state summary.
   - Separate “you opened this panel” from “analysis action ran.”
   - Reduce persistent triage/recommendation rail dominance if it makes every panel look the same.
   - Keep engine authority copy visible but not noisy.

### Phase 3 — Right-click/context-menu upgrade

Use right-click better in HexHawk. Start with custom React context menus for testability and consistent UI. Only move to native Tauri menus if requirements and permissions are clear.

Implement where practical:

1. Hex byte context menu
   - On right-click a byte/cell:
     - Copy byte hex
     - Copy offset/address
     - Copy selected bytes as hex
     - Copy selected bytes as JSON array
     - Jump to disassembly if mapping exists
     - Add bookmark/annotation if existing state supports it
   - Close on Escape, outside click, scroll, and selection change.
   - Provide keyboard equivalent with Menu key or Shift+F10 if practical.
   - Test clipboard actions with mocks.

2. Disassembly row context menu
   - On right-click instruction row:
     - Copy address
     - Copy instruction
     - Copy address + mnemonic + operands
     - Show references
     - Jump to function if applicable
     - Queue invert jump only for conditional jumps
     - Queue NOP only as queued/pending analyst-approved patch action
     - Add annotation/bookmark if existing state supports it
   - Do not let patch actions bypass approval.
   - Do not imply patching or right-click actions alter verdict truth.

3. Report/evidence context menus
   - Consider right-click on evidence cards/report rows for:
     - Copy evidence ID
     - Copy source/path/address
     - Copy authority marker
     - Open related panel
   - Keep report authority fields explicit.

Tests required:

- Component tests for context menu open/close.
- Clipboard mock tests.
- Conditional action visibility tests.
- Escape/outside click tests.
- Regression tests that right-click actions do not mutate verdict classification or export authority markers.

### Phase 4 — AETHERFRAME sorted properly

Goal: separate AETHERFRAME as a product-agnostic, language-agnostic advisory refinement framework while keeping HexHawk as the first serious adapter/proving ground, not conceptual owner.

Create or repair a neutral AETHERFRAME README, preferably:

- `docs/AETHERFRAME.md` or `docs/aetherframe/README.md`

The README must include:

1. What AETHERFRAME is
   - product-agnostic
   - language-agnostic
   - adapter-friendly
   - bounded refinement/uplift/lineage/reporting layer
   - replayable and auditable

2. What AETHERFRAME is not
   - not verdict authority
   - not malware classifier
   - not exploitability proof
   - not autonomous self-rewriter
   - not a replacement for GYRE/NEST/high-assurance deterministic paths

3. Minimal input envelope
   - adapter name/domain
   - base confidence or base score
   - evidence support
   - uncertainty
   - contradiction penalties
   - lineage references
   - policy gates

4. Minimal output envelope
   - advisory confidence/ranking
   - delta from base
   - uplift reason
   - uncertainty/contradiction penalties
   - lineage
   - warnings/proof limits
   - `authority: advisory`

5. Forbidden output/mutation fields
   - classification
   - verdict
   - malware family
   - source_engine override
   - GYRE sole-authority markers
   - NEST evidence selection truth
   - hidden scope/goal/security changes

6. Adapter responsibilities
   - declare allowed mutations
   - declare forbidden mutations
   - declare stop conditions
   - declare review checkpoints
   - report proof limits
   - preserve high-assurance disable behavior

7. Simple UI guidance
   - Show AETHERFRAME as “advisory refinement/lineage.”
   - Show base vs promoted confidence only if policy permits uplift.
   - Always expose uncertainty and proof limits.
   - Keep one plain-language authority banner in analysis/report views.
   - Never use labels like “AETHERFRAME verdict.”

8. HexHawk adapter boundary
   - HexHawk may use AETHERFRAME for confidence metadata, report refinement, lineage, and recommendations.
   - HexHawk must never let AETHERFRAME alter GYRE classification.

9. AetherframeGuard adapter boundary
   - AetherframeGuard may use AETHERFRAME-style advisory host-optimization scoring only.
   - It must not claim malware/security verdict authority or guaranteed FPS uplift.

10. NEXUS consumer boundary
   - NEXUS may consume AETHERFRAME/HexHawk outputs and propose actions.
   - It does not compute final verdict truth.

If source support exists, align any AETHERFRAME adapter code with a shared contract/reporting layer. If it does not exist, document the design and do not pretend it is implemented.

### Phase 5 — AetherframeGuard and nexus-assistant decisions

Make explicit release-branch decisions. Do not silently stage or ship adjacent projects.

Known prior findings to verify:

- `AetherframeGuard/` appears to be a standalone tracked Tauri app for host hardening/CS2/Windows optimization.
- It can write ProgramData, edit CS2/Steam profile files, install/remove scheduled tasks, and use PresentMon/NVIDIA tooling.
- It contains machine-specific paths in its README/source.
- It is not in the root package/Cargo workspace by default.
- `nexus-assistant/` appears untracked and has its own nested `.git`; it is not a configured submodule.

Decision guidance:

1. AETHERFRAME concept/spec
   - Keep in HexHawk docs as neutral framework/adapter contract.

2. HexHawk AETHERFRAME adapter
   - Keep if implemented and tested as non-authoritative.

3. AetherframeGuard/
   - Do not include in HexHawk release artifacts unless the user explicitly chooses a multi-product monorepo release.
   - Prefer separate repo or quarantine/incubator branch.
   - If retained in main, add root-level note: “Adjacent standalone product; not built or shipped with HexHawk.”
   - Scrub hardcoded personal paths before any public release.
   - Add/repair README with simple UI instructions and side-effect/rollback warnings.

4. nexus-assistant/
   - Do not stage as normal HexHawk files.
   - Either remove from working tree, convert to a real submodule/subtree with explicit decision, or keep separate.
   - Clarify NEXUS as assistant/proposal layer only.

Produce a short decision artifact if needed, e.g.:

- `docs/RELEASE_BRANCH_BOUNDARY_DECISIONS.md`

Include decision, rationale, build/release impact, and required follow-up.

### Phase 6 — Real Windows signing and updater gate

Do not fake signing. Do not use a no-op `signCommand`. Do not use self-signed development certs for public/external release claims.

Real Authenticode signing requirements:

1. Obtain/configure organization-trusted Windows code-signing certificate.
2. Use one real signing identity path:
   - `HEXHAWK_CODESIGN_THUMBPRINT` for cert in Windows cert store, or
   - `HEXHAWK_CODESIGN_PFX_PATH` plus `HEXHAWK_CODESIGN_PFX_PASSWORD` if needed.
3. Do not commit PFX files, private keys, passwords, or thumbprint secrets if sensitive.
4. Sign exact artifacts:
   - `target/release/hexhawk-backend.exe`
   - `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi`
   - `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe`
5. Verify and record:
   - Authenticode status
   - signer subject
   - signer thumbprint
   - signer issuer
   - cert validity dates
   - timestamp subject
   - timestamp time, if available
   - chain trusted boolean
   - chain status/errors
   - revocation result if available
   - SHA-256, size, mtime

Existing script to inspect/use:

- `scripts/release/sign-windows-artifact.ps1`

If needed, extend evidence collection so trust chain and timestamp details are captured, not just signer/thumbprint.

Clean rebuild sequence:

```bash
rm -f target/release/hexhawk-backend.exe \
  target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi \
  target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe

yarn typecheck
yarn build
yarn test --reporter=dot
cargo check --workspace
cargo test --workspace
yarn tauri:build
sha256sum target/release/hexhawk-backend.exe \
  target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi \
  target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe
```

PowerShell signing/verification examples from Git Bash/MSYS:

```bash
powershell.exe -NoProfile -ExecutionPolicy Bypass \
  -File ./scripts/release/sign-windows-artifact.ps1 \
  -ArtifactPath ./target/release/hexhawk-backend.exe

powershell.exe -NoProfile -ExecutionPolicy Bypass \
  -File ./scripts/release/sign-windows-artifact.ps1 \
  -ArtifactPath ./target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi

powershell.exe -NoProfile -ExecutionPolicy Bypass \
  -File ./scripts/release/sign-windows-artifact.ps1 \
  -ArtifactPath ./target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe
```

Updater requirements:

1. Keep `bundle.createUpdaterArtifacts: false` for local unsigned builds.
2. Enable updater artifacts only in an official release environment where Tauri updater signing keys exist:
   - `TAURI_SIGNING_PRIVATE_KEY`
   - `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` if needed
3. Ensure `plugins.updater.endpoints` points to a reachable service.
4. Make `https://releases.hexhawk.app/releases/latest.json` resolve and serve valid Tauri updater metadata, or change config/docs to the correct endpoint.
5. Valid updater metadata must include the expected platform URL/signature shape for Windows, not merely a website downloads manifest.
6. Verify artifact URLs are reachable and updater signatures verify against the configured pubkey.

If `releases.hexhawk.app` cannot be configured in this environment, do not claim updater readiness. Record DNS/fetch failure and exact remediation.

### Phase 7 — Native GUI parity on the exact signed artifact

After any GUI change and especially after signing/rebuilding, rerun native packaged GUI parity against the exact MSI intended for testers.

Do not treat browser/Vite tests as native proof.

Required native proof:

- `hasTauriRuntime: true`
- `browserMode: false`
- `typeof window.__TAURI_INTERNALS__ === "object"`
- URL consistent with packaged Tauri, e.g. `http://tauri.localhost/`

Drive workflow:

1. Open/load binary fixture.
2. Inspect metadata.
3. Scan strings.
4. Disassemble.
5. Navigate GYRE/verdict view.
6. Run/complete NEST if available.
7. Open CREST/report/export.
8. Export JSON.
9. Validate report authority markers:
   - `source_engine: gyre`
   - `gyre_is_sole_verdict_source: true`
   - `final_verdict_snapshot`
   - NEST evidence status fields
   - no fabricated typed NEST bundle if this export path is not the typed NEST evidence export

Use:

```bash
powershell.exe -NoProfile -ExecutionPolicy Bypass \
  -File ./scripts/release/run-native-parity-probe.ps1 \
  -MsiPath ./target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi \
  -OutputPath ./gui-evidence/release_hardening_native_gui_probe_YYYY-MM-DD_HHMMSS.json
```

Evidence must bind the GUI probe to the exact signed MSI SHA-256 and Authenticode result.

### Phase 8 — Docs, website, and release evidence sync

Any change to release posture, signing, updater, GUI validation, AETHERFRAME semantics, or public claims must update docs and site output if those files currently carry the claim.

Likely docs:

- `README.md`
- `ROADMAP.md`
- `docs/ENGINE_BOUNDARY_DOCTRINE.md`
- `docs/HIGH_ASSURANCE_GUIDE.md`
- `docs/RELEASE_SIGNING_AND_UPDATER_PLAN.md`
- `docs/RELEASE_VALIDATION_YYYY-MM-DD.md`
- `docs/TESTER_RELEASE_STATUS.md`
- `docs/INVESTOR_ONE_PAGER.md`
- `docs/INVESTOR_DILIGENCE_BRIEF.md`
- `docs/PILOT_READINESS_CHECKLIST.md`
- `docs/EXTERNAL_TESTER_KNOWN_ISSUES.md`
- `site-build/**/*.html` only if website/static copy is in scope

Search for stale phrases after edits:

- `AuthentiCode-signed`
- `Authenticode-signed`
- `signed internal artifacts`
- `internal self-signed`
- `updater ready`
- `createUpdaterArtifacts: true`
- `AETHERFRAME verdict`
- `NEXUS verdict`
- `AI decides`
- stale test counts
- stale artifact hashes

### Phase 9 — Validation commands

Run the narrowest useful validation first, then expand.

For GUI/UI work:

```bash
yarn workspace hexhawk-ui exec tsc --noEmit
yarn workspace hexhawk-ui test
```

For full frontend:

```bash
yarn typecheck
yarn build
yarn test --reporter=dot
```

For backend/release:

```bash
cargo check --workspace
cargo test --workspace
yarn tauri:build
```

For release artifacts:

```bash
sha256sum target/release/hexhawk-backend.exe \
  target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi \
  target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe
```

Then run Authenticode and updater endpoint/signature checks with real tool output.

For final polish/release readiness, run native packaged GUI parity on the exact artifact.

### Required evidence JSON for release gate

If you run release-hardening, produce/update evidence under `docs/release-evidence/` with:

- generatedAt
- git branch/commit/status
- validation commands and exit codes
- artifact paths, sizes, mtimes, SHA-256
- Authenticode signer/thumbprint/timestamp/trust-chain status
- updater config and endpoint DNS/fetch/metadata/signature validation
- native GUI parity evidence path and artifact hash tested
- booleans:
  - source_validated
  - artifacts_built
  - artifacts_signed
  - public_trusted_signature
  - updater_metadata_valid
  - native_gui_parity_passed_for_exact_artifact
  - internal_tester_candidate
  - controlled_external_pilot_candidate
  - public_release_candidate

### Final report format

End with exactly these sections:

1. Files changed
2. Validation commands run
3. What passed
4. What remains risky or unproven
5. Docs/site-build sync status
6. Release posture
   - Source validated: YES/NO
   - Artifacts built: YES/NO
   - Artifacts signed: YES/NO
   - Public-trusted signature: YES/NO
   - Updater metadata valid: YES/NO
   - Native GUI parity passed for exact artifact: YES/NO
   - Internal tester candidate: YES/NO
   - Controlled external pilot candidate: YES/NO/CONDITIONAL
   - Public release candidate: YES/NO
7. AETHERFRAME boundary status
8. AetherframeGuard/nexus-assistant decision status
9. If GUI work was included: Open → Inspect → Strings → Disassembly → Verdict → NEST → Export observations, clearly separating visual coherence, action execution, native-runtime proof, and export/report parity

If something was not validated, say so plainly. Do not turn intentions into claims.

---

## Short follow-up prompt

Use this only after the implementer already understands the detailed prompt above:

Work from `D:/Project/HexHawk`. Execute a careful “five-star hotel” HexHawk upgrade pass: polish GUI alignment/tiny bugs/right-click workflows, sort AETHERFRAME into product-agnostic non-authoritative docs/UI guidance, decide AetherframeGuard/nexus-assistant release boundaries, and advance real release gates for Windows signing/updater/native parity. Preserve GYRE as sole verdict authority, NEST as evidence orchestrator, AETHERFRAME as optional advisory uplift/refinement/lineage only, and NEXUS as assistant/consumer only. Do not fake signing, updater, DNS, or native GUI proof. Validate with focused tests, full source checks where needed, exact Authenticode/updater evidence, and native packaged GUI parity on the exact signed MSI if signing succeeds. Final report must separate source validation, artifact build, signing/trust chain, updater metadata, native GUI parity, docs sync, and remaining unproven risks.
