# HexHawk — Development Roadmap

*Targets every current limitation and capability gap.*
*Organised by self-contained milestone; each one removes at least one entry from "Known Limitations" or "What HexHawk Doesn't Do".*

---

## 🔖 Session Handoff — Status as of 2026-04-29

**Milestones completed:** 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11  
**Milestone 10 status:** Completed (AI backbone + policy boundary + provider plumbing).  
**Milestone 11 status:** Completed (customer-facing BYOK settings and guardrails).  
**Milestone 12:** Planned  
**Milestones 13–18:** Planned (NEST Enterprise sequence)

### What was done (this session)
| File | Change |
|------|--------|
| `docs/leak_audit.md` | Refreshed leak status: timer cleanup and STRIKE timeline cap marked resolved; plugin timeout/thread and QUILL cache retention called out as residual risks |
| `docs/security_regression_checks.md` | Updated regression matrix with leak-related tests (timer cleanup, STRIKE timeline cap, plugin worker cap behavior) |
| `docs/security_status.md` | Refreshed security posture to reflect implemented mitigations and remaining thread/cache retention risks |
| Build/test validation | `npm run build` (root + frontend) passed; `cargo check` passed with warnings; targeted leak regression tests passed |
| `src/utils/binaryDiffEngine.ts` | **New file** — pure TS semantic diff engine; `BinarySnapshot`, `BinaryDiffResult`, `diffSnapshots()`, `extractFunctions()`, `buildFunctionSnapshot()`, `buildCfgBlockSnapshots()`; structural similarity matching (size 30% + complexity 20% + mnemonic Jaccard 50%); hotspot detection; risk assessment |
| `src/components/BinaryDiffPanel.tsx` | **New file** — Pro-tier diff UI; loads target binary via existing `invoke()` calls; six sub-tabs (Overview, Functions, Strings, Imports, Signals, CFG); clickable addresses navigate primary disassembly; color-coded added/removed/modified |
| `src/components/WorkflowNav.tsx` | Added `'diff'` to `NavView` union; added Binary Diff (⊕) to Actions group with `minTier:'pro'` and `requiresState:'fileLoaded'` |
| `src/utils/tierConfig.ts` | Added `diff: 'pro'` to `TAB_MIN_TIER` |
| `src/App.tsx` | Added `'diff'` to `AppTab` union; imported `BinaryDiffPanel`; added `diff:'diff'` to `navigateView()` mapping; added `BinaryDiffPanel` render block with full prop wiring |
| `FINAL_EVALUATION.md` | Updated Intelligence Engines table (Binary Diff row); updated CTF coverage estimate (~60% → ~65%); added AI Integration Roadmap section (Layers 1–3); updated Mythos name note; updated test coverage note |
| `ROADMAP.md` | This update — added M9 (✅), M10, M11, M12 |

**TypeScript:** 0 errors. **Tests:** 433 total — 422 passing, 11 pre-existing failures (talonLLMPass, ssaTransform, nestEngine, benchmarkHarness — unrelated to recent features). **Rust:** 28 tests, 0 failures.

### What was done (prior sessions — M7, M8)
| File | Change |
|------|--------|
| `src-tauri/src/commands/debug.rs` | Linux `ptrace(PTRACE_SINGLESTEP)` + macOS `task_for_pid`/`thread_get_state` backends added; same `RegisterSnapshot` type emitted on all platforms |
| `src-tauri/tauri.conf.json` | `entitlements.plist` → `com.apple.security.get-task-allow` for macOS debug access |
| `scripts/import-malwarebazaar.ts` | MalwareBazaar API import with SHA-256 dedup |
| `scripts/cross-validate.ts` | Stratified 80/20 harness; per-class precision/recall |
| `DEFAULT_NEST_CONFIG` | `confidenceThreshold` 85→80, `plateauThreshold` 2→3 based on 15-session empirical analysis |

### Next steps for a new session
- **Milestone 13** (first NEST Enterprise implementation milestone): NEST Enterprise Trust Baseline
- **Milestone 12** remains independent: Agent Substrate (MCP tool interface)
- Use `Challenges/` binaries for ad-hoc testing
- Run `npx tsx scripts/cross-validate.ts` after any corpus ingestion

---

## ✅ Milestone 1 — Virtualized Hex / Disassembly Views  *(Completed)*

**Removed:** *"Practical limit ~50 MB in the UI"*

The Rust `read_hex_range` command now uses seek-based I/O (`File::open + seek + read_exact`) instead of `fs::read()` which loaded the entire file into memory. A new `get_file_size` command returns the total byte count without reading content. The HexViewer React component detects scroll-near-bottom and calls `hexLoadMore`, appending the next 4 KB chunk to the view — keeping DOM overhead constant regardless of file size.

| Task | Status |
|------|--------|
| Seek-based `read_hex_range` (no full-file read) | ✅ Done — `hex.rs` rewritten |
| `get_file_size` Tauri command | ✅ Done |
| HexViewer scroll-near-bottom detection | ✅ Done — App.tsx `hexLoadMore` |
| "Load more" button + progress indicator | ✅ Done — shown in HexViewer bar |

---

## ✅ Milestone 2 — IMP: Binary Patch Engine  *(Completed)*

**Removed:** *"Cannot automatically patch jump conditions"*

| Task | Status |
|------|--------|
| `export_patched` Tauri command (copy, never original) | ✅ Done — `patch.rs` |
| `get_jump_inversion` with full x86/x64 1-byte + 2-byte jump tables | ✅ Done — `patch.rs` |
| NOP sled helper | ✅ Done — `queueNopSled` in App.tsx |
| Patch Panel sidebar (enable/disable, byte diff, export button) | ✅ Done — `PatchPanel.tsx` |
| "Invert" and "NOP" quick-action buttons on instruction rows | ✅ Done — `EnhancedInstructionRow.tsx` |

---

## ✅ Milestone 3 — TALON ARM / AArch64 IR Lifting  *(Completed)*

**Removes:** *"TALON pseudo-code x86-64 only"*

The CFG builder already handles ARM32 and AArch64 via Capstone. TALON's IR lifter is the
only x64-only layer.

| Task | Detail |
|------|--------|
| ARM32 IR lifter | ✅ Done — `decompilerEngine.ts` `liftInstructionARM32` |
| AArch64 IR lifter | ✅ Done — `decompilerEngine.ts` `liftInstructionAArch64` |
| TALON intent detection updates | ✅ Done — `talonEngine.ts` ARM prologue + svc/ldm/stm/mrs/msr patterns |
| Update TALON engine tests | ✅ Done — `talonEngine.test.ts` ARM32 + AArch64 describe blocks |

---

## ✅ Milestone 4 — Document Content Analysis  *(Completed)*

**Removes:** *"PDF / Office content analysis — format detected and hashed; no content parsing"*

HexHawk detects and hashes PDFs and Office documents but does not inspect their content
for embedded malicious payloads.

### 4a — PDF JavaScript / Stream Extraction

| Task | Detail |
|------|--------|
| `pdf_analyze` nest_cli subcommand | ✅ Done — `document.rs` `analyze_pdf` Tauri command |
| NEST signal integration | ✅ Done — `derive_pdf_signals` + `scan_js_patterns` |
| Frontend: PDF panel in TALON tab | ✅ Done — `DocumentAnalysisPanel.tsx` + `'document'` tab |

### 4b — Office Macro Extraction

| Task | Detail |
|------|--------|
| `office_analyze` nest_cli subcommand | ✅ Done — `document.rs` `analyze_office` Tauri command (OLE2 via `cfb` + OOXML via `zip`) |
| Macro scoring | ✅ Done — `scan_vba_patterns` + `derive_office_signals` |
| Frontend: Macro viewer panel | ✅ Done — `DocumentAnalysisPanel.tsx` VBA module blocks |

**Effort:** 4–6 days. Mostly Rust backend + thin UI panels.

---

## ✅ Milestone 5 — Sandboxed Script Execution  *(Completed)*

**Removes:** *"Cannot execute scripts or perform dynamic Python analysis"*

Static Python analysis already fires signals. Dynamic execution adds runtime behavior
(what it actually does when run) to the verdict.

| Task | Detail |
|------|--------|
| `run_script_sandbox` Tauri command | Spawns the target script in a subprocess with: 30-second wall-clock timeout, `ulimit`/Windows job-object memory cap (256 MB), captured stdout/stderr, network blocked via host-level firewall rule applied only to the child PID (Windows: `New-NetFirewallRule` scoped to PID; Linux: `unshare --net`). |
| Behavior capture | Monitor: files created/deleted, registry writes (Windows), environment reads. Use `strace` on Linux, ETW/`CreateToolhelp32Snapshot` on Windows — or simply diff filesystem snapshots before/after. |
| Sandbox verdict signals | Feed captured behavior into NEST signals: file drop → dropper signal, network attempt (blocked, logged) → C2 signal, process spawn → exec signal. |
| Analyst consent UI | A prominent "Run in sandbox" button in the TALON/Strings views; sandbox is never invoked automatically. |

**Effort:** 5–7 days. The cross-platform sandboxing layer is the hard part; the signal integration is already wired.

---

## ✅ Milestone 6 — Constraint Solving & Keygen Candidate Detection  *(Completed)*

**Removes:** *"Cannot derive serial numbers or keygen algorithms"*, *"No symbolic execution / concolic testing"*
**Improves:** *"HexHawk covers ~30% of CTF work"*

This is the largest milestone. The goal is not to replace angr/Z3 but to integrate them
where they already exist and surface their output inside HexHawk.

| Task | Detail |
|------|--------|
| Taint analysis pass in TALON | Extend the data-flow pass to track taint from user-controlled inputs (stdin reads, `GetDlgItemText`, argv). Mark all SSA values that carry taint through the IR. |
| Keygen shape detection | Pattern-match on tainted data paths: input → arithmetic transform → comparison with constant → branch. This is the canonical serial check shape. Report it as a "key check candidate" annotation on the relevant basic block. |
| Z3 integration (optional bridge) | For detected key check shapes, emit the constraint in SMT-LIB2 format. Provide a "Solve with Z3" button that calls `z3` as a subprocess and displays candidate inputs that satisfy the constraint. Requires Z3 to be installed separately (document in README). |
| CTF coverage improvement | With taint + constraint output, HexHawk's estimated CTF coverage increases from ~30% to ~60%. The remaining gap (anti-tamper, VM-based obfuscation, multi-stage loaders) is left for the analyst. Update documentation accordingly once shipped. |

**Effort:** 10–15 days. The taint pass is the core investment; Z3 bridge is opt-in.

---

## ✅ Milestone 7 — STRIKE Cross-Platform Debug Backend  *(Completed)*

**Removed:** *"STRIKE uses real Windows debug API — Linux/macOS targets not supported"*

STRIKE's behavioral delta engine is architecture-agnostic; only the debug loop is
platform-specific.

| Task | Detail |
|------|--------|
| Linux ptrace backend | ✅ Done — `ptrace(PTRACE_SINGLESTEP)` via `nix` crate; `user_regs_struct` → `RegisterSnapshot` |
| macOS task_for_pid backend | ✅ Done — `task_for_pid` + `thread_get_state`; `entitlements.plist` `com.apple.security.get-task-allow` |
| Unified behavioral delta | ✅ Done — `strikeBehaviorAnalyzer.ts` unchanged; same `RegisterSnapshot[]` type consumed on all platforms |
| CI matrix | ✅ Done — Linux runner added to `ci.yml` |

**Effort:** 5–8 days. Linux is lower risk (ptrace well-documented in Rust); macOS entitlement handling adds friction.

---

## ✅ Milestone 8 — NEST Corpus Expansion  *(Completed)*

**Removed:** *"NEST training corpus is small — 17 labelled entries; false-convergence risk on unusual binary profiles"*

A larger, more diverse corpus improves verdict accuracy and reduces false convergence.

| Task | Detail |
|------|--------|
| Automated corpus ingestion CLI | ✅ Done — `nest_cli ingest <dir>` with `--label` flag; appends to `corpus/results.json` |
| Public dataset import | ✅ Done — `import-malwarebazaar.ts` via MalwareBazaar API; SHA-256 deduplicated |
| Cross-validation harness | ✅ Done — `cross-validate.ts` stratified 80/20; per-class precision/recall reported |
| Convergence guard tuning | ✅ Done — `confidenceThreshold` 85→80, `plateauThreshold` 2→3 based on 15-session empirical analysis |

**Effort:** 3–4 days for tooling; corpus quality is an ongoing process.

---

## ✅ Milestone 9 — Binary Diff / Version Tracking  *(Completed)*

**Removes:** *"No binary version comparison — cannot identify what changed between two builds"*

A pure TypeScript semantic diff engine that compares two binary snapshots across every analysis dimension HexHawk already computes. No new Tauri backend commands required — all data comes from existing `invoke()` calls.

| Task | Detail |
|------|--------|
| `binaryDiffEngine.ts` | **New file** — `BinarySnapshot`, `BinaryDiffResult`, `diffSnapshots()`. Function matching: Pass 1 = exact address; Pass 2 = structural similarity ≥ 70% (size 30% + complexity 20% + mnemonic Jaccard 50%). String/import/signal set diffs. CFG block diff by `start` address. Hotspot top-20. Risk assessment. |
| `BinaryDiffPanel.tsx` | **New file** — Pro-tier gated. Loads target binary entirely via `inspect_file_metadata` + `find_strings` + `disassemble_file_range` (max 4096 instrs) + `build_cfg` (optional) + `computeVerdict`. Six sub-tabs: Overview, Functions, Strings, Imports, Signals, CFG. Click any address → `onJumpToAddress()` navigates primary disassembly. |
| `WorkflowNav.tsx` | Added `'diff'` to `NavView` union; Binary Diff entry in Actions group (`minTier:'pro'`, `requiresState:'fileLoaded'`) |
| `tierConfig.ts` | `diff: 'pro'` added to `TAB_MIN_TIER` |
| `App.tsx` | `'diff'` to `AppTab` union; `BinaryDiffPanel` import + render block; `diff:'diff'` in `navigateView()` |

**TypeScript:** 0 errors. Accessible via **Actions → Binary Diff (⊕)** in WorkflowNav.

---

## ✅ Milestone 10 — AI Analyst Assist Backbone  *(Completed)*<a name="milestone-10"></a>

**Delivered foundation:** local AI command boundary, provider abstraction, secure key storage, and policy enforcement for explicit approval and privacy guardrails.

This milestone established the backend and policy layer that customer-facing AI depends on:

- backend command module with provider routing (OpenAI, Anthropic, Ollama)
- Stronghold-backed secret handling and provider key lifecycle commands
- explicit approval gating, endpoint policy checks, redaction, budget and timeout enforcement
- frontend utility surface for analyst-assist actions

The richer user-facing AI flows remain layered on top of this foundation and continue in Milestone 12.

| Delivered item | Detail |
|------|--------|
| `llm_query` Tauri command | Provider-aware query routing and response normalization |
| Secure provider key lifecycle | `store_llm_provider_key`, `clear_llm_provider_key`, `has_llm_provider_key` |
| Stronghold secret boundary | Provider keys stored outside ordinary frontend settings |
| Policy enforcement | Explicit approval + endpoint validation + budget/timeout checks + redaction |
| Frontend utility layer | `HexHawk/src/utils/aiAnalystAssist.ts` action wrappers |

**Result:** Backbone shipped and documented in `docs/m10_ai_backbone.md`.

---

## ✅ Milestone 11 — Customer-Facing AI (Bring-Your-Own-Key)  *(Completed)*

**Delivered:** Customer-facing BYOK controls and safety gates on top of Milestone 10.

Customers now configure provider-specific keys from settings/TALON flow with explicit opt-in behavior. The key belongs to the customer and remains in secure backend storage.

| Delivered item | Detail |
|------|--------|
| Provider-aware key management | Per-provider store/clear/status UX for OpenAI, Anthropic, Ollama |
| Explicit privacy/consent gates | No silent/background calls; explicit approval and disclosure acknowledgment |
| Feature/provider toggles | Customer controls per-provider and per-feature activation |
| Session token cap behavior | Guardrails in frontend flow with backend budget checks |
| Graceful fallback | Missing/invalid key and local provider outages degrade safely |

**Result:** BYOK layer shipped and documented in `docs/m11_byok_ai.md`.

---

## Milestone 12 — Agent Substrate (MCP Tool Interface)

**Adds:** *HexHawk as a structured tool environment for external AI agents*

As frontier cybersecurity models (including restricted-access models like Anthropic's Mythos Preview) become available via API or local deployment, analysts may want to run them *through* HexHawk rather than *alongside* it.

| Task | Detail |
|------|--------|
| `hexhawk_tool_schema.json` | MCP-compatible tool definitions for: `inspect`, `disassemble`, `strings`, `build_cfg`, `diff_snapshots`, `nest_results`, `apply_patch` |
| MCP server mode | `nest_cli serve --mcp` starts a local stdio MCP server; external agents (Claude Desktop, GPT-4 with tools, local agent frameworks) can connect and call HexHawk tools |
| Agent signal injection | Agent-returned findings are wrapped as `CorrelatedSignal` entries with `source:'agent'` and fed into `computeVerdict()` |
| Human approval gate | Any `apply_patch` tool call surfaces in the IMP patch queue for analyst approval before bytes are written; agents cannot bypass this gate |
| Agent action log | All tool calls recorded in a session log section of the CREST export |

**Effort:** 7–10 days. MCP protocol is well-specified; the main work is mapping HexHawk's existing commands to the tool schema and wiring agent signals into GYRE.

---

## Milestone 13 — NEST Enterprise Trust Baseline

**Adds:** *File-bound, replayable NEST session evidence as a product contract*

This milestone establishes the minimum trust baseline required before any enterprise claim can be made about NEST. The recent runtime work proved file-bound confidence for the tested crossfile workflow, but NEST still needs its own session-level evidence contract.

Dependencies:
- Requires the current runtime evidence baseline validated in `docs/final_filebound_validation.md`
- Builds on existing NEST artifacts from `scripts/run-nest.ts` and `nest_cli`
- Does **not** depend on Milestone 12

| Task | Detail |
|------|--------|
| Session manifest schema | Define versioned `session.json`, `iterations.json`, `deltas.json`, and `manifest.json` formats for NEST sessions; include `session_id`, `binary_sha256`, `config_version`, `engine_build_id`, `actor_id`, timestamps, and schema version |
| File-bound proof block | Persist `sha256`, `sha1`, `md5`, file size, format, architecture, and first-seen timestamp at the session root and in each iteration snapshot |
| Delta ledger | Formalize per-iteration delta records: added/removed signals, confidence delta, classification delta, contradiction delta, executed refinement action, projected gain vs actual gain |
| NEST runtime fidelity gate | Add a NEST-specific runtime validation gate proving the NEST-enriched output references the current binary identity when run through the UI |
| Replay contract | Make a completed NEST session replayable from artifacts alone without relying on renderer state |

Exit criteria:
- Every NEST session emits a versioned evidence bundle with manifest, iteration ledger, and delta ledger
- A reviewer can answer "which exact file did NEST analyze?" from artifacts alone
- Session continuation fails if binary identity changes mid-session
- GYRE remains the sole verdict source; NEST artifacts only enrich and document analysis

**Effort:** 4–6 days. Mostly schema work, artifact formalization, and runtime proof wiring.

---

## Milestone 14 — NEST Enterprise Local Governance

**Adds:** *Backend-owned session lifecycle, local RBAC, and append-only audit logs*

This milestone moves NEST from renderer-owned orchestration to a trusted local control boundary. The target is single-host governance first, not remote deployment.

Dependencies:
- Requires Milestone 13
- Independent of Milestone 12

| Task | Detail |
|------|--------|
| Tauri command boundary | Add backend-owned commands for `create_nest_session`, `run_nest_iteration`, `finalize_nest_session`, `export_nest_session_artifacts` |
| Local session record store | Persist session metadata and state outside transient renderer memory |
| Append-only audit stream | Record `nest.session.created`, `nest.iteration.started`, `nest.iteration.completed`, `nest.session.converged`, `nest.session.exported`, with actor id, actor type, binary hash, policy version, and timestamp |
| Role model | Introduce local roles: analyst, reviewer, approver, admin |
| Permission checks | Restrict export approval, corpus promotion, and policy overrides to reviewer/approver roles |

Exit criteria:
- NEST lifecycle mutations are backend-owned and audit-logged
- Renderer/UI is no longer the trust boundary for NEST session state
- Local roles and permission checks are enforced for sensitive actions
- No NEST run, re-run, export, or override occurs silently

**Effort:** 5–7 days. Mostly Tauri command surface, persistence, and permission enforcement.

---

## Milestone 15 — NEST Corpus Governance

**Adds:** *Governed corpus registry instead of flat JSON append workflow*

Milestone 8 expanded corpus volume. This milestone governs corpus trust.

Dependencies:
- Requires Milestone 14
- Builds on existing ingestion utilities: `nest_cli ingest`, `import-malwarebazaar.ts`, `cross-validate.ts`

| Task | Detail |
|------|--------|
| Corpus registry model | Replace or wrap `corpus/results.json` with records containing entry id, file hash, source, label, expected class, tags, notes, proposer, reviewer state, approval state, and supersession links |
| Lifecycle states | Support `draft`, `approved`, `quarantined`, and `retired` corpus entries |
| Review queue | Add reviewer flow for label proposals, disputes, and promotion decisions |
| Approved-slice validation | Update `cross-validate.ts` to run only against approved corpus slices |
| Provenance and rollback | Track who proposed, who approved, and what entry superseded or retired an older record |

Exit criteria:
- Corpus ingestion no longer appends directly to production training/benchmark data
- Cross-validation runs only on approved corpus entries
- Corpus record provenance, reviewer status, and rollback path are visible and auditable
- Label changes require review rather than silent overwrite

**Effort:** 5–8 days. Data model and tooling migration dominate the work.

---

## Milestone 16 — NEST Enterprise API and Automation

**Adds:** *Authenticated API surface and service-account execution path*

This milestone creates the actual machine-consumable contract for enterprise integration. `nest_cli` can remain a worker, but it must stop being the enterprise interface.

Dependencies:
- Requires Milestones 13, 14, and 15
- Remains independent of Milestone 12

| Task | Detail |
|------|--------|
| Session API DTOs | Define stable request/response schemas for session creation, retrieval, iteration listing, artifact lookup, and approval actions |
| Local API surface | Expose NEST session operations through Tauri commands first; optional local HTTP bridge later |
| Service accounts | Add machine identities with scoped permissions for replay, regression, ingestion proposal, and export jobs |
| Job runner | Introduce queued automation for nightly replay, regression evidence generation, and approved corpus cross-validation |
| Auth and policy guards | Ensure API calls include actor identity, policy version, and rate/permission checks |

Exit criteria:
- Enterprise automation no longer depends on shelling out to `nest_cli` and parsing stdout
- Service-account runs are attributable in the audit log
- API responses include schema version and artifact/evidence references
- Automated runs cannot bypass corpus approval or verdict ownership rules

**Effort:** 6–9 days. API shape and automation queueing are the main risks.

---

## Milestone 17 — NEST Team Workflows and Evidence Packaging

**Adds:** *Reviewer/approver workflows and exportable NEST evidence bundles*

This milestone turns NEST from a personal workstation loop into a reviewable team process.

Dependencies:
- Requires Milestones 13–16
- Depends on local governance and API surface being in place first

| Task | Detail |
|------|--------|
| Reviewer work queues | Add queues for pending session review, corpus proposals, export requests, and override requests |
| Approver actions | Add explicit approval flows for corpus promotion, contested label changes, policy overrides, and external evidence export |
| Evidence bundle packaging | Produce export bundles containing `manifest.json`, `binary_identity.json`, `session.json`, `iterations.json`, `deltas.json`, `final_verdict_snapshot.json`, `audit_refs.json`, and optional review summary |
| Hash manifest | Hash every exported file and list all hashes in the manifest with schema version and build id |
| CREST alignment | Keep bundle structure aligned with CREST export semantics where possible without making NEST the verdict authority |

Exit criteria:
- A reviewer can inspect and approve a NEST session without opening raw internal state
- Evidence exports are versioned, hashed, and replayable
- Reviewer and approver roles are actually exercised in the product flow
- Export packages clearly distinguish NEST enrichment from GYRE verdict output

**Effort:** 5–8 days. Mostly workflow UI plus artifact packaging.

---

## Milestone 18 — NEST Optional Centralized Deployment

**Adds:** *Multi-user centralized NEST execution mode*

This milestone is optional. It should not start until the local enterprise model is complete. The goal is deployment flexibility, not redefinition of trust semantics.

Dependencies:
- Requires Milestones 13–17
- Optional and can be deferred without weakening local enterprise claims

| Task | Detail |
|------|--------|
| Central session store | Move session records, audit logs, and corpus registry to a shared backing store |
| Worker execution model | Run NEST orchestration in background workers or service processes rather than in the desktop client |
| Job scheduling | Support multi-user queueing, retries, cancellation, and retention policies |
| Desktop-as-client mode | Keep HexHawk desktop as a client to centralized NEST execution, not the authority of record |
| Deployment parity checks | Ensure centralized mode preserves the same evidence schema, audit semantics, and GYRE ownership rules as local mode |

Exit criteria:
- Centralized deployment does not change evidence semantics or verdict ownership
- Multi-user teams can submit, review, and export NEST sessions through a shared control plane
- Retention, replay, and audit policies are enforced centrally
- No enterprise-ready claim depends on centralized deployment existing; it remains an optional deployment mode

**Effort:** 8–12 days. Mainly serviceization, queueing, and data-store hardening.

---

## Summary

| Milestone | Limitations Resolved | Effort | Status |
|-----------|---------------------|--------|--------|
| 1 — Virtualized views | 50 MB UI limit | 1–2 days | ✅ Complete |
| 2 — IMP patch engine | Jump patching, NOP sleds | 2–3 days | ✅ Complete |
| 3 — TALON ARM | ARM/AArch64 pseudo-code | 3–5 days | ✅ Complete |
| 4 — Document analysis | PDF JS, Office macros | 4–6 days | ✅ Complete |
| 5 — Sandboxed script execution | Dynamic Python/script analysis | 5–7 days | ✅ Complete |
| 6 — Constraint solving | Keygen derivation, symbolic reasoning, CTF coverage 30% → 60% | 10–15 days | ✅ Complete |
| 7 — STRIKE cross-platform | Linux/macOS debug support | 5–8 days | ✅ Complete |
| 8 — NEST corpus expansion | False-convergence risk | 3–4 days + ongoing | ✅ Complete |
| **9 — Binary Diff** | **Semantic version comparison gap** | **4–6 days** | **✅ Complete** |
| 10 — AI Analyst Assist | AI backbone / provider boundary / policy-safe invocation | 7–10 days | ✅ Complete |
| 11 — Customer BYOK AI | Bring-your-own-key LLM support | 5–7 days | ✅ Complete |
| 12 — MCP Agent Substrate | Agent tool schema, HexHawk as MCP server | 7–10 days | 🔲 Planned |
| 13 — NEST trust baseline | File-bound NEST evidence contract, manifests, delta ledger | 4–6 days | 🔲 Planned |
| 14 — NEST local governance | Backend-owned lifecycle, local RBAC, append-only audit log | 5–7 days | 🔲 Planned |
| 15 — NEST corpus governance | Governed corpus registry, approvals, approved-slice validation | 5–8 days | 🔲 Planned |
| 16 — NEST API and automation | Authenticated API surface, service accounts, job runner | 6–9 days | 🔲 Planned |
| 17 — NEST team workflows | Reviewer/approver queues, evidence bundles, export packaging | 5–8 days | 🔲 Planned |
| 18 — NEST centralized deployment | Optional shared control plane and worker mode | 8–12 days | 🔲 Planned |

**Remaining effort:** Milestones 1–11 complete. Milestone 12 is independent. Milestones 13–18 form the NEST Enterprise sequence and should be executed in order because each one establishes the trust boundary required by the next.
**Dependency note:** Milestone 12 can run in parallel with Milestone 13. Milestones 13→18 are intentionally sequential. Do not claim NEST Enterprise readiness until the exit criteria for Milestones 13–17 are met; Milestone 18 remains optional deployment work.

---

*Each completed milestone should remove the corresponding row from the Known Limitations table and the corresponding bullet from "What HexHawk Doesn't Do" in [FINAL_EVALUATION.md](FINAL_EVALUATION.md).*
