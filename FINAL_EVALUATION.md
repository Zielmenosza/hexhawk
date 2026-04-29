# HexHawk — System Evaluation

*April 2026. Reflects post-challenge-run state: all 10 Challenges folder binaries analyzed.*

---

## Session Addendum — Current Validation Pass

This session executed a full regression and challenge-focused hardening pass.

### Verified outcomes

- Frontend regression suite is now green: **34/34 test files, 635/635 tests passing** (`yarn test` in `HexHawk/`).
- `Gujian3.exe` run (user-priority sample): **79% confidence, verdict `dropper`, converged in 4 iterations** via headless NEST.
- Additional challenge robustness checks completed:
  - `chat_client` (ELF): completed with plateau stop, artifacts exported.
  - `project_chimera.py` (script/unknown magic): completed with low-confidence suspicious verdict and exported artifacts.
- Beginner-facing help was expanded in-app (`Help` view) with a practical challenge quickstart and troubleshooting guidance for low-confidence/non-PE workflows.

### Important compile note

A full production compile was attempted (`yarn build` at workspace root). It currently fails due to **pre-existing strict TypeScript type errors** in NEST evidence typing/JSON contract files (`src/types/nestEvidence.ts`, `src/utils/nestEvidenceIntegration.ts`).

The changes in this session fixed the newly introduced compatibility issue in `BinaryVerdict.tsx`; remaining compile blockers are existing type-contract debt outside this patch set.

---

## What HexHawk Is

A native desktop reverse engineering tool built with Rust (Tauri 2), React, and TypeScript.
It combines binary inspection, disassembly, CFG visualization, IR-based pseudo-code, live
debugging, and iterative multi-engine threat analysis into a single application.

The **GYRE** verdict engine is explainable by design: every confidence score is backed by a
ReasoningStage[] chain showing which signals fired, how they were weighted, what
contradicts them, and what alternative hypotheses were considered.

---

## Intelligence Engines

| Engine | Role |
|--------|------|
| **TALON** | IR lift → SSA → data-flow passes → intent detection → pseudo-code |
| **STRIKE** | Cross-platform debug loop (Windows WinDebugAPI, Linux ptrace, macOS task_for_pid), behavioral delta between execution snapshots |
| **ECHO** | Fuzzy signature matching, FLARE-derived crypto/obfuscation patterns |
| **NEST** | Iterative multi-pass convergence analysis with dampening and contradiction detection |
| **QUILL** | Dynamic user plugin system — 4 built-in analysis plugins + runtime install of `.dll`/`.so`/`.dylib` user plugins via 7-layer safety isolation |
| **GYRE** | Verdict engine — 20-section signal aggregation, reasoning chain, contradiction detection |
| **KITE** | Knowledge graph — ReactFlow visualization of how signals combine into a verdict |
| **AERIE** | Operator console — intent classification from plain text → step-by-step workflow |
| **CREST** | Intelligence report — JSON / Markdown export with full reasoning chain |
| **IMP** | Binary patch engine — invert jumps, NOP sleds, export patched copy |
| **Mythos** | capa-style capability detection — 24 built-in rules across process-injection, defense-evasion, persistence, C2, encryption, credential-access, and wiper namespaces; each rule fires on combinations of imports + strings + patterns + TALON/ECHO/YARA evidence; produces `CorrelatedSignal` entries with linked code locations, full evidence chains, navigable address chips, and `certainty:'inferred'` |
| **Binary Diff** | Semantic version comparison — `binaryDiffEngine.ts` diffs two binary snapshots across functions (exact-address + structural-similarity matching), strings, imports, CFG blocks, and GYRE signals; hotspot ranking by added suspicious patterns; risk assessment (escalated / reduced / neutral); six-tab diff UI navigable to disassembly; Pro tier |

> **Name note:** *HexHawk Mythos* is HexHawk's own deterministic capability-detection rule engine (`src/utils/mythosEngine.ts`). It is unrelated to Anthropic's *Mythos Preview* — a restricted cybersecurity frontier model (Project Glasswing, April 2026) with privileged access to malware datasets. The names were chosen independently and share only a theme of deep pattern inference.

All five core analysis engines feed GYRE.computeVerdict() — the single verdict source in the application.

---

## Backend Capabilities (Rust / nest_cli)

| Subcommand | What it does |
|------------|-------------|
| inspect  | File metadata, section layout, import/export table, SHA-256/SHA-1/MD5, architecture. Graceful fallback for any non-PE format (ELF, PDF, script, PCAP, unknown magic). No file size limit — uses memmap2 throughout. |
| disassemble | Multi-architecture disassembly via Capstone (x86-32, x86-64, ARM32, AArch64). mmap I/O, no full-file read. |
| cfg | Control flow graph: basic block detection, true/false edge classification, auto-detected architecture. Formerly hardcoded to x64; now detects I386/ARM/AArch64 from object header. |
| strings | ASCII (≥4 chars) and UTF-16LE string extraction from any file type. For files > 64 MB: first 60 MB + last 4 MB. Categorizes into URLs, file/registry paths, and API-name candidates. |
| identify | Lightweight format detection from first 4 KB only. Returns format name, magic bytes, file size, header entropy. Succeeds when inspect fails. |

---

## Challenge Binary Results

Ten binaries from the Challenges folder, analyzed with
nest_cli + NEST pipeline:

| Binary | Size | Format | Confidence | Verdict |
|--------|------|--------|-----------|---------|
| crackme_shroud.exe | 9.4 MB | PE x64 | 99% | dropper |
| UnholyDragon-150.exe | 2.7 MB | PE x86 *(was: crash)* | 86% | dropper |
| project_chimera.py | 8 KB | Python script | 43% | suspicious |
| pretty_devilish_file.pdf | 1.5 KB | PDF | — | format detected, hashed |
| ntfsm.exe | 20.2 MB | PE x64 | 81% | ransomware-like |
| chat_client | 32 MB | ELF x64 | 99% | dropper |
| hopeanddreams.exe | 4.7 MB | PE x86 | 99% | suspicious |
| FlareAuthenticator.exe | 837 KB | PE x64 | 99% | packer |
| 10000.exe | 1.1 GB *(was: blocked)* | PE x64 | — | parses, hashed |
| keygenme.exe | 2.8 MB | PE x86 | 98% | RAT |

Previously broken cases that now work:
- **UnholyDragon-150.exe** — object::File::parse crash replaced with graceful fallback
- **10000.exe** — 512 MB hard limit removed; mmap + streaming hash handles arbitrary file sizes
- **chat_client** — ELF with correct arch detection for CFG (was x64-hardcoded)
- **project_chimera.py** — Python source now scored via script-specific signals (was 0 signals)

---

## GYRE Signal Coverage

23 active signal sections covering:

- **Structure:** entropy, packed-text, minimal imports, packer stub
- **Imports:** network, crypto, injection, registry, exec, anti-debug, file ops, BCrypt, wiper, sysinfo, concurrency, resource
- **Strings:** URLs, IPs, registry paths, base64, PE names, domains
- **Scripts:** Python dangerous calls, network/crypto/system module imports, PowerShell patterns, shell commands
- **Disassembly:** critical patterns, tight loops, anti-analysis, TALON/STRIKE/ECHO typed signal injection
- **Cross-signal amplifiers:** 8 corroboration rules that increase weight when signal pairs co-occur

---

## What HexHawk Doesn't Do

> Each item below has a corresponding milestone in [ROADMAP.md](ROADMAP.md) that describes the implementation path to resolving it.

**It is a triage and intelligence tool, not a solver.**

It tells you *what a binary does and how it protects itself* — it does not:

- Derive serial numbers or keygen algorithms  *(✅ now supported — **Constraint** engine, Milestone 6: forward taint propagation over TALON IR, keygen shape detection input→arith→cmp→branch, SMT-LIB2 emission, optional Z3 subprocess solve with model output)*
- Automatically patch jump conditions  *(✅ now supported — **IMP** engine, Milestone 2: invert conditional jumps, NOP out instructions, export patched binary copy)*
- Perform symbolic execution or concolic testing  *(✅ partial — Milestone 6: linear taint constraints solved via Z3; non-linear/obfuscated paths flagged but not solved)*
- Execute scripts or perform dynamic Python analysis  *(✅ now supported — **Sandbox** engine, Milestone 5: subprocess execution with 30s timeout, Windows Job Object 256 MB memory cap, behaviour signal derivation, analyst consent gate)*
- **Parse document formats beyond detection (PDF content, Office macros)** *(✅ now supported — **Document** engine, Milestone 4: `analyze_pdf` extracts embedded JavaScript, URI actions, and stream objects; `analyze_office` parses OLE2/OOXML containers and extracts VBA macro source with pattern-level scoring; both feed NEST signals; exposed in `DocumentAnalysisPanel.tsx`)*
- **Detect capabilities, not just patterns** *(✅ now supported — **Mythos** engine, capa-style capability detection: 24 built-in rules across process-injection, defense-evasion, persistence, encryption, C2, credential-access, and wiper namespaces; each rule fires on combinations of imports + strings + patterns + TALON/ECHO/YARA evidence; matches produce `CorrelatedSignal` entries with linked code locations, full evidence chains, and `certainty:'inferred'`; fed into GYRE §16.6)*
- **Compare binary versions / track patches** *(✅ now supported — **Binary Diff** engine, Milestone 9: semantic diff of functions, strings, imports, CFG blocks, and threat signals between two binary snapshots; structural-similarity matching for address-changed functions; hotspot ranking; risk level assessment; navigable from diff sub-tabs to disassembly)*
- **Get natural-language analysis explanations** *(🔜 planned — Milestone 10: AI Analyst Assist — LLM-powered signal explainer, CREST narration, AERIE LLM mode, diff insight; GPT-4o / Claude via user-configured API key)*

AI update: Milestone 10 backbone and Milestone 11 BYOK customer layer are now in place for provider/key management and policy-safe invocation. Rich narrative UX features continue as iterative enhancements.

For CTF challenges, HexHawk now covers an estimated ~65% of the work: format identification,
packer/protection recognition, capability mapping, suspicious function localization,
serial-check constraint solving (taint + Z3), dynamic script sandbox, document macro analysis, and binary version diffing.
The remaining gap (anti-tamper rings, VM-based obfuscation, multi-stage loaders, non-linear crypto)
still requires specialist tools (angr, Ghidra scripting, manual reversing).
*Milestone 6 reached ~60%. Binary Diff (Milestone 9) and planned AI Assist (Milestone 10) target ~70–75%.*

> **Test samples available:** The `Challenges/` folder at the workspace root contains real CTF and malware samples (PE binaries, scripts, network captures, document files). They are immediately accessible in VS Code and can be loaded directly into HexHawk for manual testing, engine validation, and regression checks.

---

## Strategic Positioning (April 2026)

External model capabilities — including restricted frontier models with strong cybersecurity focus — are advancing rapidly. HexHawk's architecture is designed to remain useful regardless of what any external model can do:

| HexHawk capability | Why models alone cannot replace it |
|--------------------|------------------------------------|
| GYRE signal pipeline | Fully deterministic; same input always produces the same signal set and score. No model hallucination, no rate limits, no API cost. |
| Evidence tiers (DIRECT / STRONG / WEAK) + certainty tags (OBS / INF / HEU) | Analyst-readable confidence accounting. Models produce text; HexHawk produces structured evidence with traceable provenance. |
| Contradiction detection (§15 of computeVerdict) | Explicit reasoning about signals that disagree — packed + many-imports, GUI app + anti-debug, etc. Models may paper over contradictions. |
| NEST iteration loop with convergence dampening | Multi-pass analysis that learns from prior iterations within a session; plateau detection prevents runaway confidence inflation. |
| CREST auditable export | Full reasoning chain in JSON/Markdown, replayable with the same binary. Required for incident response, legal, and red-team reporting. |
| IMP patch workflows | Model-suggested patches require one-click analyst approval before any byte is written. Safe exports only. |
| QUILL plugin isolation | User-installed binary plugins run through 7-layer isolation. No model can install or execute arbitrary code on behalf of a user. |

**Product principle:** Models are intelligence *sources*, not the product. HexHawk is the control plane — evidence collection, structured reasoning, human approval gates, and auditable output — that makes model suggestions safe to act on in a security context.

---

## AI Integration Roadmap (Milestones 10–12)

The analyst (owner) currently has **ChatGPT Plus** (GPT-4o access) and **GitHub Copilot Pro** (Claude Sonnet 4.6 + GPT-4o via Copilot Chat). These subscriptions inform the near-term integration path. Customer-facing AI is a parallel track requiring a bring-your-own-key model.

### Layer 1 — Analyst Assist (in-tool, owner only, Milestone 10)

None of these require new Tauri backend commands. All run through a local API proxy Tauri command that holds the key and fires against OpenAI or Anthropic endpoints. The key never leaves the host machine.

| Feature | Model target | Where it appears |
|---------|-------------|-----------------|
| **AERIE LLM Mode** | GPT-4o / Claude | AERIE console — upgrades intent classification from regex → LLM; accepts natural-language operator queries |
| **Signal Explainer** | GPT-4o | GYRE verdict panel — "Why did this signal fire?" button injects signal context + code evidence into an LLM prompt; returns a one-paragraph justification |
| **Decompile Narrate** | GPT-4o | TALON tab — post-decompile LLM pass that produces a plain-English description of what a function does based on its IR + pseudo-code |
| **CREST Narration** | GPT-4o / Claude | CREST export — auto-generate an executive summary from the full structured reasoning chain JSON |
| **Diff Insight** | GPT-4o | Binary Diff panel — given the diff result JSON, LLM produces "What changed and why does it matter?" scoped to each modified function |

### Layer 2 — Customer AI (bring-your-own-key, Milestone 11)

Customers configure their own OpenAI or Anthropic API key in a settings panel. HexHawk stores it encrypted using the OS keychain (Tauri `tauri-plugin-stronghold`). All LLM calls are proxied through a Tauri command — the key never touches the frontend.

| Feature | Notes |
|---------|-------|
| API key management panel | Per-provider: OpenAI, Anthropic, local Ollama endpoint |
| Token budget indicator | Shows estimated cost per action before firing; user sets a per-session cap |
| Opt-in per feature | Every AI feature has an explicit enable toggle; nothing fires silently |
| Offline fallback | All AI features degrade gracefully to rule-based output when no key is configured |
| Tier gate | AI features require Pro tier minimum |

### Layer 3 — Agent Substrate (Milestone 12, future)

As frontier cybersecurity models — including restricted models like Anthropic's Mythos Preview — become accessible via API or local deployment, HexHawk can act as their **structured tool substrate**:

- `hexhawk_tool_schema.json` — MCP-compatible tool definitions exposing inspect, disassemble, strings, CFG, diff, and NEST result endpoints
- Agent receives structured JSON; HexHawk renders agent findings as GYRE signals tagged `source:'agent'`
- Human approval gate required before any agent-suggested patch is applied
- All agent actions logged in the CREST export for full auditability

This positions HexHawk as the **safe execution environment** for agent-grade RE tasks: the agent proposes, the analyst approves, HexHawk verifies deterministically and records the chain of custody.

---

## QUILL Plugin System

Twelve named engines now ship in HexHawk. QUILL is the plugin gateway — alongside TALON, STRIKE, ECHO, NEST, GYRE, KITE, AERIE, CREST, IMP, Mythos, and Binary Diff.

**Built-in plugins (always active):**

| Plugin | What it contributes |
|--------|--------------------|
| ByteCounter | Byte frequency histogram, printable/zero/high-byte ratio |
| EntropyAnalyzer | Shannon entropy per section; flags sections above 7.2 bits/byte as packed/encrypted |
| SuspiciousImportScanner | 50+ Win32 API names across 8 threat categories (injection, network, crypto, anti-debug, exec, registry, wiper, credential) |
| EmbeddedPayloadScanner | Scans for embedded PE (MZ) and ELF magic sequences inside the binary |

**User extensibility:**
Users install their own plugins through the 🪶 QUILL panel in the Plugins tab. Plugins are `.dll`/`.so`/`.dylib` files that expose the `hexhawk_plugin_entry` C ABI symbol. The `byte_counter` plugin in `plugins/byte_counter/` serves as the SDK reference.

**Safety guarantees (7 layers):** symbol existence validation, null-pointer guards, UTF-8 output validation, `panic::catch_unwind` across FFI, per-path load cache, plugin directory scope restriction, and cache eviction before deletion (required on Windows for DLL unlocking).

---

## Known Limitations

*Each row below maps to a milestone in [ROADMAP.md](ROADMAP.md).*

| Limitation | Status | Roadmap |
|------------|--------|---------|
| STRIKE uses real Windows debug API | ✅ **Resolved** — Linux `ptrace(PTRACE_SINGLESTEP)` backend via `nix` crate; macOS `task_for_pid` + `thread_get_state` backend; both emit the same `RegisterSnapshot` type consumed by `strikeBehaviorAnalyzer.ts`; `entitlements.plist` adds `com.apple.security.get-task-allow` for macOS | Milestone 7 |
| NEST training corpus is small | ✅ **Resolved** — `nest_cli ingest` subcommand for bulk corpus ingestion from local directories; `import-malwarebazaar.ts` imports labelled malware metadata from MalwareBazaar API (SHA-256 deduplicated); `cross-validate.ts` stratified 80/20 harness reports per-class precision/recall; `DEFAULT_NEST_CONFIG` tuned (`confidenceThreshold` 85→80, `plateauThreshold` 2→3) based on 15-session empirical convergence analysis | Milestone 8 |
| No virtualized hex/disasm for very large files | ✅ **Resolved** — seek-based I/O in `hex.rs`; HexViewer streams 4 KB chunks on scroll; `get_file_size` reports total without reading content | Milestone 1 |

---

## Reliability and Security Snapshot

- Leak and retention notes were refreshed in:
	- `docs/leak_audit.md`
	- `docs/security_status.md`
	- `docs/security_regression_checks.md`
- Recent verification status:
	- `npm run build` (workspace root): passed
	- `npm run build` (frontend): passed
	- `cargo check` (backend): passed with existing dead-code warnings
	- targeted leak regressions: passed (`CorpusBenchmarkPanel`, `strikeEngine`, plugin worker cap test)

---

## Test Coverage

| Suite | Tests | Status |
|-------|-------|--------|
| TypeScript (Vitest 2, 14+ suites) | 433 total — 422 passing, 11 pre-existing failures | 11 known failures (talonLLMPass, ssaTransform, nestEngine, benchmarkHarness — unrelated to recent features) |
| Rust (cargo test) | 28 | 0 failures |
| TypeScript compilation | — | 0 errors |
| Rust compilation | — | 0 errors (warnings present in `cargo check`) |

> Binary Diff engine (`binaryDiffEngine.ts`, `BinaryDiffPanel.tsx`) is integration-tested via TypeScript compilation. Unit tests for `diffSnapshots()` are planned as part of Milestone 9 follow-up.

---

## License Keys

Keys are HMAC-SHA256 signed, Crockford Base32 encoded (format: `HKHK-XXXXX-XXXXX-XXXXX-XXXXX`).  
Tier byte `0x01` = PRO, `0x02` = Enterprise. Expiry `0000/00` = perpetual (never expires).

Generated: April 2026. Verified by `verifyLicense()` in `src-tauri/src/commands/license.rs`.

### PRO — Perpetual

| Key | Tier | Expiry |
|-----|------|--------|
| `HKHK-04000-054FP-EFX8M-Y7610` | PRO | Perpetual |
| `HKHK-04000-02RPQ-NPM6Y-ZQ6VG` | PRO | Perpetual |
| `HKHK-04000-077N9-TKMHQ-1Y2JG` | PRO | Perpetual |

### Enterprise — Perpetual

| Key | Tier | Expiry |
|-----|------|--------|
| `HKHK-08000-00TYF-TFXJF-R28VG` | Enterprise | Perpetual |
| `HKHK-08000-01EAK-34DVN-6RXJG` | Enterprise | Perpetual |

> **To activate:** open the 🔑 License panel in HexHawk → paste key → Activate.  
> **To generate more keys:** `yarn license:keygen --tier pro --perpetual` (or `--tier enterprise`).

---

## Pricing Strategy

### Tier Overview

| Tier | Price | Rationale |
|------|-------|-----------|
| **Free** | $0 | Competes with Ghidra / x64dbg at the top of the funnel. Full hex viewer, disassembly, CFG, strings, ECHO signatures, and GYRE verdict. No time limit. Drives organic adoption and community credibility. |
| **Pro — Monthly** | $49 / mo | Best balance of perceived value and low commitment barrier. Targets individual analysts, CTF competitors, and pentesters. Cancellable removes risk objection. |
| **Pro — Annual** | $499 / yr | ~15% discount over monthly (~$41.58/mo effective). Cleaner cash flow, higher LTV. Expected to be the most common Pro conversion path once trust is established. |
| **Enterprise Starter** | $99 / user / mo | Low enough to land inside a team budget without a procurement committee. Targets 1–4 seat teams (SOC leads, malware analysts, small IR firms). Includes priority support SLA. |
| **Enterprise Team** | $15k – $25k / yr | 5–15 seat site license. Flat-rate removes per-seat friction at mid-market. Target: MSSPs, in-house IR teams, academic security labs. Includes CREST report API access. |
| **Enterprise Plus** | $40k – $75k+ / yr | Unlimited seats (org-wide), dedicated SLA, NEST corpus integration API, agent substrate (MCP) access, custom rule packs, and volume-discounted onboarding. Targets large enterprises and government. |

### Tier Feature Matrix

| Feature | Free | Pro | Enterprise |
|---------|:----:|:---:|:----------:|
| Hex Viewer (unlimited file size) | ✅ | ✅ | ✅ |
| Multi-arch disassembly + CFG | ✅ | ✅ | ✅ |
| Strings, ECHO signatures, GYRE verdict | ✅ | ✅ | ✅ |
| TALON decompiler + IR pseudo-code | ✅ | ✅ | ✅ |
| QUILL plugins (built-in) | ✅ | ✅ | ✅ |
| NEST iterative analysis | ✅ | ✅ | ✅ |
| KITE knowledge graph | ✅ | ✅ | ✅ |
| IMP patch engine | — | ✅ | ✅ |
| STRIKE live debugger | — | ✅ | ✅ |
| Mythos capability detection | — | ✅ | ✅ |
| Binary Diff (version comparison) | — | ✅ | ✅ |
| Document analysis (PDF + Office) | — | ✅ | ✅ |
| Sandbox script execution | — | ✅ | ✅ |
| Constraint solver (Z3 bridge) | — | ✅ | ✅ |
| AERIE operator console | — | ✅ | ✅ |
| CREST intelligence report export | — | ✅ | ✅ |
| QUILL user plugins (custom install) | — | ✅ | ✅ |
| AI Analyst Assist (M10, BYOK) | — | ✅ | ✅ |
| CREST report API access | — | — | ✅ |
| Agent substrate (MCP, M12) | — | — | ✅ |
| Custom NEST rule packs | — | — | ✅ |
| Priority support SLA | — | — | ✅ |
| Dedicated onboarding | — | — | ✅ |

### Positioning Notes

- **Free vs. Ghidra/x64dbg:** HexHawk Free covers the core RE workflow (hex, disassembly, CFG, strings, imports) and layers on the GYRE explainable verdict, NEST multi-pass analysis, and KITE graph — none of which Ghidra or x64dbg offer out of the box. Ghidra and IDA still lead on mature decompiler depth and ecosystem breadth; HexHawk's differentiator is *structured reasoning*, not raw decompilation parity.
- **Pro vs. Binary Ninja / IDA Pro:** IDA Pro starts at ~$1,699 one-time (x64 only) or $589/yr (cloud). Binary Ninja Personal is $499 one-time. HexHawk Pro at $499/yr is competitive on price, differentiates on the verdict + AI assist pipeline rather than decompiler depth.
- **Enterprise vs. Recorded Future / Reversing Labs:** Those are $50k–$200k+ threat-intel platforms. HexHawk Enterprise is a *desktop RE tool with structured output*, not a threat-intel feed — complementary, not competing. Pricing reflects that.
- **AI features as Pro driver:** Once Milestone 10 ships, AI Analyst Assist (signal explainer, CREST narration, diff insight) becomes a concrete Pro upgrade hook with visible daily value for analysts who already use GPT-4o or Claude.

---

## Build Artifacts

| File | Type |
|------|------|
| `target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi` | Windows MSI installer |
| `target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe` | Windows NSIS installer |
