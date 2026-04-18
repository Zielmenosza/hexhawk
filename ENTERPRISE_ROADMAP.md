# HexHawk — Enterprise Roadmap

*From working prototype to a shippable, commercial-grade reverse engineering utility.*

*Last updated: April 2026 — reflects state after TALON, STRIKE, and ECHO integration.*

---

## Where We Are Today

HexHawk is a production-quality **desktop binary intelligence tool** with:

- Binary inspection: file metadata, section layout, SHA-256/SHA-1/MD5, architecture detection
- Hex viewer with byte-range highlighting, decoded values panel, and entropy overlay
- Multi-architecture disassembly (x86, x86-64, ARM32, AArch64) via Capstone
- Control flow graph with ReactFlow — TRUE/FALSE edges, MiniMap, block colouring
- String extraction with classification (URL · IP · domain · path · base64 · registry)
- Import/export table parsing with dangerous-API flagging
- **Pattern Intelligence** — pattern categorization, threat scoring, binary profiling, workflow guidance
- **Correlation Engine** — multi-signal weighted verdict with reasoning chain, contradiction detection, alternative hypotheses, structured export; now incorporates TALON, STRIKE, and ECHO signals
- **Explainability Engine** — human-readable score breakdown with confidence factors
- **Determinism Engine** — reproducible, fixed-threshold analysis
- **Edge Case Engine** — benign-complex, packed-clean, mixed-signal detection
- **Semantic Search** — 9 behavioral intents, auto-annotation with accept/reject
- **Knowledge Graph** — ReactFlow visualization of import/string/pattern → verdict
- **Intelligence Report** — JSON + Markdown export suitable for SOC tickets and IR reports
- **Decompiler (TALON)** — reasoning-aware x86-64 pseudo-code with confidence scores, calling convention inference, operation classification, and correlation signal extraction
- **Debugger (STRIKE)** — runtime intelligence layer with delta engine, timeline recording + replay, behavioral tag detection (anti-debug, ROP/stack pivot, indirect flow analysis), sync with disassembly and TALON
- **Fuzzy Signature Recognition (ECHO)** — Jaccard-similarity fuzzy matching; context boosting from imports/strings; 25+ pattern categories; feeds correlation engine
- **Exact Signature Engine** — FNV-1a hash matching across compiler prologues/epilogues, libc, Windows API stubs, crypto, anti-debug, vectorized patterns
- A versioned plugin system with typed JSON-over-C ABI, per-plugin timeout, and SHA-256 result hashing
- 22 React components, 13 TypeScript intelligence engines, 6 Rust command modules
- TypeScript: **0 errors**. Rust: **0 errors, 0 warnings**.

What it lacks to be **sellable**: an installer, automated tests, packaging, licensing, and a clear buyer story.

---

## The Buyer

| Buyer | Pain | Willingness to Pay |
|-------|------|--------------------|
| **Malware analysts** at security firms | Too many tools, no unified workflow, manual report writing | High — daily driver |
| **Penetration testers** | Need quick binary recon without spinning up a VM | Medium — per-seat license |
| **CTF / security researchers** | Free alternatives exist but are clunky | Low — community/freemium |
| **Enterprise SOC teams** | Binary triage in incident response; need auditable output | Very High — team license |
| **Embedded / firmware engineers** | No good tool for non-x86 binaries | High — niche, less competition |
| **Incident Responders** | Need structured, exportable findings for reports | High — time savings are measurable |

**Primary target for v1.0 sale:** Malware analysts and SOC teams. They have budget, a real daily pain, and they value reproducible + auditable analysis — which HexHawk already provides through the intelligence report and reasoning chain.

---

## Feature Completion Status

### Core Analysis

| Feature | Status | Notes |
|---------|--------|-------|
| Hex viewer | ✅ Complete | Highlight, grouping, decoded values panel |
| Disassembly | ✅ Complete | x86/x64/ARM/AArch64; architecture auto-detection |
| Control flow graph | ✅ Complete | ReactFlow, edge types, MiniMap |
| String extraction + classification | ✅ Complete | URL, IP, domain, path, base64, registry |
| Import/export parsing | ✅ Complete | PE + ELF; dangerous API flagging |
| Section entropy | ✅ Complete | Shannon entropy, packed/encrypted detection |
| Function browser | ✅ Complete | Address-based navigation |
| Bookmarks | ✅ Complete | localStorage-persisted |

### Intelligence Layer

| Feature | Status | Notes |
|---------|--------|-------|
| Correlation engine | ✅ Complete | 20 signal sections, weighted corroboration, TALON/STRIKE/ECHO inputs |
| Explainability engine | ✅ Complete | Human-readable score breakdown, confidence factors |
| Determinism engine | ✅ Complete | Fixed thresholds, sorted output, reproducible verdicts |
| Edge case engine | ✅ Complete | Benign-complex, packed-clean, mixed-signal detection |
| Semantic search | ✅ Complete | 9 behavioral intents, unexplored area suggestions |
| Auto-annotation | ✅ Complete | Accept/reject with confidence scores |
| Knowledge graph | ✅ Complete | ReactFlow import/string/pattern → verdict visualization |
| Intelligence report | ✅ Complete | JSON + Markdown export with full reasoning chain |
| Pattern intelligence | ✅ Complete | Scoring, profiling, workflow guidance, smart suggestions |
| Decompiler (TALON) | ✅ Complete | Reasoning-aware pseudo-code, calling convention inference, x86-64 |
| Debugger (STRIKE) | ✅ Complete | Delta engine, timeline, behavioral tags, ROP detection |
| Fuzzy signatures (ECHO) | ✅ Complete | Jaccard similarity, context boosting, 25+ categories |
| Exact signatures | ✅ Complete | FNV-1a hash, 25+ patterns, 8 categories |

### UX & Polish

| Feature | Status | Notes |
|---------|--------|-------|
| Resizable panels | ✅ Complete | react-resizable-panels |
| File open dialog | ✅ Complete | Native Tauri dialog |
| Recent files | ✅ Complete | localStorage, last 10 |
| Dark/light theme | ✅ Complete | System preference + manual toggle |
| localStorage state persistence | ✅ Complete | All UI state survives reload |
| Keyboard shortcuts | ✅ Complete | Help panel in-app |
| Jump to address | ✅ Complete | JumpToAddressDialog |
| Error states | ✅ Complete | All Tauri calls have try/catch + UI feedback |
| Hex/disasm sync | ✅ Complete | Ctrl+J; instruction → hex offset |
| Hex viewer virtualization | ❌ Deferred | Freezes on files >1 MB. M1 priority. |
| PE digital signature verification | ❌ Deferred | Legitimate tools score SUSPICIOUS. M1 priority. |
| CSS consolidation | ❌ Deferred | 4 CSS files. No functional impact. M2 housekeeping. |

### Infrastructure

| Feature | Status | Notes |
|---------|--------|-------|
| Plugin system | ✅ Complete | Versioned ABI, typed results, timeout, JSON size cap |
| File size guard | ✅ Complete | 512 MB limit on all file reads |
| Architecture auto-detection | ✅ Complete | PE/ELF header; fallback banner |
| Rust error propagation | ✅ Complete | All commands return structured errors |
| Automated test suite | ❌ Not started | Needed before M3 |
| CI/CD pipeline | ❌ Not started | Needed before M3 |
| Native installer | ❌ Not started | Blocks every first-customer conversation |

---

## Milestone Overview

| Milestone | Focus | Status |
|-----------|-------|--------|
| **M0** | Core analysis + full intelligence layer | ✅ **Complete** |
| **M1** | Stability, tests, PE signatures, installer | 🟡 Next |
| **M2** | UX virtualization + polish | ⬜ Planned |
| **M3** | Packaging & distribution | ⬜ Planned |
| **M4** | Licensing & monetisation | ⬜ Planned |
| **M5** | Enterprise features | ⬜ Planned |
| **M6** | Market entry | ⬜ Planned |

---

## M0 — Complete ✅

All core analysis features, the full intelligence layer, and all three AI-augmented engines (TALON, STRIKE, ECHO) were delivered across phases 1–9. The intelligence layer — multi-stage reasoning, contradiction detection, alternative hypotheses, fuzzy signatures, runtime behavioral analysis, and reasoning-aware decompilation — is novel and not available in any competing tool at any price.

---

## M1 — Stability & First Demo Package

*The app must be demoable to non-developers and not freeze on realistic inputs.*

### M1.1 — PE Digital Signature Verification
Legitimate signed tools (Wireshark, PuTTY, Process Hacker) currently score SUSPICIOUS because HexHawk cannot verify Authenticode signatures. This produces false positives that erode analyst trust.

- Parse `WIN_CERTIFICATE` directory entry from the PE optional header
- Verify the signature chain against the Windows root certificate store (Tauri invoke to Rust `windows` crate)
- Add `isSignedAndTrusted: boolean` to `FileMetadata`
- Apply a strong negative signal weight in `correlationEngine` when the binary is trusted-signed
- Display a "✓ Signed" badge in the Metadata tab

**Effort:** ~3 days. **Impact:** Eliminates the most embarrassing false positive category.

### M1.2 — Hex and Disassembly View Virtualization
The hex viewer renders every row in the DOM. On a 10 MB binary (~40,000 rows) this causes a 2–20 second freeze. This is a demo-killer.

- Replace the flat render with `react-window` or a custom `useVirtualList` hook
- Render only the visible viewport (~100 rows at a time) plus a scroll buffer
- Ensure highlighted ranges (from address selection and STRIKE sync) scroll into view
- Same treatment for the disassembly view which can have 50,000+ rows on medium binaries

**Effort:** ~4 days. **Impact:** Removes the single biggest UX failure mode.

### M1.3 — Automated Test Suite
No tests means every change could silently break working features. There is no way to verify that a `correlationEngine` change does not break the threat verdict on a known-malicious binary.

- Create a `test/` directory with 5 reference binaries:
  - `clean_pe.exe` — standard Windows PE, no suspicious content
  - `upx_packed.exe` — UPX-packed executable, high entropy
  - `reverse_shell_stub.exe` — synthetic: `WSAStartup`, `connect`, `CreateProcess`, hardcoded IP
  - `legitimate_network_tool.exe` — signed network utility (should score CLEAN or LOW)
  - `corrupt.bin` — truncated/malformed binary (should fail gracefully)
- Write Vitest tests for the intelligence layer (`correlationEngine`, `patternIntelligence`, `talonEngine`, `echoEngine`, `strikeEngine`)
- Each test: input raw signals → assert verdict category, confidence range, specific signal presence/absence
- Add `vitest` to `package.json`; run as pre-commit hook

**Effort:** ~5 days. **Impact:** Enables confident iteration without manual regression testing.

### M1.4 — Native Installer
The single biggest blocker to first-customer conversations.

- Set `bundle.active = true` in `src-tauri/tauri.conf.json`
- Configure bundle metadata: app name, version, icon, copyright, identifier
- Add icons for all required sizes to `src-tauri/icons/` (use `tauri icon` generation tool)
- Produce: Windows `.msi` + portable `.exe`, macOS `.dmg` with notarisation, Linux `.AppImage` + `.deb`
- Sign the Windows installer (Azure Code Signing ~$10/month)
- GitHub Actions workflow: build frontend → `cargo check` → build installers → upload to GitHub Releases on tag push

**Effort:** ~3 days. **Impact:** Unblocks every demo and first customer conversation.

---

## M2 — UX Polish

*The app has to feel trustworthy to a professional analyst.*

### M2.1 — CSS Consolidation
Currently 4 CSS files: `styles.css`, `styles-phase5.css`, `styles-phase6.css`, `styles-phase7.css`. Merge into one `styles.css` with logical named sections. No functional change — purely maintenance.

### M2.2 — Session Save / Restore
- Save entire session (file path, bookmarks, active tab, annotations, plugin results, notes) to `.hexhawk` file
- Open a `.hexhawk` file to restore — enables passing sessions between team members
- Recent sessions list in sidebar

### M2.3 — TALON Enhancements
- Side-by-side view: pseudo-code left, original assembly right
- Click pseudo-code token → highlight corresponding assembly instruction
- Export pseudo-code to `.c` or `.txt`
- ARM/AArch64 pseudo-code support (TALON currently handles x86-64 only)

### M2.4 — STRIKE Enhancements
- Conditional breakpoints (break if register value equals N)
- Memory region watch (break on read/write to address range)
- Export timeline as JSON for offline analysis
- Real-time STRIKE signal feed into `correlationEngine` verdict (currently batch-mode after session end)

### M2.5 — ECHO Enhancements
- User-defined custom patterns (JSON file in plugin directory)
- False-positive feedback: mark a match incorrect → lower its pattern weight permanently
- Export confirmed matches as YARA rules

### M2.6 — Annotations & Notes
- Add text note to any address or instruction (currently supports auto-annotations only)
- Notes persisted per-session and exportable in intelligence reports
- Import/merge annotations from another `.hexhawk` session file

---

## M3 — Packaging & Distribution

### M3.1 — Auto-Update
- Tauri updater plugin (`tauri-plugin-updater`)
- Host update manifests on GitHub Releases
- In-app update notification with changelog text

### M3.2 — Plugin Distribution
- Ship `byte_counter` pre-compiled inside installer
- Define platform plugin directory (`~/.hexhawk/plugins/` / `%APPDATA%\HexHawk\plugins\`)
- In-app plugin browser: search, install, update from a curated index URL
- Scan platform plugin directory on startup in addition to the local `plugins/` folder

### M3.3 — CI/CD Pipeline
- GitHub Actions: build all three platforms → run Vitest + `cargo clippy` → upload to Releases on tag push
- Automated version bumping via `semantic-release` or a simple version script
- TypeScript strict-mode + test suite as required merge gates

---

## M4 — Licensing & Monetisation

### M4.1 — Licence Tiers

| Tier | Price Point | Features |
|------|-------------|----------|
| **Community** | Free | Core analysis, 1 plugin slot, no report export |
| **Professional** | ~$149 / year per seat | All engines (TALON, STRIKE, ECHO), report export, unlimited plugins |
| **Team** | ~$399 / year / 5 seats | + Shared sessions, team annotations, audit log |
| **Enterprise** | Custom | + SSO, on-prem activation server, SLA, priority support |

### M4.2 — Licence Enforcement
- Offline-first licence keys (signed JWT, hardware-tied via machine ID)
- Tauri reads licence file at startup, gates features accordingly
- Team licences: lightweight open-source activation server (single VPS)
- Hard gates only on high-value Enterprise features; Community tier is genuinely useful

### M4.3 — Telemetry (Opt-in)
- Opt-in crash reporting via Sentry
- Aggregate feature usage (which tabs are used most) to guide roadmap priorities
- Never send file contents, analysis results, binary data, or IP addresses

---

## M5 — Enterprise Features

### M5.1 — Batch Analysis
- Drag a folder of files → run all engines, generate a threat score for each
- Ranked CSV/JSON report: file · SHA-256 · verdict · threat score · top signals
- Background processing with progress bar; filter batch results by verdict category

### M5.2 — YARA Rule Integration
- Run a folder of `.yar` rules against the loaded binary
- Show matches with rule name, offset, and matched bytes highlighted in hex viewer
- Export YARA matches in the intelligence report
- ECHO auto-generates YARA rules from confirmed matches

### M5.3 — Audit Log
- Immutable append-only log: timestamp · analyst · file hash · actions taken · verdict
- Export as JSON or CSV
- Stored locally or synced to a central server (Enterprise tier)

### M5.4 — SSO / Active Directory
- SAML 2.0 or OAuth2 integration
- Role-based access: analyst · reviewer · admin
- Licence seat management via web portal (Enterprise tier)

### M5.5 — Collaboration
- Share a `.hexhawk` session with annotations and verdicts
- Reviewers add comments without modifying the original analysis
- Session diff: "what changed between analyst A and analyst B?"

---

## M6 — Market Entry

### M6.1 — Website
- Landing page: feature comparison, screenshots, pricing
- Download page gated behind email capture for Community tier
- Blog posts on analysis techniques using HexHawk
- Demo video: HexHawk vs. Ghidra on a real malware sample — side-by-side reasoning chain output

### M6.2 — Community Building
- GitHub: polished README, Issues, Discussions, contributor guide
- Discord for early users and plugin developers
- Post walkthroughs: Reddit (`r/ReverseEngineering`, `r/netsec`), Mastodon, X

### M6.3 — Security Conference Presence
- Submit to **Black Hat Arsenal** — specifically for open-source security tools; free exposure to exactly the right buyer
- DEF CON demo room or workshop
- BSides: "Why binary analysis needs explainable AI"

### M6.4 — Free Tier Strategy
- Community tier must be genuinely useful, not crippled
- Goal: analyst uses it daily → their employer buys a team licence
- Give away: core analysis, TALON, STRIKE, ECHO
- Charge for: report export, batch analysis, session sharing, collaboration, enterprise audit

### M6.5 — Early Access Programme
- Recruit 10–20 analysts pre-launch
- Offer lifetime Professional licences in exchange for feedback and testimonials
- Document real-world verdicts as case studies (with permission)

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Ghidra / IDA add explainable AI features | Medium (12–24 months) | High | Execute faster; reasoning chain is already built and working |
| CAPA (Mandiant) adds interactive UI | Medium | Medium | Different output; HexHawk's UI + interactivity is the moat |
| No traction without installer | **High** | **High** | M1.4 installer is the highest-priority remaining work item |
| Hex viewer freeze ends a demo | **High** | **High** | M1.2 virtualization must ship before any external demo |
| Plugin ABI breaks between versions | Medium | Medium | Strict semver on `plugin-api`; automated ABI compatibility tests |
| TALON pseudo-code quality gap vs Hex-Rays | High | Medium | Position as "intelligence layer", not "decompiler replacement" |
| Single developer — bus factor = 1 | High | High | Document architecture; write contributor guide early; build community |
| Code signing costs | Low | Medium | Azure Code Signing ~$10/month; not a real blocker |
| Tauri WebView2 issues on older Windows | Medium | Low | Document minimum Windows 10 21H2+; test on CI |

---

## Immediate Next Actions (Prioritized)

1. **M1.2 — Virtualize hex and disassembly views** — Demo-killer. Cannot show the tool on any realistic binary without this.
2. **M1.4 — Build native installer** — Cannot have a first-customer conversation without an installable binary.
3. **M1.1 — Add PE digital signature verification** — Eliminates the most visible false positive category.
4. **M1.3 — Write test binary corpus + Vitest tests** — Enables confident iteration after the installer ships.
5. **M2.1 — CSS consolidation** — Small maintenance win that prevents further tech debt accumulation.
6. **M2.3 — TALON ARM support** — Expands decompilation to ARM firmware analysis (high-value embedded/IoT market).

## The Buyer

Before building, define who pays:

| Buyer | Pain | Willingness to Pay |
|-------|------|--------------------|
| **Malware analysts** at security firms | Too many tools, no unified workflow | High — daily driver |
| **Penetration testers** | Need quick binary recon without spinning up a VM | Medium — per-seat license |
| **CTF / security researchers** | Free alternatives exist but are clunky | Low — community/freemium |
| **Enterprise SOC teams** | Binary triage in incident response | Very High — team license |
| **Embedded / firmware engineers** | No good tool for non-x86 binaries | High — niche, less competition |

**Primary target for v1.0 sale:** Malware analysts and SOC teams. They have budget, a real daily pain, and they value reproducible + auditable analysis (which HexHawk already provides).

---

## Milestone Overview

| Milestone | Focus | Outcome |
|-----------|-------|---------|
| **M1** | Core completeness | No obvious gaps in analysis |
| **M2** | UX & stability | App feels professional, no rough edges |
| **M3** | Packaging & distribution | Users can install it without a Rust toolchain |
| **M4** | Licensing & monetisation | Can charge for it |
| **M5** | Enterprise features | Can sell to teams |
| **M6** | Market entry | First paying customers |

---

## M1 — Core Completeness
*Everything a serious analyst expects to be there.*

### M1.1 — Architecture Auto-Detection
Current disassembly is hardcoded to x86-64. Analysts work with ARM firmware, embedded x86, etc.
- Detect from PE `Machine` field or ELF `e_machine`
- Switch Capstone mode automatically
- Display detected arch in the toolbar

### M1.2 — Import / Export Tables
`imports_count` is currently 0. This is a critical gap — import analysis is one of the first things an analyst does.
- Parse PE import directory and ELF dynamic symbols
- Show a scrollable, searchable list: function name · DLL/library · address
- Flag known dangerous imports (e.g. `VirtualAlloc`, `CreateRemoteThread`, `WriteProcessMemory`) with a threat badge
- Feed named imports into the pattern intelligence scoring

### M1.3 — String Classification
Raw strings need context to be useful.
- Classify: URL · IP · domain · registry path · file path · base64 · UUID · PE artefact
- Show a `kind` badge per string
- Filter strings by kind in the Strings tab
- Highlight strings that appear in both imports and code references

### M1.4 — Section Entropy
- Calculate Shannon entropy (0–8) per section
- Show a coloured bar (green → red) in the Metadata tab
- High entropy (>7.0) on `.text` → packed/encrypted; flag this automatically
- Connect to the `edgeCaseEngine` `isPackedButClean()` heuristic

### M1.5 — Cross-Reference Graph
Currently references are detected but not visualised as a graph.
- Show a call graph: which functions call which
- Identify root functions (called by nothing) and leaf functions
- Highlight recursive calls

### M1.6 — Decompiler Stub (Optional / Stretch)
Even a low-quality C-like pseudocode output from a short function range would be a major differentiator. Options:
- Integrate `retdec` as a plugin (it exposes a REST API)
- Expose a plugin hook so a third-party decompiler plugin can fill this tab

---

## M2 — UX & Stability
*The app has to feel trustworthy.*

### M2.1 — File Open Dialog & Recent Files
Replace the text-input path with:
- Native file picker (Tauri `dialog` plugin)
- Drag-and-drop a binary onto the window
- Recent files list in a sidebar or menu (last 10, persisted in `localStorage`)

### M2.2 — Resizable Layout
Fixed-column layout breaks on small screens and with large binaries.
- `react-resizable-panels` for resizable split panes
- Persist sizes in `localStorage`
- Collapsible sidebar

### M2.3 — Hex Viewer Polish
- Click any byte → show decoded values panel (int8, uint8, int16LE, int16BE, int32, float32, float64)
- Select a byte range → show length, sum, entropy of selection
- Jump to address by typing a hex offset
- Highlight bytes owned by the currently selected instruction

### M2.4 — Disassembly ↔ Hex Sync
`Ctrl+J` exists as a shortcut but may not be fully wired.
- Selecting an instruction scrolls the hex viewer to that offset
- Selecting a byte range highlights the containing instruction

### M2.5 — CFG Improvements
- Zoom and pan (currently static)
- Click a block → jumps to that offset in disassembly
- Colour by block type: entry (teal) · exit/return (red) · external call (orange) · normal (default)
- Export CFG as SVG or PNG

### M2.6 — Error States
Every tab currently shows blank or crashes silently on bad input.
- Add proper empty states with helpful messages ("No strings found — try a wider range")
- Show a clear error banner when a command fails, with the error message from Rust
- Add a loading indicator while commands are in flight

### M2.7 — Dark / Light Theme
- Support system theme preference via `prefers-color-scheme`
- Manual toggle persisted in `localStorage`
- Consistent token-based colour system (not ad-hoc CSS)

### M2.8 — CSS Consolidation
Currently: `styles.css`, `styles-phase5.css`, `styles-phase6.css`, `styles-phase7.css`.
- Merge into a single `styles.css` with logical sections
- No functional change — purely maintenance

---

## M3 — Packaging & Distribution
*A buyer should be able to install it without knowing what Rust is.*

### M3.1 — Signed Native Installers
Enable the Tauri bundler properly:
- Windows: `.msi` and `.exe` installer, signed with a code-signing certificate
- macOS: `.dmg`, notarised via Apple's notarisation service
- Linux: `.AppImage` and `.deb`

Steps:
1. Set `bundle.active = true` in `tauri.conf.json`
2. Configure bundle metadata (icon, version, copyright)
3. Add icons for all required sizes to `src-tauri/icons/`
4. Set up GitHub Actions to build on all three platforms and sign

### M3.2 — Auto-Update
- Use Tauri's built-in updater plugin (`tauri-plugin-updater`)
- Host update manifests on GitHub Releases or a CDN
- Show an in-app update notification with changelog

### M3.3 — Plugin Distribution
- Plugins are currently compiled manually by the user
- Ship the `byte_counter` plugin pre-compiled inside the installer
- Define a plugin directory convention (`~/.hexhawk/plugins/` or `%APPDATA%\HexHawk\plugins\`)
- Scan that directory on startup in addition to the local `plugins/` folder

### M3.4 — CI/CD Pipeline
- GitHub Actions workflow: build frontend → `cargo check` → build all three platform installers → upload to GitHub Releases
- Automated version bumping from `package.json` / `Cargo.toml`
- Run `cargo clippy` and TypeScript strict-mode checks as gates

---

## M4 — Licensing & Monetisation
*Protect the product and collect revenue.*

### M4.1 — Licence Tiers

| Tier | Price Point | Features |
|------|-------------|----------|
| **Community** | Free | Core analysis, 1 plugin slot, no export |
| **Professional** | ~$99 / year per seat | All features, unlimited plugins, export |
| **Team** | ~$299 / year / 5 seats | + Shared bookmarks, team notes |
| **Enterprise** | Custom | + SSO, audit logs, on-prem, SLA |

### M4.2 — Licence Enforcement
- Offline-first licence keys (signed JWT or hardware-tied)
- Tauri can read a licence file at startup and gate features accordingly
- For team licences: a lightweight activation server (can be hosted on a single VPS)
- Avoid DRM that annoys legitimate users — focus on honour-system for Community, hard gates only on high-value Enterprise features

### M4.3 — Telemetry (Opt-in)
- Opt-in crash reporting via Sentry or similar
- Aggregate feature usage (which tabs are used most) to guide roadmap priorities
- Never send file contents or analysis results

---

## M5 — Enterprise Features
*What makes a team buyer write a purchase order.*

### M5.1 — Analysis Export & Reporting
- Export full analysis report as Markdown, JSON, or self-contained HTML
- Report includes: file info · hashes · section summary · threat score with breakdown · string list · disassembly summary · plugin results
- Export button in the toolbar, keyboard shortcut `Ctrl+Shift+E`

### M5.2 — Session Save / Restore
- Save the entire session (file path, bookmarks, active tab, plugin results, notes) to a `.hexhawk` file
- Open a `.hexhawk` file to restore a session — pass between team members
- Recent sessions list

### M5.3 — Annotations & Notes
- Analysts can add a text note to any address or instruction
- Notes persisted per-session and exportable in reports
- Team notes sync via a shared `.hexhawk` session file

### M5.4 — Batch Analysis
- Drag a folder of files onto HexHawk
- Run all plugins and generate a threat score for each
- Output a ranked CSV/JSON report: file · SHA-256 · threat score · top patterns
- Background processing with a progress bar

### M5.5 — YARA Rule Integration
YARA is the industry standard for malware pattern matching.
- Run a folder of `.yar` rules against the loaded binary
- Show matches with rule name, offset, and matched bytes highlighted in the hex viewer
- Export results with the analysis report

### M5.6 — Audit Log
Enterprise buyers need to prove what was analysed and when.
- Immutable append-only log: timestamp · analyst (username) · file hash · analysis actions taken
- Export audit log as JSON or CSV
- Stored locally or optionally synced to a central server

### M5.7 — SSO / Active Directory
For large teams:
- SAML 2.0 or OAuth2 integration for user authentication
- Role-based access: analyst · reviewer · admin
- Licence seat management via a web portal

---

## M6 — Market Entry
*Getting the first paying customers.*

### M6.1 — Website
- Landing page with feature comparison table, screenshots, pricing
- Download page gated behind email capture for Community tier
- Blog/posts on analysis techniques using HexHawk (SEO + credibility)

### M6.2 — Community Building
- GitHub: well-written README, Issues enabled, Discussions
- Discord or Slack for early users
- Post walkthroughs on communities: Reddit (`r/ReverseEngineering`, `r/netsec`), Mastodon, X

### M6.3 — Security Conference Presence
- Submit a talk or workshop to DEF CON, Black Hat Arsenal, BSides
- Arsenal (Black Hat) is specifically for open-source security tools — it is free exposure to exactly the right audience

### M6.4 — Free Tier Strategy
- Community tier should be genuinely useful, not crippled
- The goal is: analyst uses it daily → their employer buys a team licence
- Give away the analysis engine; charge for the workflow, collaboration, and export features

### M6.5 — Early Access Programme
- Before full launch: recruit 10–20 analysts to use it for real work
- Collect feedback and testimonials
- Offer them lifetime Professional licences in exchange

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Ghidra / Binary Ninja / IDA dominate the market | High | High | Focus on speed, native UX, and pricing; don't try to be a full decompiler |
| Plugin ABI breaks between versions | Medium | Medium | Strict semver on `plugin_api`; document breaking changes |
| Code signing costs are high | Low | Medium | Use Azure Code Signing (~$10/month) instead of traditional EV certificates |
| Tauri WebView2 issues on older Windows | Medium | Low | Document minimum Windows version; test on Windows 10 21H2+ |
| Single developer bottleneck | High | High | Document architecture thoroughly; write a contributor guide early |

---

## Immediate Next Actions

These are the highest-leverage things to do right now, in order:

1. **Fix import/export parsing** (`inspect.rs`) — closes the biggest analytical gap
2. **Add native file open dialog** (`App.tsx` + Tauri dialog plugin) — removes the biggest UX friction
3. **Add section entropy** (`inspect.rs`) — small effort, high analyst value
4. **Enable the Tauri bundler** (`tauri.conf.json`) — allows sharing the app without a dev environment
5. **Merge the CSS files** — low effort, prevents further tech debt accumulation
6. **Write a plugin authoring guide** — enables the ecosystem that makes the platform sticky
