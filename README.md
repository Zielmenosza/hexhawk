# HexHawk

A native desktop application for binary inspection and advanced reverse engineering, built with Rust, Tauri 2, React, and TypeScript.

---

## What it does

HexHawk is a unified reverse engineering workspace that eliminates context switching between tools. It combines raw binary inspection, multi-architecture disassembly (x86-32, x86-64, ARM32, AArch64), control flow analysis, IR-based pseudo-code, live debugging, iterative threat analysis, and fuzzy signature recognition into one desktop application — with an explainable verdict engine that documents exactly why a binary was flagged.

---

## Intelligence Engines

Twelve named engines feed a shared GYRE verdict:

| Engine | Role | Key capability |
|--------|------|----------------|
| **TALON** | Reasoning-aware decompiler | IR lift → SSA construction → data-flow passes → intent detection → pseudo-code; ARM32 + AArch64 + x86-64 |
| **STRIKE** | Live debugger + behavioral delta | Windows WinDebugAPI, Linux ptrace, macOS task_for_pid; instruction-level stepping; behavioral change detection |
| **ECHO** | Fuzzy signature recognition | Jaccard similarity against known patterns; compiler variant detection |
| **NEST** | Iterative convergence analysis | Multi-pass re-analysis with dampening; stable convergence validated against real binaries; growing corpus via `nest_cli ingest` + MalwareBazaar import |
| **QUILL** | User plugin system | Dynamic native plugin loading (`.dll`/`.so`/`.dylib`) with 7-layer safety isolation; install/uninstall via UI |
| **GYRE** | Verdict engine | 20-section signal aggregation, reasoning chain, contradiction detection, alternative hypotheses |
| **KITE** | Knowledge graph | ReactFlow visualization of how signals combine into a verdict |
| **AERIE** | Operator console | Intent classification from plain text → step-by-step analysis workflow; LLM mode (Milestone 10) |
| **CREST** | Intelligence report | JSON / Markdown export with full reasoning chain; AI narrative summary (Milestone 10) |
| **IMP** | Binary patch engine | Invert conditional jumps, NOP sleds, export patched copy |
| **Mythos** | Capability detection | capa-style 24-rule engine: process-injection, defense-evasion, persistence, C2, encryption, credential-access, wiper; produces `CorrelatedSignal` entries with code locations and evidence chains |
| **Binary Diff** | Version comparison | Semantic diff of two binary snapshots across functions, strings, imports, CFG, and threat signals; hotspot ranking; risk assessment; Pro tier |

All core analysis engines contribute typed signals to `GYRE.computeVerdict()`. The verdict includes a `ReasoningStage[]` chain with per-signal justifications, contradiction detection, and alternative hypotheses — not just a score.

---

## Feature Matrix

| Area | Description |
|------|-------------|
| **Hex Viewer** | Raw bytes with offsets, grouping, ASCII, decoded values, jump-to, search, bookmarks; seek-based I/O for files of any size |
| **Disassembly** | x86-64 / ARM32 / AArch64 instruction view, cross-references, annotations (accept/reject), address navigation |
| **Control Flow Graph** | ReactFlow canvas with TRUE/FALSE edge labels, MiniMap, layout depth, block-level metadata; multi-arch aware |
| **Strings** | Printable string extraction with classification, entropy scoring, and jump-to |
| **TALON Decompiler** | IR lift (x86-64, ARM32, AArch64), SSA form, constant folding + copy propagation, natural loop classification, intent-annotated pseudo-code |
| **STRIKE Debugger** | Cross-platform: Windows WinDebugAPI, Linux ptrace, macOS task_for_pid; register + memory snapshots, behavioral delta engine |
| **ECHO Signatures** | Fuzzy Jaccard matching + exact FNV-1a hashing; pattern export |
| **NEST Analysis** | Iterative multi-pass verdict with MEWS benchmark harness; growing corpus via `nest_cli ingest` + MalwareBazaar import |
| **GYRE Verdict** | 20-section signal aggregation, reasoning chain, contradiction detection, alternative hypotheses |
| **KITE Graph** | ReactFlow visualization of how signals combine into a verdict |
| **AERIE Console** | Intent classification from plain text → step-by-step analysis workflow; LLM mode (Milestone 10) |
| **CREST Report** | JSON / Markdown export with full reasoning chain; AI narrative summary (Milestone 10) |
| **Mythos Capabilities** | capa-style 24-rule capability detection across 7 namespaces; produces CorrelatedSignal entries with navigable code locations |
| **Binary Diff** | Semantic diff of two binary snapshots; function / string / import / CFG / signal diff; hotspot ranking; Pro tier |
| **AI Assist** | Milestone 10 backbone + Milestone 11 BYOK layer delivered (provider-aware key handling and policy gates); narrative UX features continue iterating |
| **BRAND Annotations** | Confidence-scored suggestions; accept/reject per annotation |
| **Plugins (QUILL)** | Versioned C ABI; 7-layer safety isolation; install/uninstall from UI; 4 built-in analysis plugins |
| **MEWS Benchmark** | Load, run, and compare NEST against a curated binary corpus |

---

## Browser QA Fidelity Indicators

The frontend includes explicit QA visibility for simulation-vs-native behavior:

- **Panel Fidelity Badge**: each workflow panel shows whether it is using `REAL BACKEND`, `SIMULATION`, or `UI ONLY` behavior.
- **QA Sources Matrix**: status strip toggle (`QA Sources`) opens a subsystem matrix listing source mode for inspect, disassembly, CFG, plugins, patching, and related paths.
- **Normalized Activity Events**: activity entries use stable event codes (for example `CFG_BUILD_SIMULATION` or `INSPECT_COMPLETE`) so QA logs can be searched and compared reliably.
- **CFG Empty-State CTA**: CFG view provides an inline **Build CFG** action when no graph is loaded.

In browser mode, analysis actions are simulated for workflow validation. Full binary-processing fidelity still requires the native Tauri runtime.

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Rust | Stable | Install via [rustup.rs](https://rustup.rs) |
| Node.js | 20+ | |
| Yarn | 1.x or Berry | `npm install -g yarn` |
| WebView2 | Any | Windows — usually pre-installed on Win 10/11 |
| Visual Studio Build Tools | 2019+ | Windows — C++ workload required |

**macOS**
```bash
xcode-select --install
```

**Linux**
```bash
sudo apt install libgtk-3-dev libwebkit2gtk-4.1-dev build-essential
```

---

## Getting Started

### 1. Clone and install
```bash
git clone https://github.com/your-org/hexhawk.git
cd hexhawk
yarn install
```

### 2. Build the sample plugin
```bash
cd plugins/byte_counter
cargo build
cd ../..
```

### 3. Run in development
```bash
yarn tauri:dev
```

This starts the Vite dev server (hot-reload) and the Tauri desktop window together.

---

## Building

**Frontend only**
```bash
cd HexHawk
yarn build
# output: HexHawk/dist/
```

**Full desktop app (signed installer)**
```bash
yarn tauri:build
# output: src-tauri/target/release/bundle/
```

**NEST CLI (batch analysis)**
```bash
cargo build --bin nest_cli
# ./target/debug/nest_cli cfg <binary> <offset> <length>
```

---

## Running tests

**TypeScript (Vitest 2)**
```bash
cd HexHawk
npx vitest run
# 433 total — 422 passing, 11 pre-existing failures (talonLLMPass, ssaTransform, nestEngine, benchmarkHarness — unrelated to recent features)
```

**Rust (cargo test)**
```bash
cargo test
# 28 tests — 0 failures expected
```

Targeted reliability checks used in recent hardening work:

```bash
cd HexHawk
npm test -- src/components/__tests__/CorpusBenchmarkPanel.test.tsx src/utils/__tests__/strikeEngine.test.ts

cd ../src-tauri
cargo test -p hexhawk-backend run_plugins::tests::execute_plugin_with_timeout_enforces_worker_cap_after_timeouts -- --nocapture
```

---

## CI / CD

GitHub Actions workflows live in `.github/workflows/`:

| Workflow | Trigger | Jobs |
|----------|---------|------|
| `ci.yml` | Push / PR to `main` | typecheck · vitest · clippy · cargo-test · build-check |
| `release.yml` | Push tag `v*` | build Windows + Linux installers, create GitHub Release |

---

## Project Structure

```
hexhawk/
├── .github/
│   └── workflows/
│       ├── ci.yml              # 5-job CI pipeline
│       └── release.yml         # installer build + GitHub release
│
├── Cargo.toml                  # Rust workspace (backend + plugins + cli)
├── package.json                # Yarn workspace
│
├── src-tauri/                  # Rust backend (Tauri 2)
│   └── src/
│       ├── main.rs
│       ├── commands/
│       │   ├── hex.rs          # Raw byte reads, 512 MB guard
│       │   ├── disassemble.rs  # Multi-arch disassembly via Capstone (x86-32/64, ARM32, AArch64)
│       │   ├── graph.rs        # CFG construction, back-edge detection
│       │   ├── inspect.rs      # PE/ELF header parsing, hashes
│       │   ├── debugger.rs     # Cross-platform debug loop (Windows WinDebugAPI, Linux ptrace, macOS task_for_pid)
│       │   ├── plugin_browser.rs
│       │   └── run_plugins.rs  # Sandboxed plugin execution, 10 MB output cap
│       └── plugins/
│           ├── mod.rs          # 4 built-in plugins: ByteCounter, EntropyAnalyzer,
│           │                   #   SuspiciousImportScanner, EmbeddedPayloadScanner
│           └── quill.rs        # QUILL dynamic loader — 7-layer safety isolation
│
├── HexHawk/                    # React + TypeScript frontend
│   └── src/
│       ├── App.tsx             # Root: state, routing, verdict computation
│       ├── components/         # 22 tab views + shared UI
│       │   ├── TalonView.tsx   # Pseudo-code + intent sidebar + loop structure panel
│       │   ├── StrikeView.tsx  # Live debugger timeline + behavioral delta
│       │   ├── EchoView.tsx    # Signature match browser
│       │   ├── NestView.tsx    # Iterative analysis dashboard
│       │   ├── QuillPanel.tsx  # QUILL user plugin manager (install/uninstall/browse)
│       │   └── CorpusBenchmarkPanel.tsx
│       └── utils/              # 16 stateless intelligence engines
│           ├── ssaTransform.ts         # Cooper dominators, Cytron phi insertion, SSA rename
│           ├── dataFlowPasses.ts       # Constant folding, copy propagation, dead-def analysis
│           ├── cfgSignalExtractor.ts   # Back-edge detection, natural loop classification
│           ├── talonEngine.ts          # IR lift → SSA → intent detection → pseudo-code
│           ├── decompilerEngine.ts     # x86-64 → IRStmt → IRBlock → StructuredNode → PseudoLine
│           ├── correlationEngine.ts    # 20-section verdict engine
│           ├── nestEngine.ts           # Iterative convergence + convergence guard
│           ├── corpusManager.ts        # Binary corpus CRUD + metadata
│           ├── benchmarkHarness.ts     # Per-binary NEST benchmark runner
│           ├── signatureEngine.ts      # FNV-1a + Jaccard matching
│           ├── operatorConsole.ts      # Intent classification + workflow generation
│           └── __tests__/             # 9 test suites, 131 tests
│
├── plugin-api/                 # Shared plugin C ABI (PluginEntry, PLUGIN_SYMBOL_NAME)
└── plugins/
    └── byte_counter/           # Example QUILL plugin (also the QUILL SDK reference)
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Layer 0 — Intent   AERIE (operatorConsole.ts)          │
│  Classifies user intent → generates analysis workflow   │
└──────────────────────────┬──────────────────────────────┘
                           │ onNavigateTab() only
┌──────────────────────────▼──────────────────────────────┐
│  Layer 3 — Presentation  App.tsx + 22 components        │
│  Tab views, address navigation (selectAddress),         │
│  single useMemo verdict, props-only data flow           │
└──────────────────────────┬──────────────────────────────┘
                           │ typed signal interfaces
┌──────────────────────────▼──────────────────────────────┐
│  Layer 2 — Intelligence  HexHawk/src/utils/             │
│  16 stateless engines: TALON · STRIKE · ECHO · NEST     │
│  GYRE verdict engine (20 sections)                      │
│  SSA transform · data-flow passes · loop detection      │
└──────────────────────────┬──────────────────────────────┘
                           │ Tauri invoke()
┌──────────────────────────▼──────────────────────────────┐
│  Layer 1 — Acquisition   src-tauri/src/commands/        │
│  Rust: hex · disassemble · graph · inspect · debugger   │
│  Plugin execution (sandboxed, timeout-guarded)          │
└─────────────────────────────────────────────────────────┘
```

**Key invariants:**
- `selectAddress()` is the single dispatch point for all navigation
- `correlationEngine.computeVerdict()` is the sole source of the threat verdict
- All Layer 2 engines are pure functions — no browser globals, fully testable without Tauri

---

## Plugin Development

For the full, implementation-accurate authoring manual, see [docs/QUILL_PLUGIN_DEVELOPMENT_GUIDE.md](docs/QUILL_PLUGIN_DEVELOPMENT_GUIDE.md).

QUILL plugins are native shared libraries (`.dll` / `.so` / `.dylib`) loaded at runtime through the QUILL engine. Install them from the **Plugins** tab → **🪶 QUILL — User Plugins** panel, or drop them into the QUILL directory manually.

> **IMP** is the HexHawk binary patch engine — named after the falconry technique of grafting a replacement feather onto a damaged quill. IMP lets you invert conditional jumps, NOP out instructions, and export a patched binary copy without touching the original.

Plugins expose two symbols via the `plugin-api` crate:

```c
// Metadata — called once on load; returns JSON with name/version/description
extern "C" const char* hexhawk_plugin_entry(void);

// Analysis entry point — called per file; returns JSON result
extern "C" char* run_plugin(const uint8_t* data_ptr, size_t len);
```

**Built-in QUILL plugins** (always available, no install needed):

| Plugin | What it reports |
|--------|----------------|
| ByteCounter | Byte frequency histogram, printable/zero/high-byte ratios |
| EntropyAnalyzer | Shannon entropy per section; packed/encrypted section detection |
| SuspiciousImportScanner | 50+ Win32 API names across 8 threat categories |
| EmbeddedPayloadScanner | Embedded PE/ELF executables (MZ/ELF magic scans) |

**Safety guarantees (7 layers)**
1. Symbol existence validated before call
2. Null pointer guards on all return values
3. UTF-8 validation of all plugin output
4. `std::panic::catch_unwind` prevents plugin panics crossing the FFI boundary
5. Per-path load cache (`Arc<Mutex<HashMap>>`) — one library handle per plugin
6. Directory scope restriction — plugins must reside inside the QUILL directory
7. `evict_from_cache()` removes handle before deletion (required for Windows DLL unlocking)

### Result schema (v1)

```json
{
  "schema_version": 1,
  "plugin": "MyPlugin",
  "version": "1.0.0",
  "success": true,
  "summary": "Short result string (< 512 chars)",
  "details": {},
  "kind": "analysis",
  "plugin_hash": "abc123"
}
```

**Constraints**
- Max output: 10 MB
- Timeout: 3 seconds per run
- Output must be valid UTF-8 JSON

**Supported `kind` values:** `metric` · `analysis` · `strings` · `warning` · `error`

---

## Keyboard Shortcuts

See [KEYBOARD_SHORTCUTS.md](KEYBOARD_SHORTCUTS.md) for the full reference.

Quick usage patterns:
- Rapid inspect loop: `Ctrl+D` -> arrow keys to inspect instructions -> `Ctrl+J` to jump into hex -> `Ctrl+B` to bookmark findings.
- Navigation recall: use `Ctrl+G` and `Ctrl+Y` to move through address history during multi-panel analysis.
- In-app cheat sheet: press `?` (or `Ctrl+Shift+/`) to open the shortcut help panel any time.

| Shortcut | Action |
|----------|--------|
| `Ctrl+D` | Disassembly tab |
| `Ctrl+H` | Hex Viewer tab |
| `Ctrl+B` | Add bookmark at current address |
| `Ctrl+Shift+B` | Bookmarks panel |
| `Ctrl+J` | Jump to hex offset |
| `Ctrl+F` | Search |
| `Ctrl+G` | Navigate back |
| `Ctrl+Y` | Navigate forward |
| `?` | Help panel |

---

## Troubleshooting

**Tauri fails to start** — check Rust is installed:
```bash
cargo --version
```

**Blank window** — wait for Vite dev server to finish starting, then check the `HexHawk` terminal for Vite errors.

**No plugins available** — build the plugin first:
```bash
cd plugins/byte_counter && cargo build
```

**Plugin fails to load** — verify the output exists:
```
plugins/byte_counter/target/debug/byte_counter.dll   (Windows)
plugins/byte_counter/target/debug/libbyte_counter.so (Linux)
```

**NEST CLI not found**
```bash
cargo build --bin nest_cli
```

**Tests failing** — ensure you are in `HexHawk/`:
```bash
cd HexHawk && npx vitest run
```

---

## License

MIT — see [LICENSE](LICENSE).

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for planned capability expansions. Milestones 1–11 are complete (including AI backbone + BYOK customer layer). Next: Milestone 12 — MCP agent substrate.

For current hardening and leak posture, see:

- [docs/leak_audit.md](docs/leak_audit.md)
- [docs/security_status.md](docs/security_status.md)
- [docs/security_regression_checks.md](docs/security_regression_checks.md)