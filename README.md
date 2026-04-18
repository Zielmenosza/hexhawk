# HexHawk

A native desktop application for binary inspection and advanced reverse engineering, built with Rust, Tauri 2, React, and TypeScript.

---

## What it does

HexHawk is a unified reverse engineering workspace that eliminates context switching between tools. It combines raw binary inspection, x86-64 disassembly, control flow analysis, IR-based pseudo-code, live debugging, iterative threat analysis, and fuzzy signature recognition into one desktop application — with an explainable verdict engine that documents exactly why a binary was flagged.

---

## Intelligence Engines

Four analysis engines run alongside the standard RE views and feed a shared verdict:

| Engine | Role | Key capability |
|--------|------|----------------|
| **TALON** | Reasoning-aware decompiler | IR lift → SSA construction → data-flow passes → intent detection → pseudo-code |
| **STRIKE** | Live debugger + behavioral delta | Windows debug loop, instruction-level stepping, behavioral change detection |
| **ECHO** | Fuzzy signature recognition | Jaccard similarity against known patterns; compiler variant detection |
| **NEST** | Iterative convergence analysis | Multi-pass re-analysis with dampening; stable convergence validated against real binaries |

All four engines contribute typed signals to `correlationEngine.computeVerdict()`. The verdict includes a `ReasoningStage[]` chain with per-signal justifications, contradiction detection, and alternative hypotheses — not just a score.

---

## Feature Matrix

| Area | Description |
|------|-------------|
| **Hex Viewer** | Raw bytes with offsets, grouping, ASCII, decoded values, jump-to, search, bookmarks |
| **Disassembly** | x86-64 instruction view, cross-references, annotations (accept/reject), address navigation |
| **Control Flow Graph** | ReactFlow canvas with TRUE/FALSE edge labels, MiniMap, layout depth, block-level metadata |
| **Strings** | Printable string extraction with classification, entropy scoring, and jump-to |
| **TALON Decompiler** | x86-64 IR lift, SSA form, constant folding + copy propagation, natural loop classification, intent-annotated pseudo-code |
| **STRIKE Debugger** | Windows CreateProcess/DebugActiveProcess, hardware step loop, register + memory snapshots, behavioral delta engine |
| **ECHO Signatures** | Fuzzy Jaccard matching + exact FNV-1a hashing; pattern export |
| **NEST Analysis** | Iterative multi-pass verdict with corpus benchmark harness and per-binary learning |
| **Verdict Engine** | 20-section signal aggregation, reasoning chain, contradiction detection, alternative hypotheses |
| **Knowledge Graph** | ReactFlow visualization of how signals combine into a verdict |
| **Operator Console** | Intent classification from plain text → step-by-step analysis workflow |
| **Intelligence Report** | JSON / Markdown export with full reasoning chain |
| **Auto-Annotations** | Confidence-scored suggestions; accept/reject per annotation |
| **Plugins** | Versioned C ABI; sandboxed per-timeout execution; hot-reload |
| **Corpus Benchmark** | Load, run, and compare NEST against a curated binary corpus |

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
# 131 tests across 9 suites — 0 failures expected
```

**Rust (cargo test)**
```bash
cargo test
# 27 tests — 0 failures expected
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
│       │   ├── disassemble.rs  # x86-64 disassembly, arch detection
│       │   ├── graph.rs        # CFG construction, back-edge detection
│       │   ├── inspect.rs      # PE/ELF header parsing, hashes
│       │   ├── debugger.rs     # Windows debug loop (CreateProcess, step, registers)
│       │   ├── plugin_browser.rs
│       │   └── run_plugins.rs  # Sandboxed plugin execution, 10 MB output cap
│       └── plugins/
│
├── HexHawk/                    # React + TypeScript frontend
│   └── src/
│       ├── App.tsx             # Root: state, routing, verdict computation
│       ├── components/         # 22 tab views + shared UI
│       │   ├── TalonView.tsx   # Pseudo-code + intent sidebar + loop structure panel
│       │   ├── StrikeView.tsx  # Live debugger timeline + behavioral delta
│       │   ├── EchoView.tsx    # Signature match browser
│       │   ├── NestView.tsx    # Iterative analysis dashboard
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
├── plugin-api/                 # Shared plugin C ABI
└── plugins/
    └── byte_counter/           # Example plugin
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Layer 0 — Intent   operatorConsole.ts                  │
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
│  correlationEngine (20 sections)                        │
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

Plugins are native shared libraries (`.dll` / `.so` / `.dylib`) that expose two symbols:

```c
// Metadata — called once on load
extern "C" const char* hexhawk_plugin_entry(void);

// Analysis entry point — called per run
extern "C" char* run_plugin(const uint8_t* data_ptr, size_t len);
```

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