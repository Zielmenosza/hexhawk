# HexHawk

A native desktop application for binary inspection and reverse engineering, built with Rust, Tauri 2, and React.

---

## Overview

HexHawk is a unified reverse engineering workspace designed to reduce context switching between tools. It combines raw binary inspection, disassembly, control flow analysis, and plugin-driven intelligence into a single environment.

---

## Features

| Area | Description |
|------|-------------|
| Metadata | File headers, sections, hashes, entry point |
| Hex Viewer | Raw byte view with offsets, ASCII, search, and interpretation |
| Strings | Extract printable strings with offsets and jump-to navigation |
| Disassembly | Instruction view with references, bookmarks, and navigation |
| Control Flow Graph | Visual CFG with block-level analysis |
| Pattern Intelligence | Threat scoring, behavior detection, smart suggestions |
| Plugins | Load, run, and hot-reload external analysis plugins |
| Logs | Runtime output and analysis history |

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Rust | Stable | Install via [rustup.rs](https://rustup.rs) |
| Node.js | 20+ | |
| Yarn | 1.x / Berry | `npm install -g yarn` |
| WebView2 | Any | Required on Windows |
| Visual Studio Build Tools | 2019+ | C++ workload required |

**macOS**
```bash
xcode-select --install
```

**Linux** — install:
- `libgtk-3-dev`
- `libwebkit2gtk-4.1-dev`
- `build-essential` (or equivalent)

---

## Getting Started

### 1. Clone & install
```bash
git clone https://github.com/your-org/hexhawk.git
cd hexhawk
yarn install
```

### 2. Build the sample plugin

Required for the Plugins tab:

```bash
cd plugins/byte_counter
cargo build
cd ../..
```

### 3. Run in development
```bash
yarn tauri:dev
```

This launches:
- Vite frontend (hot reload enabled)
- Tauri desktop window

---

## Build

**Frontend only**
```bash
cd HexHawk
yarn build
```
Output: `HexHawk/dist/`

**Full desktop app**
```bash
yarn tauri:build
```
Output: `src-tauri/target/release/bundle/`

---

## Project Structure

```
hexhawk/
├── Cargo.toml              # Rust workspace
├── package.json            # Yarn workspace
│
├── src-tauri/              # Rust backend
│   ├── src/
│   │   ├── main.rs
│   │   ├── commands/
│   │   │   ├── hex.rs
│   │   │   ├── disassemble.rs
│   │   │   ├── graph.rs
│   │   │   ├── inspect.rs
│   │   │   ├── plugin_browser.rs
│   │   │   └── run_plugins.rs
│   │   └── plugins/
│   └── tauri.conf.json
│
├── HexHawk/                # React frontend
│   ├── src/
│   │   ├── App.tsx
│   │   ├── components/
│   │   ├── utils/
│   │   └── types/
│   └── vite.config.ts
│
├── plugin-api/             # Shared plugin ABI
├── plugins/
│   └── byte_counter/
└── packages/
    └── ui-components/
```

---

## Plugin Development

Plugins are shared libraries (`.dll`, `.so`, `.dylib`) that expose:

```c
extern "C" const char* hexhawk_plugin_entry(void);
extern "C" char* run_plugin(const uint8_t* data_ptr, size_t len);
```

### Plugin Result Schema (v1)

```json
{
  "schema_version": 1,
  "plugin": "MyPlugin",
  "version": "1.0.0",
  "success": true,
  "summary": "Short result string",
  "details": {},
  "kind": "analysis",
  "plugin_hash": "abc123"
}
```

**Constraints**
- Max payload: 5 MB
- Timeout: 3 seconds
- Output must be valid JSON

**Supported `kind` values:** `metric` · `analysis` · `strings` · `warning` · `error`

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+D` | Disassembly |
| `Ctrl+H` | Hex Viewer |
| `Ctrl+B` | Add bookmark |
| `Ctrl+Shift+B` | Bookmarks panel |
| `Ctrl+J` | Jump to hex |
| `Ctrl+F` | Search |
| `Ctrl+G` / `Ctrl+Y` | Back / Forward |
| `?` | Help panel |

---

## Troubleshooting

**Tauri fails to start** — check Rust is installed:
```bash
cargo --version
```

**Blank window** — wait for the Vite dev server to finish starting, then check Vite logs for errors.

**No plugins** — build the plugin first:
```bash
cd plugins/byte_counter && cargo build
```

**Plugin fails to load** — confirm the `.dll` / `.so` exists in:
```
plugins/byte_counter/target/debug/
```

---

## License

MIT — see [LICENSE](LICENSE).