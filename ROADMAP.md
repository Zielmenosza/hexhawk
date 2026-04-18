# HexHawk Roadmap

---

## Current State

The following is fully implemented and working:

**Backend (Rust / Tauri)**
- `inspect.rs` — file metadata, section layout, SHA-256 / SHA-1 / MD5 hashes
- `hex.rs` — raw byte range reads, printable string extraction
- `disassemble.rs` — x86-64 disassembly via Capstone (offset + length)
- `graph.rs` — control flow graph builder with block detection, edge types, hierarchical layout
- `plugin_browser.rs` — list and hot-reload external `.dll` / `.so` plugins
- `run_plugins.rs` — execute plugins over file bytes with timeout and size guards

**Frontend (React / TypeScript)**
- Tabs: Metadata · Hex Viewer · Strings · Disassembly · CFG · Pattern Intelligence · Plugins · Logs
- `patternIntelligence.ts` — pattern categorization, threat scoring, binary profiling
- `explainabilityEngine.ts` — score breakdowns with human-readable reasoning
- `determinismEngine.ts` — reproducible, fixed-threshold analysis
- `edgeCaseEngine.ts` — detection of benign-complex, packed-clean, and mixed-signal binaries
- `ThreatAssessment.tsx` — confidence factors, expandable breakdown, edge case warnings
- `PatternIntelligencePanel.tsx` / `PatternCategoryBrowser.tsx` — pattern browsing by category
- `WorkflowGuidance.tsx` — step-by-step analysis guidance driven by binary profile
- `SmartSuggestions.tsx` — context-aware next-step recommendations
- `FunctionBrowser.tsx` — function-level navigation
- Keyboard shortcuts with in-app help panel

**Plugin System**
- Stable JSON-over-C ABI with schema versioning
- 5 MB payload limit, 3-second execution timeout
- SHA-256 result hashing for cache invalidation
- `byte_counter` reference plugin

---

## Phase 2 — Deeper Analysis

*Goal: Improve what HexHawk can actually tell you about a binary.*

### 2.1 Architecture Detection
**Where:** `disassemble.rs`, `inspect.rs`

Currently disassembly is hardcoded to x86-64. Detect architecture from the file header and switch Capstone mode automatically.

- Read ELF `e_machine` or PE `Machine` field from `inspect.rs` and pass it through to `disassemble_file_range`
- Support at minimum: x86, x86-64, ARM32, AArch64
- Expose detected architecture in `FileMetadata` and display it in the Metadata tab

### 2.2 Import / Export Table Parsing
**Where:** `inspect.rs`

`imports_count` and `exports_count` are currently hardcoded to 0.

- Use the `object` crate's `ObjectSymbol` / `imports()` / `exports()` iterators
- Return name + address for each import and export
- Add an Imports tab or expand the Metadata tab with a collapsible imports list
- Feed import names into `patternIntelligence.ts` for additional threat signals (e.g. `VirtualAlloc`, `WriteProcessMemory`)

### 2.3 String Classification
**Where:** `hex.rs`, frontend

Strings are currently returned as raw text. Add basic classification:
- URL / IP / domain patterns (regex)
- Windows registry paths
- File system paths
- Base64-looking strings
- Show a `kind` badge next to each string in the Strings tab

### 2.4 Entropy Per Section
**Where:** `inspect.rs`

Add a Shannon entropy score (0–8) for each section.

- High entropy (> 7.0) on `.text` or unnamed sections → likely packed or encrypted
- Display as a small bar next to each section in the Metadata tab
- Feed into `edgeCaseEngine.ts` `isPackedButClean()` heuristic

---

## Phase 3 — UI Polish

*Goal: Make the app feel production-quality.*

### 3.1 File Open Dialog
**Where:** Frontend, `tauri.conf.json`

Currently the file path is entered as text. Replace with:
- A native file picker via Tauri's `dialog` plugin (`@tauri-apps/plugin-dialog`)
- Drag-and-drop a file onto the window to open it
- Recent files list stored in `localStorage`

**Steps:**
1. Add `@tauri-apps/plugin-dialog` to `src-tauri/Cargo.toml` and register it in `tauri.conf.json`
2. Add `tauri-plugin-dialog` to `Cargo.toml` dependencies
3. Replace the text input in `App.tsx` with a button that calls `open()` from the dialog plugin
4. Add a `recentFiles: string[]` state backed by `localStorage`

### 3.2 Resizable Panels
**Where:** Frontend

The layout is currently fixed columns. Replace with resizable split panes so the user can widen the hex viewer or disassembly panel.

- Use `react-resizable-panels` (small, zero-dependency)
- Persist panel sizes in `localStorage`

### 3.3 Hex Viewer Improvements
**Where:** `HexViewer.tsx` in `packages/ui-components`

- Highlight the byte currently selected in disassembly
- Click a byte to select it and show its decoded value (int8, uint8, int16, uint16, int32, float32)
- Group bytes into configurable column widths (8, 16, 32)

### 3.4 Disassembly <-> Hex Sync
**Where:** `App.tsx`, `DisassemblyView.tsx`

`Ctrl+J` already exists as a shortcut but the actual sync logic may be incomplete. Verify and implement:
- Selecting an instruction scrolls the Hex Viewer to that byte offset
- Selecting a byte range in the Hex Viewer highlights the corresponding instruction

### 3.5 CFG Layout Improvements
**Where:** `ControlFlowGraph.tsx`, `graph.rs`

- Zoom and pan controls on the CFG canvas
- Click a block to jump to that offset in the Disassembly tab
- Color blocks by type: entry (green), exit/return (red), external call (orange)

---

## Phase 4 — Plugin Ecosystem

*Goal: Make it easy to write and distribute plugins.*

### 4.1 Plugin Scaffolding CLI
Create a simple script (`scripts/new-plugin.ps1` / `new-plugin.sh`) that:
- Takes a plugin name as argument
- Copies the `byte_counter` structure into `plugins/<name>/`
- Renames identifiers throughout
- Prints next steps

### 4.2 Plugin Input/Output UI
**Where:** Frontend, `run_plugins.rs`

- Allow plugins to declare input parameters in their metadata JSON
- Render a small form in the Plugin tab for parameter input before running
- Show structured `details` output rendered as a table when `kind` is `analysis`

### 4.3 Plugin Marketplace / Registry
A local directory-based registry:
- `plugins/registry.json` listing known plugins with name, description, repo URL
- A "Browse" button in the Plugin tab that reads this file and shows what's available
- One-click build for locally cloned plugins

### 4.4 WASM Plugin Support
Longer term: allow plugins compiled to WebAssembly to run in-process via `wasmtime`.
- Removes the need for native `.dll` / `.so` per platform
- Safer isolation than `libloading`
- Define a WASM ABI mirror of the current C ABI

---

## Phase 5 — Export & Reporting

*Goal: Get analysis results out of HexHawk.*

### 5.1 Export Analysis Report
- Export the current analysis (metadata + strings + disassembly summary + threat score + plugin results) as:
  - Markdown
  - JSON
  - HTML (self-contained, for sharing)
- Add an Export button in the toolbar

### 5.2 Bookmarks Export
- Export bookmarks as CSV (address, label, note)
- Import bookmarks from CSV

### 5.3 Session Save / Restore
- Save entire session state (open file, scroll positions, bookmarks, plugin results) to a `.hexhawk` JSON file
- Open a `.hexhawk` file to restore a session

---

## Known Issues / Tech Debt

| Area | Issue | Priority |
|------|-------|----------|
| `disassemble.rs` | Architecture hardcoded to x86-64 | High |
| `inspect.rs` | `imports_count` / `exports_count` are always 0 | High |
| `graph.rs` | `mnemonic` field on `InstructionInfo` is never read | Low |
| `App.tsx` | File path is a plain text input | Medium |
| `styles-phase5.css` / `styles-phase6.css` | Multiple CSS files should be consolidated | Low |
| `HexHawk/src-tauri/plugins/` | Empty directory (plugins live at root) | Low |

---

## How to Pick Up a Task

1. Check the **Known Issues** table first — these are the safest starting points
2. For backend tasks, work in `src-tauri/src/commands/` and run `cargo check` to validate
3. For frontend tasks, run `yarn tauri:dev` from the root — Vite hot-reloads on save
4. Tauri commands must be registered in `src-tauri/src/main.rs` inside `tauri::generate_handler![]`
5. New TypeScript types that cross the Tauri invoke boundary should match the Rust `Serialize` structs exactly
