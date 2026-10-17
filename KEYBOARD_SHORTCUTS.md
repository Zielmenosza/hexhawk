# HexHawk Keyboard Shortcuts

**Updated:** 2026-08-20

The current interface uses beginner-facing names. Technical labels are included below in parentheses.

Press `?` or `Ctrl+Shift+/` to open or close the in-app shortcuts overlay.

## Navigation and analysis

| Shortcut | Current action |
|---|---|
| `Ctrl+D` | Open **Read program instructions** (`Disassembly`). |
| `Ctrl+H` | Open **View exact file bytes** (`Hex Viewer`). |
| `Ctrl+Shift+B` | Open bookmarks. |
| `Ctrl+G` | Open the jump-to-address dialog. |
| `Ctrl+Alt+G` | Go back in address navigation history. |
| `Ctrl+Y` | Go forward in address navigation history. |
| `Ctrl+I` | Run **Start inspection** for the current file. |
| `Ctrl+S` | Run **Find readable text** instead of opening the browser save dialog. |
| `Ctrl+R` | Show or hide the references panel. |
| `Ctrl+F` | Focus the first visible search field in the current tool. |
| `Ctrl+B` | Add or toggle a bookmark at the current address. |
| `Ctrl+J` | Jump from the selected instruction to the matching byte location. |
| `F` | Open function details for the selected/focused function or address. |
| `↑` / `↓` | Move through instructions when the instruction list has focus/context. |

## Help and bounded diagnostic controls

| Shortcut | Action |
|---|---|
| `?` | Toggle the shortcuts overlay. |
| `Ctrl+Shift+/` | Toggle the shortcuts overlay. |
| `Esc` | Close an open dialog/overlay where supported. |
| `Ctrl+Alt+Shift+H` | Toggle the internal self-heal diagnostic banner. This does not change the GYRE assessment. |

## Usage notes

- Shortcuts are ignored while typing in text inputs or text areas.
- Some actions require a loaded file, completed inspection, or selected address/function.
- `Ctrl+S` scans strings; it does not save a document.
- `Ctrl+G` now opens the jump dialog. Back navigation moved to `Ctrl+Alt+G`.
- The in-app overlay is the runtime source of truth if this document and a future build differ.

## Safe workflow example

1. Open a trusted test file with **Open a file**.
2. Press `Ctrl+I` to **Start inspection**.
3. Press `Ctrl+S` to **Find readable text**.
4. Press `Ctrl+D` to **Read program instructions**.
5. Move with the arrow keys, press `F` for one function, and use `Ctrl+B` to bookmark evidence.
6. Press `Ctrl+J` to inspect the exact bytes behind a selected instruction.

Keyboard shortcuts never grant containment. **Live Debugger** still executes the selected file and should only be used with trusted software in an approved runtime environment.
