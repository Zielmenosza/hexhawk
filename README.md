# HexHawk

> **Bounded Windows first-release candidate — RC HOLD.** This engineering build is not release approved or safety-certified. Its scope is authorized local PE32/x86 and PE32+/x64 EXE/DLL files up to 64 MiB, analyzed as data without execution: open → inspect/static analysis → GYRE verdict/evidence/limitations → identity-consistent JSON/Markdown reports. NEST manages evidence; CREST packages it; advisory output cannot replace GYRE authority.
>
> Native sidebar workflows outside that journey are disabled independently of license tier. Scripting/REPL, plugins, live debugging/memory editing, sandboxing, patching, comparison, saved-history restoration, function/decompiler/advisory-AI workspaces, online AI, updates and other input formats/platforms are excluded. Legacy feature descriptions/screenshots below are background, not qualification or availability claims for this candidate. Remaining dependency/security, notices/legal, signing and independent release approvals are open.

HexHawk is a local-first Windows reverse-engineering and binary-analysis workbench. It helps an analyst open a file, establish its identity, inspect bytes and code, organize evidence, review a GYRE-owned assessment, and export a report another person can check.

> **Current posture — 2026-08-20:** technical preview. The current Windows NSIS build is unsigned and may trigger SmartScreen. HexHawk is not a malware sandbox, a safety certificate, or a replacement for analyst judgment.

![Legacy HexHawk browser preview](docs/assets/hexhawk-for-dummies/03-analysis-workspace.png)

This is a legacy browser/dev preview, not a current native-runtime or release qualification screenshot. See [source verification and remaining gates](docs/RELIABILITY_VERIFICATION.md).

The persistent **Current tool** header always shows:

- the beginner-facing tool name;
- a plain-language explanation;
- the technical label used by experienced analysts;
- the matching tool icon.

## Start here

- **New to HexHawk:** [HexHawk for Dummies](docs/HEXHAWK_FOR_DUMMIES.md)
- **High-assurance use:** [High-Assurance Guide](docs/HIGH_ASSURANCE_GUIDE.md)
- **Current tester posture:** [Tester Release Status](docs/TESTER_RELEASE_STATUS.md)
- **Keyboard use:** [Keyboard Shortcuts](KEYBOARD_SHORTCUTS.md)
- **Plugins:** [Plugin Quick Reference](PLUGIN_QUICK_REFERENCE.md)
- **Authority rules:** [Engine Boundary Doctrine](docs/ENGINE_BOUNDARY_DOCTRINE.md)
- **Market fit:** [Competitive Landscape](competitive_landscape.html)

## Safe first analysis

1. Use a file you are authorized to inspect.
2. Open HexHawk. The interface should appear normally; a manual refresh is not part of startup.
3. Select **Open a file** (`Load Binary`) and choose the file.
4. Select **Start inspection** (`Inspect`). Run this before tools that need parsed file facts.
5. Review **File summary** (`Metadata`) and **Find readable text** (`Strings`).
6. Use **Read program instructions** (`Disassembly`) and **See possible code paths** (`CFG`) where useful.
7. Review **Overall assessment** (`Verdict`) and **Reasons behind the result** (`Signals`).
8. Use **Repeat and organize checks** (`NEST`) when evidence conflicts or needs a stronger lifecycle record.
9. Use **Create a report** (`Report`) to package identity, evidence, authority markers, and limitations.

### Important runtime warning

**Live Debugger** (`Debugger`) launches the selected file. Use it only with software you trust and only in an environment approved for runtime investigation. **Run inspection scripts** (`Sandbox`) is a helper-script surface; it is not a malware detonation sandbox.

## Current tool names

`HexHawk/src/components/WorkflowNav.tsx` is the terminology source of truth.

| Group | Beginner-facing name | Technical label | What it does |
|---|---|---|---|
| File | Open a file | Load Binary | Select the local file to examine. |
| File | File summary | Metadata | Show type, platform, size, fingerprints, and file regions. |
| Understand the file | Start inspection | Inspect | Record file facts needed by later tools. |
| Understand the file | View exact file bytes | Hex Viewer | Show the bytes stored on disk. |
| Understand the file | Find readable text | Strings | Find URLs, paths, names, messages, and other text clues. |
| Understand the file | Read program instructions | Disassembly | Translate machine code into processor instructions. |
| Understand the file | See possible code paths | CFG | Map decisions, loops, and exits. |
| Understand the file | Examine one function | Function Notebook | Gather calls, callers, readable code, and evidence for one function. |
| Understand the file | Read code-like text | Decompile | Produce estimated pseudocode, not original source. |
| Understand the file | Explain selected code | TALON | Explain selected code and show supporting evidence. |
| Understand the file | Review AI suggestions | AI Observations | Show advisory explanations and next steps. |
| Results and records | Overall assessment | Verdict | Present the GYRE-owned classification, confidence, evidence, and unknowns. |
| Results and records | Reasons behind the result | Signals | Show the reasons that influenced the assessment. |
| Results and records | Create a report | Report | Package evidence and limitations for review. |
| Results and records | Open earlier results | Snapshot History | Reopen saved inspection results. |
| Results and records | Repeat and organize checks | NEST | Manage evidence through repeated review passes; it does not own the verdict. |
| Results and records | See what happened | Activity | Review actions, warnings, and errors from the session. |
| Advanced tools | Plan changes to the file | Patch | Prepare exact changes for review before applying anything. |
| Advanced tools | Work out required inputs | Constraint | Suggest inputs that may lead to a chosen path. |
| Advanced tools | Run inspection scripts | Sandbox | Run available inspection helpers; not a malware sandbox. |
| Advanced tools | Live Debugger | Debugger | Execute trusted software under debugger control. |
| Advanced tools | Compare two files | Binary Diff | Compare bytes, text, functions, blocks, and assessment changes. |
| Advanced tools | Run advanced commands | REPL | Run experienced-user inspection commands. |
| Advanced tools | Review AI-proposed notes | Agent Gate | Accept or reject advisory notes; notes cannot change the assessment. |
| Add-ons | Run add-on tools | Plugin Manager | Run built-in or approved local plugins. |
| Help | Learn how to use HexHawk | Help | Show workflows, shortcuts, and common fixes. |
| Help | Automate runtime queries | STRIKE API | Document scriptable runtime-observation queries. |
| Help | About HexHawk | About HexHawk | Explain local processing and judgment boundaries. |

## Authority and evidence boundaries

- **GYRE owns the verdict and base confidence.**
- **NEST stores, organizes, and manages evidence through its lifecycle.** It does not replace GYRE.
- **AETHERFRAME is bounded advisory governance.** It may attach lineage, budgets, uncertainty, checkpoints, and proof limits; it cannot change a GYRE verdict or NEST evidence.
- **TALON, STRIKE, ECHO, plugins, debugger output, decompiler output, comparison output, and AI observations are supporting evidence or advisory help.**
- **CREST/report output packages evidence.** Packaging does not create a new verdict authority.
- **NEXUS/AI assistance is advisory and must remain labelled.**

A suspicious clue is not proof of malware. A clean-looking assessment is not a permanent safety guarantee.

## Windows installation and artifact verification

The current locally verified deliverable is an unsigned NSIS installer named:

```text
target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe
```

Use the adjacent `HexHawk_1.0.0_x64-setup.exe.sha256` sidecar or the current release handoff to obtain the expected hash. The exact hash is intentionally not embedded in these packaged docs: changing a document inside the installer changes the installer hash.

Verify from the bundle folder with:

```bash
cd target/release/bundle/nsis
sha256sum -c HexHawk_1.0.0_x64-setup.exe.sha256
```

The expected result is `HexHawk_1.0.0_x64-setup.exe: OK`. This records repository-local validation; it is not a public distribution or signing claim.

## Build and validate from source

Prerequisites: Windows 10/11, WebView2, Rust/Cargo, Node.js, and the repository's Yarn 4 toolchain.

```bash
yarn install
yarn typecheck
yarn test --reporter=dot
npm --prefix HexHawk run build
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

Development desktop app:

```bash
yarn tauri:dev
```

NSIS-only build:

```bash
node node_modules/@tauri-apps/cli/tauri.js build --bundles nsis
```

The configured Tauri build hook uses `yarn workspace hexhawk-ui build`. Do not treat a Vite browser preview as packaged-native proof.

## What HexHawk does not claim

HexHawk does not claim to:

- certify a file as safe;
- detonate malware in an isolated cloud sandbox;
- bypass protections;
- prove exploitability or shell access from one signal;
- recover exact original source code;
- let AI or NEST silently replace GYRE;
- be a universal replacement for IDA Pro, Ghidra, Binary Ninja, Cutter, or x64dbg;
- be publicly trusted or procurement-ready while the Windows artifact remains unsigned.

## Repository map

```text
HexHawk/                  React/TypeScript desktop interface
docs/                     Product, operator, assurance, and evidence documentation
src-tauri/                Rust/Tauri backend and Windows packaging
plugin-api/               Plugin ABI and result model
plugins/                  Built-in/sample plugins
site-build/               Static public-site deployment inputs
competitive_landscape.html Editorial source for the comparison page
```

Historical evidence, dated run reports, deployment captures, and archived decision records intentionally preserve what was true at their recorded time. They are not silently rewritten to resemble the current release.
