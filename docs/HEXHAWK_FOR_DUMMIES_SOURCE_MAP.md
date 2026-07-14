# HexHawk for Dummies Source Map

Last updated: 2026-07-14

This map ties the main claims in `HEXHAWK_FOR_DUMMIES.md`, the consumer/product refresh, and `HEXHAWK_FOR_DUMMIES_CAPABILITY_INVENTORY.md` to repository evidence inspected for this publication.

## Product status and authority boundaries

| Claim | Source references |
| --- | --- |
| HexHawk is a Rust/Tauri/React/TypeScript native desktop reverse-engineering and binary-intelligence platform | `README.md`, `src-tauri/tauri.conf.json`, `HexHawk/package.json`, `src-tauri/Cargo.toml` |
| HexHawk 1.0.0 unsigned Windows release candidate for controlled local acceptance, not production/procurement/enterprise/updater/public release | `docs/CURRENT_STATUS.md`, `README.md`, `ROADMAP.md`, `docs/TESTER_RELEASE_STATUS.md`, `docs/HIGH_ASSURANCE_GUIDE.md` |
| GYRE is sole verdict authority | `docs/ENGINE_BOUNDARY_DOCTRINE.md`, `docs/HIGH_ASSURANCE_GUIDE.md`, `README.md` |
| NEST orchestrates evidence and does not replace GYRE | `docs/ENGINE_BOUNDARY_DOCTRINE.md`, `docs/nest_evidence_schema_spec.md`, `docs/nest_evidence_examples.md` |
| AETHERFRAME/Forge is optional bounded uplift/refinement/lineage and cannot mutate classification | `docs/ENGINE_BOUNDARY_DOCTRINE.md`, `docs/HIGH_ASSURANCE_GUIDE.md`, `HexHawk/src/components/IntelligenceReport.tsx` |
| TALON/STRIKE/ECHO are evidence or analyst surfaces | `README.md`, `docs/ENGINE_BOUNDARY_DOCTRINE.md`, `HexHawk/src/components/TalonView.tsx`, `StrikeView.tsx`, `EchoView.tsx` |
| CREST packages reports | `README.md`, `docs/ENGINE_BOUNDARY_DOCTRINE.md`, `HexHawk/src/components/IntelligenceReport.tsx` |
| NEXUS/AI/assistant layers are not security truth | `docs/ENGINE_BOUNDARY_DOCTRINE.md`, `docs/m10_ai_backbone.md`, `docs/m11_byok_ai.md` |
| Versioned projects save/reopen with persisted binary and immutable recorded GYRE linkage | `src-tauri/src/commands/project_persistence.rs`, `HexHawk/src/utils/projectPersistenceClient.ts`, `README.md`, `docs/CURRENT_STATUS.md` |
| NEST project linkage is advisory and bound to the recorded snapshot | `src-tauri/src/commands/nest_session_lifecycle.rs`, persistence/linkage tests, `docs/ENGINE_BOUNDARY_DOCTRINE.md` |
| Restart/cache-clear hydration rejects stale, malformed, missing, unsupported, mismatched, and cross-binary authority | project-persistence and persisted-verdict hydration tests; `docs/CURRENT_STATUS.md` |
| Reports and exports bind provenance to the immutable recorded snapshot | `HexHawk/src/utils/reportAuthorityProvenance.ts`, report/export authority tests, `docs/CURRENT_STATUS.md` |
| Current milestone branch/commit | `feature/project-persistence-e2e` at `ebbd068bd8d30f68bedc2940ed9b0c5bfc80b586`; `docs/CURRENT_STATUS.md` |
| Backend-recorded snapshot IDs are the authority root; renderer/schema markers and fixture values are not provenance proof | `src-tauri/src/commands/project_persistence.rs`, persisted-verdict hydration/linkage tests, `docs/ENGINE_BOUNDARY_DOCTRINE.md` |

## Build, launch, and packaging claims

| Claim | Source references |
| --- | --- |
| Root scripts include dev, build, test, typecheck, Rust lint/test, Tauri build | `package.json` |
| UI package scripts include Vite dev/build/preview, package, NEST/STRIKE benchmark scripts, Vitest | `HexHawk/package.json` |
| Tauri product config includes WebView2/bootstrap and bundle targets; configuration presence does not prove signing or updater readiness | `src-tauri/tauri.conf.json`, `docs/RELEASE_SIGNING_AND_UPDATER_PLAN.md` |
| Rust workspace members are `plugin-api`, `plugins/byte_counter`, and `src-tauri` | `Cargo.toml` |
| Backend package is `hexhawk-backend` v1.0.0 with `nest_cli` binary and trial feature | `src-tauri/Cargo.toml` |
| Current milestone validation: 124 Rust backend + 29 `nest_cli` = 153 Rust; 22 focused frontend persistence/provenance tests across seven files; `tsc --noEmit`, Vite production build, and `cargo check --release` passed; no claim that every historical frontend suite reran or hosted CI is green | `docs/CURRENT_STATUS.md`, `docs/TESTER_RELEASE_STATUS.md` |
| Verified MSI `HexHawk_1.0.0_x64_en-US.msi` SHA-256 `A6A298CCFD39F8C53346D23A1BC7EC7795E3251E34031678735BE9C116E09BDB` and NSIS `HexHawk_1.0.0_x64-setup.exe` SHA-256 `9FCC206AA60774F9CFD43E44994967517F8209B842FF266EE047346B5CE3AD61`; both `NotSigned` and uninstalled | `docs/CURRENT_STATUS.md`, `docs/TESTER_RELEASE_STATUS.md`, canonical local release evidence under `D:/Project/HexHawk/.local/releases/HexHawk-1.0.0-ebbd068-20260714-001856` |

## CLI claims

| Claim | Source references |
| --- | --- |
| `nest_cli` supports `disassemble`, `cfg`, `inspect`, `strings`, `identify`, and `serve --mcp` | `src-tauri/src/bin/nest_cli.rs`; command smoke run in validation report |
| `nest_cli identify` returns format/magic/file_size/header entropy | `src-tauri/src/bin/nest_cli.rs`; local smoke output in validation report |
| MCP tool list includes inspect, disassemble, strings, build_cfg, nest_results, inject_agent_signal, apply_patch | `src-tauri/src/bin/nest_cli.rs` |
| MCP `nest_results` is a live-session stub and agent signal/patch calls are approval-gated | `src-tauri/src/bin/nest_cli.rs` |

## GUI and backend command claims

| Claim | Source references |
| --- | --- |
| App tabs include metadata, hex, strings, cfg, plugins, disassembly, report, decompile, debugger, signatures, TALON, document, sandbox, constraint, STRIKE, ECHO, NEST, console, diff, repl, agent | `HexHawk/src/App.tsx` |
| Workspace tab bar groups Disassembly, CFG, Decompile, TALON, NEST, and REPL; Disassembly has internal Instructions/Patches/XRefs/Patterns tabs | `HexHawk/src/App.tsx`, `HexHawk/src/styles.css` |
| Tauri command registration includes inspect, strings, disassemble, graph, plugin, debugger, patch, document, sandbox, constraint, LLM, license, NEST lifecycle, REPL, FLIRT, structs, script | `src-tauri/src/main.rs` |
| Native runtime check uses `window.__TAURI_INTERNALS__` | `HexHawk/src/App.tsx`, `HexHawk/src/utils/qaUx.ts` |
| Stable UI selectors exist for load, metadata, strings, CFG, TALON, NEST, report, plugins, activity | `HexHawk/src/App.tsx` |

## Evidence extraction and analysis claims

| Claim | Source references |
| --- | --- |
| Metadata includes type, architecture, entry point, size, image base, sections, imports, exports, SHA256/SHA1/MD5 | `src-tauri/src/commands/inspect.rs`, `HexHawk/src/App.tsx` |
| Magic detection covers PE/MZ, ELF, Mach-O, PDF, ZIP, archive, script, PCAP/PCAPNG | `src-tauri/src/commands/inspect.rs`, `src-tauri/src/bin/nest_cli.rs` |
| Disassembly uses backend command and CLI range inputs | `src-tauri/src/commands/disassemble.rs`, `src-tauri/src/bin/nest_cli.rs` |
| CFG uses backend graph command and CLI range inputs | `src-tauri/src/commands/graph.rs`, `src-tauri/src/bin/nest_cli.rs` |
| Strings are exposed through backend and CLI | `src-tauri/src/commands/strings.rs`, `src-tauri/src/commands/hex.rs`, `src-tauri/src/bin/nest_cli.rs` |
| Report authority fields include `source_engine: gyre` and `gyre_is_sole_verdict_source` | `HexHawk/src/components/IntelligenceReport.tsx`, `HexHawk/src/types/nestEvidence.ts`, `docs/nest_evidence_examples.md` |

## Configuration and security claims

| Claim | Source references |
| --- | --- |
| Free/Pro/Enterprise tier gates and file/query limits | `HexHawk/src/utils/tierConfig.ts` |
| License verification and trial/full behavior | `src-tauri/src/commands/license.rs`, `HexHawk/src/utils/tauriLicense.ts`, `LicensePanel.tsx` |
| BYOK provider support for OpenAI, Anthropic, Ollama | `docs/m11_byok_ai.md`, `src-tauri/src/commands/llm.rs` |
| LLM approval, remote endpoint, context/token/timeout guardrails | `docs/m10_ai_backbone.md`, `src-tauri/src/commands/llm.rs` |
| Stronghold-backed provider key storage | `docs/m10_ai_backbone.md`, `docs/m11_byok_ai.md`, `src-tauri/src/commands/llm.rs` |
| Updater readiness is not claimed; configuration fields cannot substitute for exact signed-artifact updater metadata, endpoint, installation/update, and rollback validation | `src-tauri/tauri.conf.json`, `docs/RELEASE_SIGNING_AND_UPDATER_PLAN.md`, `docs/CURRENT_STATUS.md` |

## Plugin and extension claims

| Claim | Source references |
| --- | --- |
| Plugin API result schema, kind enum, C ABI entry symbol | `plugin-api/src/lib.rs` |
| Built-in sample ByteCounter plugin | `plugins/byte_counter/src/lib.rs` |
| Plugin install/list/uninstall/reload/directory commands | `src-tauri/src/commands/plugin_browser.rs` |
| Plugin execution reads file bytes, includes built-in and user plugins, has timeout, size, worker limits | `src-tauri/src/commands/run_plugins.rs` |
| Plugins have platform-specific extensions (`dll`, `dylib`, `so`) | `src-tauri/src/commands/plugin_browser.rs` |

## Validation source notes

- The publication did not read `docs/credentials.md` and does not include secrets.
- `docs/PERSONA_VALIDATION_REPORT_2026-05-16.md` was requested but was not present; tool output suggested only `docs/BOARD_UPDATE_2026-05-31.md` as a similar file.
- The repository had pre-existing modified and untracked files before this publication was created; see validation report.

## Screenshot and visual-aid source notes

The screenshot pass created `scripts/capture_hexhawk_screenshots.py` for manual active-window/full-screen capture and also used `scripts/automate_browser_dev_screenshots.cjs` with Playwright against the Vite browser/dev server at `http://127.0.0.1:5173/`. The resulting manifest is `docs/assets/hexhawk-for-dummies/capture_manifest.json`.

| Image | Captured workflow | Runtime mode | Source/UI references | Evidence status |
| --- | --- | --- | --- | --- |
| `01-launch-home.png` | First-run launch/onboarding screen | browser/dev mode | `WelcomeScreen.tsx`, `App.tsx` | Real browser/dev screenshot; not native proof |
| `02-open-safe-sample.png` | Load Binary panel before sample path | browser/dev mode | `App.tsx` load panel selectors | Real browser/dev screenshot |
| `03-analysis-workspace.png` | Safe sample path entered in Load Binary | browser/dev mode | `App.tsx` load/apply path flow | Real browser/dev screenshot |
| `04-strings-view.png` | Strings panel after applying safe sample path | browser/dev mode | `App.tsx`, strings command surface | Real browser/dev screenshot; browser simulation only |
| `05-disassembly-view.png` | Disassembly workspace/navigation | browser/dev mode | `App.tsx`, workspace tabs | Real browser/dev screenshot; browser simulation only |
| `06-gyre-verdict.png` | Verdict panel visible state | browser/dev mode | `BinaryVerdict.tsx`, `App.tsx` | Real browser/dev screenshot; GYRE authority captions preserved |
| `07-nest-evidence.png` | NEST browser simulation state | browser/dev mode | `NestView.tsx`, `App.tsx` NEST nav | Real browser/dev screenshot; not typed NEST bundle proof |
| `08-aetherframe-lineage.png` | AETHERFRAME/Forge lineage disclosure contract | rendered evidence card | `IntelligenceReport.tsx`, `IntelligenceReport.test.tsx`, boundary docs | Rendered from current authority doctrine fields; source-backed evidence card, not native runtime screenshot |
| `09-report-export.png` | Report/CREST panel | browser/dev mode | `IntelligenceReport.tsx`, `App.tsx` report nav | Real browser/dev screenshot; export parity not validated |
| `10-authority-fields.png` | Report authority area visible in browser/dev pass | browser/dev mode | `IntelligenceReport.tsx`, NEST evidence types | Real browser/dev screenshot; typed export fields not validated |
| `11-cli-identify.png` | `nest_cli identify Challenges/ch76/keygenme.exe` output | rendered from real CLI output | `src-tauri/src/bin/nest_cli.rs` | Command output was real; image is rendered documentation, not an OS terminal-window capture |
| `12-gated-state.png` | NEST simulation/state view used as feature-state orientation | browser/dev mode | `NestView.tsx`, tier/workflow source | Real browser/dev screenshot; not a product authority hierarchy |
| `13-troubleshooting-native-runtime.png` | Runtime diagnostic showing native Tauri not proven | browser/dev mode | `App.tsx`, `qaUx.ts` native-runtime checks | Real rendered diagnostic from page evaluation; native proof failed/absent |
| `00-unsigned-windows-warning-not-captured.png` | Windows trust-chain warning evidence for current tester artifacts | rendered evidence card from real command output | `scripts/release/sign-windows-artifact.ps1`, PowerShell `Get-AuthenticodeSignature`, release evidence docs | Replaced placeholder with real signature-status evidence capture; not a SmartScreen UI screenshot |

These screenshots are visual examples unless a row explicitly states otherwise. Browser/dev-mode captures must not be used as packaged native Tauri/WebView2 proof, installed-artifact export parity proof, or release-readiness evidence.


## 2026-07-09 consumer/product refresh source notes

| Claim | Source references |
| --- | --- |
| The For Dummies guide is comprehensive for the current buyer/tester/operator story, while release proof remains gated | `docs/HEXHAWK_FOR_DUMMIES.md`, `docs/TESTER_RELEASE_STATUS.md`, `docs/HIGH_ASSURANCE_GUIDE.md` |
| The plain-English product pattern is input, process, output, when-to-use, and what-not-to-claim | `docs/HEXHAWK_FOR_DUMMIES.md`, `README.md`, `site-build/index.html`, `site-build/features/index.html`, `site-build/docs/index.html` |
| Competitive positioning should be job-fit, not a universal decompiler/debugger replacement claim | `competitive_landscape.html`, `site-build/competitive_landscape.html`, `docs/INVESTOR_ONE_PAGER.md`, `docs/INVESTOR_DILIGENCE_BRIEF.md` |
| The website now exposes docs and compare paths for buyer-friendly evaluation | `site-build/index.html`, `site-build/features/index.html`, `site-build/products/index.html`, `site-build/docs/index.html` |
