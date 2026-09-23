# HexHawk

**HexHawk is a local-first reverse-engineering workbench for examining binaries, following the evidence, and producing reports that another analyst can actually review.**

It is built with **Rust, Tauri, React, and TypeScript** and is designed around a fairly simple idea:

> Tools can help an analyst understand a binary, but they should not quietly turn guesses into facts.

HexHawk brings static analysis, disassembly, function analysis, decompiler output, debugger evidence, signature matching and reporting into one desktop workflow while keeping the source and confidence of that evidence visible.

You can open a local binary, investigate what it contains and how it behaves, follow relationships between functions and evidence, and export the results for later review.

---

## What HexHawk Does

At a high level, the workflow looks like this:

**Binary → Evidence → Analysis → Correlation → Verdict → Report**

Give HexHawk a supported local file such as an:

* EXE
* DLL
* SYS
* BIN
* supported sample path

HexHawk can then help you inspect things such as:

* binary identity and metadata
* strings and imports
* disassembly
* control flow
* cross-references
* function boundaries
* calling conventions
* Win32 constants
* pseudocode
* debugger and trace observations
* signatures and related binaries
* evidence associated with individual functions

The end result can be exported as a reviewable report or evidence package that keeps source information, uncertainty and known limitations attached.

HexHawk is therefore best thought of as an **analyst workbench**, not a one-click "tell me whether this file is safe" tool.

---

## Why HexHawk Exists

Reverse engineering usually means moving between several different views and tools.

One tool shows disassembly.

Another helps with debugging.

Another searches signatures.

Notes end up somewhere else.

Then, eventually, somebody has to work out which observations are actual evidence, which are reconstruction, and which are simply educated guesses.

HexHawk is trying to bring those pieces into one coherent workflow.

More importantly, it deliberately separates **evidence** from **verdicts**.

Decompiler output does not automatically become truth.

Debugger observations do not silently rewrite static conclusions.

AI assistance does not get to make an authoritative classification.

Each subsystem has a specific job and a defined boundary.

---

## The HexHawk Engines

HexHawk uses several named components internally. You do not need to understand all of them before using the application, but this is what they are responsible for.

### GYRE

**GYRE is the final classification authority.**

It owns the base verdict and confidence.

Other engines can provide evidence or bounded confidence refinement, but they do not silently replace GYRE's classification.

### NEST

**NEST organizes and converges evidence.**

It collects supporting information and packages evidence around GYRE's verdict.

NEST helps answer:

> "What evidence supports this conclusion?"

It does not create an independent competing verdict.

### TALON

**TALON handles decompilation and structured pseudocode.**

Its output is useful for understanding what code appears to be doing, but reconstructed pseudocode remains advisory rather than authoritative.

### STRIKE

**STRIKE handles runtime and debugger evidence.**

It tracks things such as execution observations, call stacks, traces and behavioral differences discovered while the program is running.

Runtime evidence can strengthen an investigation, but STRIKE does not own the final classification.

### ECHO

**ECHO handles signature and cross-binary correlation.**

This includes exact and fuzzy matching that can help identify relationships between the file being examined and previously known material.

### AETHERFRAME / Forge

**AETHERFRAME provides optional evidence refinement, confidence uplift and lineage metadata.**

Its contribution is bounded by policy.

It cannot change GYRE's underlying classification.

The standalone AetherFrame core is product-agnostic and adapter-driven. HexHawk is one integration and proving ground for it rather than the conceptual owner of AetherFrame itself.

### CREST

**CREST packages analysis into reports and exports.**

Its job is to turn the investigation into something another analyst can read, review and hand off.

### NEXUS

**NEXUS is the assistant/consumer layer.**

It can help a user interact with the available analysis, but it does not own classification truth.

---

## Function Intelligence

A major part of the current HexHawk work is **Function Intelligence**.

Instead of making an analyst jump between unrelated views, Function Intelligence brings the evidence associated with a selected function together in one place.

The Function Notebook can show things such as:

* imports used by the function
* outgoing and incoming calls
* pseudocode
* calling-convention information
* runtime observations
* known limitations
* related evidence

Function Intelligence can also be exported as **JSON or Markdown**.

It is still an advisory evidence layer.

The hierarchy remains:

**GYRE owns classification.**

**NEST organizes evidence.**

**TALON reconstructs code.**

**STRIKE contributes runtime observations.**

Function Intelligence brings those pieces together without pretending they all carry the same level of authority.

---

## Current Capabilities

HexHawk currently includes:

* native Tauri desktop application
* Rust backend commands
* React + TypeScript frontend
* binary identity and metadata inspection
* string extraction
* disassembly
* control-flow analysis
* evidence workflows
* report generation
* PE import-table parsing
* queryable cross-reference indexing
* function-boundary recovery heuristics
* Win32 constant annotation
* calling-convention inference
* Function Intelligence
* Function Notebook
* JSON and Markdown function exports
* debugger/trace evidence
* NEST evidence bundle validation
* GYRE verdict-source validation
* ECHO signature correlation
* optional AETHERFRAME lineage and report metadata
* stable GUI selectors for workflow testing
* export-parity validation
* local/offline analysis
* optional BYOK AI integration where configured
* trial and licensed feature paths
* Windows MSI and NSIS packaging support

TALON has also received work around:

* CFG/disassembly range alignment
* fallback block partitioning
* cross-block argument recovery
* first-pass semantic naming
* intermediate-representation artefact cleanup

---

## Recent Function Intelligence Work

The current Function Intelligence layer builds on several earlier HexHawk releases:

| Version     | Work introduced                                                                                                                   |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------- |
| v1.17.0     | PE import-table parsing                                                                                                           |
| v1.18.0     | Queryable xref index                                                                                                              |
| v1.19.0     | Function-boundary recovery heuristics                                                                                             |
| v1.20.0     | Win32 constant semantic annotation                                                                                                |
| v1.21.0     | TALON pseudocode IR cleanup                                                                                                       |
| v1.22.0     | Debugger call-stack reconstruction                                                                                                |
| v1.23.0     | Conditional breakpoint expressions                                                                                                |
| v1.24.0     | Calling-convention inference                                                                                                      |
| v1.25–v1.30 | Function Intelligence model, static/runtime correlation, exports, Function Notebook, workflow integration and regression coverage |

Together, these features form the current function-level evidence view rather than a collection of unrelated analysis features.

---

## Current Project Status

As of the **2026-07-09 documentation refresh**, the current source tree should be considered a **validated Function Intelligence source candidate and controlled early-access workbench**.

The relevant development branch is:

```text
feature/re-workbench-core-next
```

Recent source tags include:

```text
v1.30.0-function-intelligence-regression
v1.31.0-byte-counter-clippy-fix
```

The current source validation completed successfully:

* Rust workspace tests: **85 backend tests**
* `nest_cli`: **20 tests**
* plugin/doc-test crates: completed with no tests where applicable
* `cargo clippy --workspace -- -D warnings`: passed
* `npx tsc --noEmit`: passed
* frontend Vitest: **59 files / 832 tests**
* `yarn build`: passed

The frontend build still reports the existing Vite chunk-size/dynamic-import warnings.

### What that does not mean

A passing source tree is not automatically a releasable installer.

The current source state still requires a fresh release build and artifact-level validation before it should be treated as a deployment or public-release candidate.

In particular, the exact release artifacts still need:

* clean release-worktree rebuild
* artifact hashes
* signing verification
* installer smoke testing
* Function Notebook smoke testing
* export smoke testing

Older June 20/21 release evidence remains useful as historical provenance, but it does **not** prove that newly produced v1.30/v1.31 artifacts pass those same gates.

---

## Release Status

| Stage                                   | Status                 |
| --------------------------------------- | ---------------------- |
| Source candidate                        | ✅ Validated            |
| Fresh unsigned deployment candidate     | ⏳ Pending release gate |
| Controlled external signed-tester build | ❌ Not yet              |
| Public release candidate                | ❌ Not yet              |
| Public-trusted signing                  | ❌ Not yet verified     |
| Updater ready                           | ❌ No                   |
| Enterprise/procurement ready            | ❌ No                   |

Authenticode verification on the **exact generated artifacts** is required before a build should be described as publicly trusted or signed.

---

## What HexHawk Is Not

HexHawk is deliberately **not** intended to be:

* a one-click malware/safety verdict generator
* an automatic sandbox detonation platform
* an unchecked AI analysis engine
* a system where decompiler guesses silently become facts
* a replacement for analyst judgment
* a public or enterprise-ready product before its release gates have actually passed

The goal is reviewable analysis, not artificial certainty.

---

## Getting Started

### Requirements

For the current internal Windows workflow you will need:

* Windows 10 or Windows 11
* Rust/Cargo toolchain
* Node.js environment
* Yarn
* the project's frontend and Rust dependencies

HexHawk uses **WebView2** through its Tauri desktop shell. Installer builds are configured to bootstrap the required WebView2 runtime.

> **Unsigned build warning**
>
> Until an organization-trusted signing process is configured and verified, locally generated installers may trigger Windows security warnings.

---

## Build From Source

Install the frontend dependencies:

```bash
yarn install
```

Check the TypeScript source:

```bash
npx tsc --noEmit
```

Build the frontend:

```bash
yarn build
```

Run the Rust checks:

```bash
cargo check --workspace
cargo test --workspace
```

Build the Tauri application:

```bash
yarn tauri:build
```

---

## Full Validation

The following commands were used for the current source-validation claims:

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings

cd HexHawk

npx tsc --noEmit

TEST_FILES=$(find src \( -name '*.test.ts' -o -name '*.test.tsx' \) \
  | grep -v node_modules \
  | sort \
  | tr '\n' ' ')

npx vitest run --reporter=dot $TEST_FILES

yarn build
```

These validate the source tree.

They do **not** replace the packaging, signing, installer or application smoke-test gates required for an actual release.

---

## For New Evaluators

If you are looking at HexHawk for the first time, a useful mental model is:

```text
Load a binary
     ↓
Inspect the facts
     ↓
Explore code and functions
     ↓
Collect static + runtime evidence
     ↓
Correlate supporting information
     ↓
Review the GYRE-backed conclusion
     ↓
Export the investigation
```

The important part is that the steps remain inspectable.

You should be able to tell:

* where evidence came from
* whether something was observed or inferred
* which component produced it
* what limitations apply
* who owns the final classification

That distinction is central to the project.

---

## Documentation

If you are completely new to HexHawk, start with:

```text
docs/HEXHAWK_FOR_DUMMIES.md
```

That document is intended to provide the more detailed beginner and evaluator walkthrough.

For competitive and job-fit positioning against established reverse-engineering tools, see:

```text
competitive_landscape.html
```

---

## Development Philosophy

HexHawk follows a few important rules.

### Evidence should remain evidence

A useful observation should not silently become a verdict simply because several tools agree with it.

### Reconstruction is not ground truth

Decompiler output can be extremely useful while still being an approximation of the original source.

### Runtime and static analysis are complementary

What a program appears capable of doing and what it actually does during a particular trace are different forms of evidence.

Both matter.

Neither should erase the other.

### Automation should help the analyst, not hide the analysis

AI and automated correlation are useful when they reduce repetitive work and expose relationships.

They become dangerous when they hide uncertainty.

### Reports should survive handoff

An investigation should make sense to somebody other than the person who performed it.

That means conclusions need evidence, source labels and limitations attached to them.

---

## In Short

HexHawk is being built as a **local reverse-engineering workbench where analysts can inspect binaries, follow function-level evidence, combine static and runtime observations, and export reviewable findings without losing track of what is fact, reconstruction or inference.**

The source is currently in a validated early-access state.

The next major boundary is not adding another analytical feature.

It is proving that the **exact packaged artifacts** satisfy the signing, installer, smoke-test and release gates required to move from a validated source tree to a trustworthy distributable build.
