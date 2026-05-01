# HexHawk Roadmap

This roadmap reflects what HexHawk is now and what is next from the current shipped baseline.

## Baseline Completed

The following capability blocks are implemented and active:

- Decompiler loop reconstruction improvements (while/for recovery)
- Disassembly annotation engine with API and crypto heuristics
- STRIKE timeline intelligence (call stack, hot blocks, execution loop detection)
- MITRE ATT&CK mapping and IOC extraction for evidence enrichment
- Frontend test baseline stabilized at 670 passing tests
- STRIKE benchmark gate with deterministic challenge-derived fixtures, markdown artifacts, and committed baseline drift checks
- Phase 2 report workflow: saved snapshot checkpoints with analyst notes, diff-focused Markdown/JSON export, and cross-file snapshot history panel

## Current Priorities

### P0 - Report and Evidence Productization

Goal: turn the evidence pipeline into consistently consumable outputs for analysts and teams.

- ✅ Snapshot checkpoint workflow with analyst notes, diff exports, and cross-file history browser
- Expand CREST templates for incident and malware triage formats
- Add configurable evidence confidence thresholds in export profiles
- Standardize ATT&CK tactic/technique sections across all report modes
- Add IOC de-duplication and suppression lists for cleaner exports

Exit criteria:

- CREST outputs are consistent across sample classes
- ATT&CK + IOC sections require no manual cleanup for standard use cases

### P0 - Validation and Regression Hardening

Goal: keep confidence high as the engines evolve.

- Keep STRIKE benchmark fixtures, `latest.md`, and baseline drift checks current as debugger heuristics change
- Add targeted regression tests for loop reconstruction edge cases
- Add golden tests for disassembly annotations on known binaries
- Add robustness tests for ATT&CK mapping and IOC extraction false positives
- Add performance guardrails for annotation and evidence passes

Exit criteria:

- No regressions in structured pseudocode output across curated fixtures
- Stable annotation/evidence output shape under CI

### P1 - Debugger Depth and Usability

Goal: improve STRIKE usability for longer and noisier traces.

- Add timeline filters by event class and confidence
- Add call-stack view synchronization with disassembly and graph panels
- Add loop-cluster visualization for repeated execution regions
- Add bookmarkable timeline checkpoints

Exit criteria:

- Analysts can isolate high-signal dynamic events in under 30 seconds on long traces

### P1 - Disassembly UX Integration

Goal: make annotations first-class in analyst workflows.

- Add per-annotation category toggles
- Add severity color ramp standardization across panels
- Add source-trace links from annotation to evidence and report sections
- Add analyst feedback controls to mark annotation quality

Exit criteria:

- Annotation signal-to-noise can be tuned per workflow without losing critical findings

### P2 - Plugin and Extension Maturity

Goal: let external logic plug into the same evidence graph safely.

- Expand plugin contract docs and examples
- Add plugin capability declarations and runtime permissions metadata
- Add plugin-produced signal provenance in CREST outputs
- Add plugin quality checks for malformed outputs

Exit criteria:

- Third-party plugins can contribute structured findings without weakening trust boundaries

## Deferred Items

These remain valuable but are intentionally not in the current top priority lane:

- In-app keyboard shortcuts discovery panel refresh
- About/version badge UX refinements
- Additional cosmetic dashboard polish

## Success Metrics

Roadmap execution is tracked against:

- Build health: production frontend build must stay green
- Test health: pass rate remains 100 percent on mainline frontend suite
- Output quality: report completeness and false-positive rate trends
- Analyst efficiency: time-to-understanding on representative samples

## Update Policy

This roadmap is a living forward plan and is maintained as a current-state execution document, not a historical changelog.
