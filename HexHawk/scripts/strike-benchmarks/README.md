# STRIKE Benchmarks

This directory contains the deterministic STRIKE benchmark inputs and baseline used by Phase 1 quality gating.

## Files

- `default-scenarios.json`: hand-authored canonical STRIKE scenarios that exercise core runtime pattern detection.
- `challenge-derived-scenarios.json`: replay fixtures derived from real NEST session logs under `nest_tests/`.
- `baseline.json`: committed quality baseline used for regression drift checks in CI.

## Workflow

1. Regenerate challenge-derived fixtures:
   - `yarn workspace hexhawk-ui strike:fixtures`
2. Run the benchmark against default and challenge-derived scenarios:
   - `yarn workspace hexhawk-ui strike:benchmark --stability-runs 3 --max-score-drop 5`
3. Update the committed baseline after an intentional quality improvement:
   - `yarn workspace hexhawk-ui strike:benchmark:update-baseline`

## Artifacts

Benchmark runs write outputs to `nest_tests/strike_benchmarks/`:

- `latest.json`: machine-readable benchmark artifact for CI and diff tooling.
- `latest.md`: markdown summary for quick review in pull requests and uploaded CI artifacts. Per-scenario provenance includes the originating challenge plus relative target, session-log, and result paths.

## Scoring Model

Each scenario is evaluated for:

- expected STRIKE pattern coverage
- call-depth / loop / hot-block expectations
- minimum or maximum risk thresholds
- false-positive penalties for forbidden tags
- stability across repeated runs
- regression deltas versus the committed baseline

A scenario passes only when all checks pass and no penalties are applied.

## Fixture Provenance

Challenge-derived scenarios include a `source` block with:

- challenge name
- target path
- session log path
- result path
- fidelity marker

These fixtures are not raw debugger traces. They are deterministic STRIKE replays derived from real session outcomes so benchmark drift remains stable across local and CI environments.
