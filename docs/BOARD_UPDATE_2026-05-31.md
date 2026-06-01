# HexHawk Board Update — 2026-05-31

## Headline

HexHawk now has a repaired Windows installer build path. The product is ready for controlled internal/board/investor demonstration as an unsigned tester candidate.

## What Changed

- Fixed Tauri WebView2 installer configuration so the Rust/Tauri build accepts the config.
- Disabled updater artifact generation for the local unsigned tester build because signing credentials are not configured.
- Rebuilt Windows release executable, MSI installer, and NSIS installer.
- Verified MSI administrative extraction.
- Verified extracted CLI can identify a real PE challenge file.

## Current Evidence

- Frontend tests: 683 passing.
- Rust tests: 85 passing.
- Typecheck/build/check/test/package: passing.
- MSI and NSIS artifacts: produced.
- Artifacts: unsigned.

## Board-Relevant Interpretation

This is a real packaging milestone: HexHawk is no longer blocked at “can we produce a Windows installer?”

The next board-level risk is not core product credibility; it is release discipline:

1. sign the binaries;
2. validate installed native GUI export parity;
3. define controlled pilot/support flow;
4. avoid public-release claims until those are complete.

## Recommended Next Decision

Approve a short release-hardening sprint focused on:

- Windows code signing;
- signed updater artifacts;
- installed-artifact GUI parity proof;
- public download/checksum/signing page;
- paid pilot package and support process.
