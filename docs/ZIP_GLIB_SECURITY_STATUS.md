# ZIP and GLib dependency security status

This records a partial remediation, not a waiver or a vulnerability-free claim.

## ZIP: GHSA-m665-v7pm-7grj / Dependabot #141

The application's direct ZIP dependency is raised from 9.0.4 to 9.0.5. Because
9.0.5's consistency checks are opt-in, OOXML analysis now explicitly calls
`ZipArchive::validate_header_consistency()` before looking for VBA projects or
reporting a macro-free result. A mismatch returns a parse error with no modules
or success signals. Existing decompression bounds and owner-only temporary-file
custody remain in place. Analysis does not use streaming extraction.

Three new inert regression tests cover valid macro-free input, a conflicting
local/central filename and a conflicting compression method. Before enabling
the validator, the two malformed cases failed their rejection assertions even
with ZIP 9.0.5 installed. After enabling it, all four selected OOXML tests pass,
including the unchanged oversized-VBA regression.

**Remaining:** `libsodium-sys-stable 1.24.0`, introduced by the Stronghold runtime,
uses ZIP 8.6.0 as a build dependency. Published 1.24.3 and the inspected official
upstream manifest still require ZIP `8.6`; they do not admit ZIP 9.0.5. Its MSVC
build script verifies the libsodium archive's Minisign signature before ZIP
extraction. That is bounded exposure evidence, not remediation of the package
advisory. The build-time ZIP instance remains affected by the published range.
This patch does not replace storage/crypto, falsify versions, suppress the
advisory or claim that #141 is fully resolved.

## GLib: GHSA-wrw7-89jp-8q8g / Dependabot #54

`glib 0.18.5` remains in the all-target/Linux GTK3 graph. The advisory fixes the
unsound `VariantStrIter` implementation in GLib 0.20.0. Updating only the direct
Linux test dependency cannot remove the runtime's GLib 0.18 cohort.

The locked Tauri 2.11.1 cohort uses GTK 0.18 and WebKit2GTK 2.0.2. Inspection of
published Tauri 2.12.5, runtime 2.12.2, runtime-wry 2.12.3, TAO 0.37.2 and WRY
0.57.1 confirms they still select GTK 0.18. WebKit2GTK 2.0.2 also requires GLib,
GIO and GDK 0.18. GTK 0.19.0 exists and selects GLib 0.22, but those controlling
packages cannot consume it under their current requirements.

A coordinated compatible upstream migration, or a separately reviewed and
approved backport strategy, is required. Absence on the Windows shipping target
is not an all-target remediation. This patch neither removes Linux support nor
dismisses the alert.

## Verification and authority

- Package versions and affected ranges are checked against GitHub advisory APIs
  and actual published package manifests, not inferred from the screenshot.
- Local targeted and full-workspace Rust tests are executed; GitHub CI and CodeQL
  results must be checked for the exact PR head before merge.
- Jev was used only for a sanitized review-focus suggestion. Its recommendation
  was interface compatibility (probability 0.86; provider confidence 0.82), not a
  security verdict, command approval or merge gate. Receipt:
  `jevrec-da0a95e9b922c11e59e0e441fb1c431e`, model `jev-1.14.0`.
- Do not describe this partial patch, a merged PR, or a green test run as closure
  of either alert. Read back Dependabot after the default-branch rescan.

## Public references

- https://github.com/advisories/GHSA-m665-v7pm-7grj
- https://github.com/zip-rs/zip2/releases/tag/v9.0.5
- https://github.com/advisories/GHSA-wrw7-89jp-8q8g
- https://github.com/jedisct1/libsodium-sys-stable/blob/master/Cargo.toml
- https://crates.io/crates/tauri/2.12.5
- https://crates.io/crates/webkit2gtk/2.0.2
- https://crates.io/crates/gtk/0.19.0
