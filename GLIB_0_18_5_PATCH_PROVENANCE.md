# HexHawk glib 0.18.5 patch provenance

HexHawk pins a patched copy of `glib` 0.18.5 to remediate
[RUSTSEC-2024-0429 / GHSA-wrw7-89jp-8q8g](https://github.com/advisories/GHSA-wrw7-89jp-8q8g)
in Tauri 2's Linux GTK3 dependency chain.

## Source custody

- Original crate: `https://static.crates.io/crates/glib/glib-0.18.5.crate`
- Original archive SHA-256: `233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5`
- Files in the original archive: 121
- Upstream backport commit: `ea720152f28e293ef4362ee844ee5cc499f32d2a`
- Upstream change: `https://github.com/gtk-rs/gtk-rs-core/commit/ea720152f28e293ef4362ee844ee5cc499f32d2a`
- HexHawk immutable source commit: `e81fb5b067d2e5236ca7bdf374ef96977e039050`

Commit `e81fb5b067d2e5236ca7bdf374ef96977e039050` contains the 121
checksum-verified crates.io files. They are byte-identical to the archive
except `src/variant_iter.rs`, where the upstream two-line fix makes the
out-argument pointer mutable and passes `&mut p` to `g_variant_get_child`.
The root Cargo patch pins this exact commit, avoiding a mutable branch or tag.

The patched crate is kept out of HexHawk's current source tree so CodeQL does
not misclassify pre-existing unsafe FFI internals in third-party `glib` as new
HexHawk code. A Linux-only release-mode integration test directly exercises
the corrected `VariantStrIter` path.

## Removal condition

Remove the pin and regression test when HexHawk moves to a supported Tauri
Linux stack that no longer resolves `glib` below 0.20, expected with Tauri's
GTK4 migration.
