# HexHawk glib 0.18.5 patch provenance

HexHawk vendors `glib` 0.18.5 solely to remediate
[RUSTSEC-2024-0429 / GHSA-wrw7-89jp-8q8g](https://github.com/advisories/GHSA-wrw7-89jp-8q8g)
in Tauri 2's Linux GTK3 dependency chain.

## Source custody

- Original crate: `https://static.crates.io/crates/glib/glib-0.18.5.crate`
- Original archive SHA-256: `233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5`
- Files in the original archive: 121
- Upstream backport commit: `ea720152f28e293ef4362ee844ee5cc499f32d2a`
- Upstream change: `https://github.com/gtk-rs/gtk-rs-core/commit/ea720152f28e293ef4362ee844ee5cc499f32d2a`

The 121 original crate files are byte-identical to the crates.io archive except
`src/variant_iter.rs`. The applied change is the upstream two-line fix: make
its out-argument pointer mutable and pass `&mut p` to
`g_variant_get_child`.

## Removal condition

Remove this vendored patch when HexHawk moves to a supported Tauri Linux stack
that no longer resolves `glib` below 0.20, expected with Tauri's GTK4 migration.
