# HexHawk Plugin Quick Reference

**Updated:** 2026-08-20

In the current interface, plugins live under **Run add-on tools** (`Plugin Manager`). Plugins can add local metrics or observations, but they do not own the GYRE verdict.

> A native plugin is executable code. Install only plugins you trust and review their origin, hash, version, and source where available.

## Operator workflow

1. Open and inspect a file.
2. Select **Run add-on tools**.
3. Open the approved plugin directory or choose a built-in plugin.
4. Confirm the plugin name, version, origin, and hash.
5. Run it on the current file.
6. Review the result kind, summary, details, errors, and hash.
7. Treat the result as supporting evidence and corroborate it.

## Host guardrails

| Guard | Current limit |
|---|---:|
| Installed plugin binary | 64 MB |
| Input file for plugin execution | 512 MB |
| Execution timeout | 3 seconds |
| In-flight plugin workers | 8 |
| Returned JSON | 5 MB |

Limits reduce accidental resource abuse; they are not a security sandbox.

## Result schema (v1)

```json
{
  "schema_version": 1,
  "plugin": "ByteCounter",
  "version": "1.0.0",
  "success": true,
  "summary": "12345 bytes",
  "details": { "byte_count": 12345 },
  "kind": "metric",
  "plugin_hash": "example-hash"
}
```

Kinds:

- `metric` — compact value or counter;
- `analysis` — structured result/details;
- `strings` — a list of text/address observations;
- `warning` — non-fatal concern;
- `error` — failed or rejected execution.

## Plugin ABI

External native plugins expose the C ABI expected by the host, including `hexhawk_plugin_entry` metadata and a runner that accepts file bytes and returns UTF-8 JSON allocated using a compatible allocator. The source of truth is:

- `plugin-api/src/lib.rs`
- `src-tauri/src/commands/run_plugins.rs`
- `HexHawk/src-tauri/plugins/README.md`
- sample: `plugins/byte_counter/`

Platform extensions are `.dll` on Windows, `.dylib` on macOS, and `.so` on Linux.

## Build the sample plugin

```bash
cargo build --release -p byte_counter
```

Do not copy an arbitrary library into the plugin directory merely because it has the correct extension. Validate its identity and compatibility first.

## Authority boundary

Plugin results may contribute evidence or metrics. They cannot replace GYRE classification, silently mutate NEST evidence, or turn an advisory observation into proof. A plugin failure should remain visible as a failure rather than defaulting to a successful result.
