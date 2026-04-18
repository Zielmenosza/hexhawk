# HexHawk Plugin System

HexHawk supports extensible plugin-driven analysis workflows via a stable JSON-over-C ABI boundary.

## Plugin Architecture

### Design Goals

- **Isolation:** Plugins run in separate threads with execution timeouts.
- **Safety:** No Rust types cross plugin boundaries—only JSON over C-compatible FFI.
- **Versioning:** Schema versioning enables forward compatibility.
- **Performance:** Plugin results are hashed for caching and change detection.
- **Robustness:** Size limits and timeouts prevent resource exhaustion.

### ABI Requirements

External plugins must:

1. **Export a C function:**
   ```c
   extern "C" const char* hexhawk_plugin_entry(void)
   ```
   Returns plugin metadata as UTF-8 JSON (name, version, description).

2. **Export a runner function:**
   ```c
   extern "C" char* run_plugin(const uint8_t* data_ptr, usize len)
   ```
   - **Input:** pointer to file bytes + length
   - **Returns:** UTF-8 JSON result (must be allocated with `malloc`)
   - **Host frees:** the returned pointer after reading

### Result Schema (v1)

Plugins return JSON with this structure:

```json
{
  "schema_version": 1,
  "plugin": "ByteCounter",
  "version": "1.0.0",
  "success": true,
  "summary": "12345 bytes",
  "details": {
    "byte_count": 12345
  },
  "kind": "metric",
  "plugin_hash": "abc123def456"
}
```

#### Required Fields

| Field | Type | Purpose |
|-------|------|---------|
| `schema_version` | u32 | Always 1 for now. Increments on breaking changes; enables forward compatibility. |
| `plugin` | string | Plugin display name (e.g., "ByteCounter") |
| `version` | string | Plugin semantic version (e.g., "1.0.0") |
| `success` | bool | Execution succeeded (true) or failed (false) |
| `summary` | string | Short result or error message (max 256 chars recommended) |
| `kind` | enum | Result type category; affects frontend rendering |

#### Optional Fields

| Field | Type | Purpose |
|-------|------|---------|
| `details` | object | Structured result data (max 5 MB total JSON size) |
| `plugin_hash` | string | SHA256 hash of result for caching and version tracking |

#### Kind Values

The `kind` field is a discriminator for frontend rendering:

- **`metric`** → small badge displaying summary (e.g., "12345 bytes")
- **`analysis`** → expandable panel with raw JSON visualization
- **`strings`** → clickable list view (for arrays of strings)
- **`warning`** → highlighted alert box (yellow/orange)
- **`error`** → red error state

### Constraints

- **Max JSON size:** 5 MB (oversized payloads trigger error)
- **Execution timeout:** 3 seconds (exceeded → graceful timeout error)
- **Thread isolation:** Each plugin runs in a thread with recv_timeout guard

---

## Building Plugins

### Rust Plugin (Recommended)

1. **Create a new crate:**
   ```bash
   cargo new --lib plugins/my_plugin
   ```

2. **Add plugin-api dependency:**
   ```toml
   [dependencies]
   plugin-api = { path = "../../plugin-api" }
   serde_json = "1.0"
   ```

3. **Implement the Plugin trait:**
   ```rust
   use plugin_api::{Plugin, PluginKind, PluginResult};
   use serde_json::json;

   pub struct MyPlugin;

   impl Plugin for MyPlugin {
       fn name(&self) -> &'static str { "MyPlugin" }
       fn version(&self) -> &'static str { "1.0.0" }
       fn description(&self) -> &'static str { "Does cool analysis" }
       fn kind(&self) -> PluginKind { PluginKind::Analysis }

       fn run(&self, data: &[u8]) -> PluginResult {
           let result = analyze_data(data);
           PluginResult::success_with_details(
               self.name(),
               self.version(),
               format!("Found {} patterns", result.len()),
               json!({ "patterns": result }),
               PluginKind::Analysis,
           )
       }
   }

   fn analyze_data(data: &[u8]) -> Vec<String> {
       // Your analysis here
       vec![]
   }
   ```

4. **Build:**
   ```bash
   cd plugins/my_plugin
   cargo build --release
   ```

### C/C++ Plugin

Export two C functions following the ABI:

```c
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Metadata (called once on load)
extern "C" const char* hexhawk_plugin_entry(void) {
    return "{\"name\":\"MyPlugin\",\"version\":\"1.0.0\",\"description\":\"...\"}";
}

// Main entry point (called for each file)
extern "C" char* run_plugin(const uint8_t* data_ptr, size_t len) {
    // Analyze data...
    const char* result = "{\"schema_version\":1,\"plugin\":\"MyPlugin\",\"version\":\"1.0.0\",\"success\":true,\"summary\":\"...\",\"kind\":\"metric\"}";
    
    // Must use malloc; host will free
    char* out = malloc(strlen(result) + 1);
    strcpy(out, result);
    return out;
}
```

---

## Error Handling

Plugins should return errors gracefully via JSON:

```json
{
  "schema_version": 1,
  "plugin": "MyPlugin",
  "version": "1.0.0",
  "success": false,
  "summary": "File format not supported",
  "kind": "error"
}
```

The host enforces additional guards:

| Condition | Host Error | Kind | Summary |
|-----------|-----------|------|---------|
| Execution timeout (>3s) | Yes | error | "Plugin timed out after 3 seconds" |
| JSON > 5 MB | Yes | error | "Plugin result JSON too large" |
| Invalid UTF-8 | Yes | error | "Plugin returned invalid UTF-8" |

---

## Plugin Discovery & Loading

1. Host finds plugins in `plugins/*/target/release` (platform-specific naming)
2. Loads via `libloading` with timeout protection
3. Runs each plugin on selected file
4. Collects results in schema-versioned response
5. Displays results in UI based on `kind`

### Platform-Specific Naming

| OS | Extension | Example |
|----|-----------|---------|
| Linux | `.so` | `libmy_plugin.so` |
| macOS | `.dylib` | `libmy_plugin.dylib` |
| Windows | `.dll` | `my_plugin.dll` |

---

## Frontend Integration

The frontend uses `kind` to determine rendering:

```typescript
type PluginKind = 'metric' | 'analysis' | 'strings' | 'warning' | 'error';

// Rendering logic:
if (kind === 'strings') {
  // Render clickable list
} else if (kind === 'analysis') {
  // Render expandable JSON panel
} else if (kind === 'warning') {
  // Render highlighted alert
} else if (kind === 'error') {
  // Render red error state
} else {
  // metric: render small badge
}
```

---

## Versioning & Forward Compatibility

### Schema Versioning

- Current: v1
- When breaking changes are needed, increment `schema_version`
- Old plugins remain compatible if `schema_version` doesn't change
- New hosts can handle multiple schema versions

### Example: Adding a New Field (v2)

Future v2 might add:
```json
{
  "schema_version": 2,
  "plugin": "...",
  ...
  "cache_ttl_seconds": 3600,
  "supports_streaming": false
}
```

Old hosts reject unknown schema_version; v1 hosts ignore new v2 fields if backward-compatible.

---

## Performance & Optimization

### Hashing for Caching

Result JSON is hashed (SHA256, first 16 hex chars) for:
- **Cache invalidation:** Detect when results change
- **Version tracking:** Link results to plugin versions
- **Deduplication:** Avoid re-running identical operations

```rust
// Example hash usage
if cached_hash == new_result_hash {
  // Skip UI update; results unchanged
}
```

### Timeout Tuning

Default: 3 seconds (configurable in `plugin-api`)

Adjust for:
- **Fast plugins:** 1-2 seconds (metric, strings analysis)
- **Complex analysis:** 3-5 seconds (graph gen, decompilation)

---

## Examples

### Sample: ByteCounter

Counts file bytes and returns metrics.

**Location:** `plugins/byte_counter/`

**Build:**
```bash
cd plugins/byte_counter
cargo build --release
```

**Output:**
```json
{
  "schema_version": 1,
  "plugin": "ByteCounter",
  "version": "1.0.0",
  "success": true,
  "summary": "262144 bytes",
  "details": {
    "byte_count": 262144
  },
  "kind": "metric",
  "plugin_hash": "a1b2c3d4e5f6g7h8"
}
```

---

## Troubleshooting

### Plugin Not Found

- Ensure binary is in `plugins/<name>/target/release`
- Check platform-specific naming (`.so`, `.dylib`, `.dll`)
- Verify plugin crate builds: `cargo build --release`

### Timeout Errors

- Plugin is blocking (use threading if needed)
- Increase timeout in `plugin-api` (requires rebuild)
- Profile with `cargo bench` to identify bottlenecks

### JSON Parsing Errors

- Return valid UTF-8 JSON only
- Use `serde_json` crate for Rust plugins
- Test output with `jq` or online validator

### Size Limit Exceeded

- Limit `details` object size (nest less data)
- Stream results if needed (future enhancement)
- Consider splitting into multiple plugins

---

## API Reference

### Rust Plugin Trait

```rust
pub trait Plugin: Send + Sync {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str { "0.1.0" }
    fn description(&self) -> &'static str { "No description" }
    fn kind(&self) -> PluginKind { PluginKind::Metric }
    fn run(&self, data: &[u8]) -> PluginResult;
}
```

### PluginResult Builders

```rust
// Success with summary only
PluginResult::success(name, version, summary, kind)

// Success with details
PluginResult::success_with_details(name, version, summary, details, kind)

// Error with summary
PluginResult::error(name, version, message, kind)

// Error with details
PluginResult::error_with_details(name, version, message, details, kind)

// Add hash (optional)
result.with_hash(Some("abc123def456"))
```

### PluginKind Enum

```rust
pub enum PluginKind {
    Metric,   // Small badge
    Analysis, // Expandable JSON panel
    Strings,  // Clickable list
    Warning,  // Highlighted alert
    Error,    // Red error state
}
```

---

## License

Plugins follow the same license as HexHawk (MIT).

External plugin authors may use their own license if providing separately.
