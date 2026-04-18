use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::ffi::{c_char, CStr, CString};

pub const PLUGIN_RESULT_SCHEMA_VERSION: u32 = 1;
pub const PLUGIN_RESULT_MAX_JSON_BYTES: usize = 5 * 1024 * 1024;
pub const PLUGIN_EXECUTION_TIMEOUT_SECS: u64 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginKind {
    Metric,
    Analysis,
    Strings,
    Warning,
    Error,
}

impl Default for PluginKind {
    fn default() -> Self {
        PluginKind::Metric
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginResult {
    pub schema_version: u32,
    pub plugin: String,
    pub version: String,
    pub success: bool,
    pub summary: String,
    pub details: Option<Value>,
    pub kind: PluginKind,
    pub plugin_hash: Option<String>,
}

impl PluginResult {
    pub fn new(
        plugin: impl Into<String>,
        version: impl Into<String>,
        success: bool,
        summary: impl Into<String>,
        details: Option<Value>,
        kind: PluginKind,
    ) -> Self {
        Self {
            schema_version: PLUGIN_RESULT_SCHEMA_VERSION,
            plugin: plugin.into(),
            version: version.into(),
            success,
            summary: summary.into(),
            details,
            kind,
            plugin_hash: None,
        }
    }

    pub fn success(
        plugin: impl Into<String>,
        version: impl Into<String>,
        summary: impl Into<String>,
        kind: PluginKind,
    ) -> Self {
        Self::new(plugin, version, true, summary, None, kind)
    }

    pub fn success_with_details(
        plugin: impl Into<String>,
        version: impl Into<String>,
        summary: impl Into<String>,
        details: Value,
        kind: PluginKind,
    ) -> Self {
        Self::new(plugin, version, true, summary, Some(details), kind)
    }

    pub fn error(
        plugin: impl Into<String>,
        version: impl Into<String>,
        summary: impl Into<String>,
        kind: PluginKind,
    ) -> Self {
        Self::new(plugin, version, false, summary, None, kind)
    }

    pub fn error_with_details(
        plugin: impl Into<String>,
        version: impl Into<String>,
        summary: impl Into<String>,
        details: Value,
        kind: PluginKind,
    ) -> Self {
        Self::new(plugin, version, false, summary, Some(details), kind)
    }

    pub fn with_hash(mut self, plugin_hash: Option<String>) -> Self {
        self.plugin_hash = plugin_hash;
        self
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn from_json(json: &str) -> serde_json::Result<Self> {
        serde_json::from_str(json)
    }

    pub fn validate_json_size(json: &str) -> Result<(), String> {
        let size = json.as_bytes().len();
        if size > PLUGIN_RESULT_MAX_JSON_BYTES {
            Err(format!(
                "plugin result JSON payload is too large ({} bytes, max {} bytes)",
                size, PLUGIN_RESULT_MAX_JSON_BYTES
            ))
        } else {
            Ok(())
        }
    }
}

pub trait Plugin: Send + Sync {
    fn name(&self) -> &'static str;

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn description(&self) -> &'static str {
        "No description"
    }

    fn kind(&self) -> PluginKind {
        PluginKind::Metric
    }

    fn run(&self, data: &[u8]) -> PluginResult;

    fn make_result(
        &self,
        success: bool,
        summary: String,
        details: Option<Value>,
    ) -> PluginResult {
        PluginResult::new(
            self.name(),
            self.version(),
            success,
            summary,
            details,
            self.kind(),
        )
    }

    fn success(&self, summary: String) -> PluginResult {
        self.make_result(true, summary, None)
    }

    fn success_with_details(&self, summary: String, details: Value) -> PluginResult {
        self.make_result(true, summary, Some(details))
    }

    fn error(&self, summary: String) -> PluginResult {
        self.make_result(false, summary, None)
    }

    fn error_with_details(&self, summary: String, details: Value) -> PluginResult {
        self.make_result(false, summary, Some(details))
    }
}

#[repr(C)]
pub struct PluginInfo {
    pub name: *const c_char,
    pub description: *const c_char,
}

unsafe impl Sync for PluginInfo {}

#[repr(C)]
pub struct PluginEntry {
    pub get_info: extern "C" fn() -> *const PluginInfo,
    pub run_plugin: extern "C" fn(*const u8, usize) -> *mut c_char,
    pub free_string: extern "C" fn(*mut c_char),
}

pub const PLUGIN_SYMBOL_NAME: &[u8] = b"hexhawk_plugin_entry\0";

/// Convert a plugin-owned C string into a Rust `String` and reclaim ownership.
pub unsafe fn c_string_to_string(ptr: *mut c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let value = CStr::from_ptr(ptr).to_string_lossy().into_owned();
    let _ = CString::from_raw(ptr);
    value
}

/// Convert a Rust `String` into a C string pointer for plugin boundary crossing.
pub fn string_to_c_string(value: String) -> *mut c_char {
    CString::new(value).unwrap().into_raw()
}
