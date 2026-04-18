use plugin_api::{string_to_c_string, PluginEntry, PluginInfo, PluginKind, PluginResult};
use std::ffi::{c_char, CString};

static PLUGIN_INFO: PluginInfo = PluginInfo {
    name: b"ByteCounter\0".as_ptr() as *const c_char,
    description: b"Counts loaded bytes from a sample binary file.\0".as_ptr() as *const c_char,
};

extern "C" fn get_info() -> *const PluginInfo {
    &PLUGIN_INFO
}

extern "C" fn run_plugin(data: *const u8, len: usize) -> *mut c_char {
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };
    let result = PluginResult::success_with_details(
        "ByteCounter",
        "1.0.0",
        format!("{} bytes", bytes.len()),
        serde_json::json!({ "byte_count": bytes.len() }),
        PluginKind::Metric,
    );
    string_to_c_string(result.to_json())
}

extern "C" fn free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { let _ = CString::from_raw(ptr); }
    }
}

#[no_mangle]
pub extern "C" fn hexhawk_plugin_entry() -> *const PluginEntry {
    static ENTRY: PluginEntry = PluginEntry {
        get_info,
        run_plugin,
        free_string,
    };
    &ENTRY
}
