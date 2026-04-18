// src-tauri/src/plugins/mod.rs

use plugin_api::{Plugin, PluginResult};

pub struct ByteCounter;

impl Plugin for ByteCounter {
    fn name(&self) -> &'static str {
        "ByteCounter"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn description(&self) -> &'static str {
        "Counts the number of bytes in the input"
    }

    fn run(&self, data: &[u8]) -> PluginResult {
        self.success_with_details(
            format!("{} bytes", data.len()),
            serde_json::json!({ "byte_count": data.len() }),
        )
    }
}

pub fn get_all_plugins() -> Vec<Box<dyn Plugin>> {
    vec![Box::new(ByteCounter)]
}