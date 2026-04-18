#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod plugins;

use commands::debugger::{
    debug_continue, debug_get_state, debug_read_memory, debug_remove_breakpoint,
    debug_set_breakpoint, debug_step, debug_stop, start_debug_session,
};
use commands::disassemble::disassemble_file_range;
use commands::graph::build_cfg;
use commands::hex::{find_strings, read_hex_range};
use commands::inspect::inspect_file_metadata;
use commands::plugin_browser::{list_available_plugins, reload_plugin};
use commands::run_plugins::run_plugins_on_file;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            run_plugins_on_file,
            inspect_file_metadata,
            list_available_plugins,
            reload_plugin,
            read_hex_range,
            find_strings,
            disassemble_file_range,
            build_cfg,
            start_debug_session,
            debug_step,
            debug_continue,
            debug_set_breakpoint,
            debug_remove_breakpoint,
            debug_stop,
            debug_get_state,
            debug_read_memory,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}