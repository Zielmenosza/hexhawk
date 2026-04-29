#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod plugins;

use commands::corpus::log_analysis_result;
use commands::debugger::{
    debug_attach, debug_continue, debug_detach, debug_get_state, debug_read_memory,
    debug_remove_breakpoint, debug_set_breakpoint, debug_step, debug_step_out, debug_step_over,
    debug_stop, start_debug_session,
};
use commands::disassemble::disassemble_file_range;
use commands::graph::build_cfg;
use commands::hex::{find_strings, get_file_size, read_hex_range};
use commands::inspect::{inspect_file_metadata, inspect_pe_extras, inspect_macho_load_commands};
use commands::plugin_browser::{
    get_plugin_directory, install_plugin, list_available_plugins, list_user_plugins,
    open_plugin_directory, reload_plugin, uninstall_plugin,
};
use commands::run_plugins::run_plugins_on_file;
use commands::document::{analyze_pdf, analyze_office};
use commands::sandbox::run_script_sandbox;
use commands::constraint::solve_z3_constraint;
use commands::llm::{
    llm_query,
    store_llm_api_key,
    clear_llm_api_key,
    has_llm_api_key,
    store_llm_provider_key,
    clear_llm_provider_key,
    has_llm_provider_key,
};
use commands::license::{verify_license, get_build_info};
use commands::nest_session_lifecycle::{
    nest_append_iteration,
    nest_create_session,
    nest_export_session_bundle,
    nest_finalize_session,
    nest_get_session_summary,
};
use commands::patch::{export_patched, get_jump_inversion};

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            log_analysis_result,
            run_plugins_on_file,
            inspect_file_metadata,
            inspect_pe_extras,
            inspect_macho_load_commands,
            list_available_plugins,
            reload_plugin,
            list_user_plugins,
            install_plugin,
            uninstall_plugin,
            get_plugin_directory,
            open_plugin_directory,
            read_hex_range,
            find_strings,
            get_file_size,
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
            debug_attach,
            debug_step_over,
            debug_step_out,
            debug_detach,
            export_patched,
            get_jump_inversion,
            analyze_pdf,
            analyze_office,
            run_script_sandbox,
            solve_z3_constraint,
            llm_query,
            store_llm_api_key,
            clear_llm_api_key,
            has_llm_api_key,
            store_llm_provider_key,
            clear_llm_provider_key,
            has_llm_provider_key,
            verify_license,
            get_build_info,
            nest_create_session,
            nest_append_iteration,
            nest_finalize_session,
            nest_export_session_bundle,
            nest_get_session_summary,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}