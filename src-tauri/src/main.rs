#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(
    dead_code,
    unused_mut,
    unused_variables,
    clippy::double_ended_iterator_last,
    clippy::empty_line_after_doc_comments,
    clippy::enum_variant_names,
    clippy::if_same_then_else,
    clippy::large_enum_variant,
    clippy::manual_range_contains,
    clippy::needless_as_bytes,
    clippy::needless_return,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::unnecessary_cast,
    clippy::unwrap_or_default,
    clippy::useless_format
)]

mod commands;
mod plugins;

use commands::constraint::solve_z3_constraint;
use commands::corpus::log_analysis_result;
use commands::debugger::{
    debug_attach, debug_continue, debug_detach, debug_get_state, debug_read_memory,
    debug_remove_breakpoint, debug_set_breakpoint, debug_step, debug_step_out, debug_step_over,
    debug_stop, start_debug_session,
};
use commands::analysis_bound::{
    build_cfg, disassemble_file_range, find_strings, inspect_file_metadata,
    inspect_macho_load_commands, inspect_pe_extras, read_hex_range,
};
use commands::document::{analyze_office, analyze_pdf};
use commands::file_dialog::open_file_picker;
use commands::flirt::{inspect_sig_file, match_flirt_signatures};
use commands::gyre_snapshot::gyre_record_verdict_snapshot;
use commands::hex::get_file_size;
use commands::license::{get_build_info, verify_license};
use commands::llm::{
    clear_llm_api_key, clear_llm_provider_key, has_llm_api_key, has_llm_provider_key, llm_query,
    store_llm_api_key, store_llm_provider_key,
};
use commands::nest_session_lifecycle::{
    nest_append_iteration, nest_create_session, nest_export_session_bundle, nest_finalize_session,
    nest_get_session_summary, nest_verify_binary_identity,
};
use commands::patch::{export_patched, get_jump_inversion};
use commands::plugin_browser::get_plugin_manifest;
use commands::plugin_browser::{
    get_plugin_directory, install_plugin, list_available_plugins, list_user_plugins,
    open_plugin_directory, reload_plugin, uninstall_plugin,
};
use commands::repl::{close_repl_session, create_repl_session, get_repl_session, repl_eval};
use commands::run_plugins::run_plugins_on_file;
use commands::sandbox::run_script_sandbox;
use commands::script::run_script;
use commands::structs::infer_structs;
use commands::value_finder::{
    value_edit_commit, value_edit_preview, value_edit_rollback, value_freeze_commit,
    value_freeze_preview, value_freeze_status, value_freeze_stop, value_freeze_stop_all,
    value_process_list, value_scan_cancel, value_scan_cancel_request, value_scan_refine,
    value_scan_start,
};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
    Arc,
};
use tauri::webview::PageLoadEvent;
use tauri::Manager;

const STARTUP_REVEAL_FALLBACK_DELAY: std::time::Duration = std::time::Duration::from_secs(3);
const STARTUP_RECOVERY_SCRIPT: &str = r#"
document.documentElement.style.background = '#0b1018';
document.body.innerHTML = '<main style="box-sizing:border-box;min-height:100vh;display:grid;place-items:center;padding:2rem;background:#0b1018;color:#dce9f7;font:16px/1.5 system-ui,sans-serif"><section role="alert" style="max-width:42rem;border:1px solid #36506b;border-radius:12px;padding:1.5rem;background:#101a27"><h1 style="margin-top:0;color:#64d8ff">HexHawk could not finish starting</h1><p>The interface did not become ready after an automatic retry. Close and reopen HexHawk. If this repeats, report that this recovery screen appeared rather than refreshing a blank window.</p></section></main>';
"#;

#[derive(Default)]
struct StartupState {
    ready: AtomicBool,
    navigation_generation: AtomicU64,
    reload_attempts: AtomicU8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartupTimeoutAction {
    None,
    Reload,
    RevealRecovery,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct FrontendReadiness {
    version: String,
    href: String,
    root_child_count: u32,
    root_text_length: u32,
}

fn validate_frontend_readiness(readiness: &FrontendReadiness) -> Result<(), String> {
    if readiness.version != env!("CARGO_PKG_VERSION") {
        return Err("frontend version does not match the native application".to_string());
    }
    let trusted_origin = readiness.href.starts_with("tauri://localhost")
        || readiness.href.starts_with("http://tauri.localhost")
        || readiness.href.starts_with("https://tauri.localhost")
        || (cfg!(debug_assertions)
            && (readiness.href.starts_with("http://localhost:")
                || readiness.href.starts_with("http://127.0.0.1:")));
    if !trusted_origin {
        return Err("frontend readiness came from an unexpected application URL".to_string());
    }
    if readiness.root_child_count == 0 || readiness.root_text_length < 32 {
        return Err("frontend root is not meaningfully rendered".to_string());
    }
    Ok(())
}

fn startup_timeout_action(
    frontend_ready: bool,
    reload_attempts: u8,
    current_generation: u64,
    scheduled_generation: u64,
) -> StartupTimeoutAction {
    if frontend_ready || current_generation != scheduled_generation {
        StartupTimeoutAction::None
    } else if reload_attempts == 0 {
        StartupTimeoutAction::Reload
    } else {
        StartupTimeoutAction::RevealRecovery
    }
}

fn should_schedule_main_window_fallback(webview_label: &str, event: &PageLoadEvent) -> bool {
    webview_label == "main" && matches!(event, PageLoadEvent::Finished)
}

#[tauri::command]
fn reveal_main_window(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<StartupState>>,
    readiness: FrontendReadiness,
) -> Result<(), String> {
    validate_frontend_readiness(&readiness)?;
    let window = app
        .get_webview_window("main")
        .ok_or_else(|| "main window is unavailable".to_string())?;
    window.show().map_err(|error| error.to_string())?;
    state.ready.store(true, Ordering::SeqCst);
    Ok(())
}

fn reveal_startup_recovery(webview: &tauri::Webview) {
    if let Err(error) = webview.eval(STARTUP_RECOVERY_SCRIPT) {
        eprintln!("failed to render HexHawk startup recovery: {error}");
    }
    std::thread::sleep(std::time::Duration::from_millis(100));
    if let Err(error) = webview.window().show() {
        eprintln!("failed to show HexHawk startup recovery: {error}");
    }
}

fn schedule_main_window_fallback(
    webview: tauri::Webview,
    state: Arc<StartupState>,
    generation: u64,
) {
    std::thread::spawn(move || {
        std::thread::sleep(STARTUP_REVEAL_FALLBACK_DELAY);
        let action = startup_timeout_action(
            state.ready.load(Ordering::SeqCst),
            state.reload_attempts.load(Ordering::SeqCst),
            state.navigation_generation.load(Ordering::SeqCst),
            generation,
        );
        match action {
            StartupTimeoutAction::None => {}
            StartupTimeoutAction::Reload => {
                state.reload_attempts.store(1, Ordering::SeqCst);
                if let Err(error) = webview.eval("window.location.reload()") {
                    eprintln!("failed to reload unready HexHawk frontend: {error}");
                    reveal_startup_recovery(&webview);
                }
            }
            StartupTimeoutAction::RevealRecovery => reveal_startup_recovery(&webview),
        }
    });
}

// Frozen first-release app-command surface. Unknown and excluded workflows
// fail before argument deserialization or legacy/plugin/REPL dispatch.
fn first_release_command_allowed(command: &str) -> bool {
    matches!(command,
        "log_analysis_result" | "inspect_file_metadata" | "inspect_pe_extras"
        | "read_hex_range" | "find_strings" | "get_file_size"
        | "disassemble_file_range" | "build_cfg" | "gyre_record_verdict_snapshot"
        | "open_file_picker" | "verify_license" | "get_build_info"
        | "nest_create_session" | "nest_append_iteration" | "nest_finalize_session"
        | "nest_export_session_bundle" | "nest_get_session_summary" | "nest_verify_binary_identity"
        | "reveal_main_window")
}

fn main() {
    let app = tauri::Builder::default()
        .manage(Arc::new(StartupState::default()))
        .on_page_load(|webview, payload| {
            if should_schedule_main_window_fallback(webview.label(), &payload.event()) {
                let state = webview
                    .app_handle()
                    .state::<Arc<StartupState>>()
                    .inner()
                    .clone();
                let generation = state.navigation_generation.fetch_add(1, Ordering::SeqCst) + 1;
                schedule_main_window_fallback(webview.clone(), state, generation);
            }
        })
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(|invoke| {
            if !first_release_command_allowed(invoke.message.command()) {
                invoke.resolver.reject("This workflow is excluded from the bounded Windows first release. No operation was started.");
                return true;
            }
            let legacy_dispatch: fn(tauri::ipc::Invoke) -> bool = tauri::generate_handler![
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
            gyre_record_verdict_snapshot,
            open_file_picker,
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
            nest_verify_binary_identity,
            create_repl_session,
            get_repl_session,
            repl_eval,
            close_repl_session,
            inspect_sig_file,
            match_flirt_signatures,
            infer_structs,
            value_process_list,
            value_scan_start,
            value_scan_refine,
            value_scan_cancel,
            value_scan_cancel_request,
            value_edit_preview,
            value_edit_commit,
            value_edit_rollback,
            value_freeze_preview,
            value_freeze_commit,
            value_freeze_status,
            value_freeze_stop,
            run_script,
            get_plugin_manifest,
            reveal_main_window,
            ];
            legacy_dispatch(invoke)
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application");
    app.run(|_, event| {
        if matches!(
            event,
            tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit
        ) {
            value_freeze_stop_all();
        }
    });
}

#[cfg(test)]
mod startup_tests;
