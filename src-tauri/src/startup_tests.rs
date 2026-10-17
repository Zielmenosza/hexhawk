use super::{
    should_schedule_main_window_fallback, startup_timeout_action, validate_frontend_readiness,
    FrontendReadiness, StartupTimeoutAction,
};
use tauri::webview::PageLoadEvent;

#[test]
fn first_release_scope_keeps_the_core_journey_and_license_checks() {
    for command in ["inspect_file_metadata", "inspect_pe_extras", "read_hex_range", "find_strings",
        "disassemble_file_range", "build_cfg", "gyre_record_verdict_snapshot", "open_file_picker",
        "verify_license", "get_build_info", "nest_create_session", "nest_append_iteration",
        "nest_finalize_session", "nest_export_session_bundle", "nest_get_session_summary",
        "nest_verify_binary_identity", "reveal_main_window", "get_file_size", "log_analysis_result"] {
        assert!(super::first_release_command_allowed(command), "required command disabled: {command}");
    }
}

#[test]
fn first_release_scope_rejects_unqualified_and_unknown_app_commands() {
    for command in ["run_script", "run_script_sandbox", "create_repl_session", "get_repl_session",
        "repl_eval", "close_repl_session", "inspect_sig_file", "match_flirt_signatures", "infer_structs",
        "run_plugins_on_file", "list_available_plugins", "install_plugin", "reload_plugin", "uninstall_plugin",
        "start_debug_session", "debug_attach", "value_scan_start", "value_edit_commit", "value_freeze_commit",
        "analyze_pdf", "analyze_office", "inspect_macho_load_commands", "llm_query", "store_llm_api_key",
        "export_patched", "solve_z3_constraint", "future_unreviewed_command", "", "Build_Cfg"] {
        assert!(!super::first_release_command_allowed(command), "excluded command reachable: {command}");
    }
}

#[test]
fn first_release_scope_is_enforced_before_registered_legacy_dispatch() {
    let source = include_str!("main.rs");
    let handler = &source[source.find(".invoke_handler(").expect("native handler")..];
    let guard = handler.find("first_release_command_allowed(invoke.message.command())")
        .expect("bounded release must reject excluded commands before legacy dispatch");
    let legacy = handler.find("tauri::generate_handler![").expect("native command dispatch");
    assert!(guard < legacy, "scope check must precede native command deserialization/dispatch");
}

#[test]
fn main_window_fallback_is_scheduled_only_after_finished_navigation() {
    assert!(!should_schedule_main_window_fallback(
        "main",
        &PageLoadEvent::Started
    ));
    assert!(should_schedule_main_window_fallback(
        "main",
        &PageLoadEvent::Finished
    ));
    assert!(!should_schedule_main_window_fallback(
        "secondary",
        &PageLoadEvent::Finished
    ));
}

#[test]
fn packaged_main_window_starts_hidden_with_a_visible_html_fallback() {
    let config: serde_json::Value =
        serde_json::from_str(include_str!("../tauri.conf.json")).expect("valid Tauri config");
    assert_eq!(config["app"]["windows"][0]["visible"], false);

    let html = include_str!("../../HexHawk/index.html");
    assert!(html.contains("class=\"startup-shell\""));
    assert!(html.contains("role=\"status\""));
    assert!(html.contains("Starting HexHawk…"));
}

#[test]
fn startup_timeout_reloads_once_before_revealing_recovery_ui() {
    assert_eq!(
        startup_timeout_action(false, 0, 4, 4),
        StartupTimeoutAction::Reload
    );
    assert_eq!(
        startup_timeout_action(false, 1, 5, 5),
        StartupTimeoutAction::RevealRecovery
    );
}

#[test]
fn startup_timeout_does_nothing_after_readiness_or_for_stale_navigation() {
    assert_eq!(
        startup_timeout_action(true, 0, 3, 3),
        StartupTimeoutAction::None
    );
    assert_eq!(
        startup_timeout_action(false, 0, 4, 3),
        StartupTimeoutAction::None
    );
}

#[test]
fn frontend_readiness_requires_matching_version_trusted_url_and_meaningful_root() {
    let valid = FrontendReadiness {
        version: env!("CARGO_PKG_VERSION").to_string(),
        href: "tauri://localhost/".to_string(),
        root_child_count: 1,
        root_text_length: 128,
    };
    assert!(validate_frontend_readiness(&valid).is_ok());

    let empty = FrontendReadiness {
        root_child_count: 0,
        ..valid
    };
    assert!(validate_frontend_readiness(&empty).is_err());
}

#[test]
fn frontend_readiness_rejects_untrusted_or_mismatched_frontends() {
    let untrusted = FrontendReadiness {
        version: env!("CARGO_PKG_VERSION").to_string(),
        href: "https://example.invalid/".to_string(),
        root_child_count: 1,
        root_text_length: 128,
    };
    assert!(validate_frontend_readiness(&untrusted).is_err());

    let mismatched = FrontendReadiness {
        version: "0.0.0-stale".to_string(),
        href: "tauri://localhost/".to_string(),
        root_child_count: 1,
        root_text_length: 128,
    };
    assert!(validate_frontend_readiness(&mismatched).is_err());
}
