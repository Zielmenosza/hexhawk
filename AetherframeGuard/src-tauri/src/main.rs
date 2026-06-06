#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use sysinfo::System;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
#[cfg(windows)]
use winreg::RegKey;

static CS2_CAPTURE_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

fn windows_no_window_creation_flags() -> u32 {
    #[cfg(windows)]
    {
        CREATE_NO_WINDOW
    }
    #[cfg(not(windows))]
    {
        0
    }
}

fn silent_command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(program);
    #[cfg(windows)]
    {
        command.creation_flags(windows_no_window_creation_flags());
    }
    command
}

#[derive(Debug, Clone, Copy)]
struct AetherframePromotionConfig {
    uncertainty_penalty_multiplier: f64,
    uncertainty_penalty_min: f64,
    uncertainty_penalty_max: f64,
    contradiction_penalty_scale: f64,
    contradiction_penalty_max: f64,
    contradiction_uncertainty_coupling: f64,
    low_signal_penalty_scale: f64,
    bayesian_momentum: f64,
    support_boost_per_strong_signal: f64,
    support_boost_max: f64,
    support_saturation_start: f64,
}

#[derive(Debug, Clone, Copy)]
struct AetherframePromotionInputs {
    base_confidence: f64,
    bayesian_confidence: f64,
    ci_width: f64,
    is_uncertain: bool,
    contradiction_burden: f64,
    strong_signal_count: f64,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AetherframePromotionBreakdown {
    promoted: f64,
    target: f64,
    uncertainty_penalty: f64,
    contradiction_penalty: f64,
    support_boost: f64,
    ci_width: f64,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct HostSignals {
    firewall_enabled: bool,
    defender_realtime_enabled: bool,
    remote_desktop_enabled: bool,
    active_power_plan: String,
    high_performance_plan_active: bool,
    active_network_adapter_count: usize,
    ethernet_adapter_active: bool,
    wifi_adapter_active: bool,
    background_process_count: usize,
    overlay_process_count: usize,
    overlay_process_names: Vec<String>,
    counter_strike_process_names: Vec<String>,
    counter_strike_active: bool,
    total_memory_mb: u64,
    available_memory_mb: u64,
    cpu_usage_percent: f32,
    avg_ping_ms: Option<f64>,
    system_latency_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ModuleSummary {
    score: f64,
    signals: Vec<String>,
    blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Recommendation {
    id: String,
    title: String,
    rationale: String,
    risk: String,
    impact: String,
    confidence: f64,
    category: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct QuickAction {
    id: String,
    title: String,
    category: String,
    rationale: String,
    confidence: f64,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CounterStrikeSummary {
    active: bool,
    process_names: Vec<String>,
    score: f64,
    signals: Vec<String>,
    blockers: Vec<String>,
    avg_fps: Option<f64>,
    avg_frametime_ms: Option<f64>,
    pc_latency_ms: Option<f64>,
    network_latency_ms: Option<f64>,
    fps_capture_source: Option<String>,
    last_fps_capture_at: Option<String>,
    #[serde(default)]
    fps_1pct_low: Option<f64>,
    #[serde(default)]
    fps_0_1pct_low: Option<f64>,
    #[serde(default)]
    stutter_count: u64,
    #[serde(default)]
    stability_score: f64,
    #[serde(default)]
    scene_classification: String,
    telemetry_diagnostics: CounterStrikeCaptureDiagnostics,
    launch_status: CounterStrikeLaunchStatus,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CounterStrikeFpsTelemetry {
    captured_at: String,
    avg_fps: Option<f64>,
    avg_frametime_ms: Option<f64>,
    pc_latency_ms: Option<f64>,
    network_latency_ms: Option<f64>,
    #[serde(default)]
    fps_1pct_low: Option<f64>,
    #[serde(default)]
    fps_0_1pct_low: Option<f64>,
    #[serde(default)]
    stutter_count: u64,
    #[serde(default)]
    stability_score: f64,
    #[serde(default)]
    scene_classification: String,
    source: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CounterStrikeOptimizationMetrics {
    avg_fps: Option<f64>,
    avg_frametime_ms: Option<f64>,
    pc_latency_ms: Option<f64>,
    network_latency_ms: Option<f64>,
    system_latency_ms: Option<f64>,
    fps_1pct_low: Option<f64>,
    fps_0_1pct_low: Option<f64>,
    stutter_count: u64,
    stability_score: f64,
    scene_classification: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CounterStrikeCaptureDiagnostics {
    captured_at: String,
    presentmon_found: bool,
    presentmon_path: Option<String>,
    cs2_process_found: bool,
    capture_attempted: bool,
    capture_succeeded: bool,
    capture_error: Option<String>,
    avg_fps: Option<f64>,
    avg_frametime_ms: Option<f64>,
    pc_latency_ms: Option<f64>,
    #[serde(default)]
    fps_1pct_low: Option<f64>,
    #[serde(default)]
    fps_0_1pct_low: Option<f64>,
    #[serde(default)]
    stutter_count: u64,
    #[serde(default)]
    stability_score: f64,
    #[serde(default)]
    scene_classification: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CounterStrikeLaunchStatus {
    preferred_launch_path: String,
    exists: bool,
    readable: bool,
    uses_steam_applaunch_730: bool,
    uses_high_priority: bool,
    notes: Vec<String>,
}

#[derive(Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CounterStrikeOptimizationRequest {
    requested_at: String,
    last_score: f64,
    process_names: Vec<String>,
    target_score: f64,
    #[serde(default)]
    steam_userdata_roots: Vec<String>,
    #[serde(default)]
    last_sync_at: Option<String>,
}

#[derive(Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CounterStrikeSteamAccountSync {
    root_path: String,
    account_id: String,
    cfg_dir: String,
    autoexec_path: String,
    managed_profile_path: String,
    autoexec_hook_present: bool,
    managed_profile_written: bool,
    synced: bool,
    notes: Vec<String>,
}

#[derive(Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CounterStrikeSteamSyncState {
    last_synced_at: Option<String>,
    total_syncs: u64,
    total_accounts: u64,
    synced_accounts: u64,
    last_score: Option<f64>,
    accounts: Vec<CounterStrikeSteamAccountSync>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CounterStrikeSteamSyncStatus {
    last_synced_at: Option<String>,
    total_syncs: u64,
    total_accounts: u64,
    synced_accounts: u64,
    last_score: Option<f64>,
    accounts: Vec<CounterStrikeSteamAccountSync>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AnalysisResponse {
    generated_at: String,
    signals: HostSignals,
    promotion: AetherframePromotionBreakdown,
    modules: ModuleCollection,
    counter_strike: CounterStrikeSummary,
    recommendations: Vec<Recommendation>,
    actions: Vec<QuickAction>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ModuleCollection {
    security: ModuleSummary,
    network: ModuleSummary,
    performance: ModuleSummary,
    gaming: ModuleSummary,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ActionResult {
    id: String,
    success: bool,
    message: String,
}

#[derive(Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ProfileSnapshot {
    active_power_plan: Option<String>,
    game_dvr_enabled: Option<u32>,
    app_capture_enabled: Option<u32>,
    remote_desktop_enabled: Option<bool>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ProfileDelta {
    promotion_before: f64,
    promotion_after: f64,
    promotion_delta: f64,
    security_before: f64,
    security_after: f64,
    security_delta: f64,
    network_before: f64,
    network_after: f64,
    network_delta: f64,
    performance_before: f64,
    performance_after: f64,
    performance_delta: f64,
    gaming_before: f64,
    gaming_after: f64,
    gaming_delta: f64,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ProfileExecutionResult {
    profile_id: String,
    profile_name: String,
    success: bool,
    message: String,
    snapshot_path: String,
    before: AnalysisResponse,
    after: AnalysisResponse,
    delta: ProfileDelta,
    applied_changes: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ThreatFinding {
    id: String,
    category: String,
    title: String,
    description: String,
    severity: String,
    confidence: f64,
    evidence: String,
    recommendation: String,
    source: String,
    confirmed: bool,
    observed_at: String,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SecurityScanResult {
    scan_time: String,
    total_findings: usize,
    critical_findings: usize,
    high_findings: usize,
    medium_findings: usize,
    low_findings: usize,
    findings: Vec<ThreatFinding>,
    threat_promotion: AetherframePromotionBreakdown,
    clean: bool,
}

#[derive(Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct BootEntry {
    boot_number: u64,
    timestamp: String,
    promotion_score: f64,
    security_score: f64,
    network_score: f64,
    performance_score: f64,
    gaming_score: f64,
    latency_ms: Option<f64>,
    applied_settings: Vec<String>,
    improvement_delta: f64,
}

#[derive(Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct BootHistory {
    entries: Vec<BootEntry>,
    best_promotion_ever: f64,
    total_boots_optimized: u64,
}

#[derive(Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CalibrationResult {
    calibrated_at: String,
    baseline_promotion: f64,
    baseline_latency_ms: Option<f64>,
    baseline_security: f64,
    baseline_network: f64,
    baseline_performance: f64,
    baseline_gaming: f64,
    network_settings_applied: Vec<String>,
    system_settings_applied: Vec<String>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SystemIntegrationStatus {
    boot_service_installed: bool,
    boot_service_running: bool,
    total_boots_optimized: u64,
    best_promotion_ever: f64,
    last_boot_promotion: Option<f64>,
    calibrated: bool,
    service_task_name: String,
}

#[derive(Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct NvidiaTuningIteration {
    iteration: u64,
    timestamp: String,
    method: String,
    before_gaming: f64,
    after_gaming: f64,
    before_network: f64,
    after_network: f64,
    before_latency_ms: Option<f64>,
    after_latency_ms: Option<f64>,
    improvement_delta: f64,
    notes: Vec<String>,
}

#[derive(Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct NvidiaTuningState {
    tools_path: String,
    cli_path: Option<String>,
    gui_path: Option<String>,
    profile_path: Option<String>,
    total_iterations: u64,
    best_delta: f64,
    last_delta: Option<f64>,
    iterations: Vec<NvidiaTuningIteration>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct NvidiaTuningStatus {
    tools_path: String,
    found: bool,
    cli_found: bool,
    gui_found: bool,
    profile_found: bool,
    total_iterations: u64,
    best_delta: f64,
    last_delta: Option<f64>,
    last_notes: Vec<String>,
}

#[derive(Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct AutoCycleRecord {
    cycle_number: u64,
    timestamp: String,
    before_promotion: f64,
    after_promotion: f64,
    promotion_delta: f64,
    threat_score: f64,
    total_findings: usize,
    nvidia_success: bool,
    notes: Vec<String>,
}

#[derive(Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct AutoMonitorState {
    total_cycles: u64,
    best_promotion: f64,
    last_promotion: Option<f64>,
    last_threat_score: Option<f64>,
    history: Vec<AutoCycleRecord>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct AutoMonitorStatus {
    task_installed: bool,
    task_running: bool,
    task_name: String,
    total_cycles: u64,
    best_promotion: f64,
    last_promotion: Option<f64>,
    last_threat_score: Option<f64>,
    recent_cycles: Vec<AutoCycleRecord>,
}

#[derive(Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct BenchmarkSession {
    id: String,
    timestamp: String,
    source: String,
    promotion_score: f64,
    counter_strike_score: f64,
    avg_fps: Option<f64>,
    avg_frametime_ms: Option<f64>,
    pc_latency_ms: Option<f64>,
    network_latency_ms: Option<f64>,
    system_latency_ms: Option<f64>,
    #[serde(default)]
    fps_1pct_low: Option<f64>,
    #[serde(default)]
    fps_0_1pct_low: Option<f64>,
    #[serde(default)]
    stutter_count: u64,
    #[serde(default)]
    stability_score: f64,
    #[serde(default)]
    scene_classification: String,
    confidence: f64,
    objective_score: f64,
    notes: Vec<String>,
}

#[derive(Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct BenchmarkState {
    #[serde(default)]
    total_sessions: u64,
    #[serde(default)]
    sessions: Vec<BenchmarkSession>,
    #[serde(default)]
    last_guardrail_active: bool,
    #[serde(default)]
    last_guardrail_note: Option<String>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct BenchmarkStatus {
    total_sessions: u64,
    baseline: Option<BenchmarkSession>,
    latest: Option<BenchmarkSession>,
    best: Option<BenchmarkSession>,
    regression_guardrail_active: bool,
    last_guardrail_note: Option<String>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SuggestedFpsSettingsResult {
    applied_at: String,
    success: bool,
    message: String,
    backup_dir: String,
    applied_changes: Vec<String>,
    warnings: Vec<String>,
    cs2_restart_required: bool,
    windows_restart_required: bool,
    benchmark_status: BenchmarkStatus,
}

const NVIDIA_TOOLS_DIR: &str = r"C:\Users\Ziel\Desktop\Tools\NvidiaInspector";
const NVIDIA_PROFILE_FILE: &str = "AetherframeGuard-Competitive.nip";
const NVIDIA_CLI_NAMES: &[&str] = &[
    "nvidiaProfileInspectorCli.exe",
    "nvidiaProfileInspectorCLI.exe",
    "NVIDIAProfileInspectorCLI.exe",
];
const NVIDIA_GUI_NAMES: &[&str] = &[
    "nvidiaProfileInspector.exe",
    "nvidiaInspector.exe",
    "NVIDIAProfileInspector.exe",
];
const PRESENTMON_DIR_CANDIDATES: &[&str] = &[
    r"C:\Users\Ziel\Desktop\Tools\PresentMon",
    r"C:\Program Files\PresentMon",
    r"C:\Program Files (x86)\PresentMon",
    r"C:\Program Files\Intel\PresentMon",
    r"C:\Program Files\Intel\PresentMon\x64",
    r"C:\Program Files\Intel\PresentMon\PresentMonConsoleApplication",
    r"C:\Program Files\NVIDIA Corporation\FrameViewSDK\bin",
    NVIDIA_TOOLS_DIR,
];
const PRESENTMON_BINARY_NAMES: &[&str] = &[
    "PresentMon-64bit.exe",
    "PresentMon64.exe",
    "PresentMon.exe",
    "presentmon.exe",
    "PresentMon-2.4.1-x64.exe",
    "PresentMon_x64.exe",
];
const CS2_AFFINITY_LAUNCH_PATH: &str = r"C:\Users\Ziel\Desktop\CS2_Affinity.bat";
const POWER_PLAN_CHRIS_TITUS_TOKENS: &[&str] = &[
    "chris",
    "titus",
    "christitus",
    "ultimate power plan",
    "ultimate performance",
];
const COUNTER_STRIKE_STEAM_USERDATA_DIRS: &[&str] = &[
    r"C:\Program Files (x86)\Steam\userdata\31018967",
    r"C:\Program Files (x86)\Steam\userdata\64577344",
    r"C:\Program Files (x86)\Steam\userdata\122317429",
    r"C:\Program Files (x86)\Steam\userdata\424155109",
];
const COUNTER_STRIKE_STEAM_MANAGED_CFG: &str = "aetherframeguard_cs2.cfg";
const COUNTER_STRIKE_STEAM_AUTOEXEC_HOOK: &str = "exec aetherframeguard_cs2";
const AUTO_MONITOR_TASK_NAME: &str = "AetherframeGuard\\AutoMonitor";
const BOOT_TASK_NAME: &str = "AetherframeGuard\\BootOptimize";

const KNOWN_MALWARE_NAMES: &[&str] = &[
    "njrat",
    "darkcomet",
    "quasar",
    "asyncrat",
    "remcos",
    "nanocore",
    "ardamax",
    "refog",
    "keylogger",
    "xmrig",
    "xmr-stak",
    "minerd",
    "cpuminer",
    "nbminer",
    "t-rex",
    "mimikatz",
    "mimilib",
    "beacon.exe",
    "meterpreter",
    "cobaltstrike",
];

const MULTI_INSTANCE_WHITELIST: &[&str] = &[
    "svchost",
    "conhost",
    "rundll32",
    "dllhost",
    "werfault",
    "runtimebroker",
    "backgroundtaskhost",
    "sihost",
    "ctfmon",
    "msedge",
    "msedgewebview2",
    "chrome",
    "firefox",
    "brave",
    "steamwebhelper",
    "cefsharp.browsersubprocess",
    "discord",
    "teams",
    "slack",
    "chatgpt",
    "wmi",
    "wmiprvse",
    "code",
];

const SUSPICIOUS_REMOTE_PORTS: &[u16] = &[
    4444, 1337, 31337, 6666, 6667, 6668, 6669, 9999, 12345, 54321, 65535, 3333, 1234, 2345, 9898,
];

const OVERLAY_CAPTURE_PROCESS_MARKERS: &[&str] = &[
    "obs",
    "streamlabs",
    "xsplit",
    "rtss",
    "rivatuner",
    "msiafterburner",
    "overwolf",
    "medal",
    "outplayed",
    "xboxgamebar",
    "gamebar",
    "sharex",
    "capframex",
    "presentmon",
    "discord",
    "steamwebhelper",
    "nvidia",
    "amd",
];

const SUSPICIOUS_TASK_ACTION_MARKERS: &[&str] = &[
    r"	emp",
    r"	mp",
    r"\downloads",
    r"appdata\local	emp",
    "-encodedcommand",
    "frombase64string",
    "iex ",
    "invoke-expression",
    "mshta",
    "wscript",
    "cscript",
];

fn clamp(v: f64, min: f64, max: f64) -> f64 {
    v.max(min).min(max)
}

fn compute_aetherframe_promotion(
    input: AetherframePromotionInputs,
    config: AetherframePromotionConfig,
) -> AetherframePromotionBreakdown {
    let normalized_ci_width = clamp(input.ci_width, 0.0, 1.0);

    let uncertainty_penalty = if input.is_uncertain {
        clamp(
            normalized_ci_width * config.uncertainty_penalty_multiplier,
            config.uncertainty_penalty_min,
            config.uncertainty_penalty_max,
        )
        .round()
    } else {
        0.0
    };

    let contradiction_base_penalty = clamp(
        input.contradiction_burden * config.contradiction_penalty_scale,
        0.0,
        config.contradiction_penalty_max,
    )
    .round();

    let contradiction_coupling_penalty = clamp(
        input.contradiction_burden
            * normalized_ci_width
            * config.contradiction_uncertainty_coupling,
        0.0,
        config.contradiction_penalty_max,
    )
    .round();

    let contradiction_penalty = clamp(
        contradiction_base_penalty + contradiction_coupling_penalty,
        0.0,
        config.contradiction_penalty_max,
    )
    .round();

    let raw_support_boost = input.strong_signal_count * config.support_boost_per_strong_signal;
    let saturation_overhang =
        (input.strong_signal_count - config.support_saturation_start).max(0.0);
    let saturation_penalty = saturation_overhang * 0.25;
    let support_boost = clamp(
        raw_support_boost - saturation_penalty,
        0.0,
        config.support_boost_max,
    )
    .round();

    let low_signal_penalty = if input.is_uncertain && input.strong_signal_count == 0.0 {
        clamp(
            normalized_ci_width * 10.0 * config.low_signal_penalty_scale,
            0.0,
            6.0,
        )
        .round()
    } else {
        0.0
    };

    let weighted_bayes = input.base_confidence
        + ((input.bayesian_confidence - input.base_confidence) * config.bayesian_momentum);

    let target = clamp(
        weighted_bayes - uncertainty_penalty - contradiction_penalty - low_signal_penalty
            + support_boost,
        0.0,
        100.0,
    );

    let promoted = input.base_confidence.max(target);

    AetherframePromotionBreakdown {
        promoted,
        target,
        uncertainty_penalty,
        contradiction_penalty,
        support_boost,
        ci_width: input.ci_width,
    }
}

fn run_powershell(script: &str) -> Option<String> {
    let output = silent_command("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn parse_bool_result(value: Option<String>) -> bool {
    matches!(
        value.unwrap_or_default().to_ascii_lowercase().as_str(),
        "true" | "1" | "yes"
    )
}

fn detect_active_power_plan() -> String {
    let raw = silent_command("powercfg").arg("/getactivescheme").output();
    match raw {
        Ok(out) if out.status.success() => {
            let s = String::from_utf8_lossy(&out.stdout).to_string();
            let trimmed = s.lines().last().unwrap_or("Unknown").trim().to_string();
            if trimmed.is_empty() {
                "Unknown".to_string()
            } else {
                trimmed
            }
        }
        _ => "Unknown".to_string(),
    }
}

fn parse_ping_output_average_ms(text: &str) -> Option<f64> {
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if !lower.contains("average") {
            continue;
        }

        // Windows ping line example:
        // Minimum = 12ms, Maximum = 30ms, Average = 20ms
        let mut candidate = line;
        if let Some(eq) = line.rfind('=') {
            candidate = &line[(eq + 1)..];
        }

        let mut buf = String::new();
        for c in candidate.chars() {
            if c.is_ascii_digit() || c == '.' {
                buf.push(c);
            } else if !buf.is_empty() {
                break;
            }
        }

        if !buf.is_empty() {
            if let Ok(v) = buf.parse::<f64>() {
                return Some(v);
            }
        }
    }
    None
}

fn parse_ping_average_ms() -> Option<f64> {
    let targets = ["1.1.1.1", "8.8.8.8", "9.9.9.9"];
    let mut samples = Vec::new();

    for target in targets {
        let output = silent_command("ping")
            .args(["-n", "3", "-w", "700", target])
            .output();

        if let Ok(out) = output {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                if let Some(avg) = parse_ping_output_average_ms(&text) {
                    // Bound absurd parsed values to avoid poisoning the score.
                    if (0.0..=3000.0).contains(&avg) {
                        samples.push(avg);
                    }
                }
            }
        }
    }

    if samples.is_empty() {
        return None;
    }

    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    // Use median for resilience against one noisy route sample.
    let mid = samples.len() / 2;
    if samples.len() % 2 == 1 {
        Some(samples[mid])
    } else {
        Some((samples[mid - 1] + samples[mid]) / 2.0)
    }
}

fn parse_system_latency_ms() -> Option<f64> {
    let output = silent_command("ping")
        .args(["-n", "4", "-w", "250", "127.0.0.1"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let avg = parse_ping_output_average_ms(&text)?;
    if (0.0..=100.0).contains(&avg) {
        Some(avg)
    } else {
        None
    }
}

fn parse_network_adapter_names() -> Vec<String> {
    let script =
        "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty Name";
    let output = run_powershell(script);
    output
        .map(|text| {
            text.lines()
                .map(|line| line.trim().to_string())
                .filter(|line| !line.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn detect_remote_desktop_enabled() -> bool {
    #[cfg(windows)]
    {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(key) = hklm.open_subkey("SYSTEM\\CurrentControlSet\\Control\\Terminal Server") {
            if let Ok(value) = key.get_value::<u32, _>("fDenyTSConnections") {
                return value == 0;
            }
        }
        false
    }

    #[cfg(not(windows))]
    {
        false
    }
}

fn collect_host_signals() -> HostSignals {
    let mut system = System::new_all();
    system.refresh_all();

    let firewall_enabled = parse_bool_result(run_powershell(
        "([int](Get-NetFirewallProfile | Where-Object {$_.Enabled -eq 'True'}).Count -ge 3)",
    ));

    let defender_realtime_enabled = parse_bool_result(run_powershell(
        "(Get-MpComputerStatus).RealTimeProtectionEnabled",
    ));

    let active_power_plan = detect_active_power_plan();
    let active_power_plan_lower = active_power_plan.to_ascii_lowercase();
    let high_performance_plan_active = active_power_plan_lower.contains("high performance")
        || active_power_plan_lower.contains("ultimate performance")
        || (active_power_plan_lower.contains("chris") && active_power_plan_lower.contains("titus"));

    let process_names: Vec<String> = system
        .processes()
        .values()
        .map(|proc| proc.name().to_string().to_ascii_lowercase())
        .collect();

    let overlay_process_names: Vec<String> = process_names
        .iter()
        .filter(|name| {
            OVERLAY_CAPTURE_PROCESS_MARKERS
                .iter()
                .any(|marker| name.as_str().contains(*marker))
        })
        .cloned()
        .collect();

    let cs_markers = ["cs2", "csgo", "counter-strike", "counterstrike"];
    let counter_strike_process_names: Vec<String> = process_names
        .iter()
        .filter(|name| {
            cs_markers
                .iter()
                .any(|marker| name.as_str().contains(marker))
        })
        .cloned()
        .collect();
    let counter_strike_active = !counter_strike_process_names.is_empty();

    let network_adapters = parse_network_adapter_names();
    let ethernet_adapter_active = network_adapters
        .iter()
        .any(|name| name.to_ascii_lowercase().contains("ethernet"));
    let wifi_adapter_active = network_adapters.iter().any(|name| {
        name.to_ascii_lowercase().contains("wi-fi")
            || name.to_ascii_lowercase().contains("wireless")
    });

    system.refresh_memory();
    system.refresh_cpu();
    let total_memory_mb = system.total_memory() / 1024;
    let available_memory_mb = system.available_memory() / 1024;
    let cpu_usage_percent = system.global_cpu_info().cpu_usage();

    HostSignals {
        firewall_enabled,
        defender_realtime_enabled,
        remote_desktop_enabled: detect_remote_desktop_enabled(),
        active_power_plan,
        high_performance_plan_active,
        active_network_adapter_count: network_adapters.len(),
        ethernet_adapter_active,
        wifi_adapter_active,
        background_process_count: system.processes().len(),
        overlay_process_count: overlay_process_names.len(),
        overlay_process_names,
        counter_strike_process_names,
        counter_strike_active,
        total_memory_mb,
        available_memory_mb,
        cpu_usage_percent,
        avg_ping_ms: parse_ping_average_ms(),
        system_latency_ms: parse_system_latency_ms(),
    }
}

fn score_security(signals: &HostSignals) -> ModuleSummary {
    let mut score = 35.0;
    let mut signals_list = Vec::new();
    let mut blockers = Vec::new();

    if signals.firewall_enabled {
        score += 18.0;
        signals_list.push("Firewall enabled for all profiles".to_string());
    } else {
        blockers.push("Firewall disabled or incomplete".to_string());
    }

    if signals.defender_realtime_enabled {
        score += 18.0;
        signals_list.push("Defender realtime protection enabled".to_string());
    } else {
        blockers.push("Defender realtime protection off".to_string());
    }

    if !signals.remote_desktop_enabled {
        score += 10.0;
        signals_list.push("Remote Desktop disabled".to_string());
    } else {
        blockers.push("Remote Desktop exposure present".to_string());
    }

    ModuleSummary {
        score: clamp(score, 0.0, 100.0),
        signals: signals_list,
        blockers,
    }
}

fn score_network(signals: &HostSignals) -> ModuleSummary {
    let mut score = 45.0;
    let mut signals_list = Vec::new();
    let mut blockers = Vec::new();

    if signals.active_network_adapter_count > 0 {
        score += 10.0;
        signals_list.push(format!(
            "{} active network adapter(s)",
            signals.active_network_adapter_count
        ));
    } else {
        blockers.push("No active network adapter detected".to_string());
    }

    if signals.ethernet_adapter_active {
        score += 10.0;
        signals_list.push("Ethernet path available".to_string());
    }

    if signals.wifi_adapter_active {
        score += 2.0;
        signals_list.push("Wi-Fi path available".to_string());
    }

    if let Some(ping) = signals.avg_ping_ms {
        if ping < 20.0 {
            score += 18.0;
            signals_list.push(format!("Excellent latency: {:.1}ms", ping));
        } else if ping < 40.0 {
            score += 10.0;
            signals_list.push(format!("Healthy latency: {:.1}ms", ping));
        } else if ping > 60.0 {
            blockers.push(format!("Elevated latency: {:.1}ms", ping));
            score -= 8.0;
        }
    }

    ModuleSummary {
        score: clamp(score, 0.0, 100.0),
        signals: signals_list,
        blockers,
    }
}

fn score_performance(signals: &HostSignals) -> ModuleSummary {
    let mut score = 40.0;
    let mut signals_list = Vec::new();
    let mut blockers = Vec::new();

    if signals.high_performance_plan_active {
        score += 18.0;
        signals_list.push("Performance power plan active".to_string());
    } else {
        blockers.push("Power plan is not performance-oriented".to_string());
    }

    if signals.background_process_count < 180 {
        score += 15.0;
        signals_list.push(format!(
            "Light background load: {} processes",
            signals.background_process_count
        ));
    } else if signals.background_process_count > 240 {
        score -= 10.0;
        blockers.push(format!(
            "High background load: {} processes",
            signals.background_process_count
        ));
    }

    let free_ratio = if signals.total_memory_mb > 0 {
        signals.available_memory_mb as f64 / signals.total_memory_mb as f64
    } else {
        0.0
    };

    if free_ratio > 0.25 {
        score += 14.0;
        signals_list.push(format!("Memory headroom {:.0}%", free_ratio * 100.0));
    } else if free_ratio < 0.12 {
        score -= 10.0;
        blockers.push(format!("Low memory headroom {:.0}%", free_ratio * 100.0));
    }

    if signals.cpu_usage_percent < 25.0 {
        score += 8.0;
        signals_list.push(format!("Idle CPU load {:.0}%", signals.cpu_usage_percent));
    }

    ModuleSummary {
        score: clamp(score, 0.0, 100.0),
        signals: signals_list,
        blockers,
    }
}

fn score_gaming(signals: &HostSignals) -> ModuleSummary {
    let mut score = 42.0;
    let mut signals_list = Vec::new();
    let mut blockers = Vec::new();

    if signals.overlay_process_count == 0 {
        score += 16.0;
        signals_list.push("No obvious overlay/capture contention detected".to_string());
    } else {
        score -= (signals.overlay_process_count as f64 * 2.0).min(10.0);
        blockers.push(format!(
            "Overlay/capture processes detected: {}",
            signals.overlay_process_names.join(", ")
        ));
    }

    if signals.high_performance_plan_active {
        score += 10.0;
        signals_list.push("High/Ultimate performance power plan active".to_string());
    } else {
        blockers.push("Power plan is not performance-oriented".to_string());
    }

    if signals.background_process_count < 180 {
        score += 10.0;
        signals_list.push(format!(
            "Background load is light: {} processes",
            signals.background_process_count
        ));
    } else if signals.background_process_count > 240 {
        score -= 8.0;
        blockers.push(format!(
            "High background load: {} processes",
            signals.background_process_count
        ));
    }

    let free_ratio = if signals.total_memory_mb > 0 {
        signals.available_memory_mb as f64 / signals.total_memory_mb as f64
    } else {
        0.0
    };

    if free_ratio > 0.25 {
        score += 10.0;
        signals_list.push(format!("Memory headroom {:.0}%", free_ratio * 100.0));
    } else if free_ratio < 0.12 {
        score -= 8.0;
        blockers.push(format!("Low memory headroom {:.0}%", free_ratio * 100.0));
    }

    if signals.ethernet_adapter_active {
        score += 6.0;
        signals_list.push("Ethernet path available for lower jitter".to_string());
    }

    if let Some(ping) = signals.avg_ping_ms {
        if ping < 25.0 {
            score += 8.0;
            signals_list.push(format!("Low-latency connection {:.1}ms", ping));
        } else if ping > 55.0 {
            score -= 6.0;
            blockers.push(format!("Network jitter risk {:.1}ms", ping));
        }
    }

    if signals.cpu_usage_percent < 25.0 {
        score += 5.0;
        signals_list.push(format!(
            "Low host CPU contention {:.1}%",
            signals.cpu_usage_percent
        ));
    }

    ModuleSummary {
        score: clamp(score, 0.0, 100.0),
        signals: signals_list,
        blockers,
    }
}

fn score_counter_strike(signals: &HostSignals) -> CounterStrikeSummary {
    score_counter_strike_with_capture_mode(signals, false)
}

fn score_counter_strike_with_capture_mode(
    signals: &HostSignals,
    force_capture: bool,
) -> CounterStrikeSummary {
    let mut score = if signals.counter_strike_active {
        54.0
    } else {
        0.0
    };
    let mut signals_list = Vec::new();
    let mut blockers = Vec::new();
    let mut avg_fps = None;
    let mut avg_frametime_ms = None;
    let mut pc_latency_ms = None;
    let mut fps_capture_source = None;
    let mut last_fps_capture_at = None;
    let mut fps_1pct_low = None;
    let mut fps_0_1pct_low = None;
    let mut stutter_count = 0_u64;
    let mut stability_score = 0.0_f64;
    let mut scene_classification = "unknown".to_string();
    let telemetry_diagnostics;

    if signals.counter_strike_active {
        signals_list.push(format!(
            "Counter-Strike process detected: {}",
            signals.counter_strike_process_names.join(", ")
        ));

        if let Some(telemetry) = capture_counter_strike_fps_telemetry(
            signals.avg_ping_ms,
            signals.system_latency_ms,
            force_capture,
        ) {
            telemetry_diagnostics = load_counter_strike_fps_diagnostics()
                .unwrap_or_else(|| default_counter_strike_capture_diagnostics(true));
            avg_fps = telemetry.avg_fps;
            avg_frametime_ms = telemetry.avg_frametime_ms;
            pc_latency_ms = telemetry.pc_latency_ms;
            fps_1pct_low = telemetry.fps_1pct_low;
            fps_0_1pct_low = telemetry.fps_0_1pct_low;
            stutter_count = telemetry.stutter_count;
            stability_score = telemetry.stability_score;
            scene_classification = if telemetry.scene_classification.is_empty() {
                classify_counter_strike_scene(
                    telemetry.avg_fps,
                    telemetry.avg_frametime_ms,
                    telemetry.network_latency_ms,
                    signals.system_latency_ms,
                )
            } else {
                telemetry.scene_classification.clone()
            };
            fps_capture_source = Some(telemetry.source.clone());
            last_fps_capture_at = Some(telemetry.captured_at.clone());

            if let Some(fps) = telemetry.avg_fps {
                if fps >= 240.0 {
                    score += 12.0;
                } else if fps >= 165.0 {
                    score += 8.0;
                } else if fps < 120.0 {
                    score -= 10.0;
                    blockers.push(format!(
                        "Measured FPS is below competitive target ({:.1})",
                        fps
                    ));
                }
                signals_list.push(format!("Measured average FPS {:.1}", fps));
            } else {
                blockers.push("FPS capture did not yield valid samples".to_string());
            }

            if let Some(frame_ms) = telemetry.avg_frametime_ms {
                if frame_ms <= 6.5 {
                    score += 8.0;
                } else if frame_ms >= 10.0 {
                    score -= 8.0;
                    blockers.push(format!("High frametime variance {:.2}ms", frame_ms));
                }
                signals_list.push(format!("Measured frametime {:.2}ms", frame_ms));
            }

            if let Some(pc_lat) = telemetry.pc_latency_ms {
                if pc_lat <= 14.0 {
                    score += 6.0;
                } else if pc_lat >= 24.0 {
                    score -= 6.0;
                    blockers.push(format!("High render/display latency {:.2}ms", pc_lat));
                }
                signals_list.push(format!("PC render/display latency {:.2}ms", pc_lat));
            }

            if let Some(low) = telemetry.fps_1pct_low {
                if low >= 180.0 {
                    score += 7.0;
                } else if low < 100.0 {
                    score -= 7.0;
                    blockers.push(format!(
                        "1% low FPS is weak for CS2 consistency ({:.1})",
                        low
                    ));
                }
                signals_list.push(format!("Measured 1% low FPS {:.1}", low));
            }

            if telemetry.stability_score >= 85.0 {
                score += 8.0;
                signals_list.push(format!(
                    "Frame pacing stability {:.0}%",
                    telemetry.stability_score
                ));
            } else if telemetry.stability_score > 0.0 && telemetry.stability_score < 60.0 {
                score -= 8.0;
                blockers.push(format!(
                    "Frame pacing stability is low ({:.0}%, {} stutter spike candidates)",
                    telemetry.stability_score, telemetry.stutter_count
                ));
            }

            if scene_classification == "menu_or_lobby" {
                blockers.push("Telemetry looks like CS2 menu/lobby rather than gameplay; optimize using a live match/practice-map sample.".to_string());
            } else if scene_classification == "gameplay_candidate" {
                score += 5.0;
                signals_list.push(
                    "Telemetry resembles a gameplay sample rather than a menu-only FPS snapshot"
                        .to_string(),
                );
            }
        } else {
            telemetry_diagnostics = load_counter_strike_fps_diagnostics()
                .unwrap_or_else(|| default_counter_strike_capture_diagnostics(true));
            let reason = telemetry_diagnostics
                .capture_error
                .clone()
                .unwrap_or_else(|| "No FPS capture source found".to_string());
            blockers.push(format!("CS2 telemetry unavailable: {}", reason));
        }

        if signals.high_performance_plan_active {
            score += 16.0;
            signals_list.push("Chris Titus / high-performance power plan active".to_string());
        } else {
            blockers.push("Chris Titus power plan is not active".to_string());
        }

        if signals.overlay_process_count == 0 {
            score += 15.0;
            signals_list
                .push("No overlay/capture contention detected during CS session".to_string());
        } else {
            score -= (signals.overlay_process_count as f64 * 2.0).min(12.0);
            blockers.push(format!(
                "Overlay processes may reduce CS FPS: {}",
                signals.overlay_process_names.join(", ")
            ));
        }

        if signals.background_process_count < 180 {
            score += 10.0;
            signals_list.push(format!(
                "Background load is light: {} processes",
                signals.background_process_count
            ));
        } else if signals.background_process_count > 240 {
            score -= 8.0;
            blockers.push(format!(
                "High background load: {} processes",
                signals.background_process_count
            ));
        }

        let free_ratio = if signals.total_memory_mb > 0 {
            signals.available_memory_mb as f64 / signals.total_memory_mb as f64
        } else {
            0.0
        };

        if free_ratio > 0.25 {
            score += 10.0;
            signals_list.push(format!("Memory headroom {:.0}%", free_ratio * 100.0));
        } else if free_ratio < 0.12 {
            score -= 8.0;
            blockers.push(format!("Low memory headroom {:.0}%", free_ratio * 100.0));
        }

        if signals.ethernet_adapter_active {
            score += 6.0;
            signals_list.push("Ethernet path available for lower jitter".to_string());
        }

        if let Some(ping) = signals.avg_ping_ms {
            if ping < 25.0 {
                score += 8.0;
                signals_list.push(format!("Low-latency connection {:.1}ms", ping));
            } else if ping > 55.0 {
                score -= 6.0;
                blockers.push(format!("Network jitter risk {:.1}ms", ping));
            }
        }

        if signals.cpu_usage_percent < 25.0 {
            score += 5.0;
            signals_list.push(format!(
                "Low host CPU contention {:.1}%",
                signals.cpu_usage_percent
            ));
        }

        if let Some(system_latency) = signals.system_latency_ms {
            if system_latency <= 1.5 {
                score += 4.0;
            } else if system_latency > 4.0 {
                score -= 4.0;
                blockers.push(format!("Elevated local OS latency {:.2}ms", system_latency));
            }
            signals_list.push(format!(
                "OS scheduling latency proxy {:.2}ms",
                system_latency
            ));
        }
    } else {
        let mut inactive_diagnostics = default_counter_strike_capture_diagnostics(false);
        inactive_diagnostics.capture_error = Some("CS2 process not running; launch CS2 before requesting live FPS/frametime/latency capture".to_string());
        save_counter_strike_fps_diagnostics(&inactive_diagnostics);
        telemetry_diagnostics = inactive_diagnostics;
        blockers.push("Counter-Strike is not running. Launch CS2/CSGO to capture real FPS and latency telemetry.".to_string());
    }

    CounterStrikeSummary {
        active: signals.counter_strike_active,
        process_names: signals.counter_strike_process_names.clone(),
        score: clamp(score, 0.0, 100.0),
        signals: signals_list,
        blockers,
        avg_fps,
        avg_frametime_ms,
        pc_latency_ms,
        network_latency_ms: signals.avg_ping_ms,
        fps_capture_source,
        last_fps_capture_at,
        fps_1pct_low,
        fps_0_1pct_low,
        stutter_count,
        stability_score,
        scene_classification,
        telemetry_diagnostics,
        launch_status: counter_strike_launch_status(),
    }
}

const DEFAULT_AETHERFRAME_PROMOTION_CONFIG: AetherframePromotionConfig =
    AetherframePromotionConfig {
        uncertainty_penalty_multiplier: 45.0,
        uncertainty_penalty_min: 2.0,
        uncertainty_penalty_max: 12.0,
        contradiction_penalty_scale: 1.7,
        contradiction_penalty_max: 10.0,
        contradiction_uncertainty_coupling: 1.0,
        low_signal_penalty_scale: 1.6,
        bayesian_momentum: 0.85,
        support_boost_per_strong_signal: 1.4,
        support_boost_max: 6.0,
        support_saturation_start: 4.0,
    };

fn load_json<T: for<'de> serde::Deserialize<'de>>(path: PathBuf) -> Option<T> {
    fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
}

fn save_json<T: serde::Serialize>(path: PathBuf, value: &T) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(text) = serde_json::to_string_pretty(value) {
        let _ = fs::write(path, text);
    }
}

fn aetherframe_data_dir() -> PathBuf {
    PathBuf::from(r"C:\ProgramData\AetherframeGuard")
}

fn counter_strike_fps_diagnostics_path() -> PathBuf {
    aetherframe_data_dir().join("counter_strike_fps_diagnostics.json")
}

fn counter_strike_diagnostics_log_path() -> PathBuf {
    aetherframe_data_dir().join("counter_strike_diagnostics.log")
}

fn default_counter_strike_capture_diagnostics(
    cs2_process_found: bool,
) -> CounterStrikeCaptureDiagnostics {
    CounterStrikeCaptureDiagnostics {
        captured_at: chrono_like_timestamp(),
        presentmon_found: false,
        presentmon_path: None,
        cs2_process_found,
        capture_attempted: false,
        capture_succeeded: false,
        capture_error: None,
        avg_fps: None,
        avg_frametime_ms: None,
        pc_latency_ms: None,
        fps_1pct_low: None,
        fps_0_1pct_low: None,
        stutter_count: 0,
        stability_score: 0.0,
        scene_classification: "unknown".to_string(),
    }
}

fn save_counter_strike_fps_diagnostics(diagnostics: &CounterStrikeCaptureDiagnostics) {
    save_json(counter_strike_fps_diagnostics_path(), diagnostics);
}

fn load_counter_strike_fps_diagnostics() -> Option<CounterStrikeCaptureDiagnostics> {
    load_json(counter_strike_fps_diagnostics_path())
}

fn write_counter_strike_diagnostic_report() -> Result<String, String> {
    let signals = collect_host_signals();
    let launch_status = counter_strike_launch_status();
    let mut diagnostics = default_counter_strike_capture_diagnostics(signals.counter_strike_active);

    if let Some(presentmon) = discover_presentmon_binary() {
        diagnostics.presentmon_found = true;
        diagnostics.presentmon_path = Some(presentmon.to_string_lossy().to_string());
    } else {
        diagnostics.capture_error = Some(
            "PresentMon was not found. Install Intel PresentMon or place the console executable in the configured compatibility path.".to_string(),
        );
    }

    if signals.counter_strike_active {
        if let Some(sample) = capture_counter_strike_fps_telemetry(
            signals.avg_ping_ms,
            signals.system_latency_ms,
            false,
        ) {
            diagnostics = load_counter_strike_fps_diagnostics()
                .unwrap_or_else(|| default_counter_strike_capture_diagnostics(true));
            diagnostics.avg_fps = sample.avg_fps;
            diagnostics.avg_frametime_ms = sample.avg_frametime_ms;
            diagnostics.pc_latency_ms = sample.pc_latency_ms;
            diagnostics.fps_1pct_low = sample.fps_1pct_low;
            diagnostics.fps_0_1pct_low = sample.fps_0_1pct_low;
            diagnostics.stutter_count = sample.stutter_count;
            diagnostics.stability_score = sample.stability_score;
            diagnostics.scene_classification = sample.scene_classification;
        } else if diagnostics.capture_error.is_none() {
            diagnostics = load_counter_strike_fps_diagnostics()
                .unwrap_or_else(|| default_counter_strike_capture_diagnostics(true));
            if diagnostics.capture_error.is_none() {
                diagnostics.capture_error = Some(
                    "CS2 is running, but PresentMon did not produce valid FPS/frametime/latency samples. Keep CS2 in an active match/menu scene for several seconds and retry.".to_string(),
                );
            }
        }
    } else {
        diagnostics.capture_error = Some(
            "CS2 is not running. Launch CS2 first, wait until the menu or a match is visible, then click Measure/Re-test or run --diagnose-cs2 again.".to_string(),
        );
    }

    save_counter_strike_fps_diagnostics(&diagnostics);

    let report_path = aetherframe_data_dir().join("counter_strike_diagnostics.json");
    let report = serde_json::json!({
        "schema": "aetherframeguard.counter_strike_diagnostics.v1",
        "generatedAt": chrono_like_timestamp(),
        "readOnly": true,
        "cs2ProcessNames": signals.counter_strike_process_names.clone(),
        "counterStrikeActive": signals.counter_strike_active,
        "presentMonFound": diagnostics.presentmon_found,
        "presentMonPath": diagnostics.presentmon_path.clone(),
        "captureAttempted": diagnostics.capture_attempted,
        "captureSucceeded": diagnostics.capture_succeeded,
        "captureError": diagnostics.capture_error.clone(),
        "avgFps": diagnostics.avg_fps,
        "avgFrametimeMs": diagnostics.avg_frametime_ms,
        "pcLatencyMs": diagnostics.pc_latency_ms,
        "fps1pctLow": diagnostics.fps_1pct_low,
        "fps01pctLow": diagnostics.fps_0_1pct_low,
        "stutterCount": diagnostics.stutter_count,
        "stabilityScore": diagnostics.stability_score,
        "sceneClassification": diagnostics.scene_classification.clone(),
        "networkLatencyMs": signals.avg_ping_ms,
        "preferredLaunch": launch_status.clone(),
        "diagnosticsJsonPath": counter_strike_fps_diagnostics_path().to_string_lossy(),
        "humanLogPath": counter_strike_diagnostics_log_path().to_string_lossy(),
        "nextSteps": [
            "Launch CS2 using the preferred CS2_Affinity.bat shortcut or Steam.",
            "Wait until the CS2 menu or a match is visible; do not test from a closed game.",
            "Click Step 1: Measure Current FPS / PC State, or run aetherframe-guard-backend.exe --diagnose-cs2.",
            "If FPS is still n/a, open C:\\ProgramData\\AetherframeGuard\\counter_strike_diagnostics.log and check PresentMon/CS2/capture fields."
        ]
    });
    save_json(report_path.clone(), &report);

    let log = format!(
        "AetherFrameGuard CS2 diagnostics\n\
Generated: {}\n\
Read-only: yes\n\
\n\
CS2 process: {}\n\
Detected process names: {}\n\
Preferred launcher: {}\n\
Launcher found/readable: {}/{}\n\
Launcher checks: Steam app 730={} | high priority={}\n\
\n\
PresentMon found: {}\n\
PresentMon path: {}\n\
Capture attempted: {}\n\
Capture succeeded: {}\n\
Capture error: {}\n\
Last FPS: {}\n\
Last frametime ms: {}\n\
Last PC latency ms: {}\n\
1% low FPS: {}\n\
0.1% low FPS: {}\n\
Frame stability: {}\n\
Stutter candidates: {}\n\
Scene classification: {}\n\
\n\
What to do next:\n\
1. Start CS2 and wait until the menu or a match is visible.\n\
2. In AetherFrameGuard click Step 1: Measure Current FPS / PC State.\n\
3. If FPS still says n/a, click Re-test Now after CS2 has been visible for 10+ seconds.\n\
4. If capture still fails, confirm PresentMon path above exists and run this diagnostic again.\n\
\n\
Machine-readable details: {}\n",
        chrono_like_timestamp(),
        if signals.counter_strike_active {
            "running"
        } else {
            "not running"
        },
        if signals.counter_strike_process_names.is_empty() {
            "none".to_string()
        } else {
            signals.counter_strike_process_names.join(", ")
        },
        launch_status.preferred_launch_path,
        launch_status.exists,
        launch_status.readable,
        launch_status.uses_steam_applaunch_730,
        launch_status.uses_high_priority,
        diagnostics.presentmon_found,
        diagnostics
            .presentmon_path
            .clone()
            .unwrap_or_else(|| "n/a".to_string()),
        diagnostics.capture_attempted,
        diagnostics.capture_succeeded,
        diagnostics
            .capture_error
            .clone()
            .unwrap_or_else(|| "none".to_string()),
        diagnostics
            .avg_fps
            .map(|v| format!("{v:.1}"))
            .unwrap_or_else(|| "n/a".to_string()),
        diagnostics
            .avg_frametime_ms
            .map(|v| format!("{v:.2}"))
            .unwrap_or_else(|| "n/a".to_string()),
        diagnostics
            .pc_latency_ms
            .map(|v| format!("{v:.2}"))
            .unwrap_or_else(|| "n/a".to_string()),
        diagnostics
            .fps_1pct_low
            .map(|v| format!("{v:.1}"))
            .unwrap_or_else(|| "n/a".to_string()),
        diagnostics
            .fps_0_1pct_low
            .map(|v| format!("{v:.1}"))
            .unwrap_or_else(|| "n/a".to_string()),
        if diagnostics.stability_score > 0.0 {
            format!("{:.0}%", diagnostics.stability_score)
        } else {
            "n/a".to_string()
        },
        diagnostics.stutter_count,
        if diagnostics.scene_classification.is_empty() {
            "unknown".to_string()
        } else {
            diagnostics.scene_classification.clone()
        },
        report_path.to_string_lossy()
    );

    let log_path = counter_strike_diagnostics_log_path();
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(&log_path, &log).map_err(|e| e.to_string())?;
    Ok(log)
}

fn counter_strike_launch_flags_from_text(text: &str) -> (bool, bool, bool) {
    let lower = text.to_ascii_lowercase();
    let uses_steam_applaunch_730 = lower.contains("steam.exe") && lower.contains("-applaunch 730");
    let uses_high_priority = lower.contains("/high");
    let mentions_optimized_autoexec =
        lower.contains("+exec autoexec_optimized.cfg") || lower.contains("+exec autoexec.cfg");
    (
        uses_steam_applaunch_730,
        uses_high_priority,
        mentions_optimized_autoexec,
    )
}

fn counter_strike_launch_status() -> CounterStrikeLaunchStatus {
    let path = PathBuf::from(CS2_AFFINITY_LAUNCH_PATH);
    let exists = path.exists();
    let text = fs::read_to_string(&path).ok();
    let readable = text.is_some();
    let (uses_steam_applaunch_730, uses_high_priority, mentions_optimized_autoexec) =
        counter_strike_launch_flags_from_text(text.as_deref().unwrap_or_default());
    let mut notes = Vec::new();

    if exists && readable && uses_steam_applaunch_730 {
        notes.push("Preferred CS2 launch batch is readable and launches Steam app 730".to_string());
    } else if exists && !readable {
        notes.push("Preferred CS2 launch batch exists but could not be read".to_string());
    } else if !exists {
        notes.push("Preferred CS2 launch batch was not found".to_string());
    } else {
        notes.push(
            "Preferred CS2 launch batch is readable but app 730 launch intent was not proven"
                .to_string(),
        );
    }

    if uses_high_priority {
        notes.push("Batch requests high process priority through Windows start /high".to_string());
    }
    if mentions_optimized_autoexec {
        notes.push(
            "Batch preserves the user's explicit +exec CS2 config launch argument".to_string(),
        );
    }
    if exists {
        notes.push(
            "AetherFrameGuard reports this launch path but does not rewrite or intercept it"
                .to_string(),
        );
    }

    CounterStrikeLaunchStatus {
        preferred_launch_path: CS2_AFFINITY_LAUNCH_PATH.to_string(),
        exists,
        readable,
        uses_steam_applaunch_730,
        uses_high_priority,
        notes,
    }
}

fn chrono_like_timestamp() -> String {
    let now = SystemTime::now();
    let secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    format!("{}", secs)
}

fn compute_module_average(modules: &ModuleCollection) -> f64 {
    (modules.security.score
        + modules.network.score
        + modules.performance.score
        + modules.gaming.score)
        / 4.0
}

fn benchmark_confidence(analysis: &AnalysisResponse) -> f64 {
    let mut points = 30.0;
    if analysis.counter_strike.active {
        points += 15.0;
    }
    if analysis.counter_strike.avg_fps.is_some() {
        points += 20.0;
    }
    if analysis.counter_strike.avg_frametime_ms.is_some() {
        points += 12.0;
    }
    if analysis.counter_strike.pc_latency_ms.is_some() {
        points += 10.0;
    }
    if analysis.signals.avg_ping_ms.is_some() {
        points += 7.0;
    }
    if analysis.signals.system_latency_ms.is_some() {
        points += 6.0;
    }
    clamp(points, 0.0, 100.0)
}

fn benchmark_objective_score(session: &BenchmarkSession) -> f64 {
    let metrics = CounterStrikeOptimizationMetrics {
        avg_fps: session.avg_fps,
        avg_frametime_ms: session.avg_frametime_ms,
        pc_latency_ms: session.pc_latency_ms,
        network_latency_ms: session.network_latency_ms,
        system_latency_ms: session.system_latency_ms,
        fps_1pct_low: session.fps_1pct_low,
        fps_0_1pct_low: session.fps_0_1pct_low,
        stutter_count: session.stutter_count,
        stability_score: session.stability_score,
        scene_classification: if session.scene_classification.is_empty() {
            "unknown".to_string()
        } else {
            session.scene_classification.clone()
        },
    };
    let optimizer_term = cs2_optimization_objective_score(&metrics);
    let blend = (session.counter_strike_score * 0.35) + (session.promotion_score * 0.25);
    clamp((optimizer_term * 0.55) + blend, 0.0, 100.0)
}

fn classify_counter_strike_scene(
    avg_fps: Option<f64>,
    avg_frametime_ms: Option<f64>,
    network_latency_ms: Option<f64>,
    system_latency_ms: Option<f64>,
) -> String {
    let Some(fps) = avg_fps else {
        return "unknown".to_string();
    };
    let frame = avg_frametime_ms.unwrap_or_else(|| if fps > 0.0 { 1000.0 / fps } else { 0.0 });
    let network = network_latency_ms.unwrap_or(999.0);
    let system = system_latency_ms.unwrap_or(0.0);

    if fps >= 360.0 && frame <= 3.5 && (network >= 70.0 || system <= 0.2) {
        "menu_or_lobby".to_string()
    } else if fps >= 55.0 && frame <= 24.0 && network <= 85.0 && system >= 0.2 {
        "gameplay_candidate".to_string()
    } else {
        "unknown".to_string()
    }
}

fn cs2_optimization_objective_score(metrics: &CounterStrikeOptimizationMetrics) -> f64 {
    let avg = metrics.avg_fps.unwrap_or(0.0);
    let low_1 = metrics.fps_1pct_low.unwrap_or(avg * 0.72);
    let low_01 = metrics.fps_0_1pct_low.unwrap_or(avg * 0.55);
    let frame_penalty = metrics.avg_frametime_ms.unwrap_or(16.7) * 1.4;
    let pc_penalty = metrics.pc_latency_ms.unwrap_or(22.0) * 0.7;
    let net_penalty = metrics.network_latency_ms.unwrap_or(65.0) * 0.18;
    let sys_penalty = metrics.system_latency_ms.unwrap_or(4.0) * 2.0;
    let stutter_penalty = (metrics.stutter_count as f64 * 2.4).min(28.0);
    let stability = metrics.stability_score.clamp(0.0, 100.0) * 0.42;
    let scene_adjust = match metrics.scene_classification.as_str() {
        "gameplay_candidate" => 10.0,
        "menu_or_lobby" => -32.0,
        _ => -8.0,
    };

    clamp(
        (avg.min(360.0) * 0.08)
            + (low_1.min(300.0) * 0.14)
            + (low_01.min(240.0) * 0.10)
            + stability
            + scene_adjust
            - frame_penalty
            - pc_penalty
            - net_penalty
            - sys_penalty
            - stutter_penalty,
        0.0,
        100.0,
    )
}

fn build_benchmark_session(
    source: &str,
    analysis: &AnalysisResponse,
    notes: Vec<String>,
) -> BenchmarkSession {
    let timestamp = chrono_like_timestamp();
    let mut session = BenchmarkSession {
        id: format!("{}-{}", source, timestamp),
        timestamp,
        source: source.to_string(),
        promotion_score: analysis.promotion.promoted,
        counter_strike_score: analysis.counter_strike.score,
        avg_fps: analysis.counter_strike.avg_fps,
        avg_frametime_ms: analysis.counter_strike.avg_frametime_ms,
        pc_latency_ms: analysis.counter_strike.pc_latency_ms,
        network_latency_ms: analysis.counter_strike.network_latency_ms,
        system_latency_ms: analysis.signals.system_latency_ms,
        fps_1pct_low: analysis.counter_strike.fps_1pct_low,
        fps_0_1pct_low: analysis.counter_strike.fps_0_1pct_low,
        stutter_count: analysis.counter_strike.stutter_count,
        stability_score: analysis.counter_strike.stability_score,
        scene_classification: analysis.counter_strike.scene_classification.clone(),
        confidence: benchmark_confidence(analysis),
        objective_score: 0.0,
        notes,
    };
    session.objective_score = benchmark_objective_score(&session);
    session
}

fn push_benchmark_session(session: BenchmarkSession) {
    let mut state = load_benchmark_state();
    state.total_sessions += 1;
    state.sessions.push(session);
    if state.sessions.len() > 120 {
        state.sessions.remove(0);
    }
    save_benchmark_state(&state);
}

fn benchmark_status_from_state(state: &BenchmarkState) -> BenchmarkStatus {
    let baseline = state.sessions.first().cloned();
    let latest = state.sessions.last().cloned();
    let best = state
        .sessions
        .iter()
        .max_by(|a, b| {
            a.objective_score
                .partial_cmp(&b.objective_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .cloned();

    BenchmarkStatus {
        total_sessions: state.total_sessions,
        baseline,
        latest,
        best,
        regression_guardrail_active: state.last_guardrail_active,
        last_guardrail_note: state.last_guardrail_note.clone(),
    }
}

fn evaluate_regression_guardrail(
    before: &BenchmarkSession,
    after: &BenchmarkSession,
) -> Option<String> {
    if before.confidence < 55.0 || after.confidence < 55.0 {
        return None;
    }

    if after.objective_score + 4.0 < before.objective_score {
        return Some(format!(
            "Objective score regressed {:.1} -> {:.1}",
            before.objective_score, after.objective_score
        ));
    }

    if let (Some(before_fps), Some(after_fps)) = (before.avg_fps, after.avg_fps) {
        if after_fps + 8.0 < before_fps {
            return Some(format!(
                "FPS regressed {:.1} -> {:.1}",
                before_fps, after_fps
            ));
        }
    }

    if let (Some(before_frame), Some(after_frame)) =
        (before.avg_frametime_ms, after.avg_frametime_ms)
    {
        if after_frame > before_frame * 1.12 {
            return Some(format!(
                "Frametime regressed {:.2}ms -> {:.2}ms",
                before_frame, after_frame
            ));
        }
    }

    None
}

fn build_module_collection(signals: &HostSignals) -> ModuleCollection {
    ModuleCollection {
        security: score_security(signals),
        network: score_network(signals),
        performance: score_performance(signals),
        gaming: score_gaming(signals),
    }
}

fn build_recommendations(
    signals: &HostSignals,
    modules: &ModuleCollection,
    promotion: &AetherframePromotionBreakdown,
    counter_strike: &CounterStrikeSummary,
) -> Vec<Recommendation> {
    let mut out = Vec::new();

    if !signals.firewall_enabled {
        out.push(Recommendation {
            id: "enable_firewall".to_string(),
            title: "Enable Windows Firewall for all profiles".to_string(),
            rationale:
                "Firewall is not fully enabled. This is a high-value security hardening baseline."
                    .to_string(),
            risk: "low".to_string(),
            impact: "high".to_string(),
            confidence: clamp(promotion.promoted + 8.0, 0.0, 100.0),
            category: "security".to_string(),
        });
    }

    if !signals.defender_realtime_enabled {
        out.push(Recommendation {
            id: "enable_defender_realtime".to_string(),
            title: "Enable Defender real-time monitoring".to_string(),
            rationale: "Real-time protection appears disabled. This increases exploit and malware exposure.".to_string(),
            risk: "low".to_string(),
            impact: "high".to_string(),
            confidence: clamp(promotion.promoted + 10.0, 0.0, 100.0),
            category: "security".to_string(),
        });
    }

    if !signals.high_performance_plan_active {
        out.push(Recommendation {
            id: "switch_power_plan".to_string(),
            title: "Switch to High/Ultimate performance while gaming".to_string(),
            rationale: "Current power plan is not optimized for stable frame-time under load."
                .to_string(),
            risk: "medium".to_string(),
            impact: "medium".to_string(),
            confidence: clamp(promotion.promoted + 4.0, 0.0, 100.0),
            category: "performance".to_string(),
        });
    }

    if signals.background_process_count > 220 {
        out.push(Recommendation {
            id: "trim_background".to_string(),
            title: "Trim startup and background processes before game launch".to_string(),
            rationale: format!(
                "Detected {} active processes; reducing background contention can improve FPS consistency.",
                signals.background_process_count
            ),
            risk: "medium".to_string(),
            impact: "medium".to_string(),
            confidence: clamp(promotion.promoted + 2.0, 0.0, 100.0),
            category: "performance".to_string(),
        });
    }

    if !signals.ethernet_adapter_active && signals.wifi_adapter_active {
        out.push(Recommendation {
            id: "prefer_ethernet".to_string(),
            title: "Prefer Ethernet for CS2 or latency-sensitive play".to_string(),
            rationale: "Wi-Fi is active but no Ethernet path is detected. Wired networking usually improves jitter stability.".to_string(),
            risk: "low".to_string(),
            impact: "medium".to_string(),
            confidence: clamp(modules.network.score + 6.0, 0.0, 100.0),
            category: "network".to_string(),
        });
    }

    if let Some(ping) = signals.avg_ping_ms {
        if ping > 45.0 {
            out.push(Recommendation {
                id: "network_latency_path".to_string(),
                title: "Prioritize low-latency network path".to_string(),
                rationale: format!(
                    "Average outbound latency {:.1}ms is elevated for competitive play. Prefer wired path and reduce concurrent traffic.",
                    ping
                ),
                risk: "low".to_string(),
                impact: "medium".to_string(),
                confidence: clamp(promotion.promoted + 3.0, 0.0, 100.0),
                category: "network".to_string(),
            });
        }
    }

    if signals.overlay_process_count > 0 {
        out.push(Recommendation {
            id: "close_overlays".to_string(),
            title: "Close overlays and capture hooks before gaming".to_string(),
            rationale: format!(
                "Detected overlay-related processes: {}.",
                signals.overlay_process_names.join(", ")
            ),
            risk: "low".to_string(),
            impact: "medium".to_string(),
            confidence: clamp(modules.gaming.score + 5.0, 0.0, 100.0),
            category: "gaming".to_string(),
        });
    }

    if counter_strike.active && counter_strike.score < 100.0 {
        out.push(Recommendation {
            id: "cs_performance_hardening".to_string(),
            title: "Continue Counter-Strike tuning until readiness reaches 100%".to_string(),
            rationale: "AetherframeGuard detected Counter-Strike and still sees room for FPS/readiness gains.".to_string(),
            risk: "low".to_string(),
            impact: "high".to_string(),
            confidence: clamp(counter_strike.score + 8.0, 0.0, 100.0),
            category: "gaming".to_string(),
        });
    }

    out.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

fn build_actions(signals: &HostSignals, modules: &ModuleCollection) -> Vec<QuickAction> {
    let mut out = vec![
        QuickAction {
            id: "open_security_center".to_string(),
            title: "Open Windows Security".to_string(),
            category: "security".to_string(),
            rationale:
                "Jump to Windows Security for firewall, Defender, and account health checks."
                    .to_string(),
            confidence: modules.security.score,
        },
        QuickAction {
            id: "open_firewall".to_string(),
            title: "Open Firewall settings".to_string(),
            category: "security".to_string(),
            rationale: "Review firewall profile state and inbound rules.".to_string(),
            confidence: if signals.firewall_enabled { 82.0 } else { 96.0 },
        },
        QuickAction {
            id: "open_power_settings".to_string(),
            title: "Open Power settings".to_string(),
            category: "performance".to_string(),
            rationale: "Switch power profiles quickly for gaming sessions.".to_string(),
            confidence: modules.performance.score,
        },
        QuickAction {
            id: "open_startup_apps".to_string(),
            title: "Open Startup Apps".to_string(),
            category: "performance".to_string(),
            rationale: "Trim unnecessary startup load before gaming.".to_string(),
            confidence: modules.performance.score,
        },
        QuickAction {
            id: "open_network_status".to_string(),
            title: "Open Network status".to_string(),
            category: "network".to_string(),
            rationale: "Inspect active adapters and connectivity state.".to_string(),
            confidence: modules.network.score,
        },
        QuickAction {
            id: "flush_dns".to_string(),
            title: "Flush DNS cache".to_string(),
            category: "network".to_string(),
            rationale: "Refresh cached DNS resolution before a play session.".to_string(),
            confidence: 78.0,
        },
        QuickAction {
            id: "open_task_manager".to_string(),
            title: "Open Task Manager".to_string(),
            category: "performance".to_string(),
            rationale: "Identify heavy background consumers and overlays.".to_string(),
            confidence: 88.0,
        },
        QuickAction {
            id: "open_game_bar_settings".to_string(),
            title: "Open Game Bar settings".to_string(),
            category: "gaming".to_string(),
            rationale: "Review capture overlays and Game Bar behavior for CS sessions.".to_string(),
            confidence: modules.gaming.score,
        },
    ];

    out.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

fn validate_action_id(id: &str) -> bool {
    matches!(
        id,
        "open_security_center"
            | "open_firewall"
            | "open_power_settings"
            | "open_startup_apps"
            | "open_network_status"
            | "flush_dns"
            | "open_task_manager"
            | "open_game_bar_settings"
    )
}

fn save_counter_strike_request(request: &CounterStrikeOptimizationRequest) {
    save_json(
        PathBuf::from(r"C:\ProgramData\AetherframeGuard\counter_strike_request.json"),
        request,
    );
}

fn load_counter_strike_request() -> Option<CounterStrikeOptimizationRequest> {
    load_json(PathBuf::from(
        r"C:\ProgramData\AetherframeGuard\counter_strike_request.json",
    ))
}

fn clear_counter_strike_request() {
    let _ = fs::remove_file(PathBuf::from(
        r"C:\ProgramData\AetherframeGuard\counter_strike_request.json",
    ));
}

fn boot_history_path() -> PathBuf {
    aetherframe_data_dir().join("boot_history.json")
}
fn calibration_path() -> PathBuf {
    aetherframe_data_dir().join("calibration.json")
}
fn nvidia_tuning_path() -> PathBuf {
    aetherframe_data_dir().join("nvidia_tuning.json")
}
fn auto_monitor_path() -> PathBuf {
    aetherframe_data_dir().join("auto_monitor.json")
}
fn counter_strike_steam_sync_path() -> PathBuf {
    aetherframe_data_dir().join("counter_strike_steam_sync.json")
}
fn counter_strike_fps_path() -> PathBuf {
    aetherframe_data_dir().join("counter_strike_fps.json")
}
fn benchmark_path() -> PathBuf {
    aetherframe_data_dir().join("benchmark_history.json")
}
fn safe_process_whitelist_path() -> PathBuf {
    aetherframe_data_dir().join("safe_process_whitelist.json")
}
fn cs2_change_log_path() -> PathBuf {
    aetherframe_data_dir().join("cs2_suggested_settings_changes.json")
}
fn backup_root_path() -> PathBuf {
    aetherframe_data_dir().join("backups")
}
fn latest_diagnostics_log_path() -> PathBuf {
    aetherframe_data_dir().join("latest_diagnostics.log")
}

fn redact_sensitive_text(text: &str) -> String {
    let mut redacted = text.to_string();
    if let Ok(user_profile) = env::var("USERPROFILE") {
        if !user_profile.trim().is_empty() {
            redacted = redacted.replace(&user_profile, "%USERPROFILE%");
            redacted = redacted.replace(&user_profile.replace('\\', "/"), "%USERPROFILE%");
        }
    }
    redacted
}

fn timestamped_backup_dir(label: &str) -> PathBuf {
    backup_root_path().join(format!("{}-{}", label, chrono_like_timestamp()))
}

fn backup_file_if_exists(
    path: &Path,
    backup_dir: &Path,
    notes: &mut Vec<String>,
) -> Result<Option<PathBuf>, String> {
    if !path.exists() {
        notes.push(format!(
            "No existing file to back up: {}",
            redact_sensitive_text(&path.to_string_lossy())
        ));
        return Ok(None);
    }
    fs::create_dir_all(backup_dir).map_err(|e| e.to_string())?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config.bak");
    let backup_path = backup_dir.join(file_name);
    fs::copy(path, &backup_path).map_err(|e| e.to_string())?;
    notes.push(format!(
        "Backed up {} to {}",
        redact_sensitive_text(&path.to_string_lossy()),
        redact_sensitive_text(&backup_path.to_string_lossy())
    ));
    Ok(Some(backup_path))
}

fn contains_risky_cs2_config_line(text: &str) -> bool {
    text.lines().any(|line| {
        let trimmed = line.trim().to_ascii_lowercase();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            return false;
        }
        trimmed.contains("alias ")
            || trimmed.contains("bind mouse1")
            || trimmed.contains(r"exec \..")
            || trimmed.contains("developer 1")
            || trimmed.contains("sv_cheats")
    })
}

fn overwrite_latest_diagnostics_log(text: &str) -> Result<(), String> {
    let path = latest_diagnostics_log_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(path, text).map_err(|e| e.to_string())
}

fn load_boot_history() -> BootHistory {
    load_json(boot_history_path()).unwrap_or(BootHistory {
        entries: Vec::new(),
        best_promotion_ever: 0.0,
        total_boots_optimized: 0,
    })
}
fn save_boot_history(history: &BootHistory) {
    save_json(boot_history_path(), history);
}
fn load_nvidia_tuning_state() -> NvidiaTuningState {
    load_json(nvidia_tuning_path()).unwrap_or(NvidiaTuningState {
        tools_path: NVIDIA_TOOLS_DIR.to_string(),
        cli_path: None,
        gui_path: None,
        profile_path: None,
        total_iterations: 0,
        best_delta: 0.0,
        last_delta: None,
        iterations: Vec::new(),
    })
}
fn save_nvidia_tuning_state(state: &NvidiaTuningState) {
    save_json(nvidia_tuning_path(), state);
}
fn load_auto_monitor_state() -> AutoMonitorState {
    load_json(auto_monitor_path()).unwrap_or(AutoMonitorState {
        total_cycles: 0,
        best_promotion: 0.0,
        last_promotion: None,
        last_threat_score: None,
        history: Vec::new(),
    })
}
fn save_auto_monitor_state(state: &AutoMonitorState) {
    save_json(auto_monitor_path(), state);
}
fn load_counter_strike_steam_sync_state() -> CounterStrikeSteamSyncState {
    load_json(counter_strike_steam_sync_path()).unwrap_or(CounterStrikeSteamSyncState {
        last_synced_at: None,
        total_syncs: 0,
        total_accounts: 0,
        synced_accounts: 0,
        last_score: None,
        accounts: Vec::new(),
    })
}
fn save_counter_strike_steam_sync_state(state: &CounterStrikeSteamSyncState) {
    save_json(counter_strike_steam_sync_path(), state);
}
fn load_counter_strike_fps_telemetry() -> Option<CounterStrikeFpsTelemetry> {
    load_json(counter_strike_fps_path())
}
fn save_counter_strike_fps_telemetry(sample: &CounterStrikeFpsTelemetry) {
    save_json(counter_strike_fps_path(), sample);
}
fn load_benchmark_state() -> BenchmarkState {
    load_json(benchmark_path()).unwrap_or(BenchmarkState {
        total_sessions: 0,
        sessions: Vec::new(),
        last_guardrail_active: false,
        last_guardrail_note: None,
    })
}
fn save_benchmark_state(state: &BenchmarkState) {
    save_json(benchmark_path(), state);
}

fn load_user_safe_multi_instance_whitelist() -> HashSet<String> {
    load_json::<Vec<String>>(safe_process_whitelist_path())
        .unwrap_or_default()
        .into_iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn save_user_safe_multi_instance_whitelist(items: &HashSet<String>) -> Result<(), String> {
    let mut out: Vec<String> = items.iter().cloned().collect();
    out.sort();
    let text = serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?;
    if let Some(parent) = safe_process_whitelist_path().parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(safe_process_whitelist_path(), text).map_err(|e| e.to_string())
}

fn normalize_process_name(name: &str) -> String {
    name.trim()
        .to_ascii_lowercase()
        .trim_end_matches(".exe")
        .to_string()
}
fn validate_whitelist_process_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 80
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}
fn is_builtin_multi_instance_safe(name: &str) -> bool {
    MULTI_INSTANCE_WHITELIST
        .iter()
        .any(|known| name == *known || name.contains(known))
}
fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn security_recommendation(category: &str, severity: &str) -> String {
    match category {
        "process" => "Review the process path, publisher, and launch context before terminating or quarantining. If unexpected, scan the file with Defender and remove only through a trusted security tool.".to_string(),
        "network" => "Correlate the PID with Task Manager or Resource Monitor. If the connection is unexpected, close the app and run a Defender offline or full scan.".to_string(),
        "persistence" => "Review the startup entry owner and file path. Disable it through Windows Startup Apps or Autoruns only after confirming it is not expected software.".to_string(),
        "scheduled_task" => "Review the scheduled task action, author, and run account. Disable only if it is unexpected or points to an untrusted/temp/user-writable path.".to_string(),
        "overlay" => "If you are not actively using the overlay/capture tool, close it before CS2. If expected, treat this as performance/privacy context rather than a threat.".to_string(),
        "system" => "Review the Windows security setting in Windows Security or Settings. Do not disable protections; re-enable missing controls unless you intentionally manage them elsewhere.".to_string(),
        _ if severity == "critical" => "Treat as high priority: verify the evidence, disconnect from untrusted networks if needed, and run a trusted security scan.".to_string(),
        _ => "Review the evidence and confirm whether this is expected software before taking action.".to_string(),
    }
}

fn advisory_or_confirmed_label(confirmed: bool) -> &'static str {
    if confirmed {
        "confirmed local observation"
    } else {
        "advisory signal"
    }
}

fn annotate_finding(mut finding: ThreatFinding, source: &str, confirmed: bool) -> ThreatFinding {
    finding.recommendation = security_recommendation(&finding.category, &finding.severity);
    finding.source = source.to_string();
    finding.confirmed = confirmed;
    finding.observed_at = chrono_like_timestamp();
    finding.description = redact_sensitive_text(&finding.description);
    finding.evidence = redact_sensitive_text(&finding.evidence);
    if !finding.evidence.contains("observation=") {
        finding.evidence = format!(
            "{} | observation={}",
            finding.evidence,
            advisory_or_confirmed_label(confirmed)
        );
    }
    finding
}

fn is_user_writable_or_temp_path(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains(r"	emp")
        || lower.contains(r"	mp")
        || lower.contains("/tmp/")
        || lower.contains(r"\downloads")
        || lower.contains(r"appdata\local	emp")
}

fn scan_security_misconfiguration(signals: &HostSignals) -> Vec<ThreatFinding> {
    let mut findings = Vec::new();
    if !signals.firewall_enabled {
        findings.push(annotate_finding(ThreatFinding {
            id: "config_firewall_incomplete".to_string(),
            category: "system".to_string(),
            title: "Windows Firewall is not enabled for all profiles".to_string(),
            description: "A local Windows configuration check did not confirm all firewall profiles are enabled.".to_string(),
            severity: "medium".to_string(),
            confidence: 70.0,
            evidence: "Get-NetFirewallProfile enabled-profile count was below 3".to_string(),
            recommendation: String::new(), source: String::new(), confirmed: false, observed_at: String::new(),
        }, "windows_security_config", true));
    }
    if !signals.defender_realtime_enabled {
        findings.push(annotate_finding(
            ThreatFinding {
                id: "config_defender_realtime_off".to_string(),
                category: "system".to_string(),
                title: "Defender realtime protection was not confirmed enabled".to_string(),
                description:
                    "A local Defender status query did not confirm realtime protection is enabled."
                        .to_string(),
                severity: "high".to_string(),
                confidence: 76.0,
                evidence: "Get-MpComputerStatus.RealTimeProtectionEnabled was false or unavailable"
                    .to_string(),
                recommendation: String::new(),
                source: String::new(),
                confirmed: false,
                observed_at: String::new(),
            },
            "windows_security_config",
            true,
        ));
    }
    if signals.remote_desktop_enabled {
        findings.push(annotate_finding(ThreatFinding {
            id: "config_remote_desktop_enabled".to_string(),
            category: "system".to_string(),
            title: "Remote Desktop is enabled".to_string(),
            description: "Remote Desktop increases local attack surface if exposed to untrusted networks.".to_string(),
            severity: "low".to_string(),
            confidence: 65.0,
            evidence: "fDenyTSConnections indicates RDP is enabled".to_string(),
            recommendation: String::new(), source: String::new(), confirmed: false, observed_at: String::new(),
        }, "windows_security_config", false));
    }
    findings
}

fn scan_overlay_capture_tools(system: &System) -> Vec<ThreatFinding> {
    let mut names: Vec<String> = system
        .processes()
        .values()
        .map(|proc| proc.name().to_string())
        .filter(|name| {
            let lower = name.to_ascii_lowercase();
            OVERLAY_CAPTURE_PROCESS_MARKERS
                .iter()
                .any(|marker| lower.contains(marker))
        })
        .collect();
    names.sort();
    names.dedup();
    if names.is_empty() {
        return Vec::new();
    }
    vec![annotate_finding(ThreatFinding {
        id: "overlay_capture_tools_present".to_string(),
        category: "overlay".to_string(),
        title: "Overlay or capture tools are running".to_string(),
        description: "Overlay/capture processes can affect CS2 performance or privacy, but many are legitimate. This is an advisory local observation, not a malware verdict.".to_string(),
        severity: "low".to_string(),
        confidence: 48.0,
        evidence: names.join(", "),
        recommendation: String::new(), source: String::new(), confirmed: false, observed_at: String::new(),
    }, "process_overlay_scan", false)]
}

fn scan_scheduled_task_persistence() -> Vec<ThreatFinding> {
    let mut findings = Vec::new();
    let script = r#"Get-ScheduledTask | ForEach-Object {
        $task = $_
        foreach ($action in $task.Actions) {
            $exec = [string]$action.Execute
            $args = [string]$action.Arguments
            if ($exec -or $args) {
                "$($task.TaskPath)$($task.TaskName)`t$($task.Author)`t$exec $args"
            }
        }
    }"#;
    let Some(output) = run_powershell(script) else {
        return findings;
    };
    for (idx, line) in output.lines().enumerate() {
        let parts: Vec<&str> = line.splitn(3, '\t').collect();
        if parts.len() < 3 {
            continue;
        }
        let task_name = parts[0].trim();
        let author = parts[1].trim();
        let action = parts[2].trim();
        let lower = action.to_ascii_lowercase();
        if task_name.to_ascii_lowercase().contains("aetherframeguard") {
            continue;
        }
        if let Some(marker) = SUSPICIOUS_TASK_ACTION_MARKERS
            .iter()
            .find(|marker| lower.contains(**marker))
        {
            let severity =
                if lower.contains("-encodedcommand") || lower.contains("frombase64string") {
                    "high"
                } else if is_user_writable_or_temp_path(action) {
                    "medium"
                } else {
                    "low"
                };
            findings.push(annotate_finding(ThreatFinding {
                id: format!("task_suspicious_action_{}", idx),
                category: "scheduled_task".to_string(),
                title: format!("Scheduled task has a risky-looking action: {}", task_name),
                description: "A scheduled task action matched a local heuristic for temp/user-writable paths or script-obfuscation patterns. This requires user review and is not a malware verdict.".to_string(),
                severity: severity.to_string(),
                confidence: if severity == "high" { 72.0 } else { 58.0 },
                evidence: format!("task='{}' author='{}' marker='{}' action='{}'", task_name, author, marker, action),
                recommendation: String::new(), source: String::new(), confirmed: false, observed_at: String::new(),
            }, "scheduled_task_inventory", false));
        }
    }
    findings
}

fn scan_processes_for_threats(system: &System) -> Vec<ThreatFinding> {
    let mut findings = Vec::new();
    let mut name_counts: HashMap<String, usize> = HashMap::new();
    let user_whitelist = load_user_safe_multi_instance_whitelist();

    for proc in system.processes().values() {
        let name = normalize_process_name(&proc.name().to_string());
        *name_counts.entry(name).or_insert(0) += 1;
    }

    for proc in system.processes().values() {
        let name_raw = proc.name().to_string();
        let name = normalize_process_name(&name_raw);
        let pid = format!("{}", proc.pid());

        for bad in KNOWN_MALWARE_NAMES {
            if name.contains(bad) {
                findings.push(annotate_finding(ThreatFinding {
                    id: format!("proc_malware_{}_{}", bad, pid),
                    category: "process".to_string(),
                    title: format!("Known threat signature matched: {}", name_raw),
                    description: format!("Process '{}' (PID {}) matches known malware or offensive-tool pattern '{}'.", name_raw, pid, bad),
                    severity: "critical".to_string(),
                    confidence: 87.0,
                    evidence: format!("PID {} - name matched '{}'", pid, bad),
                    recommendation: String::new(),
                    source: String::new(),
                    confirmed: false,
                    observed_at: String::new(),
                }, "process_scan", true));
            }
        }

        if let Some(exe) = proc.exe() {
            let p = exe.to_string_lossy().to_lowercase();
            if p.contains("\\temp\\") || p.contains("\\tmp\\") || p.contains("/tmp/") {
                findings.push(annotate_finding(
                    ThreatFinding {
                        id: format!("proc_temppath_{}", pid),
                        category: "process".to_string(),
                        title: format!("Executable running from temp directory: {}", name_raw),
                        description: format!(
                            "'{}' (PID {}) is executing from '{}'.",
                            name_raw,
                            pid,
                            exe.display()
                        ),
                        severity: "high".to_string(),
                        confidence: 73.0,
                        evidence: exe.to_string_lossy().to_string(),
                        recommendation: String::new(),
                        source: String::new(),
                        confirmed: false,
                        observed_at: String::new(),
                    },
                    "process_scan",
                    true,
                ));
            }
        }
    }

    for (name, count) in &name_counts {
        if *count > 3 && !is_builtin_multi_instance_safe(name) && !user_whitelist.contains(name) {
            findings.push(annotate_finding(
                ThreatFinding {
                    id: format!("proc_dupes_{}", name),
                    category: "process".to_string(),
                    title: format!("Suspicious replication: {} ({} instances)", name, count),
                    description: format!(
                        "{} simultaneous instances of '{}' detected.",
                        count, name
                    ),
                    severity: "medium".to_string(),
                    confidence: 55.0,
                    evidence: format!("{} simultaneous instances", count),
                    recommendation: String::new(),
                    source: String::new(),
                    confirmed: false,
                    observed_at: String::new(),
                },
                "process_scan",
                false,
            ));
        }
    }

    findings
}

fn scan_network_connections() -> Vec<ThreatFinding> {
    let mut findings = Vec::new();
    let output = match silent_command("netstat").args(["-ano"]).output() {
        Ok(o) => o,
        Err(_) => return findings,
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut pid_connection_counts: HashMap<String, u32> = HashMap::new();

    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 || parts[0] != "TCP" || parts[3] != "ESTABLISHED" {
            continue;
        }
        let foreign_addr = parts[2];
        let pid = parts[4];
        if let Some(port_str) = foreign_addr.rsplit(':').next() {
            if let Ok(port) = port_str.parse::<u16>() {
                if SUSPICIOUS_REMOTE_PORTS.contains(&port) {
                    findings.push(annotate_finding(
                        ThreatFinding {
                            id: format!("net_suspport_{}_{}", port, pid),
                            category: "network".to_string(),
                            title: format!("Active connection to high-risk port {}", port),
                            description: format!(
                                "Established TCP connection to '{}' on port {}.",
                                foreign_addr, port
                            ),
                            severity: "high".to_string(),
                            confidence: 79.0,
                            evidence: format!("netstat: {} ESTABLISHED PID {}", foreign_addr, pid),
                            recommendation: String::new(),
                            source: String::new(),
                            confirmed: false,
                            observed_at: String::new(),
                        },
                        "netstat",
                        true,
                    ));
                }
                *pid_connection_counts.entry(pid.to_string()).or_insert(0) += 1;
            }
        }
    }

    for (pid, count) in &pid_connection_counts {
        if *count > 18 {
            findings.push(annotate_finding(
                ThreatFinding {
                    id: format!("net_beaconing_{}", pid),
                    category: "network".to_string(),
                    title: format!("Potential beaconing or exfiltration from PID {}", pid),
                    description: format!(
                        "PID {} holds {} simultaneous established outbound connections.",
                        pid, count
                    ),
                    severity: "high".to_string(),
                    confidence: 68.0,
                    evidence: format!("{} simultaneous established connections", count),
                    recommendation: String::new(),
                    source: String::new(),
                    confirmed: false,
                    observed_at: String::new(),
                },
                "netstat",
                false,
            ));
        }
    }

    findings
}

fn scan_startup_persistence() -> Vec<ThreatFinding> {
    let mut findings = Vec::new();
    #[cfg(windows)]
    {
        let run_keys: &[(bool, &str)] = &[
            (true, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (
                true,
                "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            ),
            (false, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (
                false,
                "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            ),
        ];
        for &(is_hkcu, key_path) in run_keys {
            let root = if is_hkcu {
                RegKey::predef(HKEY_CURRENT_USER)
            } else {
                RegKey::predef(HKEY_LOCAL_MACHINE)
            };
            let hive = if is_hkcu { "HKCU" } else { "HKLM" };
            let key = match root.open_subkey(key_path) {
                Ok(k) => k,
                Err(_) => continue,
            };
            for item in key.enum_values() {
                let (name, data) = match item {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let val = data.to_string();
                let lower = val.to_ascii_lowercase();
                if lower.contains("\\temp\\") || lower.contains("\\tmp\\") {
                    findings.push(annotate_finding(
                        ThreatFinding {
                            id: format!("startup_temp_{}_{}", hive, name),
                            category: "persistence".to_string(),
                            title: format!("Startup entry executing from temp: {}", name),
                            description: format!(
                                "Registry run key '{}\\{}\\{}' points to a temporary path.",
                                hive, key_path, name
                            ),
                            severity: "high".to_string(),
                            confidence: 81.0,
                            evidence: val.clone(),
                            recommendation: String::new(),
                            source: String::new(),
                            confirmed: false,
                            observed_at: String::new(),
                        },
                        "registry_run_key",
                        true,
                    ));
                }
            }
        }
    }
    findings
}

fn scan_counter_strike_config_security() -> Vec<ThreatFinding> {
    let mut findings = Vec::new();
    for root in counter_strike_steam_userdata_roots() {
        let account_id = counter_strike_steam_account_id(&root);
        let cfg_dir = root.join("730").join("local").join("cfg");
        for file_name in ["autoexec.cfg", COUNTER_STRIKE_STEAM_MANAGED_CFG] {
            let path = cfg_dir.join(file_name);
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            if contains_risky_cs2_config_line(&text) {
                findings.push(annotate_finding(ThreatFinding {
                    id: format!("cs2_config_review_{}_{}", account_id, file_name.replace('.', "_")),
                    category: "gaming".to_string(),
                    title: format!("CS2 config needs review: {}", file_name),
                    description: "A CS2 config file contains command patterns that can change behavior or hide telemetry. This is a defensive review prompt, not a cheat or malware verdict.".to_string(),
                    severity: "low".to_string(),
                    confidence: 46.0,
                    evidence: format!("account={} file={}", account_id, path.to_string_lossy()),
                    recommendation: String::new(),
                    source: String::new(),
                    confirmed: false,
                    observed_at: String::new(),
                }, "cs2_config_review", false));
            }
        }
    }
    findings
}

fn compute_threat_promotion(findings: &[ThreatFinding]) -> AetherframePromotionBreakdown {
    if findings.is_empty() {
        return compute_aetherframe_promotion(
            AetherframePromotionInputs {
                base_confidence: 0.0,
                bayesian_confidence: 0.0,
                ci_width: 0.5,
                is_uncertain: true,
                contradiction_burden: 0.0,
                strong_signal_count: 0.0,
            },
            DEFAULT_AETHERFRAME_PROMOTION_CONFIG,
        );
    }
    let critical = findings.iter().filter(|f| f.severity == "critical").count() as f64;
    let high = findings.iter().filter(|f| f.severity == "high").count() as f64;
    let total = findings.len() as f64;
    let avg_conf = findings.iter().map(|f| f.confidence).sum::<f64>() / total;
    let base_confidence = clamp(avg_conf, 0.0, 100.0);
    let bayesian_confidence = clamp(
        base_confidence + (critical * 5.0) + (high * 2.0),
        0.0,
        100.0,
    );
    let mut seen: Vec<&str> = Vec::new();
    for f in findings {
        if !seen.contains(&f.category.as_str()) {
            seen.push(f.category.as_str());
        }
    }
    let ci_width = clamp(0.65 - (seen.len() as f64 * 0.1), 0.08, 0.75);
    compute_aetherframe_promotion(
        AetherframePromotionInputs {
            base_confidence,
            bayesian_confidence,
            ci_width,
            is_uncertain: ci_width > 0.35,
            contradiction_burden: 0.0,
            strong_signal_count: critical + high,
        },
        DEFAULT_AETHERFRAME_PROMOTION_CONFIG,
    )
}

#[tauri::command]
fn run_security_scan() -> SecurityScanResult {
    let mut system = System::new_all();
    system.refresh_all();
    let host_signals = collect_host_signals();
    let mut findings = Vec::new();
    findings.extend(scan_security_misconfiguration(&host_signals));
    findings.extend(scan_processes_for_threats(&system));
    findings.extend(scan_overlay_capture_tools(&system));
    findings.extend(scan_network_connections());
    findings.extend(scan_startup_persistence());
    findings.extend(scan_scheduled_task_persistence());
    findings.extend(scan_counter_strike_config_security());
    findings.sort_by(|a, b| {
        severity_rank(&b.severity)
            .cmp(&severity_rank(&a.severity))
            .then(
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
    });
    let threat_promotion = compute_threat_promotion(&findings);
    let total_findings = findings.len();

    SecurityScanResult {
        scan_time: chrono_like_timestamp(),
        total_findings,
        critical_findings: findings.iter().filter(|f| f.severity == "critical").count(),
        high_findings: findings.iter().filter(|f| f.severity == "high").count(),
        medium_findings: findings.iter().filter(|f| f.severity == "medium").count(),
        low_findings: findings.iter().filter(|f| f.severity == "low").count(),
        findings,
        threat_promotion,
        clean: total_findings == 0,
    }
}

fn find_first_existing_file(dir: &PathBuf, names: &[&str]) -> Option<PathBuf> {
    for name in names {
        let candidate = dir.join(name);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn detect_chris_titus_power_plan_guid() -> Option<String> {
    let output = silent_command("powercfg").args(["/list"]).output().ok()?;
    if !output.status.success() {
        return detect_active_power_plan_guid().and_then(|guid| {
            let active = detect_active_power_plan().to_ascii_lowercase();
            if POWER_PLAN_CHRIS_TITUS_TOKENS
                .iter()
                .any(|token| active.contains(token))
            {
                Some(guid)
            } else {
                None
            }
        });
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if POWER_PLAN_CHRIS_TITUS_TOKENS
            .iter()
            .any(|token| lower.contains(token))
            || (lower.contains("chris") && lower.contains("titus"))
        {
            if let Some(start) = line.find('{') {
                if let Some(end_rel) = line[start..].find('}') {
                    return Some(line[start..=start + end_rel].to_string());
                }
            }
        }
    }
    let active = detect_active_power_plan().to_ascii_lowercase();
    if POWER_PLAN_CHRIS_TITUS_TOKENS
        .iter()
        .any(|token| active.contains(token))
    {
        return detect_active_power_plan_guid();
    }
    None
}

fn presentmon_candidate_priority(path: &Path) -> u8 {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name.starts_with("presentmon-") && name.ends_with("-x64.exe") {
        0
    } else if PRESENTMON_BINARY_NAMES
        .iter()
        .any(|known| name.eq_ignore_ascii_case(known))
    {
        1
    } else if name.starts_with("presentmon-") && name.ends_with(".exe") {
        2
    } else {
        9
    }
}

fn collect_presentmon_candidates(dir: &Path, depth_remaining: usize, out: &mut Vec<PathBuf>) {
    if depth_remaining == 0 || !dir.exists() {
        return;
    }
    if let Some(binary) = find_first_existing_file(&dir.to_path_buf(), PRESENTMON_BINARY_NAMES) {
        out.push(binary);
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(|entry| entry.ok()) {
        let path = entry.path();
        if path.is_dir() {
            collect_presentmon_candidates(&path, depth_remaining.saturating_sub(1), out);
        } else if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
            let lower = name.to_ascii_lowercase();
            if (lower.starts_with("presentmon-") || lower == "presentmon.exe")
                && lower.ends_with(".exe")
            {
                out.push(path);
            }
        }
    }
}

fn discover_presentmon_binary_in_dirs(dirs: &[PathBuf], include_path: bool) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    for dir in dirs {
        collect_presentmon_candidates(dir, 4, &mut candidates);
    }
    if include_path {
        if let Some(paths) = env::var_os("PATH") {
            for dir in env::split_paths(&paths) {
                if let Some(binary) = find_first_existing_file(&dir, PRESENTMON_BINARY_NAMES) {
                    candidates.push(binary);
                }
            }
        }
    }
    candidates.sort_by(|a, b| {
        presentmon_candidate_priority(a)
            .cmp(&presentmon_candidate_priority(b))
            .then(a.to_string_lossy().len().cmp(&b.to_string_lossy().len()))
    });
    candidates.dedup();
    candidates.into_iter().find(|path| path.exists())
}

fn discover_presentmon_binary() -> Option<PathBuf> {
    let dirs: Vec<PathBuf> = PRESENTMON_DIR_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .collect();
    discover_presentmon_binary_in_dirs(&dirs, true)
}

fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                current.push('"');
                let _ = chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(current.trim().trim_matches('"').to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    fields.push(current.trim().trim_matches('"').to_string());
    fields
}

fn percentile_fps_from_frame_samples(frame_samples: &[f64], percentile: f64) -> Option<f64> {
    if frame_samples.is_empty() {
        return None;
    }
    let mut sorted = frame_samples
        .iter()
        .copied()
        .filter(|v| (0.2..=1000.0).contains(v))
        .collect::<Vec<_>>();
    if sorted.is_empty() {
        return None;
    }
    sorted.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
    let idx = ((sorted.len() as f64 * percentile).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    let frame = sorted[idx];
    if frame > 0.0 {
        Some(1000.0 / frame)
    } else {
        None
    }
}

fn stability_from_frame_samples(frame_samples: &[f64]) -> (f64, u64) {
    if frame_samples.is_empty() {
        return (0.0, 0);
    }
    let avg = frame_samples.iter().sum::<f64>() / frame_samples.len() as f64;
    if avg <= 0.0 {
        return (0.0, 0);
    }
    let variance =
        frame_samples.iter().map(|v| (v - avg).powi(2)).sum::<f64>() / frame_samples.len() as f64;
    let std_dev = variance.sqrt();
    let stutters = frame_samples
        .iter()
        .filter(|v| **v >= 18.0 || **v >= avg * 2.0)
        .count() as u64;
    let jitter_penalty = (std_dev / avg) * 55.0;
    let stutter_penalty = (stutters as f64 * 2.0).min(35.0);
    (
        clamp(100.0 - jitter_penalty - stutter_penalty, 0.0, 100.0),
        stutters,
    )
}

fn parse_presentmon_csv_metrics(
    text: &str,
    network_latency_ms: Option<f64>,
    system_latency_ms: Option<f64>,
) -> Option<CounterStrikeOptimizationMetrics> {
    let mut lines = text.lines();
    let header = lines.next()?;
    let cols = split_csv_line(header);
    let idx_frame = cols.iter().position(|c| {
        let col = c.trim().trim_start_matches('\u{feff}');
        col.eq_ignore_ascii_case("msBetweenPresents")
            || col.eq_ignore_ascii_case("msBetweenDisplayChange")
            || col.eq_ignore_ascii_case("msInPresentAPI")
    })?;
    let pc_latency_indices: Vec<usize> = cols
        .iter()
        .enumerate()
        .filter_map(|(idx, c)| {
            let col = c.trim().trim_start_matches('\u{feff}');
            if col.eq_ignore_ascii_case("msUntilDisplayed")
                || col.eq_ignore_ascii_case("msUntilRenderComplete")
                || col.eq_ignore_ascii_case("msAllInputToPhotonLatency")
                || col.eq_ignore_ascii_case("msClickToPhotonLatency")
                || col.eq_ignore_ascii_case("msRenderPresentLatency")
            {
                Some(idx)
            } else {
                None
            }
        })
        .collect();
    if pc_latency_indices.is_empty() {
        return None;
    }
    let mut frame_samples = Vec::new();
    let mut pc_latency_samples = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let values = split_csv_line(line);
        if idx_frame >= values.len() {
            continue;
        }
        if let Ok(v) = values[idx_frame].trim().parse::<f64>() {
            if (0.2..=1000.0).contains(&v) {
                frame_samples.push(v);
            }
        }
        for idx_pc_latency in &pc_latency_indices {
            if *idx_pc_latency >= values.len() {
                continue;
            }
            if let Ok(v) = values[*idx_pc_latency].trim().parse::<f64>() {
                if (0.1..=150.0).contains(&v) {
                    pc_latency_samples.push(v);
                    break;
                }
            }
        }
    }
    if frame_samples.is_empty() {
        return None;
    }
    let avg_frame = frame_samples.iter().sum::<f64>() / frame_samples.len() as f64;
    let avg_pc_latency = if pc_latency_samples.is_empty() {
        None
    } else {
        Some(pc_latency_samples.iter().sum::<f64>() / pc_latency_samples.len() as f64)
    };
    if avg_frame <= 0.0 {
        return None;
    }
    let avg_fps = 1000.0 / avg_frame;
    let (stability_score, stutter_count) = stability_from_frame_samples(&frame_samples);
    let fps_1pct_low = percentile_fps_from_frame_samples(&frame_samples, 0.01);
    let fps_0_1pct_low = percentile_fps_from_frame_samples(&frame_samples, 0.001);
    let scene_classification = classify_counter_strike_scene(
        Some(avg_fps),
        Some(avg_frame),
        network_latency_ms,
        system_latency_ms,
    );
    Some(CounterStrikeOptimizationMetrics {
        avg_fps: Some(avg_fps),
        avg_frametime_ms: Some(avg_frame),
        pc_latency_ms: avg_pc_latency,
        network_latency_ms,
        system_latency_ms,
        fps_1pct_low,
        fps_0_1pct_low,
        stutter_count,
        stability_score,
        scene_classification,
    })
}

#[cfg(test)]
fn parse_presentmon_csv_text(text: &str) -> Option<(f64, f64, f64)> {
    let metrics = parse_presentmon_csv_metrics(text, None, None)?;
    Some((
        metrics.avg_fps?,
        metrics.avg_frametime_ms?,
        metrics.pc_latency_ms?,
    ))
}

#[cfg(test)]
fn parse_presentmon_csv(path: &PathBuf) -> Option<(f64, f64, f64)> {
    let text = fs::read_to_string(path).ok()?;
    parse_presentmon_csv_text(&text)
}

fn parse_presentmon_csv_metrics_from_path(
    path: &PathBuf,
    network_latency_ms: Option<f64>,
    system_latency_ms: Option<f64>,
) -> Option<CounterStrikeOptimizationMetrics> {
    let text = fs::read_to_string(path).ok()?;
    parse_presentmon_csv_metrics(&text, network_latency_ms, system_latency_ms)
}

fn run_presentmon_capture_for_metrics(
    presentmon: &Path,
    args: &[String],
    output_csv: &PathBuf,
    network_latency_ms: Option<f64>,
    system_latency_ms: Option<f64>,
    timeout_secs: u64,
) -> Result<CounterStrikeOptimizationMetrics, String> {
    let _ = fs::remove_file(output_csv);
    let mut command = Command::new(presentmon);
    command.args(args.iter().map(|s| s.as_str()));
    command.stdout(Stdio::null()).stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|err| format!("PresentMon failed to launch: {}", err))?;
    let started = SystemTime::now();
    let mut exited = false;

    loop {
        if let Some(metrics) = parse_presentmon_csv_metrics_from_path(
            output_csv,
            network_latency_ms,
            system_latency_ms,
        ) {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(metrics);
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                exited = true;
                if !status.success() {
                    return Err(format!("PresentMon exited with status {}", status));
                }
                break;
            }
            Ok(None) => {}
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("PresentMon wait failed: {}", err));
            }
        }

        let elapsed = started
            .elapsed()
            .map(|d| d.as_secs())
            .unwrap_or(timeout_secs + 1);
        if elapsed >= timeout_secs {
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    if let Some(metrics) =
        parse_presentmon_csv_metrics_from_path(output_csv, network_latency_ms, system_latency_ms)
    {
        return Ok(metrics);
    }

    let csv_state = if output_csv.exists() {
        "CSV parser failed or found no valid CS2 samples"
    } else if exited {
        "PresentMon exited without writing the expected CSV"
    } else {
        "PresentMon timed out before writing a usable CSV"
    };
    Err(csv_state.to_string())
}

fn capture_counter_strike_fps_telemetry(
    network_latency_ms: Option<f64>,
    system_latency_ms: Option<f64>,
    force_refresh: bool,
) -> Option<CounterStrikeFpsTelemetry> {
    let now = chrono_like_timestamp();
    if !force_refresh {
        if let Some(existing) = load_counter_strike_fps_telemetry() {
            if let (Ok(now_secs), Ok(sample_secs)) =
                (now.parse::<u64>(), existing.captured_at.parse::<u64>())
            {
                if now_secs.saturating_sub(sample_secs) <= 90 {
                    let mut diagnostics = default_counter_strike_capture_diagnostics(true);
                    diagnostics.presentmon_found = existing.source.starts_with("presentmon:");
                    diagnostics.presentmon_path = existing
                        .source
                        .strip_prefix("presentmon:")
                        .map(|s| s.to_string());
                    diagnostics.capture_succeeded = true;
                    diagnostics.avg_fps = existing.avg_fps;
                    diagnostics.avg_frametime_ms = existing.avg_frametime_ms;
                    diagnostics.pc_latency_ms = existing.pc_latency_ms;
                    diagnostics.fps_1pct_low = existing.fps_1pct_low;
                    diagnostics.fps_0_1pct_low = existing.fps_0_1pct_low;
                    diagnostics.stutter_count = existing.stutter_count;
                    diagnostics.stability_score = existing.stability_score;
                    diagnostics.scene_classification = if existing.scene_classification.is_empty() {
                        classify_counter_strike_scene(
                            existing.avg_fps,
                            existing.avg_frametime_ms,
                            existing.network_latency_ms,
                            system_latency_ms,
                        )
                    } else {
                        existing.scene_classification.clone()
                    };
                    save_counter_strike_fps_diagnostics(&diagnostics);
                    return Some(existing);
                }
            }
        }
    }

    if CS2_CAPTURE_IN_PROGRESS
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        let mut diagnostics = default_counter_strike_capture_diagnostics(true);
        diagnostics.capture_error = Some(
            "A CS2 FPS capture is already running. Wait for it to finish, then re-test."
                .to_string(),
        );
        save_counter_strike_fps_diagnostics(&diagnostics);
        return load_counter_strike_fps_telemetry();
    }

    let mut diagnostics = default_counter_strike_capture_diagnostics(true);
    let Some(presentmon) = discover_presentmon_binary() else {
        diagnostics.capture_error = Some("PresentMon missing or not discoverable; searched configured Intel/compatibility/PATH locations".to_string());
        save_counter_strike_fps_diagnostics(&diagnostics);
        CS2_CAPTURE_IN_PROGRESS.store(false, Ordering::SeqCst);
        return None;
    };

    diagnostics.presentmon_found = true;
    diagnostics.presentmon_path = Some(presentmon.to_string_lossy().to_string());
    diagnostics.capture_attempted = true;
    let output_csv = aetherframe_data_dir().join("presentmon_cs2_capture.csv");

    let mut captured = None;
    let mut last_error = None;
    let arg_sets = [vec![
        "--session_name".to_string(),
        format!("AetherFrameGuardCS2{}", now),
        "--process_name".to_string(),
        "cs2.exe".to_string(),
        "--timed".to_string(),
        "6".to_string(),
        "--output_file".to_string(),
        output_csv.to_string_lossy().to_string(),
        "--terminate_after_timed".to_string(),
        "--no_console_stats".to_string(),
    ]];

    for args in arg_sets {
        match run_presentmon_capture_for_metrics(
            &presentmon,
            &args,
            &output_csv,
            network_latency_ms,
            system_latency_ms,
            20,
        ) {
            Ok(metrics) => {
                diagnostics.capture_succeeded = true;
                diagnostics.capture_error = None;
                diagnostics.avg_fps = metrics.avg_fps;
                diagnostics.avg_frametime_ms = metrics.avg_frametime_ms;
                diagnostics.pc_latency_ms = metrics.pc_latency_ms;
                diagnostics.fps_1pct_low = metrics.fps_1pct_low;
                diagnostics.fps_0_1pct_low = metrics.fps_0_1pct_low;
                diagnostics.stutter_count = metrics.stutter_count;
                diagnostics.stability_score = metrics.stability_score;
                diagnostics.scene_classification = metrics.scene_classification.clone();
                captured = Some(CounterStrikeFpsTelemetry {
                    captured_at: now.clone(),
                    avg_fps: metrics.avg_fps,
                    avg_frametime_ms: metrics.avg_frametime_ms,
                    pc_latency_ms: metrics.pc_latency_ms,
                    network_latency_ms,
                    fps_1pct_low: metrics.fps_1pct_low,
                    fps_0_1pct_low: metrics.fps_0_1pct_low,
                    stutter_count: metrics.stutter_count,
                    stability_score: metrics.stability_score,
                    scene_classification: metrics.scene_classification,
                    source: format!("presentmon:{}", presentmon.to_string_lossy()),
                });
                break;
            }
            Err(err) => {
                last_error = Some(err);
            }
        }
    }

    let result = if let Some(sample) = captured {
        save_counter_strike_fps_telemetry(&sample);
        save_counter_strike_fps_diagnostics(&diagnostics);
        Some(sample)
    } else {
        diagnostics.capture_error =
            last_error.or_else(|| Some("PresentMon capture failed".to_string()));
        save_counter_strike_fps_diagnostics(&diagnostics);
        None
    };
    CS2_CAPTURE_IN_PROGRESS.store(false, Ordering::SeqCst);
    result
}

fn discover_nvidia_artifacts() -> (Option<PathBuf>, Option<PathBuf>, Option<PathBuf>) {
    let dir = PathBuf::from(NVIDIA_TOOLS_DIR);
    if !dir.exists() {
        return (None, None, None);
    }
    let cli = find_first_existing_file(&dir, NVIDIA_CLI_NAMES);
    let gui = find_first_existing_file(&dir, NVIDIA_GUI_NAMES);
    let preferred_profile = dir.join(NVIDIA_PROFILE_FILE);
    let profile = if preferred_profile.exists() {
        Some(preferred_profile)
    } else {
        fs::read_dir(&dir).ok().and_then(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.path())
                .find(|path| {
                    path.extension()
                        .map(|ext| ext.to_string_lossy().eq_ignore_ascii_case("nip"))
                        .unwrap_or(false)
                })
        })
    };
    (cli, gui, profile)
}

fn try_apply_nvidia_profile(cli_path: &PathBuf, profile_path: &PathBuf) -> Result<String, String> {
    for args in [
        vec![
            "-silentImport".to_string(),
            profile_path.to_string_lossy().to_string(),
        ],
        vec![
            "-importProfile".to_string(),
            profile_path.to_string_lossy().to_string(),
        ],
        vec![profile_path.to_string_lossy().to_string()],
    ] {
        let status = silent_command(cli_path)
            .args(args.iter().map(|s| s.as_str()))
            .status();
        if let Ok(s) = status {
            if s.success() {
                return Ok(format!(
                    "Applied NVIDIA profile via CLI: {}",
                    profile_path.to_string_lossy()
                ));
            }
        }
    }
    Err("NVIDIA Profile Inspector CLI was found, but no known import argument worked".to_string())
}

fn launch_nvidia_gui(gui_path: &PathBuf) -> Result<String, String> {
    Command::new(gui_path)
        .spawn()
        .map(|_| {
            format!(
                "Opened NVIDIA Profile Inspector UI: {}",
                gui_path.to_string_lossy()
            )
        })
        .map_err(|e| e.to_string())
}

fn counter_strike_steam_userdata_roots() -> Vec<PathBuf> {
    COUNTER_STRIKE_STEAM_USERDATA_DIRS
        .iter()
        .map(PathBuf::from)
        .filter(|path| path.exists())
        .collect()
}

fn counter_strike_steam_account_id(root: &PathBuf) -> String {
    root.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown-account")
        .to_string()
}

fn render_counter_strike_steam_profile(account_id: &str, score: f64) -> String {
    let mut lines = vec![
        format!("// AetherframeGuard managed Counter-Strike profile for {}", account_id),
        format!("// Last observed readiness signal: {:.1}% (not a guaranteed FPS gain)", score),
        "// Safe, reversible CS2 recommendations only. Remove the autoexec hook to stop applying this file.".to_string(),
        "fps_max 0".to_string(),
        "rate 786432".to_string(),
        "cl_showfps 0".to_string(),
        "cl_autohelp 0".to_string(),
        "// Keep telemetry visible enough for after-change testing; external capture uses PresentMon.".to_string(),
        "cl_hud_telemetry_frametime_show 2".to_string(),
        "cl_hud_telemetry_ping_show 2".to_string(),
        "cl_hud_telemetry_net_misdelivery_show 2".to_string(),
        "engine_low_latency_sleep_after_client_tick true".to_string(),
        "cl_disablefreezecam 1".to_string(),
    ];
    lines.push(String::new());
    lines.join("\r\n") + "\r\n"
}

fn sync_counter_strike_steam_profile(
    root: &PathBuf,
    score: f64,
    backup_dir: Option<&Path>,
) -> CounterStrikeSteamAccountSync {
    let account_id = counter_strike_steam_account_id(root);
    let cfg_dir = root.join("730").join("local").join("cfg");
    let autoexec_path = cfg_dir.join("autoexec.cfg");
    let managed_profile_path = cfg_dir.join(COUNTER_STRIKE_STEAM_MANAGED_CFG);
    let mut notes = Vec::new();
    let mut autoexec_hook_present = false;
    let mut managed_profile_written = false;

    if !root.exists() {
        notes.push("Steam userdata root missing".to_string());
        return CounterStrikeSteamAccountSync {
            root_path: root.to_string_lossy().to_string(),
            account_id,
            cfg_dir: cfg_dir.to_string_lossy().to_string(),
            autoexec_path: autoexec_path.to_string_lossy().to_string(),
            managed_profile_path: managed_profile_path.to_string_lossy().to_string(),
            autoexec_hook_present,
            managed_profile_written,
            synced: false,
            notes,
        };
    }

    if let Err(err) = fs::create_dir_all(&cfg_dir) {
        notes.push(format!("Failed to create cfg folder: {}", err));
    } else {
        let account_backup_dir = backup_dir.map(|dir| dir.join(&account_id));
        let managed_profile = render_counter_strike_steam_profile(&account_id, score);
        let existing_profile = fs::read_to_string(&managed_profile_path).ok();
        if existing_profile.as_deref() != Some(managed_profile.as_str()) {
            if let Some(dir) = account_backup_dir.as_deref() {
                if let Err(err) = backup_file_if_exists(&managed_profile_path, dir, &mut notes) {
                    notes.push(format!("Managed profile backup failed: {}", err));
                }
            }
            match fs::write(&managed_profile_path, &managed_profile) {
                Ok(_) => {
                    managed_profile_written = true;
                    notes.push(format!(
                        "Updated managed profile {}",
                        managed_profile_path.to_string_lossy()
                    ));
                }
                Err(err) => notes.push(format!("Failed to write managed profile: {}", err)),
            }
        }

        let hook_line = COUNTER_STRIKE_STEAM_AUTOEXEC_HOOK;
        let existing_autoexec = fs::read_to_string(&autoexec_path).unwrap_or_default();
        autoexec_hook_present = existing_autoexec
            .lines()
            .any(|line| line.trim().eq_ignore_ascii_case(hook_line));
        if !autoexec_hook_present {
            if contains_risky_cs2_config_line(&existing_autoexec) {
                notes.push("Autoexec contains review-worthy lines; AetherFrameGuard will append only its managed hook and will not remove user commands".to_string());
            }
            if let Some(dir) = account_backup_dir.as_deref() {
                if let Err(err) = backup_file_if_exists(&autoexec_path, dir, &mut notes) {
                    notes.push(format!("Autoexec backup failed: {}", err));
                }
            }
            let mut updated_autoexec = existing_autoexec.trim_end().to_string();
            if !updated_autoexec.is_empty() {
                updated_autoexec.push_str("\r\n");
            }
            updated_autoexec.push_str("// AetherframeGuard managed hook\r\n");
            updated_autoexec.push_str(hook_line);
            updated_autoexec.push_str("\r\n");
            match fs::write(&autoexec_path, updated_autoexec) {
                Ok(_) => {
                    autoexec_hook_present = true;
                    notes.push(format!(
                        "Updated autoexec hook {}",
                        autoexec_path.to_string_lossy()
                    ));
                }
                Err(err) => notes.push(format!("Failed to update autoexec: {}", err)),
            }
        }
    }

    let synced = root.exists() && autoexec_hook_present;
    if synced && notes.is_empty() {
        notes.push("Steam Counter-Strike profile already up to date".to_string());
    }

    CounterStrikeSteamAccountSync {
        root_path: root.to_string_lossy().to_string(),
        account_id,
        cfg_dir: cfg_dir.to_string_lossy().to_string(),
        autoexec_path: autoexec_path.to_string_lossy().to_string(),
        managed_profile_path: managed_profile_path.to_string_lossy().to_string(),
        autoexec_hook_present,
        managed_profile_written,
        synced,
        notes,
    }
}

fn sync_counter_strike_steam_profiles_with_backup(
    score: f64,
    backup_dir: Option<&Path>,
) -> CounterStrikeSteamSyncState {
    let roots = counter_strike_steam_userdata_roots();
    let mut state = load_counter_strike_steam_sync_state();
    let mut accounts = Vec::new();
    let mut synced_accounts = 0_u64;

    if roots.is_empty() {
        accounts.push(CounterStrikeSteamAccountSync {
            root_path: String::new(),
            account_id: "steam-userdata".to_string(),
            cfg_dir: String::new(),
            autoexec_path: String::new(),
            managed_profile_path: String::new(),
            autoexec_hook_present: false,
            managed_profile_written: false,
            synced: false,
            notes: vec!["No configured Steam userdata roots were found".to_string()],
        });
    } else {
        for root in roots {
            let account = sync_counter_strike_steam_profile(&root, score, backup_dir);
            if account.synced {
                synced_accounts += 1;
            }
            accounts.push(account);
        }
    }

    state.last_synced_at = Some(chrono_like_timestamp());
    state.total_syncs += 1;
    state.total_accounts = accounts.len() as u64;
    state.synced_accounts = synced_accounts;
    state.last_score = Some(score);
    state.accounts = accounts.clone();
    save_counter_strike_steam_sync_state(&state);
    state
}

fn sync_counter_strike_steam_profiles(score: f64) -> CounterStrikeSteamSyncState {
    sync_counter_strike_steam_profiles_with_backup(score, None)
}

fn sync_counter_strike_steam_profiles_action(score: f64) -> ActionResult {
    let state = sync_counter_strike_steam_profiles(score);
    ActionResult {
        id: "run_counter_strike_steam_sync".to_string(),
        success: state.total_accounts > 0 && state.synced_accounts == state.total_accounts,
        message: if state.total_accounts == 0 {
            "No Steam userdata roots were configured".to_string()
        } else {
            format!(
                "Synced {} of {} Steam Counter-Strike profiles",
                state.synced_accounts, state.total_accounts
            )
        },
    }
}

fn optimize_network_stack() -> Vec<String> {
    let mut applied = Vec::new();
    #[cfg(windows)]
    {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok((key, _)) =
            hklm.create_subkey("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters")
        {
            let _ = key.set_value("TcpNoDelay", &1_u32);
            applied.push("TCP Nagle disabled".to_string());
            let _ = key.set_value("TcpAckFrequency", &1_u32);
            applied.push("TCP ACK frequency immediate".to_string());
            let _ = key.set_value("TCPTimedWaitDelay", &30_u32);
            applied.push("TCP TIME_WAIT reduced".to_string());
            let _ = key.set_value("MaxUserPort", &65534_u32);
            applied.push("Ephemeral port range expanded".to_string());
            let _ = key.set_value("DefaultTTL", &64_u32);
            applied.push("Default TTL set to 64".to_string());
        }
    }
    let _ = run_powershell("Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Enable-NetAdapterRss -ErrorAction SilentlyContinue");
    applied.push("RSS enabled".to_string());
    let _ = silent_command("ipconfig").args(["/flushdns"]).output();
    applied.push("DNS cache flushed".to_string());
    applied
}

fn optimize_system_memory() -> Vec<String> {
    let mut applied = Vec::new();
    #[cfg(windows)]
    {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok((key, _)) = hklm
            .create_subkey("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management")
        {
            let _ = key.set_value("DisablePagingExecutive", &1_u32);
            applied.push("DisablePagingExecutive enabled".to_string());
            let _ = key.set_value("LargeSystemCache", &0_u32);
            applied.push("LargeSystemCache disabled".to_string());
        }
    }
    let _ = run_powershell("Set-Service -Name MMCSS -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service MMCSS -ErrorAction SilentlyContinue");
    applied.push("MMCSS started".to_string());
    applied
}

fn run_nvidia_tuning_cycle_internal(allow_gui_launch: bool) -> ActionResult {
    let mut state = load_nvidia_tuning_state();
    let (cli, gui, profile) = discover_nvidia_artifacts();
    state.cli_path = cli.as_ref().map(|p| p.to_string_lossy().to_string());
    state.gui_path = gui.as_ref().map(|p| p.to_string_lossy().to_string());
    state.profile_path = profile.as_ref().map(|p| p.to_string_lossy().to_string());
    state.tools_path = NVIDIA_TOOLS_DIR.to_string();

    let before_signals = collect_host_signals();
    let before_modules = build_module_collection(&before_signals);
    let mut notes = Vec::new();
    let mut method = "none".to_string();
    let mut success = false;

    if let (Some(cli_path), Some(profile_path)) = (&cli, &profile) {
        match try_apply_nvidia_profile(cli_path, profile_path) {
            Ok(msg) => {
                notes.push(msg);
                method = "cli-profile-import".to_string();
                success = true;
            }
            Err(err) => {
                notes.push(err);
                if allow_gui_launch {
                    if let Some(gui_path) = &gui {
                        if let Ok(msg) = launch_nvidia_gui(gui_path) {
                            notes.push(msg);
                            success = true;
                        }
                    }
                    method = "gui-manual".to_string();
                } else {
                    notes.push(
                        "Skipped NVIDIA Profile Inspector GUI launch in scheduled/background mode"
                            .to_string(),
                    );
                    method = "cli-profile-import-failed-background-skip-gui".to_string();
                }
            }
        }
    } else if let Some(gui_path) = &gui {
        if allow_gui_launch {
            if let Ok(msg) = launch_nvidia_gui(gui_path) {
                notes.push(msg);
                success = true;
            }
            method = "gui-manual".to_string();
        } else {
            notes.push(format!("NVIDIA Profile Inspector GUI found at {}, but scheduled/background mode will not open visible tools", gui_path.to_string_lossy()));
            method = "background-skip-gui".to_string();
        }
    } else {
        notes.push(format!(
            "NVIDIA Profile Inspector not found at {}",
            NVIDIA_TOOLS_DIR
        ));
    }

    let after_signals = collect_host_signals();
    let after_modules = build_module_collection(&after_signals);
    let before_weighted =
        (before_modules.gaming.score * 0.65) + (before_modules.network.score * 0.35);
    let after_weighted = (after_modules.gaming.score * 0.65) + (after_modules.network.score * 0.35);
    let improvement_delta = after_weighted - before_weighted;

    state.total_iterations += 1;
    state.last_delta = Some(improvement_delta);
    if improvement_delta > state.best_delta {
        state.best_delta = improvement_delta;
    }
    state.iterations.push(NvidiaTuningIteration {
        iteration: state.total_iterations,
        timestamp: chrono_like_timestamp(),
        method,
        before_gaming: before_modules.gaming.score,
        after_gaming: after_modules.gaming.score,
        before_network: before_modules.network.score,
        after_network: after_modules.network.score,
        before_latency_ms: before_signals.avg_ping_ms,
        after_latency_ms: after_signals.avg_ping_ms,
        improvement_delta,
        notes: notes.clone(),
    });
    if state.iterations.len() > 40 {
        state.iterations.remove(0);
    }
    save_nvidia_tuning_state(&state);

    let latest_log = format!(
        "AetherframeGuard latest diagnostics\ncategory=nvidia_tuning\ntimestamp={}\niteration={}\nmethod={}\nsuccess={}\nbefore_gaming={:.2}\nafter_gaming={:.2}\nbefore_network={:.2}\nafter_network={:.2}\nbefore_latency_ms={}\nafter_latency_ms={}\nimprovement_delta={:.2}\nnotes={}\n",
        chrono_like_timestamp(),
        state.total_iterations,
        state.iterations.last().map(|it| it.method.as_str()).unwrap_or("none"),
        success,
        before_modules.gaming.score,
        after_modules.gaming.score,
        before_modules.network.score,
        after_modules.network.score,
        before_signals.avg_ping_ms.map(|v| format!("{:.2}", v)).unwrap_or_else(|| "n/a".to_string()),
        after_signals.avg_ping_ms.map(|v| format!("{:.2}", v)).unwrap_or_else(|| "n/a".to_string()),
        improvement_delta,
        if notes.is_empty() { "none".to_string() } else { notes.join(" | ") },
    );

    if let Err(err) = overwrite_latest_diagnostics_log(&latest_log) {
        notes.push(format!("Failed to update latest diagnostics log: {}", err));
    }

    ActionResult {
        id: "run_nvidia_tuning_cycle".to_string(),
        success,
        message: notes.join("; "),
    }
}

fn run_calibration_internal() -> CalibrationResult {
    let _ = fs::create_dir_all(aetherframe_data_dir());
    let signals = collect_host_signals();
    let modules = build_module_collection(&signals);
    let inputs = promotion_inputs_from_signals(&signals);
    let promotion = compute_aetherframe_promotion(inputs, DEFAULT_AETHERFRAME_PROMOTION_CONFIG);
    let network_settings = optimize_network_stack();
    let system_settings = optimize_system_memory();
    let nvidia = run_nvidia_tuning_cycle_internal(false);

    let result = CalibrationResult {
        calibrated_at: chrono_like_timestamp(),
        baseline_promotion: promotion.promoted,
        baseline_latency_ms: signals.avg_ping_ms,
        baseline_security: modules.security.score,
        baseline_network: modules.network.score,
        baseline_performance: modules.performance.score,
        baseline_gaming: modules.gaming.score,
        network_settings_applied: network_settings,
        system_settings_applied: {
            let mut all = system_settings;
            all.push(format!("NVIDIA tuning: {}", nvidia.message));
            all
        },
    };
    save_json(calibration_path(), &result);
    result
}

fn run_boot_cycle_internal() {
    let _ = fs::create_dir_all(aetherframe_data_dir());
    let mut history = load_boot_history();
    let signals = collect_host_signals();
    let modules = build_module_collection(&signals);
    let counter_strike = score_counter_strike(&signals);
    let inputs = promotion_inputs_from_signals(&signals);
    let promotion = compute_aetherframe_promotion(inputs, DEFAULT_AETHERFRAME_PROMOTION_CONFIG);
    push_benchmark_session(build_benchmark_session(
        "boot-before",
        &AnalysisResponse {
            generated_at: chrono_like_timestamp(),
            signals: signals.clone(),
            promotion: promotion.clone(),
            modules: modules.clone(),
            counter_strike: counter_strike.clone(),
            recommendations: Vec::new(),
            actions: Vec::new(),
        },
        vec!["Boot cycle pre-tune snapshot".to_string()],
    ));
    let last_score = history
        .entries
        .last()
        .map(|e| e.promotion_score)
        .unwrap_or(0.0);
    let improvement_delta = promotion.promoted - last_score;

    let mut applied_settings = Vec::new();
    applied_settings.extend(optimize_network_stack());
    applied_settings.extend(optimize_system_memory());

    if load_counter_strike_request().is_some()
        || (counter_strike.active && counter_strike.score < 100.0)
    {
        let steam_sync = sync_counter_strike_steam_profiles(counter_strike.score);
        applied_settings.push(format!(
            "Steam CS profile sync: {} of {} accounts",
            steam_sync.synced_accounts, steam_sync.total_accounts
        ));
        for account in &steam_sync.accounts {
            applied_settings.push(format!(
                "Steam {}: {}",
                account.account_id,
                if account.synced {
                    "synced"
                } else {
                    "needs attention"
                }
            ));
        }
        let (game_changes, _) = apply_system_profile("game");
        applied_settings.extend(game_changes);
        let refreshed = score_counter_strike(&collect_host_signals());
        applied_settings.push(format!(
            "CS FPS readiness after boot tuning: {:.1}%",
            refreshed.score
        ));
        if refreshed.score >= 100.0 {
            clear_counter_strike_request();
        } else {
            let sync_state = load_counter_strike_steam_sync_state();
            save_counter_strike_request(&CounterStrikeOptimizationRequest {
                requested_at: chrono_like_timestamp(),
                last_score: refreshed.score,
                process_names: refreshed.process_names,
                target_score: 100.0,
                steam_userdata_roots: COUNTER_STRIKE_STEAM_USERDATA_DIRS
                    .iter()
                    .map(|path| path.to_string())
                    .collect(),
                last_sync_at: sync_state.last_synced_at,
            });
        }
    }

    let nvidia = run_nvidia_tuning_cycle_internal(false);
    applied_settings.push(format!("NVIDIA tuning: {}", nvidia.message));

    if history.entries.len() >= 2
        && history.entries[history.entries.len() - 1].promotion_score
            <= history.entries[history.entries.len() - 2].promotion_score
    {
        if run_powershell("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue").is_some() {
            applied_settings.push("Adaptive: firewall re-hardened after score regression".to_string());
        }
    }

    history.total_boots_optimized += 1;
    history.best_promotion_ever = history.best_promotion_ever.max(promotion.promoted);
    history.entries.push(BootEntry {
        boot_number: history.total_boots_optimized,
        timestamp: chrono_like_timestamp(),
        promotion_score: promotion.promoted,
        security_score: modules.security.score,
        network_score: modules.network.score,
        performance_score: modules.performance.score,
        gaming_score: modules.gaming.score,
        latency_ms: signals.avg_ping_ms,
        applied_settings,
        improvement_delta,
    });
    if history.entries.len() > 30 {
        history.entries.remove(0);
    }
    save_boot_history(&history);

    let mut boot_log_lines = vec![
        "AetherframeGuard latest diagnostics".to_string(),
        "category=boot_cycle".to_string(),
        format!("timestamp={}", chrono_like_timestamp()),
        format!("boot_number={}", history.total_boots_optimized),
        format!("promotion_before={:.2}", promotion.promoted),
        format!("delta_vs_previous={:.2}", improvement_delta),
        format!("security_score={:.2}", modules.security.score),
        format!("network_score={:.2}", modules.network.score),
        format!("performance_score={:.2}", modules.performance.score),
        format!("gaming_score={:.2}", modules.gaming.score),
        format!(
            "latency_ms={}",
            signals
                .avg_ping_ms
                .map(|v| format!("{:.2}", v))
                .unwrap_or_else(|| "n/a".to_string())
        ),
    ];
    if let Some(last_entry) = history.entries.last() {
        boot_log_lines.push(format!(
            "applied_settings={}",
            if last_entry.applied_settings.is_empty() {
                "none".to_string()
            } else {
                last_entry.applied_settings.join(" | ")
            }
        ));
    }
    if let Err(err) = overwrite_latest_diagnostics_log(&boot_log_lines.join("\n")) {
        eprintln!("failed to write boot diagnostics log: {}", err);
    }

    let after = analyze_host();
    push_benchmark_session(build_benchmark_session(
        "boot-after",
        &after,
        vec!["Boot cycle post-tune snapshot".to_string()],
    ));
}

fn run_auto_cycle_internal() -> ActionResult {
    let rollback_snapshot = capture_profile_snapshot();
    let before = analyze_host();
    let before_session = build_benchmark_session(
        "auto-before",
        &before,
        vec!["Auto-cycle baseline".to_string()],
    );
    push_benchmark_session(before_session.clone());
    let mut notes = optimize_network_stack();
    if load_counter_strike_request().is_some()
        || (before.counter_strike.active && before.counter_strike.score < 100.0)
    {
        let steam_sync = sync_counter_strike_steam_profiles(before.counter_strike.score);
        notes.push(format!(
            "Steam CS profile sync: {} of {} accounts",
            steam_sync.synced_accounts, steam_sync.total_accounts
        ));
        let (game_changes, game_warnings) = apply_system_profile("game");
        notes.extend(game_changes);
        notes.extend(
            game_warnings
                .into_iter()
                .map(|warning| format!("CS tuning warning: {}", warning)),
        );

        let tuned_signals = collect_host_signals();
        let refreshed = score_counter_strike(&tuned_signals);
        notes.push(format!(
            "Counter-Strike readiness after tuning: {:.1}%",
            refreshed.score
        ));
        if refreshed.score >= 100.0 {
            clear_counter_strike_request();
        } else {
            let sync_state = load_counter_strike_steam_sync_state();
            save_counter_strike_request(&CounterStrikeOptimizationRequest {
                requested_at: chrono_like_timestamp(),
                last_score: refreshed.score,
                process_names: refreshed.process_names,
                target_score: 100.0,
                steam_userdata_roots: COUNTER_STRIKE_STEAM_USERDATA_DIRS
                    .iter()
                    .map(|path| path.to_string())
                    .collect(),
                last_sync_at: sync_state.last_synced_at,
            });
        }
    }
    let nvidia = run_nvidia_tuning_cycle_internal(false);
    notes.push(format!("NVIDIA tuning: {}", nvidia.message));
    let security = run_security_scan();
    let after = analyze_host();
    let after_session = build_benchmark_session("auto-after", &after, notes.clone());
    let guardrail_note = evaluate_regression_guardrail(&before_session, &after_session);
    let mut benchmark_state = load_benchmark_state();

    if let Some(note) = guardrail_note.clone() {
        notes.push(format!("Guardrail triggered: {}", note));
        notes.extend(restore_profile_snapshot(&rollback_snapshot));
        benchmark_state.last_guardrail_active = true;
        benchmark_state.last_guardrail_note = Some(note);
    } else {
        benchmark_state.last_guardrail_active = false;
        benchmark_state.last_guardrail_note = None;
    }

    benchmark_state.total_sessions += 1;
    benchmark_state.sessions.push(after_session);
    if benchmark_state.sessions.len() > 120 {
        benchmark_state.sessions.remove(0);
    }
    save_benchmark_state(&benchmark_state);

    let mut state = load_auto_monitor_state();
    state.total_cycles += 1;
    state.last_promotion = Some(after.promotion.promoted);
    state.last_threat_score = Some(security.threat_promotion.promoted);
    state.best_promotion = state.best_promotion.max(after.promotion.promoted);
    state.history.push(AutoCycleRecord {
        cycle_number: state.total_cycles,
        timestamp: chrono_like_timestamp(),
        before_promotion: before.promotion.promoted,
        after_promotion: after.promotion.promoted,
        promotion_delta: after.promotion.promoted - before.promotion.promoted,
        threat_score: security.threat_promotion.promoted,
        total_findings: security.total_findings,
        nvidia_success: nvidia.success,
        notes: notes.clone(),
    });
    if state.history.len() > 48 {
        state.history.remove(0);
    }
    save_auto_monitor_state(&state);

    let latest_cycle = state.history.last();
    let auto_log = format!(
        "AetherframeGuard latest diagnostics\ncategory=auto_cycle\ntimestamp={}\ncycle_number={}\nbefore_promotion={:.2}\nafter_promotion={:.2}\npromotion_delta={:.2}\nthreat_score={:.2}\nfindings={}\nnvidia_success={}\nguardrail_active={}\nguardrail_note={}\nnotes={}\n",
        chrono_like_timestamp(),
        latest_cycle.map(|it| it.cycle_number).unwrap_or(state.total_cycles),
        before.promotion.promoted,
        after.promotion.promoted,
        after.promotion.promoted - before.promotion.promoted,
        security.threat_promotion.promoted,
        security.total_findings,
        nvidia.success,
        benchmark_state.last_guardrail_active,
        benchmark_state.last_guardrail_note.clone().unwrap_or_else(|| "none".to_string()),
        if notes.is_empty() { "none".to_string() } else { notes.join(" | ") },
    );
    if let Err(err) = overwrite_latest_diagnostics_log(&auto_log) {
        eprintln!("failed to write auto-cycle diagnostics log: {}", err);
    }

    ActionResult {
        id: "run_auto_cycle".to_string(),
        success: true,
        message: format!(
            "Auto cycle complete: promotion {:.1}% -> {:.1}%",
            before.promotion.promoted, after.promotion.promoted
        ),
    }
}

fn install_auto_monitor_task_internal() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let task_cmd = format!("\"{}\" --auto-cycle", exe.to_string_lossy());
    let out = silent_command("schtasks")
        .args([
            "/Create",
            "/TN",
            AUTO_MONITOR_TASK_NAME,
            "/TR",
            &task_cmd,
            "/SC",
            "MINUTE",
            "/MO",
            "5",
            "/RU",
            "SYSTEM",
            "/RL",
            "HIGHEST",
            "/F",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(
            "Auto-monitor task installed (every 5 minutes as SYSTEM, silent background mode)"
                .to_string(),
        )
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn uninstall_auto_monitor_task_internal() -> Result<String, String> {
    let out = silent_command("schtasks")
        .args(["/Delete", "/TN", AUTO_MONITOR_TASK_NAME, "/F"])
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok("Auto-monitor task removed".to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn query_auto_monitor_task() -> (bool, bool) {
    let out = silent_command("schtasks")
        .args(["/Query", "/TN", AUTO_MONITOR_TASK_NAME, "/FO", "LIST"])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout).to_ascii_lowercase();
            (true, text.contains("running"))
        }
        _ => (false, false),
    }
}

fn install_boot_service_internal() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let task_cmd = format!("\"{}\" --boot-optimize", exe.to_string_lossy());
    let out = silent_command("schtasks")
        .args([
            "/Create",
            "/TN",
            BOOT_TASK_NAME,
            "/TR",
            &task_cmd,
            "/SC",
            "ONSTART",
            "/RU",
            "SYSTEM",
            "/RL",
            "HIGHEST",
            "/F",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(format!(
            "Boot service registered. Task '{}' runs as SYSTEM at highest privilege on every boot.",
            BOOT_TASK_NAME
        ))
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn uninstall_boot_service_internal() -> Result<String, String> {
    let out = silent_command("schtasks")
        .args(["/Delete", "/TN", BOOT_TASK_NAME, "/F"])
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok("Boot optimization service removed".to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn query_boot_service() -> (bool, bool) {
    let out = silent_command("schtasks")
        .args(["/Query", "/TN", BOOT_TASK_NAME, "/FO", "LIST"])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout).to_ascii_lowercase();
            (true, text.contains("running"))
        }
        _ => (false, false),
    }
}

fn profile_snapshot_path(profile_id: &str) -> PathBuf {
    env::temp_dir().join(format!("aetherframeguard-{}-snapshot.json", profile_id))
}
fn capture_profile_snapshot() -> ProfileSnapshot {
    ProfileSnapshot {
        active_power_plan: detect_active_power_plan_guid(),
        game_dvr_enabled: read_game_dvr_value("GameDVR_Enabled"),
        app_capture_enabled: read_game_dvr_value("AppCaptureEnabled"),
        remote_desktop_enabled: Some(detect_remote_desktop_enabled()),
    }
}
fn detect_active_power_plan_guid() -> Option<String> {
    let output = silent_command("powercfg")
        .args(["/getactivescheme"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let start = text.find('{')?;
    let rest = &text[start..];
    let end = rest.find('}')?;
    Some(rest[..=end].to_string())
}
fn read_game_dvr_value(name: &str) -> Option<u32> {
    #[cfg(windows)]
    {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        for path in [
            "System\\GameConfigStore",
            "Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR",
        ] {
            if let Ok(key) = hkcu.open_subkey(path) {
                if let Ok(value) = key.get_value::<u32, _>(name) {
                    return Some(value);
                }
            }
        }
    }
    None
}
fn write_game_dvr_value(name: &str, value: u32) -> Result<(), String> {
    #[cfg(windows)]
    {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        for path in [
            "System\\GameConfigStore",
            "Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR",
        ] {
            let (key, _) = hkcu.create_subkey(path).map_err(|e| e.to_string())?;
            key.set_value(name, &value).map_err(|e| e.to_string())?;
        }
        return Ok(());
    }
    #[cfg(not(windows))]
    {
        let _ = (name, value);
        Ok(())
    }
}
fn set_active_power_plan(alias: &str) -> Result<String, String> {
    run_command("powercfg", &["/setactive", alias])
}
fn enforce_chris_titus_power_plan() -> Result<String, String> {
    if let Some(guid) = detect_chris_titus_power_plan_guid() {
        return set_active_power_plan(&guid)
            .map(|_| format!("Kept Chris Titus power plan active ({})", guid));
    }
    Err("Chris Titus power plan was not found. Import/activate it once, then rerun AetherframeGuard.".to_string())
}
fn set_remote_desktop_enabled(enabled: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let (key, _) = hklm
            .create_subkey("SYSTEM\\CurrentControlSet\\Control\\Terminal Server")
            .map_err(|e| e.to_string())?;
        let deny_connections = if enabled { 0_u32 } else { 1_u32 };
        key.set_value("fDenyTSConnections", &deny_connections)
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    #[cfg(not(windows))]
    {
        let _ = enabled;
        Ok(())
    }
}

fn apply_system_profile(profile_id: &str) -> (Vec<String>, Vec<String>) {
    let mut applied_changes = Vec::new();
    let mut warnings = Vec::new();

    let power_result = match profile_id {
        "game" | "work" | "hardened" => enforce_chris_titus_power_plan(),
        _ => Err(format!("Unknown profile: {}", profile_id)),
    };

    match power_result {
        Ok(message) => applied_changes.push(message),
        Err(err) => warnings.push(err),
    }

    match profile_id {
        "game" => {
            if let Err(err) = write_game_dvr_value("GameDVR_Enabled", 0) {
                warnings.push(err);
            } else {
                applied_changes.push("Disabled Game DVR background capture".to_string());
            }
            if let Err(err) = write_game_dvr_value("AppCaptureEnabled", 0) {
                warnings.push(err);
            } else {
                applied_changes.push("Disabled app capture overlays".to_string());
            }
        }
        "work" => {
            if let Err(err) = write_game_dvr_value("GameDVR_Enabled", 1) {
                warnings.push(err);
            } else {
                applied_changes.push("Restored Game DVR capture defaults".to_string());
            }
            if let Err(err) = write_game_dvr_value("AppCaptureEnabled", 1) {
                warnings.push(err);
            } else {
                applied_changes.push("Restored app capture defaults".to_string());
            }
        }
        "hardened" => {
            if let Err(err) = write_game_dvr_value("GameDVR_Enabled", 0) {
                warnings.push(err);
            } else {
                applied_changes
                    .push("Disabled Game DVR capture for reduced attack surface".to_string());
            }
            if let Err(err) = write_game_dvr_value("AppCaptureEnabled", 0) {
                warnings.push(err);
            } else {
                applied_changes.push("Disabled app capture overlays".to_string());
            }
            if let Err(err) = set_remote_desktop_enabled(false) {
                warnings.push(err);
            } else {
                applied_changes.push("Disabled Remote Desktop connections".to_string());
            }
            if run_powershell("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True")
                .is_some()
            {
                applied_changes.push("Enabled Windows Firewall for all profiles".to_string());
            } else {
                warnings.push("Failed to enable Windows Firewall for all profiles".to_string());
            }
            if run_powershell("Set-MpPreference -DisableRealtimeMonitoring $false").is_some() {
                applied_changes.push("Re-enabled Defender real-time monitoring".to_string());
            } else {
                warnings.push("Failed to re-enable Defender real-time monitoring".to_string());
            }
        }
        _ => {}
    }

    (applied_changes, warnings)
}

fn restore_profile_snapshot(snapshot: &ProfileSnapshot) -> Vec<String> {
    let mut restored = Vec::new();
    if let Some(plan) = &snapshot.active_power_plan {
        if let Err(err) = run_command("powercfg", &["/setactive", plan]) {
            restored.push(err);
        } else {
            restored.push(format!("Restored power plan {}", plan));
        }
    }
    if let Some(value) = snapshot.game_dvr_enabled {
        if let Err(err) = write_game_dvr_value("GameDVR_Enabled", value) {
            restored.push(err);
        } else {
            restored.push("Restored GameDVR_Enabled".to_string());
        }
    }
    if let Some(value) = snapshot.app_capture_enabled {
        if let Err(err) = write_game_dvr_value("AppCaptureEnabled", value) {
            restored.push(err);
        } else {
            restored.push("Restored AppCaptureEnabled".to_string());
        }
    }
    if let Some(enabled) = snapshot.remote_desktop_enabled {
        if let Err(err) = set_remote_desktop_enabled(enabled) {
            restored.push(err);
        } else {
            restored.push(format!("Restored Remote Desktop to {}", enabled));
        }
    }
    restored
}

fn build_profile_delta(before: &AnalysisResponse, after: &AnalysisResponse) -> ProfileDelta {
    ProfileDelta {
        promotion_before: before.promotion.promoted,
        promotion_after: after.promotion.promoted,
        promotion_delta: after.promotion.promoted - before.promotion.promoted,
        security_before: before.modules.security.score,
        security_after: after.modules.security.score,
        security_delta: after.modules.security.score - before.modules.security.score,
        network_before: before.modules.network.score,
        network_after: after.modules.network.score,
        network_delta: after.modules.network.score - before.modules.network.score,
        performance_before: before.modules.performance.score,
        performance_after: after.modules.performance.score,
        performance_delta: after.modules.performance.score - before.modules.performance.score,
        gaming_before: before.modules.gaming.score,
        gaming_after: after.modules.gaming.score,
        gaming_delta: after.modules.gaming.score - before.modules.gaming.score,
    }
}

#[tauri::command]
fn apply_profile(profile_id: String) -> ProfileExecutionResult {
    let profile_name = match profile_id.as_str() {
        "work" => "Work",
        "game" => "Game",
        "hardened" => "Hardened",
        _ => "Unknown",
    }
    .to_string();
    let snapshot = capture_profile_snapshot();
    let snapshot_path = profile_snapshot_path(&profile_id);
    let before = analyze_host();
    let (mut applied_changes, mut warnings) = apply_system_profile(&profile_id);
    if let Ok(snapshot_text) = serde_json::to_string_pretty(&snapshot) {
        if let Err(err) = fs::write(&snapshot_path, snapshot_text) {
            warnings.push(err.to_string());
        } else {
            applied_changes.push(format!(
                "Saved reversible snapshot to {}",
                snapshot_path.display()
            ));
        }
    } else {
        warnings.push("Failed to serialize profile snapshot".to_string());
    }
    let after = analyze_host();
    let delta = build_profile_delta(&before, &after);
    let success = warnings.is_empty();
    let message = if success {
        format!(
            "Applied {} profile and captured before/after measurement",
            profile_name
        )
    } else {
        format!("Applied {} profile with warnings", profile_name)
    };
    ProfileExecutionResult {
        profile_id,
        profile_name,
        success,
        message,
        snapshot_path: snapshot_path.to_string_lossy().to_string(),
        before,
        after,
        delta,
        applied_changes,
        warnings,
    }
}

#[tauri::command]
fn restore_profile(profile_id: String) -> ActionResult {
    let snapshot_path = profile_snapshot_path(&profile_id);
    let snapshot_text = match fs::read_to_string(&snapshot_path) {
        Ok(text) => text,
        Err(err) => {
            return ActionResult {
                id: profile_id,
                success: false,
                message: err.to_string(),
            };
        }
    };
    let snapshot: ProfileSnapshot = match serde_json::from_str(&snapshot_text) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            return ActionResult {
                id: profile_id,
                success: false,
                message: err.to_string(),
            };
        }
    };
    let restored = restore_profile_snapshot(&snapshot);
    ActionResult {
        id: profile_id,
        success: true,
        message: restored.join("; "),
    }
}

fn promotion_inputs_from_signals(signals: &HostSignals) -> AetherframePromotionInputs {
    let strong_signal_count = [
        signals.firewall_enabled,
        signals.defender_realtime_enabled,
        !signals.remote_desktop_enabled,
        signals.high_performance_plan_active,
        signals.ethernet_adapter_active,
        signals.overlay_process_count == 0,
        signals.background_process_count < 180,
    ]
    .into_iter()
    .filter(|f| *f)
    .count() as f64;

    let contradiction_burden = [
        !signals.firewall_enabled,
        !signals.defender_realtime_enabled,
        signals.remote_desktop_enabled,
        !signals.high_performance_plan_active,
        signals.overlay_process_count > 0,
        signals.background_process_count > 240,
        signals.avg_ping_ms.is_some_and(|p| p > 60.0),
    ]
    .into_iter()
    .filter(|f| *f)
    .count() as f64;

    let modules = build_module_collection(signals);
    let module_average = compute_module_average(&modules);
    let base_confidence = clamp(module_average, 0.0, 100.0);
    let bayesian_confidence = clamp(base_confidence + (strong_signal_count * 1.6), 0.0, 100.0);
    let ci_width = clamp(
        0.58 - (strong_signal_count * 0.06) + (contradiction_burden * 0.04),
        0.05,
        0.9,
    );

    AetherframePromotionInputs {
        base_confidence,
        bayesian_confidence,
        ci_width,
        is_uncertain: ci_width > 0.35,
        contradiction_burden,
        strong_signal_count,
    }
}

fn run_command(command: &str, args: &[&str]) -> Result<String, String> {
    let output = silent_command(command)
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

fn open_uri(target: &str) -> Result<String, String> {
    silent_command("cmd")
        .args(["/C", "start", "", target])
        .spawn()
        .map(|_| format!("Launched {}", target))
        .map_err(|e| e.to_string())
}

fn open_command(command: &str, args: &[&str]) -> Result<String, String> {
    silent_command(command)
        .args(args)
        .spawn()
        .map(|_| format!("Launched {}", command))
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn analyze_host() -> AnalysisResponse {
    analyze_host_internal(false)
}

fn analyze_host_internal(force_counter_strike_capture: bool) -> AnalysisResponse {
    let signals = collect_host_signals();
    let modules = build_module_collection(&signals);
    let counter_strike =
        score_counter_strike_with_capture_mode(&signals, force_counter_strike_capture);
    let inputs = promotion_inputs_from_signals(&signals);
    let promotion = compute_aetherframe_promotion(inputs, DEFAULT_AETHERFRAME_PROMOTION_CONFIG);
    let recommendations = build_recommendations(&signals, &modules, &promotion, &counter_strike);
    let actions = build_actions(&signals, &modules);

    if counter_strike.active {
        save_counter_strike_request(&CounterStrikeOptimizationRequest {
            requested_at: chrono_like_timestamp(),
            last_score: counter_strike.score,
            process_names: counter_strike.process_names.clone(),
            target_score: 100.0,
            steam_userdata_roots: COUNTER_STRIKE_STEAM_USERDATA_DIRS
                .iter()
                .map(|path| path.to_string())
                .collect(),
            last_sync_at: load_counter_strike_steam_sync_state().last_synced_at,
        });
    }

    AnalysisResponse {
        generated_at: chrono_like_timestamp(),
        signals,
        promotion,
        modules,
        counter_strike,
        recommendations,
        actions,
    }
}

#[tauri::command]
fn perform_action(action_id: String) -> ActionResult {
    if !validate_action_id(&action_id) {
        return ActionResult {
            id: action_id,
            success: false,
            message: "Unknown action ID".to_string(),
        };
    }

    let result = match action_id.as_str() {
        "open_security_center" => open_uri("windowsdefender:"),
        "open_firewall" => open_command("control.exe", &["/name", "Microsoft.WindowsFirewall"]),
        "open_power_settings" => open_uri("ms-settings:powersleep"),
        "open_startup_apps" => open_uri("ms-settings:startupapps"),
        "open_network_status" => open_uri("ms-settings:network-status"),
        "open_task_manager" => open_command("taskmgr.exe", &[]),
        "open_game_bar_settings" => open_uri("ms-settings:gaming-gamedvr"),
        "open_game_mode_settings" => open_uri("ms-settings:gaming-gamemode"),
        "flush_dns" => run_command("ipconfig", &["/flushdns"]),
        _ => Err(format!("Unknown action: {}", action_id)),
    };

    match result {
        Ok(message) => ActionResult {
            id: action_id,
            success: true,
            message,
        },
        Err(message) => ActionResult {
            id: action_id,
            success: false,
            message,
        },
    }
}

#[tauri::command]
fn install_boot_service() -> ActionResult {
    match install_boot_service_internal() {
        Ok(msg) => ActionResult {
            id: "install_boot_service".to_string(),
            success: true,
            message: msg,
        },
        Err(err) => ActionResult {
            id: "install_boot_service".to_string(),
            success: false,
            message: err,
        },
    }
}

#[tauri::command]
fn uninstall_boot_service() -> ActionResult {
    match uninstall_boot_service_internal() {
        Ok(msg) => ActionResult {
            id: "uninstall_boot_service".to_string(),
            success: true,
            message: msg,
        },
        Err(err) => ActionResult {
            id: "uninstall_boot_service".to_string(),
            success: false,
            message: err,
        },
    }
}

#[tauri::command]
fn get_system_integration_status() -> SystemIntegrationStatus {
    let (installed, running) = query_boot_service();
    let history = load_boot_history();
    SystemIntegrationStatus {
        boot_service_installed: installed,
        boot_service_running: running,
        total_boots_optimized: history.total_boots_optimized,
        best_promotion_ever: history.best_promotion_ever,
        last_boot_promotion: history.entries.last().map(|e| e.promotion_score),
        calibrated: calibration_path().exists(),
        service_task_name: BOOT_TASK_NAME.to_string(),
    }
}

#[tauri::command]
fn run_calibration() -> CalibrationResult {
    run_calibration_internal()
}

#[tauri::command]
fn get_boot_history() -> BootHistory {
    load_boot_history()
}

#[tauri::command]
fn run_network_optimization() -> ActionResult {
    ActionResult {
        id: "run_network_optimization".to_string(),
        success: true,
        message: optimize_network_stack().join("; "),
    }
}

#[tauri::command]
fn run_nvidia_tuning_cycle() -> ActionResult {
    run_nvidia_tuning_cycle_internal(true)
}

#[tauri::command]
fn get_nvidia_tuning_status() -> NvidiaTuningStatus {
    let mut state = load_nvidia_tuning_state();
    let (cli, gui, profile) = discover_nvidia_artifacts();
    state.cli_path = cli.as_ref().map(|p| p.to_string_lossy().to_string());
    state.gui_path = gui.as_ref().map(|p| p.to_string_lossy().to_string());
    state.profile_path = profile.as_ref().map(|p| p.to_string_lossy().to_string());
    state.tools_path = NVIDIA_TOOLS_DIR.to_string();
    save_nvidia_tuning_state(&state);

    let last_notes = state
        .iterations
        .last()
        .map(|it| it.notes.clone())
        .unwrap_or_default();
    NvidiaTuningStatus {
        tools_path: state.tools_path,
        found: state.cli_path.is_some() || state.gui_path.is_some(),
        cli_found: state.cli_path.is_some(),
        gui_found: state.gui_path.is_some(),
        profile_found: state.profile_path.is_some(),
        total_iterations: state.total_iterations,
        best_delta: state.best_delta,
        last_delta: state.last_delta,
        last_notes,
    }
}

#[tauri::command]
fn get_safe_multi_instance_processes() -> Vec<String> {
    let mut list: Vec<String> = load_user_safe_multi_instance_whitelist()
        .into_iter()
        .collect();
    list.sort();
    list
}

#[tauri::command]
fn add_safe_multi_instance_process(process_name: String) -> ActionResult {
    let normalized = normalize_process_name(&process_name);
    if !validate_whitelist_process_name(&normalized) {
        return ActionResult {
            id: "add_safe_multi_instance_process".to_string(),
            success: false,
            message: "Invalid process name. Use only letters, numbers, dot, underscore, and dash."
                .to_string(),
        };
    }
    let mut current = load_user_safe_multi_instance_whitelist();
    current.insert(normalized.clone());
    match save_user_safe_multi_instance_whitelist(&current) {
        Ok(_) => ActionResult {
            id: "add_safe_multi_instance_process".to_string(),
            success: true,
            message: format!("Added '{}' to safe multi-instance whitelist", normalized),
        },
        Err(err) => ActionResult {
            id: "add_safe_multi_instance_process".to_string(),
            success: false,
            message: err,
        },
    }
}

#[tauri::command]
fn remove_safe_multi_instance_process(process_name: String) -> ActionResult {
    let normalized = normalize_process_name(&process_name);
    let mut current = load_user_safe_multi_instance_whitelist();
    current.remove(&normalized);
    match save_user_safe_multi_instance_whitelist(&current) {
        Ok(_) => ActionResult {
            id: "remove_safe_multi_instance_process".to_string(),
            success: true,
            message: format!(
                "Removed '{}' from safe multi-instance whitelist",
                normalized
            ),
        },
        Err(err) => ActionResult {
            id: "remove_safe_multi_instance_process".to_string(),
            success: false,
            message: err,
        },
    }
}

#[tauri::command]
fn install_auto_monitor_task() -> ActionResult {
    match install_auto_monitor_task_internal() {
        Ok(msg) => ActionResult {
            id: "install_auto_monitor_task".to_string(),
            success: true,
            message: msg,
        },
        Err(err) => ActionResult {
            id: "install_auto_monitor_task".to_string(),
            success: false,
            message: err,
        },
    }
}

#[tauri::command]
fn uninstall_auto_monitor_task() -> ActionResult {
    match uninstall_auto_monitor_task_internal() {
        Ok(msg) => ActionResult {
            id: "uninstall_auto_monitor_task".to_string(),
            success: true,
            message: msg,
        },
        Err(err) => ActionResult {
            id: "uninstall_auto_monitor_task".to_string(),
            success: false,
            message: err,
        },
    }
}

#[tauri::command]
fn run_auto_cycle_now() -> ActionResult {
    run_auto_cycle_internal()
}

#[tauri::command]
fn get_auto_monitor_status() -> AutoMonitorStatus {
    let state = load_auto_monitor_state();
    let (installed, running) = query_auto_monitor_task();
    let recent_cycles = state
        .history
        .iter()
        .rev()
        .take(8)
        .cloned()
        .collect::<Vec<_>>();
    AutoMonitorStatus {
        task_installed: installed,
        task_running: running,
        task_name: AUTO_MONITOR_TASK_NAME.to_string(),
        total_cycles: state.total_cycles,
        best_promotion: state.best_promotion,
        last_promotion: state.last_promotion,
        last_threat_score: state.last_threat_score,
        recent_cycles,
    }
}

fn persist_cs2_change_log(result: &SuggestedFpsSettingsResult) {
    save_json(cs2_change_log_path(), result);
}

#[tauri::command]
fn apply_suggested_fps_settings() -> SuggestedFpsSettingsResult {
    let applied_at = chrono_like_timestamp();
    let backup_dir = timestamped_backup_dir("cs2-suggested-settings");
    let before = analyze_host();
    let before_session = build_benchmark_session(
        "suggested-before",
        &before,
        vec!["Before applying suggested CS2 FPS settings".to_string()],
    );
    push_benchmark_session(before_session);

    let mut applied_changes = Vec::new();
    let mut warnings = Vec::new();
    let snapshot = capture_profile_snapshot();
    if let Ok(snapshot_text) = serde_json::to_string_pretty(&snapshot) {
        if let Err(err) = fs::create_dir_all(&backup_dir).and_then(|_| {
            fs::write(
                backup_dir.join("windows_profile_snapshot.json"),
                snapshot_text,
            )
        }) {
            warnings.push(format!("Windows settings snapshot failed: {}", err));
        } else {
            applied_changes.push(format!(
                "Saved Windows settings snapshot in {}",
                redact_sensitive_text(&backup_dir.to_string_lossy())
            ));
        }
    } else {
        warnings.push("Failed to serialize Windows settings snapshot".to_string());
    }

    let steam_sync = sync_counter_strike_steam_profiles_with_backup(
        before.counter_strike.score,
        Some(&backup_dir),
    );
    applied_changes.push(format!(
        "Backed up and synced {} of {} Steam CS2 profile(s)",
        steam_sync.synced_accounts, steam_sync.total_accounts
    ));
    for account in &steam_sync.accounts {
        applied_changes.push(format!(
            "Steam account {}: {}",
            account.account_id,
            if account.synced {
                "managed profile hook ready"
            } else {
                "needs manual review"
            }
        ));
        for note in &account.notes {
            applied_changes.push(redact_sensitive_text(note));
        }
    }
    if steam_sync.total_accounts == 0 || steam_sync.synced_accounts == 0 {
        warnings.push("No writable configured Steam CS2 userdata profile was synced; review the Steam path list or run CS2 once.".to_string());
    }

    let (game_changes, game_warnings) = apply_system_profile("game");
    applied_changes.extend(game_changes);
    warnings.extend(game_warnings);

    let after = analyze_host();
    let after_session = build_benchmark_session(
        "suggested-after",
        &after,
        vec![
            "After applying suggested CS2 FPS settings; restart/relaunch may still be required"
                .to_string(),
        ],
    );
    let guardrail_note = benchmark_status_from_state(&load_benchmark_state())
        .latest
        .as_ref()
        .and_then(|latest| evaluate_regression_guardrail(latest, &after_session));
    if let Some(note) = guardrail_note {
        warnings.push(format!(
            "Measured regression guardrail note: {}; consider Restore Last Profile after review",
            note
        ));
    }
    push_benchmark_session(after_session);

    let status = benchmark_status_from_state(&load_benchmark_state());
    let success =
        warnings.is_empty() || steam_sync.synced_accounts > 0 || !applied_changes.is_empty();
    let message = if success {
        "Suggested FPS settings applied. Relaunch CS2, capture a new benchmark, and compare Baseline / Latest / Best observed before keeping the result.".to_string()
    } else {
        "No safe automatic CS2 FPS setting could be applied. Review warnings and use manual recommendations.".to_string()
    };
    let result = SuggestedFpsSettingsResult {
        applied_at,
        success,
        message,
        backup_dir: redact_sensitive_text(&backup_dir.to_string_lossy()),
        applied_changes,
        warnings,
        cs2_restart_required: true,
        windows_restart_required: false,
        benchmark_status: status,
    };
    persist_cs2_change_log(&result);
    result
}

#[tauri::command]
fn run_counter_strike_steam_sync() -> ActionResult {
    let score = score_counter_strike(&collect_host_signals()).score;
    sync_counter_strike_steam_profiles_action(score)
}

#[tauri::command]
fn get_counter_strike_steam_sync_status() -> CounterStrikeSteamSyncStatus {
    let state = load_counter_strike_steam_sync_state();
    CounterStrikeSteamSyncStatus {
        last_synced_at: state.last_synced_at,
        total_syncs: state.total_syncs,
        total_accounts: state.total_accounts,
        synced_accounts: state.synced_accounts,
        last_score: state.last_score,
        accounts: state.accounts,
    }
}

#[tauri::command]
fn run_benchmark_capture() -> ActionResult {
    let analysis = analyze_host_internal(true);
    let session = build_benchmark_session(
        "manual",
        &analysis,
        vec!["Manual benchmark capture".to_string()],
    );
    push_benchmark_session(session);
    ActionResult {
        id: "run_benchmark_capture".to_string(),
        success: true,
        message: "Re-test complete".to_string(),
    }
}

#[tauri::command]
fn get_benchmark_status() -> BenchmarkStatus {
    let state = load_benchmark_state();
    benchmark_status_from_state(&state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_presentmon_csv_extracts_fps_frametime_and_latency() {
        let path = env::temp_dir().join("aetherframeguard-presentmon-test.csv");
        fs::write(
            &path,
            "Application,msBetweenPresents,msUntilDisplayed\ncs2.exe,5.0,9.5\ncs2.exe,4.0,8.5\n",
        )
        .unwrap();

        let (fps, frametime, latency) = parse_presentmon_csv(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert!((fps - 222.222).abs() < 0.01);
        assert!((frametime - 4.5).abs() < 0.01);
        assert!((latency - 9.0).abs() < 0.01);
    }

    #[test]
    fn cs2_managed_profile_keeps_latency_telemetry_and_low_latency_setting() {
        let profile = render_counter_strike_steam_profile("tester", 73.5);

        assert!(profile.contains("cl_hud_telemetry_frametime_show 2"));
        assert!(profile.contains("cl_hud_telemetry_ping_show 2"));
        assert!(profile.contains("engine_low_latency_sleep_after_client_tick true"));
        assert!(!profile.contains("cl_hud_telemetry 0"));
    }

    #[test]
    fn cs2_affinity_batch_detection_recognizes_launch_intent_without_rewriting() {
        let batch = r#"@echo off
start "" /high "C:\Program Files (x86)\Steam\steam.exe" -applaunch 730 +exec autoexec_optimized.cfg
"#;
        let (uses_steam, uses_high_priority, mentions_autoexec) =
            counter_strike_launch_flags_from_text(batch);

        assert!(uses_steam);
        assert!(uses_high_priority);
        assert!(mentions_autoexec);
        assert_eq!(
            CS2_AFFINITY_LAUNCH_PATH,
            r"C:\Users\Ziel\Desktop\CS2_Affinity.bat"
        );
    }

    #[test]
    fn parses_presentmon_csv_with_latency_columns() {
        let csv =
            "Application,msBetweenPresents,msUntilDisplayed\ncs2.exe,4.0,8.0\ncs2.exe,5.0,10.0\n";
        let (fps, frame, latency) = parse_presentmon_csv_text(csv).expect("valid samples");
        assert!((frame - 4.5).abs() < 0.01);
        assert!((fps - 222.22).abs() < 0.5);
        assert!((latency - 9.0).abs() < 0.01);
    }

    #[test]
    fn parser_rejects_csv_without_valid_samples() {
        let csv = "Application,msBetweenPresents,msUntilDisplayed\ncs2.exe,0,0\n";
        assert!(parse_presentmon_csv_text(csv).is_none());
    }

    #[test]
    fn parser_uses_fallback_presentmon_latency_columns_when_until_displayed_is_na() {
        let csv = "Application,msBetweenPresents,msUntilDisplayed,MsAllInputToPhotonLatency\ncs2.exe,6.0,NA,18.5\ncs2.exe,4.0,NA,21.5\n";
        let (fps, frame, latency) =
            parse_presentmon_csv_text(csv).expect("fallback latency samples");
        assert!((frame - 5.0).abs() < 0.01);
        assert!((fps - 200.0).abs() < 0.5);
        assert!((latency - 20.0).abs() < 0.01);
    }

    #[test]
    fn presentmon_discovery_finds_nested_intel_console_binary() {
        let root = env::temp_dir().join(format!("afg-presentmon-test-{}", chrono_like_timestamp()));
        let nested = root
            .join("Intel")
            .join("PresentMon")
            .join("PresentMonConsoleApplication");
        fs::create_dir_all(&nested).unwrap();
        let exe = nested.join("PresentMon-2.4.1-x64.exe");
        fs::write(&exe, b"test").unwrap();
        let found =
            discover_presentmon_binary_in_dirs(&[root.clone()], false).expect("presentmon found");
        assert_eq!(found, exe);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cs2_not_running_diagnostics_are_explicit() {
        let mut diagnostics = default_counter_strike_capture_diagnostics(false);
        diagnostics.capture_error = Some("CS2 process not running; launch CS2 before requesting live FPS/frametime/latency capture".to_string());
        assert!(!diagnostics.cs2_process_found);
        assert!(!diagnostics.capture_attempted);
        assert!(diagnostics
            .capture_error
            .unwrap()
            .contains("CS2 process not running"));
    }

    #[test]
    fn finding_annotation_formats_severity_evidence_and_recommendation() {
        let finding = annotate_finding(
            ThreatFinding {
                id: "test".to_string(),
                category: "overlay".to_string(),
                title: "Overlay".to_string(),
                description: "desc".to_string(),
                severity: "low".to_string(),
                confidence: 42.0,
                evidence: "obs64.exe".to_string(),
                recommendation: String::new(),
                source: String::new(),
                confirmed: false,
                observed_at: String::new(),
            },
            "unit_test",
            false,
        );
        assert_eq!(finding.severity, "low");
        assert_eq!(finding.source, "unit_test");
        assert!(!finding.confirmed);
        assert!(finding.evidence.contains("observation=advisory signal"));
        assert!(finding.recommendation.contains("overlay"));
    }

    #[test]
    fn sensitive_text_redacts_user_profile_path() {
        std::env::set_var("USERPROFILE", r"C:\Users\Example");
        let redacted = redact_sensitive_text(r"C:\Users\Example\AppData\Local\Temp\tool.exe");
        assert!(redacted.contains("%USERPROFILE%"));
        assert!(!redacted.contains(r"C:\Users\Example"));
    }

    #[test]
    fn risky_cs2_config_line_detector_flags_behavior_changing_lines() {
        assert!(contains_risky_cs2_config_line(
            "alias +jumpthrow +jump;-attack"
        ));
        assert!(contains_risky_cs2_config_line("bind mouse1 +attack"));
        assert!(!contains_risky_cs2_config_line("fps_max 0\nrate 786432"));
    }

    #[test]
    fn cs2_scene_classifier_separates_menu_from_gameplay() {
        assert_eq!(
            classify_counter_strike_scene(Some(480.0), Some(2.1), Some(95.0), Some(0.0)),
            "menu_or_lobby"
        );
        assert_eq!(
            classify_counter_strike_scene(Some(238.0), Some(4.2), Some(31.0), Some(1.4)),
            "gameplay_candidate"
        );
        assert_eq!(
            classify_counter_strike_scene(None, None, None, None),
            "unknown"
        );
    }

    #[test]
    fn cs2_optimizer_prefers_stable_gameplay_lows_over_raw_menu_fps() {
        let menu = CounterStrikeOptimizationMetrics {
            avg_fps: Some(480.0),
            avg_frametime_ms: Some(2.1),
            pc_latency_ms: Some(12.0),
            network_latency_ms: Some(95.0),
            system_latency_ms: Some(4.0),
            fps_1pct_low: Some(180.0),
            fps_0_1pct_low: Some(120.0),
            stutter_count: 18,
            stability_score: 52.0,
            scene_classification: "menu_or_lobby".to_string(),
        };
        let gameplay = CounterStrikeOptimizationMetrics {
            avg_fps: Some(238.0),
            avg_frametime_ms: Some(4.2),
            pc_latency_ms: Some(10.0),
            network_latency_ms: Some(31.0),
            system_latency_ms: Some(1.3),
            fps_1pct_low: Some(205.0),
            fps_0_1pct_low: Some(176.0),
            stutter_count: 1,
            stability_score: 92.0,
            scene_classification: "gameplay_candidate".to_string(),
        };

        assert!(
            cs2_optimization_objective_score(&gameplay) > cs2_optimization_objective_score(&menu)
        );
    }

    #[test]
    fn no_window_flag_helper_is_stable() {
        #[cfg(windows)]
        assert_eq!(windows_no_window_creation_flags(), CREATE_NO_WINDOW);
        #[cfg(not(windows))]
        assert_eq!(windows_no_window_creation_flags(), 0);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--boot-optimize") {
        run_boot_cycle_internal();
        return;
    }
    if args.iter().any(|a| a == "--auto-cycle") {
        let _ = run_auto_cycle_internal();
        return;
    }
    if args.iter().any(|a| a == "--diagnose-cs2") {
        match write_counter_strike_diagnostic_report() {
            Ok(log) => println!("{}", log),
            Err(err) => {
                eprintln!("AetherFrameGuard CS2 diagnostic failed: {}", err);
                std::process::exit(1);
            }
        }
        return;
    }

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            analyze_host,
            perform_action,
            apply_profile,
            restore_profile,
            run_security_scan,
            install_boot_service,
            uninstall_boot_service,
            get_system_integration_status,
            run_calibration,
            get_boot_history,
            run_network_optimization,
            run_nvidia_tuning_cycle,
            get_nvidia_tuning_status,
            get_safe_multi_instance_processes,
            add_safe_multi_instance_process,
            remove_safe_multi_instance_process,
            install_auto_monitor_task,
            uninstall_auto_monitor_task,
            run_auto_cycle_now,
            get_auto_monitor_status,
            apply_suggested_fps_settings,
            run_counter_strike_steam_sync,
            get_counter_strike_steam_sync_status,
            run_benchmark_capture,
            get_benchmark_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running aetherframe-guard");
}
