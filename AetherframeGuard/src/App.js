import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { invoke } from '@tauri-apps/api/core';
import { useState, useEffect } from 'react';
export function App() {
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState(null);
    const [actionState, setActionState] = useState(null);
    const [profileState, setProfileState] = useState(null);
    const [lastProfileId, setLastProfileId] = useState(null);
    const [scanResult, setScanResult] = useState(null);
    const [scanning, setScanning] = useState(false);
    const [integrationStatus, setIntegrationStatus] = useState(null);
    const [bootHistory, setBootHistory] = useState(null);
    const [calibrating, setCalibrating] = useState(false);
    const [calibrationResult, setCalibrationResult] = useState(null);
    const [netOptResult, setNetOptResult] = useState(null);
    const [serviceActionState, setServiceActionState] = useState(null);
    const [nvidiaStatus, setNvidiaStatus] = useState(null);
    const [nvidiaActionState, setNvidiaActionState] = useState(null);
    const [safeProcesses, setSafeProcesses] = useState([]);
    const [autoMonitor, setAutoMonitor] = useState(null);
    const [autoMonitorAction, setAutoMonitorAction] = useState(null);
    const [steamSyncStatus, setSteamSyncStatus] = useState(null);
    const [steamSyncAction, setSteamSyncAction] = useState(null);
    const [benchmarkStatus, setBenchmarkStatus] = useState(null);
    const [benchmarkAction, setBenchmarkAction] = useState(null);
    const [benchmarkBusy, setBenchmarkBusy] = useState(false);
    const [suggestedFpsAction, setSuggestedFpsAction] = useState(null);
    async function runAnalysis() {
        setLoading(true);
        setError(null);
        setActionState(null);
        try {
            const data = await invoke('analyze_host');
            setResult(data);
        }
        catch (err) {
            setError(err instanceof Error ? err.message : String(err));
        }
        finally {
            setLoading(false);
        }
    }
    async function applyProfile(profileId) {
        setLoading(true);
        setError(null);
        setActionState(null);
        try {
            const data = await invoke('apply_profile', { profileId });
            setProfileState(data);
            setResult(data.after);
            setLastProfileId(profileId);
        }
        catch (err) {
            setError(err instanceof Error ? err.message : String(err));
        }
        finally {
            setLoading(false);
        }
    }
    async function restoreLastProfile() {
        if (!lastProfileId) {
            setError('Apply a profile first so there is something to restore.');
            return;
        }
        setLoading(true);
        setError(null);
        try {
            const data = await invoke('restore_profile', { profileId: lastProfileId });
            setActionState(data);
            await runAnalysis();
        }
        catch (err) {
            setError(err instanceof Error ? err.message : String(err));
        }
        finally {
            setLoading(false);
        }
    }
    async function loadIntegrationStatus() {
        try {
            const status = await invoke('get_system_integration_status');
            setIntegrationStatus(status);
            const history = await invoke('get_boot_history');
            setBootHistory(history);
            const nvidia = await invoke('get_nvidia_tuning_status');
            setNvidiaStatus(nvidia);
            const auto = await invoke('get_auto_monitor_status');
            setAutoMonitor(auto);
            const steamSync = await invoke('get_counter_strike_steam_sync_status');
            setSteamSyncStatus(steamSync);
            const bench = await invoke('get_benchmark_status');
            setBenchmarkStatus(bench);
        }
        catch (_) { }
    }
    async function loadSafeProcessWhitelist() {
        try {
            const list = await invoke('get_safe_multi_instance_processes');
            setSafeProcesses(list);
        }
        catch (_) { }
    }
    useEffect(() => {
        loadIntegrationStatus();
        loadSafeProcessWhitelist();
    }, []);
    async function installBootService() {
        setServiceActionState(null);
        const result = await invoke('install_boot_service');
        setServiceActionState(result);
        loadIntegrationStatus();
    }
    async function uninstallBootService() {
        setServiceActionState(null);
        const result = await invoke('uninstall_boot_service');
        setServiceActionState(result);
        loadIntegrationStatus();
    }
    async function runCalibration() {
        setCalibrating(true);
        setServiceActionState(null);
        try {
            const result = await invoke('run_calibration');
            setCalibrationResult(result);
            loadIntegrationStatus();
        }
        catch (err) {
            setServiceActionState({ id: 'calibration', success: false, message: String(err) });
        }
        finally {
            setCalibrating(false);
        }
    }
    async function runNetworkOptimization() {
        setNetOptResult(null);
        try {
            const result = await invoke('run_network_optimization');
            setNetOptResult(result.message);
        }
        catch (err) {
            setNetOptResult(String(err));
        }
    }
    async function runNvidiaTuningCycle() {
        setNvidiaActionState(null);
        try {
            const result = await invoke('run_nvidia_tuning_cycle');
            setNvidiaActionState(result);
            await loadIntegrationStatus();
        }
        catch (err) {
            setNvidiaActionState({
                id: 'run_nvidia_tuning_cycle',
                success: false,
                message: err instanceof Error ? err.message : String(err),
            });
        }
    }
    async function installAutoMonitorTask() {
        const result = await invoke('install_auto_monitor_task');
        setAutoMonitorAction(result);
        await loadIntegrationStatus();
    }
    async function uninstallAutoMonitorTask() {
        const result = await invoke('uninstall_auto_monitor_task');
        setAutoMonitorAction(result);
        await loadIntegrationStatus();
    }
    async function runAutoCycleNow() {
        const result = await invoke('run_auto_cycle_now');
        setAutoMonitorAction(result);
        await loadIntegrationStatus();
    }
    async function runCounterStrikeSteamSync() {
        setSteamSyncAction(null);
        try {
            const result = await invoke('run_counter_strike_steam_sync');
            setSteamSyncAction(result);
            await loadIntegrationStatus();
        }
        catch (err) {
            setSteamSyncAction({
                id: 'run_counter_strike_steam_sync',
                success: false,
                message: err instanceof Error ? err.message : String(err),
            });
        }
    }
    async function applySuggestedFpsSettings() {
        setSuggestedFpsAction(null);
        const confirmed = window.confirm('Apply suggested CS2 FPS settings?\n\nThis will back up CS2 config files and Windows gaming settings, add/refresh the AetherFrameGuard CS2 profile hook, disable Game DVR capture overlays for gaming, and record before/after benchmark snapshots. It will not edit game memory or bypass anti-cheat. Relaunch CS2 before judging FPS.');
        if (!confirmed) {
            return;
        }
        try {
            const result = await invoke('apply_suggested_fps_settings');
            setSuggestedFpsAction(result);
            setBenchmarkStatus(result.benchmarkStatus);
            await loadIntegrationStatus();
            await runAnalysis();
        }
        catch (err) {
            setSuggestedFpsAction({
                appliedAt: '',
                success: false,
                message: err instanceof Error ? err.message : String(err),
                backupDir: '',
                appliedChanges: [],
                detailedSettingChanges: [],
                performanceComparison: {
                    avgFpsDelta: null,
                    fps1pctLowDelta: null,
                    stabilityDelta: null,
                    pcLatencyDelta: null,
                    networkLatencyDelta: null,
                    objectiveScoreDelta: 0,
                    summary: [],
                    bestObservedSummary: 'No benchmark comparison available because the settings action failed.',
                    selectedSettingPolicy: 'Do not keep or treat this failed run as a recommended setting.',
                },
                warnings: [err instanceof Error ? err.message : String(err)],
                cs2RestartRequired: true,
                windowsRestartRequired: false,
                benchmarkStatus: benchmarkStatus ?? {
                    totalSessions: 0,
                    baseline: null,
                    latest: null,
                    best: null,
                    regressionGuardrailActive: false,
                    lastGuardrailNote: null,
                },
            });
        }
    }
    async function runBenchmarkCapture() {
        if (loading || benchmarkBusy || scanning || calibrating)
            return;
        setBenchmarkBusy(true);
        setBenchmarkAction(null);
        try {
            const result = await invoke('run_benchmark_capture');
            setBenchmarkAction(result);
            await loadIntegrationStatus();
            await runAnalysis();
        }
        catch (err) {
            setBenchmarkAction({
                id: 'run_benchmark_capture',
                success: false,
                message: err instanceof Error ? err.message : String(err),
            });
        }
        finally {
            setBenchmarkBusy(false);
        }
    }
    async function runSecurityScan() {
        setScanning(true);
        setError(null);
        try {
            const data = await invoke('run_security_scan');
            setScanResult(data);
        }
        catch (err) {
            setError(err instanceof Error ? err.message : String(err));
        }
        finally {
            setScanning(false);
        }
    }
    function whitelistCandidateFromFinding(finding) {
        if (finding.id.startsWith('proc_dupes_')) {
            return finding.id.slice('proc_dupes_'.length).trim().toLowerCase();
        }
        return null;
    }
    async function addSafeProcess(processName) {
        const result = await invoke('add_safe_multi_instance_process', { processName });
        setActionState(result);
        await loadSafeProcessWhitelist();
        await runSecurityScan();
    }
    async function removeSafeProcess(processName) {
        const result = await invoke('remove_safe_multi_instance_process', { processName });
        setActionState(result);
        await loadSafeProcessWhitelist();
        await runSecurityScan();
    }
    async function triggerAction(actionId) {
        setActionState(null);
        try {
            const data = await invoke('perform_action', { actionId });
            setActionState(data);
        }
        catch (err) {
            setActionState({
                id: actionId,
                success: false,
                message: err instanceof Error ? err.message : String(err),
            });
        }
    }
    function clampScore(value) {
        return Math.max(0, Math.min(100, value));
    }
    function calculateImprovementPercent(current, baseline) {
        if (baseline === null || !Number.isFinite(baseline)) {
            return null;
        }
        const denominator = Math.max(Math.abs(baseline), 1);
        return ((current - baseline) / denominator) * 100;
    }
    function scoreBand(score) {
        if (score < 60) {
            return 'low';
        }
        if (score < 80) {
            return 'mid';
        }
        return 'high';
    }
    function bandColor(band) {
        if (band === 'low') {
            return '#ff6b6b';
        }
        if (band === 'mid') {
            return '#f4b860';
        }
        return '#59e4dc';
    }
    const calibrationBaselines = calibrationResult
        ? {
            security: calibrationResult.baselineSecurity,
            network: calibrationResult.baselineNetwork,
            performance: calibrationResult.baselinePerformance,
            gaming: calibrationResult.baselineGaming,
            promotion: calibrationResult.baselinePromotion,
        }
        : null;
    const moduleOdometers = result
        ? [
            {
                key: 'Security',
                score: result.modules.security.score,
                baseline: calibrationBaselines?.security ?? null,
                subtitle: result.modules.security.signals[0] ?? 'No positive signal yet',
            },
            {
                key: 'Network',
                score: result.modules.network.score,
                baseline: calibrationBaselines?.network ?? null,
                subtitle: result.modules.network.signals[0] ?? 'No positive signal yet',
            },
            {
                key: 'Performance',
                score: result.modules.performance.score,
                baseline: calibrationBaselines?.performance ?? null,
                subtitle: result.modules.performance.signals[0] ?? 'No positive signal yet',
            },
            {
                key: 'Gaming',
                score: result.modules.gaming.score,
                baseline: calibrationBaselines?.gaming ?? null,
                subtitle: result.modules.gaming.signals[0] ?? 'No positive signal yet',
            },
            {
                key: 'CS FPS',
                score: result.counterStrike.score,
                baseline: benchmarkStatus?.baseline?.counterStrikeScore ?? null,
                subtitle: result.counterStrike.signals[0] ?? 'No positive signal yet',
            },
            {
                key: 'AETHERFRAME',
                score: result.promotion.promoted,
                baseline: calibrationBaselines?.promotion ?? null,
                subtitle: `Target ${result.promotion.target.toFixed(1)}%`,
                accent: true,
            },
        ]
        : [];
    const moduleCards = result
        ? [
            { key: 'Security', value: result.modules.security },
            { key: 'Network', value: result.modules.network },
            { key: 'Performance', value: result.modules.performance },
            { key: 'Gaming', value: result.modules.gaming },
            { key: 'CS FPS', value: result.counterStrike },
        ]
        : [];
    const profileCards = [
        { id: 'work', title: 'Work', description: 'Balanced power, restored capture defaults, quieter background state.' },
        { id: 'game', title: 'Game', description: 'High performance power and capture reduction for lower contention.' },
        { id: 'hardened', title: 'Hardened', description: 'Security-biased baseline with firewall, Defender, and RDP hardening.' },
    ];
    const systemActionBusy = loading || scanning || calibrating || benchmarkBusy;
    return (_jsxs("div", { className: "app app-simple", children: [_jsxs("div", { className: "hero panel", children: [_jsxs("div", { children: [_jsx("p", { className: "eyebrow", children: "CS2 FPS helper" }), _jsx("h1", { children: "AetherFrameGuard" }), _jsx("p", { className: "panel-desc simple-lead", children: "Measure live for 20 seconds \u2192 Apply safe settings \u2192 Re-test. Advanced tools are collapsed below." })] }), _jsx("button", { onClick: runAnalysis, disabled: systemActionBusy, children: loading ? 'Measuring…' : 'Measure' })] }), _jsxs("div", { className: "panel simple-flow", children: [_jsxs("div", { className: "panel-header", children: [_jsx("h2", { children: "Main flow" }), _jsx("small", { className: "muted-text", children: "Keep CS2 open and visible while measuring." })] }), _jsxs("div", { className: "action-grid three-step-grid", children: [_jsxs("button", { className: "action-card", onClick: runAnalysis, disabled: systemActionBusy, children: [_jsx("span", { children: "1. Measure" }), _jsx("small", { children: loading ? 'Capturing live data…' : '20 sec live FPS/PC capture' })] }), _jsxs("button", { className: "action-card", onClick: applySuggestedFpsSettings, disabled: systemActionBusy, children: [_jsx("span", { children: "2. Apply safe CS2 settings" }), _jsx("small", { children: "Backs up files first" })] }), _jsxs("button", { className: "action-card", onClick: runBenchmarkCapture, disabled: systemActionBusy, children: [_jsx("span", { children: "3. Re-test" }), _jsx("small", { children: benchmarkBusy ? 'Capturing…' : 'Compare latest vs best' })] })] }), error ? _jsx("p", { className: "failure", children: error }) : null, suggestedFpsAction ? _jsxs("p", { className: suggestedFpsAction.success ? 'success' : 'failure', children: [suggestedFpsAction.message, suggestedFpsAction.cs2RestartRequired ? ' Relaunch CS2 before re-testing.' : ''] }) : null, suggestedFpsAction ? (_jsxs("details", { className: "details-panel inline-details", open: true, children: [_jsx("summary", { children: "What changed and what performance did" }), _jsxs("div", { className: "advanced-section", children: [_jsx("h3", { children: "Settings changed" }), suggestedFpsAction.detailedSettingChanges.length > 0 ? (suggestedFpsAction.detailedSettingChanges.map((change, index) => (_jsxs("div", { className: "boot-entry detail-entry", children: [_jsx("span", { className: "boot-num", children: change.domain }), _jsx("span", { className: "boot-score-pos", children: change.setting }), _jsxs("span", { className: "boot-latency", children: [change.before, " \u2192 ", change.after, change.restartRequired ? ' (restart/relaunch)' : ''] }), _jsx("small", { className: "panel-desc short-note", children: change.evidence })] }, `${change.domain}-${change.setting}-${index}`)))) : _jsx("p", { className: "panel-desc", children: "No structured setting-change details were returned." }), _jsx("h3", { children: "Measured difference" }), suggestedFpsAction.performanceComparison.summary.map((line) => _jsx("p", { className: "panel-desc short-note", children: line }, line)), _jsx("p", { className: "success short-note", children: suggestedFpsAction.performanceComparison.bestObservedSummary }), _jsx("p", { className: "panel-desc short-note", children: suggestedFpsAction.performanceComparison.selectedSettingPolicy }), _jsx("p", { className: "panel-desc short-note", children: "A winning setting is not made permanent blindly. It becomes the recommended setting to keep only after repeated gameplay/practice-map re-tests confirm better FPS, 1% lows, stability, latency, and no guardrail regression." })] })] })) : null, benchmarkAction ? _jsx("p", { className: benchmarkAction.success ? 'success' : 'failure', children: benchmarkAction.message }) : null] }), _jsxs("div", { className: "panel", children: [_jsx("h2", { children: "Status" }), _jsxs("div", { className: "grid compact-grid", children: [_jsxs("div", { className: "metric", children: ["CS2", _jsx("strong", { children: result?.counterStrike.active ? 'Running' : 'Not running' })] }), _jsxs("div", { className: "metric", children: ["FPS", _jsx("strong", { children: result?.counterStrike.avgFps !== null && result?.counterStrike.avgFps !== undefined ? result.counterStrike.avgFps.toFixed(1) : 'n/a' })] }), _jsxs("div", { className: "metric", children: ["1% low", _jsx("strong", { children: result?.counterStrike.telemetryDiagnostics.fps1pctLow !== null && result?.counterStrike.telemetryDiagnostics.fps1pctLow !== undefined ? result.counterStrike.telemetryDiagnostics.fps1pctLow.toFixed(1) : 'n/a' })] }), _jsxs("div", { className: "metric", children: ["Stability", _jsx("strong", { children: result?.counterStrike.telemetryDiagnostics.stabilityScore ? `${result.counterStrike.telemetryDiagnostics.stabilityScore.toFixed(0)}%` : 'n/a' })] }), _jsxs("div", { className: "metric", children: ["Scene", _jsx("strong", { children: result?.counterStrike.telemetryDiagnostics.sceneClassification || 'unknown' })] }), _jsxs("div", { className: "metric", children: ["PresentMon", _jsx("strong", { children: result?.counterStrike.telemetryDiagnostics.presentmonFound ? 'Found' : 'Missing/unknown' })] })] }), result?.counterStrike.telemetryDiagnostics.captureError ? _jsx("p", { className: "failure short-note", children: result.counterStrike.telemetryDiagnostics.captureError }) : null, _jsx("p", { className: "panel-desc log-path", children: "Logs: C:\\ProgramData\\AetherframeGuard" })] }), benchmarkStatus ? (_jsxs("div", { className: "panel", children: [_jsxs("div", { className: "panel-header", children: [_jsx("h2", { children: "Benchmark" }), _jsx("button", { onClick: runBenchmarkCapture, disabled: systemActionBusy, children: benchmarkBusy ? 'Capturing…' : 'Re-test' })] }), ['Baseline', 'Latest', 'Best'].map((label) => {
                        const session = label === 'Baseline' ? benchmarkStatus.baseline : label === 'Latest' ? benchmarkStatus.latest : benchmarkStatus.best;
                        return (_jsxs("div", { className: "boot-entry", children: [_jsx("span", { className: "boot-num", children: label }), _jsx("span", { className: "boot-score-pos", children: session?.avgFps !== null && session?.avgFps !== undefined ? `${session.avgFps.toFixed(1)} FPS` : 'FPS n/a' }), _jsx("span", { className: "boot-latency", children: session ? `${session.confidence.toFixed(0)}% conf · ${session.objectiveScore.toFixed(1)} obj · ${session.stabilityScore.toFixed(0)}% stable · ${session.sceneClassification || 'unknown'}` : '' })] }, label));
                    }), benchmarkStatus.regressionGuardrailActive ? _jsxs("p", { className: "failure", children: ["Guardrail: ", benchmarkStatus.lastGuardrailNote] }) : null] })) : null, _jsxs("details", { className: "panel details-panel", children: [_jsx("summary", { children: "Advanced tools" }), _jsxs("div", { className: "advanced-section", children: [_jsxs("div", { className: "panel-header", children: [_jsx("h3", { children: "Security" }), _jsx("button", { onClick: runSecurityScan, disabled: systemActionBusy, children: scanning ? 'Scanning…' : 'Scan' })] }), scanResult ? _jsx("p", { className: scanResult.clean ? 'success' : 'failure', children: scanResult.clean ? 'No findings.' : `${scanResult.totalFindings} finding(s).` }) : _jsx("p", { className: "panel-desc", children: "Optional local safety scan." }), _jsx("h3", { children: "Profiles" }), _jsxs("div", { className: "chip-row", children: [profileCards.map((profile) => _jsx("button", { onClick: () => applyProfile(profile.id), disabled: systemActionBusy, children: profile.title }, profile.id)), _jsx("button", { onClick: restoreLastProfile, disabled: systemActionBusy || !lastProfileId, children: "Restore last" })] }), _jsx("h3", { children: "System tasks" }), _jsxs("div", { className: "chip-row", children: [_jsx("button", { onClick: installBootService, disabled: systemActionBusy, children: "Install boot task" }), _jsx("button", { onClick: uninstallBootService, disabled: systemActionBusy, children: "Remove boot task" }), _jsx("button", { onClick: runCalibration, disabled: systemActionBusy, children: calibrating ? 'Calibrating…' : 'Calibrate' }), _jsx("button", { onClick: runNetworkOptimization, disabled: systemActionBusy, children: "Network tune" })] }), serviceActionState ? _jsx("p", { className: serviceActionState.success ? 'success' : 'failure', children: serviceActionState.message }) : null, netOptResult ? _jsx("p", { className: "panel-desc", children: netOptResult }) : null, _jsx("h3", { children: "Auto/NVIDIA" }), _jsxs("div", { className: "chip-row", children: [_jsx("button", { onClick: runNvidiaTuningCycle, disabled: systemActionBusy, children: "NVIDIA cycle" }), _jsx("button", { onClick: installAutoMonitorTask, disabled: systemActionBusy, children: "Install auto monitor" }), _jsx("button", { onClick: uninstallAutoMonitorTask, disabled: systemActionBusy, children: "Remove auto monitor" }), _jsx("button", { onClick: runAutoCycleNow, disabled: systemActionBusy, children: "Run auto cycle" }), _jsx("button", { onClick: runCounterStrikeSteamSync, disabled: systemActionBusy, children: "Refresh CS2 hook" })] }), nvidiaActionState ? _jsx("p", { className: nvidiaActionState.success ? 'success' : 'failure', children: nvidiaActionState.message }) : null, autoMonitorAction ? _jsx("p", { className: autoMonitorAction.success ? 'success' : 'failure', children: autoMonitorAction.message }) : null, steamSyncAction ? _jsx("p", { className: steamSyncAction.success ? 'success' : 'failure', children: steamSyncAction.message }) : null] })] }), result ? (_jsxs("details", { className: "panel details-panel", children: [_jsx("summary", { children: "Details" }), _jsxs("div", { className: "grid compact-grid", children: [_jsxs("div", { className: "metric", children: ["Firewall", _jsx("strong", { children: result.signals.firewallEnabled ? 'On' : 'Off' })] }), _jsxs("div", { className: "metric", children: ["Defender", _jsx("strong", { children: result.signals.defenderRealtimeEnabled ? 'On' : 'Off' })] }), _jsxs("div", { className: "metric", children: ["Power", _jsx("strong", { children: result.signals.activePowerPlan })] }), _jsxs("div", { className: "metric", children: ["Ping", _jsxs("strong", { children: [result.signals.avgPingMs ?? 'n/a', " ms"] })] }), _jsxs("div", { className: "metric", children: ["CPU", _jsxs("strong", { children: [result.signals.cpuUsagePercent.toFixed(1), "%"] })] }), _jsxs("div", { className: "metric", children: ["Memory", _jsxs("strong", { children: [result.signals.availableMemoryMb, " MB free"] })] })] }), _jsxs("p", { className: "panel-desc short-note", children: ["Capture path: ", result.counterStrike.telemetryDiagnostics.presentmonPath ?? 'PresentMon not found'] })] })) : null] }));
}
