import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
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
    const systemActionBusy = loading || scanning || calibrating;
    return (_jsxs("div", { className: "app", children: [_jsxs("div", { className: "hero panel", children: [_jsxs("div", { children: [_jsx("p", { className: "eyebrow", children: "Guided CS2 FPS and PC safety helper" }), _jsx("h1", { children: "AetherFrameGuard" }), _jsx("p", { children: "Simple flow: 1) start CS2 first and wait until the menu or a match is visible, 2) click Measure, 3) review the CS2 diagnostics, 4) apply only safe settings if you want them, 5) fully close and relaunch CS2, then 6) measure again. If FPS says n/a, open C:\\ProgramData\\AetherframeGuard\\counter_strike_diagnostics.log. Scores are advisory only; GYRE remains the only HexHawk verdict authority." })] }), _jsx("button", { onClick: runAnalysis, disabled: loading, children: loading ? 'Measuring...' : 'Step 1: Measure Current FPS / PC State' })] }), _jsxs("div", { className: "panel", children: [_jsxs("div", { className: "panel-header", children: [_jsx("h2", { children: "Security Scan" }), _jsx("button", { onClick: runSecurityScan, disabled: scanning || loading, children: scanning ? 'Scanning…' : 'Run Security Scan' })] }), _jsx("p", { className: "panel-desc", children: "Click this when you want a safety check before changing settings. It looks for obvious local risks, overlay/capture tools, suspicious startup entries, and CS2 config lines that deserve review. It does not collect passwords, does not replace antivirus, and does not make final malware verdicts." }), safeProcesses.length > 0 ? (_jsxs("div", { className: "whitelist-strip", children: [_jsx("strong", { children: "Safe Multi-Instance Whitelist" }), _jsx("div", { className: "chip-row", children: safeProcesses.map((name) => (_jsxs("button", { className: "chip-button", onClick: () => removeSafeProcess(name), title: "Remove from whitelist", children: [name, " \u00D7"] }, name))) })] })) : null, scanResult ? (_jsxs(_Fragment, { children: [_jsx("div", { className: `scan-status ${scanResult.clean ? 'scan-clean' : 'scan-threats'}`, children: scanResult.clean
                                    ? 'No local security findings from the current defensive checks.'
                                    : `${scanResult.totalFindings} security finding${scanResult.totalFindings !== 1 ? 's' : ''} detected. Review severity, evidence, and advisory/confirmed status below.` }), _jsxs("div", { className: "grid", children: [_jsxs("div", { className: "metric accent", children: ["AETHERFRAME Advisory Signal", _jsxs("strong", { children: [scanResult.threatPromotion.promoted.toFixed(1), "%"] }), _jsx("small", { children: "Host-defense triage signal only; not a malware verdict or HexHawk authority" })] }), _jsxs("div", { className: `metric ${scanResult.criticalFindings > 0 ? 'sev-critical' : ''}`, children: ["Critical", _jsx("strong", { children: scanResult.criticalFindings })] }), _jsxs("div", { className: `metric ${scanResult.highFindings > 0 ? 'sev-high' : ''}`, children: ["High", _jsx("strong", { children: scanResult.highFindings })] }), _jsxs("div", { className: `metric ${scanResult.mediumFindings > 0 ? 'sev-medium' : ''}`, children: ["Medium", _jsx("strong", { children: scanResult.mediumFindings })] }), _jsxs("div", { className: "metric", children: ["Low", _jsx("strong", { children: scanResult.lowFindings })] })] }), _jsx("div", { style: { marginTop: 14 }, children: scanResult.findings.map(finding => (_jsxs("div", { className: `reco finding-${finding.severity}`, children: [_jsxs("div", { className: "finding-header", children: [_jsx("span", { className: `sev-badge sev-badge-${finding.severity}`, children: finding.severity.toUpperCase() }), _jsx("strong", { children: finding.title }), whitelistCandidateFromFinding(finding) ? (_jsx("button", { className: "mini-button", onClick: () => addSafeProcess(whitelistCandidateFromFinding(finding)), title: "Trust this known app and suppress future replication alerts", children: "Trust App" })) : null] }), _jsx("p", { children: finding.description }), _jsxs("p", { className: "finding-meta", children: ["Category: ", finding.category, " \u00A0|\u00A0 Status: ", finding.confirmed ? 'confirmed local observation' : 'advisory', " \u00A0|\u00A0 Source: ", finding.source, " \u00A0|\u00A0 Observed: ", finding.observedAt, " \u00A0|\u00A0 Confidence: ", finding.confidence.toFixed(1), "%"] }), _jsxs("p", { className: "finding-evidence", children: ["Evidence: ", finding.evidence] }), _jsxs("p", { className: "finding-evidence", children: ["Recommendation: ", finding.recommendation] })] }, finding.id))) })] })) : (_jsx("p", { className: "panel-desc", children: "No scan run yet. Click \u201CRun Security Scan\u201D to analyse processes, network connections, and startup persistence." }))] }), _jsxs("div", { className: "panel", children: [_jsxs("div", { className: "panel-header", children: [_jsx("h2", { children: "System Integration" }), _jsx("button", { onClick: loadIntegrationStatus, disabled: calibrating, children: "Refresh" })] }), _jsx("p", { className: "panel-desc", children: "Optional advanced automation. Start with the simple CS2 button below. Install background tasks only if you understand they run with high Windows privileges and may need Administrator approval. Restart requirements are shown after each action." }), integrationStatus ? (_jsxs("div", { className: "grid", style: { marginBottom: 14 }, children: [_jsxs("div", { className: `metric ${integrationStatus.bootServiceInstalled ? 'metric-ok' : 'metric-warn'}`, children: ["Boot Service", _jsx("strong", { children: integrationStatus.bootServiceInstalled ? 'Installed' : 'Not installed' }), _jsx("small", { children: integrationStatus.serviceTaskName })] }), _jsxs("div", { className: "metric", children: ["Calibrated", _jsx("strong", { children: integrationStatus.calibrated ? 'Yes' : 'No' }), _jsx("small", { children: "Run calibration to baseline and apply optimisations" })] }), _jsxs("div", { className: "metric accent", children: ["Boots Optimised", _jsx("strong", { children: integrationStatus.totalBootsOptimized }), _jsxs("small", { children: ["Best AETHERFRAME: ", integrationStatus.bestPromotionEver.toFixed(1), "%"] })] }), integrationStatus.lastBootPromotion !== null ? (_jsxs("div", { className: "metric", children: ["Last Boot Score", _jsxs("strong", { children: [integrationStatus.lastBootPromotion.toFixed(1), "%"] }), _jsx("small", { children: "Tracked in boot history" })] })) : null] })) : null, _jsxs("div", { className: "reco", style: { marginBottom: 12 }, children: [_jsx("strong", { children: "NVIDIA Profile Inspector Learning Engine" }), _jsxs("p", { children: ["Target tools path: ", nvidiaStatus?.toolsPath ?? 'C:/Users/Ziel/Desktop/Tools/NvidiaInspector', ". On each cycle, AetherframeGuard measures before/after gaming and network module scores, applies NVIDIA tuning by CLI import when available, and stores iterative learning in ProgramData. Scheduled/background cycles do not open the NVIDIA Inspector GUI; use the manual button below when GUI review is needed."] }), nvidiaStatus ? (_jsxs("p", { children: ["Found: ", nvidiaStatus.found ? 'Yes' : 'No', " | CLI: ", nvidiaStatus.cliFound ? 'Yes' : 'No', " | GUI: ", nvidiaStatus.guiFound ? 'Yes' : 'No', " | Profile: ", nvidiaStatus.profileFound ? 'Yes' : 'No', " | Iterations: ", nvidiaStatus.totalIterations, " | Best delta: ", nvidiaStatus.bestDelta.toFixed(2), nvidiaStatus.lastDelta !== null ? ` | Last delta: ${nvidiaStatus.lastDelta.toFixed(2)}` : ''] })) : null, nvidiaStatus?.lastNotes && nvidiaStatus.lastNotes.length > 0 ? (_jsx("p", { className: "finding-evidence", style: { whiteSpace: 'pre-wrap' }, children: nvidiaStatus.lastNotes.join('\n') })) : null, _jsx("button", { onClick: runNvidiaTuningCycle, disabled: systemActionBusy, children: "Run NVIDIA Tuning Cycle" }), nvidiaActionState ? (_jsxs("p", { className: nvidiaActionState.success ? 'success' : 'failure', children: [nvidiaActionState.success ? 'NVIDIA cycle: ' : 'NVIDIA cycle failed: ', nvidiaActionState.message] })) : null] }), _jsxs("div", { className: "reco", style: { marginBottom: 12 }, children: [_jsx("strong", { children: "Step 3: Apply safe CS2 FPS settings" }), _jsx("p", { children: "This is the main beginner-friendly action. It backs up your CS2 config, writes a small managed CS2 profile, disables Windows capture overlays for gaming, records the change, and then asks you to relaunch CS2 and measure again." }), steamSyncStatus ? (_jsxs("p", { children: ["Accounts: ", steamSyncStatus.syncedAccounts, "/", steamSyncStatus.totalAccounts, " synced", ' ', "| Sync runs: ", steamSyncStatus.totalSyncs, steamSyncStatus.lastScore !== null ? ` | Last score: ${steamSyncStatus.lastScore.toFixed(1)}%` : '', steamSyncStatus.lastSyncedAt ? ` | Last sync: ${steamSyncStatus.lastSyncedAt}` : ''] })) : null, _jsxs("div", { className: "chip-row", children: [_jsx("button", { onClick: applySuggestedFpsSettings, disabled: systemActionBusy, children: "Apply Suggested FPS Settings" }), _jsx("button", { onClick: runCounterStrikeSteamSync, disabled: systemActionBusy, children: "Only Refresh CS2 Profile Hook" })] }), _jsx("p", { className: "panel-desc", children: "Applies now: CS2 config hook and Windows capture overlay setting. Requires: relaunch CS2 before judging FPS. Windows restart: not normally required for this button. Manual action: close heavy overlays if the scan reports them." }), suggestedFpsAction ? (_jsxs("div", { className: suggestedFpsAction.success ? 'success' : 'failure', children: [_jsx("p", { children: suggestedFpsAction.message }), suggestedFpsAction.backupDir ? _jsxs("p", { children: ["Backup folder: ", suggestedFpsAction.backupDir] }) : null, _jsxs("p", { children: ["Restart needed: ", suggestedFpsAction.cs2RestartRequired ? 'Relaunch CS2' : 'No CS2 restart', suggestedFpsAction.windowsRestartRequired ? ' + restart Windows' : ''] }), suggestedFpsAction.appliedChanges.length > 0 ? _jsxs("p", { children: ["Changed: ", suggestedFpsAction.appliedChanges.slice(0, 8).join('; ')] }) : null, suggestedFpsAction.warnings.length > 0 ? _jsxs("p", { children: ["Warnings: ", suggestedFpsAction.warnings.join('; ')] }) : null] })) : null, steamSyncAction ? (_jsx("p", { className: steamSyncAction.success ? 'success' : 'failure', children: steamSyncAction.message })) : null, steamSyncStatus?.accounts?.length ? (_jsx("div", { style: { marginTop: 8 }, children: steamSyncStatus.accounts.map((account) => (_jsxs("div", { className: "boot-entry", children: [_jsx("span", { className: "boot-num", children: account.accountId }), _jsx("span", { className: account.synced ? 'boot-score-pos' : 'boot-score-neg', children: account.synced ? 'Synced' : 'Needs attention' }), _jsx("span", { className: "boot-latency", children: account.autoexecHookPresent ? 'Hooked' : 'Hook missing' }), _jsx("span", { className: "boot-settings-count", children: account.managedProfileWritten ? 'Profile updated' : 'Profile unchanged' })] }, account.accountId))) })) : null] }), _jsxs("div", { className: "reco", style: { marginBottom: 12 }, children: [_jsx("strong", { children: "Automatic Monitoring & Setting Changes" }), _jsx("p", { children: "Enable auto-monitor only after you have tested the manual flow. Each cycle re-measures host state, repairs Steam CS userdata profiles, applies supported tuning, runs a security scan, and logs before/after deltas. It aims for the best observed safe state, but cannot guarantee FPS improvement." }), autoMonitor ? (_jsxs("p", { children: ["Task: ", autoMonitor.taskInstalled ? 'Installed' : 'Not installed', autoMonitor.taskInstalled ? ` (${autoMonitor.taskName})` : '', ' ', "| Running: ", autoMonitor.taskRunning ? 'Yes' : 'No', ' ', "| Cycles: ", autoMonitor.totalCycles, ' ', "| Best promotion: ", autoMonitor.bestPromotion.toFixed(1), "%", autoMonitor.lastThreatScore !== null ? ` | Last security signal: ${autoMonitor.lastThreatScore.toFixed(1)}%` : ''] })) : null, _jsx("p", { className: "panel-desc", children: "System-changing action: installing auto-monitor creates/removes a Windows Scheduled Task and running a cycle can write Steam CS profiles, tuning state, diagnostics, and network/NVIDIA optimization results. Use benchmark history and diagnostics to verify any real improvement." }), _jsxs("div", { className: "chip-row", children: [_jsx("button", { onClick: installAutoMonitorTask, disabled: systemActionBusy, children: "Install Auto Monitor" }), _jsx("button", { onClick: uninstallAutoMonitorTask, disabled: systemActionBusy, children: "Remove Auto Monitor" }), _jsx("button", { onClick: runAutoCycleNow, disabled: systemActionBusy, children: "Run Auto Cycle Now" })] }), autoMonitorAction ? (_jsx("p", { className: autoMonitorAction.success ? 'success' : 'failure', children: autoMonitorAction.message })) : null, autoMonitor?.recentCycles?.length ? (_jsx("div", { style: { marginTop: 8 }, children: autoMonitor.recentCycles.slice(0, 4).map((cycle) => (_jsxs("div", { className: "boot-entry", children: [_jsxs("span", { className: "boot-num", children: ["Cycle #", cycle.cycleNumber] }), _jsxs("span", { className: cycle.promotionDelta >= 0 ? 'boot-score-pos' : 'boot-score-neg', children: [cycle.afterPromotion.toFixed(1), "% (", cycle.promotionDelta >= 0 ? '+' : '', cycle.promotionDelta.toFixed(1), ")"] }), _jsxs("span", { className: "boot-latency", children: ["Security signal ", cycle.threatScore.toFixed(1), "%"] }), _jsxs("span", { className: "boot-settings-count", children: [cycle.totalFindings, " findings"] })] }, cycle.cycleNumber))) })) : null] }), _jsxs("div", { className: "reco", style: { marginBottom: 12 }, children: [_jsx("strong", { children: "Step 5: Measure again and compare" }), _jsx("p", { children: "Use this after launching CS2, after applying settings, and after any restart. Compare Baseline, Latest, and Best observed. More samples mean more trustworthy results." }), benchmarkStatus ? (_jsxs("p", { children: ["Sessions: ", benchmarkStatus.totalSessions, ' ', "| Guardrail: ", benchmarkStatus.regressionGuardrailActive ? 'Triggered' : 'Clear', benchmarkStatus.lastGuardrailNote ? ` | Last note: ${benchmarkStatus.lastGuardrailNote}` : ''] })) : null, _jsx("div", { className: "chip-row", children: _jsx("button", { onClick: runBenchmarkCapture, disabled: systemActionBusy, children: "Re-test Now" }) }), benchmarkAction ? (_jsx("p", { className: benchmarkAction.success ? 'success' : 'failure', children: benchmarkAction.message })) : null, benchmarkStatus ? (_jsx("div", { style: { marginTop: 8 }, children: [
                                    { label: 'Baseline', session: benchmarkStatus.baseline },
                                    { label: 'Latest', session: benchmarkStatus.latest },
                                    { label: 'Best', session: benchmarkStatus.best },
                                ].map(({ label, session }) => (_jsxs("div", { className: "boot-entry", children: [_jsx("span", { className: "boot-num", children: label }), _jsx("span", { className: "boot-score-pos", children: session ? `${session.objectiveScore.toFixed(1)} objective` : 'n/a' }), _jsx("span", { className: "boot-latency", children: session?.avgFps !== null && session?.avgFps !== undefined ? `${session.avgFps.toFixed(1)} FPS` : 'FPS n/a' }), _jsx("span", { className: "boot-settings-count", children: session ? `conf ${session.confidence.toFixed(0)}%` : '' })] }, label))) })) : null] }), _jsx("p", { className: "panel-desc", children: "Advanced buttons below can change Windows settings or scheduled tasks. Use the CS2 button first. Verify every change with Re-test Now; the app reports best observed results, not guaranteed gains." }), _jsxs("div", { className: "action-grid", style: { marginBottom: 12 }, children: [_jsxs("button", { className: "action-card", onClick: installBootService, disabled: systemActionBusy, children: [_jsx("span", { children: "Install Boot Service" }), _jsx("small", { children: "SYSTEM-level task, runs every boot. Requires Administrator." })] }), _jsxs("button", { className: "action-card", onClick: uninstallBootService, disabled: systemActionBusy, children: [_jsx("span", { children: "Remove Boot Service" }), _jsx("small", { children: "Deletes the scheduled task. Applied registry settings persist until reverted." })] }), _jsxs("button", { className: "action-card", onClick: runCalibration, disabled: systemActionBusy, children: [_jsx("span", { children: calibrating ? 'Calibrating…' : 'Run Calibration' }), _jsx("small", { children: "Baseline your system and apply all TCP + memory optimisations immediately." })] }), _jsxs("button", { className: "action-card", onClick: runNetworkOptimization, disabled: systemActionBusy, children: [_jsx("span", { children: "Optimise Network Now" }), _jsx("small", { children: "Apply TCP/IP kernel-driver tuning and RSS immediately without reboot." })] })] }), serviceActionState ? (_jsxs("p", { className: serviceActionState.success ? 'success' : 'failure', children: [serviceActionState.success ? '✓ ' : '✗ ', serviceActionState.message] })) : null, netOptResult ? (_jsxs("div", { className: "reco", children: [_jsx("strong", { children: "Network Optimisation Applied" }), _jsx("p", { className: "finding-evidence", style: { whiteSpace: 'pre-wrap' }, children: netOptResult.split('; ').join('\n') })] })) : null, calibrationResult ? (_jsxs("div", { className: "reco", children: [_jsxs("strong", { children: ["Calibration Complete \u2014 Baseline AETHERFRAME: ", calibrationResult.baselinePromotion.toFixed(1), "%"] }), calibrationResult.baselineLatencyMs !== null ? (_jsxs("p", { children: ["Baseline latency: ", calibrationResult.baselineLatencyMs.toFixed(1), " ms"] })) : null, _jsx("p", { children: _jsx("strong", { children: "Network settings applied:" }) }), _jsx("p", { className: "finding-evidence", style: { whiteSpace: 'pre-wrap' }, children: calibrationResult.networkSettingsApplied.join('\n') }), _jsx("p", { children: _jsx("strong", { children: "System settings applied:" }) }), _jsx("p", { className: "finding-evidence", style: { whiteSpace: 'pre-wrap' }, children: calibrationResult.systemSettingsApplied.join('\n') })] })) : null, bootHistory && bootHistory.entries.length > 0 ? (_jsxs("div", { style: { marginTop: 8 }, children: [_jsxs("h3", { style: { margin: '0 0 10px', fontSize: '1rem', color: 'rgba(237,246,255,0.80)' }, children: ["Boot History \u2014 ", bootHistory.totalBootsOptimized, " optimised boots"] }), [...bootHistory.entries].reverse().slice(0, 5).map((entry) => (_jsxs("div", { className: "boot-entry", children: [_jsxs("span", { className: "boot-num", children: ["Boot #", entry.bootNumber] }), _jsxs("span", { className: entry.improvementDelta >= 0 ? 'boot-score-pos' : 'boot-score-neg', children: [entry.promotionScore.toFixed(1), "%", ' ', _jsxs("span", { className: "boot-delta", children: ["(", entry.improvementDelta >= 0 ? '+' : '', entry.improvementDelta.toFixed(1), ")"] })] }), entry.latencyMs !== null ? (_jsxs("span", { className: "boot-latency", children: [entry.latencyMs.toFixed(0), " ms"] })) : null, _jsxs("span", { className: "boot-settings-count", children: [entry.appliedSettings.length, " optimisations"] })] }, entry.bootNumber)))] })) : null] }), _jsxs("div", { className: "panel", children: [_jsx("h2", { children: "Optimization Profiles" }), _jsx("p", { className: "panel-desc", children: "Optional presets. They save a snapshot first so you can restore the last applied profile. Game is for FPS testing, Work restores capture defaults, Hardened favors security." }), _jsx("div", { className: "action-grid", children: profileCards.map((profile) => (_jsxs("button", { className: "action-card", onClick: () => applyProfile(profile.id), disabled: systemActionBusy, title: profile.description, children: [_jsx("span", { children: profile.title }), _jsx("small", { children: profile.description })] }, profile.id))) }), _jsxs("div", { className: "restore-row", children: [_jsx("button", { onClick: restoreLastProfile, disabled: systemActionBusy || !lastProfileId, children: "Restore Last Profile" }), _jsx("small", { children: lastProfileId ? `Last profile: ${lastProfileId}` : 'No profile snapshot saved yet.' })] })] }), _jsxs("div", { className: "panel", children: [error ? _jsxs("p", { className: "failure", children: ["Scan error: ", error] }) : null, actionState ? (_jsxs("p", { className: actionState.success ? 'success' : 'failure', children: [actionState.success ? 'Action complete: ' : 'Action failed: ', actionState.message] })) : null, profileState ? (_jsxs("div", { className: profileState.success ? 'success' : 'failure', children: [_jsx("p", { children: profileState.message }), profileState.warnings.length > 0 ? _jsxs("p", { children: ["Warnings: ", profileState.warnings.join('; ')] }) : null, _jsxs("p", { children: ["Snapshot: ", profileState.snapshotPath] })] })) : null] }), result ? (_jsxs(_Fragment, { children: [_jsxs("div", { className: "panel", children: [_jsx("h2", { children: "Module Scores" }), _jsx("div", { className: "odometer-grid", children: moduleOdometers.map((module) => {
                                    const progress = clampScore(module.score);
                                    const ringDegrees = (progress / 100) * 360;
                                    const delta = calculateImprovementPercent(module.score, module.baseline);
                                    const band = scoreBand(progress);
                                    const ringColor = bandColor(band);
                                    return (_jsxs("div", { className: `odometer-card odometer-card-${band} ${module.accent ? 'odometer-card-accent' : ''}`, children: [_jsxs("div", { className: "odometer-header", children: [_jsx("strong", { children: module.key }), _jsxs("span", { children: [progress.toFixed(1), "%"] })] }), _jsx("div", { className: "odometer-ring", style: {
                                                    background: `conic-gradient(${ringColor} 0deg ${ringDegrees.toFixed(1)}deg, rgba(93, 129, 171, 0.28) ${ringDegrees.toFixed(1)}deg 360deg)`,
                                                }, children: _jsx("div", { className: "odometer-inner", children: _jsx("span", { children: progress.toFixed(1) }) }) }), _jsx("p", { className: "odometer-subtitle", children: module.subtitle }), delta !== null ? (_jsxs("p", { className: `odometer-delta ${delta >= 0 ? 'odometer-delta-pos' : 'odometer-delta-neg'}`, children: ["Improvement ", delta >= 0 ? '+' : '', delta.toFixed(1), "%"] })) : (_jsx("p", { className: "odometer-delta odometer-delta-neutral", children: "Improvement n/a until baseline capture" }))] }, module.key));
                                }) }), !calibrationResult ? (_jsx("p", { className: "panel-desc", style: { marginTop: 10 }, children: "Run calibration once to lock module baselines for exact improvement percentages." })) : null, _jsx("div", { className: "grid", style: { marginTop: 12 }, children: moduleCards.map((module) => (_jsxs("div", { className: "metric", children: [module.key, _jsx("strong", { children: module.value.score.toFixed(1) }), _jsx("small", { children: module.value.signals[0] ?? 'No positive signal yet' })] }, `summary-${module.key}`))) })] }), _jsxs("div", { className: "panel", children: [_jsx("h2", { children: "Host Snapshot" }), _jsxs("div", { className: "grid", children: [_jsxs("div", { className: "metric", children: ["Firewall", _jsx("strong", { children: result.signals.firewallEnabled ? 'On' : 'Off' })] }), _jsxs("div", { className: "metric", children: ["Defender", _jsx("strong", { children: result.signals.defenderRealtimeEnabled ? 'On' : 'Off' })] }), _jsxs("div", { className: "metric", children: ["RDP", _jsx("strong", { children: result.signals.remoteDesktopEnabled ? 'Exposed' : 'Closed' })] }), _jsxs("div", { className: "metric", children: ["Power Plan", _jsx("strong", { children: result.signals.activePowerPlan })] }), _jsxs("div", { className: "metric", children: ["Adapters", _jsx("strong", { children: result.signals.activeNetworkAdapterCount })] }), _jsxs("div", { className: "metric", children: ["Ping", _jsxs("strong", { children: [result.signals.avgPingMs ?? 'n/a', " ms"] })] }), _jsxs("div", { className: "metric", children: ["OS Latency", _jsxs("strong", { children: [result.signals.systemLatencyMs ?? 'n/a', " ms"] })] }), _jsxs("div", { className: "metric", children: ["CPU", _jsxs("strong", { children: [result.signals.cpuUsagePercent.toFixed(1), "%"] })] }), _jsxs("div", { className: "metric", children: ["Memory", _jsxs("strong", { children: [result.signals.availableMemoryMb, " / ", result.signals.totalMemoryMb, " MB"] })] }), _jsxs("div", { className: "metric", children: ["Overlays", _jsx("strong", { children: result.signals.overlayProcessCount })] }), _jsxs("div", { className: "metric", children: ["CS Active", _jsx("strong", { children: result.signals.counterStrikeActive ? 'Yes' : 'No' })] }), _jsxs("div", { className: "metric", children: ["CS Score", _jsxs("strong", { children: [result.counterStrike.score.toFixed(1), "%"] })] }), _jsxs("div", { className: "metric", children: ["CS FPS", _jsx("strong", { children: result.counterStrike.avgFps !== null ? result.counterStrike.avgFps.toFixed(1) : 'n/a' })] }), _jsxs("div", { className: "metric", children: ["CS Frametime", _jsx("strong", { children: result.counterStrike.avgFrametimeMs !== null ? `${result.counterStrike.avgFrametimeMs.toFixed(2)} ms` : 'n/a' })] }), _jsxs("div", { className: "metric", children: ["CS PC Latency", _jsx("strong", { children: result.counterStrike.pcLatencyMs !== null ? `${result.counterStrike.pcLatencyMs.toFixed(2)} ms` : 'n/a' })] }), _jsxs("div", { className: "metric", children: ["CS Net Latency", _jsx("strong", { children: result.counterStrike.networkLatencyMs !== null ? `${result.counterStrike.networkLatencyMs.toFixed(1)} ms` : 'n/a' })] }), _jsxs("div", { className: "metric", children: ["Ethernet", _jsx("strong", { children: result.signals.ethernetAdapterActive ? 'Yes' : 'No' })] }), _jsxs("div", { className: "metric", children: ["Wi-Fi", _jsx("strong", { children: result.signals.wifiAdapterActive ? 'Yes' : 'No' })] })] }), _jsxs("div", { className: "reco", style: { marginTop: 12 }, children: [_jsx("strong", { children: "CS2 Readiness & Telemetry Diagnostics" }), _jsxs("p", { children: ["Preferred launch: ", result.counterStrike.launchStatus.preferredLaunchPath] }), _jsxs("p", { children: ["Launch batch: ", result.counterStrike.launchStatus.exists ? 'found' : 'missing', " | Readable: ", result.counterStrike.launchStatus.readable ? 'yes' : 'no', " | Steam app 730: ", result.counterStrike.launchStatus.usesSteamApplaunch730 ? 'yes' : 'not proven', " | High priority: ", result.counterStrike.launchStatus.usesHighPriority ? 'yes' : 'no'] }), _jsxs("p", { children: ["PresentMon: ", result.counterStrike.telemetryDiagnostics.presentmonFound ? 'found' : 'missing', result.counterStrike.telemetryDiagnostics.presentmonPath ? ` at ${result.counterStrike.telemetryDiagnostics.presentmonPath}` : ''] }), _jsxs("p", { children: ["CS2 process: ", result.counterStrike.telemetryDiagnostics.cs2ProcessFound ? 'running' : 'not running', " | Capture attempted: ", result.counterStrike.telemetryDiagnostics.captureAttempted ? 'yes' : 'no', " | Capture succeeded: ", result.counterStrike.telemetryDiagnostics.captureSucceeded ? 'yes' : 'no'] }), _jsxs("p", { children: ["Last capture time: ", result.counterStrike.lastFpsCaptureAt ?? result.counterStrike.telemetryDiagnostics.capturedAt] }), _jsxs("p", { children: ["Last values: FPS ", result.counterStrike.telemetryDiagnostics.avgFps !== null ? result.counterStrike.telemetryDiagnostics.avgFps.toFixed(1) : 'n/a', " | Frametime ", result.counterStrike.telemetryDiagnostics.avgFrametimeMs !== null ? `${result.counterStrike.telemetryDiagnostics.avgFrametimeMs.toFixed(2)} ms` : 'n/a', " | PC latency ", result.counterStrike.telemetryDiagnostics.pcLatencyMs !== null ? `${result.counterStrike.telemetryDiagnostics.pcLatencyMs.toFixed(2)} ms` : 'n/a'] }), result.counterStrike.telemetryDiagnostics.captureError ? _jsxs("p", { className: "finding-evidence", children: ["Unavailable reason: ", result.counterStrike.telemetryDiagnostics.captureError] }) : null, result.counterStrike.launchStatus.notes.length > 0 ? _jsxs("p", { className: "finding-evidence", children: ["Launch notes: ", result.counterStrike.launchStatus.notes.join(' | ')] }) : null, result.counterStrike.fpsCaptureSource ? _jsxs("p", { className: "panel-desc", children: ["CS telemetry source: ", result.counterStrike.fpsCaptureSource, result.counterStrike.lastFpsCaptureAt ? ` | last capture: ${result.counterStrike.lastFpsCaptureAt}` : ''] }) : null] })] }), _jsxs("div", { className: "panel", children: [_jsx("h2", { children: "Safe Actions" }), _jsx("div", { className: "action-grid", children: result.actions.map((action) => (_jsxs("button", { className: "action-card", onClick: () => triggerAction(action.id), title: action.rationale, children: [_jsx("span", { children: action.title }), _jsxs("small", { children: [action.category, " | ", action.confidence.toFixed(1), "%"] })] }, action.id))) })] }), _jsxs("div", { className: "panel", children: [_jsx("h2", { children: "Ranked Recommendations" }), result.recommendations.length === 0 ? _jsx("p", { children: "No priority actions detected." }) : null, result.recommendations.map((item) => (_jsxs("div", { className: "reco", children: [_jsx("strong", { children: item.title }), _jsx("p", { children: item.rationale }), _jsxs("p", { children: ["Category: ", item.category, " | Risk: ", item.risk, " | Impact: ", item.impact, " | Confidence: ", item.confidence.toFixed(1), "%"] })] }, item.id)))] }), _jsxs("div", { className: "panel", children: [_jsx("h2", { children: "Module Details" }), moduleCards.map((module) => (_jsxs("div", { className: "reco", children: [_jsx("strong", { children: module.key }), _jsxs("p", { children: ["Signals: ", module.value.signals.length > 0 ? module.value.signals.join('; ') : 'None'] }), _jsxs("p", { children: ["Blockers: ", module.value.blockers.length > 0 ? module.value.blockers.join('; ') : 'None'] })] }, module.key)))] }), profileState ? (_jsxs("div", { className: "panel", children: [_jsx("h2", { children: "Before / After Proof" }), _jsxs("div", { className: "grid", children: [_jsxs("div", { className: "metric", children: ["Promotion", _jsxs("strong", { children: [profileState.delta.promotionAfter.toFixed(1), "%"] }), _jsxs("small", { children: [profileState.delta.promotionDelta >= 0 ? '+' : '', profileState.delta.promotionDelta.toFixed(1), " pts"] })] }), _jsxs("div", { className: "metric", children: ["Security", _jsx("strong", { children: profileState.delta.securityAfter.toFixed(1) }), _jsxs("small", { children: [profileState.delta.securityDelta >= 0 ? '+' : '', profileState.delta.securityDelta.toFixed(1), " pts"] })] }), _jsxs("div", { className: "metric", children: ["Network", _jsx("strong", { children: profileState.delta.networkAfter.toFixed(1) }), _jsxs("small", { children: [profileState.delta.networkDelta >= 0 ? '+' : '', profileState.delta.networkDelta.toFixed(1), " pts"] })] }), _jsxs("div", { className: "metric", children: ["Performance", _jsx("strong", { children: profileState.delta.performanceAfter.toFixed(1) }), _jsxs("small", { children: [profileState.delta.performanceDelta >= 0 ? '+' : '', profileState.delta.performanceDelta.toFixed(1), " pts"] })] }), _jsxs("div", { className: "metric", children: ["Gaming", _jsx("strong", { children: profileState.delta.gamingAfter.toFixed(1) }), _jsxs("small", { children: [profileState.delta.gamingDelta >= 0 ? '+' : '', profileState.delta.gamingDelta.toFixed(1), " pts"] })] })] }), _jsxs("div", { className: "reco", children: [_jsx("strong", { children: "Applied Changes" }), _jsx("p", { children: profileState.appliedChanges.length > 0 ? profileState.appliedChanges.join('; ') : 'No changes were applied.' })] })] })) : null] })) : null] }));
}
