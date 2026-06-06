import { invoke } from '@tauri-apps/api/core';
import { useState, useEffect } from 'react';

type HostSignals = {
  firewallEnabled: boolean;
  defenderRealtimeEnabled: boolean;
  remoteDesktopEnabled: boolean;
  activePowerPlan: string;
  highPerformancePlanActive: boolean;
  activeNetworkAdapterCount: number;
  ethernetAdapterActive: boolean;
  wifiAdapterActive: boolean;
  backgroundProcessCount: number;
  overlayProcessCount: number;
  overlayProcessNames: string[];
  counterStrikeProcessNames: string[];
  counterStrikeActive: boolean;
  totalMemoryMb: number;
  availableMemoryMb: number;
  cpuUsagePercent: number;
  avgPingMs: number | null;
  systemLatencyMs: number | null;
};

type PromotionBreakdown = {
  promoted: number;
  target: number;
  uncertaintyPenalty: number;
  contradictionPenalty: number;
  supportBoost: number;
  ciWidth: number;
};

type Recommendation = {
  id: string;
  title: string;
  rationale: string;
  risk: 'low' | 'medium' | 'high';
  impact: 'low' | 'medium' | 'high';
  confidence: number;
  category: 'security' | 'network' | 'performance' | 'gaming';
};

type ModuleSummary = {
  score: number;
  signals: string[];
  blockers: string[];
};

type CounterStrikeCaptureDiagnostics = {
  capturedAt: string;
  presentmonFound: boolean;
  presentmonPath: string | null;
  cs2ProcessFound: boolean;
  captureAttempted: boolean;
  captureSucceeded: boolean;
  captureError: string | null;
  avgFps: number | null;
  avgFrametimeMs: number | null;
  pcLatencyMs: number | null;
  fps1pctLow: number | null;
  fps01pctLow: number | null;
  stutterCount: number;
  stabilityScore: number;
  sceneClassification: string;
};

type CounterStrikeLaunchStatus = {
  preferredLaunchPath: string;
  exists: boolean;
  readable: boolean;
  usesSteamApplaunch730: boolean;
  usesHighPriority: boolean;
  notes: string[];
};

type CounterStrikeSummary = {
  active: boolean;
  processNames: string[];
  score: number;
  signals: string[];
  blockers: string[];
  avgFps: number | null;
  avgFrametimeMs: number | null;
  pcLatencyMs: number | null;
  networkLatencyMs: number | null;
  fpsCaptureSource: string | null;
  lastFpsCaptureAt: string | null;
  fps1pctLow: number | null;
  fps01pctLow: number | null;
  stutterCount: number;
  stabilityScore: number;
  sceneClassification: string;
  telemetryDiagnostics: CounterStrikeCaptureDiagnostics;
  launchStatus: CounterStrikeLaunchStatus;
};

type QuickAction = {
  id: string;
  title: string;
  category: 'security' | 'network' | 'performance' | 'gaming';
  rationale: string;
  confidence: number;
};

type AnalysisResponse = {
  generatedAt: string;
  signals: HostSignals;
  promotion: PromotionBreakdown;
  modules: {
    security: ModuleSummary;
    network: ModuleSummary;
    performance: ModuleSummary;
    gaming: ModuleSummary;
  };
  counterStrike: CounterStrikeSummary;
  recommendations: Recommendation[];
  actions: QuickAction[];
};

type ActionResult = {
  id: string;
  success: boolean;
  message: string;
};

type SettingChangeDetail = {
  domain: string;
  setting: string;
  before: string;
  after: string;
  evidence: string;
  restartRequired: boolean;
};

type PerformanceComparison = {
  avgFpsDelta: number | null;
  fps1pctLowDelta: number | null;
  stabilityDelta: number | null;
  pcLatencyDelta: number | null;
  networkLatencyDelta: number | null;
  objectiveScoreDelta: number;
  summary: string[];
  bestObservedSummary: string;
  selectedSettingPolicy: string;
};

type SuggestedFpsSettingsResult = {
  appliedAt: string;
  success: boolean;
  message: string;
  backupDir: string;
  appliedChanges: string[];
  detailedSettingChanges: SettingChangeDetail[];
  performanceComparison: PerformanceComparison;
  warnings: string[];
  cs2RestartRequired: boolean;
  windowsRestartRequired: boolean;
  benchmarkStatus: BenchmarkStatus;
};

type ThreatFinding = {
  id: string;
  category: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: number;
  evidence: string;
  recommendation: string;
  source: string;
  confirmed: boolean;
  observedAt: string;
};

type SecurityScanResult = {
  scanTime: string;
  totalFindings: number;
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  lowFindings: number;
  findings: ThreatFinding[];
  threatPromotion: PromotionBreakdown;
  clean: boolean;
};

type ProfileDelta = {
  promotionBefore: number;
  promotionAfter: number;
  promotionDelta: number;
  securityBefore: number;
  securityAfter: number;
  securityDelta: number;
  networkBefore: number;
  networkAfter: number;
  networkDelta: number;
  performanceBefore: number;
  performanceAfter: number;
  performanceDelta: number;
  gamingBefore: number;
  gamingAfter: number;
  gamingDelta: number;
};

type ProfileExecutionResult = {
  profileId: string;
  profileName: string;
  success: boolean;
  message: string;
  snapshotPath: string;
  before: AnalysisResponse;
  after: AnalysisResponse;
  delta: ProfileDelta;
  appliedChanges: string[];
  warnings: string[];
};

type BootEntry = {
  bootNumber: number;
  timestamp: string;
  promotionScore: number;
  securityScore: number;
  networkScore: number;
  performanceScore: number;
  gamingScore: number;
  latencyMs: number | null;
  appliedSettings: string[];
  improvementDelta: number;
};

type BootHistory = {
  entries: BootEntry[];
  bestPromotionEver: number;
  totalBootsOptimized: number;
};

type SystemIntegrationStatus = {
  bootServiceInstalled: boolean;
  bootServiceRunning: boolean;
  totalBootsOptimized: number;
  bestPromotionEver: number;
  lastBootPromotion: number | null;
  calibrated: boolean;
  serviceTaskName: string;
};

type CalibrationResult = {
  calibratedAt: string;
  baselinePromotion: number;
  baselineLatencyMs: number | null;
  baselineSecurity: number;
  baselineNetwork: number;
  baselinePerformance: number;
  baselineGaming: number;
  networkSettingsApplied: string[];
  systemSettingsApplied: string[];
};

type NvidiaTuningStatus = {
  toolsPath: string;
  found: boolean;
  cliFound: boolean;
  guiFound: boolean;
  profileFound: boolean;
  totalIterations: number;
  bestDelta: number;
  lastDelta: number | null;
  lastNotes: string[];
};

type AutoCycleRecord = {
  cycleNumber: number;
  timestamp: string;
  beforePromotion: number;
  afterPromotion: number;
  promotionDelta: number;
  threatScore: number;
  totalFindings: number;
  nvidiaSuccess: boolean;
  notes: string[];
};

type AutoMonitorStatus = {
  taskInstalled: boolean;
  taskRunning: boolean;
  taskName: string;
  totalCycles: number;
  bestPromotion: number;
  lastPromotion: number | null;
  lastThreatScore: number | null;
  recentCycles: AutoCycleRecord[];
};

type CounterStrikeSteamAccountSync = {
  rootPath: string;
  accountId: string;
  cfgDir: string;
  autoexecPath: string;
  managedProfilePath: string;
  autoexecHookPresent: boolean;
  managedProfileWritten: boolean;
  synced: boolean;
  notes: string[];
};

type CounterStrikeSteamSyncStatus = {
  lastSyncedAt: string | null;
  totalSyncs: number;
  totalAccounts: number;
  syncedAccounts: number;
  lastScore: number | null;
  accounts: CounterStrikeSteamAccountSync[];
};

type BenchmarkSession = {
  id: string;
  timestamp: string;
  source: string;
  promotionScore: number;
  counterStrikeScore: number;
  avgFps: number | null;
  avgFrametimeMs: number | null;
  pcLatencyMs: number | null;
  networkLatencyMs: number | null;
  systemLatencyMs: number | null;
  fps1pctLow: number | null;
  fps01pctLow: number | null;
  stutterCount: number;
  stabilityScore: number;
  sceneClassification: string;
  confidence: number;
  objectiveScore: number;
  notes: string[];
};

type BenchmarkStatus = {
  totalSessions: number;
  baseline: BenchmarkSession | null;
  latest: BenchmarkSession | null;
  best: BenchmarkSession | null;
  regressionGuardrailActive: boolean;
  lastGuardrailNote: string | null;
};

export function App() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionState, setActionState] = useState<ActionResult | null>(null);
  const [profileState, setProfileState] = useState<ProfileExecutionResult | null>(null);
  const [lastProfileId, setLastProfileId] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<SecurityScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [integrationStatus, setIntegrationStatus] = useState<SystemIntegrationStatus | null>(null);
  const [bootHistory, setBootHistory] = useState<BootHistory | null>(null);
  const [calibrating, setCalibrating] = useState(false);
  const [calibrationResult, setCalibrationResult] = useState<CalibrationResult | null>(null);
  const [netOptResult, setNetOptResult] = useState<string | null>(null);
  const [serviceActionState, setServiceActionState] = useState<ActionResult | null>(null);
  const [nvidiaStatus, setNvidiaStatus] = useState<NvidiaTuningStatus | null>(null);
  const [nvidiaActionState, setNvidiaActionState] = useState<ActionResult | null>(null);
  const [safeProcesses, setSafeProcesses] = useState<string[]>([]);
  const [autoMonitor, setAutoMonitor] = useState<AutoMonitorStatus | null>(null);
  const [autoMonitorAction, setAutoMonitorAction] = useState<ActionResult | null>(null);
  const [steamSyncStatus, setSteamSyncStatus] = useState<CounterStrikeSteamSyncStatus | null>(null);
  const [steamSyncAction, setSteamSyncAction] = useState<ActionResult | null>(null);
  const [benchmarkStatus, setBenchmarkStatus] = useState<BenchmarkStatus | null>(null);
  const [benchmarkAction, setBenchmarkAction] = useState<ActionResult | null>(null);
  const [benchmarkBusy, setBenchmarkBusy] = useState(false);
  const [suggestedFpsAction, setSuggestedFpsAction] = useState<SuggestedFpsSettingsResult | null>(null);

  async function runAnalysis() {
    setLoading(true);
    setError(null);
    setActionState(null);
    try {
      const data = await invoke<AnalysisResponse>('analyze_host');
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  async function applyProfile(profileId: string) {
    setLoading(true);
    setError(null);
    setActionState(null);
    try {
      const data = await invoke<ProfileExecutionResult>('apply_profile', { profileId });
      setProfileState(data);
      setResult(data.after);
      setLastProfileId(profileId);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
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
      const data = await invoke<ActionResult>('restore_profile', { profileId: lastProfileId });
      setActionState(data);
      await runAnalysis();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  async function loadIntegrationStatus() {
    try {
      const status = await invoke<SystemIntegrationStatus>('get_system_integration_status');
      setIntegrationStatus(status);
      const history = await invoke<BootHistory>('get_boot_history');
      setBootHistory(history);
      const nvidia = await invoke<NvidiaTuningStatus>('get_nvidia_tuning_status');
      setNvidiaStatus(nvidia);
      const auto = await invoke<AutoMonitorStatus>('get_auto_monitor_status');
      setAutoMonitor(auto);
      const steamSync = await invoke<CounterStrikeSteamSyncStatus>('get_counter_strike_steam_sync_status');
      setSteamSyncStatus(steamSync);
      const bench = await invoke<BenchmarkStatus>('get_benchmark_status');
      setBenchmarkStatus(bench);
    } catch (_) {}
  }

  async function loadSafeProcessWhitelist() {
    try {
      const list = await invoke<string[]>('get_safe_multi_instance_processes');
      setSafeProcesses(list);
    } catch (_) {}
  }

  useEffect(() => {
    loadIntegrationStatus();
    loadSafeProcessWhitelist();
  }, []);

  async function installBootService() {
    setServiceActionState(null);
    const result = await invoke<ActionResult>('install_boot_service');
    setServiceActionState(result);
    loadIntegrationStatus();
  }

  async function uninstallBootService() {
    setServiceActionState(null);
    const result = await invoke<ActionResult>('uninstall_boot_service');
    setServiceActionState(result);
    loadIntegrationStatus();
  }

  async function runCalibration() {
    setCalibrating(true);
    setServiceActionState(null);
    try {
      const result = await invoke<CalibrationResult>('run_calibration');
      setCalibrationResult(result);
      loadIntegrationStatus();
    } catch (err) {
      setServiceActionState({ id: 'calibration', success: false, message: String(err) });
    } finally {
      setCalibrating(false);
    }
  }

  async function runNetworkOptimization() {
    setNetOptResult(null);
    try {
      const result = await invoke<ActionResult>('run_network_optimization');
      setNetOptResult(result.message);
    } catch (err) {
      setNetOptResult(String(err));
    }
  }

  async function runNvidiaTuningCycle() {
    setNvidiaActionState(null);
    try {
      const result = await invoke<ActionResult>('run_nvidia_tuning_cycle');
      setNvidiaActionState(result);
      await loadIntegrationStatus();
    } catch (err) {
      setNvidiaActionState({
        id: 'run_nvidia_tuning_cycle',
        success: false,
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }

  async function installAutoMonitorTask() {
    const result = await invoke<ActionResult>('install_auto_monitor_task');
    setAutoMonitorAction(result);
    await loadIntegrationStatus();
  }

  async function uninstallAutoMonitorTask() {
    const result = await invoke<ActionResult>('uninstall_auto_monitor_task');
    setAutoMonitorAction(result);
    await loadIntegrationStatus();
  }

  async function runAutoCycleNow() {
    const result = await invoke<ActionResult>('run_auto_cycle_now');
    setAutoMonitorAction(result);
    await loadIntegrationStatus();
  }

  async function runCounterStrikeSteamSync() {
    setSteamSyncAction(null);
    try {
      const result = await invoke<ActionResult>('run_counter_strike_steam_sync');
      setSteamSyncAction(result);
      await loadIntegrationStatus();
    } catch (err) {
      setSteamSyncAction({
        id: 'run_counter_strike_steam_sync',
        success: false,
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }

  async function applySuggestedFpsSettings() {
    setSuggestedFpsAction(null);
    const confirmed = window.confirm(
      'Apply suggested CS2 FPS settings?\n\nThis will back up CS2 config files and Windows gaming settings, add/refresh the AetherFrameGuard CS2 profile hook, disable Game DVR capture overlays for gaming, and record before/after benchmark snapshots. It will not edit game memory or bypass anti-cheat. Relaunch CS2 before judging FPS.'
    );
    if (!confirmed) {
      return;
    }
    try {
      const result = await invoke<SuggestedFpsSettingsResult>('apply_suggested_fps_settings');
      setSuggestedFpsAction(result);
      setBenchmarkStatus(result.benchmarkStatus);
      await loadIntegrationStatus();
      await runAnalysis();
    } catch (err) {
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
    if (loading || benchmarkBusy || scanning || calibrating) return;
    setBenchmarkBusy(true);
    setBenchmarkAction(null);
    try {
      const result = await invoke<ActionResult>('run_benchmark_capture');
      setBenchmarkAction(result);
      await loadIntegrationStatus();
      await runAnalysis();
    } catch (err) {
      setBenchmarkAction({
        id: 'run_benchmark_capture',
        success: false,
        message: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBenchmarkBusy(false);
    }
  }

  async function runSecurityScan() {
    setScanning(true);
    setError(null);
    try {
      const data = await invoke<SecurityScanResult>('run_security_scan');
      setScanResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setScanning(false);
    }
  }

  function whitelistCandidateFromFinding(finding: ThreatFinding): string | null {
    if (finding.id.startsWith('proc_dupes_')) {
      return finding.id.slice('proc_dupes_'.length).trim().toLowerCase();
    }
    return null;
  }

  async function addSafeProcess(processName: string) {
    const result = await invoke<ActionResult>('add_safe_multi_instance_process', { processName });
    setActionState(result);
    await loadSafeProcessWhitelist();
    await runSecurityScan();
  }

  async function removeSafeProcess(processName: string) {
    const result = await invoke<ActionResult>('remove_safe_multi_instance_process', { processName });
    setActionState(result);
    await loadSafeProcessWhitelist();
    await runSecurityScan();
  }

  async function triggerAction(actionId: string) {
    setActionState(null);
    try {
      const data = await invoke<ActionResult>('perform_action', { actionId });
      setActionState(data);
    } catch (err) {
      setActionState({
        id: actionId,
        success: false,
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }

  function clampScore(value: number): number {
    return Math.max(0, Math.min(100, value));
  }

  function calculateImprovementPercent(current: number, baseline: number | null): number | null {
    if (baseline === null || !Number.isFinite(baseline)) {
      return null;
    }
    const denominator = Math.max(Math.abs(baseline), 1);
    return ((current - baseline) / denominator) * 100;
  }

  function scoreBand(score: number): 'low' | 'mid' | 'high' {
    if (score < 60) {
      return 'low';
    }
    if (score < 80) {
      return 'mid';
    }
    return 'high';
  }

  function bandColor(band: 'low' | 'mid' | 'high'): string {
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

  return (
    <div className="app app-simple">
      <div className="hero panel">
        <div>
          <p className="eyebrow">CS2 FPS helper</p>
          <h1>AetherFrameGuard</h1>
          <p className="panel-desc simple-lead">Measure live for 20 seconds → Apply safe settings → Re-test. Advanced tools are collapsed below.</p>
        </div>
        <button onClick={runAnalysis} disabled={systemActionBusy}>{loading ? 'Measuring…' : 'Measure'}</button>
      </div>

      <div className="panel simple-flow">
        <div className="panel-header">
          <h2>Main flow</h2>
          <small className="muted-text">Keep CS2 open and visible while measuring.</small>
        </div>
        <div className="action-grid three-step-grid">
          <button className="action-card" onClick={runAnalysis} disabled={systemActionBusy}>
            <span>1. Measure</span><small>{loading ? 'Capturing live data…' : '20 sec live FPS/PC capture'}</small>
          </button>
          <button className="action-card" onClick={applySuggestedFpsSettings} disabled={systemActionBusy}>
            <span>2. Apply safe CS2 settings</span><small>Backs up files first</small>
          </button>
          <button className="action-card" onClick={runBenchmarkCapture} disabled={systemActionBusy}>
            <span>3. Re-test</span><small>{benchmarkBusy ? 'Capturing…' : 'Compare latest vs best'}</small>
          </button>
        </div>
        {error ? <p className="failure">{error}</p> : null}
        {suggestedFpsAction ? <p className={suggestedFpsAction.success ? 'success' : 'failure'}>{suggestedFpsAction.message}{suggestedFpsAction.cs2RestartRequired ? ' Relaunch CS2 before re-testing.' : ''}</p> : null}
        {suggestedFpsAction ? (
          <details className="details-panel inline-details" open>
            <summary>What changed and what performance did</summary>
            <div className="advanced-section">
              <h3>Settings changed</h3>
              {suggestedFpsAction.detailedSettingChanges.length > 0 ? (
                suggestedFpsAction.detailedSettingChanges.map((change, index) => (
                  <div key={`${change.domain}-${change.setting}-${index}`} className="boot-entry detail-entry">
                    <span className="boot-num">{change.domain}</span>
                    <span className="boot-score-pos">{change.setting}</span>
                    <span className="boot-latency">{change.before} → {change.after}{change.restartRequired ? ' (restart/relaunch)' : ''}</span>
                    <small className="panel-desc short-note">{change.evidence}</small>
                  </div>
                ))
              ) : <p className="panel-desc">No structured setting-change details were returned.</p>}
              <h3>Measured difference</h3>
              {suggestedFpsAction.performanceComparison.summary.map((line) => <p key={line} className="panel-desc short-note">{line}</p>)}
              <p className="success short-note">{suggestedFpsAction.performanceComparison.bestObservedSummary}</p>
              <p className="panel-desc short-note">{suggestedFpsAction.performanceComparison.selectedSettingPolicy}</p>
              <p className="panel-desc short-note">A winning setting is not made permanent blindly. It becomes the recommended setting to keep only after repeated gameplay/practice-map re-tests confirm better FPS, 1% lows, stability, latency, and no guardrail regression.</p>
            </div>
          </details>
        ) : null}
        {benchmarkAction ? <p className={benchmarkAction.success ? 'success' : 'failure'}>{benchmarkAction.message}</p> : null}
      </div>

      <div className="panel">
        <h2>Status</h2>
        <div className="grid compact-grid">
          <div className="metric">CS2<strong>{result?.counterStrike.active ? 'Running' : 'Not running'}</strong></div>
          <div className="metric">FPS<strong>{result?.counterStrike.avgFps !== null && result?.counterStrike.avgFps !== undefined ? result.counterStrike.avgFps.toFixed(1) : 'n/a'}</strong></div>
          <div className="metric">1% low<strong>{result?.counterStrike.telemetryDiagnostics.fps1pctLow !== null && result?.counterStrike.telemetryDiagnostics.fps1pctLow !== undefined ? result.counterStrike.telemetryDiagnostics.fps1pctLow.toFixed(1) : 'n/a'}</strong></div>
          <div className="metric">Stability<strong>{result?.counterStrike.telemetryDiagnostics.stabilityScore ? `${result.counterStrike.telemetryDiagnostics.stabilityScore.toFixed(0)}%` : 'n/a'}</strong></div>
          <div className="metric">Scene<strong>{result?.counterStrike.telemetryDiagnostics.sceneClassification || 'unknown'}</strong></div>
          <div className="metric">PresentMon<strong>{result?.counterStrike.telemetryDiagnostics.presentmonFound ? 'Found' : 'Missing/unknown'}</strong></div>
        </div>
        {result?.counterStrike.telemetryDiagnostics.captureError ? <p className="failure short-note">{result.counterStrike.telemetryDiagnostics.captureError}</p> : null}
        <p className="panel-desc log-path">Logs: C:\ProgramData\AetherframeGuard</p>
      </div>

      {benchmarkStatus ? (
        <div className="panel">
          <div className="panel-header">
            <h2>Benchmark</h2>
            <button onClick={runBenchmarkCapture} disabled={systemActionBusy}>{benchmarkBusy ? 'Capturing…' : 'Re-test'}</button>
          </div>
          {['Baseline', 'Latest', 'Best'].map((label) => {
            const session = label === 'Baseline' ? benchmarkStatus.baseline : label === 'Latest' ? benchmarkStatus.latest : benchmarkStatus.best;
            return (
              <div key={label} className="boot-entry">
                <span className="boot-num">{label}</span>
                <span className="boot-score-pos">{session?.avgFps !== null && session?.avgFps !== undefined ? `${session.avgFps.toFixed(1)} FPS` : 'FPS n/a'}</span>
                <span className="boot-latency">{session ? `${session.confidence.toFixed(0)}% conf · ${session.objectiveScore.toFixed(1)} obj · ${session.stabilityScore.toFixed(0)}% stable · ${session.sceneClassification || 'unknown'}` : ''}</span>
              </div>
            );
          })}
          {benchmarkStatus.regressionGuardrailActive ? <p className="failure">Guardrail: {benchmarkStatus.lastGuardrailNote}</p> : null}
        </div>
      ) : null}

      <details className="panel details-panel">
        <summary>Advanced tools</summary>
        <div className="advanced-section">
          <div className="panel-header"><h3>Security</h3><button onClick={runSecurityScan} disabled={systemActionBusy}>{scanning ? 'Scanning…' : 'Scan'}</button></div>
          {scanResult ? <p className={scanResult.clean ? 'success' : 'failure'}>{scanResult.clean ? 'No findings.' : `${scanResult.totalFindings} finding(s).`}</p> : <p className="panel-desc">Optional local safety scan.</p>}
          <h3>Profiles</h3>
          <div className="chip-row">
            {profileCards.map((profile) => <button key={profile.id} onClick={() => applyProfile(profile.id)} disabled={systemActionBusy}>{profile.title}</button>)}
            <button onClick={restoreLastProfile} disabled={systemActionBusy || !lastProfileId}>Restore last</button>
          </div>
          <h3>System tasks</h3>
          <div className="chip-row">
            <button onClick={installBootService} disabled={systemActionBusy}>Install boot task</button>
            <button onClick={uninstallBootService} disabled={systemActionBusy}>Remove boot task</button>
            <button onClick={runCalibration} disabled={systemActionBusy}>{calibrating ? 'Calibrating…' : 'Calibrate'}</button>
            <button onClick={runNetworkOptimization} disabled={systemActionBusy}>Network tune</button>
          </div>
          {serviceActionState ? <p className={serviceActionState.success ? 'success' : 'failure'}>{serviceActionState.message}</p> : null}
          {netOptResult ? <p className="panel-desc">{netOptResult}</p> : null}
          <h3>Auto/NVIDIA</h3>
          <div className="chip-row">
            <button onClick={runNvidiaTuningCycle} disabled={systemActionBusy}>NVIDIA cycle</button>
            <button onClick={installAutoMonitorTask} disabled={systemActionBusy}>Install auto monitor</button>
            <button onClick={uninstallAutoMonitorTask} disabled={systemActionBusy}>Remove auto monitor</button>
            <button onClick={runAutoCycleNow} disabled={systemActionBusy}>Run auto cycle</button>
            <button onClick={runCounterStrikeSteamSync} disabled={systemActionBusy}>Refresh CS2 hook</button>
          </div>
          {nvidiaActionState ? <p className={nvidiaActionState.success ? 'success' : 'failure'}>{nvidiaActionState.message}</p> : null}
          {autoMonitorAction ? <p className={autoMonitorAction.success ? 'success' : 'failure'}>{autoMonitorAction.message}</p> : null}
          {steamSyncAction ? <p className={steamSyncAction.success ? 'success' : 'failure'}>{steamSyncAction.message}</p> : null}
        </div>
      </details>

      {result ? (
        <details className="panel details-panel">
          <summary>Details</summary>
          <div className="grid compact-grid">
            <div className="metric">Firewall<strong>{result.signals.firewallEnabled ? 'On' : 'Off'}</strong></div>
            <div className="metric">Defender<strong>{result.signals.defenderRealtimeEnabled ? 'On' : 'Off'}</strong></div>
            <div className="metric">Power<strong>{result.signals.activePowerPlan}</strong></div>
            <div className="metric">Ping<strong>{result.signals.avgPingMs ?? 'n/a'} ms</strong></div>
            <div className="metric">CPU<strong>{result.signals.cpuUsagePercent.toFixed(1)}%</strong></div>
            <div className="metric">Memory<strong>{result.signals.availableMemoryMb} MB free</strong></div>
          </div>
          <p className="panel-desc short-note">Capture path: {result.counterStrike.telemetryDiagnostics.presentmonPath ?? 'PresentMon not found'}</p>
        </details>
      ) : null}
    </div>
  );
}
