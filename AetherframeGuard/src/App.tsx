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

type SuggestedFpsSettingsResult = {
  appliedAt: string;
  success: boolean;
  message: string;
  backupDir: string;
  appliedChanges: string[];
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

  const systemActionBusy = loading || scanning || calibrating;

  return (
    <div className="app">
      <div className="hero panel">
        <div>
          <p className="eyebrow">Guided CS2 FPS and PC safety helper</p>
          <h1>AetherFrameGuard</h1>
          <p>
            Simple flow: 1) start CS2 first and wait until the menu or a match is visible, 2) click Measure,
            3) review the CS2 diagnostics, 4) apply only safe settings if you want them, 5) fully close and relaunch CS2,
            then 6) measure again. If FPS says n/a, open C:\ProgramData\AetherframeGuard\counter_strike_diagnostics.log.
            Scores are advisory only; GYRE remains the only HexHawk verdict authority.
          </p>
        </div>
        <button onClick={runAnalysis} disabled={loading}>
          {loading ? 'Measuring...' : 'Step 1: Measure Current FPS / PC State'}
        </button>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h2>Security Scan</h2>
          <button onClick={runSecurityScan} disabled={scanning || loading}>
            {scanning ? 'Scanning…' : 'Run Security Scan'}
          </button>
        </div>
        <p className="panel-desc">
          Click this when you want a safety check before changing settings. It looks for obvious local risks,
          overlay/capture tools, suspicious startup entries, and CS2 config lines that deserve review. It does not
          collect passwords, does not replace antivirus, and does not make final malware verdicts.
        </p>
        {safeProcesses.length > 0 ? (
          <div className="whitelist-strip">
            <strong>Safe Multi-Instance Whitelist</strong>
            <div className="chip-row">
              {safeProcesses.map((name) => (
                <button
                  key={name}
                  className="chip-button"
                  onClick={() => removeSafeProcess(name)}
                  title="Remove from whitelist"
                >
                  {name} ×
                </button>
              ))}
            </div>
          </div>
        ) : null}
        {scanResult ? (
          <>
            <div className={`scan-status ${scanResult.clean ? 'scan-clean' : 'scan-threats'}`}>
              {scanResult.clean
                ? 'No local security findings from the current defensive checks.'
                : `${scanResult.totalFindings} security finding${scanResult.totalFindings !== 1 ? 's' : ''} detected. Review severity, evidence, and advisory/confirmed status below.`}
            </div>
            <div className="grid">
              <div className="metric accent">
                AETHERFRAME Advisory Signal
                <strong>{scanResult.threatPromotion.promoted.toFixed(1)}%</strong>
                <small>Host-defense triage signal only; not a malware verdict or HexHawk authority</small>
              </div>
              <div className={`metric ${scanResult.criticalFindings > 0 ? 'sev-critical' : ''}`}>
                Critical
                <strong>{scanResult.criticalFindings}</strong>
              </div>
              <div className={`metric ${scanResult.highFindings > 0 ? 'sev-high' : ''}`}>
                High
                <strong>{scanResult.highFindings}</strong>
              </div>
              <div className={`metric ${scanResult.mediumFindings > 0 ? 'sev-medium' : ''}`}>
                Medium
                <strong>{scanResult.mediumFindings}</strong>
              </div>
              <div className="metric">
                Low
                <strong>{scanResult.lowFindings}</strong>
              </div>
            </div>
            <div style={{ marginTop: 14 }}>
              {scanResult.findings.map(finding => (
                <div key={finding.id} className={`reco finding-${finding.severity}`}>
                  <div className="finding-header">
                    <span className={`sev-badge sev-badge-${finding.severity}`}>{finding.severity.toUpperCase()}</span>
                    <strong>{finding.title}</strong>
                    {whitelistCandidateFromFinding(finding) ? (
                      <button
                        className="mini-button"
                        onClick={() => addSafeProcess(whitelistCandidateFromFinding(finding)!)}
                        title="Trust this known app and suppress future replication alerts"
                      >
                        Trust App
                      </button>
                    ) : null}
                  </div>
                  <p>{finding.description}</p>
                  <p className="finding-meta">Category: {finding.category} &nbsp;|&nbsp; Status: {finding.confirmed ? 'confirmed local observation' : 'advisory'} &nbsp;|&nbsp; Source: {finding.source} &nbsp;|&nbsp; Observed: {finding.observedAt} &nbsp;|&nbsp; Confidence: {finding.confidence.toFixed(1)}%</p>
                  <p className="finding-evidence">Evidence: {finding.evidence}</p>
                  <p className="finding-evidence">Recommendation: {finding.recommendation}</p>
                </div>
              ))}
            </div>
          </>
        ) : (
          <p className="panel-desc">No scan run yet. Click “Run Security Scan” to analyse processes, network connections, and startup persistence.</p>
        )}
      </div>
      {/* ── System Integration ─────────────────────────────────── */}
      <div className="panel">
        <div className="panel-header">
          <h2>System Integration</h2>
          <button onClick={loadIntegrationStatus} disabled={calibrating}>Refresh</button>
        </div>
        <p className="panel-desc">
          Optional advanced automation. Start with the simple CS2 button below. Install background tasks only if you
          understand they run with high Windows privileges and may need Administrator approval. Restart requirements
          are shown after each action.
        </p>

        {integrationStatus ? (
          <div className="grid" style={{ marginBottom: 14 }}>
            <div className={`metric ${integrationStatus.bootServiceInstalled ? 'metric-ok' : 'metric-warn'}`}>
              Boot Service
              <strong>{integrationStatus.bootServiceInstalled ? 'Installed' : 'Not installed'}</strong>
              <small>{integrationStatus.serviceTaskName}</small>
            </div>
            <div className="metric">
              Calibrated
              <strong>{integrationStatus.calibrated ? 'Yes' : 'No'}</strong>
              <small>Run calibration to baseline and apply optimisations</small>
            </div>
            <div className="metric accent">
              Boots Optimised
              <strong>{integrationStatus.totalBootsOptimized}</strong>
              <small>Best AETHERFRAME: {integrationStatus.bestPromotionEver.toFixed(1)}%</small>
            </div>
            {integrationStatus.lastBootPromotion !== null ? (
              <div className="metric">
                Last Boot Score
                <strong>{integrationStatus.lastBootPromotion!.toFixed(1)}%</strong>
                <small>Tracked in boot history</small>
              </div>
            ) : null}
          </div>
        ) : null}

        <div className="reco" style={{ marginBottom: 12 }}>
          <strong>NVIDIA Profile Inspector Learning Engine</strong>
          <p>
            Target tools path: {nvidiaStatus?.toolsPath ?? 'C:/Users/Ziel/Desktop/Tools/NvidiaInspector'}.
            On each cycle, AetherframeGuard measures before/after gaming and network module scores,
            applies NVIDIA tuning by CLI import when available, and stores iterative learning in ProgramData.
            Scheduled/background cycles do not open the NVIDIA Inspector GUI; use the manual button below when GUI review is needed.
          </p>
          {nvidiaStatus ? (
            <p>
              Found: {nvidiaStatus.found ? 'Yes' : 'No'} | CLI: {nvidiaStatus.cliFound ? 'Yes' : 'No'} |
              GUI: {nvidiaStatus.guiFound ? 'Yes' : 'No'} | Profile: {nvidiaStatus.profileFound ? 'Yes' : 'No'} |
              Iterations: {nvidiaStatus.totalIterations} | Best delta: {nvidiaStatus.bestDelta.toFixed(2)}
              {nvidiaStatus.lastDelta !== null ? ` | Last delta: ${nvidiaStatus.lastDelta.toFixed(2)}` : ''}
            </p>
          ) : null}
          {nvidiaStatus?.lastNotes && nvidiaStatus.lastNotes.length > 0 ? (
            <p className="finding-evidence" style={{ whiteSpace: 'pre-wrap' }}>
              {nvidiaStatus.lastNotes.join('\n')}
            </p>
          ) : null}
          <button onClick={runNvidiaTuningCycle} disabled={systemActionBusy}>
            Run NVIDIA Tuning Cycle
          </button>
          {nvidiaActionState ? (
            <p className={nvidiaActionState.success ? 'success' : 'failure'}>
              {nvidiaActionState.success ? 'NVIDIA cycle: ' : 'NVIDIA cycle failed: '}
              {nvidiaActionState.message}
            </p>
          ) : null}
        </div>

        <div className="reco" style={{ marginBottom: 12 }}>
          <strong>Step 3: Apply safe CS2 FPS settings</strong>
          <p>
            This is the main beginner-friendly action. It backs up your CS2 config, writes a small managed CS2 profile,
            disables Windows capture overlays for gaming, records the change, and then asks you to relaunch CS2 and measure again.
          </p>
          {steamSyncStatus ? (
            <p>
              Accounts: {steamSyncStatus.syncedAccounts}/{steamSyncStatus.totalAccounts} synced
              {' '}| Sync runs: {steamSyncStatus.totalSyncs}
              {steamSyncStatus.lastScore !== null ? ` | Last score: ${steamSyncStatus.lastScore.toFixed(1)}%` : ''}
              {steamSyncStatus.lastSyncedAt ? ` | Last sync: ${steamSyncStatus.lastSyncedAt}` : ''}
            </p>
          ) : null}
          <div className="chip-row">
            <button onClick={applySuggestedFpsSettings} disabled={systemActionBusy}>Apply Suggested FPS Settings</button>
            <button onClick={runCounterStrikeSteamSync} disabled={systemActionBusy}>Only Refresh CS2 Profile Hook</button>
          </div>
          <p className="panel-desc">
            Applies now: CS2 config hook and Windows capture overlay setting. Requires: relaunch CS2 before judging FPS.
            Windows restart: not normally required for this button. Manual action: close heavy overlays if the scan reports them.
          </p>
          {suggestedFpsAction ? (
            <div className={suggestedFpsAction.success ? 'success' : 'failure'}>
              <p>{suggestedFpsAction.message}</p>
              {suggestedFpsAction.backupDir ? <p>Backup folder: {suggestedFpsAction.backupDir}</p> : null}
              <p>Restart needed: {suggestedFpsAction.cs2RestartRequired ? 'Relaunch CS2' : 'No CS2 restart'}{suggestedFpsAction.windowsRestartRequired ? ' + restart Windows' : ''}</p>
              {suggestedFpsAction.appliedChanges.length > 0 ? <p>Changed: {suggestedFpsAction.appliedChanges.slice(0, 8).join('; ')}</p> : null}
              {suggestedFpsAction.warnings.length > 0 ? <p>Warnings: {suggestedFpsAction.warnings.join('; ')}</p> : null}
            </div>
          ) : null}
          {steamSyncAction ? (
            <p className={steamSyncAction.success ? 'success' : 'failure'}>
              {steamSyncAction.message}
            </p>
          ) : null}
          {steamSyncStatus?.accounts?.length ? (
            <div style={{ marginTop: 8 }}>
              {steamSyncStatus.accounts.map((account) => (
                <div key={account.accountId} className="boot-entry">
                  <span className="boot-num">{account.accountId}</span>
                  <span className={account.synced ? 'boot-score-pos' : 'boot-score-neg'}>
                    {account.synced ? 'Synced' : 'Needs attention'}
                  </span>
                  <span className="boot-latency">{account.autoexecHookPresent ? 'Hooked' : 'Hook missing'}</span>
                  <span className="boot-settings-count">{account.managedProfileWritten ? 'Profile updated' : 'Profile unchanged'}</span>
                </div>
              ))}
            </div>
          ) : null}
        </div>

        <div className="reco" style={{ marginBottom: 12 }}>
          <strong>Automatic Monitoring & Setting Changes</strong>
          <p>
            Enable auto-monitor only after you have tested the manual flow. Each cycle re-measures host state, repairs
            Steam CS userdata profiles, applies supported tuning, runs a security scan, and logs before/after deltas.
            It aims for the best observed safe state, but cannot guarantee FPS improvement.
          </p>
          {autoMonitor ? (
            <p>
              Task: {autoMonitor.taskInstalled ? 'Installed' : 'Not installed'}
              {autoMonitor.taskInstalled ? ` (${autoMonitor.taskName})` : ''}
              {' '}| Running: {autoMonitor.taskRunning ? 'Yes' : 'No'}
              {' '}| Cycles: {autoMonitor.totalCycles}
              {' '}| Best promotion: {autoMonitor.bestPromotion.toFixed(1)}%
              {autoMonitor.lastThreatScore !== null ? ` | Last security signal: ${autoMonitor.lastThreatScore.toFixed(1)}%` : ''}
            </p>
          ) : null}
          <p className="panel-desc">
            System-changing action: installing auto-monitor creates/removes a Windows Scheduled Task and running a
            cycle can write Steam CS profiles, tuning state, diagnostics, and network/NVIDIA optimization results.
            Use benchmark history and diagnostics to verify any real improvement.
          </p>

          <div className="chip-row">
            <button onClick={installAutoMonitorTask} disabled={systemActionBusy}>Install Auto Monitor</button>
            <button onClick={uninstallAutoMonitorTask} disabled={systemActionBusy}>Remove Auto Monitor</button>
            <button onClick={runAutoCycleNow} disabled={systemActionBusy}>Run Auto Cycle Now</button>
          </div>

          {autoMonitorAction ? (
            <p className={autoMonitorAction.success ? 'success' : 'failure'}>
              {autoMonitorAction.message}
            </p>
          ) : null}

          {autoMonitor?.recentCycles?.length ? (
            <div style={{ marginTop: 8 }}>
              {autoMonitor.recentCycles.slice(0, 4).map((cycle) => (
                <div key={cycle.cycleNumber} className="boot-entry">
                  <span className="boot-num">Cycle #{cycle.cycleNumber}</span>
                  <span className={cycle.promotionDelta >= 0 ? 'boot-score-pos' : 'boot-score-neg'}>
                    {cycle.afterPromotion.toFixed(1)}% ({cycle.promotionDelta >= 0 ? '+' : ''}{cycle.promotionDelta.toFixed(1)})
                  </span>
                  <span className="boot-latency">Security signal {cycle.threatScore.toFixed(1)}%</span>
                  <span className="boot-settings-count">{cycle.totalFindings} findings</span>
                </div>
              ))}
            </div>
          ) : null}
        </div>

        <div className="reco" style={{ marginBottom: 12 }}>
          <strong>Step 5: Measure again and compare</strong>
          <p>
            Use this after launching CS2, after applying settings, and after any restart. Compare Baseline, Latest,
            and Best observed. More samples mean more trustworthy results.
          </p>
          {benchmarkStatus ? (
            <p>
              Sessions: {benchmarkStatus.totalSessions}
              {' '}| Guardrail: {benchmarkStatus.regressionGuardrailActive ? 'Triggered' : 'Clear'}
              {benchmarkStatus.lastGuardrailNote ? ` | Last note: ${benchmarkStatus.lastGuardrailNote}` : ''}
            </p>
          ) : null}
          <div className="chip-row">
            <button onClick={runBenchmarkCapture} disabled={systemActionBusy}>Re-test Now</button>
          </div>
          {benchmarkAction ? (
            <p className={benchmarkAction.success ? 'success' : 'failure'}>
              {benchmarkAction.message}
            </p>
          ) : null}
          {benchmarkStatus ? (
            <div style={{ marginTop: 8 }}>
              {[
                { label: 'Baseline', session: benchmarkStatus.baseline },
                { label: 'Latest', session: benchmarkStatus.latest },
                { label: 'Best', session: benchmarkStatus.best },
              ].map(({ label, session }) => (
                <div key={label} className="boot-entry">
                  <span className="boot-num">{label}</span>
                  <span className="boot-score-pos">{session ? `${session.objectiveScore.toFixed(1)} objective` : 'n/a'}</span>
                  <span className="boot-latency">{session?.avgFps !== null && session?.avgFps !== undefined ? `${session.avgFps.toFixed(1)} FPS` : 'FPS n/a'}</span>
                  <span className="boot-settings-count">{session ? `conf ${session.confidence.toFixed(0)}%` : ''}</span>
                </div>
              ))}
            </div>
          ) : null}
        </div>

        <p className="panel-desc">
          Advanced buttons below can change Windows settings or scheduled tasks. Use the CS2 button first.
          Verify every change with Re-test Now; the app reports best observed results, not guaranteed gains.
        </p>
        <div className="action-grid" style={{ marginBottom: 12 }}>
          <button className="action-card" onClick={installBootService} disabled={systemActionBusy}>
            <span>Install Boot Service</span>
            <small>SYSTEM-level task, runs every boot. Requires Administrator.</small>
          </button>
          <button className="action-card" onClick={uninstallBootService} disabled={systemActionBusy}>
            <span>Remove Boot Service</span>
            <small>Deletes the scheduled task. Applied registry settings persist until reverted.</small>
          </button>
          <button className="action-card" onClick={runCalibration} disabled={systemActionBusy}>
            <span>{calibrating ? 'Calibrating…' : 'Run Calibration'}</span>
            <small>Baseline your system and apply all TCP + memory optimisations immediately.</small>
          </button>
          <button className="action-card" onClick={runNetworkOptimization} disabled={systemActionBusy}>
            <span>Optimise Network Now</span>
            <small>Apply TCP/IP kernel-driver tuning and RSS immediately without reboot.</small>
          </button>
        </div>

        {serviceActionState ? (
          <p className={serviceActionState.success ? 'success' : 'failure'}>
            {serviceActionState.success ? '✓ ' : '✗ '}{serviceActionState.message}
          </p>
        ) : null}

        {netOptResult ? (
          <div className="reco">
            <strong>Network Optimisation Applied</strong>
            <p className="finding-evidence" style={{ whiteSpace: 'pre-wrap' }}>
              {netOptResult.split('; ').join('\n')}
            </p>
          </div>
        ) : null}

        {calibrationResult ? (
          <div className="reco">
            <strong>Calibration Complete — Baseline AETHERFRAME: {calibrationResult.baselinePromotion.toFixed(1)}%</strong>
            {calibrationResult.baselineLatencyMs !== null ? (
              <p>Baseline latency: {calibrationResult.baselineLatencyMs!.toFixed(1)} ms</p>
            ) : null}
            <p><strong>Network settings applied:</strong></p>
            <p className="finding-evidence" style={{ whiteSpace: 'pre-wrap' }}>
              {calibrationResult.networkSettingsApplied.join('\n')}
            </p>
            <p><strong>System settings applied:</strong></p>
            <p className="finding-evidence" style={{ whiteSpace: 'pre-wrap' }}>
              {calibrationResult.systemSettingsApplied.join('\n')}
            </p>
          </div>
        ) : null}

        {bootHistory && bootHistory.entries.length > 0 ? (
          <div style={{ marginTop: 8 }}>
            <h3 style={{ margin: '0 0 10px', fontSize: '1rem', color: 'rgba(237,246,255,0.80)' }}>
              Boot History — {bootHistory.totalBootsOptimized} optimised boots
            </h3>
            {[...bootHistory.entries].reverse().slice(0, 5).map((entry) => (
              <div key={entry.bootNumber} className="boot-entry">
                <span className="boot-num">Boot #{entry.bootNumber}</span>
                <span className={entry.improvementDelta >= 0 ? 'boot-score-pos' : 'boot-score-neg'}>
                  {entry.promotionScore.toFixed(1)}%{' '}
                  <span className="boot-delta">
                    ({entry.improvementDelta >= 0 ? '+' : ''}{entry.improvementDelta.toFixed(1)})
                  </span>
                </span>
                {entry.latencyMs !== null ? (
                  <span className="boot-latency">{entry.latencyMs!.toFixed(0)} ms</span>
                ) : null}
                <span className="boot-settings-count">{entry.appliedSettings.length} optimisations</span>
              </div>
            ))}
          </div>
        ) : null}
      </div>
      <div className="panel">
        <h2>Optimization Profiles</h2>
        <p className="panel-desc">
          Optional presets. They save a snapshot first so you can restore the last applied profile.
          Game is for FPS testing, Work restores capture defaults, Hardened favors security.
        </p>
        <div className="action-grid">
          {profileCards.map((profile) => (
            <button
              key={profile.id}
              className="action-card"
              onClick={() => applyProfile(profile.id)}
              disabled={systemActionBusy}
              title={profile.description}
            >
              <span>{profile.title}</span>
              <small>{profile.description}</small>
            </button>
          ))}
        </div>
        <div className="restore-row">
          <button onClick={restoreLastProfile} disabled={systemActionBusy || !lastProfileId}>
            Restore Last Profile
          </button>
          <small>{lastProfileId ? `Last profile: ${lastProfileId}` : 'No profile snapshot saved yet.'}</small>
        </div>
      </div>

      <div className="panel">
        {error ? <p className="failure">Scan error: {error}</p> : null}
        {actionState ? (
          <p className={actionState.success ? 'success' : 'failure'}>
            {actionState.success ? 'Action complete: ' : 'Action failed: '}
            {actionState.message}
          </p>
        ) : null}
        {profileState ? (
          <div className={profileState.success ? 'success' : 'failure'}>
            <p>{profileState.message}</p>
            {profileState.warnings.length > 0 ? <p>Warnings: {profileState.warnings.join('; ')}</p> : null}
            <p>Snapshot: {profileState.snapshotPath}</p>
          </div>
        ) : null}
      </div>

      {result ? (
        <>
          <div className="panel">
            <h2>Module Scores</h2>
            <div className="odometer-grid">
              {moduleOdometers.map((module) => {
                const progress = clampScore(module.score);
                const ringDegrees = (progress / 100) * 360;
                const delta = calculateImprovementPercent(module.score, module.baseline);
                const band = scoreBand(progress);
                const ringColor = bandColor(band);

                return (
                  <div className={`odometer-card odometer-card-${band} ${module.accent ? 'odometer-card-accent' : ''}`} key={module.key}>
                    <div className="odometer-header">
                      <strong>{module.key}</strong>
                      <span>{progress.toFixed(1)}%</span>
                    </div>
                    <div
                      className="odometer-ring"
                      style={{
                        background: `conic-gradient(${ringColor} 0deg ${ringDegrees.toFixed(1)}deg, rgba(93, 129, 171, 0.28) ${ringDegrees.toFixed(1)}deg 360deg)`,
                      }}
                    >
                      <div className="odometer-inner">
                        <span>{progress.toFixed(1)}</span>
                      </div>
                    </div>
                    <p className="odometer-subtitle">{module.subtitle}</p>
                    {delta !== null ? (
                      <p className={`odometer-delta ${delta >= 0 ? 'odometer-delta-pos' : 'odometer-delta-neg'}`}>
                        Improvement {delta >= 0 ? '+' : ''}{delta.toFixed(1)}%
                      </p>
                    ) : (
                      <p className="odometer-delta odometer-delta-neutral">Improvement n/a until baseline capture</p>
                    )}
                  </div>
                );
              })}
            </div>

            {!calibrationResult ? (
              <p className="panel-desc" style={{ marginTop: 10 }}>
                Run calibration once to lock module baselines for exact improvement percentages.
              </p>
            ) : null}

            <div className="grid" style={{ marginTop: 12 }}>
              {moduleCards.map((module) => (
                <div className="metric" key={`summary-${module.key}`}>
                  {module.key}
                  <strong>{module.value.score.toFixed(1)}</strong>
                  <small>{module.value.signals[0] ?? 'No positive signal yet'}</small>
                </div>
              ))}
            </div>
          </div>

          <div className="panel">
            <h2>Host Snapshot</h2>
            <div className="grid">
              <div className="metric">Firewall<strong>{result.signals.firewallEnabled ? 'On' : 'Off'}</strong></div>
              <div className="metric">Defender<strong>{result.signals.defenderRealtimeEnabled ? 'On' : 'Off'}</strong></div>
              <div className="metric">RDP<strong>{result.signals.remoteDesktopEnabled ? 'Exposed' : 'Closed'}</strong></div>
              <div className="metric">Power Plan<strong>{result.signals.activePowerPlan}</strong></div>
              <div className="metric">Adapters<strong>{result.signals.activeNetworkAdapterCount}</strong></div>
              <div className="metric">Ping<strong>{result.signals.avgPingMs ?? 'n/a'} ms</strong></div>
              <div className="metric">OS Latency<strong>{result.signals.systemLatencyMs ?? 'n/a'} ms</strong></div>
              <div className="metric">CPU<strong>{result.signals.cpuUsagePercent.toFixed(1)}%</strong></div>
              <div className="metric">Memory<strong>{result.signals.availableMemoryMb} / {result.signals.totalMemoryMb} MB</strong></div>
              <div className="metric">Overlays<strong>{result.signals.overlayProcessCount}</strong></div>
              <div className="metric">CS Active<strong>{result.signals.counterStrikeActive ? 'Yes' : 'No'}</strong></div>
              <div className="metric">CS Score<strong>{result.counterStrike.score.toFixed(1)}%</strong></div>
              <div className="metric">CS FPS<strong>{result.counterStrike.avgFps !== null ? result.counterStrike.avgFps.toFixed(1) : 'n/a'}</strong></div>
              <div className="metric">CS Frametime<strong>{result.counterStrike.avgFrametimeMs !== null ? `${result.counterStrike.avgFrametimeMs.toFixed(2)} ms` : 'n/a'}</strong></div>
              <div className="metric">CS PC Latency<strong>{result.counterStrike.pcLatencyMs !== null ? `${result.counterStrike.pcLatencyMs.toFixed(2)} ms` : 'n/a'}</strong></div>
              <div className="metric">CS Net Latency<strong>{result.counterStrike.networkLatencyMs !== null ? `${result.counterStrike.networkLatencyMs.toFixed(1)} ms` : 'n/a'}</strong></div>
              <div className="metric">Ethernet<strong>{result.signals.ethernetAdapterActive ? 'Yes' : 'No'}</strong></div>
              <div className="metric">Wi-Fi<strong>{result.signals.wifiAdapterActive ? 'Yes' : 'No'}</strong></div>
            </div>
            <div className="reco" style={{ marginTop: 12 }}>
              <strong>CS2 Readiness & Telemetry Diagnostics</strong>
              <p>Preferred launch: {result.counterStrike.launchStatus.preferredLaunchPath}</p>
              <p>Launch batch: {result.counterStrike.launchStatus.exists ? 'found' : 'missing'} | Readable: {result.counterStrike.launchStatus.readable ? 'yes' : 'no'} | Steam app 730: {result.counterStrike.launchStatus.usesSteamApplaunch730 ? 'yes' : 'not proven'} | High priority: {result.counterStrike.launchStatus.usesHighPriority ? 'yes' : 'no'}</p>
              <p>PresentMon: {result.counterStrike.telemetryDiagnostics.presentmonFound ? 'found' : 'missing'}{result.counterStrike.telemetryDiagnostics.presentmonPath ? ` at ${result.counterStrike.telemetryDiagnostics.presentmonPath}` : ''}</p>
              <p>CS2 process: {result.counterStrike.telemetryDiagnostics.cs2ProcessFound ? 'running' : 'not running'} | Capture attempted: {result.counterStrike.telemetryDiagnostics.captureAttempted ? 'yes' : 'no'} | Capture succeeded: {result.counterStrike.telemetryDiagnostics.captureSucceeded ? 'yes' : 'no'}</p>
              <p>Last capture time: {result.counterStrike.lastFpsCaptureAt ?? result.counterStrike.telemetryDiagnostics.capturedAt}</p>
              <p>Last values: FPS {result.counterStrike.telemetryDiagnostics.avgFps !== null ? result.counterStrike.telemetryDiagnostics.avgFps.toFixed(1) : 'n/a'} | Frametime {result.counterStrike.telemetryDiagnostics.avgFrametimeMs !== null ? `${result.counterStrike.telemetryDiagnostics.avgFrametimeMs.toFixed(2)} ms` : 'n/a'} | PC latency {result.counterStrike.telemetryDiagnostics.pcLatencyMs !== null ? `${result.counterStrike.telemetryDiagnostics.pcLatencyMs.toFixed(2)} ms` : 'n/a'}</p>
              {result.counterStrike.telemetryDiagnostics.captureError ? <p className="finding-evidence">Unavailable reason: {result.counterStrike.telemetryDiagnostics.captureError}</p> : null}
              {result.counterStrike.launchStatus.notes.length > 0 ? <p className="finding-evidence">Launch notes: {result.counterStrike.launchStatus.notes.join(' | ')}</p> : null}
              {result.counterStrike.fpsCaptureSource ? <p className="panel-desc">CS telemetry source: {result.counterStrike.fpsCaptureSource}{result.counterStrike.lastFpsCaptureAt ? ` | last capture: ${result.counterStrike.lastFpsCaptureAt}` : ''}</p> : null}
            </div>
          </div>

          <div className="panel">
            <h2>Safe Actions</h2>
            <div className="action-grid">
              {result.actions.map((action) => (
                <button
                  key={action.id}
                  className="action-card"
                  onClick={() => triggerAction(action.id)}
                  title={action.rationale}
                >
                  <span>{action.title}</span>
                  <small>{action.category} | {action.confidence.toFixed(1)}%</small>
                </button>
              ))}
            </div>
          </div>

          <div className="panel">
            <h2>Ranked Recommendations</h2>
            {result.recommendations.length === 0 ? <p>No priority actions detected.</p> : null}
            {result.recommendations.map((item) => (
              <div key={item.id} className="reco">
                <strong>{item.title}</strong>
                <p>{item.rationale}</p>
                <p>
                  Category: {item.category} | Risk: {item.risk} | Impact: {item.impact} | Confidence: {item.confidence.toFixed(1)}%
                </p>
              </div>
            ))}
          </div>

          <div className="panel">
            <h2>Module Details</h2>
            {moduleCards.map((module) => (
              <div key={module.key} className="reco">
                <strong>{module.key}</strong>
                <p>Signals: {module.value.signals.length > 0 ? module.value.signals.join('; ') : 'None'}</p>
                <p>Blockers: {module.value.blockers.length > 0 ? module.value.blockers.join('; ') : 'None'}</p>
              </div>
            ))}
          </div>

          {profileState ? (
            <div className="panel">
              <h2>Before / After Proof</h2>
              <div className="grid">
                <div className="metric">
                  Promotion
                  <strong>{profileState.delta.promotionAfter.toFixed(1)}%</strong>
                  <small>{profileState.delta.promotionDelta >= 0 ? '+' : ''}{profileState.delta.promotionDelta.toFixed(1)} pts</small>
                </div>
                <div className="metric">
                  Security
                  <strong>{profileState.delta.securityAfter.toFixed(1)}</strong>
                  <small>{profileState.delta.securityDelta >= 0 ? '+' : ''}{profileState.delta.securityDelta.toFixed(1)} pts</small>
                </div>
                <div className="metric">
                  Network
                  <strong>{profileState.delta.networkAfter.toFixed(1)}</strong>
                  <small>{profileState.delta.networkDelta >= 0 ? '+' : ''}{profileState.delta.networkDelta.toFixed(1)} pts</small>
                </div>
                <div className="metric">
                  Performance
                  <strong>{profileState.delta.performanceAfter.toFixed(1)}</strong>
                  <small>{profileState.delta.performanceDelta >= 0 ? '+' : ''}{profileState.delta.performanceDelta.toFixed(1)} pts</small>
                </div>
                <div className="metric">
                  Gaming
                  <strong>{profileState.delta.gamingAfter.toFixed(1)}</strong>
                  <small>{profileState.delta.gamingDelta >= 0 ? '+' : ''}{profileState.delta.gamingDelta.toFixed(1)} pts</small>
                </div>
              </div>
              <div className="reco">
                <strong>Applied Changes</strong>
                <p>{profileState.appliedChanges.length > 0 ? profileState.appliedChanges.join('; ') : 'No changes were applied.'}</p>
              </div>
            </div>
          ) : null}
        </>
      ) : null}
    </div>
  );
}
