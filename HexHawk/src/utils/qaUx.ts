import type { NavView } from '../components/WorkflowNav';

export type SubsystemSource = 'real-backend' | 'simulation' | 'ui-only';

export type QASubsystemStatus = {
  subsystem: string;
  source: SubsystemSource;
  detail: string;
};

const ACTIVITY_EVENT_PATTERNS: Array<{ pattern: RegExp; code: string }> = [
  { pattern: /^Navigate:/i, code: 'NAVIGATE_VIEW' },
  { pattern: /Opened jump dialog/i, code: 'JUMP_DIALOG_OPENED' },
  { pattern: /Toggled keyboard shortcuts/i, code: 'SHORTCUTS_TOGGLED' },
  { pattern: /Toggled QA source matrix/i, code: 'QA_MATRIX_TOGGLED' },
  { pattern: /Selected local file/i, code: 'FILE_SELECTED_LOCAL' },
  { pattern: /File picker unavailable/i, code: 'FILE_PICKER_UNAVAILABLE' },
  { pattern: /Inspected file/i, code: 'INSPECT_COMPLETE' },
  { pattern: /Simulated inspect/i, code: 'INSPECT_SIMULATION' },
  { pattern: /Seeded browser hex preview/i, code: 'HEX_PREVIEW_SEEDED' },
  { pattern: /Loaded hex preview/i, code: 'HEX_PREVIEW_LOADED' },
  { pattern: /Simulated hex preview/i, code: 'HEX_PREVIEW_SIMULATION' },
  { pattern: /Scanned strings/i, code: 'STRINGS_SCAN_COMPLETE' },
  { pattern: /Simulated string scan/i, code: 'STRINGS_SCAN_SIMULATION' },
  { pattern: /Disassembled /i, code: 'DISASSEMBLY_COMPLETE' },
  { pattern: /Simulated disassembly/i, code: 'DISASSEMBLY_SIMULATION' },
  { pattern: /Built CFG/i, code: 'CFG_BUILD_COMPLETE' },
  { pattern: /Simulated CFG build/i, code: 'CFG_BUILD_SIMULATION' },
  { pattern: /Loaded available plugins/i, code: 'PLUGIN_LIST_LOADED' },
  { pattern: /Loaded simulated built-in plugins/i, code: 'PLUGIN_LIST_SIMULATION' },
  { pattern: /Started NEST simulation/i, code: 'NEST_SIMULATION_START' },
  { pattern: /Semantic query/i, code: 'SEMANTIC_QUERY' },
  { pattern: /Jumped to constraint candidate/i, code: 'CONSTRAINT_NAVIGATION' },
  { pattern: /Ran plugin analysis/i, code: 'PLUGIN_ANALYSIS_COMPLETE' },
  { pattern: /Simulated plugin analysis/i, code: 'PLUGIN_ANALYSIS_SIMULATION' },
  { pattern: /Reloaded plugin/i, code: 'PLUGIN_RELOAD_COMPLETE' },
  { pattern: /Simulated reload for plugin/i, code: 'PLUGIN_RELOAD_SIMULATION' },
  { pattern: /Queued /i, code: 'PATCH_QUEUED' },
  { pattern: /Exported analysis/i, code: 'ANALYSIS_EXPORTED' },
  { pattern: /Failed to /i, code: 'OPERATION_FAILED' },
];

export function normalizeActivityMessage(messageText: string): string {
  const trimmed = messageText.trim();
  if (/^[A-Z0-9_]+\s\|\s/.test(trimmed)) return trimmed;

  const matched = ACTIVITY_EVENT_PATTERNS.find(({ pattern }) => pattern.test(trimmed));
  const eventCode = matched?.code ?? 'APP_EVENT';
  return `${eventCode} | ${trimmed}`;
}

export function splitActivityMessage(messageText: string): { eventCode: string; detail: string } {
  const sepIndex = messageText.indexOf(' | ');
  if (sepIndex <= 0) {
    return { eventCode: 'APP_EVENT', detail: messageText };
  }

  return {
    eventCode: messageText.slice(0, sepIndex),
    detail: messageText.slice(sepIndex + 3),
  };
}

export function sourceLabel(source: SubsystemSource): string {
  switch (source) {
    case 'real-backend':
      return 'REAL BACKEND';
    case 'simulation':
      return 'SIMULATION';
    case 'ui-only':
      return 'UI ONLY';
    default:
      return 'UNKNOWN';
  }
}

export function getPanelFidelityForView(
  activeView: NavView,
  browserMode: boolean,
): { source: SubsystemSource; detail: string } {
  const sourceByView: Record<NavView, SubsystemSource> = {
    load: 'ui-only',
    metadata: browserMode ? 'simulation' : 'real-backend',
    inspect: browserMode ? 'simulation' : 'real-backend',
    hex: browserMode ? 'simulation' : 'real-backend',
    strings: browserMode ? 'simulation' : 'real-backend',
    disassembly: browserMode ? 'simulation' : 'real-backend',
    cfg: browserMode ? 'simulation' : 'real-backend',
    decompile: browserMode ? 'simulation' : 'real-backend',
    verdict: browserMode ? 'simulation' : 'real-backend',
    signals: browserMode ? 'simulation' : 'real-backend',
    nest: browserMode ? 'simulation' : 'real-backend',
    activity: 'ui-only',
    patch: browserMode ? 'simulation' : 'real-backend',
    report: browserMode ? 'simulation' : 'real-backend',
    history: browserMode ? 'simulation' : 'real-backend',
    constraint: browserMode ? 'simulation' : 'real-backend',
    sandbox: browserMode ? 'simulation' : 'real-backend',
    debugger: browserMode ? 'simulation' : 'real-backend',
    diff: browserMode ? 'simulation' : 'real-backend',
    talon: browserMode ? 'simulation' : 'real-backend',
    agent: browserMode ? 'simulation' : 'real-backend',
    repl: browserMode ? 'simulation' : 'real-backend',
    plugins: browserMode ? 'simulation' : 'real-backend',
    help: 'ui-only',
    about: 'ui-only',
  };

  const source = sourceByView[activeView];
  if (source === 'real-backend') {
    return { source, detail: 'Panel actions are served by native backend commands.' };
  }

  if (source === 'ui-only') {
    if (activeView === 'load') {
      return {
        source,
        detail: 'Load view is UI-only path entry. Backend analysis starts when you run Inspect/Hex/Strings/Disassembly actions.',
      };
    }
    return {
      source,
      detail: 'Panel is purely client-side UI and does not call analysis backends.',
    };
  }

  if (!browserMode) {
    return { source, detail: 'Simulation mode is disabled in native runtime.' };
  }

  const browserSimulationDetailByView: Partial<Record<NavView, string>> = {
    inspect: 'Metadata is generated from browser simulation fixtures; no native file inspection is invoked.',
    metadata: 'Summary values are derived from simulated inspection output in browser mode.',
    hex: 'Hex bytes are browser-generated simulation data; native read_hex_range is not invoked.',
    strings: 'String extraction is simulated for workflow QA; no backend scanner is invoked.',
    disassembly: 'Instructions are simulated for browser-mode validation and are not backend disassembly output.',
    cfg: 'CFG is built from simulated disassembly data in browser mode.',
    decompile: 'Decompiler output is rendered from simulated disassembly/CFG inputs.',
    signals: 'Signals are computed from currently available client-side analysis artifacts in browser mode.',
    verdict: 'Verdict is computed client-side from simulated or loaded UI artifacts in browser mode.',
    nest: 'NEST session is simulated for workflow QA without native backend orchestration.',
    patch: 'Patch queue operations are simulated in browser mode; no binary writes occur.',
    report: 'Intelligence report content is generated from simulated analysis artifacts in browser mode.',
    history: 'Analysis history is simulated in browser mode and not backed by native persistence.',
    constraint: 'Constraint analysis actions are simulated and do not execute native solvers in browser mode.',
    sandbox: 'Sandbox output is simulated in browser mode and does not run subprocess instrumentation.',
    debugger: 'Debugger state is simulated in browser mode and not sourced from STRIKE runtime sessions.',
    diff: 'Binary diff results are simulated in browser mode for UI workflow validation.',
    plugins: 'Plugin lifecycle actions are simulated in browser mode and do not load native plugin binaries.',
  };

  return {
    source,
    detail: browserSimulationDetailByView[activeView] ?? 'Panel actions are simulated in browser mode for workflow QA.',
  };
}

export function getQaSubsystemStatuses(browserMode: boolean): QASubsystemStatus[] {
  const source: SubsystemSource = browserMode ? 'simulation' : 'real-backend';
  const detail = browserMode
    ? 'Browser-mode simulation path active.'
    : 'Native Tauri backend path active.';

  return [
    { subsystem: 'File Inspect', source, detail },
    { subsystem: 'Hex Preview', source, detail },
    { subsystem: 'String Scan', source, detail },
    { subsystem: 'Disassembly', source, detail },
    { subsystem: 'CFG Build', source, detail },
    { subsystem: 'Verdict Correlation', source, detail },
    { subsystem: 'Plugin Runtime', source, detail },
    { subsystem: 'Patch Queue', source, detail },
    { subsystem: 'Constraint Engine', source, detail },
    { subsystem: 'Sandbox', source, detail },
    { subsystem: 'Debugger', source, detail },
    { subsystem: 'NEST Session', source, detail },
    {
      subsystem: 'Export JSON',
      source: 'ui-only',
      detail: 'Export is generated directly by browser download APIs.',
    },
  ];
}