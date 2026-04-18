/**
 * CapabilitySummary — Groups imports into behavioral clusters and renders
 * a compact "what this binary can do" capability card set.
 */
import React, { useMemo } from 'react';

export interface ImportEntry {
  name: string;
  library: string;
}

interface Props {
  imports: ImportEntry[];
}

// ─── Capability clusters ──────────────────────────────────────────────────────

interface Cluster {
  id: string;
  label: string;
  description: string;
  icon: string;
  color: string;
  imports: Set<string>;
}

const CLUSTERS: Cluster[] = [
  {
    id: 'process-injection',
    label: 'Process Injection',
    description: 'Can inject code into other processes',
    icon: '💉',
    color: '#f44336',
    imports: new Set([
      'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
      'NtCreateThreadEx', 'OpenProcess', 'NtOpenProcess',
      'SetWindowsHookEx', 'QueueUserAPC',
    ]),
  },
  {
    id: 'anti-analysis',
    label: 'Anti-Analysis',
    description: 'Detects or evades debugging and analysis tools',
    icon: '🛡',
    color: '#ff5722',
    imports: new Set([
      'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
      'OutputDebugStringA', 'OutputDebugStringW', 'NtSetInformationThread',
      'FindWindowA', 'FindWindowW', 'GetTickCount', 'NtQuerySystemInformation',
    ]),
  },
  {
    id: 'network',
    label: 'Network / C2',
    description: 'Performs network communication',
    icon: '🌐',
    color: '#2196f3',
    imports: new Set([
      'InternetOpenA', 'InternetOpenW', 'InternetConnectA', 'InternetConnectW',
      'HttpSendRequestA', 'HttpSendRequestW', 'URLDownloadToFileA', 'URLDownloadToFileW',
      'WSAStartup', 'connect', 'send', 'recv', 'socket',
      'WinHttpOpen', 'WinHttpConnect', 'WinHttpSendRequest',
      'getaddrinfo', 'gethostbyname', 'InternetOpen', 'InternetConnect',
      'HttpSendRequest', 'URLDownloadToFile', 'WinHttpOpenRequest',
    ]),
  },
  {
    id: 'file-system',
    label: 'File System',
    description: 'Reads, writes, or deletes files',
    icon: '📁',
    color: '#ff9800',
    imports: new Set([
      'CreateFileA', 'CreateFileW', 'WriteFile', 'ReadFile', 'DeleteFileA', 'DeleteFileW',
      'FindFirstFileA', 'FindFirstFileW', 'MoveFileA', 'MoveFileW',
      'CopyFileA', 'CopyFileW', 'GetTempPath', 'GetTempFileName',
      'CreateFile', 'WriteFile',
    ]),
  },
  {
    id: 'registry',
    label: 'Registry',
    description: 'Modifies Windows Registry (often for persistence)',
    icon: '🔑',
    color: '#ffc107',
    imports: new Set([
      'RegSetValueExA', 'RegSetValueExW', 'RegCreateKeyA', 'RegCreateKeyW',
      'RegCreateKeyExA', 'RegCreateKeyExW', 'RegOpenKeyA', 'RegOpenKeyW',
      'RegOpenKeyExA', 'RegOpenKeyExW', 'RegDeleteKeyA', 'RegDeleteKeyW',
      'RegSetValueEx', 'RegCreateKey', 'RegCreateKeyEx',
    ]),
  },
  {
    id: 'cryptography',
    label: 'Cryptography',
    description: 'Encrypts or decrypts data',
    icon: '🔐',
    color: '#9c27b0',
    imports: new Set([
      'CryptEncrypt', 'CryptDecrypt', 'CryptGenRandom', 'CryptCreateHash',
      'BCryptEncrypt', 'BCryptDecrypt', 'BCryptGenRandom', 'BCryptOpenAlgorithmProvider',
      'CryptAcquireContext',
    ]),
  },
  {
    id: 'dynamic-loading',
    label: 'Dynamic Loading',
    description: 'Loads code at runtime to hide capabilities',
    icon: '🔄',
    color: '#607d8b',
    imports: new Set([
      'GetProcAddress', 'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW',
      'LdrLoadDll', 'LoadLibrary',
    ]),
  },
  {
    id: 'execution',
    label: 'Process Execution',
    description: 'Spawns or executes other processes',
    icon: '▶',
    color: '#e91e63',
    imports: new Set([
      'ShellExecuteA', 'ShellExecuteW', 'CreateProcessA', 'CreateProcessW',
      'WinExec', 'system', 'ShellExecuteExA', 'ShellExecuteExW',
      'ShellExecute', 'CreateProcess',
    ]),
  },
  {
    id: 'memory-ops',
    label: 'Memory Operations',
    description: 'Allocates or manipulates process memory',
    icon: '🧠',
    color: '#795548',
    imports: new Set([
      'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
      'VirtualFree', 'HeapCreate', 'HeapAlloc', 'MapViewOfFile', 'CreateFileMapping',
    ]),
  },
];

// ─── Negative / benign indicators ────────────────────────────────────────────

const BENIGN_INDICATORS: Array<{ import: string; reason: string }> = [
  { import: 'MessageBoxA',    reason: 'Has user-facing dialogs — typical of GUI apps' },
  { import: 'MessageBoxW',    reason: 'Has user-facing dialogs — typical of GUI apps' },
  { import: 'DialogBoxParamA',reason: 'Has dialog windows — typical of GUI apps' },
  { import: 'InitCommonControls', reason: 'Uses common controls — standard Windows app' },
];

// ─── Component ────────────────────────────────────────────────────────────────

export default function CapabilitySummary({ imports }: Props) {
  const importNames = useMemo(() => new Set(imports.map(i => i.name)), [imports]);

  const activeClusters = useMemo(() =>
    CLUSTERS.map(cluster => {
      const matched = Array.from(cluster.imports).filter(imp => importNames.has(imp));
      return { ...cluster, matched };
    }).filter(c => c.matched.length > 0),
    [importNames]
  );

  const benignHits = useMemo(() =>
    BENIGN_INDICATORS.filter(b => importNames.has(b.import)),
    [importNames]
  );

  if (imports.length === 0) {
    return (
      <div className="capability-summary capability-summary-empty">
        <p>No imports loaded. Run <strong>Inspect file</strong> to populate.</p>
      </div>
    );
  }

  if (activeClusters.length === 0 && benignHits.length === 0) {
    return (
      <div className="capability-summary">
        <div className="capability-clean">
          <span>✓</span>
          <span>No known dangerous capabilities detected in import table.</span>
        </div>
      </div>
    );
  }

  return (
    <div className="capability-summary">
      <div className="capability-summary-title">Capability Clusters</div>

      <div className="capability-clusters">
        {activeClusters.map(cluster => (
          <div
            key={cluster.id}
            className="capability-cluster"
            style={{ borderLeftColor: cluster.color }}
          >
            <div className="capability-cluster-header">
              <span className="capability-cluster-icon">{cluster.icon}</span>
              <span className="capability-cluster-label" style={{ color: cluster.color }}>
                {cluster.label}
              </span>
              <span className="capability-cluster-count" style={{ background: cluster.color + '33', color: cluster.color }}>
                {cluster.matched.length}
              </span>
            </div>
            <div className="capability-cluster-desc">{cluster.description}</div>
            <div className="capability-cluster-imports">
              {cluster.matched.map(imp => (
                <code key={imp} className="capability-import-chip" style={{ borderColor: cluster.color + '44' }}>
                  {imp}
                </code>
              ))}
            </div>
          </div>
        ))}
      </div>

      {benignHits.length > 0 && (
        <div className="capability-benign">
          <div className="capability-benign-title">✓ Benign indicators</div>
          {benignHits.map(b => (
            <div key={b.import} className="capability-benign-item">
              <code>{b.import}</code> — {b.reason}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
