import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { open as openFileDialog } from '@tauri-apps/plugin-dialog';
import './styles.css';

// Tier system
import TierGate from './components/TierGate';
import LicensePanel from './components/LicensePanel';
import {
  type Tier,
  TIER_DISPLAY,
  TAB_MIN_TIER,
  tierAtLeast,
  loadTier,
  saveTier,
  loadConsoleQueriesUsed,
  incrementConsoleQueriesUsed,
  FREE_FILE_SIZE_LIMIT,
  FREE_CONSOLE_QUERY_LIMIT,
  loadLicenseKey,
} from './utils/tierConfig';
import { verifyLicense, getBuildInfo } from './utils/tauriLicense';
import type { LicenseInfo } from './utils/tauriLicense';

// Workflow-driven UI
import WorkflowNav from './components/WorkflowNav';
import type { NavView, WorkflowState } from './components/WorkflowNav';
import TopBar from './components/TopBar';
import ActionBar from './components/ActionBar';
import WorkflowCta from './components/WorkflowCta';

// Phase 6 UI Components
import UnifiedAnalysisPanel from './components/UnifiedAnalysisPanel';
import FunctionBrowser from './components/FunctionBrowser';
import SmartSuggestions from './components/SmartSuggestions';
import EnhancedInstructionRow from './components/EnhancedInstructionRow';
import ReferenceStrengthBadge from './components/ReferenceStrengthBadge';
import DisassemblyList from './components/DisassemblyList';

// Phase 7 Pattern Intelligence Components
import ThreatAssessment from './components/ThreatAssessment';
import BinaryVerdict from './components/BinaryVerdict';
import { computeVerdict } from './utils/correlationEngine';
import type { BinaryVerdictResult, BinaryClassification } from './utils/correlationEngine';
import PatternIntelligencePanel from './components/PatternIntelligencePanel';
import PatternCategoryBrowser from './components/PatternCategoryBrowser';
import WorkflowGuidance from './components/WorkflowGuidance';
import JumpToAddressDialog from './components/JumpToAddressDialog';
import CapabilitySummary from './components/CapabilitySummary';
import { ControlFlowGraph } from './components/ControlFlowGraph';

// Phase 8 � Decision Engine Components
import { AnalysisGraph } from './components/AnalysisGraph';
import { IntelligenceReport } from './components/IntelligenceReport';
import { SnapshotHistoryPanel } from './components/SnapshotHistoryPanel';
import { AutoHealBanner } from './components/AutoHealBanner';
import { diagnose } from './utils/selfHealEngine';
import type { HealPrescription } from './utils/selfHealEngine';

// Demangling (wired in M10 gap pass)
import { demangle } from './utils/demangler';
import { semanticSearch, getAllActiveIntents } from './utils/semanticSearch';
import type { SemanticSearchResult } from './utils/semanticSearch';
import { useVirtualList } from './utils/useVirtualList';
import {
  generateAutoAnnotations,
  acceptAnnotation,
  rejectAnnotation,
  visibleAnnotations,
  getAnnotationForAddress,
} from './utils/autoAnnotationEngine';
import type { AutoAnnotation } from './utils/autoAnnotationEngine';

// Decompiler
import DecompilerView from './components/DecompilerView';

// Phase 9 � Debugger + Signature
import DebuggerPanel from './components/DebuggerPanel';
import SignaturePanel from './components/SignaturePanel';

// TALON � Reasoning-Aware Decompiler
import TalonView from './components/TalonView';
import DocumentAnalysisPanel from './components/DocumentAnalysisPanel';
import SandboxPanel from './components/SandboxPanel';
import ConstraintPanel from './components/ConstraintPanel';

// STRIKE � Runtime Intelligence Debugger
import StrikeView from './components/StrikeView';

// ECHO � Fuzzy Signature Recognition
import EchoView from './components/EchoView';
import NestView from './components/NestView';
import ReplView from './components/ReplView';
import BinaryDiffPanel from './components/BinaryDiffPanel';
import OperatorConsole from './components/OperatorConsole';
import WelcomeScreen, { shouldShowWelcome, markFirstRunComplete } from './components/WelcomeScreen';
import QuillPanel from './components/QuillPanel';
import type { UserPluginInfo } from './components/QuillPanel';
import PatchPanel from './components/PatchPanel';
import { XRefPanel } from './components/XRefPanel';
import type { Patch as PanelPatch } from './components/PatchPanel';
import { detectPatchableBranches } from './utils/patchEngine';
import type { PatchSuggestion } from './utils/patchEngine';
import { computeNaturalLoops, buildDomTreeFromCfg } from './utils/cfgSignalExtractor';
import type { NaturalLoop } from './utils/cfgSignalExtractor';
import type { DomTree } from './utils/ssaTransform';
import { findPathNodesAnyRoute } from './utils/cfgPath';
import { DomTreePanel } from './components/DomTreePanel';
import {
  capArraySize,
  clampInt,
  sanitizeAddress,
  sanitizeBridgePath,
  sanitizePluginName,
  sanitizeRange,
  MAX_BRIDGE_LIST_ITEMS,
} from './utils/tauriGuards';
import {
  type QASubsystemStatus,
  type SubsystemSource,
  getPanelFidelityForView,
  getQaSubsystemStatuses,
  normalizeActivityMessage,
  sourceLabel,
  splitActivityMessage,
} from './utils/qaUx';

// ─── Corpus logging ───────────────────────────────────────────────────────────

function classificationToCorpusVerdict(
  c: BinaryClassification,
): 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' {
  if (c === 'clean') return 'CLEAN';
  if (c === 'unknown' || c === 'suspicious' || c === 'packer') return 'SUSPICIOUS';
  return 'MALICIOUS';
}

/**
 * Fire-and-forget: append one entry to the corpus log via the Tauri backend.
 * Never throws � logging failures are silently printed to the console so they
 * can never interrupt or degrade the analysis experience.
 */
async function appendCorpusLog(entry: CorpusLogEntry): Promise<void> {
  try {
    await invoke('log_analysis_result', { entry });
  } catch (err) {
    console.warn('[corpus] Failed to write log entry:', err);
  }
}

interface CorpusLogEntry {
  hash:                string;
  filename:            string;
  timestamp:           string;
  verdict:             'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS';
  confidence:          number;
  signals:             Array<{ source: string; id: string; finding: string; weight: number }>;
  engineContributions: Record<string, number>;
  talonSummary:        null;   // populated by TalonView in a future pass
  notes:               string;
}

type AppTab =
  | 'metadata'
  | 'hex'
  | 'strings'
  | 'cfg'
  | 'plugins'
  | 'disassembly'
  | 'bookmarks'
  | 'logs'
  | 'graph'
  | 'report'
  | 'decompile'
  | 'debugger'
  | 'signatures'
  | 'talon'
  | 'document'
  | 'sandbox'
  | 'constraint'
  | 'strike'
  | 'echo'
  | 'nest'
  | 'console'
  | 'diff'
  | 'repl'
  | 'agent';

type SectionMetadata = {
  name: string;
  file_offset: number;
  file_size: number;
  virtual_address: number;
  virtual_size: number;
  permissions: string;
  entropy: number;
};

export type ImportEntry = {
  name: string;
  library: string;
};

type ExportEntry = {
  name: string;
  address: number;
};

export type FileMetadata = {
  file_type: string;
  architecture: string;
  entry_point: number;
  file_size: number;
  image_base: number;
  sections: SectionMetadata[];
  imports_count: number;
  exports_count: number;
  symbols_count: number;
  imports: ImportEntry[];
  exports: ExportEntry[];
  sha256: string;
  sha1: string;
  md5: string;
};

type PluginMetadata = {
  name: string;
  description: string;
  version?: string | null;
  enabled: boolean;
  path?: string | null;
};

function hasTauriRuntime(): boolean {
  return typeof window !== 'undefined' && typeof (window as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ !== 'undefined';
}

function buildMockHexBytes(seedText: string, offset: number, length: number): number[] {
  const safeLength = clampInt(length, 1, 8192, 'mock hex length');
  const seed = Math.max(1, seedText.split('').reduce((acc, ch) => acc + ch.charCodeAt(0), 0));
  const bytes: number[] = [];
  for (let i = 0; i < safeLength; i++) {
    const value = (seed + offset + (i * 13) + ((i % 17) * 7)) & 0xff;
    bytes.push(value);
  }
  return bytes;
}

function buildMockMetadata(path: string): FileMetadata {
  const fileName = path.split(/[\\/]/).pop() || path;
  const isDll = /\.dll$/i.test(fileName);
  const isPdf = /\.pdf$/i.test(fileName);
  const lower = fileName.toLowerCase();
  const ext = lower.includes('.') ? lower.slice(lower.lastIndexOf('.')) : '';
  const fileType = isPdf ? 'PDF' : isDll ? 'PE32+ DLL' : 'PE32+ EXE';
  const fileSize = Math.max(64 * 1024, fileName.length * 4096);
  const sections: SectionMetadata[] = isPdf
    ? [
        { name: '.pdfhdr', file_offset: 0, file_size: 4096, virtual_address: 0x1000, virtual_size: 4096, permissions: 'r--', entropy: 4.21 },
      ]
    : [
        { name: '.text', file_offset: 0x400, file_size: 0x6000, virtual_address: 0x1000, virtual_size: 0x6800, permissions: 'r-x', entropy: 6.78 },
        { name: '.rdata', file_offset: 0x6400, file_size: 0x2800, virtual_address: 0x8000, virtual_size: 0x2a00, permissions: 'r--', entropy: 5.44 },
        { name: '.data', file_offset: 0x8c00, file_size: 0x1000, virtual_address: 0xb000, virtual_size: 0x1200, permissions: 'rw-', entropy: 3.11 },
      ];
  const imports: ImportEntry[] = isPdf
    ? [
        { library: 'kernel32.dll', name: 'CreateFileW' },
        { library: 'kernel32.dll', name: 'ReadFile' },
      ]
    : [
        { library: 'kernel32.dll', name: 'GetProcAddress' },
        { library: 'kernel32.dll', name: 'LoadLibraryA' },
        { library: 'kernel32.dll', name: 'VirtualAlloc' },
        { library: 'kernel32.dll', name: 'VirtualProtect' },
        { library: 'advapi32.dll', name: 'RegSetValueExA' },
      ];

  const exports: ExportEntry[] = isDll
    ? [
        { name: 'DllRegisterServer', address: 0x140001050 },
        { name: 'DllUnregisterServer', address: 0x1400011b0 },
      ]
    : [];

  const seedHex = fileName
    .split('')
    .map((ch) => ch.charCodeAt(0).toString(16).padStart(2, '0'))
    .join('')
    .slice(0, 32)
    .padEnd(32, '0');

  return {
    file_type: `${fileType}${ext ? ` (${ext})` : ''}`,
    architecture: isPdf ? 'x86_64 (document container)' : 'x86_64',
    entry_point: isPdf ? 0 : 0x140001000,
    file_size: fileSize,
    image_base: isPdf ? 0 : 0x140000000,
    sections,
    imports_count: imports.length,
    exports_count: exports.length,
    symbols_count: exports.length,
    imports,
    exports,
    sha256: `${seedHex}${seedHex}`.slice(0, 64),
    sha1: `${seedHex}${seedHex}`.slice(0, 40),
    md5: seedHex.slice(0, 32),
  };
}

function buildMockStrings(fileName: string): StringMatch[] {
  return [
    { offset: 0x4010, length: 18, text: 'https://example.com' },
    { offset: 0x4040, length: 20, text: 'HKEY_LOCAL_MACHINE\\SOFTWARE\\HexHawk' },
    { offset: 0x4080, length: 14, text: 'kernel32.dll' },
    { offset: 0x40b0, length: 26, text: `${fileName}:demo-analysis-token` },
    { offset: 0x4100, length: 16, text: 'CreateRemoteThread' },
  ];
}

function buildMockDisassembly(baseOffset: number): DisassembledInstruction[] {
  const base = Math.max(0x140001000, baseOffset || 0x140001000);
  return [
    { address: base + 0x00, mnemonic: 'push', operands: 'rbp' },
    { address: base + 0x01, mnemonic: 'mov', operands: 'rbp, rsp' },
    { address: base + 0x04, mnemonic: 'sub', operands: 'rsp, 0x30' },
    { address: base + 0x08, mnemonic: 'call', operands: `${formatHex(base + 0x80)}` },
    { address: base + 0x0d, mnemonic: 'cmp', operands: 'eax, 0x0' },
    { address: base + 0x10, mnemonic: 'je', operands: `${formatHex(base + 0x28)}` },
    { address: base + 0x16, mnemonic: 'mov', operands: 'ecx, 0x1' },
    { address: base + 0x1b, mnemonic: 'jmp', operands: `${formatHex(base + 0x2f)}` },
    { address: base + 0x28, mnemonic: 'xor', operands: 'ecx, ecx' },
    { address: base + 0x2f, mnemonic: 'add', operands: 'rsp, 0x30' },
    { address: base + 0x33, mnemonic: 'pop', operands: 'rbp' },
    { address: base + 0x34, mnemonic: 'ret', operands: '' },
  ];
}

function buildMockCfg(baseOffset: number): CfgGraph {
  const base = Math.max(0x140001000, baseOffset || 0x140001000);
  return {
    nodes: [
      { id: 'entry', label: 'entry', start: base + 0x00, end: base + 0x10, instruction_count: 6, block_type: 'entry' },
      { id: 'then', label: 'then', start: base + 0x16, end: base + 0x1f, instruction_count: 2, block_type: 'target' },
      { id: 'exit', label: 'exit', start: base + 0x28, end: base + 0x34, instruction_count: 4, block_type: 'target' },
    ],
    edges: [
      { source: 'entry', target: 'then', kind: 'branch', condition: 'fallthrough' },
      { source: 'entry', target: 'exit', kind: 'branch', condition: 'conditional' },
      { source: 'then', target: 'exit', kind: 'fallthrough', condition: 'unconditional' },
    ],
  };
}

function buildMockPluginResults(path: string): PluginExecutionResult[] {
  const filename = path.split(/[\\/]/).pop() || path;
  return [
    {
      plugin: 'ByteCounter',
      description: 'Counts bytes and reports file size metrics',
      version: '1.0.0',
      success: true,
      summary: `Processed ${filename} with browser-mode simulated plugin engine.`,
      kind: 'metric',
      schema_version: 1,
      details: {
        metrics: {
          estimated_size_bytes: Math.max(65536, filename.length * 4096),
          byte_classes: { printable: 4123, nulls: 198, high_entropy_regions: 4 },
        },
      },
    },
    {
      plugin: 'SuspiciousImportScanner',
      description: 'Flags potentially risky imports',
      version: '1.0.0',
      success: true,
      summary: 'Detected 2 suspicious import patterns in simulated analysis.',
      kind: 'warning',
      schema_version: 1,
      details: {
        findings: [
          { offset: 0x4020, symbol: 'VirtualAlloc', severity: 'warning' },
          { offset: 0x4040, symbol: 'CreateRemoteThread', severity: 'warning' },
        ],
      },
    },
  ];
}

export type { UserPluginInfo };

type PluginKind = 'metric' | 'analysis' | 'strings' | 'warning' | 'error';

type PluginExecutionResult = {
  plugin: string;
  description: string;
  version?: string | null;
  success: boolean;
  summary: string;
  details?: Record<string, unknown> | null;
  kind?: PluginKind | null;
  schema_version?: number | null;
  plugin_hash?: string | null;
};

type LogLevel = 'info' | 'warn' | 'error';

type LogEntry = {
  timestamp: string;
  level: LogLevel;
  message: string;
};

export type DisassembledInstruction = {
  address: number;
  mnemonic: string;
  operands: string;
};

type CfgNode = {
  id: string;
  label?: string;
  start?: number;
  end?: number;
  instruction_count?: number;
  block_type?: string;  // "entry", "target", "external"
  layout_x?: number;
  layout_y?: number;
  layout_depth?: number;
};

type CfgEdge = {
  source: string;
  target: string;
  kind?: string;  // "branch", "fallthrough"
  condition?: string;  // "conditional", "unconditional"
};

type CfgGraph = {
  nodes: CfgNode[];
  edges: CfgEdge[];
};

export type StringMatch = {
  offset: number;
  length: number;
  text: string;
};

type Bookmark = {
  id: string;
  address: number;
  range?: { start: number; end: number };
  blockId?: string;
  tab?: AppTab;  // NEW: Restore to specific tab
  note: string;
  tags: string[];
  timestamp: number;
};

type Patch = {
  id: string;
  address: number;
  label: string;
  originalBytes: number[];
  patchedBytes: number[];
  enabled: boolean;
  timestamp: number;
  // Explainability (optional � absent on manual patches)
  reason?: string;
  impact?: string;
  verifyBefore?: string;
  risk?: 'low' | 'medium' | 'high';
  signalIds?: string[];
};

type HistoryEntry = {
  id: string;
  address: number;
  range: { start: number; end: number };
  tab: AppTab;
  timestamp: number;
  description: string;
};

// ===== PHASE 5: Advanced Analysis Types =====

// Known dangerous imports flagged with a threat badge
const DANGEROUS_IMPORTS: Record<string, string> = {
  VirtualAlloc: 'memory allocation',
  VirtualAllocEx: 'remote memory allocation',
  WriteProcessMemory: 'process injection',
  ReadProcessMemory: 'process memory reading',
  CreateRemoteThread: 'remote thread creation',
  NtCreateThreadEx: 'remote thread creation',
  OpenProcess: 'process access',
  SetWindowsHookEx: 'keyboard/mouse hooking',
  GetProcAddress: 'dynamic API resolution',
  LoadLibrary: 'dynamic loading',
  LoadLibraryA: 'dynamic loading',
  LoadLibraryW: 'dynamic loading',
  ShellExecute: 'process execution',
  ShellExecuteA: 'process execution',
  ShellExecuteW: 'process execution',
  CreateProcess: 'process spawning',
  CreateProcessA: 'process spawning',
  CreateProcessW: 'process spawning',
  WinExec: 'process execution',
  RegSetValueEx: 'registry modification',
  RegSetValueExA: 'registry modification',
  RegSetValueExW: 'registry modification',
  InternetOpen: 'network access',
  InternetConnect: 'network connection',
  HttpSendRequest: 'HTTP request',
  URLDownloadToFile: 'file download',
  WSAStartup: 'network socket init',
  connect: 'network connection',
  IsDebuggerPresent: 'anti-debugging',
  CheckRemoteDebuggerPresent: 'anti-debugging',
  NtQueryInformationProcess: 'anti-debugging / process info',
  CryptEncrypt: 'cryptography',
  CryptDecrypt: 'cryptography',
};

type StringKind = 'url' | 'ip' | 'domain' | 'registry' | 'filepath' | 'base64' | 'uuid' | 'pe-artifact' | 'plain';

function classifyString(text: string): StringKind {
  if (/^https?:\/\/\S+/i.test(text)) return 'url';
  if (/^ftp:\/\/\S+/i.test(text)) return 'url';
  if (/^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(text)) return 'ip';
  if (/^HKEY_(LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)/i.test(text)) return 'registry';
  if (/^[A-Za-z]:[\\\/]/.test(text) || /^\\\\[^\\]+/.test(text)) return 'filepath';
  if (/\.(exe|dll|sys|bat|cmd|ps1|vbs|js)$/i.test(text)) return 'pe-artifact';
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(text)) return 'uuid';
  if (/^[A-Za-z0-9+/]{20,}={0,2}$/.test(text) && text.length % 4 === 0) return 'base64';
  // Domain: require at least two labels, TLD of 2–6 lowercase letters, no uppercase-only segments
  // (excludes Windows namespaces like Windows.Forms, Microsoft.Win32, etc.)
  if (
    /^([a-z0-9-]+\.)+[a-z]{2,6}$/.test(text) &&
    text.includes('.') &&
    !/[A-Z]/.test(text)
  ) return 'domain';
  return 'plain';
}

const STRING_KIND_LABELS: Record<StringKind, { label: string; color: string }> = {
  url:         { label: 'URL',      color: '#4fc3f7' },
  ip:          { label: 'IP',       color: '#ef9a9a' },
  domain:      { label: 'Domain',   color: '#80cbc4' },
  registry:    { label: 'Registry', color: '#ffcc02' },
  filepath:    { label: 'Path',     color: '#ffb74d' },
  base64:      { label: 'Base64',   color: '#ce93d8' },
  uuid:        { label: 'UUID',     color: '#90caf9' },
  'pe-artifact': { label: 'PE',    color: '#ff8a65' },
  plain:       { label: '',         color: '' },
};

export type ReferenceStrength = {
  incomingCount: number;
  outgoingCount: number;
  importance: 'critical' | 'high' | 'medium' | 'low';
};

export type FunctionMetadata = {
  startAddress: number;
  endAddress: number;
  size: number;
  prologueType?: 'push_rbp' | 'sub_rsp' | 'custom' | 'leaf';
  callCount: number;
  incomingCalls: Set<number>;
  returnCount: number;
  hasLoops: boolean;
  complexity: number;
  suspiciousPatterns: string[];
  /** True if this function calls itself (directly or via incomingCalls from its own body) */
  isRecursive: boolean;
  /** True if the last transfer instruction before the next function boundary is a jmp to outside this function */
  hasTailCall: boolean;
  /** Inferred calling convention based on prologue and argument register usage */
  callingConvention?: 'cdecl' | 'fastcall' | 'stdcall' | 'unknown';
  /** True if this function is a thunk — a tiny (≤2-instruction) wrapper that immediately jmps to another address */
  isThunk?: boolean;
  /** For thunks: the address they jump to */
  thunkTarget?: number;
};

export type LoopInfo = {
  startAddress: number;
  endAddress: number;
  backEdgeAddress: number;
  depth: number;
  iterationPattern?: string;
};

export type SuspiciousPattern = {
  address: number;
  type: 'tight_loop' | 'repeated_memory' | 'indirect_call' | 'jump_table' | 'switch_table' | 'obfuscation' | 'validation' | 'opaque_predicate' | 'flattened_cf' | 'anti_tamper' | 'self_modifying';
  severity: 'warning' | 'critical';
  description: string;
  relatedAddresses?: number[];
};

export type BlockAnalysis = {
  blockId: string;
  blockType: 'entry' | 'loop' | 'exit' | 'normal' | 'unreachable';
  branchingComplexity: number;
  loopDepth: number;
  callCount: number;
  suspiciousPatterns: SuspiciousPattern[];
};

export type DisassemblyAnalysis = {
  functions: Map<number, FunctionMetadata>;
  loops: LoopInfo[];
  suspiciousPatterns: SuspiciousPattern[];
  referenceStrength: Map<number, ReferenceStrength>;
  blockAnalysis: Map<string, BlockAnalysis>;
};

function formatHex(value: number | bigint | undefined | null): string {
  if (value === undefined || value === null) return '0x0';
  const n = typeof value === 'bigint' ? value : BigInt(value);
  return `0x${n.toString(16).toUpperCase()}`;
}

function formatBytes(bytes: Uint8Array | number[]): string {
  const arr = Array.from(bytes);
  const lines: string[] = [];

  for (let i = 0; i < arr.length; i += 16) {
    const chunk = arr.slice(i, i + 16);
    const offset = i.toString(16).padStart(8, '0').toUpperCase();
    const hex = chunk
      .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
      .join(' ')
      .padEnd(16 * 3 - 1, ' ');
    const ascii = chunk
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
      .join('');
    lines.push(`${offset}  ${hex}  ${ascii}`);
  }

  return lines.join('\n');
}

function StatusPanel({ status }: { status: string }) {
  return (
    <section className="panel">
      <h3>Status</h3>
      <p>{status}</p>
    </section>
  );
}

function ActivityLog({ entries }: { entries: LogEntry[] }) {
  return (
    <div className="panel" data-testid="panel-activity">
      <h3>Activity</h3>
      {entries.length === 0 ? (
        <p>No activity yet.</p>
      ) : (
        <div className="activity-list" data-testid="activity-list">
          {entries.map((entry, index) => {
            const parsed = splitActivityMessage(entry.message);
            return (
              <div key={`${entry.timestamp}-${index}`} className={`activity-item activity-${entry.level}`} data-testid="activity-item">
                <div className="activity-meta">
                  [{entry.timestamp}] {entry.level.toUpperCase()}
                </div>
                <div>
                  <span className="activity-event-code" data-testid="activity-event-code">{parsed.eventCode}</span>
                  {' '}
                  {parsed.detail}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function PanelFidelityBadge({ source, detail }: { source: SubsystemSource; detail: string }) {
  return (
    <div className={`panel-fidelity-badge panel-fidelity-${source}`} data-testid="panel-fidelity-badge" data-source={source}>
      <strong>Data Source: {sourceLabel(source)}</strong>
      <span>{detail}</span>
    </div>
  );
}

function QASubsystemPanel({ statuses }: { statuses: QASubsystemStatus[] }) {
  return (
    <div className="panel qa-subsystem-panel" data-testid="qa-source-matrix">
      <h3>QA Source Matrix</h3>
      <div className="qa-source-grid">
        {statuses.map((status) => (
          <div key={status.subsystem} className="qa-source-item" data-testid={`qa-source-${status.subsystem.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`} data-source={status.source}>
            <div className="qa-source-header">
              <strong>{status.subsystem}</strong>
              <span className={`qa-source-pill qa-source-${status.source}`}>{sourceLabel(status.source)}</span>
            </div>
            <div className="qa-source-detail">{status.detail}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// Helper: Interpret bytes as different types
function interpretBytes(bytes: number[], littleEndian: boolean = false): Record<string, any> {
  if (bytes.length === 0) return {};

  const result: Record<string, any> = {
    bytes: bytes.map(b => '0x' + b.toString(16).padStart(2, '0').toUpperCase()).join(' '),
    byteCount: bytes.length,
  };

  // u8
  if (bytes.length >= 1) {
    result.u8 = bytes[0];
  }

  // u16
  if (bytes.length >= 2) {
    const val = (bytes[0] << 8) | bytes[1];
    result.u16_be = val;
    const val_le = (bytes[1] << 8) | bytes[0];
    result.u16_le = val_le;
  }

  // u32
  if (bytes.length >= 4) {
    const val = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    result.u32_be = val;
    const val_le = (bytes[3] << 24) | (bytes[2] << 16) | (bytes[1] << 8) | bytes[0];
    result.u32_le = val_le;
  }

  // Float (32-bit)
  if (bytes.length >= 4) {
    const buf = new ArrayBuffer(4);
    const view = new DataView(buf);
    view.setUint8(0, bytes[0]);
    view.setUint8(1, bytes[1]);
    view.setUint8(2, bytes[2]);
    view.setUint8(3, bytes[3]);
    result.float32_be = view.getFloat32(0, false);
    result.float32_le = view.getFloat32(0, true);
  }

  // Double (64-bit)
  if (bytes.length >= 8) {
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    for (let i = 0; i < 8; i++) {
      view.setUint8(i, bytes[i]);
    }
    result.float64_be = view.getFloat64(0, false);
    result.float64_le = view.getFloat64(0, true);
  }

  return result;
}

// Helper: Find pattern in bytes
function findPattern(bytes: number[], pattern: string, patternType: 'hex' | 'ascii' | 'regex'): number[] {
  const matches: number[] = [];

  if (patternType === 'hex') {
    const cleanHex = pattern.replace(/\s+/g, '');
    if (cleanHex.length % 2 !== 0) return matches;
    
    const patternBytes: number[] = [];
    for (let i = 0; i < cleanHex.length; i += 2) {
      patternBytes.push(parseInt(cleanHex.substr(i, 2), 16));
    }

    for (let i = 0; i <= bytes.length - patternBytes.length; i++) {
      let match = true;
      for (let j = 0; j < patternBytes.length; j++) {
        if (bytes[i + j] !== patternBytes[j]) {
          match = false;
          break;
        }
      }
      if (match) matches.push(i);
    }
  } else if (patternType === 'ascii') {
    const patternBytes = pattern.split('').map(c => c.charCodeAt(0));
    for (let i = 0; i <= bytes.length - patternBytes.length; i++) {
      let match = true;
      for (let j = 0; j < patternBytes.length; j++) {
        if (bytes[i + j] !== patternBytes[j]) {
          match = false;
          break;
        }
      }
      if (match) matches.push(i);
    }
  } else if (patternType === 'regex') {
    try {
      const regex = new RegExp(pattern);
      let ascii = bytes.map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('');
      let match;
      const re = new RegExp(regex.source, 'g');
      while ((match = re.exec(ascii)) !== null) {
        matches.push(match.index);
      }
    } catch {
      // Invalid regex
    }
  }

  return matches;
}

// Helper: Copy to clipboard
async function copyToClipboard(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
  } catch (err) {
    console.error('Failed to copy:', err);
  }
}

// ─── Virtual HexViewer � module-level constants + row renderer ───────────────
const HEX_ROW_SIZE = 16;
const HEX_ROW_HEIGHT_PX = 28;

/// Number of instructions fetched per disassembly chunk (initial load + each load-more).
const DISASM_CHUNK_SIZE = 256;
const MAX_UI_DISASSEMBLY_ITEMS = 20000;

function readStorageJson<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return fallback;
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function readStorageInt(key: string, fallback: number, min: number, max: number): number {
  const raw = localStorage.getItem(key);
  const n = Number(raw ?? fallback);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(n)));
}

function getHexHighlightColor(
  value: number,
  mode: 'none' | 'null' | 'printable' | 'entropy'
): string | undefined {
  if (mode === 'null' && value === 0) return 'rgba(244,67,54,0.35)';
  if (mode === 'printable' && value >= 32 && value <= 126) return 'rgba(76,175,80,0.25)';
  if (mode === 'entropy') {
    if (value > 200 || (value > 100 && value < 150)) return 'rgba(156,39,176,0.3)';
  }
  return undefined;
}

interface HexRowItemData {
  bytes: number[];
  baseOffset: number;
  selectedIndex: number | null;
  highlightedRange: { start: number; end: number } | undefined;
  searchResultsSet: Set<number>;
  onSelectByte: (index: number) => void;
  hexGrouping: 1 | 2 | 4 | 8;
  hexHighlightMode: 'none' | 'null' | 'printable' | 'entropy';
}

interface HexRowProps extends HexRowItemData {
  index: number;
  style: React.CSSProperties;
}

const HexRow = React.memo(function HexRow({
  index,
  style,
  bytes,
  baseOffset,
  selectedIndex,
  highlightedRange,
  searchResultsSet,
  onSelectByte,
  hexGrouping,
  hexHighlightMode,
}: HexRowProps) {

  const rowStart = index * HEX_ROW_SIZE;
  const rowBytes = bytes.slice(rowStart, rowStart + HEX_ROW_SIZE);
  const offset = baseOffset + rowStart;
  const rowEndOffset = offset + rowBytes.length;

  const isRowHighlighted =
    highlightedRange != null &&
    offset < highlightedRange.end &&
    rowEndOffset > highlightedRange.start;

  const hexCells: React.ReactNode[] = [];
  rowBytes.forEach((value, idx) => {
    const byteIndex = rowStart + idx;
    const cellOffset = baseOffset + byteIndex;
    const isSelected = selectedIndex === byteIndex;
    const isCellHighlighted =
      highlightedRange != null &&
      cellOffset >= highlightedRange.start &&
      cellOffset < highlightedRange.end;
    const isSearchResult = searchResultsSet.has(byteIndex);
    const patternBg = getHexHighlightColor(value, hexHighlightMode);

    hexCells.push(
      <button
        key={byteIndex}
        type="button"
        className={`hex-cell${isSelected ? ' selected' : ''}${isCellHighlighted ? ' highlighted' : ''}${isSearchResult ? ' search-result' : ''}`}
        onClick={() => onSelectByte(byteIndex)}
        title={`${formatHex(cellOffset)} = 0x${value.toString(16).padStart(2, '0').toUpperCase()}${isSearchResult ? ' (search match)' : ''}`}
        style={patternBg ? { background: patternBg } : undefined}
      >
        {value.toString(16).padStart(2, '0').toUpperCase()}
      </button>
    );
    if (hexGrouping > 1 && (idx + 1) % hexGrouping === 0 && idx + 1 < rowBytes.length) {
      hexCells.push(
        <span key={`sep-${byteIndex}`} style={{ display: 'inline-block', width: '4px' }} />
      );
    }
  });

  const ascii = rowBytes
    .map((v) => (v >= 32 && v <= 126 ? String.fromCharCode(v) : '.'))
    .join('');

  return (
    <div
      style={style}
      className={`hex-row${isRowHighlighted ? ' highlighted' : ''}`}
      data-hex-offset={offset}
    >
      <div className="hex-offset">{offset.toString(16).padStart(8, '0').toUpperCase()}</div>
      <div className="hex-row-cells">{hexCells}</div>
      <div className="hex-ascii">{ascii}</div>
    </div>
  );
});

function HexViewer({
  bytes,
  title,
  baseOffset,
  selectedIndex,
  onSelectByte,
  onJumpToDisasm,
  highlightedRange,
  onRangeSelect,
  hexGrouping = 1,
  hexHighlightMode = 'none',
  fileSize,
  onLoadMore,
  isLoadingMore,
}: {
  bytes: number[];
  title?: string;
  baseOffset: number;
  selectedIndex: number | null;
  onSelectByte: (index: number) => void;
  onJumpToDisasm?: (address: number) => void;
  highlightedRange?: { start: number; end: number };
  onRangeSelect?: (start: number, end: number) => void;
  hexGrouping?: 1 | 2 | 4 | 8;
  hexHighlightMode?: 'none' | 'null' | 'printable' | 'entropy';
  /** Total size of the file � used to show a progress indicator. */
  fileSize?: number;
  /** Called when the user scrolls near the bottom to load the next chunk. */
  onLoadMore?: () => void;
  /** True while a chunk is being fetched. */
  isLoadingMore?: boolean;
}) {
  const [searchPattern, setSearchPattern] = React.useState('');
  const [searchType, setSearchType] = React.useState<'hex' | 'ascii' | 'regex'>('hex');
  const [searchResults, setSearchResults] = React.useState<number[]>([]);
  const [searchResultIndex, setSearchResultIndex] = React.useState(0);
  const [littleEndian, setLittleEndian] = React.useState(false);

  // Keep a stable ref to the latest onSelectByte so the effect dependency
  // array can stay [searchPattern, searchType, bytes] without going stale.
  const onSelectByteRef = React.useRef(onSelectByte);
  React.useEffect(() => { onSelectByteRef.current = onSelectByte; });

  // Search when pattern or bytes change
  React.useEffect(() => {
    if (searchPattern.trim()) {
      const results = findPattern(bytes, searchPattern, searchType);
      setSearchResults(results);
      setSearchResultIndex(0);
      if (results.length > 0) {
        onSelectByteRef.current(results[0]);
      }
    } else {
      setSearchResults([]);
    }
  }, [searchPattern, searchType, bytes]);

  if (bytes.length === 0) {
    return (
      <div className="panel">
        <h3>{title ?? 'Hex Viewer'}</h3>
        <p>No bytes loaded.</p>
      </div>
    );
  }

  // Get selected bytes for type interpretation
  const getSelectedBytes = (): number[] => {
    if (selectedIndex === null) return [];
    const endIdx = Math.min(selectedIndex + 8, bytes.length);
    return bytes.slice(selectedIndex, endIdx);
  };

  const selectedBytes = getSelectedBytes();
  const typeInfo = interpretBytes(selectedBytes, littleEndian);

  // Convert search results to Set for O(1) lookups
  const searchResultsSet = React.useMemo(() => new Set(searchResults), [searchResults]);

  const rowCount = Math.ceil(bytes.length / HEX_ROW_SIZE);
  const containerHeight = Math.min(
    rowCount * HEX_ROW_HEIGHT_PX,
    Math.round(window.innerHeight * 0.56)
  );

  const { virtualItems, totalHeight, containerRef: hexContainerRef, scrollToIndex } = useVirtualList({
    count: rowCount,
    itemHeight: HEX_ROW_HEIGHT_PX,
    overscan: 5,
  });

  // Scroll to the row containing the selected byte when selection changes
  React.useEffect(() => {
    if (selectedIndex !== null) {
      scrollToIndex(Math.floor(selectedIndex / HEX_ROW_SIZE));
    }
  }, [selectedIndex, scrollToIndex]);

  // Load-more: detect when the user scrolls near the bottom of the hex view
  const onLoadMoreRef = React.useRef(onLoadMore);
  React.useEffect(() => { onLoadMoreRef.current = onLoadMore; });
  React.useEffect(() => {
    const el = hexContainerRef.current;
    if (!el || !onLoadMore) return;
    const handleScroll = () => {
      const { scrollTop, scrollHeight, clientHeight } = el;
      if (scrollHeight - scrollTop - clientHeight < 300) {
        onLoadMoreRef.current?.();
      }
    };
    el.addEventListener('scroll', handleScroll, { passive: true });
    return () => el.removeEventListener('scroll', handleScroll);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hexContainerRef, !!onLoadMore]);

  // itemData for HexRow � stable object avoids prop-drilling into each row
  const hexRowItemData = React.useMemo<HexRowItemData>(
    () => ({
      bytes,
      baseOffset,
      selectedIndex,
      highlightedRange,
      searchResultsSet,
      onSelectByte,
      hexGrouping,
      hexHighlightMode,
    }),
    [bytes, baseOffset, selectedIndex, highlightedRange, searchResultsSet, onSelectByte, hexGrouping, hexHighlightMode]
  );

  return (
    <div className="panel hex-viewer-enhanced-panel">
      <div className="hex-viewer-bar">
        <div className="hex-viewer-title">{title ?? 'Hex Viewer'}</div>
        <div className="hex-viewer-meta">
          <span>Base offset: {formatHex(baseOffset)}</span>
          <span>Size: {bytes.length} bytes{fileSize && fileSize > bytes.length ? ` / ${fileSize} total` : ''}</span>
          {selectedIndex !== null && (
            <span>Selected: {formatHex(baseOffset + selectedIndex)}</span>
          )}
          {isLoadingMore && <span style={{ color: '#79c0ff', fontSize: '0.75rem' }}>Loading...</span>}
          {onLoadMore && fileSize && fileSize > bytes.length && !isLoadingMore && (
            <button
              type="button"
              style={{ fontSize: '0.72rem', padding: '0.1rem 0.4rem', background: 'rgba(56,139,253,0.12)', border: '1px solid rgba(56,139,253,0.3)', borderRadius: '0.35rem', color: '#79c0ff', cursor: 'pointer' }}
              onClick={onLoadMore}
              title="Load next 4 KB"
            >Load more</button>
          )}
        </div>
      </div>

      {/* Search toolbar */}
      <div className="hex-search-toolbar">
        <div className="search-input-group">
          <input
            type="text"
            placeholder="Search pattern..."
            value={searchPattern}
            onChange={(e) => setSearchPattern(e.target.value)}
            className="search-input"
          />
          <select
            value={searchType}
            onChange={(e) => setSearchType(e.target.value as any)}
            className="search-type-select"
          >
            <option value="hex">Hex</option>
            <option value="ascii">ASCII</option>
            <option value="regex">Regex</option>
          </select>
          {searchResults.length > 0 && (
            <div className="search-results-info">
              Match {searchResultIndex + 1} of {searchResults.length}
            </div>
          )}
        </div>
        {searchResults.length > 0 && (
          <div className="search-nav-buttons">
            <button
              onClick={() => {
                const prevIndex = (searchResultIndex - 1 + searchResults.length) % searchResults.length;
                setSearchResultIndex(prevIndex);
                onSelectByte(searchResults[prevIndex]);
              }}
            >
              ← Prev
            </button>
            <button
              onClick={() => {
                const nextIndex = (searchResultIndex + 1) % searchResults.length;
                setSearchResultIndex(nextIndex);
                onSelectByte(searchResults[nextIndex]);
              }}
            >
              Next →
            </button>
          </div>
        )}
      </div>

      {/* Jump to disasm button */}
      {selectedIndex !== null && onJumpToDisasm && (
        <div className="hex-jump-row">
          <button type="button" onClick={() => onJumpToDisasm(baseOffset + selectedIndex)}>
            Jump to disassembly at {formatHex(baseOffset + selectedIndex)}
          </button>
        </div>
      )}

      {/* Copy buttons */}
      {selectedIndex !== null && (
        <div className="hex-copy-toolbar">
          <button
            onClick={() => copyToClipboard(bytes[selectedIndex].toString(16).padStart(2, '0').toUpperCase())}
            title="Copy hex byte"
          >
            Copy Hex
          </button>
          <button
            onClick={() => copyToClipboard(selectedBytes.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' '))}
            title={`Copy ${selectedBytes.length} bytes as hex`}
          >
            Copy {selectedBytes.length}B Hex
          </button>
          <button
            onClick={() => copyToClipboard(`0x${bytes[selectedIndex].toString(16).padStart(2, '0').toUpperCase()}`)}
            title="Copy as hex value"
          >
            Copy 0x Format
          </button>
          <button
            onClick={() => copyToClipboard(JSON.stringify(selectedBytes))}
            title="Copy as JSON array"
          >
            Copy JSON
          </button>
          <button
            onClick={() => {
              const str = String.fromCharCode(...selectedBytes);
              copyToClipboard(btoa(str));
            }}
            title="Copy as Base64"
          >
            Copy Base64
          </button>
        </div>
      )}

      {/* Type interpreter */}
      {selectedIndex !== null && selectedBytes.length > 0 && (
        <div className="hex-type-interpreter">
          <div className="type-interpreter-header">
            <strong>Type Interpreter</strong>
            <label>
              <input
                type="checkbox"
                checked={littleEndian}
                onChange={(e) => setLittleEndian(e.target.checked)}
              />
              Little Endian
            </label>
          </div>
          <div className="type-interpreter-values">
            {typeInfo.byteCount && (
              <div className="type-value">
                <span className="type-label">Bytes:</span>
                <span className="type-data">{typeInfo.bytes}</span>
              </div>
            )}
            {typeInfo.u8 !== undefined && (
              <div className="type-value">
                <span className="type-label">u8:</span>
                <span className="type-data">{typeInfo.u8}</span>
              </div>
            )}
            {typeInfo.u16_be !== undefined && (
              <div className="type-value">
                <span className="type-label">u16 (BE):</span>
                <span className="type-data">{typeInfo.u16_be} / 0x{typeInfo.u16_be.toString(16).padStart(4, '0')}</span>
              </div>
            )}
            {typeInfo.u16_le !== undefined && (
              <div className="type-value">
                <span className="type-label">u16 (LE):</span>
                <span className="type-data">{typeInfo.u16_le} / 0x{typeInfo.u16_le.toString(16).padStart(4, '0')}</span>
              </div>
            )}
            {typeInfo.u32_be !== undefined && (
              <div className="type-value">
                <span className="type-label">u32 (BE):</span>
                <span className="type-data">{typeInfo.u32_be} / 0x{typeInfo.u32_be.toString(16).padStart(8, '0')}</span>
              </div>
            )}
            {typeInfo.u32_le !== undefined && (
              <div className="type-value">
                <span className="type-label">u32 (LE):</span>
                <span className="type-data">{typeInfo.u32_le} / 0x{typeInfo.u32_le.toString(16).padStart(8, '0')}</span>
              </div>
            )}
            {typeInfo.float32_be !== undefined && (
              <div className="type-value">
                <span className="type-label">f32 (BE):</span>
                <span className="type-data">{typeInfo.float32_be.toFixed(6)}</span>
              </div>
            )}
            {typeInfo.float32_le !== undefined && (
              <div className="type-value">
                <span className="type-label">f32 (LE):</span>
                <span className="type-data">{typeInfo.float32_le.toFixed(6)}</span>
              </div>
            )}
            {typeInfo.float64_be !== undefined && (
              <div className="type-value">
                <span className="type-label">f64 (BE):</span>
                <span className="type-data">{typeInfo.float64_be.toFixed(12)}</span>
              </div>
            )}
            {typeInfo.float64_le !== undefined && (
              <div className="type-value">
                <span className="type-label">f64 (LE):</span>
                <span className="type-data">{typeInfo.float64_le.toFixed(12)}</span>
              </div>
            )}
          </div>
        </div>
      )}

      <div
        ref={hexContainerRef}
        className="hex-viewer-scroll"
        style={{ height: containerHeight, overflowY: 'auto' }}
      >
        <div style={{ height: totalHeight, position: 'relative' }}>
          {virtualItems.map(({ index, top }) => (
            <HexRow
              key={index}
              index={index}
              style={{ position: 'absolute', top, height: HEX_ROW_HEIGHT_PX, width: '100%' }}
              {...hexRowItemData}
            />
          ))}
        </div>
      </div>
    </div>
  );
}

function CfgView({
  graph,
  naturalLoops,
  onNodeClick,
  highlightedBlockId,
  onBuildCfg,
}: {
  graph: CfgGraph | null;
  naturalLoops?: NaturalLoop[];
  onNodeClick?: (blockId: string, start: number, end: number) => void;
  highlightedBlockId?: string | null;
  onBuildCfg?: () => void;
}) {
  const [pathMode, setPathMode] = useState(false);
  const [pathStartId, setPathStartId] = useState<string | null>(null);
  const [pathEndId, setPathEndId] = useState<string | null>(null);

  const backEdgeKeys = useMemo(() => {
    const s = new Set<string>();
    for (const loop of naturalLoops ?? []) {
      const idx = loop.backEdgeKey.indexOf('->');
      if (idx >= 0) {
        const latch  = loop.backEdgeKey.slice(0, idx);
        const header = loop.backEdgeKey.slice(idx + 2);
        s.add(latch + '\x00' + header);
      }
    }
    return s;
  }, [naturalLoops]);

  const loopHeaders = useMemo(() => {
    const s = new Set<string>();
    for (const loop of naturalLoops ?? []) s.add(loop.header);
    return s;
  }, [naturalLoops]);

  const loopBodies = useMemo(() => {
    const m = new Map<string, number>();
    for (const loop of naturalLoops ?? []) {
      for (const blockId of loop.body) {
        const prev = m.get(blockId) ?? 0;
        if (loop.depth > prev) m.set(blockId, loop.depth);
      }
    }
    return m;
  }, [naturalLoops]);

  const exitBlocks = useMemo(() => {
    // A true CFG exit block has no outgoing edges (ends with ret/syscall).
    // block_type === 'external' nodes are *external jump/call targets* � different concept.
    const s = new Set<string>();
    if (graph) {
      const hasOutgoing = new Set(graph.edges.map(e => e.source));
      for (const node of graph.nodes) {
        if (node.block_type !== 'external' && !hasOutgoing.has(node.id)) s.add(node.id);
      }
    }
    return s;
  }, [graph]);

  // Dispatcher blocks: ≥6 outgoing branch edges and ≤5 instructions (CFF heuristic)
  const dispatcherBlocks = useMemo(() => {
    const s = new Set<string>();
    if (graph) {
      const branchCount = new Map<string, number>();
      for (const e of graph.edges) {
        if (e.kind === 'branch') branchCount.set(e.source, (branchCount.get(e.source) ?? 0) + 1);
      }
      for (const node of graph.nodes) {
        const bc = branchCount.get(node.id) ?? 0;
        const ic = node.instruction_count ?? 0;
        if (bc >= 6 && ic <= 5) s.add(node.id);
      }
    }
    return s;
  }, [graph]);

  const pathNodes = useMemo(() => {
    if (!graph || !pathMode || !pathStartId || !pathEndId) return undefined;
    const reachable = findPathNodesAnyRoute(graph, pathStartId, pathEndId);
    return reachable.size > 0 ? reachable : new Set<string>();
  }, [graph, pathMode, pathStartId, pathEndId]);

  const autoSelectPath = useCallback(() => {
    if (!graph || graph.nodes.length === 0) return;
    const entry = graph.nodes.find(n => n.block_type === 'entry') ?? graph.nodes[0];
    if (!entry) return;

    const candidates = graph.nodes.filter(n => n.id !== entry.id);
    const fallback = candidates[candidates.length - 1] ?? entry;

    let bestTarget = fallback;
    let bestSize = -1;
    for (const candidate of candidates) {
      const route = findPathNodesAnyRoute(graph, entry.id, candidate.id);
      if (route.size > bestSize) {
        bestSize = route.size;
        bestTarget = candidate;
      }
    }

    setPathMode(true);
    setPathStartId(entry.id);
    setPathEndId(bestTarget.id);
  }, [graph]);

  if (!graph || graph.nodes.length === 0) {
    return (
      <div className="panel">
        <h3>Control Flow Graph</h3>
        <p>No CFG loaded yet. Use &quot;Build CFG&quot; to analyze the control flow.</p>
        {onBuildCfg && (
          <button type="button" className="wf-action-btn wf-action-btn--primary" onClick={onBuildCfg} data-testid="cfg-build-empty-state">
            Build CFG
          </button>
        )}
      </div>
    );
  }

  const cfgData = {
    nodes: graph.nodes.map(n => ({
      id:                n.id,
      label:             n.label,
      start:             n.start,
      end:               n.end,
      instruction_count: n.instruction_count,
      block_type:        n.block_type,
      layout_x:          n.layout_x,
      layout_y:          n.layout_y,
    })),
    edges: graph.edges.map((e, i) => ({
      id:        e.source + '-' + e.target + '-' + String(i),
      source:    e.source,
      target:    e.target,
      kind:      e.kind,
      condition: e.condition,
    })),
  };

  const loopCount = naturalLoops?.length ?? 0;
  return (
    <div className="panel cfg-panel-modern">
      <div className="cfg-header-bar cfg-header-bar--modern">
        <h3 className="cfg-heading">Control Flow Graph</h3>
        <span className="cfg-heading-meta">
          {graph.nodes.length}{' blocks \u00b7 '}{graph.edges.length}{' edges'}
          {loopCount > 0 ? (' \u00b7 ' + loopCount + ' loop' + (loopCount > 1 ? 's' : '')) : ''}
        </span>
        <button
          type="button"
          title="Toggle execution path mode"
          onClick={() => {
            setPathMode(v => {
              const next = !v;
              if (!next) {
                setPathStartId(null);
                setPathEndId(null);
              }
              return next;
            });
          }}
          className={`cfg-toolbar-btn ${pathMode ? 'cfg-toolbar-btn--active' : ''}`}
        >
          {pathMode ? 'Path: ON' : 'Path: OFF'}
        </button>
        <button
          type="button"
          title="Auto-select strongest route from entry block"
          onClick={autoSelectPath}
          className="cfg-toolbar-btn"
        >
          Auto Route
        </button>
        {pathMode && (
          <span className="cfg-path-hint">
            {pathStartId && pathEndId
              ? `Path ${pathStartId} → ${pathEndId}${(pathNodes?.size ?? 0) > 0 ? ` (${pathNodes?.size ?? 0} nodes)` : ' (no route)'}`
              : pathStartId
              ? `Start ${pathStartId} selected — click end block`
              : 'Click start block, then end block'}
          </span>
        )}
        {pathMode && (pathStartId || pathEndId) && (
          <button
            type="button"
            title="Clear selected path endpoints"
            onClick={() => {
              setPathStartId(null);
              setPathEndId(null);
            }}
            className="cfg-toolbar-btn"
          >
            Clear Path
          </button>
        )}
        {loopCount > 0 && (
          <span className="cfg-inline-legend">
            <span><span className="cfg-legend-dot cfg-legend-dot--loop-header" />Loop header</span>
            <span><span className="cfg-legend-dot cfg-legend-dot--loop-body" />Loop body</span>
            <span title="Block with no outgoing edges (ret/syscall)"><span className="cfg-legend-dot cfg-legend-dot--exit" />Exit block</span>
            <span title="Jump/call target outside analyzed range"><span className="cfg-legend-dot cfg-legend-dot--external" />External</span>
          </span>
        )}
      </div>
      <div className="cfg-canvas-wrap">
        <ControlFlowGraph
          graph={cfgData}
          onNodeClick={(node) => {
            if (pathMode) {
              if (!pathStartId || (pathStartId && pathEndId)) {
                setPathStartId(node.id);
                setPathEndId(null);
              } else if (pathStartId && !pathEndId) {
                setPathEndId(node.id);
              }
            }
            if (node.start !== undefined && node.end !== undefined && onNodeClick) {
              onNodeClick(node.id, node.start, node.end);
            }
          }}
          highlightedBlockId={highlightedBlockId}
          backEdgeKeys={backEdgeKeys}
          loopHeaders={loopHeaders}
          loopBodies={loopBodies}
          exitBlocks={exitBlocks}
          dispatcherBlocks={dispatcherBlocks}
          pathNodes={pathNodes}
        />
      </div>
    </div>
  );
}

export default function App() {
  const browserMode = !hasTauriRuntime();
  const [binaryPath, setBinaryPath] = useState<string>(
    () => localStorage.getItem('hexhawk.binaryPath') ?? 'sample.bin'
  );
  const [recentFiles, setRecentFiles] = useState<string[]>(
    () => readStorageJson<string[]>('hexhawk.recentFiles', [])
  );
  const [showWelcome, setShowWelcome] = useState<boolean>(() => shouldShowWelcome());
  const [activeTab, setActiveTab] = useState<AppTab>(
    () => (localStorage.getItem('hexhawk.activeTab') as AppTab) ?? 'metadata'
  );
  const [activeView, setActiveView] = useState<NavView>(
    () => (localStorage.getItem('hexhawk.activeView') as NavView) ?? 'inspect'
  );
  const [message, setMessage] = useState('Ready for analysis');

  // ─── Tier system ────────────────────────────────────────────────────────────
  const [tier, setTierState] = useState<Tier>(() => loadTier());
  const effectiveTier: Tier = browserMode ? 'enterprise' : tier;
  const [consoleQueriesUsed, setConsoleQueriesUsed] = useState<number>(
    () => loadConsoleQueriesUsed()
  );
  const [isTrial, setIsTrial] = useState(false);
  const [buildInfo, setBuildInfo] = useState<{ version: string; is_trial: boolean } | null>(null);
  const [activeLicense, setActiveLicense] = useState<LicenseInfo | null>(null);
  const [showLicensePanel, setShowLicensePanel] = useState(false);
  const [isDragOver, setIsDragOver] = useState(false);

  // Tauri file drag-and-drop listener
  useEffect(() => {
    if (!hasTauriRuntime()) {
      return;
    }

    let disposed = false;
    const unlistenFns: Array<() => void> = [];

    const registerUnlisten = (promise: Promise<() => void>) => {
      promise.then((fn) => {
        if (disposed) {
          fn();
          return;
        }
        unlistenFns.push(fn);
      }).catch(() => {
        // no-op on listener registration failure
      });
    };

    registerUnlisten(listen<{ paths: string[] }>('tauri://drag-drop', (event) => {
      setIsDragOver(false);
      const paths = event.payload?.paths;
      if (paths && paths.length > 0) {
        try {
          prepareForBinarySelection(sanitizeBridgePath(paths[0], 'dropped file path'));
        } catch {
          setMessage('Ignored dropped path: invalid input');
        }
      }
    }));
    registerUnlisten(listen('tauri://drag-over', () => setIsDragOver(true)));
    registerUnlisten(listen('tauri://drag-leave', () => setIsDragOver(false)));

    return () => {
      disposed = true;
      for (const fn of unlistenFns) fn();
    };
  }, []);

  // On mount: detect trial build + restore previously activated license
  useEffect(() => {
    if (!hasTauriRuntime()) {
      setIsTrial(false);
      setBuildInfo({ version: '1.0.0-web', is_trial: false });
      setTierState('enterprise');
      saveTier('enterprise');
      return;
    }

    getBuildInfo().then((info) => {
      setIsTrial(info.is_trial);
      setBuildInfo(info);
      if (info.is_trial) {
        // Trial binary: tier is determined by how many days have elapsed.
        // Days 0-15: full Enterprise access for testers
        // Days 16-30: Enterprise locked ? Pro only
        // Days 31+:   Pro locked ? Free only
        const trialTier: Tier = info.pro_locked
          ? 'free'
          : info.enterprise_locked
            ? 'pro'
            : 'enterprise';
        setTierState(trialTier);
        saveTier(trialTier);
        return;
      }
      // Full binary: attempt to restore stored license key
      const storedKey = loadLicenseKey();
      if (storedKey) {
        verifyLicense(storedKey).then((licInfo) => {
          setActiveLicense(licInfo);
          setTierState(licInfo.tier as Tier);
          saveTier(licInfo.tier as Tier);
        }).catch(() => {
          // Stored key is invalid / expired � fall back to manual tier
        });
      }
    }).catch(() => {
      // Backend not yet ready in dev � silently ignore
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function setTier(t: Tier) {
    saveTier(t);
    setTierState(t);
  }
  /** Gate helper: returns TierGate if tier is insufficient, otherwise returns content. */
  function gateTab(tab: string, label: string, content: React.ReactNode): React.ReactNode {
    const minTier = (TAB_MIN_TIER[tab] ?? 'free') as Tier;
    if (!tierAtLeast(effectiveTier, minTier)) {
      return <TierGate tab={tab} tabLabel={label} requiredTier={minTier} currentTier={effectiveTier} onTierChange={setTier} />;
    }
    return content;
  }


  const [metadata, setMetadata] = useState<FileMetadata | null>(null);
  const [peExtras, setPeExtras] = useState<{ tls_callbacks: Array<{ address: number }>; resources: Array<{ type_name: string; id: number; size: number; offset: number }> } | null>(null);
  const [hexBytes, setHexBytes] = useState<number[]>([]);
  const [hexOffset, setHexOffset] = useState<number>(
    () => readStorageInt('hexhawk.hexOffset', 0, 0, Number.MAX_SAFE_INTEGER)
  );
  const [hexLength, setHexLength] = useState<number>(
    () => readStorageInt('hexhawk.hexLength', 256, 1, 1024 * 1024)
  );
  const [selectedHexIndex, setSelectedHexIndex] = useState<number | null>(null);
  const [selectedDisasmAddress, setSelectedDisasmAddress] = useState<number | null>(null);
  const [disasmOffset, setDisasmOffset] = useState<number>(
    () => readStorageInt('hexhawk.disasmOffset', 0, 0, Number.MAX_SAFE_INTEGER)
  );
  const [disasmLength, setDisasmLength] = useState<number>(
    () => readStorageInt('hexhawk.disasmLength', 256, 1, 1024 * 1024)
  );
  const [disassembly, setDisassembly] = useState<DisassembledInstruction[]>([]);
  const [disasmArch, setDisasmArch] = useState<string | null>(null);
  const [disasmArchFallback, setDisasmArchFallback] = useState<boolean>(false);
  const [disasmHasMore, setDisasmHasMore] = useState<boolean>(false);
  const [disasmNextByteOffset, setDisasmNextByteOffset] = useState<number | null>(null);
  const [disasmIsLoadingMore, setDisasmIsLoadingMore] = useState<boolean>(false);
  const [disasmIsLoading, setDisasmIsLoading] = useState<boolean>(false);
  const [cfg, setCfg] = useState<CfgGraph | null>(null);
  const [cfgNaturalLoops, setCfgNaturalLoops] = useState<NaturalLoop[]>([]);
  const [cfgDomTree, setCfgDomTree] = useState<DomTree | null>(null);
  const [cfgPostDomTree, setCfgPostDomTree] = useState<DomTree | null>(null);
  const [showDomPanel, setShowDomPanel] = useState<boolean>(
    () => localStorage.getItem('hexhawk.showDomPanel') === 'true'
  );
  const [strings, setStrings] = useState<StringMatch[]>([]);
  const [stringFilter, setStringFilter] = useState<string>('');
  const [stringKindFilter, setStringKindFilter] = useState<StringKind | 'all'>('all');
  const [stringMinLength, setStringMinLength] = useState<number>(
    () => readStorageInt('hexhawk.stringMinLength', 4, 1, 2048)
  );
  const [pluginResults, setPluginResults] = useState<PluginExecutionResult[]>([]);
  const [plugins, setPlugins] = useState<PluginMetadata[]>([]);
  const [selectedPluginName, setSelectedPluginName] = useState<string>('');
  const [pluginManagerKey, setPluginManagerKey] = useState(0);
  const [reloading, setReloading] = useState<string | null>(null);
  const [reloadStatus, setReloadStatus] = useState<Record<string, 'success' | 'error'>>({});
  const [expandedAnalysis, setExpandedAnalysis] = useState<Record<number, boolean>>({});
  const [logs, setLogs] = useState<LogEntry[]>([]);

  // Global interconnection state - single source of truth
  const [currentAddress, setCurrentAddress] = useState<number | null>(null);
  const [currentRange, setCurrentRange] = useState<{ start: number; end: number } | null>(null);
  const [highlightedHexRange, setHighlightedHexRange] = useState<{ start: number; end: number } | undefined>(undefined);
  const [highlightedDisasmRange, setHighlightedDisasmRange] = useState<{ start: number; end: number } | null>(null);
  const [highlightedCfgBlock, setHighlightedCfgBlock] = useState<string | null>(null);
  const [highlightedStrings, setHighlightedStrings] = useState<Set<number>>(new Set());

  // NEW: Bookmarks, patches, and history
  const [bookmarks, setBookmarks] = useState<Bookmark[]>([]);
  const [patches, setPatches] = useState<Patch[]>([]);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [historyIndex, setHistoryIndex] = useState<number>(-1);
  const [showKeyboardHelp, setShowKeyboardHelp] = useState<boolean>(false);
  const [showQaSources, setShowQaSources] = useState<boolean>(false);

  // PHASE 5: Advanced Analysis Results
  const [disassemblyAnalysis, setDisassemblyAnalysis] = useState<DisassemblyAnalysis>({
    functions: new Map(),
    loops: [],
    suspiciousPatterns: [],
    referenceStrength: new Map(),
    blockAnalysis: new Map(),
  });
  const [selectedFunction, setSelectedFunction] = useState<number | null>(
    () => {
      const value = readStorageInt('hexhawk.selectedFunction', 0, 0, Number.MAX_SAFE_INTEGER);
      return value || null;
    }
  );
  const [expandedFunctions, setExpandedFunctions] = useState<Set<number>>(new Set());

  // NEST-enriched verdict � set when a NEST session completes; cleared on new file load
  const [nestEnrichedVerdict, setNestEnrichedVerdict] = useState<BinaryVerdictResult | null>(null);
  React.useEffect(() => { setNestEnrichedVerdict(null); }, [binaryPath]);

  // Self-heal banner dismiss state — reset when the binary changes
  const [healDismissed, setHealDismissed] = useState(false);
  const [showSelfHealBanner, setShowSelfHealBanner] = useState(false);
  React.useEffect(() => { setHealDismissed(false); }, [binaryPath]);
  React.useEffect(() => { setShowSelfHealBanner(false); }, [binaryPath]);

  // M12: Agent-approved signals (declared here so verdict memo can depend on them)
  const [approvedAgentSignals, setApprovedAgentSignals] = useState<Array<{ id: string; finding: string; weight: number; certainty?: 'observed' | 'inferred' | 'heuristic' }>>([]);

  // Unified threat verdict � correlates structure, imports, strings, disassembly
  const verdict = useMemo<BinaryVerdictResult>(() => {
    if (!metadata) {
      return computeVerdict({ sections: [], imports: [], strings: [], patterns: [] });
    }
    return computeVerdict({
      sections: (metadata.sections ?? []).map(s => ({
        name: s.name,
        entropy: s.entropy ?? 0,
        file_size: s.file_size ?? 0,
      })),
      imports: metadata.imports ?? [],
      strings: strings.map(s => ({ text: s.text })),
      patterns: disassemblyAnalysis.suspiciousPatterns,
      agentSignals: approvedAgentSignals.length > 0 ? approvedAgentSignals : undefined,
    });
  }, [metadata, strings, disassemblyAnalysis.suspiciousPatterns, approvedAgentSignals]);


  // --- Patch Intelligence suggestions ---
  const patchSuggestions = useMemo(() =>
    disassembly.length > 0
      ? detectPatchableBranches(
          disassembly.map(i => ({ address: i.address, mnemonic: i.mnemonic, operands: i.operands ?? '' })),
          verdict,
          [],
        )
      : [],
  [disassembly, verdict]);
  // ─── Workflow state machine ────────────────────────────────────────────────
  const workflowState = useMemo<WorkflowState>(() => {
    const isDefault = binaryPath === 'sample.bin' || binaryPath === '';
    if (isDefault && !metadata) return 'noFile';
    if (!metadata) return 'fileLoaded';
    const hasAnalysis = disassembly.length > 0 || strings.length > 0 || (cfg !== null && cfg.nodes.length > 0);
    if (hasAnalysis) return 'analyzed';
    return 'inspected';
  }, [binaryPath, metadata, disassembly, strings, cfg]);

  // ─── Self-heal diagnosis ───────────────────────────────────────────────────
  const healDiagnosis = useMemo(() => diagnose({
    hasMetadata: !!metadata,
    disassemblyCount: disassembly.length,
    stringCount: strings.length,
    hasCfg: !!(cfg && cfg.nodes.length > 0),
    hasStrike: false, // extended when STRIKE session is active
    hasNest: !!nestEnrichedVerdict,
    verdict: nestEnrichedVerdict ?? verdict,
  }), [metadata, disassembly, strings, cfg, nestEnrichedVerdict, verdict]);

  function navigateView(view: NavView) {
    setActiveView(view);
    localStorage.setItem('hexhawk.activeView', view);
    // Mirror to legacy tab system
    const viewToTab: Partial<Record<NavView, AppTab>> = {
      metadata: 'metadata', inspect: 'metadata', hex: 'hex', strings: 'strings',
      disassembly: 'disassembly', cfg: 'cfg', decompile: 'decompile',
      talon: 'talon',
      verdict: 'graph', signals: 'metadata', nest: 'nest',
      activity: 'logs', patch: 'disassembly', constraint: 'constraint',
      sandbox: 'sandbox', debugger: 'debugger', plugins: 'plugins',
      diff: 'diff', repl: 'repl', agent: 'agent',
    };
    const tab = viewToTab[view];
    if (tab) setAndPersistTab(tab);
  }

  const panelFidelity = useMemo<{ source: SubsystemSource; detail: string }>(() => {
    return getPanelFidelityForView(activeView, browserMode);
  }, [activeView, browserMode]);

  const qaSubsystemStatuses = useMemo<QASubsystemStatus[]>(() => {
    return getQaSubsystemStatuses(browserMode);
  }, [browserMode]);

  const seededSignalsAddress = useMemo<number>(() => {
    if (selectedDisasmAddress !== null) return selectedDisasmAddress;
    if (disassemblyAnalysis.suspiciousPatterns.length > 0) {
      return disassemblyAnalysis.suspiciousPatterns[0].address;
    }
    if (disassembly.length > 0) {
      return disassembly[0].address;
    }
    return 0;
  }, [selectedDisasmAddress, disassemblyAnalysis.suspiciousPatterns, disassembly]);

  useEffect(() => {
    if (typeof window === 'undefined') return;

    (window as unknown as { __HEXHAWK_RUNTIME_SNAPSHOT__?: unknown }).__HEXHAWK_RUNTIME_SNAPSHOT__ = {
      timestamp: new Date().toISOString(),
      runtime: {
        hasTauriRuntime: hasTauriRuntime(),
        browserMode,
      },
      binaryPath,
      activeView,
      workflowState,
      panelFidelity,
      qaSubsystemStatuses,
      metadata: metadata
        ? {
            fileType: metadata.file_type,
            architecture: metadata.architecture,
            fileSize: metadata.file_size,
            sha256: metadata.sha256,
            entryPoint: metadata.entry_point,
          }
        : null,
      strings: {
        count: strings.length,
        sample: strings.slice(0, 10).map((s) => ({ offset: s.offset, text: s.text })),
      },
      disassembly: {
        count: disassembly.length,
        arch: disasmArch,
        fallback: disasmArchFallback,
        sample: disassembly.slice(0, 12).map((i) => ({
          address: i.address,
          mnemonic: i.mnemonic,
          operands: i.operands ?? '',
        })),
      },
      cfg: {
        nodes: cfg?.nodes.length ?? 0,
        edges: cfg?.edges.length ?? 0,
      },
      plugins: {
        availableCount: plugins.length,
        resultCount: pluginResults.length,
        resultSample: pluginResults.slice(0, 6).map((r) => ({
          name: r.plugin,
          success: r.success,
          outputPreview: r.summary.slice(0, 160),
        })),
      },
      patches: {
        queuedCount: patches.length,
        sample: patches.slice(0, 10).map((p) => ({
          address: p.address,
          label: p.label,
        })),
      },
      nest: {
        enriched: nestEnrichedVerdict
          ? {
              confidence: nestEnrichedVerdict.confidence ?? nestEnrichedVerdict.threatScore,
              signals: nestEnrichedVerdict.signals.length,
            }
          : null,
      },
      activity: logs.slice(0, 20).map((entry) => ({
        level: entry.level,
        message: entry.message,
      })),
    };
  }, [
    activeView,
    binaryPath,
    browserMode,
    cfg,
    disasmArch,
    disasmArchFallback,
    disassembly,
    logs,
    metadata,
    nestEnrichedVerdict,
    panelFidelity,
    patches,
    pluginResults,
    plugins,
    qaSubsystemStatuses,
    strings,
    workflowState,
  ]);

  // PHASE 8: Auto-annotation engine state
  const [autoAnnotations, setAutoAnnotations] = useState<AutoAnnotation[]>([]);

  // M12: Agent signal approval gate & action log
  type AgentSignalPending = {
    pendingId: string;
    sessionId: string;
    signal: { id: string; finding: string; weight: number; certainty: 'observed' | 'inferred' | 'heuristic' };
    receivedAt: number;
  };
  type AgentActionEntry = {
    id: string;
    tool: string;
    summary: string;
    timestamp: number;
    approved: boolean | null; // null = pending
  };
  const [pendingAgentSignals, setPendingAgentSignals] = useState<AgentSignalPending[]>([]);
  const [agentActionLog, setAgentActionLog] = useState<AgentActionEntry[]>([]);

  const handleApproveAgentSignal = React.useCallback((pendingId: string) => {
    setPendingAgentSignals(prev => {
      const entry = prev.find(p => p.pendingId === pendingId);
      if (!entry) return prev;
      setApprovedAgentSignals(a => [...a, entry.signal]);
      setAgentActionLog(log => [...log, {
        id: pendingId,
        tool: 'inject_agent_signal',
        summary: `Approved: "${entry.signal.finding}" (weight ${entry.signal.weight})`,
        timestamp: Date.now(),
        approved: true,
      }]);
      return prev.filter(p => p.pendingId !== pendingId);
    });
  }, []);

  const handleRejectAgentSignal = React.useCallback((pendingId: string) => {
    setPendingAgentSignals(prev => {
      const entry = prev.find(p => p.pendingId === pendingId);
      if (!entry) return prev;
      setAgentActionLog(log => [...log, {
        id: pendingId,
        tool: 'inject_agent_signal',
        summary: `Rejected: "${entry.signal.finding}"`,
        timestamp: Date.now(),
        approved: false,
      }]);
      return prev.filter(p => p.pendingId !== pendingId);
    });
  }, []);
  React.useEffect(() => {
    const newAnnotations = generateAutoAnnotations({
      imports: metadata?.imports ?? [],
      strings: strings.map(s => ({ offset: s.offset, text: s.text })),
      disassembly: disassembly.map(i => ({ address: i.address, mnemonic: i.mnemonic, operands: i.operands })),
      patterns: disassemblyAnalysis.suspiciousPatterns,
      sectionEntropies: (metadata?.sections ?? []).map(s => ({ name: s.name, entropy: s.entropy ?? 0 })),
    });
    setAutoAnnotations(newAnnotations);
  }, [metadata, strings, disassembly, disassemblyAnalysis.suspiciousPatterns]);

  // PHASE 8: Semantic search state
  const [semanticQuery, setSemanticQuery] = useState<string>('');
  const [semanticResult, setSemanticResult] = useState<SemanticSearchResult | null>(null);

  const runSemanticSearch = (query: string): SemanticSearchResult | null => {
    if (!query.trim()) {
      setSemanticResult(null);
      addLog('Semantic query skipped: empty input.', 'warn');
      return null;
    }
    const result = semanticSearch(query, {
      imports: metadata?.imports ?? [],
      strings: strings.map(s => ({ offset: s.offset, text: s.text })),
      patterns: disassemblyAnalysis.suspiciousPatterns,
    });
    setSemanticResult(result);
    if (result.bestMatch) {
      addLog(`Semantic query matched "${result.bestMatch.intentName}" (${result.bestMatch.confidence}% confidence).`, 'info');
    } else {
      addLog(`Semantic query returned no matches for "${query.trim()}".`, 'warn');
    }
    return result;
  };

  // PHASE 6: Persistent UI state for improved UX
  const [functionBrowserSearch, setFunctionBrowserSearch] = useState<string>('');
  const [showAnalysisPanel, setShowAnalysisPanel] = useState<boolean>(
    () => localStorage.getItem('hexhawk.showAnalysisPanel') !== 'false'
  );
  const [showFunctionBrowser, setShowFunctionBrowser] = useState<boolean>(
    () => localStorage.getItem('hexhawk.showFunctionBrowser') !== 'false'
  );
  const [showSmartSuggestions, setShowSmartSuggestions] = useState<boolean>(
    () => localStorage.getItem('hexhawk.showSmartSuggestions') !== 'false'
  );

  // Helper: Update global address and sync all views
  const selectAddress = (address: number, range?: { start: number; end: number }) => {
    setCurrentAddress(address);
    if (range) {
      setCurrentRange(range);
      setHighlightedHexRange(range);
      setHighlightedDisasmRange(range);
    } else {
      const range = { start: address, end: address + 1 };
      setCurrentRange(range);
      setHighlightedHexRange(range);
      setHighlightedDisasmRange(range);
    }
  };

  // Helper: Highlight hex range in other views
  const selectHexRange = (start: number, end: number) => {
    setHighlightedHexRange({ start, end });
    setCurrentRange({ start, end });
    setCurrentAddress(start);
    // Try to find and highlight corresponding disasm
    const disasmInstr = disassembly.find(ins => ins.address >= start && ins.address < end);
    if (disasmInstr) {
      setHighlightedDisasmRange({ start: disasmInstr.address, end: disasmInstr.address + 1 });
    }
  };

  // Helper: Highlight disasm range in other views
  const selectDisasmRange = (start: number, end: number) => {
    setHighlightedDisasmRange({ start, end });
    setCurrentRange({ start, end });
    setCurrentAddress(start);
    setHighlightedHexRange({ start, end });
  };

  // Helper: Highlight CFG block and sync disasm
  const selectCfgBlock = (blockId: string, start: number, end: number) => {
    setHighlightedCfgBlock(blockId);
    setCurrentAddress(start);
    setCurrentRange({ start, end });
    setHighlightedDisasmRange({ start, end });
    setHighlightedHexRange({ start, end });
  };

  // NEW: Transient highlighting (for fade animations)
  const [transientHighlight, setTransientHighlight] = useState<{
    type: 'hex' | 'disasm' | 'cfg';
    element?: HTMLElement;
    timeout?: ReturnType<typeof setTimeout>;
  } | null>(null);
  const uiTimeoutIdsRef = useRef<number[]>([]);

  const scheduleUiTimeout = useCallback((fn: () => void, ms: number): number => {
    const id = window.setTimeout(() => {
      uiTimeoutIdsRef.current = uiTimeoutIdsRef.current.filter((x) => x !== id);
      fn();
    }, ms);
    uiTimeoutIdsRef.current.push(id);
    return id;
  }, []);

  useEffect(() => {
    return () => {
      for (const id of uiTimeoutIdsRef.current) {
        window.clearTimeout(id);
      }
      uiTimeoutIdsRef.current = [];
    };
  }, []);

  // NEW: Cross-reference map (address -> set of addresses that reference it)
  const [referencesMap, setReferencesMap] = useState<Map<number, Set<number>>>(new Map());
  const [jumpTargetsMap, setJumpTargetsMap] = useState<Map<number, Set<number>>>(new Map());

  // NEW: Map from instruction address to its block (for range intelligence)
  const [addressToBlockMap, setAddressToBlockMap] = useState<Map<number, { blockId: string; start: number; end: number }>>(new Map());

  // Build reference maps from disassembly
  // NEW: Reference type tracking for advanced analysis
  type XRefKind = 'CALL' | 'JMP' | 'JMP_COND' | 'DATA' | 'STRING' | 'RIP_REL';
  const [xrefTypes, setXrefTypes] = useState<Map<string, XRefKind>>(new Map());  // key: "src:dst"

  // NEW: Jump-to-address dialog state
  const [showJumpDialog, setShowJumpDialog] = useState<boolean>(false);
  const [recentJumpAddresses, setRecentJumpAddresses] = useState<number[]>(
    () => readStorageJson<number[]>('hexhawk.recentJumpAddresses', [])
  );
  const [showReferencesPanel, setShowReferencesPanel] = useState<boolean>(
    () => localStorage.getItem('hexhawk.showReferencesPanel') !== 'false'
  );

  // NEW: User annotations (address → note text)
  const [annotations, setAnnotations] = useState<Map<number, string>>(
    () => {
      try {
        const raw = localStorage.getItem('hexhawk.annotations');
        if (!raw) return new Map();
        return new Map(JSON.parse(raw) as [number, string][]);
      } catch { return new Map(); }
    }
  );

  // NEW: Hex viewer display options
  const [hexGrouping, setHexGrouping] = useState<1 | 2 | 4 | 8>(
    () => (Number(localStorage.getItem('hexhawk.hexGrouping') ?? 1) as 1 | 2 | 4 | 8) || 1
  );
  const [hexHighlightMode, setHexHighlightMode] = useState<'none' | 'null' | 'printable' | 'entropy'>(
    () => (localStorage.getItem('hexhawk.hexHighlightMode') as 'none' | 'null' | 'printable' | 'entropy') ?? 'none'
  );

  // UPGRADE: Enhanced reference detection (Phase 2: Reference Detection v2)
  const buildReferenceMaps = (instructions: DisassembledInstruction[]) => {
    const refMap = new Map<number, Set<number>>();
    const targetMap = new Map<number, Set<number>>();
    const xrefTypeMap = new Map<string, XRefKind>();

    // Helper: Detect instruction type from mnemonic
    const getInstructionType = (mnemonic: string): XRefKind | null => {
      const m = mnemonic.toLowerCase();
      if (m.startsWith('call')) return 'CALL';
      if (m.startsWith('j') && m !== 'jmp') return 'JMP_COND';  // je, jne, jl, etc.
      if (m === 'jmp') return 'JMP';
      if (m.startsWith('mov') || m.startsWith('lea') || m.startsWith('add') || m.startsWith('sub')) return 'DATA';
      return null;
    };

    // Helper: Extract addresses from operands with RIP-relative detection
    const extractAddressesFromOperands = (
      address: number,
      mnemonic: string,
      operands: string
    ): { address: number; kind: XRefKind }[] => {
      const results: { address: number; kind: XRefKind }[] = [];
      const baseType = getInstructionType(mnemonic);

      // Pattern 1: Direct hex addresses (0xNNNN)
      const hexMatches = operands.matchAll(/\b0x[0-9a-fA-F]+\b/g);
      for (const match of hexMatches) {
        const targetAddr = parseInt(match[0], 16);
        const kind = baseType || 'DATA';
        results.push({ address: targetAddr, kind });
      }

      // Pattern 2: RIP-relative addressing (x86-64 very common)
      // Formats: [rip+0xNNN], [rip-0xNNN], rip+0xNNN
      const ripMatches = operands.matchAll(/\[?rip\s*[+-]\s*0x([0-9a-fA-F]+)\]?/gi);
      for (const match of ripMatches) {
        const offset = parseInt(match[1], 16);
        const isNegative = match[0].includes('-');
        // RIP-relative: effective address = next_instruction_address + signed_offset
        const nextInstructionAddr = address + 7;  // Approximate (actual varies by instr length)
        const targetAddr = isNegative ? nextInstructionAddr - offset : nextInstructionAddr + offset;
        results.push({ address: targetAddr, kind: 'RIP_REL' });
      }

      // Pattern 3: Negative/backward jumps (jmp -0x10)
      const negativeMatches = operands.matchAll(/\b-0x([0-9a-fA-F]+)\b/g);
      for (const match of negativeMatches) {
        const offset = parseInt(match[1], 16);
        const targetAddr = address - offset;
        const kind = baseType || 'JMP_COND';
        results.push({ address: targetAddr, kind });
      }

      // Pattern 4: Memory operands with absolute addresses [0xNNNN]
      const memMatches = operands.matchAll(/\[\s*(0x[0-9a-fA-F]+)\s*\]/g);
      for (const match of memMatches) {
        const targetAddr = parseInt(match[1], 16);
        results.push({ address: targetAddr, kind: 'DATA' });
      }

      return results;
    };

    // Build maps
    instructions.forEach((ins) => {
      if (ins.operands) {
        const targets = extractAddressesFromOperands(ins.address, ins.mnemonic, ins.operands);

        targets.forEach(({ address: targetAddr, kind }) => {
          // Add to target map (what does this instruction reference)
          if (!targetMap.has(ins.address)) {
            targetMap.set(ins.address, new Set());
          }
          targetMap.get(ins.address)!.add(targetAddr);

          // Add to reference map (who references this address)
          if (!refMap.has(targetAddr)) {
            refMap.set(targetAddr, new Set());
          }
          refMap.get(targetAddr)!.add(ins.address);

          // Track xref type
          const key = `${ins.address}:${targetAddr}`;
          xrefTypeMap.set(key, kind);
        });
      }
    });

    setJumpTargetsMap(targetMap);
    setReferencesMap(refMap);
    setXrefTypes(xrefTypeMap);  // NEW: Store xref types for UI rendering
  };

  // Build address to block map from CFG
  const buildAddressToBlockMap = (graph: CfgGraph) => {
    const map = new Map<number, { blockId: string; start: number; end: number }>();
    graph.nodes.forEach((node) => {
      if (node.start !== undefined && node.end !== undefined) {
        for (let addr = node.start; addr < node.end; addr++) {
          map.set(addr, {
            blockId: node.id,
            start: node.start,
            end: node.end,
          });
        }
      }
    });
    setAddressToBlockMap(map);
  };

  // NEW: Helper for instruction type coloring
  const getInstructionTypeInfo = (mnemonic: string): { type: string; color: string; badge: string } => {
    const m = mnemonic.toLowerCase();
    if (m.startsWith('call')) {
      return { type: 'CALL', color: '#ff9f64', badge: '◉' };  // Orange
    } else if (m.startsWith('j') && m !== 'jmp') {
      return { type: 'JMP_COND', color: '#f7768e', badge: '⟲' };  // Red
    } else if (m === 'jmp') {
      return { type: 'JMP', color: '#ff9f64', badge: '⟹' };  // Orange
    } else if (m.startsWith('ret')) {
      return { type: 'RET', color: '#bb9af7', badge: '↲' };  // Purple
    } else if (m.startsWith('mov') || m.startsWith('lea')) {
      return { type: 'MOV', color: '#7aa2f7', badge: '=' };  // Blue
    } else if (m.startsWith('add') || m.startsWith('sub') || m.startsWith('xor') || m.startsWith('and') || m.startsWith('or')) {
      return { type: 'ALU', color: '#9ece6a', badge: '◆' };  // Green
    } else if (m.startsWith('nop')) {
      return { type: 'NOP', color: '#565f89', badge: '-' };  // Gray
    }
    return { type: 'OTHER', color: '#9d9d9d', badge: '·' };
  };

  // Helper: Find containing block for an address
  const findBlockForAddress = (address: number): { blockId: string; start: number; end: number } | undefined => {
    return addressToBlockMap.get(address);
  };

  // NEW: Enhanced selectDisasmRange with auto-block expansion
  const selectDisasmRangeEnhanced = (address: number, instructionLength?: number) => {
    // Try to expand to full block if available
    const block = findBlockForAddress(address);
    if (block) {
      setHighlightedDisasmRange({ start: block.start, end: block.end });
      setCurrentRange({ start: block.start, end: block.end });
      setCurrentAddress(address);
      setHighlightedHexRange({ start: block.start, end: block.end });
    } else {
      // Fallback to instruction-level
      const end = instructionLength ? address + instructionLength : address + 1;
      setHighlightedDisasmRange({ start: address, end });
      setCurrentRange({ start: address, end });
      setCurrentAddress(address);
      setHighlightedHexRange({ start: address, end });
    }
  };

  // Helper: Smooth scroll with center position
  const smoothScrollToElement = (element: HTMLElement, view: 'hex' | 'disasm') => {
    if (!element) return;
    
    // Small delay to ensure view is rendered
    scheduleUiTimeout(() => {
      element.scrollIntoView({
        behavior: 'smooth',
        block: 'center',
      });
    }, 10);
  };

  // ===== PHASE 5: ANALYSIS FUNCTIONS =====

  // Detect function boundaries using heuristics
  const detectFunctions = (
    instructions: DisassembledInstruction[],
    refMap: Map<number, Set<number>>,
    targetMap: Map<number, Set<number>>
  ): Map<number, FunctionMetadata> => {
    const functions = new Map<number, FunctionMetadata>();
    if (instructions.length === 0) return functions;

    const callTargets = new Set<number>();
    const jumpTargets = new Set<number>();
    const addrToIndex = new Map<number, number>();
    instructions.forEach((ins, idx) => {
      addrToIndex.set(ins.address, idx);
      const mn = ins.mnemonic.toLowerCase();
      const targets = targetMap.get(ins.address) || new Set();
      if (mn.startsWith('call')) {
        targets.forEach((addr) => callTargets.add(addr));
      }
      if (mn.startsWith('j')) {
        targets.forEach((addr) => jumpTargets.add(addr));
      }
    });

    const candidateStarts = new Set<number>([instructions[0].address, ...callTargets]);
    for (let i = 0; i < instructions.length; i++) {
      const ins = instructions[i];
      const mn = ins.mnemonic.toLowerCase();

      // Canonical frame-setup prologue
      if (
        mn === 'push' &&
        ins.operands.includes('rbp') &&
        i + 1 < instructions.length &&
        instructions[i + 1].mnemonic.toLowerCase().startsWith('mov') &&
        instructions[i + 1].operands.includes('rbp')
      ) {
        candidateStarts.add(ins.address);
      }

      // Frame allocation style prologue
      if (mn.startsWith('sub') && ins.operands.includes('rsp')) {
        candidateStarts.add(ins.address);
      }
    }

    // Promote jump targets that look like true entries (prologue-like)
    for (const tgt of jumpTargets) {
      const idx = addrToIndex.get(tgt);
      if (idx === undefined) continue;
      const cur = instructions[idx];
      const nxt = instructions[idx + 1];
      const mn = cur.mnemonic.toLowerCase();
      const looksLikePrologue =
        (mn === 'push' && cur.operands.includes('rbp') && !!nxt && nxt.mnemonic.toLowerCase().startsWith('mov')) ||
        (mn.startsWith('sub') && cur.operands.includes('rsp'));
      if (looksLikePrologue) candidateStarts.add(tgt);
    }

    const sortedStarts = [...candidateStarts]
      .filter((addr) => addrToIndex.has(addr))
      .sort((a, b) => a - b);

    for (let s = 0; s < sortedStarts.length; s++) {
      const funcStart = sortedStarts[s];
      const startIdx = addrToIndex.get(funcStart);
      if (startIdx === undefined) continue;

      const nextStart = sortedStarts[s + 1];
      const nextStartIdx = nextStart !== undefined ? addrToIndex.get(nextStart) : undefined;
      const endBoundIdx = nextStartIdx !== undefined ? Math.max(startIdx, nextStartIdx - 1) : instructions.length - 1;
      const funcInstructions = instructions.slice(startIdx, endBoundIdx + 1);
      if (funcInstructions.length === 0) continue;

      const first = funcInstructions[0];
      const second = funcInstructions[1];
      let prologueType: FunctionMetadata['prologueType'] = undefined;
      if (
        first.mnemonic.toLowerCase() === 'push' &&
        first.operands.includes('rbp') &&
        !!second &&
        second.mnemonic.toLowerCase().startsWith('mov')
      ) {
        prologueType = 'push_rbp';
      } else if (first.mnemonic.toLowerCase().startsWith('sub') && first.operands.includes('rsp')) {
        prologueType = 'sub_rsp';
      } else if (callTargets.has(funcStart)) {
        prologueType = 'custom';
      }

      let callCount = 0;
      let returnCount = 0;
      for (const ins of funcInstructions) {
        const mn = ins.mnemonic.toLowerCase();
        if (mn.startsWith('call')) callCount++;
        if (mn.startsWith('ret')) returnCount++;
      }

      const incomingCalls = refMap.get(funcStart) || new Set<number>();
      const hasRet = returnCount > 0;
      const isEntryCandidate = s === 0;
      const strongEvidence = !!prologueType || hasRet || incomingCalls.size > 0 || isEntryCandidate;
      if (!strongEvidence) continue;

      const funcEnd = funcInstructions[funcInstructions.length - 1].address;
      const size = Math.max(0, funcEnd - funcStart);
      const isRecursive = incomingCalls.has(funcStart);

      let hasTailCall = false;
      for (let k = funcInstructions.length - 1; k >= 0; k--) {
        const ins = funcInstructions[k];
        const mn = ins.mnemonic.toLowerCase();
        if (mn === 'ret') break;
        if (mn === 'jmp' || mn === 'jmpq') {
          const jmpTargets = targetMap.get(ins.address);
          if (jmpTargets) {
            for (const tgt of jmpTargets) {
              if (tgt < funcStart || tgt > funcEnd) { hasTailCall = true; break; }
            }
          }
          break;
        }
      }

      let callingConvention: FunctionMetadata['callingConvention'] = 'unknown';
      if (prologueType === 'push_rbp') {
        callingConvention = 'cdecl';
      } else if (prologueType === 'sub_rsp') {
        callingConvention = 'fastcall';
      }

      let isThunk = false;
      let thunkTarget: number | undefined;
      const nonNopInstrs = funcInstructions.filter(ins => {
        const m = ins.mnemonic.toLowerCase();
        return m !== 'nop' && m !== 'nopl' && m !== 'nopw';
      });
      if (nonNopInstrs.length <= 2 && nonNopInstrs.length > 0) {
        const lastInstr = nonNopInstrs[nonNopInstrs.length - 1];
        if (lastInstr.mnemonic.toLowerCase() === 'jmp' || lastInstr.mnemonic.toLowerCase() === 'jmpq') {
          const tgts = targetMap.get(lastInstr.address);
          if (tgts && tgts.size === 1) {
            const tgt = Array.from(tgts)[0];
            if (tgt < funcStart || tgt > funcEnd) {
              isThunk = true;
              thunkTarget = tgt;
            }
          }
        }
      }

      functions.set(funcStart, {
        startAddress: funcStart,
        endAddress: funcEnd,
        size,
        prologueType,
        callCount,
        incomingCalls: new Set(incomingCalls),
        returnCount,
        hasLoops: false,
        complexity: Math.min(10, callCount + returnCount),
        suspiciousPatterns: [],
        isRecursive,
        hasTailCall,
        callingConvention,
        isThunk,
        thunkTarget,
      });
    }

    return functions;
  };

  // Detect loops from CFG structure
  const detectLoops = (graph: CfgGraph): LoopInfo[] => {
    const loops: LoopInfo[] = [];
    const visited = new Set<string>();
    const recursionStack = new Set<string>();

    // Pre-build adjacency list and node map for O(V+E) total complexity
    const adjacency = new Map<string, string[]>();
    const nodeMap = new Map<string, (typeof graph.nodes)[number]>();
    for (const node of graph.nodes) {
      nodeMap.set(node.id, node);
      adjacency.set(node.id, []);
    }
    for (const edge of graph.edges) {
      const list = adjacency.get(edge.source);
      if (list) list.push(edge.target);
    }

    const dfs = (nodeId: string, depth: number = 0) => {
      if (visited.has(nodeId)) return;
      visited.add(nodeId);
      recursionStack.add(nodeId);

      const node = nodeMap.get(nodeId);
      if (!node) { recursionStack.delete(nodeId); return; }

      for (const targetId of (adjacency.get(nodeId) ?? [])) {
        if (recursionStack.has(targetId)) {
          // Back edge detected = loop found
          const targetNode = nodeMap.get(targetId);
          if (targetNode && node.start && targetNode.start) {
            loops.push({
              startAddress: Math.min(node.start, targetNode.start),
              endAddress: Math.max(node.end || 0, targetNode.end || 0),
              backEdgeAddress: node.start,
              depth,
            });
          }
        } else {
          dfs(targetId, depth + 1);
        }
      }

      recursionStack.delete(nodeId);
    };

    graph.nodes.forEach((node) => dfs(node.id));
    return loops;
  };

  // Detect suspicious patterns in instructions
  const detectSuspiciousPatterns = (instructions: DisassembledInstruction[]): SuspiciousPattern[] => {
    const patterns: SuspiciousPattern[] = [];
    const memoryAccessCount = new Map<number, number>();

    for (let i = 0; i < instructions.length; i++) {
      const ins = instructions[i];
      const m = ins.mnemonic.toLowerCase();

      // Pattern 1: Tight loops (jmp backwards within 100 bytes)
      if (m === 'jmp' && ins.operands) {
        const matches = ins.operands.match(/0x[0-9a-fA-F]+/);
        if (matches) {
          const targetAddr = parseInt(matches[0], 16);
          const distance = Math.abs(ins.address - targetAddr);
          if (distance < 100 && distance > 0) {
            patterns.push({
              address: ins.address,
              type: 'tight_loop',
              severity: 'warning',
              description: `Tight backward jump (${distance} bytes)`,
              relatedAddresses: [targetAddr],
            });
          }
        }
      }

      // Pattern 2: Repeated memory access (same location accessed 5+ times in a row)
      if (m.startsWith('mov') || m.startsWith('lea') || m.startsWith('cmp')) {
        const memMatch = ins.operands.match(/\[([^\]]+)\]/);
        if (memMatch) {
          const addr = memMatch[1];
          memoryAccessCount.set(ins.address, (memoryAccessCount.get(ins.address) || 0) + 1);
        }
      }

      // Pattern 3: Indirect calls (call rax, call rcx, etc.)
      if (m === 'call' && /r[0-9a-z]+/.test(ins.operands)) {
        patterns.push({
          address: ins.address,
          type: 'indirect_call',
          severity: 'warning',
          description: `Indirect call through register: ${ins.operands}`,
        });
      }

      // Pattern 4: Large immediate values (possible jump table)
      if ((m.startsWith('mov') || m.startsWith('lea')) && /0x[0-9a-fA-F]{6,}/.test(ins.operands)) {
        patterns.push({
          address: ins.address,
          type: 'jump_table',
          severity: 'critical',
          description: 'Large address constant (possible jump table)',
        });
      }
    }

    // -- Pattern 5: Validation / gating logic --------------------------------
    // Detect comparison-heavy windows: sliding 12-instruction window with =3
    // cmp/test instructions followed by at least one conditional jump.
    // A secondary pass detects serial comparisons of the same register against
    // multiple distinct constants (license / auth checks).
    const CMP_MNS = new Set(['cmp', 'test', 'cmpl', 'cmpq', 'cmpb', 'cmpw', 'testl', 'testq', 'testb']);
    const CJMP_MNS = new Set(['je','jne','jz','jnz','jl','jle','jg','jge','ja','jae','jb','jbe','jns','js','jo','jno']);
    const WINDOW = 12;
    for (let i = 0; i < instructions.length; i++) {
      const slice = instructions.slice(i, i + WINDOW);
      const cmpCount  = slice.filter(x => CMP_MNS.has(x.mnemonic.toLowerCase().trim())).length;
      const cjmpCount = slice.filter(x => CJMP_MNS.has(x.mnemonic.toLowerCase().trim())).length;
      if (cmpCount >= 3 && cjmpCount >= 1) {
        // Avoid duplicate regions: skip if the previous window already flagged this address range
        const prevFlagged = patterns.some(
          p => p.type === 'validation' && Math.abs(p.address - instructions[i].address) < 20
        );
        if (!prevFlagged) {
          patterns.push({
            address: instructions[i].address,
            type: 'validation',
            severity: 'warning',
            description: `Comparison-dense region: ${cmpCount} cmp/test + ${cjmpCount} conditional branch(es) in ${WINDOW} instructions - likely validation or control gate`,
            relatedAddresses: slice
              .filter(x => CMP_MNS.has(x.mnemonic.toLowerCase().trim()) || CJMP_MNS.has(x.mnemonic.toLowerCase().trim()))
              .map(x => x.address),
          });
          i += WINDOW - 1; // advance past the window to avoid overlapping regions
        }
      }
    }

    // Serial-comparison: same register tested against =3 distinct constants
    // across consecutive cmp instructions ? probable auth/license check.
    const regConstHits = new Map<string, Set<number>>();
    const regFirstAddr = new Map<string, number>();
    for (const ins of instructions) {
      const mn = ins.mnemonic.toLowerCase().trim();
      if (mn === 'cmp' || mn === 'cmpl' || mn === 'cmpb' || mn === 'cmpq') {
        const parts = ins.operands.split(',').map(s => s.trim());
        if (parts.length === 2) {
          const [left, right] = parts;
          const constMatch = right.match(/^(?:0x[0-9a-fA-F]+|\d+)$/);
          if (constMatch) {
            const constVal = constMatch[0].startsWith('0x')
              ? parseInt(constMatch[0], 16)
              : parseInt(constMatch[0], 10);
            if (!regConstHits.has(left)) {
              regConstHits.set(left, new Set());
              regFirstAddr.set(left, ins.address);
            }
            regConstHits.get(left)!.add(constVal);
          }
        }
      }
    }
    for (const [reg, constants] of regConstHits) {
      if (constants.size >= 3) {
        const firstAddr = regFirstAddr.get(reg)!;
        const alreadyFlagged = patterns.some(
          p => p.type === 'validation' && Math.abs(p.address - firstAddr) < 30
        );
        if (!alreadyFlagged) {
          patterns.push({
            address: firstAddr,
            type: 'validation',
            severity: 'critical',
            description: `Serial comparison: '${reg}' compared against ${constants.size} distinct constants - probable auth, license, or dispatch check`,
            relatedAddresses: [],
          });
        }
      }
    }

    return patterns;
  };

  // Calculate reference strength for each address
  const calculateReferenceStrength = (
    refMap: Map<number, Set<number>>,
    targetMap: Map<number, Set<number>>,
    functions: Map<number, FunctionMetadata>
  ): Map<number, ReferenceStrength> => {
    const strength = new Map<number, ReferenceStrength>();

    refMap.forEach((incoming, addr) => {
      const outgoing = targetMap.get(addr) || new Set();
      const isFunctionStart = functions.has(addr);
      const incomingCount = incoming.size;
      const outgoingCount = outgoing.size;
      
      let importance: ReferenceStrength['importance'] = 'low';
      if (isFunctionStart && incomingCount >= 5) {
        importance = 'critical';
      } else if (incomingCount >= 3) {
        importance = 'high';
      } else if (incomingCount >= 1) {
        importance = 'medium';
      }

      strength.set(addr, { incomingCount, outgoingCount, importance });
    });

    return strength;
  };

  // Comprehensive analysis orchestration
  const performFullAnalysis = (instructions: DisassembledInstruction[], graph: CfgGraph | null) => {
    if (instructions.length === 0) return;

    const functions = detectFunctions(instructions, referencesMap, jumpTargetsMap);
    const loops = detectLoops(graph || { nodes: [], edges: [] });
    const patterns = detectSuspiciousPatterns(instructions);
    const refStrength = calculateReferenceStrength(referencesMap, jumpTargetsMap, functions);

    // Build block analysis
    const blockAnalysis = new Map<string, BlockAnalysis>();
    if (graph) {
      graph.nodes.forEach((node) => {
        const blockType = node.block_type === 'entry' ? 'entry' 
          : loops.some((l) => l.startAddress === node.start) ? 'loop' 
          : node.block_type === 'external' ? 'exit' 
          : 'normal';

        blockAnalysis.set(node.id, {
          blockId: node.id,
          blockType,
          branchingComplexity: graph.edges.filter((e) => e.source === node.id).length,
          loopDepth: loops.filter((l) => l.startAddress >= (node.start || 0) && l.endAddress <= (node.end || 0)).length,
          callCount: 0,
          suspiciousPatterns: patterns.filter(
            (p) => p.address >= (node.start || 0) && p.address <= (node.end || 0)
          ),
        });
      });
    }

    setDisassemblyAnalysis({
      functions,
      loops,
      suspiciousPatterns: patterns,
      referenceStrength: refStrength,
      blockAnalysis,
    });
  };

  // NEW: Add bookmark at current address
  const addBookmark = (note: string = '') => {
    if (currentAddress === null) {
      setMessage('No address selected for bookmark');
      return;
    }
    const bookmark: Bookmark = {
      id: `bm-${Date.now()}`,
      address: currentAddress,
      range: currentRange || undefined,
      tab: activeTab,  // UPGRADE: Capture current tab
      note,
      tags: [],
      timestamp: Date.now(),
    };
    setBookmarks([...bookmarks, bookmark]);
    setMessage(`Bookmarked ${formatHex(currentAddress)}`);
  };

  // NEW: Delete bookmark
  const deleteBookmark = (id: string) => {
    setBookmarks(bookmarks.filter(b => b.id !== id));
  };

  // ─── Patch Engine (Milestone 2) ─────────────────────────────────────────────

  /** Queue an inverted-jump patch for the instruction at `address`. */
  const queueInvertJump = async (address: number) => {
    if (!hasTauriRuntime()) {
      const patch: Patch = {
        id: `patch-${Date.now()}-${Math.random().toString(36).slice(2)}`,
        address,
        label: 'Invert conditional jump (simulated)',
        originalBytes: [0x74],
        patchedBytes: [0x75],
        enabled: true,
        timestamp: Date.now(),
      };
      setPatches((prev) => [...prev, patch]);
      addLog(`Queued simulated invert-jump patch at ${formatHex(address)}`, 'info');
      setMessage(`Patch queued (simulated) at ${formatHex(address)}`);
      return;
    }

    try {
      const safePath = sanitizeBridgePath(binaryPath, 'binary path');
      const safeOffset = sanitizeAddress(address, 'offset');
      const result = await invoke<{
        is_invertible: boolean;
        inverted_opcode: number[];
        description: string;
      }>('get_jump_inversion', { path: safePath, offset: safeOffset });

      if (!result.is_invertible) {
        setMessage(`Not an invertible jump at ${formatHex(address)}: ${result.description}`);
        return;
      }

      // Read the original bytes at that offset (same length as inverted opcode)
      const safeLength = clampInt(result.inverted_opcode.length, 1, 16, 'opcode length');
      const originalBytes = await invoke<number[]>('read_hex_range', {
        path: safePath,
        offset: safeOffset,
        length: safeLength,
      });

      const patch: Patch = {
        id: `patch-${Date.now()}-${Math.random().toString(36).slice(2)}`,
        address,
        label: result.description,
        originalBytes,
        patchedBytes: result.inverted_opcode,
        enabled: true,
        timestamp: Date.now(),
      };
      setPatches((prev) => [...prev, patch]);
      addLog(`Queued patch: ${result.description} at ${formatHex(address)}`);
      setMessage(`Patch queued: ${result.description} at ${formatHex(address)}`);
    } catch (err) {
      addLog(`Failed to queue invert-jump patch: ${err}`, 'error');
      setMessage(`Patch failed: ${err}`);
    }
  };

  /** Queue a NOP-sled patch for `count` bytes starting at `address`. */
  const queueNopSled = async (address: number, count: number) => {
    if (!hasTauriRuntime()) {
      const safeCount = clampInt(count, 1, 64, 'NOP count');
      const originalBytes = buildMockHexBytes(binaryPath, address, safeCount);
      const patch: Patch = {
        id: `patch-${Date.now()}-${Math.random().toString(36).slice(2)}`,
        address,
        label: `NOP ×${safeCount} (simulated)`,
        originalBytes,
        patchedBytes: new Array<number>(safeCount).fill(0x90),
        enabled: true,
        timestamp: Date.now(),
      };
      setPatches((prev) => [...prev, patch]);
      addLog(`Queued simulated NOP sled (${safeCount}B) at ${formatHex(address)}`, 'info');
      setMessage(`NOP sled queued (simulated): ${safeCount} bytes at ${formatHex(address)}`);
      return;
    }

    try {
      const safePath = sanitizeBridgePath(binaryPath, 'binary path');
      const safeOffset = sanitizeAddress(address, 'offset');
      const safeCount = clampInt(count, 1, 64, 'NOP count');
      const originalBytes = await invoke<number[]>('read_hex_range', {
        path: safePath,
        offset: safeOffset,
        length: safeCount,
      });
      const nopBytes = new Array<number>(safeCount).fill(0x90);
      const patch: Patch = {
        id: `patch-${Date.now()}-${Math.random().toString(36).slice(2)}`,
        address,
        label: `NOP ×${safeCount}`,
        originalBytes,
        patchedBytes: nopBytes,
        enabled: true,
        timestamp: Date.now(),
      };
      setPatches((prev) => [...prev, patch]);
      addLog(`Queued NOP sled (${safeCount}B) at ${formatHex(address)}`);
      setMessage(`NOP sled queued: ${safeCount} bytes at ${formatHex(address)}`);
    } catch (err) {
      addLog(`Failed to queue NOP patch: ${err}`, 'error');
      setMessage(`Patch failed: ${err}`);
    }
  };

  const removePatch = (id: string) => setPatches((prev) => prev.filter((p) => p.id !== id));
  const togglePatch = (id: string) =>
    setPatches((prev) => prev.map((p) => p.id === id ? { ...p, enabled: !p.enabled } : p));
  const clearAllPatches = () => setPatches([]);

  /** Queue an explainable patch from a Patch Intelligence suggestion. */
  const queueFromSuggestion = async (s: import('./utils/patchEngine').PatchSuggestion) => {
    if (s.kind === 'invert-jump') {
      await queueInvertJump(s.address);
      setPatches(prev => {
        const last = prev[prev.length - 1];
        if (!last || last.address !== s.address) return prev;
        return [
          ...prev.slice(0, -1),
          { ...last, reason: s.reason, impact: s.impact, verifyBefore: s.verifyBefore, risk: s.risk, signalIds: s.signalLinks.map(l => l.signalId) },
        ];
      });
    } else if (s.kind === 'nop-call') {
      await queueNopSled(s.address, 5);
      setPatches(prev => {
        const last = prev[prev.length - 1];
        if (!last || last.address !== s.address) return prev;
        return [
          ...prev.slice(0, -1),
          { ...last, reason: s.reason, impact: s.impact, verifyBefore: s.verifyBefore, risk: s.risk, signalIds: s.signalLinks.map(l => l.signalId) },
        ];
      });
    }
  };

  // ─── Hex streaming: load-more for large files (Milestone 1) ─────────────────

  const [hexFileSize, setHexFileSize] = useState<number>(0);
  const [hexIsLoadingMore, setHexIsLoadingMore] = useState(false);

  function prepareForBinarySelection(nextBinaryPath: string) {
    setBinaryPath(nextBinaryPath);

    // Reset file-bound state so a new binary does not inherit analysis from
    // the previous file and the workflow returns to "fileLoaded".
    setMetadata(null);
    setPeExtras(null);
    setHexFileSize(0);
    setHexBytes([]);
    setSelectedHexIndex(null);
    setSelectedDisasmAddress(null);
    setDisasmOffset(0);
    localStorage.setItem('hexhawk.disasmOffset', '0');
    setDisassembly([]);
    setDisasmArch(null);
    setDisasmArchFallback(false);
    setDisasmHasMore(false);
    setDisasmNextByteOffset(null);
    setDisasmIsLoadingMore(false);
    setCfg(null);
    setCfgNaturalLoops([]);
    setCfgDomTree(null);
    setCfgPostDomTree(null);
    setStrings([]);
    setPluginResults([]);
    setExpandedAnalysis({});
    setCurrentAddress(null);
    setCurrentRange(null);
    setHighlightedHexRange(undefined);
    setHighlightedDisasmRange(null);
    setHighlightedCfgBlock(null);
    setHighlightedStrings(new Set());
  }

  /** Append the next chunk of bytes to the hex view. Called when user scrolls near bottom. */
  const hexLoadMore = async () => {
    if (!binaryPath || hexIsLoadingMore) return;
    const nextOffset = hexOffset + hexBytes.length;
    if (hexFileSize > 0 && nextOffset >= hexFileSize) return; // at end of file
    setHexIsLoadingMore(true);
    if (!hasTauriRuntime()) {
      try {
        const chunk = buildMockHexBytes(binaryPath, nextOffset, 4096);
        if (chunk.length > 0) {
          setHexBytes((prev) => [...prev, ...chunk]);
        }
      } finally {
        setHexIsLoadingMore(false);
      }
      return;
    }

    try {
      const safePath = sanitizeBridgePath(binaryPath, 'binary path');
      const chunk = await invoke<number[]>('read_hex_range', {
        path: safePath,
        offset: sanitizeAddress(nextOffset, 'offset'),
        length: 4096,
      });
      if (chunk.length > 0) {
        setHexBytes((prev) => [...prev, ...chunk]);
      }
    } catch (err) {
      addLog(`Failed to load more hex: ${err}`, 'error');
    } finally {
      setHexIsLoadingMore(false);
    }
  };

  // NEW: Navigate to bookmark (with full context restoration)
  const goToBookmark = (bookmark: Bookmark) => {
    navigateTo({
      address: bookmark.address,
      range: bookmark.range,
      tab: bookmark.tab || 'hex',  // UPGRADE: Use stored tab, default to hex
      description: `Bookmark: ${bookmark.note || formatHex(bookmark.address)}`,
      skipHistory: true,  // Bookmarks shouldn't create history entries
      message: `🔖 ${bookmark.note || formatHex(bookmark.address)}`,
    });
  };

  // NEW: Go back in history (with full context restoration)
  const goBack = () => {
    if (historyIndex > 0) {
      const entry = history[historyIndex - 1];
      navigateTo({
        address: entry.address,
        range: entry.range,
        tab: entry.tab,
        description: entry.description,
        skipHistory: true,  // Coming from history, don't re-push
        fromHistory: true,
        message: `← ${entry.description}`,
      });
      setHistoryIndex(historyIndex - 1);
    }
  };

  // NEW: Go forward in history (with full context restoration)
  const goForward = () => {
    if (historyIndex < history.length - 1) {
      const entry = history[historyIndex + 1];
      navigateTo({
        address: entry.address,
        range: entry.range,
        tab: entry.tab,
        description: entry.description,
        skipHistory: true,  // Coming from history, don't re-push
        fromHistory: true,
        message: `→ ${entry.description}`,
      });
      setHistoryIndex(historyIndex + 1);
    }
  };

  const renderStringDetails = (details: Record<string, unknown> | null) => {
    if (!details) {
      return null;
    }

    const maybeStrings = (details as any).strings;
    if (Array.isArray(maybeStrings)) {
      return (
        <div className="plugin-result-strings">
          {(maybeStrings as Array<unknown>).map((item, index) => {
            // Check if item has offset property
            const itemObj = typeof item === 'object' ? item as any : null;
            const offset = itemObj?.offset;
            const text = typeof item === 'string' ? item : itemObj?.text || JSON.stringify(item);
            const isHighlighted = typeof offset === 'number' && highlightedStrings.has(offset);
            
            return (
              <div 
                key={index} 
                className={`plugin-result-string-row ${isHighlighted ? 'highlighted' : ''}`}
              >
                <button
                  type="button"
                  className="plugin-result-string"
                  onClick={() => {
                    if (typeof offset === 'number') {
                      selectAddress(offset, { start: offset, end: offset + (text?.length || 1) });
                    } else {
                      setMessage(`String: ${text}`);
                    }
                  }}
                  title={typeof offset === 'number' ? `Click to highlight and jump to ${formatHex(offset)}` : ''}
                  style={{ cursor: 'pointer' }}
                >
                  {typeof offset === 'number' ? (
                    <>
                      <span className="string-offset">[{formatHex(offset)}]</span>{' '}
                      <span>{text}</span>
                    </>
                  ) : (
                    text
                  )}
                </button>
                {typeof offset === 'number' && (
                  <button
                    type="button"
                    className="plugin-result-string-nav"
                    onClick={() => jumpToDisassembly(offset, 32)}
                    title={`Jump to disassembly at ${formatHex(offset)}`}
                  >
                    Disasm
                  </button>
                )}
              </div>
            );
          })}
        </div>
      );
    }

    return (
      <pre className="plugin-result-output">
        {JSON.stringify(details, null, 2)}
      </pre>
    );
  };

  const renderAnalysisDetails = (result: PluginExecutionResult, index: number) => {
    const expanded = expandedAnalysis[index] ?? false;

    return (
      <div className="plugin-result-analysis">
        <button
          type="button"
          className="plugin-result-toggle"
          onClick={() =>
            setExpandedAnalysis((prev) => ({
              ...prev,
              [index]: !expanded,
            }))
          }
        >
          {expanded ? 'Hide analysis details' : 'Show analysis details'}
        </button>
        {expanded && result.details ? (
          <div>
            <pre 
              className="plugin-result-output"
              title="Click on offset values to jump to hex view"
            >
              {JSON.stringify(result.details, null, 2)}
            </pre>
            <small style={{ color: '#aaa', marginTop: '0.5rem', display: 'block' }}>
              💡 Tip: Hover over offsets (e.g., "0x...", "offset") to see if they're clickable
            </small>
          </div>
        ) : null}
      </div>
    );
  };

  useEffect(() => {
    localStorage.setItem('hexhawk.hexOffset', String(hexOffset));
  }, [hexOffset]);

  useEffect(() => {
    localStorage.setItem('hexhawk.hexLength', String(hexLength));
  }, [hexLength]);

  useEffect(() => {
    localStorage.setItem('hexhawk.disasmOffset', String(disasmOffset));
  }, [disasmOffset]);

  useEffect(() => {
    localStorage.setItem('hexhawk.disasmLength', String(disasmLength));
  }, [disasmLength]);

  useEffect(() => {
    localStorage.setItem('hexhawk.stringMinLength', String(stringMinLength));
  }, [stringMinLength]);

  // Build reference maps when disassembly changes
  useEffect(() => {
    if (disassembly.length > 0) {
      buildReferenceMaps(disassembly);
    }
  }, [disassembly]);

  // Build address-to-block map when CFG changes
  useEffect(() => {
    if (cfg && cfg.nodes.length > 0) {
      buildAddressToBlockMap(cfg);
    }
  }, [cfg]);

  function addLog(messageText: string, level: LogLevel = 'info') {
    const entry: LogEntry = {
      timestamp: new Date().toLocaleTimeString(),
      level,
      message: normalizeActivityMessage(messageText),
    };
    setLogs((current) => [entry, ...current].slice(0, 250));
  }

  /** Export a JSON snapshot of the current analysis session */
  function exportAnalysis() {
    const exportData = {
      timestamp: new Date().toISOString(),
      binaryPath,
      metadata: metadata
        ? {
            file_type: metadata.file_type,
            architecture: metadata.architecture,
            entry_point: formatHex(metadata.entry_point),
            file_size: metadata.file_size,
            sha256: metadata.sha256,
            md5: metadata.md5,
            sections: metadata.sections.map(s => ({ name: s.name, entropy: s.entropy.toFixed(2), size: s.file_size })),
            imports: metadata.imports.map(i => `${i.library}!${i.name}`),
            exports: metadata.exports.map(e => ({ name: e.name, address: formatHex(e.address) })),
          }
        : null,
      verdict: metadata
        ? {
            classification: verdict.classification,
            threatScore: verdict.threatScore,
            confidence: verdict.confidence,
            summary: verdict.summary,
            signals: verdict.signals.map(s => ({ source: s.source, finding: s.finding, weight: s.weight })),
            negativeSignals: verdict.negativeSignals.map(s => ({ finding: s.finding, reduction: s.reduction })),
            amplifiers: verdict.amplifiers,
            dismissals: verdict.dismissals,
          }
        : null,
      strings: strings.slice(0, 500).map(s => ({ offset: formatHex(s.offset), text: s.text })),
      disassembly: disassembly.slice(0, 500).map(i => ({ address: formatHex(i.address), mnemonic: i.mnemonic, operands: i.operands })),
      bookmarks: bookmarks.map(b => ({ address: formatHex(b.address), note: b.note, tags: b.tags })),
      annotations: [...annotations.entries()].map(([addr, note]) => ({ address: formatHex(addr), note })),
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const fileName = binaryPath.split(/[/\\]/).pop()?.replace(/\.[^.]+$/, '') ?? 'binary';
    a.download = `hexhawk-analysis-${fileName}-${Date.now()}.json`;
    a.click();
    scheduleUiTimeout(() => URL.revokeObjectURL(url), 1000);
    addLog('Exported analysis to JSON file.');
  }

  function setAndPersistTab(tab: AppTab) {
    setActiveTab(tab);
    localStorage.setItem('hexhawk.activeTab', tab);
  }

    function handleHeal(action: HealPrescription['action']) {
      switch (action) {
        case 'inspect':       void inspectFile(); break;
        case 'scan_strings':  void scanStrings(); break;
        case 'disassemble':   void disassembleFile(); break;
        case 'build_cfg':     void buildCfg(); break;
        case 'run_nest':      navigateView('nest'); break;
        case 'run_strike':    navigateView('debugger'); break;
        case 'ask_llm':       navigateView('agent'); break;
      }
      addLog(`Self-heal: triggered "${action}" from banner.`, 'info');
    }

  useEffect(() => {
    localStorage.setItem('hexhawk.binaryPath', binaryPath);
  }, [binaryPath]);

  // NEW: Persist bookmarks to localStorage
  useEffect(() => {
    try {
      localStorage.setItem('hexhawk.bookmarks', JSON.stringify(bookmarks));
    } catch (e) {
      console.warn('Failed to persist bookmarks:', e);
    }
  }, [bookmarks]);

  // NEW: Persist history to localStorage
  useEffect(() => {
    try {
      localStorage.setItem('hexhawk.history', JSON.stringify(history));
      localStorage.setItem('hexhawk.historyIndex', String(historyIndex));
    } catch (e) {
      console.warn('Failed to persist history:', e);
    }
  }, [history, historyIndex]);

  // NEW: Load persisted bookmarks and history on mount
  useEffect(() => {
    try {
      const savedBookmarks = localStorage.getItem('hexhawk.bookmarks');
      if (savedBookmarks) {
        setBookmarks(JSON.parse(savedBookmarks) as Bookmark[]);
      }
    } catch (e) {
      console.warn('Failed to load bookmarks:', e);
    }

    try {
      const savedHistory = localStorage.getItem('hexhawk.history');
      const savedIndex = localStorage.getItem('hexhawk.historyIndex');
      if (savedHistory) {
        setHistory(JSON.parse(savedHistory) as HistoryEntry[]);
        if (savedIndex) {
          setHistoryIndex(Number(savedIndex));
        }
      }
    } catch (e) {
      console.warn('Failed to load history:', e);
    }
  }, []);  // Run only on mount

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Don't trigger shortcuts when typing in input fields
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) {
        return;
      }

      // ?: Show keyboard shortcuts help
      if (e.key === '?' || (e.ctrlKey && e.shiftKey && e.key === '/')) {
        e.preventDefault();
        setShowKeyboardHelp(!showKeyboardHelp);
      }

      // Escape: Close help
      if (e.key === 'Escape' && showKeyboardHelp) {
        setShowKeyboardHelp(false);
      }

      // Ctrl+Alt+Shift+H: Toggle hidden self-heal banner visibility
      if (e.ctrlKey && e.altKey && e.shiftKey && e.key.toLowerCase() === 'h') {
        e.preventDefault();
        setShowSelfHealBanner((prev) => {
          const next = !prev;
          addLog(`Self-heal hints ${next ? 'revealed' : 'hidden'} via advanced shortcut.`, 'info');
          if (next) {
            setHealDismissed(false);
          }
          return next;
        });
      }

      // Ctrl+B: Add/Toggle bookmark
      if (e.ctrlKey && e.key === 'b') {
        e.preventDefault();
        if (currentAddress !== null) {
          addBookmark();
        } else {
          setMessage('Select an address first to bookmark');
        }
      }

      // Ctrl+Shift+B: Go to bookmarks tab
      if (e.ctrlKey && e.shiftKey && e.key === 'B') {
        e.preventDefault();
        setAndPersistTab('bookmarks');
      }

      // Ctrl+D: Go to disassembly tab
      if (e.ctrlKey && e.key === 'd') {
        e.preventDefault();
        setAndPersistTab('disassembly');
      }

      // Ctrl+H: Go to hex tab
      if (e.ctrlKey && e.key === 'h') {
        e.preventDefault();
        setAndPersistTab('hex');
      }

      // Ctrl+J: Jump to hex from disassembly
      if (e.ctrlKey && e.key === 'j') {
        e.preventDefault();
        if (selectedDisasmAddress !== null) {
          jumpToHex(selectedDisasmAddress);
        }
      }

      // Ctrl+G: Jump to address dialog
      if (e.ctrlKey && e.key === 'g') {
        e.preventDefault();
        setShowJumpDialog(true);
      }

      // Ctrl+Alt+G: Go back in history (moved from Ctrl+G)
      if (e.ctrlKey && e.altKey && e.key === 'g') {
        e.preventDefault();
        goBack();
      }

      // Ctrl+R: Toggle references panel
      if (e.ctrlKey && e.key === 'r') {
        e.preventDefault();
        setShowReferencesPanel(v => {
          localStorage.setItem('hexhawk.showReferencesPanel', String(!v));
          return !v;
        });
      }

      // Ctrl+Y: Go forward in history
      if (e.ctrlKey && e.key === 'y') {
        e.preventDefault();
        goForward();
      }

      // Ctrl+F: Focus search in current tab (could be extended)
      if (e.ctrlKey && e.key === 'f') {
        e.preventDefault();
        // Focus on first search input in current tab
        const searchInput = document.querySelector<HTMLInputElement>('.search-input');
        if (searchInput) {
          searchInput.focus();
          searchInput.select();
        }
      }

      // Arrow keys for navigation in disassembly
      if (activeTab === 'disassembly' && disassembly.length > 0) {
        if ((e.key === 'ArrowUp' || e.key === 'ArrowDown') && selectedDisasmAddress !== null) {
          e.preventDefault();
          const currentIndex = disassembly.findIndex(ins => ins.address === selectedDisasmAddress);
          if (currentIndex !== -1) {
            if (e.key === 'ArrowUp' && currentIndex > 0) {
              const prevInstr = disassembly[currentIndex - 1];
              selectAddress(prevInstr.address, { start: prevInstr.address, end: prevInstr.address + 1 });
              setSelectedDisasmAddress(prevInstr.address);
            } else if (e.key === 'ArrowDown' && currentIndex < disassembly.length - 1) {
              const nextInstr = disassembly[currentIndex + 1];
              selectAddress(nextInstr.address, { start: nextInstr.address, end: nextInstr.address + 1 });
              setSelectedDisasmAddress(nextInstr.address);
            }
          }
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [activeTab, currentAddress, selectedDisasmAddress, disassembly, historyIndex, history.length, showKeyboardHelp]);

  useEffect(() => {
    async function loadPlugins() {
      if (!hasTauriRuntime()) {
        setPlugins([
          { name: 'ByteCounter', description: 'Counts bytes in selected file', version: '1.0.0', enabled: true, path: null },
          { name: 'EntropyAnalyzer', description: 'Estimates entropy by section/range', version: '1.0.0', enabled: true, path: null },
          { name: 'SuspiciousImportScanner', description: 'Flags risky import signatures', version: '1.0.0', enabled: true, path: null },
          { name: 'EmbeddedPayloadScanner', description: 'Searches for embedded payload markers', version: '1.0.0', enabled: true, path: null },
        ]);
        addLog('Loaded simulated built-in plugins for browser mode.', 'info');
        return;
      }

      try {
        const response = await invoke<PluginMetadata[]>('list_available_plugins', {});
        const capped = capArraySize(response, 1000);
        setPlugins(capped);
        if (capped.length > 0) {
          setSelectedPluginName((current) => current || capped[0].name);
        }
        if (capped.length !== response.length) addLog('Plugin list display capped to prevent UI freeze.', 'warn');
        addLog('Loaded available plugins.');
      } catch (error) {
        const msg = String(error);
        console.error('Failed to load plugins', error);
        setMessage(`Failed to load plugins: ${msg}`);
        addLog(`Failed to load plugins: ${msg}`, 'warn');
        setPlugins([]);
      }
    }

    loadPlugins();
  }, []);

  // PHASE 6: Persist UI state to localStorage
  useEffect(() => {
    if (selectedFunction) {
      localStorage.setItem('hexhawk.selectedFunction', selectedFunction.toString());
    }
  }, [selectedFunction]);

  useEffect(() => {
    localStorage.setItem('hexhawk.showAnalysisPanel', showAnalysisPanel.toString());
  }, [showAnalysisPanel]);

  useEffect(() => {
    localStorage.setItem('hexhawk.showFunctionBrowser', showFunctionBrowser.toString());
  }, [showFunctionBrowser]);

  useEffect(() => {
    localStorage.setItem('hexhawk.showSmartSuggestions', showSmartSuggestions.toString());
  }, [showSmartSuggestions]);

  const selectedPlugin = useMemo(
    () => plugins.find((p) => p.name === selectedPluginName) ?? null,
    [plugins, selectedPluginName]
  );

  // PHASE 6: Smart navigation handler - logs context and updates state
  const handleSmartNavigation = (targetAddress: number, description: string) => {
    setSelectedDisasmAddress(targetAddress);
    selectAddress(targetAddress);
    addLog(`Navigate: ${description}`, 'info');
  };

  // Open native file picker and set binary path
  async function pickFile() {
    if (!hasTauriRuntime()) {
      if (typeof document === 'undefined') {
        setMessage('File picker is unavailable in this environment.');
        addLog('File picker unavailable: no browser document in current runtime.', 'warn');
        return;
      }

      const input = document.createElement('input');
      input.type = 'file';
      input.multiple = false;
      input.onchange = () => {
        const selectedFile = input.files?.[0];
        if (!selectedFile) {
          return;
        }

        const selectedName = selectedFile.name;
        prepareForBinarySelection(selectedName);
        setRecentFiles(prev => {
          const next = [selectedName, ...prev.filter(f => f !== selectedName)].slice(0, 10);
          localStorage.setItem('hexhawk.recentFiles', JSON.stringify(next));
          return next;
        });
        setMessage('Browser mode selected local file name only. Run Tauri app for full analysis.');
        addLog(`Selected local file in browser mode: ${selectedName}`, 'info');
      };
      input.click();
      return;
    }

    try {
      const selected = await openFileDialog({ multiple: false, directory: false });
      const selectedPath = Array.isArray(selected) ? selected[0] : selected;
      if (selectedPath && typeof selectedPath === 'string') {
        const safePath = sanitizeBridgePath(selectedPath, 'selected file path');
        prepareForBinarySelection(safePath);
        setRecentFiles(prev => {
          const next = [safePath, ...prev.filter(f => f !== safePath)].slice(0, 10);
          localStorage.setItem('hexhawk.recentFiles', JSON.stringify(next));
          return next;
        });
      }
      return;
    } catch (error) {
      const msg = String(error);
      // Treat explicit cancellation as a no-op; surface all other dialog failures.
      if (/cancel/i.test(msg)) {
        return;
      }
      addLog(`Browse via plugin-dialog failed, trying backend fallback: ${msg}`, 'warn');
    }

    // Fallback path: use backend-native picker command if plugin dialog path fails.
    try {
      const fallbackPath = await invoke<string | null>('open_file_picker');
      if (fallbackPath && typeof fallbackPath === 'string') {
        const safePath = sanitizeBridgePath(fallbackPath, 'selected file path');
        prepareForBinarySelection(safePath);
        setRecentFiles(prev => {
          const next = [safePath, ...prev.filter(f => f !== safePath)].slice(0, 10);
          localStorage.setItem('hexhawk.recentFiles', JSON.stringify(next));
          return next;
        });
        return;
      }
    } catch (fallbackError) {
      const fallbackMsg = String(fallbackError);
      setMessage(`Browse failed: ${fallbackMsg}`);
      addLog(`Browse fallback failed: ${fallbackMsg}`, 'error');
      return;
    }

    setMessage('Browse cancelled.');
  }

  async function inspectFile() {
    if (!hasTauriRuntime()) {
      const mockMeta = buildMockMetadata(binaryPath);
      const safeRange = sanitizeRange(hexOffset, hexLength);
      setMetadata(mockMeta);
      setPeExtras(null);
      setHexFileSize(mockMeta.file_size);
      setHexOffset(safeRange.offset);
      setHexBytes(buildMockHexBytes(binaryPath, safeRange.offset, safeRange.length));
      setSelectedHexIndex(null);
      setSelectedDisasmAddress(null);
      setMessage('Browser mode inspection completed (simulated backend).');
      addLog(`Simulated inspect for ${binaryPath}`, 'info');
      addLog(`Seeded browser hex preview for ${binaryPath} at ${formatHex(safeRange.offset)}.`, 'info');
      navigateView('inspect');
      return;
    }

    try {
      const safePath = sanitizeBridgePath(binaryPath, 'binary path');
      const response = await invoke<FileMetadata>('inspect_file_metadata', {
        path: safePath,
      });
      setMetadata(response);

      // Fetch PE-specific extras (TLS callbacks + resources) — returns empty for non-PE files
      try {
        const extras = await invoke<{ tls_callbacks: Array<{ address: number }>; resources: Array<{ type_name: string; id: number; size: number; offset: number }> }>('inspect_pe_extras', { path: safePath });
        setPeExtras(extras.tls_callbacks.length > 0 || extras.resources.length > 0 ? extras : null);
      } catch {
        setPeExtras(null);
      }
      setHexFileSize(response.file_size ?? 0);
      setMessage('File inspection completed');
      addLog(`Inspected file: ${binaryPath}`);
      navigateView('inspect');

      // ── Corpus log ──────────────────────────────────────────────────────────
      // Compute a verdict from the freshly returned metadata.  Strings and
      // disassembly patterns may not be loaded yet; computeVerdict handles
      // empty arrays gracefully and we record what we know right now.
      const freshVerdict = computeVerdict({
        sections: (response.sections ?? []).map(s => ({
          name:      s.name,
          entropy:   s.entropy ?? 0,
          file_size: s.file_size ?? 0,
        })),
        imports:  response.imports ?? [],
        strings:  strings.map(s => ({ text: s.text })),
        patterns: disassemblyAnalysis.suspiciousPatterns,
      });

      // Group signal weights by source for engineContributions
      const contributions: Record<string, number> = {};
      for (const sig of freshVerdict.signals) {
        contributions[sig.source] = (contributions[sig.source] ?? 0) + sig.weight;
      }

      const filename = binaryPath.split(/[/\\]/).pop() ?? binaryPath;

      void appendCorpusLog({
        hash:                response.sha256,
        filename,
        timestamp:           new Date().toISOString(),
        verdict:             classificationToCorpusVerdict(freshVerdict.classification),
        confidence:          freshVerdict.confidence,
        signals:             freshVerdict.signals.map(s => ({
          source:  s.source,
          id:      s.id,
          finding: s.finding,
          weight:  s.weight,
        })),
        engineContributions: contributions,
        talonSummary:        null,
        notes:               '',
      });
    } catch (error) {
      const rawMsg = String(error);
      const notFound = /(os error 3|cannot find the path|path not found|No such file or directory)/i.test(rawMsg);
      const msg = notFound
        ? `${rawMsg}. Path not found: verify the file exists, or click Browse... to select a valid file.`
        : rawMsg;
      console.error('Failed to inspect file', error);
      setMessage(`Failed to inspect file: ${msg}`);
      addLog(`Failed to inspect file: ${msg}`, 'error');
      setMetadata(null);
      setPeExtras(null);
    }
  }

  async function previewHex() {
    if (!hasTauriRuntime()) {
      const safeRange = sanitizeRange(hexOffset, hexLength);
      const response = buildMockHexBytes(binaryPath, safeRange.offset, safeRange.length);
      setHexBytes(response);
      setSelectedHexIndex(null);
      setSelectedDisasmAddress(null);
      setMessage('Hex preview loaded (browser-mode simulation).');
      addLog(`Simulated hex preview for ${binaryPath} at offset ${hexOffset}`);
      navigateView('hex');
      return;
    }

    try {
      const safePath = sanitizeBridgePath(binaryPath, 'binary path');
      const safeRange = sanitizeRange(hexOffset, hexLength);
      const response = await invoke<number[]>('read_hex_range', {
        path: safePath,
        offset: safeRange.offset,
        length: safeRange.length,
      });
      setHexBytes(response);
      setSelectedHexIndex(null);
      setSelectedDisasmAddress(null);
      setMessage('Hex preview loaded');
      addLog(`Loaded hex preview for ${binaryPath} at offset ${hexOffset}`);
      navigateView('hex');
    } catch (error) {
      const msg = String(error);
      console.error('Failed to load hex preview', error);
      setMessage(`Failed to load hex preview: ${msg}`);
      addLog(`Failed to load hex preview: ${msg}`, 'error');
      setHexBytes([]);
      setSelectedHexIndex(null);
    }
  }

  async function previewHexAt(offset: number) {
    if (!hasTauriRuntime()) {
      const safeRange = sanitizeRange(offset, hexLength);
      const response = buildMockHexBytes(binaryPath, safeRange.offset, safeRange.length);
      setHexOffset(safeRange.offset);
      setHexBytes(response);
      setSelectedHexIndex(0);
      setSelectedDisasmAddress(null);
      setMessage(`Hex preview loaded at ${formatHex(offset)} (browser simulation)`);
      addLog(`Simulated hex preview at ${formatHex(offset)} for ${binaryPath}`);
      navigateView('hex');
      return;
    }

    try {
      const safePath = sanitizeBridgePath(binaryPath, 'binary path');
      const safeRange = sanitizeRange(offset, hexLength);
      const response = await invoke<number[]>('read_hex_range', {
        path: safePath,
        offset: safeRange.offset,
        length: safeRange.length,
      });
      setHexOffset(safeRange.offset);
      setHexBytes(response);
      setSelectedHexIndex(0);
      setSelectedDisasmAddress(null);
      setMessage(`Hex preview loaded at ${formatHex(offset)}`);
      addLog(`Loaded hex preview at ${formatHex(offset)} for ${binaryPath}`);
      navigateView('hex');
    } catch (error) {
      const msg = String(error);
      console.error('Failed to load hex preview at offset', error);
      setMessage(`Failed to load hex preview: ${msg}`);
      addLog(`Failed to load hex preview: ${msg}`, 'error');
    }
  }

  async function scanStrings() {
    if (!hasTauriRuntime()) {
      const capped = capArraySize(buildMockStrings(binaryPath.split(/[\\/]/).pop() || binaryPath), MAX_BRIDGE_LIST_ITEMS);
      setStrings(capped);
      setMessage(`Found ${capped.length} strings (browser-mode simulation).`);
      addLog(`Simulated string scan for ${binaryPath}`, 'info');
      navigateView('strings');
      return;
    }

    try {
      const safePath = sanitizeBridgePath(binaryPath, 'binary path');
      const safeRange = sanitizeRange(hexOffset, hexLength);
      const safeMinLength = clampInt(stringMinLength, 1, 4096, 'min string length');
      const response = await invoke<StringMatch[]>('find_strings', {
        path: safePath,
        offset: safeRange.offset,
        length: safeRange.length,
        minLength: safeMinLength,
      });
      const capped = capArraySize(response, MAX_BRIDGE_LIST_ITEMS);
      setStrings(capped);
      if (capped.length !== response.length) {
        addLog(`String results capped at ${MAX_BRIDGE_LIST_ITEMS} entries to keep UI responsive.`, 'warn');
      }
      setMessage(`Found ${capped.length} strings from ${formatHex(safeRange.offset)}`);
      addLog(`Scanned strings in ${safePath} at ${formatHex(safeRange.offset)} length ${safeRange.length}`);
      navigateView('strings');
    } catch (error) {
      const msg = String(error);
      console.error('Failed to scan strings', error);
      setMessage(`Failed to scan strings: ${msg}`);
      addLog(`Failed to scan strings: ${msg}`, 'error');
      setStrings([]);
    }
  }

  const selectHexByte = useCallback((index: number) => {
    setSelectedHexIndex(index);
    setSelectedDisasmAddress(hexOffset + index);
  }, [hexOffset]);

  async function disassembleFile(offset?: number) {
    const startOffset = offset ?? disasmOffset;
    setDisasmIsLoading(true);
    if (!hasTauriRuntime()) {
      const safeRange = sanitizeRange(startOffset, disasmLength);
      const instructions = buildMockDisassembly(safeRange.offset);
      setDisassembly(capArraySize(instructions, MAX_UI_DISASSEMBLY_ITEMS));
      setDisasmArch('x86_64');
      setDisasmArchFallback(false);
      setDisasmOffset(safeRange.offset);
      setDisasmHasMore(false);
      setDisasmNextByteOffset(null);
      setMessage(`Disassembly loaded from ${formatHex(startOffset)} (browser simulation)`);
      addLog(`Simulated disassembly for ${binaryPath} from ${formatHex(startOffset)}`, 'info');
      performFullAnalysis(instructions, cfg);
      setDisasmIsLoading(false);
      navigateView('disassembly');
      return;
    }

    try {
      const safePath = sanitizeBridgePath(binaryPath, 'binary path');
      const safeRange = sanitizeRange(startOffset, disasmLength);
      const response = await invoke<{
        arch: string;
        is_fallback: boolean;
        instructions: DisassembledInstruction[];
        has_more: boolean;
        next_byte_offset: number;
      }>('disassemble_file_range', {
        path: safePath,
        offset: safeRange.offset,
        length: safeRange.length,
        max_instructions: DISASM_CHUNK_SIZE,
      });
      const instructions = capArraySize(response.instructions, MAX_UI_DISASSEMBLY_ITEMS);
      if (instructions.length === 0) {
        addLog(`No instructions decoded at ${formatHex(safeRange.offset)} for ${binaryPath}.`, 'warn');
        if (safeRange.offset !== 0) {
          setMessage(`No instructions decoded at ${formatHex(safeRange.offset)}. Retrying from 0x0...`);
          setDisasmOffset(0);
          localStorage.setItem('hexhawk.disasmOffset', '0');
          await disassembleFile(0);
          return;
        }

        setMessage(`No instructions decoded at ${formatHex(safeRange.offset)}. Try a different offset.`);
        setDisassembly([]);
        setDisasmHasMore(false);
        setDisasmNextByteOffset(null);
        navigateView('disassembly');
        return;
      }

      setDisassembly(instructions);
      setDisasmArch(response.arch);
      setDisasmArchFallback(response.is_fallback);
      setDisasmOffset(safeRange.offset);
      setDisasmHasMore(response.has_more);
      setDisasmNextByteOffset(response.has_more ? response.next_byte_offset : null);
      const archNote = response.is_fallback ? ` (⚠ unsupported arch - fell back to ${response.arch})` : ` (${response.arch})`;
      setMessage(`Disassembly loaded from ${formatHex(startOffset)}${archNote}`);
      addLog(`Disassembled ${binaryPath} from ${formatHex(startOffset)}${archNote}`, response.is_fallback ? 'warn' : 'info');
      
      // PHASE 5: Perform analysis on disassembly
      performFullAnalysis(instructions, cfg);
      
      navigateView('disassembly');
    } catch (error) {
      const msg = String(error);
      console.error('Failed to disassemble file', error);
      setMessage(`Failed to disassemble file: ${msg}`);
      addLog(`Failed to disassemble file: ${msg}`, 'error');
      setDisassembly([]);
      setDisasmHasMore(false);
      setDisasmNextByteOffset(null);
    } finally {
      setDisasmIsLoading(false);
    }
  }

  async function loadMoreDisassembly() {
    if (!binaryPath || disasmNextByteOffset === null || disasmIsLoadingMore) return;
    if (!hasTauriRuntime()) {
      setDisasmHasMore(false);
      addLog('Browser mode disassembly pagination reached simulated end.', 'info');
      return;
    }

    const remaining = disasmOffset + disasmLength - disasmNextByteOffset;
    if (remaining <= 0) {
      setDisasmHasMore(false);
      return;
    }
    setDisasmIsLoadingMore(true);
    try {
      const safePath = sanitizeBridgePath(binaryPath, 'binary path');
      const response = await invoke<{
        arch: string;
        is_fallback: boolean;
        instructions: DisassembledInstruction[];
        has_more: boolean;
        next_byte_offset: number;
      }>('disassemble_file_range', {
        path: safePath,
        offset: sanitizeAddress(disasmNextByteOffset, 'offset'),
        length: clampInt(remaining, 1, 1024 * 1024 * 1024, 'length'),
        max_instructions: DISASM_CHUNK_SIZE,
      });
      setDisassembly((prev) => capArraySize([...prev, ...response.instructions], MAX_UI_DISASSEMBLY_ITEMS));
      setDisasmHasMore(response.has_more);
      setDisasmNextByteOffset(response.has_more ? response.next_byte_offset : null);
    } catch (error) {
      const msg = String(error);
      console.error('Failed to load more disassembly', error);
      addLog(`Failed to load more disassembly: ${msg}`, 'error');
    } finally {
      setDisasmIsLoadingMore(false);
    }
  }

  async function buildCfg() {
    if (!hasTauriRuntime()) {
      const response = buildMockCfg(disasmOffset);
      setCfg(response);
      setCfgNaturalLoops(computeNaturalLoops(response));
      if (response.nodes.length > 0) {
        const { domTree, postDomTree } = buildDomTreeFromCfg(response);
        setCfgDomTree(domTree);
        setCfgPostDomTree(postDomTree);
      } else {
        setCfgDomTree(null);
        setCfgPostDomTree(null);
      }
      setMessage('CFG built successfully (browser-mode simulation).');
      addLog(`Simulated CFG build for ${binaryPath}`, 'info');
      performFullAnalysis(disassembly.length > 0 ? disassembly : buildMockDisassembly(disasmOffset), response);
      navigateView('cfg');
      return;
    }

    try {
      const safePath = sanitizeBridgePath(binaryPath, 'binary path');
      const safeRange = sanitizeRange(disasmOffset, disasmLength);
      const response = await invoke<CfgGraph>('build_cfg', {
        path: safePath,
        offset: safeRange.offset,
        length: safeRange.length,
      });
      setCfg(response);
      setCfgNaturalLoops(computeNaturalLoops(response));
      if (response.nodes.length > 0) {
        const { domTree, postDomTree } = buildDomTreeFromCfg(response);
        setCfgDomTree(domTree);
        setCfgPostDomTree(postDomTree);
      } else {
        setCfgDomTree(null);
        setCfgPostDomTree(null);
      }
      setMessage('CFG built successfully');
      addLog(`Built CFG for ${binaryPath}`);
      
      // PHASE 5: Re-analyze with new CFG data
      performFullAnalysis(disassembly, response);
      
      navigateView('cfg');
    } catch (error) {
      const msg = String(error);
      console.error('Failed to build CFG', error);
      setMessage(`Failed to build CFG: ${msg}`);
      addLog(`Failed to build CFG: ${msg}`, 'error');
      setCfg(null);
    }
  }

  async function analyzePlugins() {
    if (!hasTauriRuntime()) {
      const response = buildMockPluginResults(binaryPath);
      setPluginResults(response);
      setMessage('Plugin analysis completed (browser-mode simulation).');
      addLog(`Simulated plugin analysis for ${binaryPath}`, 'info');
      navigateView('plugins');
      return;
    }

    try {
      const safePath = sanitizeBridgePath(binaryPath, 'binary path');
      const response = await invoke<PluginExecutionResult[]>('run_plugins_on_file', {
        path: safePath,
      });
      setPluginResults(response);
      setMessage('Plugin analysis completed');
      addLog(`Ran plugin analysis for ${binaryPath}`);
      navigateView('plugins');
    } catch (error) {
      const msg = String(error);
      console.error('Failed to run plugins', error);
      setMessage(`Failed to run plugin analysis: ${msg}`);
      addLog(`Failed to run plugin analysis: ${msg}`, 'error');
      setPluginResults([]);
    }
  }

  // ======== UNIFIED NAVIGATION SYSTEM (Phase 2 Unification) ========
  
  /**
   * CENTRAL HUB: All navigation flows through this ONE function.
   * Handles: selection, highlighting, tab switching, scrolling, history tracking
   */
  interface NavigateOptions {
    address: number;
    range?: { start: number; end: number };
    tab?: AppTab;
    description?: string;
    skipHistory?: boolean;  // Don't auto-push to history
    fromHistory?: boolean;  // Coming from history navigation
    message?: string;
  }

  function navigateTo(options: NavigateOptions) {
    const {
      address,
      range,
      tab = activeTab,
      description = `Jump to ${formatHex(address)}`,
      skipHistory = false,
      fromHistory = false,
      message,
    } = options;

    // STEP 1: Update selection (lights up hex/disasm/CFG)
    selectAddress(address, range);

    // STEP 2: Auto-push history ONLY if not coming from history navigation
    if (!fromHistory && !skipHistory && activeTab !== 'bookmarks') {
      const entry: HistoryEntry = {
        id: `hist-${Date.now()}`,
        address,
        range: range || { start: address, end: address + 1 },
        tab,
        timestamp: Date.now(),
        description,
      };
      const newHistory = history.slice(0, historyIndex + 1);
      newHistory.push(entry);
      const capped = newHistory.slice(-100); // cap at 100 entries
      setHistory(capped);
      setHistoryIndex(capped.length - 1);
    }

    // STEP 3: Switch tab if different
    if (tab !== activeTab) {
      setAndPersistTab(tab);
    }

    // STEP 4: Scroll to view (tab-specific)
    if (tab === 'hex' && range) {
      const rangeLen = Math.max(16, Math.min(range.end - range.start, 65536));
      setHexOffset(range.start);
      setHexLength(rangeLen);
      localStorage.setItem('hexhawk.hexOffset', String(range.start));
      localStorage.setItem('hexhawk.hexLength', String(rangeLen));
      
      scheduleUiTimeout(() => {
        const element = document.querySelector(`[data-hex-offset="${range.start}"]`);
        if (element instanceof HTMLElement) {
          element.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      }, 50);
    } else if (tab === 'disassembly') {
      const length = range ? range.end - range.start : 256;
      setDisasmOffset(address);
      setDisasmLength(length);
      localStorage.setItem('hexhawk.disasmOffset', String(address));
      localStorage.setItem('hexhawk.disasmLength', String(length));
      disassembleFile(address);
      
      scheduleUiTimeout(() => {
        const element = document.querySelector(`[data-disasm-address="${address}"]`);
        if (element instanceof HTMLElement) {
          element.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      }, 50);
    }

    // STEP 5: Status message
    setMessage(message || description);
  }

  // ======== Backward-Compatible Navigation Helpers (Now Built on navigateTo) ========

  /** Legacy: Jump to hex view at specific offset */
  function jumpToHex(offset: number, length?: number) {
    navigateTo({
      address: offset,
      range: length ? { start: offset, end: offset + length } : undefined,
      tab: 'hex',
      message: `Jumped to hex at ${formatHex(offset)}`,
      skipHistory: false,
    });
  }

  /** Legacy: Jump to disassembly at specific address */
  function jumpToDisassembly(address: number, length?: number) {
    navigateTo({
      address,
      range: length ? { start: address, end: address + length } : undefined,
      tab: 'disassembly',
      message: `Jumped to disassembly at ${formatHex(address)}`,
      skipHistory: false,
    });
  }

  /** Legacy: Jump to CFG node by disassembling its address range */
  function jumpToCFGNode(nodeStart: number, nodeEnd: number) {
    navigateTo({
      address: nodeStart,
      range: { start: nodeStart, end: nodeEnd },
      tab: 'disassembly',
      message: `Jumped to CFG node at ${formatHex(nodeStart)}-${formatHex(nodeEnd)}`,
      skipHistory: false,
    });
  }

  /** Legacy: Jump to hex then optionally to disassembly */
  async function jumpToHexThenDisasm(offset: number, length?: number) {
    navigateTo({
      address: offset,
      range: length ? { start: offset, end: offset + length } : undefined,
      tab: 'hex',
      skipHistory: false,
    });
    scheduleUiTimeout(() => {
      disassembleFile(offset);
    }, 100);
  }

  /** Legacy: Navigate to offset with options */
  function navigateToOffset(offset: number, length?: number, options?: { hex?: boolean; disasm?: boolean }) {
    const opts = options ?? { hex: true };
    const tab = opts.disasm ? 'disassembly' : 'hex';
    navigateTo({
      address: offset,
      range: length ? { start: offset, end: offset + length } : undefined,
      tab,
      skipHistory: false,
    });
  }

  async function reloadPlugin(name: string) {
    setReloading(name);
    setReloadStatus((current) => {
      const next = { ...current };
      delete next[name];
      return next;
    });

    try {
      if (!hasTauriRuntime()) {
        setReloadStatus((current) => ({ ...current, [name]: 'success' }));
        setMessage(`Reloaded plugin: ${name} (browser-mode simulation)`);
        addLog(`Simulated reload for plugin ${name}`, 'info');
        scheduleUiTimeout(() => {
          setReloadStatus((current) => {
            const next = { ...current };
            delete next[name];
            return next;
          });
        }, 3000);
        return;
      }

      const safeName = sanitizePluginName(name);
      await invoke('reload_plugin', { name: safeName });
      setReloadStatus((current) => ({ ...current, [name]: 'success' }));
      setMessage(`Reloaded plugin: ${name}`);
      addLog(`Reloaded plugin ${name}`);
      scheduleUiTimeout(() => {
        setReloadStatus((current) => {
          const next = { ...current };
          delete next[name];
          return next;
        });
      }, 3000);
    } catch (error) {
      const msg = String(error);
      console.error('Failed to reload plugin', error);
      setReloadStatus((current) => ({ ...current, [name]: 'error' }));
      setMessage(`Failed to reload plugin ${name}: ${msg}`);
      addLog(`Failed to reload plugin ${name}: ${msg}`, 'warn');
    } finally {
      setReloading(null);
    }
  }

  const tabs: AppTab[] = ['metadata', 'hex', 'strings', 'cfg', 'plugins', 'disassembly', 'decompile', 'talon', 'constraint', 'document', 'sandbox', 'debugger', 'strike', 'signatures', 'echo', 'nest', 'repl', 'console', 'bookmarks', 'logs', 'graph', 'report', 'agent'];

  return (
    <div className="wf-shell">
      {isDragOver && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 9999,
          background: 'rgba(0, 120, 255, 0.18)',
          border: '3px dashed rgba(0, 160, 255, 0.8)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          pointerEvents: 'none',
          fontSize: '1.5rem', color: 'rgba(0, 200, 255, 0.9)',
          fontWeight: 600, letterSpacing: '0.05em',
        }}>
          Drop file to open
        </div>
      )}
      {/* First-run welcome screen */}
      {showWelcome && (
        <WelcomeScreen
          onDismiss={(permanent) => {
            if (permanent) markFirstRunComplete();
            setShowWelcome(false);
          }}
          onOpenFile={() => {
            void pickFile();
          }}
        />
      )}
      {/* Global dialogs */}
      <JumpToAddressDialog
        open={showJumpDialog}
        onClose={() => setShowJumpDialog(false)}
        recentAddresses={recentJumpAddresses}
        formatHex={formatHex}
        onJump={(address) => {
          setShowJumpDialog(false);
          setRecentJumpAddresses(prev => {
            const updated = [address, ...prev.filter(a => a !== address)].slice(0, 8);
            localStorage.setItem('hexhawk.recentJumpAddresses', JSON.stringify(updated));
            return updated;
          });
          if (activeTab === 'disassembly') {
            setSelectedDisasmAddress(address);
            selectAddress(address, { start: address, end: address + 4 });
          } else if (activeTab === 'hex') {
            setHexOffset(Math.max(0, address - 128));
            setSelectedHexIndex(address);
          } else {
            selectAddress(address);
          }
        }}
      />

      {/* ── Top Bar ─────────────────────────────────────────────────────────── */}
      <TopBar
        tier={effectiveTier}
        isTrial={isTrial}
        consoleQuery={semanticQuery}
        onConsoleQueryChange={setSemanticQuery}
        onConsoleSubmit={() => {
          const result = runSemanticSearch(semanticQuery);
          const suggestedView = result?.bestMatch?.suggestedTab ?? 'verdict';
          navigateView(suggestedView as NavView);
        }}
        onUpgradeClick={() => setShowLicensePanel(true)}
        onLicenseClick={() => setShowLicensePanel(true)}
      />

      {/* ── Semantic result banner ──────────────────────────────────────────── */}
      {semanticResult && semanticResult.bestMatch && (
        <div className="semantic-result-banner">
          <span className="sem-intent">{semanticResult.bestMatch.intentName}</span>
          <span className="sem-confidence">{semanticResult.bestMatch.confidence}% confidence</span>
          <span className="sem-hits">{semanticResult.bestMatch.matchedImports.length} import hits · {semanticResult.bestMatch.matchedStringOffsets.length} string hits</span>
          <span className="sem-explanation">{semanticResult.bestMatch.explanation}</span>
          <button
            className="sem-goto"
            onClick={() => setAndPersistTab(semanticResult.bestMatch!.suggestedTab as AppTab)}
          >
            Go to {semanticResult.bestMatch.suggestedTab} →
          </button>
          <button className="semantic-search-clear" onClick={() => { setSemanticQuery(''); setSemanticResult(null); }}>✕</button>
        </div>
      )}

      {/* Free-tier file size warning */}
      {effectiveTier === 'free' && metadata && metadata.file_size > FREE_FILE_SIZE_LIMIT && (
        <div className="tier-file-size-warning">
          Warning: File is {(metadata.file_size / 1024 / 1024).toFixed(0)} MB - exceeds the 50 MB Free tier guideline.
          Upgrade to&nbsp;
          <button type="button" className="tier-inline-upgrade" onClick={() => setTier('pro')}>PRO</button>
          &nbsp;for unlimited file sizes.
        </div>
      )}

      <div className="wf-body">
        {/* ── Left: Primary Nav ─────────────────────────────────────────────── */}
        <WorkflowNav
          activeView={activeView}
          workflowState={workflowState}
          tier={effectiveTier}
          fileName={binaryPath.split(/[\\/]/).pop() ?? binaryPath}
          onSelect={navigateView}
          onLoadFile={pickFile}
        />

        {/* ── Right: Main content ───────────────────────────────────────────── */}
        <div className="wf-main">
          {/* Status strip */}
          <div className="wf-status-strip">
            <span className="wf-status-msg">{message}</span>
            {currentAddress !== null && (
              <span className="wf-status-addr">
                {formatHex(currentAddress)}
                {currentRange && ` (${formatHex(currentRange.start)}–${formatHex(currentRange.end)})`}
              </span>
            )}
            <div className="wf-status-actions">
              <button
                type="button"
                className="wf-status-icon-btn"
                onClick={() => {
                  setShowJumpDialog(true);
                  addLog('Opened jump dialog from status strip.', 'info');
                }}
                title="Jump to address (Ctrl+G)"
                data-testid="status-jump"
              >Jump</button>
              <button
                type="button"
                className="wf-status-icon-btn"
                onClick={() => {
                  const next = !showKeyboardHelp;
                  setShowKeyboardHelp(next);
                  addLog(`Toggled keyboard shortcuts overlay: ${next ? 'open' : 'closed'}.`, 'info');
                }}
                title="Keyboard shortcuts (?)"
                data-testid="status-shortcuts"
              >Shortcuts</button>
              <button
                type="button"
                className="wf-status-icon-btn"
                onClick={exportAnalysis}
                disabled={!metadata}
                title="Export analysis"
                data-testid="status-export"
              >Export</button>
              <button
                type="button"
                className={`wf-status-icon-btn ${showQaSources ? 'wf-status-icon-btn--active' : ''}`}
                onClick={() => {
                  setShowQaSources((current) => {
                    const next = !current;
                    addLog(`Toggled QA source matrix: ${next ? 'open' : 'closed'}.`, 'info');
                    return next;
                  });
                }}
                title="Toggle QA source matrix"
                data-testid="status-qa-sources"
              >QA Sources</button>
            </div>
          </div>

          {/* Action Bar */}
          <ActionBar
            workflowState={workflowState}
            tier={effectiveTier}
            hasDisassembly={disassembly.length > 0}
            hasCfg={cfg !== null && cfg.nodes.length > 0}
            hasVerdict={verdict !== null && verdict.classification !== 'unknown'}
            disassemblyLoading={disasmIsLoading}
            onInspect={inspectFile}
            onDisassemble={() => disassembleFile()}
            onBuildCfg={buildCfg}
            onScanStrings={scanStrings}
            onRunAnalysis={async () => {
              await inspectFile();
              await scanStrings();
              await disassembleFile();
              await buildCfg();
              navigateView('verdict');
            }}
            onNavigate={navigateView}
            onExport={exportAnalysis}
            onJumpTo={() => setShowJumpDialog(true)}
          />

          {/* Keyboard shortcuts help */}
          {showKeyboardHelp && (
            <div style={{
              backgroundColor: '#1a1a2e', border: '2px solid #00bfff', borderRadius: '0.5rem',
              padding: '1.5rem', marginBottom: '1rem', color: '#ddd',
              fontFamily: 'monospace', fontSize: '0.9rem',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <h3 style={{ margin: 0, color: '#00bfff' }}>Keyboard Shortcuts</h3>
                <button onClick={() => setShowKeyboardHelp(false)} style={{ background: 'transparent', border: 'none', color: '#aaa', cursor: 'pointer', fontSize: '1.2rem' }}>✕</button>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
                <div>
                  <h4 style={{ color: '#00d4ff', marginTop: 0 }}>Navigation</h4>
                  <div style={{ lineHeight: '1.8' }}>
                    <div><strong>Ctrl+D</strong> → Disassembly tab</div>
                    <div><strong>Ctrl+H</strong> → Hex Viewer tab</div>
                    <div><strong>Ctrl+Shift+B</strong> → Bookmarks tab</div>
                    <div><strong>Ctrl+G</strong> → Jump to address</div>
                  </div>
                </div>
                <div>
                  <h4 style={{ color: '#00d4ff', marginTop: 0 }}>Actions</h4>
                  <div style={{ lineHeight: '1.8' }}>
                    <div><strong>Ctrl+I</strong> → Inspect file</div>
                    <div><strong>Ctrl+S</strong> → Scan strings</div>
                    <div><strong>?</strong> → Toggle shortcuts</div>
                    <div><strong>Ctrl+Alt+Shift+H</strong> → Reveal hidden self-heal hints</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ── Main Panel � workflow CTA or active view ──────────────────── */}
          <div className="wf-panel">
            {panelFidelity && (
              <PanelFidelityBadge source={panelFidelity.source} detail={panelFidelity.detail} />
            )}

            {showQaSources && (
              <QASubsystemPanel statuses={qaSubsystemStatuses} />
            )}

            {/* Recent-files quick-access for the load view */}
            {activeView === 'load' && (
              <div className="panel" data-testid="panel-load">
                <h3>Load Binary</h3>
                <div className="file-picker-row">
                  <span className="binary-path-display" title={binaryPath}>
                    {binaryPath.split(/[\\/]/).pop() || binaryPath}
                  </span>
                  <button type="button" className="browse-btn" onClick={pickFile} title={binaryPath} data-testid="load-browse">Browse...</button>
                </div>
                <div className="file-picker-row" style={{ marginTop: '0.5rem' }}>
                  <input
                    type="text"
                    value={binaryPath}
                    onChange={(event) => setBinaryPath(event.target.value)}
                    className="binary-path-display"
                    data-testid="load-path-input"
                    aria-label="Binary path"
                    placeholder="Enter full binary path"
                  />
                  <button
                    type="button"
                    className="browse-btn"
                    data-testid="load-apply-path"
                    onClick={() => {
                      const candidate = binaryPath.trim();
                      if (!candidate) {
                        setMessage('Provide a binary path before applying it.');
                        addLog('Missing binary path while applying runtime harness path.', 'warn');
                        return;
                      }
                      prepareForBinarySelection(candidate);
                      setRecentFiles((prev) => {
                        const next = [candidate, ...prev.filter((f) => f !== candidate)].slice(0, 10);
                        localStorage.setItem('hexhawk.recentFiles', JSON.stringify(next));
                        return next;
                      });
                      if (!hasTauriRuntime()) {
                        const safeRange = sanitizeRange(hexOffset, hexLength);
                        setHexOffset(safeRange.offset);
                        setHexBytes(buildMockHexBytes(candidate, safeRange.offset, safeRange.length));
                        setSelectedHexIndex(null);
                        setSelectedDisasmAddress(null);
                        addLog(`Seeded browser hex preview for ${candidate} at ${formatHex(safeRange.offset)}.`, 'info');
                      }
                      setMessage(`Applied binary path: ${candidate}`);
                      addLog(`Applied binary path for analysis: ${candidate}`, 'info');
                    }}
                    title="Apply typed path"
                  >Apply Path</button>
                </div>
                {recentFiles.length > 0 && (
                  <div style={{ marginTop: '1rem' }}>
                    <h4>Recent files</h4>
                    {recentFiles.map((f, i) => (
                      <div key={i} className="wf-recent-file" onClick={() => prepareForBinarySelection(f)}>
                        <span>{f.split(/[\\/]/).pop() ?? f}</span>
                        <span style={{ color: '#555', fontSize: '0.75rem' }}>{f}</span>
                      </div>
                    ))}
                  </div>
                )}
                {workflowState === 'noFile' && (
                  <WorkflowCta
                    workflowState={workflowState}
                    fileName={binaryPath.split(/[\\/]/).pop() ?? binaryPath}
                    hasDisassembly={disassembly.length > 0}
                    hasCfg={cfg !== null && cfg.nodes.length > 0}
                    hasStrings={strings.length > 0}
                    onLoadFile={pickFile}
                    onInspect={inspectFile}
                    onDisassemble={() => disassembleFile()}
                    onBuildCfg={buildCfg}
                    onScanStrings={scanStrings}
                    onRunAnalysis={async () => { await inspectFile(); await scanStrings(); navigateView('verdict'); }}
                    onViewVerdict={() => navigateView('verdict')}
                  />
                )}
              </div>
            )}

            {/* ── Inspect / Metadata ─────────────────────────────────────────── */}
            {/* -- Metadata (compact summary) ------------------------------------------ */}
            {activeView === 'metadata' && (
              <div className="panel" data-testid="panel-metadata">
                {!metadata ? (
                  <div style={{ padding: '2rem', textAlign: 'center', color: '#888' }}>
                    <div style={{ fontSize: '2rem', marginBottom: '0.75rem' }}>??</div>
                    <div>No file loaded. Use <strong>Load Binary</strong> to open a file.</div>
                  </div>
                ) : (
                  <>
                    <h3>File Summary</h3>
                    <div className="metadata-grid">
                      <div className="metadata-row"><span>Type</span><span>{metadata.file_type}</span></div>
                      <div className="metadata-row"><span>Architecture</span><span>{metadata.architecture}</span></div>
                      <div className="metadata-row"><span>Entry Point</span><span>{formatHex(metadata.entry_point)}</span></div>
                      <div className="metadata-row"><span>Image Base</span><span>{formatHex(metadata.image_base)}</span></div>
                      <div className="metadata-row"><span>File Size</span><span>{(metadata.file_size / 1024).toFixed(1)} KB</span></div>
                      <div className="metadata-row"><span>SHA-256</span><span style={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>{metadata.sha256}</span></div>
                      <div className="metadata-row"><span>Sections</span><span>{metadata.sections.length}</span></div>
                      <div className="metadata-row"><span>Imports</span><span>{metadata.imports_count}</span></div>
                      <div className="metadata-row"><span>Exports</span><span>{metadata.exports_count}</span></div>
                      <div className="metadata-row"><span>Symbols</span><span>{metadata.symbols_count}</span></div>
                    </div>
                  </>
                )}
              </div>
            )}

            {/* -- Inspect (full details: sections + imports + exports) ----------- */}
            {activeView === 'inspect' && (
              <>
                {workflowState === 'fileLoaded' && (
                  <WorkflowCta
                    workflowState={workflowState}
                    fileName={binaryPath.split(/[\\/]/).pop() ?? binaryPath}
                    hasDisassembly={disassembly.length > 0}
                    hasCfg={cfg !== null && cfg.nodes.length > 0}
                    hasStrings={strings.length > 0}
                    onLoadFile={pickFile}
                    onInspect={inspectFile}
                    onDisassemble={() => disassembleFile()}
                    onBuildCfg={buildCfg}
                    onScanStrings={scanStrings}
                    onRunAnalysis={async () => { await inspectFile(); navigateView('verdict'); }}
                    onViewVerdict={() => navigateView('verdict')}
                  />
                )}
                {(workflowState === 'inspected' || workflowState === 'analyzed') && !metadata && (
                  <WorkflowCta
                    workflowState="inspected"
                    fileName={binaryPath.split(/[\\/]/).pop() ?? binaryPath}
                    hasDisassembly={disassembly.length > 0}
                    hasCfg={cfg !== null && cfg.nodes.length > 0}
                    hasStrings={strings.length > 0}
                    onLoadFile={pickFile}
                    onInspect={inspectFile}
                    onDisassemble={() => disassembleFile()}
                    onBuildCfg={buildCfg}
                    onScanStrings={scanStrings}
                    onRunAnalysis={async () => { await inspectFile(); navigateView('verdict'); }}
                    onViewVerdict={() => navigateView('verdict')}
                  />
                )}
                {metadata && (
                  <div className="panel" data-testid="panel-inspect">
                    <h3>File Metadata</h3>
                    <div className="metadata-grid">
                      <div className="metadata-row"><span>Type</span><span>{metadata.file_type}</span></div>
                      <div className="metadata-row"><span>Architecture</span><span>{metadata.architecture}</span></div>
                      <div className="metadata-row"><span>Entry Point</span><span>{formatHex(metadata.entry_point)}</span></div>
                      <div className="metadata-row"><span>Image Base</span><span>{formatHex(metadata.image_base)}</span></div>
                      <div className="metadata-row"><span>File Size</span><span>{(metadata.file_size / 1024).toFixed(1)} KB</span></div>
                      <div className="metadata-row"><span>SHA-256</span><span style={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>{metadata.sha256}</span></div>
                    </div>
                    <h4>Sections ({metadata.sections.length})</h4>
                    <div className="imports-table">
                      <div className="imports-row imports-header">
                        <div>Name</div><div>VAddr</div><div>Size</div><div>Entropy</div><div>Perms</div>
                      </div>
                      {metadata.sections.map((sec, i) => (
                        <div key={i} className={`imports-row${sec.entropy > 7.0 ? ' imports-row-danger' : ''}`}>
                          <div><code>{sec.name}</code></div>
                          <div><code>{formatHex(sec.virtual_address)}</code></div>
                          <div>{(sec.file_size / 1024).toFixed(1)} KB</div>
                          <div style={{ color: sec.entropy > 7.0 ? '#ff6b6b' : 'inherit' }}>{sec.entropy.toFixed(2)}</div>
                          <div><code>{sec.permissions}</code></div>
                        </div>
                      ))}
                    </div>
                    {metadata.imports.length > 0 && (
                      <>
                        <h4>Imports ({metadata.imports_count})</h4>
                        <CapabilitySummary imports={metadata.imports} />
                        <div className="imports-table">
                          <div className="imports-row imports-header"><div>Library</div><div>Function</div></div>
                          {metadata.imports.map((imp, i) => {
                            const threat = DANGEROUS_IMPORTS[imp.name];
                            const displayName = demangle(imp.name);
                            const wasMangled = displayName !== imp.name;
                            return (
                              <div key={i} className={`imports-row${threat ? ' imports-row-danger' : ''}`}>
                                <div><code>{imp.library || '-'}</code></div>
                                <div>
                                  <span title={wasMangled ? `Mangled: ${imp.name}` : undefined}>{demangle(imp.name)}</span>
                                  {threat && <span className="import-threat-badge" title={threat}>⚠ {threat}</span>}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </>
                    )}
                    {metadata.exports.length > 0 && (
                      <>
                        <h4>Exports ({metadata.exports_count})</h4>
                        <div className="imports-table">
                          <div className="imports-row imports-header"><div>Address</div><div>Function</div></div>
                          {metadata.exports.map((exp, i) => {
                            const displayName = demangle(exp.name);
                            const wasMangled = displayName !== exp.name;
                            return (
                              <div key={i} className="imports-row">
                                <div><code>{formatHex(exp.address)}</code></div>
                                <div>
                                  <span title={wasMangled ? `Mangled: ${exp.name}` : undefined}>{displayName}</span>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </>
                    )}
                    {peExtras && (
                      <>
                        {peExtras.tls_callbacks.length > 0 && (
                          <>
                            <h4>TLS Callbacks ({peExtras.tls_callbacks.length})</h4>
                            <div className="imports-table">
                              <div className="imports-row imports-header"><div>Address</div></div>
                              {peExtras.tls_callbacks.map((cb, i) => (
                                <div key={i} className="imports-row">
                                  <div><code>{formatHex(cb.address)}</code></div>
                                </div>
                              ))}
                            </div>
                          </>
                        )}
                        {peExtras.resources.length > 0 && (
                          <>
                            <h4>Resources ({peExtras.resources.length})</h4>
                            <div className="imports-table">
                              <div className="imports-row imports-header"><div>Type</div><div>ID</div><div>Size</div></div>
                              {peExtras.resources.slice(0, 50).map((res, i) => (
                                <div key={i} className="imports-row">
                                  <div>{res.type_name}</div>
                                  <div><code>{res.id}</code></div>
                                  <div>{res.size} B</div>
                                </div>
                              ))}
                              {peExtras.resources.length > 50 && (
                                <div className="imports-row" style={{color:'#888',fontStyle:'italic'}}>
                                  <div>… {peExtras.resources.length - 50} more entries</div>
                                </div>
                              )}
                            </div>
                          </>
                        )}
                      </>
                    )}
                  </div>
                )}
              </>
            )}



            {/* Hex Viewer */}
            {activeView === 'hex' && (
              <div className="panel" style={{ padding: 0, height: "100%", display: "flex", flexDirection: "column" }}>
                <HexViewer
                  bytes={hexBytes}
                  baseOffset={hexOffset}
                  selectedIndex={selectedHexIndex}
                  onSelectByte={(idx) => selectAddress(idx)}
                  onJumpToDisasm={(addr) => { selectAddress(addr); navigateView('disassembly'); }}
                  highlightedRange={highlightedHexRange ?? undefined}
                  fileSize={hexFileSize || metadata?.file_size}
                  onLoadMore={() => void previewHexAt(hexOffset + hexBytes.length)}
                />
              </div>
            )}
            {/* ── Strings ───────────────────────────────────────────────────── */}
            {activeView === 'strings' && (
              <div className="panel" data-testid="panel-strings">
                <h3>Strings</h3>
                <div className="strings-controls">
                  <label>Min length <input type="number" min={1} value={stringMinLength} onChange={(e) => setStringMinLength(Number(e.target.value) || 4)} /></label>
                  <label>Filter <input type="text" value={stringFilter} onChange={(e) => setStringFilter(e.target.value)} placeholder="Search strings..." /></label>
                  <label>
                    Kind&nbsp;
                    <select value={stringKindFilter} onChange={(e) => setStringKindFilter(e.target.value as StringKind | 'all')}>
                      <option value="all">All</option>
                      {(['url','ip','domain','registry','filepath','base64','uuid','pe-artifact'] as StringKind[]).map(k => (
                        <option key={k} value={k}>{STRING_KIND_LABELS[k].label || k}</option>
                      ))}
                    </select>
                  </label>
                  <button onClick={scanStrings} data-testid="strings-scan">Scan strings</button>
                </div>
                {strings.length === 0 ? (
                  <p>No strings scanned yet. Click "Scan strings" above.</p>
                ) : (
                  <div className="strings-table">
                    <div className="strings-row strings-header">
                      <div>Offset</div><div>Kind</div><div>String</div>
                    </div>
                    {strings
                      .filter(s => s.text.length >= stringMinLength)
                      .filter(s => !stringFilter || s.text.toLowerCase().includes(stringFilter.toLowerCase()))
                      .filter(s => stringKindFilter === 'all' || classifyString(s.text) === stringKindFilter)
                      .slice(0, 500)
                      .map((s, i) => {
                        const kind = classifyString(s.text);
                        const meta = STRING_KIND_LABELS[kind];
                        return (
                          <div
                            key={i}
                            className="strings-row"
                            onClick={() => {
                              selectAddress(s.offset, { start: s.offset, end: s.offset + s.length });
                              navigateView('disassembly');
                            }}
                          >
                            <div><code>{formatHex(s.offset)}</code></div>
                            <div>{meta.label && <span className="string-kind-badge" style={{ background: meta.color + '22', color: meta.color, border: `1px solid ${meta.color}44` }}>{meta.label}</span>}</div>
                            <div style={{ wordBreak: 'break-all' }}>{s.text}</div>
                          </div>
                        );
                      })
                    }
                  </div>
                )}
              </div>
            )}

            {/* ── Disassembly ───────────────────────────────────────────────── */}
            {activeView === 'disassembly' && (
              disassembly.length === 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', flex: 1, gap: '1rem', color: '#888' }}>
                  {disasmIsLoading ? (
                    <>
                      <div style={{ fontSize: '2.5rem', animation: 'spin 1s linear infinite' }}>⟳</div>
                      <div style={{ fontSize: '1.1rem', fontWeight: 600, color: '#aaa' }}>Disassembling...</div>
                      <div style={{ fontSize: '0.875rem' }}>Processing binary at {disasmOffset ? formatHex(disasmOffset) : 'default offset'}...</div>
                    </>
                  ) : (
                    <>
                      <div style={{ fontSize: '2.5rem' }}>?</div>
                      <div style={{ fontSize: '1.1rem', fontWeight: 600, color: '#aaa' }}>No disassembly loaded</div>
                      <div style={{ fontSize: '0.875rem' }}>Click the <strong style={{ color: '#00d4ff' }}>Disassemble</strong> button in the toolbar above, or use Inspect ? Disassemble.</div>
                      {metadata && (
                        <button
                          type="button"
                          className="wf-cta-primary-btn"
                          style={{ marginTop: '0.5rem' }}
                          onClick={() => disassembleFile()}
                        >
                          ? Disassemble Now
                        </button>
                      )}
                    </>
                  )}
                </div>
              ) : (
              <div className="wf-panel-split">
                <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>
                  {patches.length > 0 && (
                    <PatchPanel
                      patches={patches as PanelPatch[]}
                      binaryPath={binaryPath}
                      onRemovePatch={removePatch}
                      onTogglePatch={togglePatch}
                      onClearAll={clearAllPatches}
                      suggestions={patchSuggestions as any}
                      onQueueSuggestion={(s) => void queueFromSuggestion(s as any)}
                    />
                  )}
                  <DisassemblyList
                    disassembly={disassembly}
                    highlightedDisasmRange={highlightedDisasmRange}
                    disassemblyAnalysis={disassemblyAnalysis}
                    selectedDisasmAddress={selectedDisasmAddress}
                    annotations={annotations}
                    onSelectInstruction={(address) => { setSelectedDisasmAddress(address); selectAddress(address); }}
                    onNavigateToFunction={(address) => { setSelectedFunction(address); }}
                    onShowReferences={(address) => { setSelectedDisasmAddress(address); setShowReferencesPanel(true); }}
                    onInvertJump={(address) => { void queueInvertJump(address); }}
                    onNopOut={(address, count) => { void queueNopSled(address, count); }}
                    onLoadMore={disasmHasMore ? () => disassembleFile(disasmNextByteOffset ?? undefined) : undefined}
                    hasMore={disasmHasMore}
                    isLoadingMore={disasmIsLoadingMore}
                    patchedAddresses={patches.length > 0 ? new Set(patches.map(p => p.address)) : undefined}
                  />
                </div>
                <div className="wf-disasm-sidebar">
                  {disassemblyAnalysis.suspiciousPatterns.length > 0 && (
                    <PatternCategoryBrowser
                      analysis={disassemblyAnalysis}
                      disassembly={disassembly}
                      onNavigate={(addr) => handleSmartNavigation(addr, `Pattern at ${formatHex(addr)}`)}
                    />
                  )}
                  <XRefPanel
                    selectedAddress={selectedDisasmAddress}
                    xrefTypes={xrefTypes}
                    referencesMap={referencesMap}
                    jumpTargetsMap={jumpTargetsMap}
                    onNavigate={(addr) => handleSmartNavigation(addr, `XRef -> ${formatHex(addr)}`)}
                  />
                  <UnifiedAnalysisPanel
                    analysis={disassemblyAnalysis}
                    selectedAddress={selectedDisasmAddress}
                    selectedFunction={selectedFunction}
                    disassembly={disassembly}
                    onNavigate={(addr) => handleSmartNavigation(addr, `Navigate to ${formatHex(addr)}`)}
                  />
                </div>
              </div>
              )
            )}

            {/* ── CFG ───────────────────────────────────────────────────────── */}
            {activeView === 'cfg' && (
              <div style={{ display: 'flex', flex: 1, minHeight: 0, gap: 0 }} data-testid="panel-cfg">
                <div style={{ flex: 1, minHeight: 0, minWidth: 0 }}>
                  <CfgView graph={cfg} naturalLoops={cfgNaturalLoops} onNodeClick={selectCfgBlock} highlightedBlockId={highlightedCfgBlock} onBuildCfg={buildCfg} />
                </div>
                {cfgDomTree && (
                  <div style={{ width: showDomPanel ? 260 : 36, flexShrink: 0, display: 'flex', flexDirection: 'column', borderLeft: '1px solid #2a2a2a', transition: 'width 0.2s' }}>
                    <button
                      type="button"
                      title={showDomPanel ? 'Collapse dominator tree' : 'Show dominator tree (idom/post-dom)'}
                      style={{ background: 'none', border: 'none', color: '#79c0ff', cursor: 'pointer', padding: '0.4rem', fontSize: '0.75rem', borderBottom: '1px solid #2a2a2a', flexShrink: 0, whiteSpace: 'nowrap' }}
                      onClick={() => {
                        setShowDomPanel(v => { localStorage.setItem('hexhawk.showDomPanel', String(!v)); return !v; });
                      }}
                    >
                      {showDomPanel ? '? DOM' : '?'}
                    </button>
                    {showDomPanel && (
                      <div style={{ flex: 1, overflow: 'auto', minHeight: 0 }}>
                        <DomTreePanel
                          domTree={cfgDomTree}
                          postDomTree={cfgPostDomTree ?? undefined}
                          onSelectBlock={(id) => { setHighlightedCfgBlock(id); }}
                          highlightedBlockId={highlightedCfgBlock}
                        />
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* ── Decompile ─────────────────────────────────────────────────── */}
            {activeView === 'decompile' && (
              <div style={{ flex: 1, overflow: 'hidden', minHeight: 0 }} data-testid="panel-decompile">
                <DecompilerView
                  disassembly={disassembly} cfg={cfg} functions={disassemblyAnalysis.functions}
                  currentAddress={currentAddress}
                  onAddressSelect={(addr) => { selectAddress(addr); navigateView('disassembly'); }}
                  metadata={metadata ? { architecture: metadata.architecture } : null}
                />
              </div>
            )}

            {/* ── TALON ────────────────────────────────────────────────────── */}
            {activeView === 'talon' && gateTab('talon', 'TALON', (
              <div style={{ flex: 1, overflow: 'hidden', minHeight: 0 }} data-testid="panel-talon">
                <TalonView
                  disassembly={disassembly}
                  cfg={cfg}
                  functions={disassemblyAnalysis.functions}
                  currentAddress={currentAddress}
                  onAddressSelect={(addr) => { selectAddress(addr); navigateView('disassembly'); }}
                  metadata={metadata ? { architecture: metadata.architecture } : null}
                />
              </div>
            ))}

            {/* ── Verdict (Intelligence answer screen) ───────────────────────── */}
            {activeView === 'verdict' && (
              <div className="panel wf-verdict-panel">
                {(!metadata && workflowState !== 'analyzed') ? (
                  <div className="wf-cta wf-cta--center">
                    <div className="wf-cta-icon">⚖</div>
                    <h2 className="wf-cta-title">No analysis yet</h2>
                    <p className="wf-cta-body">Inspect a file first to generate a verdict.</p>
                    <button type="button" className="wf-cta-primary-btn" onClick={inspectFile}>🔎 Inspect File</button>
                  </div>
                ) : (
                  <>
                    {nestEnrichedVerdict && (
                      <div style={{
                        display: 'flex', alignItems: 'center', gap: '0.5rem',
                        padding: '0.4rem 0.75rem', marginBottom: '0.75rem',
                        background: '#0d2a1f', border: '1px solid #22c55e',
                        borderRadius: '0.4rem', fontSize: '0.82rem', color: '#4ade80',
                      }}>
                        <span>?</span>
                        <span>NEST-enriched verdict - {nestEnrichedVerdict.signals.length} signals, {nestEnrichedVerdict.confidence ?? nestEnrichedVerdict.threatScore}% confidence</span>
                        <button
                          onClick={() => setNestEnrichedVerdict(null)}
                          style={{ marginLeft: 'auto', background: 'none', border: 'none', color: '#4ade80', cursor: 'pointer', fontSize: '0.8rem' }}
                          title="Revert to base verdict"
                        >? revert</button>
                      </div>
                    )}
                    {showSelfHealBanner && !healDismissed && (
                      <AutoHealBanner
                        diagnosis={healDiagnosis}
                        onHeal={handleHeal}
                        onDismiss={() => setHealDismissed(true)}
                      />
                    )}
                    <BinaryVerdict verdict={nestEnrichedVerdict ?? verdict} onNavigateTab={(tab) => setAndPersistTab(tab as AppTab)} onJumpToAddress={jumpToDisassembly} />
                    <div style={{ marginTop: '1.5rem' }}>
                      <AnalysisGraph
                        imports={metadata?.imports ?? []}
                        strings={strings.map(s => ({ offset: s.offset, text: s.text }))}
                        disassembly={disassembly.map(i => ({ address: i.address, mnemonic: i.mnemonic, operands: i.operands }))}
                        patterns={disassemblyAnalysis.suspiciousPatterns}
                        verdict={nestEnrichedVerdict ?? verdict}
                        onNavigate={(tab) => setAndPersistTab(tab as AppTab)}
                        onSelectStringOffset={() => navigateView('strings')}
                        onSelectAddress={(address) => { selectAddress(address); navigateView('disassembly'); }}
                      />
                    </div>
                  </>
                )}
              </div>
            )}

            {/* ── Signals ───────────────────────────────────────────────────── */}
            {activeView === 'signals' && (
              <div className="panel">
                <h3>Pattern Intelligence</h3>
                {disassembly.length === 0 ? (
                  <div className="pi-empty" style={{ padding: '1rem 0.25rem' }}>
                    <div className="pi-empty-icon">📊</div>
                    <div className="pi-empty-text">Signals need disassembly context before pattern intelligence can be scored.</div>
                    <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.85rem', flexWrap: 'wrap' }}>
                      <button
                        type="button"
                        onClick={() => {
                          void disassembleFile();
                          addLog('Signals panel requested disassembly seed.', 'info');
                        }}
                      >⊞ Run Disassembly</button>
                      <button
                        type="button"
                        onClick={() => {
                          void scanStrings();
                          addLog('Signals panel requested string scan seed.', 'info');
                        }}
                      >𝕊 Scan Strings</button>
                    </div>
                  </div>
                ) : disassemblyAnalysis.suspiciousPatterns.length === 0 ? (
                  <div className="pi-empty" style={{ padding: '1rem 0.25rem' }}>
                    <div className="pi-empty-icon">🧭</div>
                    <div className="pi-empty-text">No suspicious patterns were detected yet for this range.</div>
                    <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.85rem', flexWrap: 'wrap' }}>
                      <button
                        type="button"
                        onClick={() => {
                          navigateView('disassembly');
                          addLog('Signals panel redirected to disassembly for manual review.', 'info');
                        }}
                      >Open Disassembly</button>
                      <button
                        type="button"
                        onClick={() => {
                          void buildCfg();
                          addLog('Signals panel requested CFG build for additional context.', 'info');
                        }}
                      >⬡ Build CFG</button>
                    </div>
                  </div>
                ) : (
                  <>
                    {selectedDisasmAddress === null && (
                      <div className="wf-notice" style={{ marginBottom: '0.75rem' }}>
                        Seeded from top pattern at <code>{formatHex(seededSignalsAddress)}</code>. Select another instruction in Disassembly to pivot analysis.
                      </div>
                    )}
                    <PatternIntelligencePanel
                      analysis={disassemblyAnalysis}
                      selectedAddress={seededSignalsAddress}
                      disassembly={disassembly}
                      onNavigate={(addr) => { selectAddress(addr); navigateView('disassembly'); }}
                    />
                  </>
                )}
              </div>
            )}

            {/* ── NEST ──────────────────────────────────────────────────────── */}
            {activeView === 'nest' && gateTab('nest', 'NEST', (
              browserMode ? (
                <div className="panel" data-testid="panel-nest">
                  <h3>NEST (Browser Simulation)</h3>
                  <p>Simulated iterative convergence mode is active. This mirrors Enterprise workflow without invoking the desktop backend.</p>
                  <button
                    type="button"
                    onClick={() => {
                      addLog('Started NEST simulation session in browser mode.', 'info');
                      setNestEnrichedVerdict({
                        ...(verdict ?? computeVerdict({ sections: [], imports: [], strings: [], patterns: [] })),
                        confidence: Math.max(80, verdict?.confidence ?? 0),
                        summary: 'NEST simulation elevated confidence after iterative passes.',
                      });
                      setMessage('NEST simulation completed. Verdict enriched.');
                    }}
                  >
                    ⟳ Start NEST Session
                  </button>
                </div>
              ) : (
                <div style={{ flex: 1, overflow: 'hidden', minHeight: 0 }} data-testid="panel-nest">
                  <NestView
                    binaryPath={binaryPath} metadata={metadata} disassembly={disassembly}
                    strings={strings} disassemblyAnalysis={disassemblyAnalysis}
                    disasmOffset={disasmOffset} disasmLength={disasmLength}
                    onAddressSelect={(addr) => { selectAddress(addr); navigateView('disassembly'); }}
                    onNestComplete={(v) => setNestEnrichedVerdict(v)}
                    onLoadTrainingBinary={(path) => {
                      setBinaryPath(path);
                      setRecentFiles(prev => {
                        const next = [path, ...prev.filter(f => f !== path)].slice(0, 10);
                        localStorage.setItem('hexhawk.recentFiles', JSON.stringify(next));
                        return next;
                      });
                    }}
                  />
                </div>
              )
            ))}

            {/* ── Activity ──────────────────────────────────────────────────── */}
            {activeView === 'activity' && gateTab('logs', 'Activity Logs', <ActivityLog entries={logs} />)}

            {/* ── Intelligence Report ───────────────────────────────────────── */}
            {activeView === 'report' && (
              <div className="panel" style={{ overflowY: 'auto', flex: 1 }} data-testid="panel-report">
                <IntelligenceReport
                  verdict={nestEnrichedVerdict ?? verdict}
                  binaryPath={binaryPath}
                  binarySize={metadata?.file_size}
                  architecture={metadata?.architecture}
                  fileType={metadata?.file_type}
                />
              </div>
            )}

            {/* ── Snapshot History ──────────────────────────────────────────── */}
            {activeView === 'history' && (
              <div className="panel" style={{ overflowY: 'auto', flex: 1 }} data-testid="panel-history">
                <SnapshotHistoryPanel />
              </div>
            )}

            {/* ── Patch ─────────────────────────────────────────────────────── */}
            {activeView === 'patch' && gateTab('disassembly', 'Patch', (
              browserMode ? (
                <div className="panel">
                  <h3>Patch Manager (Browser Simulation)</h3>
                  {patches.length === 0 ? (
                    <p>No queued patches. Add patches from Disassembly first.</p>
                  ) : (
                    <ul>
                      {patches.map((p) => (
                        <li key={p.id}>{formatHex(p.address)} - {p.label}</li>
                      ))}
                    </ul>
                  )}
                </div>
              ) : (
                <div>
                  <PatchPanel
                    patches={patches as PanelPatch[]}
                    binaryPath={binaryPath}
                    onRemovePatch={removePatch}
                    onTogglePatch={togglePatch}
                    onClearAll={clearAllPatches}
                  />
                </div>
              )
            ))}

            {/* ── Constraint ────────────────────────────────────────────────── */}
            {activeView === 'constraint' && gateTab('constraint', 'Constraint', (
              browserMode ? (
                <div className="panel">
                  <h3>Constraint Solver (Browser Simulation)</h3>
                  <p>Simulated taint and key-check flow available in browser mode.</p>
                  <button
                    type="button"
                    onClick={() => {
                      selectAddress(0x140001010);
                      navigateView('disassembly');
                      addLog('Jumped to constraint candidate block (browser simulation).', 'info');
                    }}
                  >Jump to candidate constraint block</button>
                </div>
              ) : (
                <div style={{ flex: 1, overflowY: 'auto', minHeight: 0 }}>
                  <ConstraintPanel
                    disassembly={disassembly} cfg={cfg}
                    onAddressSelect={(addr) => { selectAddress(addr); navigateView('disassembly'); }}
                    ownedSignals={nestEnrichedVerdict?.signals.map(s => s.id)}
                  />
                </div>
              )
            ))}

            {/* ── REPL ─────────────────────────────────────────────────────── */}
            {activeView === 'repl' && gateTab('repl', 'REPL', (
              <div style={{ flex: 1, overflow: 'hidden', minHeight: 0, display: 'flex', flexDirection: 'column' }} data-testid="panel-repl">
                <ReplView binaryPath={binaryPath} />
              </div>
            ))}

            {/* ── Agent Gate ────────────────────────────────────────────────── */}
            {activeView === 'agent' && gateTab('agent', 'Agent Gate', (
              <div style={{ flex: 1, overflowY: 'auto', padding: '12px 16px' }} data-testid="panel-agent">
                <div className="agent-gate-panel">
                  <h2 className="agent-gate-title">⬢ Agent Signal Gate</h2>
                  <p className="agent-gate-desc">
                    External AI agents connected via <code>nest_cli serve --mcp</code> may propose signals for GYRE analysis.
                    Each signal requires explicit analyst approval before it influences the verdict.
                  </p>

                  {/* Pending approvals */}
                  <section className="agent-gate-section">
                    <h3 className="agent-gate-section-title">
                      Pending Approval ({pendingAgentSignals.length})
                    </h3>
                    {pendingAgentSignals.length === 0 ? (
                      <p className="agent-gate-empty">No pending agent signals.</p>
                    ) : (
                      <ul className="agent-signal-list">
                        {pendingAgentSignals.map(p => (
                          <li key={p.pendingId} className="agent-signal-item">
                            <div className="agent-signal-meta">
                              <span className="agent-signal-id">{p.signal.id}</span>
                              <span className={`agent-signal-certainty agent-cert-${p.signal.certainty}`}>{p.signal.certainty}</span>
                              <span className="agent-signal-weight">w={p.signal.weight}</span>
                            </div>
                            <div className="agent-signal-finding">{p.signal.finding}</div>
                            <div className="agent-signal-actions">
                              <button type="button" className="agent-btn-approve" onClick={() => handleApproveAgentSignal(p.pendingId)}>✓ Approve</button>
                              <button type="button" className="agent-btn-reject"  onClick={() => handleRejectAgentSignal(p.pendingId)}>✗ Reject</button>
                            </div>
                          </li>
                        ))}
                      </ul>
                    )}
                  </section>

                  {/* Approved signals */}
                  <section className="agent-gate-section">
                    <h3 className="agent-gate-section-title">
                      Active Agent Signals ({approvedAgentSignals.length})
                    </h3>
                    {approvedAgentSignals.length === 0 ? (
                      <p className="agent-gate-empty">No approved agent signals in current verdict.</p>
                    ) : (
                      <ul className="agent-signal-list agent-signal-list--approved">
                        {approvedAgentSignals.map(s => (
                          <li key={s.id} className="agent-signal-item agent-signal-item--approved">
                            <span className="agent-signal-id">{s.id}</span>
                            <span className="agent-signal-finding">{s.finding}</span>
                            <span className="agent-signal-weight">w={s.weight}</span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </section>

                  {/* Agent action log */}
                  <section className="agent-gate-section">
                    <h3 className="agent-gate-section-title">Agent Action Log ({agentActionLog.length})</h3>
                    {agentActionLog.length === 0 ? (
                      <p className="agent-gate-empty">No actions recorded yet.</p>
                    ) : (
                      <table className="agent-log-table">
                        <thead>
                          <tr><th>Time</th><th>Tool</th><th>Summary</th><th>Decision</th></tr>
                        </thead>
                        <tbody>
                          {[...agentActionLog].reverse().map(e => (
                            <tr key={e.id} className={`agent-log-row agent-log-row--${e.approved === true ? 'approved' : e.approved === false ? 'rejected' : 'pending'}`}>
                              <td>{new Date(e.timestamp).toLocaleTimeString()}</td>
                              <td><code>{e.tool}</code></td>
                              <td>{e.summary}</td>
                              <td>{e.approved === true ? '✓ Approved' : e.approved === false ? '✗ Rejected' : '⏳ Pending'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </section>
                </div>
              </div>
            ))}

            {/* ── Sandbox ───────────────────────────────────────────────────── */}
            {activeView === 'sandbox' && gateTab('sandbox', 'Sandbox', (
              browserMode ? (
                <div className="panel">
                  <h3>Sandbox (Browser Simulation)</h3>
                  <p>Script execution is simulated in browser mode. Use desktop runtime for real subprocess instrumentation.</p>
                  <pre className="plugin-result-output">stdout: simulated behavioral trace\nchild_exit: 0\nsignals: ["networking", "persistence"]</pre>
                </div>
              ) : (
                <div style={{ flex: 1, overflowY: 'auto', minHeight: 0 }}>
                  <SandboxPanel binaryPath={binaryPath} ownedSignals={nestEnrichedVerdict?.signals.map(s => s.id)} />
                </div>
              )
            ))}

            {/* ── Debugger ──────────────────────────────────────────────────── */}
            {activeView === 'debugger' && gateTab('debugger', 'Debugger', (
              browserMode ? (
                <div className="panel">
                  <h3>Debugger (Browser Simulation)</h3>
                  <p>Launch/step/breakpoint actions are simulated for browser QA.</p>
                  <div className="metadata-grid">
                    <div className="metadata-row"><span>RIP</span><span>{formatHex(0x140001010)}</span></div>
                    <div className="metadata-row"><span>RSP</span><span>{formatHex(0x7ffde000)}</span></div>
                    <div className="metadata-row"><span>RAX</span><span>{formatHex(0x0)}</span></div>
                  </div>
                </div>
              ) : (
                <div style={{ flex: 1, overflow: 'hidden', minHeight: 0 }}>
                  <DebuggerPanel
                    binaryPath={binaryPath || null}
                    onAddressSelect={(addr) => { selectAddress(addr); navigateView('disassembly'); }}
                    onNavigateHex={(addr) => { setHexOffset(addr); setAndPersistTab('hex'); }}
                  />
                </div>
              )
            ))}

            {/* -- Binary Diff ------------------------------------------------------------- */}
            {activeView === 'diff' && gateTab('diff', '\u2295 Binary Diff', (
              browserMode ? (
                <div className="panel">
                  <h3>Binary Diff (Browser Simulation)</h3>
                  <p>Diff engine is simulated in browser mode to validate layout and workflow.</p>
                  <div className="imports-table">
                    <div className="imports-row imports-header"><div>Region</div><div>Change</div></div>
                    <div className="imports-row"><div><code>{formatHex(0x140001020)}</code></div><div>Conditional jump inverted</div></div>
                    <div className="imports-row"><div><code>{formatHex(0x14000108a)}</code></div><div>String table delta detected</div></div>
                  </div>
                </div>
              ) : (
                <div style={{ flex: 1, overflowY: 'auto', minHeight: 0, padding: '0.5rem' }}>
                  <BinaryDiffPanel
                    basePath={binaryPath}
                    baseMetadata={metadata}
                    baseStrings={strings}
                    baseDisassembly={disassembly}
                    baseCfg={cfg}
                    baseVerdict={nestEnrichedVerdict ?? verdict}
                    onJumpToAddress={jumpToDisassembly}
                  />
                </div>
              )
            ))}
            {/* ── Plugin Manager ────────────────────────────────────────────── */}
            {activeView === 'plugins' && (
              <div className="panel" data-testid="panel-plugins">
                <h3>Plugin Manager</h3>
                <QuillPanel
                  onPluginListChanged={analyzePlugins}
                />
                {plugins.length > 0 && (
                  <div style={{ marginTop: '1rem' }}>
                    <h4>Built-in Plugins</h4>
                    <div className="plugin-list">
                      {plugins.map((plugin) => {
                        const status = reloadStatus[plugin.name];
                        const isReloading = reloading === plugin.name;
                        return (
                          <div
                            key={plugin.name}
                            className={`plugin-card ${selectedPluginName === plugin.name ? 'selected' : ''}`}
                            onClick={() => setSelectedPluginName(plugin.name)}
                            title={`${plugin.description}${plugin.version ? ` (${plugin.version})` : ''}`}
                          >
                            <div className="plugin-card-top">
                              <div>
                                <strong>{plugin.enabled ? '[?]' : '[ ]'} {plugin.name}</strong>
                                <div className="plugin-description">{plugin.description}</div>
                              </div>
                              <div className="plugin-actions">
                                <button onClick={(e) => { e.stopPropagation(); void reloadPlugin(plugin.name); }} disabled={isReloading}>
                                  {isReloading ? 'Reloading...' : 'Reload'}
                                </button>
                                <div className="plugin-status-icon">{status === 'success' ? '?' : status === 'error' ? '?' : ''}</div>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                    {selectedPlugin && (
                      <div className="panel" style={{ marginTop: '0.5rem' }}>
                        <strong>{selectedPlugin.name}</strong> - {selectedPlugin.description}
                        {selectedPlugin.version && <div>Version: {selectedPlugin.version}</div>}
                        {selectedPlugin.path && <div>Path: {selectedPlugin.path}</div>}
                      </div>
                    )}
                    <div style={{ marginTop: '1rem' }}>
                      <button onClick={analyzePlugins} data-testid="plugins-run">Run Plugins on Current Binary</button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* -- Help -------------------------------------------------------- */}
            {activeView === 'help' && (
              <div className="panel" style={{ maxWidth: 720, lineHeight: 1.7 }}>
                <h3>Help &amp; Keyboard Shortcuts</h3>
                <h4 style={{ color: '#00d4ff' }}>Navigation</h4>
                <table style={{ borderCollapse: 'collapse', width: '100%', marginBottom: '1rem' }}>
                  <tbody>
                    {([
                      ['Ctrl+D', 'Disassembly tab'],
                      ['Ctrl+H', 'Hex Viewer tab'],
                      ['Ctrl+Shift+B', 'Bookmarks tab'],
                      ['Ctrl+G', 'Jump to address dialog'],
                      ['Ctrl+I', 'Inspect file'],
                      ['Ctrl+S', 'Scan strings'],
                      ['?', 'Toggle shortcuts overlay'],
                      ['Ctrl+Alt+Shift+H', 'Reveal hidden self-heal hints'],
                    ] as [string, string][]).map(([key, desc]) => (
                      <tr key={key} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                        <td style={{ padding: '0.35rem 1rem 0.35rem 0', fontFamily: 'monospace', color: '#79c0ff', whiteSpace: 'nowrap' }}>
                          <strong>{key}</strong>
                        </td>
                        <td style={{ padding: '0.35rem 0', color: '#ccc' }}>{desc}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>

                <h4 style={{ color: '#00d4ff' }}>Analysis Workflow</h4>
                <ol style={{ color: '#ccc', paddingLeft: '1.2rem' }}>
                  <li><strong>Load Binary</strong> - open any PE, ELF, PDF, script, or PCAP file.</li>
                  <li><strong>Inspect</strong> - parse headers, hashes, imports, exports, sections.</li>
                  <li><strong>Disassemble / CFG</strong> - multi-arch disassembly and control flow graph.</li>
                  <li><strong>Strings</strong> - extract ASCII + UTF-16 strings; filter by URL/path/API.</li>
                  <li><strong>Run Analysis</strong> - GYRE verdict with full reasoning chain.</li>
                  <li><strong>Verdict / Signals / NEST</strong> - explore scored signals and convergence.</li>
                  <li><strong>Patch / Constraint / Sandbox</strong> - invert jumps, solve serials, run scripts.</li>
                  <li><strong>Export</strong> - save full analysis as JSON or Markdown.</li>
                </ol>

                <h4 style={{ color: '#00d4ff' }}>Beginner Challenge Quickstart</h4>
                <ol style={{ color: '#ccc', paddingLeft: '1.2rem', marginTop: 0 }}>
                  <li><strong>Start in Load</strong> and pick one file from the Challenges folder (for example Gujian3.exe).</li>
                  <li><strong>Press Ctrl+I, then Ctrl+S</strong> to collect metadata and strings before disassembly.</li>
                  <li><strong>Run Analysis</strong> and read Evidence Chain first, then contradictions, then next steps.</li>
                  <li><strong>If confidence stalls below 50%</strong>, open NEST and run more iterations before patching.</li>
                  <li><strong>For scripts or unknown formats</strong>, expect lower confidence and focus on strings + sandbox output instead of PE-specific assumptions.</li>
                  <li><strong>Export report</strong> when finished so you can compare progress across attempts.</li>
                </ol>

                <h4 style={{ color: '#00d4ff' }}>Troubleshooting</h4>
                <ul style={{ color: '#ccc', paddingLeft: '1.2rem', marginTop: 0 }}>
                  <li>Very large binaries can yield a tiny initial disassembly window; use CFG and NEST to expand context.</li>
                  <li>If contradiction count remains high, prioritize corroborated signals and deprioritize isolated hits.</li>
                  <li>If a workflow step is unclear, open Operator Console and request a step-by-step plan for your current file.</li>
                </ul>

                <h4 style={{ color: '#00d4ff' }}>Engines</h4>
                <table style={{ borderCollapse: 'collapse', width: '100%' }}>
                  <tbody>
                    {([
                      ['TALON', 'IR lift ? SSA ? pseudo-code + intent classification'],
                      ['STRIKE', 'Live debugger (Windows / Linux / macOS) with behavioral delta'],
                      ['ECHO', 'Fuzzy signature matching, FLARE crypto/obfuscation patterns'],
                      ['NEST', 'Iterative multi-pass convergence with dampening'],
                      ['GYRE', 'Verdict engine - 23-section signal aggregation + reasoning chain'],
                      ['KITE', 'Knowledge graph - ReactFlow signal-to-verdict visualization'],
                      ['AERIE', 'Operator console - plain-text to step-by-step workflow'],
                      ['CREST', 'Intelligence report - JSON / Markdown export'],
                      ['IMP', 'Binary patch engine - invert jumps, NOP sleds, patched copy'],
                      ['QUILL', 'Plugin system - 4 built-in + runtime user .dll/.so/.dylib plugins'],
                    ] as [string, string][]).map(([eng, desc]) => (
                      <tr key={eng} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                        <td style={{ padding: '0.35rem 1rem 0.35rem 0', color: '#00d4ff', fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
                          <strong>{eng}</strong>
                        </td>
                        <td style={{ padding: '0.35rem 0', color: '#ccc', fontSize: '0.88rem' }}>{desc}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* -- About ------------------------------------------------------- */}
            {activeView === 'about' && (
              <div className="panel" style={{ maxWidth: 680, lineHeight: 1.7 }}>
                <h3>About HexHawk</h3>
                <p style={{ color: '#aaa', fontSize: '0.95rem' }}>
                  HexHawk is a native desktop reverse engineering workstation built with
                  <strong> Rust</strong> (Tauri 2), <strong>React 18</strong>, and <strong>TypeScript</strong>.
                  It combines binary inspection, disassembly, CFG visualization, IR-based pseudo-code,
                  live debugging, and iterative multi-engine threat analysis in a single application.
                </p>

                <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', margin: '1rem 0' }}>
                  {([
                    { label: 'Version', value: buildInfo?.version ?? '1.0.0' },
                    { label: 'License', value: effectiveTier.toUpperCase() },
                    { label: 'Build', value: buildInfo?.is_trial ? 'Trial' : 'Release' },
                  ] as { label: string; value: string }[]).map(({ label, value }) => (
                    <div key={label} style={{
                      background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '0.5rem', padding: '0.6rem 1rem', minWidth: 100,
                    }}>
                      <div style={{ fontSize: '0.72rem', color: '#888', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</div>
                      <div style={{ color: '#00d4ff', fontWeight: 600, fontSize: '1rem' }}>{value}</div>
                    </div>
                  ))}
                </div>

                <h4 style={{ color: '#00d4ff' }}>Technology</h4>
                <ul style={{ color: '#ccc', paddingLeft: '1.2rem', fontSize: '0.9rem' }}>
                  <li>Tauri 2 + Rust backend (Capstone, object, memmap2, HMAC-SHA256)</li>
                  <li>React 18 + TypeScript + Vite frontend</li>
                  <li>ReactFlow for CFG / KITE knowledge graph</li>
                  <li>10 named analysis engines (TALON, STRIKE, ECHO, NEST, GYRE, KITE, AERIE, CREST, IMP, QUILL)</li>
                  <li>Plugin API with C ABI and 7-layer safety isolation</li>
                  <li>HMAC-SHA256 signed license keys (Crockford Base32)</li>
                </ul>

                <h4 style={{ color: '#00d4ff' }}>License Keys</h4>
                <p style={{ color: '#aaa', fontSize: '0.88rem' }}>
                  Keys are in <code>HKHK-XXXXX-XXXXX-XXXXX-XXXXX</code> format.
                  Open the ?? key icon in the top bar to activate a license and unlock Pro or Enterprise features.
                </p>
              </div>
            )}
          </div>

          {/* Operator Console � persistent bottom bar when view is active */}
          {activeView === 'verdict' && effectiveTier !== 'free' && (
            <div className="wf-console-bar">
              <OperatorConsole
                onNavigateTab={(tab) => setAndPersistTab(tab as AppTab)}
                queryLimit={undefined}
                queriesUsed={consoleQueriesUsed}
                onQueryUsed={() => setConsoleQueriesUsed(incrementConsoleQueriesUsed())}
                context={{
                  binaryPath, fileType: metadata?.file_type, architecture: metadata?.architecture,
                  importNames: metadata?.imports?.map((imp) => imp.name) ?? [],
                  stringTexts: strings.map((s) => s.text),
                  verdictClassification: verdict?.classification,
                  verdictBehaviors: verdict?.behaviors as string[] | undefined,
                  signalIds: verdict?.signals?.map((sig) => sig.id) ?? [],
                }}
              />
            </div>
          )}
        </div>
      </div>

      {/* License panel */}
      {showLicensePanel && (
        <LicensePanel
          isTrial={isTrial}
          currentTier={effectiveTier}
          activeLicense={activeLicense}
          onLicenseActivated={(info) => {
            setActiveLicense(info);
            setTierState(info.tier as Tier);
            saveTier(info.tier as Tier);
          }}
          onLicenseCleared={() => {
            setActiveLicense(null);
            setTierState('free');
            saveTier('free');
          }}
          onClose={() => setShowLicensePanel(false)}
        />
      )}
    </div>
  );
}
