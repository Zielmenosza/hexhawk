import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { open as openFileDialog } from '@tauri-apps/plugin-dialog';
import './styles.css';

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
import type { BinaryVerdictResult } from './utils/correlationEngine';
import PatternIntelligencePanel from './components/PatternIntelligencePanel';
import PatternCategoryBrowser from './components/PatternCategoryBrowser';
import WorkflowGuidance from './components/WorkflowGuidance';
import JumpToAddressDialog from './components/JumpToAddressDialog';
import CapabilitySummary from './components/CapabilitySummary';

// Phase 8 — Decision Engine Components
import { AnalysisGraph } from './components/AnalysisGraph';
import { IntelligenceReport } from './components/IntelligenceReport';
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

// Phase 9 — Debugger + Signature
import DebuggerPanel from './components/DebuggerPanel';
import SignaturePanel from './components/SignaturePanel';

// TALON — Reasoning-Aware Decompiler
import TalonView from './components/TalonView';

// STRIKE — Runtime Intelligence Debugger
import StrikeView from './components/StrikeView';

// ECHO — Fuzzy Signature Recognition
import EchoView from './components/EchoView';
import NestView from './components/NestView';
import OperatorConsole from './components/OperatorConsole';
import WelcomeScreen, { shouldShowWelcome, markFirstRunComplete } from './components/WelcomeScreen';

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
  | 'strike'
  | 'echo'
  | 'nest'
  | 'console';

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
  originalBytes: number[];
  patchedBytes: number[];
  enabled: boolean;
  timestamp: number;
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
  type: 'tight_loop' | 'repeated_memory' | 'indirect_call' | 'jump_table' | 'switch_table' | 'obfuscation';
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
    <div className="panel">
      <h3>Activity</h3>
      {entries.length === 0 ? (
        <p>No activity yet.</p>
      ) : (
        <div className="activity-list">
          {entries.map((entry, index) => (
            <div key={`${entry.timestamp}-${index}`} className={`activity-item activity-${entry.level}`}>
              <div className="activity-meta">
                [{entry.timestamp}] {entry.level.toUpperCase()}
              </div>
              <div>{entry.message}</div>
            </div>
          ))}
        </div>
      )}
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

// ─── Virtual HexViewer — module-level constants + row renderer ───────────────
const HEX_ROW_SIZE = 16;
const HEX_ROW_HEIGHT_PX = 28;

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

  // itemData for HexRow — stable object avoids prop-drilling into each row
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
          <span>Size: {bytes.length} bytes</span>
          {selectedIndex !== null && (
            <span>Selected: {formatHex(baseOffset + selectedIndex)}</span>
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

function CfgView({ graph, onNodeClick, highlightedBlockId }: { graph: CfgGraph | null, onNodeClick?: (blockId: string, start: number, end: number) => void, highlightedBlockId?: string | null }) {
  return (
    <div className="panel">
      <h3>Control Flow Graph</h3>
      {!graph || graph.nodes.length === 0 ? (
        <p>No CFG loaded yet.</p>
      ) : (
        <div className="cfg-layout">
          <div>
            <strong>Nodes:</strong> {graph.nodes.length} | <strong>Edges:</strong> {graph.edges.length}
          </div>

          <div>
            <h4>Basic Blocks</h4>
            <div className="cfg-blocks">
              {graph.nodes.map((node) => {
                const nodeType = (node as any).block_type || 'unknown';
                const instrCount = (node as any).instruction_count || 0;
                const isHighlighted = node.id === highlightedBlockId;
                return (
                  <div 
                    key={node.id} 
                    className={`cfg-block cfg-block-${nodeType} ${isHighlighted ? 'cfg-block-highlighted' : ''}`}
                    onClick={() => {
                      if (node.start !== undefined && node.end !== undefined && onNodeClick) {
                        onNodeClick(node.id, node.start, node.end);
                      }
                    }}
                    style={{
                      cursor: (node.start !== undefined && node.end !== undefined && onNodeClick) ? 'pointer' : 'default',
                    }}
                    title={node.start !== undefined ? `Click to inspect range ${formatHex(node.start)}-${formatHex(node.end)}` : ''}
                  >
                    <div><strong>{node.id}</strong></div>
                    {node.start !== undefined ? <div className="cfg-block-addr">{formatHex(node.start)}</div> : null}
                    {instrCount > 0 ? <div className="cfg-block-count">{instrCount} instructions</div> : null}
                    {nodeType === 'entry' && <div className="cfg-block-type">Entry</div>}
                    {nodeType === 'external' && <div className="cfg-block-type">External</div>}
                  </div>
                );
              })}
            </div>
          </div>

          <div>
            <h4>Control Flow Edges</h4>
            <div className="cfg-edges">
              {graph.edges.map((edge, index) => {
                const edgeKind = (edge as any).kind || 'flow';
                const condition = (edge as any).condition || '';
                const label = edgeKind === 'branch' 
                  ? `${condition} branch` 
                  : edgeKind === 'fallthrough'
                  ? 'fallthrough'
                  : edgeKind;
                return (
                  <div key={`${edge.source}-${edge.target}-${index}`} className="cfg-edge-entry">
                    <span className="cfg-edge-source">{edge.source}</span>
                    <span className="cfg-edge-arrow">→</span>
                    <span className="cfg-edge-target">{edge.target}</span>
                    <span className={`cfg-edge-kind cfg-edge-${edgeKind}`}>{label}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [binaryPath, setBinaryPath] = useState<string>(
    () => localStorage.getItem('hexhawk.binaryPath') ?? 'sample.bin'
  );
  const [recentFiles, setRecentFiles] = useState<string[]>(
    () => JSON.parse(localStorage.getItem('hexhawk.recentFiles') ?? '[]')
  );
  const [showWelcome, setShowWelcome] = useState<boolean>(() => shouldShowWelcome());
  const [activeTab, setActiveTab] = useState<AppTab>(
    () => (localStorage.getItem('hexhawk.activeTab') as AppTab) ?? 'metadata'
  );
  const [message, setMessage] = useState('Ready for analysis');

  const [metadata, setMetadata] = useState<FileMetadata | null>(null);
  const [hexBytes, setHexBytes] = useState<number[]>([]);
  const [hexOffset, setHexOffset] = useState<number>(
    () => Number(localStorage.getItem('hexhawk.hexOffset') ?? 0)
  );
  const [hexLength, setHexLength] = useState<number>(
    () => Number(localStorage.getItem('hexhawk.hexLength') ?? 256)
  );
  const [selectedHexIndex, setSelectedHexIndex] = useState<number | null>(null);
  const [selectedDisasmAddress, setSelectedDisasmAddress] = useState<number | null>(null);
  const [disasmOffset, setDisasmOffset] = useState<number>(
    () => Number(localStorage.getItem('hexhawk.disasmOffset') ?? 0)
  );
  const [disasmLength, setDisasmLength] = useState<number>(
    () => Number(localStorage.getItem('hexhawk.disasmLength') ?? 256)
  );
  const [disassembly, setDisassembly] = useState<DisassembledInstruction[]>([]);
  const [disasmArch, setDisasmArch] = useState<string | null>(null);
  const [disasmArchFallback, setDisasmArchFallback] = useState<boolean>(false);
  const [cfg, setCfg] = useState<CfgGraph | null>(null);
  const [strings, setStrings] = useState<StringMatch[]>([]);
  const [stringKindFilter, setStringKindFilter] = useState<StringKind | 'all'>('all');
  const [stringMinLength, setStringMinLength] = useState<number>(
    () => Number(localStorage.getItem('hexhawk.stringMinLength') ?? 4)
  );
  const [pluginResults, setPluginResults] = useState<PluginExecutionResult[]>([]);
  const [plugins, setPlugins] = useState<PluginMetadata[]>([]);
  const [selectedPluginName, setSelectedPluginName] = useState<string>('');
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

  // PHASE 5: Advanced Analysis Results
  const [disassemblyAnalysis, setDisassemblyAnalysis] = useState<DisassemblyAnalysis>({
    functions: new Map(),
    loops: [],
    suspiciousPatterns: [],
    referenceStrength: new Map(),
    blockAnalysis: new Map(),
  });
  const [selectedFunction, setSelectedFunction] = useState<number | null>(
    () => Number(localStorage.getItem('hexhawk.selectedFunction') ?? 'null') || null
  );
  const [expandedFunctions, setExpandedFunctions] = useState<Set<number>>(new Set());

  // Unified threat verdict — correlates structure, imports, strings, disassembly
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
    });
  }, [metadata, strings, disassemblyAnalysis.suspiciousPatterns]);

  // PHASE 8: Auto-annotation engine state
  const [autoAnnotations, setAutoAnnotations] = useState<AutoAnnotation[]>([]);
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

  const runSemanticSearch = (query: string) => {
    if (!query.trim()) { setSemanticResult(null); return; }
    const result = semanticSearch(query, {
      imports: metadata?.imports ?? [],
      strings: strings.map(s => ({ offset: s.offset, text: s.text })),
      patterns: disassemblyAnalysis.suspiciousPatterns,
    });
    setSemanticResult(result);
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
    () => JSON.parse(localStorage.getItem('hexhawk.recentJumpAddresses') ?? '[]')
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
      return { type: 'NOP', color: '#565f89', badge: '—' };  // Gray
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
    setTimeout(() => {
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
    const callTargets = new Set<number>();
    
    // Collect all CALL targets as likely function starts
    instructions.forEach((ins) => {
      if (ins.mnemonic.toLowerCase().startsWith('call') && ins.operands) {
        const targets = targetMap.get(ins.address) || new Set();
        targets.forEach((addr) => callTargets.add(addr));
      }
    });

    // Prologue patterns (x64): push rbp; mov rbp,rsp or sub rsp,<N>
    let i = 0;
    while (i < instructions.length) {
      const curr = instructions[i];
      let funcStart = curr.address;
      let prologueType: FunctionMetadata['prologueType'] = undefined;
      let hasRet = false;
      let callCount = 0;
      let returnCount = 0;

      // Check for prologue
      if (curr.mnemonic.toLowerCase() === 'push' && curr.operands.includes('rbp')) {
        if (i + 1 < instructions.length && instructions[i + 1].mnemonic.toLowerCase().startsWith('mov')) {
          prologueType = 'push_rbp';
          i += 2;
        }
      } else if (curr.mnemonic.toLowerCase().startsWith('sub') && curr.operands.includes('rsp')) {
        prologueType = 'sub_rsp';
        i++;
      } else if (callTargets.has(funcStart)) {
        prologueType = 'custom';
        i++;
      } else {
        i++;
        continue;
      }

      // Scan for function end (ret instruction or next function start)
      let funcEnd = funcStart;
      let j = i;
      while (j < instructions.length) {
        const ins = instructions[j];
        funcEnd = ins.address;

        if (ins.mnemonic.toLowerCase().startsWith('ret')) {
          hasRet = true;
          returnCount++;
        }
        if (ins.mnemonic.toLowerCase().startsWith('call')) {
          callCount++;
        }

        // Stop at next likely function start
        if (callTargets.has(ins.address) && j > i) {
          break;
        }

        j++;
      }

      if (prologueType || hasRet) {
        const incomingCalls = refMap.get(funcStart) || new Set();
        const size = funcEnd - funcStart;
        
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
        });
      }
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
      message: messageText,
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
    URL.revokeObjectURL(url);
    addLog('Exported analysis to JSON file.');
  }

  function setAndPersistTab(tab: AppTab) {
    setActiveTab(tab);
    localStorage.setItem('hexhawk.activeTab', tab);
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
      try {
        const response = await invoke<PluginMetadata[]>('list_available_plugins');
        setPlugins(response);
        if (response.length > 0) {
          setSelectedPluginName((current) => current || response[0].name);
        }
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
    try {
      const selected = await openFileDialog({ multiple: false, directory: false });
      if (selected && typeof selected === 'string') {
        setBinaryPath(selected);
        setRecentFiles(prev => {
          const next = [selected, ...prev.filter(f => f !== selected)].slice(0, 10);
          localStorage.setItem('hexhawk.recentFiles', JSON.stringify(next));
          return next;
        });
      }
    } catch {
      // User cancelled
    }
  }

  async function inspectFile() {
    try {
      const response = await invoke<FileMetadata>('inspect_file_metadata', {
        path: binaryPath,
      });
      setMetadata(response);
      setMessage('File inspection completed');
      addLog(`Inspected file: ${binaryPath}`);
      setAndPersistTab('metadata');
    } catch (error) {
      const msg = String(error);
      console.error('Failed to inspect file', error);
      setMessage(`Failed to inspect file: ${msg}`);
      addLog(`Failed to inspect file: ${msg}`, 'error');
      setMetadata(null);
    }
  }

  async function previewHex() {
    try {
      const response = await invoke<number[]>('read_hex_range', {
        path: binaryPath,
        offset: hexOffset,
        length: hexLength,
      });
      setHexBytes(response);
      setSelectedHexIndex(null);
      setSelectedDisasmAddress(null);
      setMessage('Hex preview loaded');
      addLog(`Loaded hex preview for ${binaryPath} at offset ${hexOffset}`);
      setAndPersistTab('hex');
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
    try {
      const response = await invoke<number[]>('read_hex_range', {
        path: binaryPath,
        offset,
        length: hexLength,
      });
      setHexOffset(offset);
      setHexBytes(response);
      setSelectedHexIndex(0);
      setSelectedDisasmAddress(null);
      setMessage(`Hex preview loaded at ${formatHex(offset)}`);
      addLog(`Loaded hex preview at ${formatHex(offset)} for ${binaryPath}`);
      setAndPersistTab('hex');
    } catch (error) {
      const msg = String(error);
      console.error('Failed to load hex preview at offset', error);
      setMessage(`Failed to load hex preview: ${msg}`);
      addLog(`Failed to load hex preview: ${msg}`, 'error');
    }
  }

  async function scanStrings() {
    try {
      const response = await invoke<StringMatch[]>('find_strings', {
        path: binaryPath,
        offset: hexOffset,
        length: hexLength,
        min_length: stringMinLength,
      });
      setStrings(response);
      setMessage(`Found ${response.length} strings from ${formatHex(hexOffset)}`);
      addLog(`Scanned strings in ${binaryPath} at ${formatHex(hexOffset)} length ${hexLength}`);
      setAndPersistTab('strings');
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
    try {
      const response = await invoke<{ arch: string; is_fallback: boolean; instructions: DisassembledInstruction[] }>('disassemble_file_range', {
        path: binaryPath,
        offset: startOffset,
        length: disasmLength,
      });
      setDisassembly(response.instructions);
      setDisasmArch(response.arch);
      setDisasmArchFallback(response.is_fallback);
      setDisasmOffset(startOffset);
      const archNote = response.is_fallback ? ` (⚠ unsupported arch — fell back to ${response.arch})` : ` (${response.arch})`;
      setMessage(`Disassembly loaded from ${formatHex(startOffset)}${archNote}`);
      addLog(`Disassembled ${binaryPath} from ${formatHex(startOffset)}${archNote}`, response.is_fallback ? 'warn' : 'info');
      
      // PHASE 5: Perform analysis on disassembly
      performFullAnalysis(response.instructions, cfg);
      
      setAndPersistTab('disassembly');
    } catch (error) {
      const msg = String(error);
      console.error('Failed to disassemble file', error);
      setMessage(`Failed to disassemble file: ${msg}`);
      addLog(`Failed to disassemble file: ${msg}`, 'error');
      setDisassembly([]);
    }
  }

  async function buildCfg() {
    try {
      const response = await invoke<CfgGraph>('build_cfg', {
        path: binaryPath,
        offset: disasmOffset,
        length: disasmLength,
      });
      setCfg(response);
      setMessage('CFG built successfully');
      addLog(`Built CFG for ${binaryPath}`);
      
      // PHASE 5: Re-analyze with new CFG data
      performFullAnalysis(disassembly, response);
      
      setAndPersistTab('cfg');
    } catch (error) {
      const msg = String(error);
      console.error('Failed to build CFG', error);
      setMessage(`Failed to build CFG: ${msg}`);
      addLog(`Failed to build CFG: ${msg}`, 'error');
      setCfg(null);
    }
  }

  async function analyzePlugins() {
    try {
      const response = await invoke<PluginExecutionResult[]>('run_plugins_on_file', {
        path: binaryPath,
      });
      setPluginResults(response);
      setMessage('Plugin analysis completed');
      addLog(`Ran plugin analysis for ${binaryPath}`);
      setAndPersistTab('plugins');
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
      
      setTimeout(() => {
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
      
      setTimeout(() => {
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
    setTimeout(() => {
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
      await invoke('reload_plugin', { name });
      setReloadStatus((current) => ({ ...current, [name]: 'success' }));
      setMessage(`Reloaded plugin: ${name}`);
      addLog(`Reloaded plugin ${name}`);
      setTimeout(() => {
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

  const tabs: AppTab[] = ['metadata', 'hex', 'strings', 'cfg', 'plugins', 'disassembly', 'decompile', 'talon', 'debugger', 'strike', 'signatures', 'echo', 'nest', 'console', 'bookmarks', 'logs', 'graph', 'report'];

  return (
    <div className="app-shell">
      {/* First-run welcome screen */}
      {showWelcome && (
        <WelcomeScreen
          onDismiss={(permanent) => {
            if (permanent) markFirstRunComplete();
            setShowWelcome(false);
          }}
          onOpenFile={() => {
            // reuse existing file-open logic if available
            void openFileDialog({ multiple: false }).then((selected) => {
              if (typeof selected === 'string') setBinaryPath(selected);
            });
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
          // Navigate in whichever tab is active
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
      <header className="app-header">
        <div>
          <h1>HexHawk</h1>
          <p>Reverse engineering workspace with disassembly and CFG visualization.</p>
        </div>
        <div className="semantic-search-bar">
          <input
            type="text"
            className="semantic-search-input"
            placeholder="Search by intent: e.g. 'network activity', 'process injection'…"
            value={semanticQuery}
            onChange={(e) => setSemanticQuery(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') runSemanticSearch(semanticQuery); }}
          />
          <button className="semantic-search-btn" onClick={() => runSemanticSearch(semanticQuery)}>
            Search
          </button>
          {semanticResult && (
            <button className="semantic-search-clear" onClick={() => { setSemanticQuery(''); setSemanticResult(null); }}>
              ✕
            </button>
          )}
        </div>
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
          </div>
        )}
      </header>

      <StatusPanel status={message} />
      
      {currentAddress !== null && (
        <div style={{
          background: 'rgba(0, 100, 200, 0.15)',
          border: '1px solid rgba(0, 180, 255, 0.3)',
          borderRadius: '0.5rem',
          padding: '0.5rem 1rem',
          margin: '0.5rem 0',
          fontSize: '0.9rem',
          color: '#7fb6ff',
          fontFamily: 'monospace',
        }}>
          <strong>Global Context:</strong> {formatHex(currentAddress)}{currentRange && ` (range: ${formatHex(currentRange.start)}-${formatHex(currentRange.end)})`}
        </div>
      )}

      <div className="app-body">
        <aside className="sidebar">
          <div className="panel">
            <h3>Binary</h3>
            <div className="file-picker-row">
              <span className="binary-path-display" title={binaryPath}>
                {binaryPath.split(/[\\/]/).pop() || binaryPath}
              </span>
              <button type="button" className="browse-btn" onClick={pickFile} title={binaryPath}>
                Browse…
              </button>
            </div>
            {recentFiles.length > 0 && (
              <select
                className="recent-files-select"
                value=""
                onChange={(e) => { if (e.target.value) setBinaryPath(e.target.value); }}
              >
                <option value="">Recent files…</option>
                {recentFiles.map((f, i) => (
                  <option key={i} value={f}>{f.split(/[\\/]/).pop() ?? f}</option>
                ))}
              </select>
            )}
            <div className="hex-control-row">
              <label>
                Offset
                <input
                  type="number"
                  min={0}
                  value={hexOffset}
                  onChange={(e) => setHexOffset(Number(e.target.value) || 0)}
                />
              </label>
              <label>
                Length
                <input
                  type="number"
                  min={16}
                  value={hexLength}
                  onChange={(e) => setHexLength(Number(e.target.value) || 256)}
                />
              </label>
            </div>
            <div className="hex-control-row">
              <label>
                Disasm offset
                <input
                  type="number"
                  min={0}
                  value={disasmOffset}
                  onChange={(e) => setDisasmOffset(Number(e.target.value) || 0)}
                />
              </label>
              <label>
                Disasm length
                <input
                  type="number"
                  min={16}
                  value={disasmLength}
                  onChange={(e) => setDisasmLength(Number(e.target.value) || 256)}
                />
              </label>
            </div>
            <div className="button-row">
              <button onClick={inspectFile}>Inspect file</button>
              <button onClick={previewHex}>Hex preview</button>
              <button onClick={scanStrings}>Scan strings</button>
              <button onClick={() => disassembleFile()}>Disassemble</button>
              <button onClick={buildCfg}>Build CFG</button>
              <button onClick={analyzePlugins}>Analyze plugins</button>
            </div>
            <div className="button-row" style={{ marginTop: '0.5rem' }}>
              <button
                type="button"
                onClick={exportAnalysis}
                disabled={!metadata}
                title="Export current analysis as JSON"
                style={{ fontSize: '0.8rem' }}
              >
                ⬇ Export Analysis
              </button>
              <button
                type="button"
                onClick={() => setShowJumpDialog(true)}
                title="Jump to address (Ctrl+G)"
                style={{ fontSize: '0.8rem' }}
              >
                ↗ Jump to…
              </button>
            </div>
          </div>

          <div className="panel">
            <h3>Plugins</h3>
            {plugins.length === 0 ? (
              <p>No plugin crates found in workspace.</p>
            ) : (
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
                          <strong>{plugin.enabled ? '[✓]' : '[ ]'} {plugin.name}</strong>
                          <div className="plugin-description">{plugin.description}</div>
                        </div>
                        <div className="plugin-actions">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              void reloadPlugin(plugin.name);
                            }}
                            disabled={isReloading}
                          >
                            {isReloading ? 'Reloading...' : 'Reload'}
                          </button>
                          <div className="plugin-status-icon">
                            {status === 'success' ? '✅' : status === 'error' ? '⚠️' : ''}
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <div className="panel">
            <h3>Current binary path</h3>
            <div className="binary-path-display">{binaryPath}</div>
          </div>

          {selectedPlugin ? (
            <div className="panel">
              <h3>Selected plugin</h3>
              <div><strong>{selectedPlugin.name}</strong></div>
              <div>{selectedPlugin.description}</div>
              {selectedPlugin.version ? <div>Version: {selectedPlugin.version}</div> : null}
              {selectedPlugin.path ? <div>Path: {selectedPlugin.path}</div> : null}
            </div>
          ) : null}

          {/* Unified Intelligence Verdict */}
          <div className="panel verdict-panel-container">
            <h3>Intelligence</h3>
            <BinaryVerdict
              verdict={verdict}
              onNavigateTab={(tab) => setAndPersistTab(tab as AppTab)}
            />
          </div>
        </aside>

        <main className="main-content">
          <div className="tab-row">
            {tabs.map((tab) => (
              <button
                key={tab}
                onClick={() => setAndPersistTab(tab)}
                className={activeTab === tab ? 'active-tab' : ''}
              >
                {tab === 'metadata'
                  ? 'Metadata'
                  : tab === 'hex'
                  ? 'Hex Viewer'
                  : tab === 'cfg'
                  ? 'CFG'
                  : tab === 'plugins'
                  ? 'Plugin Results'
                  : tab === 'disassembly'
                  ? 'Disassembly'
                  : tab === 'strings'
                  ? 'Strings'
                  : tab === 'bookmarks'
                  ? 'Bookmarks'
                  : tab === 'graph'
                  ? '⬡ Graph'
                  : tab === 'report'
                  ? '📊 Report'
                  : tab === 'decompile'
                  ? '⟨/⟩ Decompile'
                  : tab === 'debugger'
                  ? '⚙ Debugger'
                  : tab === 'strike'
                  ? '⚡ STRIKE'
                  : tab === 'signatures'
                  ? '🔍 Signatures'
                  : tab === 'echo'
                  ? '◎ ECHO'
                  : tab === 'nest'
                  ? '⟳ NEST'
                  : tab === 'talon'
                  ? '⟁ TALON'
                  : 'Activity'}
              </button>
            ))}
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '0.5rem' }}>
            <button
              onClick={() => setShowKeyboardHelp(!showKeyboardHelp)}
              style={{
                padding: '0.4rem 0.8rem',
                fontSize: '0.85rem',
                backgroundColor: '#444',
                color: '#aaa',
                border: '1px solid #555',
                borderRadius: '0.3rem',
                cursor: 'pointer',
              }}
              title="Press ? to toggle keyboard shortcuts help"
            >
              ⌨️ Keyboard Shortcuts (?)
            </button>
          </div>

          {showKeyboardHelp && (
            <div style={{
              backgroundColor: '#1a1a2e',
              border: '2px solid #00bfff',
              borderRadius: '0.5rem',
              padding: '1.5rem',
              marginBottom: '1rem',
              color: '#ddd',
              fontFamily: 'monospace',
              fontSize: '0.9rem',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <h3 style={{ margin: 0, color: '#00bfff' }}>⌨️ Keyboard Shortcuts</h3>
                <button
                  onClick={() => setShowKeyboardHelp(false)}
                  style={{
                    backgroundColor: 'transparent',
                    border: 'none',
                    color: '#aaa',
                    cursor: 'pointer',
                    fontSize: '1.2rem',
                  }}
                >
                  ✕
                </button>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
                <div>
                  <h4 style={{ color: '#00d4ff', marginTop: 0 }}>Navigation</h4>
                  <div style={{ lineHeight: '1.8' }}>
                    <div><strong>Ctrl+D</strong> → Disassembly tab</div>
                    <div><strong>Ctrl+H</strong> → Hex Viewer tab</div>
                    <div><strong>Ctrl+Shift+B</strong> → Bookmarks tab</div>
                    <div><strong>Ctrl+G</strong> → Go back in history</div>
                    <div><strong>Ctrl+Y</strong> → Go forward in history</div>
                  </div>
                </div>

                <div>
                  <h4 style={{ color: '#00d4ff', marginTop: 0 }}>Analysis</h4>
                  <div style={{ lineHeight: '1.8' }}>
                    <div><strong>Ctrl+B</strong> → Bookmark current address</div>
                    <div><strong>Ctrl+J</strong> → Jump from disasm to hex</div>
                    <div><strong>Ctrl+F</strong> → Focus search in current tab</div>
                    <div><strong>↑/↓</strong> → Navigate instructions (disasm)</div>
                  </div>
                </div>
              </div>

              <div style={{ marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid #444', color: '#999', fontSize: '0.85rem' }}>
                <strong>Tip:</strong> Press <strong>?</strong> or <strong>Ctrl+Shift+/</strong> to toggle this help. Press <strong>Esc</strong> to close.
              </div>
            </div>
          )}

          {activeTab === 'metadata' && (
            <div className="panel">
              <h3>File metadata</h3>
              {!metadata ? (
                <p>No metadata loaded yet. Click Inspect file to begin.</p>
              ) : (
                <div className="metadata-grid">
                  <div><strong>Type:</strong> {metadata.file_type}</div>
                  <div><strong>Architecture:</strong> {metadata.architecture}</div>
                  <div><strong>Entry point:</strong> {formatHex(metadata.entry_point)}</div>
                  <div><strong>Image base:</strong> {formatHex(metadata.image_base)}</div>
                  <div><strong>File size:</strong> {metadata.file_size.toLocaleString()} bytes</div>

                  <div><strong>Imports:</strong> {metadata.imports_count} | <strong>Exports:</strong> {metadata.exports_count} | <strong>Symbols:</strong> {metadata.symbols_count}</div>

                  <div>
                    <strong>Hashes</strong>
                    <div className="hash-display">
                      <div><code>{metadata.sha256}</code> <span className="hash-label">SHA-256</span></div>
                      <div><code>{metadata.sha1}</code> <span className="hash-label">SHA-1</span></div>
                      <div><code>{metadata.md5}</code> <span className="hash-label">MD5</span></div>
                    </div>
                  </div>

                  <div>
                    <h4>Sections ({metadata.sections.length})</h4>
                    {metadata.sections.length === 0 ? (
                      <p>No sections found.</p>
                    ) : (
                      <div className="section-table">
                        <div className="section-row section-header">
                          <div>Name</div>
                          <div>File Offset</div>
                          <div>File Size</div>
                          <div>Virtual Address</div>
                          <div>Virtual Size</div>
                          <div>Entropy</div>
                        </div>
                        {metadata.sections.map((section, index) => {
                          const ent = section.entropy ?? 0;
                          const entPct = Math.round((ent / 8) * 100);
                          const entColor = ent >= 7.0 ? '#ff5555' : ent >= 5.5 ? '#ffaa44' : '#44cc88';
                          return (
                          <div 
                            key={`${section.name}-${index}`} 
                            className="section-row section-interactive"
                            onClick={() => {
                              jumpToHex(section.file_offset, section.file_size);
                              selectAddress(section.file_offset, { start: section.file_offset, end: section.file_offset + section.file_size });
                            }}
                            title={`Entropy: ${ent.toFixed(2)} — Click to jump to this section`}
                          >
                            <div><strong>{section.name || '(unnamed)'}</strong></div>
                            <div>{formatHex(section.file_offset)}</div>
                            <div>{section.file_size.toLocaleString()}</div>
                            <div>{formatHex(section.virtual_address)}</div>
                            <div>{section.virtual_size.toLocaleString()}</div>
                            <div className="entropy-cell">
                              <div className="entropy-bar-track">
                                <div className="entropy-bar-fill" style={{ width: `${entPct}%`, background: entColor }} />
                              </div>
                              <span className="entropy-label" style={{ color: entColor }}>{ent.toFixed(2)}</span>
                              {ent >= 7.0 && <span className="entropy-warn" title="High entropy — possibly packed or encrypted">⚠</span>}
                            </div>
                          </div>
                          );
                        })}
                      </div>
                    )}
                  </div>

                  {metadata.imports.length > 0 && (
                    <div>
                      <h4>Imports ({metadata.imports_count})</h4>
                      {/* Capability summary — groups imports into behavioral clusters */}
                      <CapabilitySummary imports={metadata.imports} />
                      <div className="imports-table">
                        <div className="imports-row imports-header">
                          <div>Library</div>
                          <div>Function</div>
                        </div>
                        {metadata.imports.map((imp, i) => {
                          const threat = DANGEROUS_IMPORTS[imp.name];
                          return (
                            <div key={i} className={`imports-row${threat ? ' imports-row-danger' : ''}`}>
                              <div><code>{imp.library || '—'}</code></div>
                              <div>
                                {imp.name}
                                {threat && (
                                  <span className="import-threat-badge" title={threat}>⚠ {threat}</span>
                                )}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {metadata.exports.length > 0 && (
                    <div>
                      <h4>Exports ({metadata.exports_count})</h4>
                      <div className="imports-table">
                        <div className="imports-row imports-header">
                          <div>Address</div>
                          <div>Function</div>
                        </div>
                        {metadata.exports.map((exp, i) => (
                          <div key={i} className="imports-row">
                            <div><code>{formatHex(exp.address)}</code></div>
                            <div>{exp.name}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {activeTab === 'hex' && (
            <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
              {/* Grouping + highlight toolbar */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', padding: '0.5rem 0.75rem', background: '#1a1a2e', borderBottom: '1px solid #333', flexWrap: 'wrap', fontSize: '0.8rem' }}>
                <span style={{ color: '#888' }}>Byte grouping:</span>
                {([1, 2, 4, 8] as const).map(g => (
                  <button
                    key={g}
                    type="button"
                    onClick={() => { setHexGrouping(g); localStorage.setItem('hexhawk.hexGrouping', String(g)); }}
                    style={{
                      background: hexGrouping === g ? 'rgba(0,191,255,0.15)' : 'none',
                      border: `1px solid ${hexGrouping === g ? '#00bfff' : '#444'}`,
                      color: hexGrouping === g ? '#00bfff' : '#aaa',
                      borderRadius: '0.25rem',
                      padding: '0.15rem 0.5rem',
                      cursor: 'pointer',
                      fontSize: '0.78rem',
                    }}
                  >{g}B</button>
                ))}
                <span style={{ color: '#888', marginLeft: '1rem' }}>Highlight:</span>
                {(['none', 'null', 'printable', 'entropy'] as const).map(m => (
                  <button
                    key={m}
                    type="button"
                    onClick={() => { setHexHighlightMode(m); localStorage.setItem('hexhawk.hexHighlightMode', m); }}
                    style={{
                      background: hexHighlightMode === m ? 'rgba(0,191,255,0.15)' : 'none',
                      border: `1px solid ${hexHighlightMode === m ? '#00bfff' : '#444'}`,
                      color: hexHighlightMode === m ? '#00bfff' : '#aaa',
                      borderRadius: '0.25rem',
                      padding: '0.15rem 0.5rem',
                      cursor: 'pointer',
                      fontSize: '0.78rem',
                      textTransform: 'capitalize',
                    }}
                  >{m}</button>
                ))}
              </div>
              <HexViewer
                bytes={hexBytes}
                baseOffset={hexOffset}
                selectedIndex={selectedHexIndex}
                onSelectByte={selectHexByte}
                onJumpToDisasm={(address) => {
                  setSelectedDisasmAddress(address);
                  disassembleFile(address);
                }}
                highlightedRange={highlightedHexRange}
                onRangeSelect={selectHexRange}
                hexGrouping={hexGrouping}
                hexHighlightMode={hexHighlightMode}
              />
            </div>
          )}
          {activeTab === 'cfg' && <CfgView graph={cfg} onNodeClick={selectCfgBlock} highlightedBlockId={highlightedCfgBlock} />}

          {activeTab === 'strings' && (
            <div className="panel">
              <h3>Strings</h3>
              <div className="strings-controls">
                <div>
                  <strong>Range:</strong> {formatHex(hexOffset)} + {hexLength} bytes
                </div>
                <label>
                  Minimum length
                  <input
                    type="number"
                    min={1}
                    value={stringMinLength}
                    onChange={(e) => setStringMinLength(Number(e.target.value) || 4)}
                  />
                </label>
                <label>
                  Filter kind
                  <select value={stringKindFilter} onChange={(e) => setStringKindFilter(e.target.value as StringKind | 'all')}>
                    <option value="all">All</option>
                    {(Object.keys(STRING_KIND_LABELS) as StringKind[]).filter(k => k !== 'plain').map(k => (
                      <option key={k} value={k}>{STRING_KIND_LABELS[k].label}</option>
                    ))}
                    <option value="plain">Plain</option>
                  </select>
                </label>
                <button type="button" onClick={scanStrings}>Refresh</button>
              </div>

              {strings.length === 0 ? (
                <p>No strings found yet. Click Scan strings to search the current range.</p>
              ) : (
                <div className="string-list">
                  <div className="string-row string-row-header">
                    <div>Offset</div>
                    <div>Length</div>
                    <div>Kind</div>
                    <div>Text</div>
                    <div style={{ width: '55px', textAlign: 'center' }}>Entropy</div>
                    <div style={{ width: '100px', textAlign: 'center' }}>Actions</div>
                  </div>
                  {strings.filter(item => {
                    if (stringKindFilter === 'all') return true;
                    return classifyString(item.text) === stringKindFilter;
                  }).map((item) => {
                    const kind = classifyString(item.text);
                    const kindMeta = STRING_KIND_LABELS[kind];
                    const isHighlighted = highlightedStrings.has(item.offset);
                    // Compute Shannon entropy for the string
                    const stringEntropy = (() => {
                      const freq: Record<string, number> = {};
                      for (const c of item.text) freq[c] = (freq[c] ?? 0) + 1;
                      const len = item.text.length;
                      let h = 0;
                      for (const cnt of Object.values(freq)) {
                        const p = cnt / len;
                        h -= p * Math.log2(p);
                      }
                      return Math.round(h * 10) / 10;
                    })();
                    const entropyColor = stringEntropy > 3.5 ? '#f44336' : stringEntropy > 2.5 ? '#ffc107' : '#4caf50';
                    // Check if referenced by disassembly (address in referencesMap/jumpTargetsMap)
                    const isXrefTarget = referencesMap.has(item.offset) || jumpTargetsMap.has(item.offset);
                    return (
                      <div 
                        key={`${item.offset}-${item.length}`} 
                        className={`string-row string-row-interactive ${isHighlighted ? 'highlighted' : ''}`}
                        onClick={() => selectAddress(item.offset, { start: item.offset, end: item.offset + item.length })}
                        style={{ cursor: 'pointer' }}
                        title="Click to highlight this string"
                      >
                        <div 
                          onClick={(e) => { e.stopPropagation(); jumpToHex(item.offset); }}
                          style={{ cursor: 'pointer', flex: 1, color: '#0ea5e9' }}
                          title="Click to view in hex"
                        >
                          {formatHex(item.offset)}
                          {isXrefTarget && (
                            <span title="Referenced by disassembly" style={{ marginLeft: '4px', color: '#ffc107', fontSize: '0.65rem' }}>xref</span>
                          )}
                        </div>
                        <div>{item.length}</div>
                        <div>
                          {kindMeta.label && (
                            <span className="string-kind-badge" style={{ background: kindMeta.color + '33', color: kindMeta.color, border: `1px solid ${kindMeta.color}66` }}>
                              {kindMeta.label}
                            </span>
                          )}
                        </div>
                        <div className="string-value" 
                          onClick={(e) => { e.stopPropagation(); jumpToHex(item.offset); }}
                          style={{ cursor: 'pointer', flex: 1 }}
                          title="Click to view in hex"
                        >
                          {item.text}
                        </div>
                        <div style={{ width: '55px', textAlign: 'center' }}>
                          <span style={{ color: entropyColor, fontSize: '0.75rem', fontVariantNumeric: 'tabular-nums' }}>{stringEntropy.toFixed(1)}</span>
                        </div>
                        <div style={{ display: 'flex', gap: '0.25rem', width: '100px' }} onClick={(e) => e.stopPropagation()}>
                          <button
                            type="button"
                            className="mini-button"
                            onClick={() => jumpToHex(item.offset)}
                            title="View in hex"
                          >
                            Hex
                          </button>
                          <button
                            type="button"
                            className="mini-button"
                            onClick={() => jumpToDisassembly(item.offset, 32)}
                            title="View disassembly at this offset"
                          >
                            Disasm
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {activeTab === 'plugins' && (
            <div className="panel">
              <h3>Plugin results</h3>
              {pluginResults.length === 0 ? (
                <p>No plugin results yet.</p>
              ) : (
                <div className="plugin-results">
                  {pluginResults.map((result, index) => {
                    const success = result.success;
                    const kind = result.kind ?? 'metric';
                    const label = kind.charAt(0).toUpperCase() + kind.slice(1);

                    return (
                      <div
                        key={`${result.plugin}-${index}`}
                        className={`plugin-result-card ${kind} ${success ? 'success' : 'error'}`}
                      >
                        <div className="plugin-result-card-header">
                          <div className="plugin-result-title">
                            <strong>{result.plugin}</strong> {success ? '✅' : '⚠️'}
                          </div>
                          <span className={`kind-badge ${kind}`}>{label}</span>
                        </div>
                        <div className="plugin-result-meta">
                          <span>{result.description}</span>
                          {result.version ? <span>Version: {result.version}</span> : null}
                          {result.schema_version ? <span>Schema: {result.schema_version}</span> : null}
                          {result.plugin_hash ? <span>Hash: {result.plugin_hash.slice(0, 8)}</span> : null}
                        </div>
                        <div className="plugin-result-summary">
                          <strong>{success ? 'Result:' : 'Error:'}</strong> {result.summary}
                        </div>
                        {result.details ? (
                          kind === 'strings' ? (
                            renderStringDetails(result.details)
                          ) : kind === 'analysis' ? (
                            renderAnalysisDetails(result, index)
                          ) : (
                            <pre className="plugin-result-output">
                              {JSON.stringify(result.details, null, 2)}
                            </pre>
                          )
                        ) : null}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {activeTab === 'disassembly' && (
            <div style={{ display: 'flex', gap: 0, height: 'calc(100vh - 200px)', background: '#0f0f1e' }}>
              {/* Left Panel: Function Browser */}
              {showFunctionBrowser && disassemblyAnalysis.functions.size > 0 && (
                <FunctionBrowser
                  functions={disassemblyAnalysis.functions}
                  selectedFunction={selectedFunction}
                  expandedFunctions={expandedFunctions}
                  onFunctionSelect={(addr) => {
                    setSelectedFunction(addr);
                    setSelectedDisasmAddress(addr);
                    selectAddress(addr);
                  }}
                  onToggle={(addr) => {
                    const newSet = new Set(expandedFunctions);
                    if (newSet.has(addr)) newSet.delete(addr);
                    else newSet.add(addr);
                    setExpandedFunctions(newSet);
                  }}
                  onNavigate={(addr) => {
                    handleSmartNavigation(addr, `Jump to function at ${formatHex(addr)}`);
                  }}
                  searchQuery={functionBrowserSearch}
                  onSearchChange={setFunctionBrowserSearch}
                />
              )}

              {/* Main Column: Disassembly + Smart Suggestions */}
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', borderRight: '2px solid #00bfff', borderLeft: showFunctionBrowser && disassemblyAnalysis.functions.size > 0 ? '2px solid #333' : 'none' }}>
                <div className="disasm-controls" style={{ padding: '0.75rem', borderBottom: '1px solid #333', background: '#1a1a2e' }}>
                  <div style={{ marginBottom: '0.5rem' }}>
                    <strong>Range:</strong> {formatHex(disasmOffset)} + {disasmLength} bytes | <strong>Instructions:</strong> {disassembly.length}
                    {disasmArch && <span style={{ marginLeft: '0.75rem', color: disasmArchFallback ? '#ffaa00' : '#00bfff', fontSize: '0.85em' }}>Arch: {disasmArch}</span>}
                  </div>
                  {disasmArchFallback && (
                    <div style={{ padding: '0.4rem 0.6rem', marginBottom: '0.5rem', background: '#332200', border: '1px solid #ffaa00', borderRadius: 4, color: '#ffaa00', fontSize: '0.85em' }}>
                      ⚠ Architecture not natively supported — disassembly shown as x86-64 and may be inaccurate.
                    </div>
                  )}
                  {selectedDisasmAddress !== null ? (
                    <button
                      type="button"
                      className="button-secondary"
                      onClick={() => disassembleFile(selectedDisasmAddress)}
                    >
                      Disassemble selected {formatHex(selectedDisasmAddress)}
                    </button>
                  ) : null}
                </div>

                {/* Phase 7: Threat Assessment */}
                {disassemblyAnalysis.suspiciousPatterns.length > 0 && (
                  <div style={{ padding: '0.75rem', borderBottom: '1px solid #333', background: '#0f0f1e' }}>
                    <ThreatAssessment analysis={disassemblyAnalysis} />
                  </div>
                )}

                {/* Phase 7: Workflow Guidance */}
                {disassemblyAnalysis.suspiciousPatterns.length > 0 && (
                  <div style={{ padding: '0.75rem', borderBottom: '1px solid #333', background: '#0f0f1e' }}>
                    <WorkflowGuidance analysis={disassemblyAnalysis} />
                  </div>
                )}

                {/* Smart Suggestions */}
                {showSmartSuggestions && selectedDisasmAddress !== null && (
                  <div style={{ padding: '0.75rem', borderBottom: '1px solid #333', background: '#0f0f1e' }}>
                    <SmartSuggestions
                      selectedAddress={selectedDisasmAddress}
                      analysis={disassemblyAnalysis}
                      disassembly={disassembly}
                      referencesMap={referencesMap}
                      jumpTargetsMap={jumpTargetsMap}
                      onNavigate={handleSmartNavigation}
                    />
                  </div>
                )}

                {/* Disassembly scroll area */}
                {disassembly.length === 0 ? (
                  <div style={{ padding: '2rem', textAlign: 'center', color: '#666' }}>
                    <p>No disassembly loaded yet.</p>
                  </div>
                ) : (
                  <div className="disassembly-scroll-enhanced">
                    {/* Sticky column header — lives outside the virtual list */}
                    <div className="disassembly-header disassembly-line" style={{ flexShrink: 0, background: '#1a1a2e', zIndex: 5, padding: '0.5rem' }}>
                      <span style={{ flex: '0 0 100px' }}>Address</span>
                      <span style={{ flex: '0 0 50px' }}>Refs</span>
                      <span style={{ flex: '0 0 60px' }}>Type</span>
                      <span style={{ flex: 1 }}>Code</span>
                      <span style={{ flex: '0 0 60px' }}>Pattern</span>
                      <span style={{ flex: '0 0 60px' }}>Loop</span>
                    </div>
                    {/* Virtualized instruction list — manages its own scroll */}
                    <DisassemblyList
                      disassembly={disassembly}
                      highlightedDisasmRange={highlightedDisasmRange}
                      disassemblyAnalysis={disassemblyAnalysis}
                      selectedDisasmAddress={selectedDisasmAddress}
                      annotations={annotations}
                      onSelectInstruction={(address) => {
                        setSelectedDisasmAddress(address);
                        selectAddress(address);
                      }}
                      onNavigateToFunction={(address) => {
                        setSelectedFunction(address);
                      }}
                      onShowReferences={(address) => {
                        setSelectedDisasmAddress(address);
                        setShowReferencesPanel(true);
                      }}
                    />
                  </div>
                )}

                {/* References panel (Ctrl+R to toggle) */}
                {showReferencesPanel && selectedDisasmAddress !== null && (
                  <div
                    style={{
                      padding: '0.75rem',
                      background: '#1a1a2e',
                      borderTop: '1px solid #333',
                      maxHeight: '200px',
                      overflowY: 'auto',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                      <div style={{ fontSize: '0.8rem', color: '#00bfff', fontWeight: 'bold' }}>
                        Cross-References for {formatHex(selectedDisasmAddress)}
                      </div>
                      <button
                        type="button"
                        onClick={() => setShowReferencesPanel(false)}
                        style={{ background: 'none', border: 'none', color: '#666', cursor: 'pointer', fontSize: '0.8rem' }}
                        title="Close (Ctrl+R)"
                      >✕</button>
                    </div>
                    <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', fontSize: '0.75rem' }}>
                      {(jumpTargetsMap.get(selectedDisasmAddress)?.size || 0) > 0 && (
                        <div>
                          <strong style={{ color: '#888' }}>Calls/Jumps to:</strong>
                          <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap', marginTop: '0.25rem' }}>
                            {Array.from(jumpTargetsMap.get(selectedDisasmAddress) || []).slice(0, 6).map((addr) => (
                              <button
                                key={`jump-to-${addr}`}
                                onClick={() => handleSmartNavigation(addr, `Jump to ${formatHex(addr)}`)}
                                style={{
                                  background: 'none',
                                  border: '1px solid #00bfff',
                                  color: '#00bfff',
                                  cursor: 'pointer',
                                  padding: '0.2rem 0.4rem',
                                  borderRadius: '0.2rem',
                                  fontSize: '0.7rem',
                                }}
                              >
                                → {formatHex(addr)}
                                {xrefTypes.get(`${selectedDisasmAddress}:${addr}`) ? ` (${xrefTypes.get(`${selectedDisasmAddress}:${addr}`)})` : ''}
                              </button>
                            ))}
                          </div>
                        </div>
                      )}
                      {(referencesMap.get(selectedDisasmAddress)?.size || 0) > 0 && (
                        <div>
                          <strong style={{ color: '#888' }}>Referenced by:</strong>
                          <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap', marginTop: '0.25rem' }}>
                            {Array.from(referencesMap.get(selectedDisasmAddress) || []).slice(0, 6).map((addr) => (
                              <button
                                key={`ref-by-${addr}`}
                                onClick={() => handleSmartNavigation(addr, `Jump to referrer at ${formatHex(addr)}`)}
                                style={{
                                  background: 'none',
                                  border: '1px solid #ffc107',
                                  color: '#ffc107',
                                  cursor: 'pointer',
                                  padding: '0.2rem 0.4rem',
                                  borderRadius: '0.2rem',
                                  fontSize: '0.7rem',
                                }}
                              >
                                ← {formatHex(addr)}
                                {xrefTypes.get(`${addr}:${selectedDisasmAddress}`) ? ` (${xrefTypes.get(`${addr}:${selectedDisasmAddress}`)})` : ''}
                              </button>
                            ))}
                          </div>
                        </div>
                      )}
                      {(jumpTargetsMap.get(selectedDisasmAddress)?.size || 0) === 0 && (referencesMap.get(selectedDisasmAddress)?.size || 0) === 0 && (
                        <span style={{ color: '#555' }}>No cross-references found for this address.</span>
                      )}
                    </div>
                    {/* Inline annotation */}
                    <div style={{ marginTop: '0.75rem', borderTop: '1px solid #2a2a4a', paddingTop: '0.5rem' }}>
                      <div style={{ fontSize: '0.7rem', color: '#888', marginBottom: '0.25rem' }}>Annotation:</div>
                      <input
                        type="text"
                        placeholder="Add a note for this address…"
                        value={annotations.get(selectedDisasmAddress) ?? ''}
                        onChange={(e) => {
                          const updated = new Map(annotations);
                          if (e.target.value) updated.set(selectedDisasmAddress, e.target.value);
                          else updated.delete(selectedDisasmAddress);
                          setAnnotations(updated);
                          localStorage.setItem('hexhawk.annotations', JSON.stringify([...updated.entries()]));
                        }}
                        style={{
                          width: '100%',
                          background: '#0f0f1e',
                          border: '1px solid #333',
                          color: '#ddd',
                          borderRadius: '0.25rem',
                          padding: '0.3rem 0.5rem',
                          fontSize: '0.75rem',
                        }}
                      />
                    </div>
                  </div>
                )}
                {!showReferencesPanel && selectedDisasmAddress !== null && (
                  <div style={{ padding: '0.3rem 0.75rem', background: '#0f0f1e', borderTop: '1px solid #222', fontSize: '0.7rem', color: '#555' }}>
                    Press <kbd>Ctrl+R</kbd> to show references
                  </div>
                )}
              </div>

              {/* Right Panel: Unified Analysis + Pattern Intelligence */}
              {showAnalysisPanel && (
                <div style={{ display: 'flex', flexDirection: 'column', width: '350px', borderLeft: '2px solid #00bfff', background: '#1a1a2e', overflow: 'hidden', gap: '8px', padding: '8px' }}>
                  {/* Pattern Intelligence Panel */}
                  {selectedDisasmAddress !== null && disassemblyAnalysis.suspiciousPatterns.length > 0 && (
                    <div style={{ flex: '0 1 auto', minHeight: '200px', overflow: 'hidden' }}>
                      <PatternIntelligencePanel
                        analysis={disassemblyAnalysis}
                        selectedAddress={selectedDisasmAddress}
                        disassembly={disassembly}
                        onNavigate={(addr) =>
                          handleSmartNavigation(addr, `Navigate to pattern at ${formatHex(addr)}`)
                        }
                      />
                    </div>
                  )}

                  {/* Pattern Category Browser */}
                  {disassemblyAnalysis.suspiciousPatterns.length > 0 && (
                    <div style={{ flex: '1', minHeight: '150px', overflow: 'hidden', marginBottom: '8px' }}>
                      <PatternCategoryBrowser
                        analysis={disassemblyAnalysis}
                        disassembly={disassembly}
                        onNavigate={(addr) =>
                          handleSmartNavigation(addr, `Navigate to category pattern at ${formatHex(addr)}`)
                        }
                      />
                    </div>
                  )}

                  {/* Unified Analysis Panel */}
                  <div style={{ flex: '1', minHeight: '200px', overflow: 'hidden' }}>
                    <UnifiedAnalysisPanel
                      analysis={disassemblyAnalysis}
                      selectedAddress={selectedDisasmAddress}
                      selectedFunction={selectedFunction}
                      disassembly={disassembly}
                      onNavigate={(addr) =>
                        handleSmartNavigation(addr, `Navigate to ${formatHex(addr)}`)
                      }
                    />
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'bookmarks' && (
            <div className="panel">
              <h3>Bookmarks & History</h3>
              
              <div className="bookmarks-toolbar">
                <button 
                  type="button" 
                  className="button-secondary"
                  onClick={goBack}
                  disabled={historyIndex <= 0}
                  title="Go back"
                >
                  ← Back
                </button>
                <button 
                  type="button" 
                  className="button-secondary"
                  onClick={goForward}
                  disabled={historyIndex >= history.length - 1}
                  title="Go forward"
                >
                  Forward →
                </button>
                <button 
                  type="button" 
                  className="button-secondary"
                  onClick={() => addBookmark()}
                  title="Bookmark current address"
                >
                  🔖 Add Bookmark
                </button>
              </div>

              <div className="bookmarks-section">
                <h4>Bookmarks ({bookmarks.length})</h4>
                {bookmarks.length === 0 ? (
                  <p className="placeholder">No bookmarks yet. Click "Add Bookmark" to save important locations.</p>
                ) : (
                  <div className="bookmarks-list">
                    {bookmarks.map((bookmark) => (
                      <div 
                        key={bookmark.id}
                        className="bookmark-row"
                        onClick={() => goToBookmark(bookmark)}
                      >
                        <div className="bookmark-info">
                          <div className="bookmark-addr">{formatHex(bookmark.address)}</div>
                          <div className="bookmark-note">{bookmark.note || '(no note)'}</div>
                          <div className="bookmark-time">
                            {new Date(bookmark.timestamp).toLocaleTimeString()}
                          </div>
                        </div>
                        <button
                          type="button"
                          className="icon-button"
                          onClick={(e) => {
                            e.stopPropagation();
                            deleteBookmark(bookmark.id);
                          }}
                          title="Delete bookmark"
                        >
                          ✕
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="bookmarks-section">
                <h4>Navigation History ({history.length})</h4>
                {history.length === 0 ? (
                  <p className="placeholder">No navigation history yet.</p>
                ) : (
                  <div className="history-list">
                    {history.map((entry, idx) => (
                      <div
                        key={entry.id}
                        className={`history-row ${idx === historyIndex ? 'current' : ''}`}
                        onClick={() => {
                          selectAddress(entry.address, entry.range);
                          setHistoryIndex(idx);
                          setAndPersistTab(entry.tab);
                        }}
                      >
                        <div className="history-idx">{idx + 1}</div>
                        <div className="history-info">
                          <div className="history-addr">{formatHex(entry.address)}</div>
                          <div className="history-desc">{entry.description}</div>
                          <div className="history-tab">{entry.tab}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'logs' && <ActivityLog entries={logs} />}

          {activeTab === 'graph' && (
            <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
              <AnalysisGraph
                imports={metadata?.imports ?? []}
                strings={strings.map(s => ({ offset: s.offset, text: s.text }))}
                disassembly={disassembly.map(i => ({ address: i.address, mnemonic: i.mnemonic, operands: i.operands }))}
                patterns={disassemblyAnalysis.suspiciousPatterns}
                verdict={verdict}
                onNavigate={(tab) => setAndPersistTab(tab as AppTab)}
                onSelectStringOffset={(offset) => {
                  setAndPersistTab('strings');
                }}
                onSelectAddress={(address) => {
                  selectAddress(address);
                  setAndPersistTab('disassembly');
                }}
              />
            </div>
          )}

          {activeTab === 'report' && (
            <div className="panel">
              <IntelligenceReport
                verdict={verdict}
                binaryPath={binaryPath}
                binarySize={metadata?.file_size}
                architecture={metadata?.architecture}
                fileType={metadata?.file_type}
              />
            </div>
          )}

          {activeTab === 'decompile' && (
            <div className="panel" style={{ padding: 0, height: 'calc(100vh - 160px)', overflow: 'hidden' }}>
              <DecompilerView
                disassembly={disassembly}
                cfg={cfg}
                functions={disassemblyAnalysis.functions}
                currentAddress={currentAddress}
                onAddressSelect={(addr) => {
                  selectAddress(addr);
                  setAndPersistTab('disassembly');
                }}
                metadata={metadata ? { architecture: metadata.architecture } : null}
              />
            </div>
          )}

          {activeTab === 'debugger' && (
            <div className="panel" style={{ padding: 0, height: 'calc(100vh - 160px)', overflow: 'hidden' }}>
              <DebuggerPanel
                binaryPath={binaryPath || null}
                onAddressSelect={(addr) => {
                  selectAddress(addr);
                  setAndPersistTab('disassembly');
                }}
                onNavigateHex={(addr) => {
                  setHexOffset(addr);
                  setAndPersistTab('hex');
                }}
              />
            </div>
          )}

          {activeTab === 'signatures' && (
            <div className="panel" style={{ padding: 0, height: 'calc(100vh - 160px)', overflow: 'hidden' }}>
              <SignaturePanel
                disassembly={disassembly}
                functions={disassemblyAnalysis.functions}
                onAddressSelect={(addr) => {
                  selectAddress(addr);
                  setAndPersistTab('disassembly');
                }}
              />
            </div>
          )}

          {activeTab === 'talon' && (
            <div className="panel" style={{ padding: 0, height: 'calc(100vh - 160px)', overflow: 'hidden' }}>
              <TalonView
                disassembly={disassembly}
                cfg={cfg}
                functions={disassemblyAnalysis.functions}
                currentAddress={currentAddress}
                onAddressSelect={(addr) => {
                  selectAddress(addr);
                  setAndPersistTab('disassembly');
                }}
                metadata={metadata ? { architecture: metadata.architecture } : null}
              />
            </div>
          )}

          {activeTab === 'strike' && (
            <div className="panel" style={{ padding: 0, height: 'calc(100vh - 160px)', overflow: 'hidden' }}>
              <StrikeView
                binaryPath={binaryPath}
                currentAddress={currentAddress}
                onAddressSelect={(addr) => {
                  selectAddress(addr);
                  setAndPersistTab('disassembly');
                }}
                onNavigateHex={(addr) => {
                  selectAddress(addr);
                  setAndPersistTab('hex');
                }}
              />
            </div>
          )}

          {activeTab === 'echo' && (
            <div className="panel" style={{ padding: 0, height: 'calc(100vh - 160px)', overflow: 'hidden' }}>
              <EchoView
                disassembly={disassembly}
                functions={disassemblyAnalysis.functions}
                imports={metadata?.imports ?? []}
                strings={strings}
                onAddressSelect={(addr) => {
                  selectAddress(addr);
                  setAndPersistTab('disassembly');
                }}
              />
            </div>
          )}
          {activeTab === 'console' && (
            <div className="panel" style={{ padding: 0, height: 'calc(100vh - 160px)', overflow: 'hidden' }}>
              <OperatorConsole
                onNavigateTab={(tab) => setAndPersistTab(tab as AppTab)}
                context={{
                  binaryPath,
                  fileType: metadata?.file_type,
                  architecture: metadata?.architecture,
                  importNames: metadata?.imports?.map((imp) => imp.name) ?? [],
                  stringTexts: strings.map((s) => s.text),
                  verdictClassification: verdict?.classification,
                  verdictBehaviors: verdict?.behaviors as string[] | undefined,
                  signalIds: verdict?.signals?.map((sig) => sig.id) ?? [],
                }}
              />
            </div>
          )}

          {activeTab === 'nest' && (
            <div className="panel" style={{ padding: 0, height: 'calc(100vh - 160px)', overflow: 'hidden' }}>
              <NestView
                binaryPath={binaryPath}
                metadata={metadata}
                disassembly={disassembly}
                strings={strings}
                disassemblyAnalysis={disassemblyAnalysis}
                disasmOffset={disasmOffset}
                disasmLength={disasmLength}
                onAddressSelect={(addr) => {
                  selectAddress(addr);
                  setAndPersistTab('disassembly');
                }}
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
          )}
        </main>
      </div>
    </div>
  );
}