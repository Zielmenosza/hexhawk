/**
 * BinaryDiffPanel — Binary Diff / Version Comparison UI
 *
 * Compares a "base" binary (already loaded in App) against a "target" binary
 * that the user provides. Loads the target via existing Tauri invoke() calls,
 * runs the binaryDiffEngine, and surfaces semantic differences across:
 *
 *   Overview   — summary bar, hotspots, risk level
 *   Functions  — added/removed/modified function list, click to jump
 *   Strings    — new/removed strings by kind
 *   Imports    — new/removed API calls
 *   Signals    — GYRE signal changes (new threats, resolved threats)
 *   CFG        — basic block structural changes
 *
 * Color convention:
 *   Green  (#4caf50) = added   (new in target)
 *   Red    (#f44336) = removed (gone from target)
 *   Amber  (#ffc107) = modified
 *   Gray   (#888)    = unchanged
 */

import React, { useState, useCallback, useMemo } from 'react';
import { invoke } from '@tauri-apps/api/core';
import type { FileMetadata, StringMatch, DisassembledInstruction } from '../App';
import type { BinaryVerdictResult } from '../utils/correlationEngine';
import {
  diffSnapshots,
  extractFunctions,
  buildCfgBlockSnapshots,
  type BinarySnapshot,
  type BinaryDiffResult,
  type FunctionDiff,
  type StringDiff,
  type ImportDiff,
  type SignalDiff,
  type CfgBlockDiff,
  type DiffStatus,
} from '../utils/binaryDiffEngine';
import { computeVerdict } from '../utils/correlationEngine';
import { sanitizeBridgePath } from '../utils/tauriGuards';

const MAX_DIFF_STRING_SCAN_BYTES = 16 * 1024 * 1024;
const MAX_DIFF_CFG_BYTES = 8 * 1024 * 1024;

// ─── Color palette ─────────────────────────────────────────────────────────────

const DIFF_COLORS: Record<DiffStatus | 'added' | 'removed' | 'unchanged', string> = {
  added:     '#4caf50',
  removed:   '#f44336',
  modified:  '#ffc107',
  unchanged: '#555',
};

const DIFF_BG: Record<DiffStatus | 'added' | 'removed' | 'unchanged', string> = {
  added:     'rgba(76,175,80,0.08)',
  removed:   'rgba(244,67,54,0.08)',
  modified:  'rgba(255,193,7,0.08)',
  unchanged: 'transparent',
};

const RISK_COLORS: Record<string, string> = {
  escalated: '#f44336',
  reduced:   '#4caf50',
  neutral:   '#79c0ff',
};

type SubTab = 'overview' | 'functions' | 'strings' | 'imports' | 'signals' | 'cfg';

// ─── Props ─────────────────────────────────────────────────────────────────────

interface BinaryDiffPanelProps {
  /** Primary (base) binary path from App */
  basePath:        string;
  baseMetadata:    FileMetadata | null;
  baseStrings:     StringMatch[];
  baseDisassembly: DisassembledInstruction[];
  baseCfg:         { nodes: Array<{ id: string; start?: number; end?: number; instruction_count?: number; block_type?: string }>; edges: Array<{ source: string; target: string }> } | null;
  baseVerdict:     BinaryVerdictResult;
  /** Navigate primary binary's disassembly to an address */
  onJumpToAddress?: (address: number) => void;
}

// ─── Snapshot builder ──────────────────────────────────────────────────────────

function buildSnapshot(
  path:        string,
  label:       string,
  metadata:    FileMetadata,
  strings:     StringMatch[],
  disassembly: DisassembledInstruction[],
  cfg:         { nodes: Array<any>; edges: Array<any> } | null,
  verdict:     BinaryVerdictResult,
): BinarySnapshot {
  const functions = extractFunctions(disassembly, metadata.exports ?? []);
  const cfgBlocks = cfg ? buildCfgBlockSnapshots(cfg.nodes, cfg.edges) : [];

  return {
    path,
    label,
    fileSize:     metadata.file_size,
    fileType:     metadata.file_type,
    architecture: metadata.architecture,
    sha256:       metadata.sha256,
    sections:     (metadata.sections ?? []).map(s => ({
      name:            s.name,
      file_size:       s.file_size,
      virtual_address: s.virtual_address,
      entropy:         s.entropy ?? 0,
    })),
    imports:  metadata.imports ?? [],
    exports:  metadata.exports ?? [],
    strings:  strings.map(s => ({ text: s.text, offset: s.offset, kind: classifyKind(s.text) })),
    functions,
    cfgBlocks,
    verdict,
  };
}

function classifyKind(text: string): string {
  if (/^https?:\/\//i.test(text)) return 'url';
  if (/^\d{1,3}(\.\d{1,3}){3}/.test(text)) return 'ip';
  if (/^HKEY_/i.test(text)) return 'registry';
  if (/^[A-Za-z]:[\\\/]/.test(text)) return 'filepath';
  if (/\.(exe|dll|sys|bat)$/i.test(text)) return 'pe-artifact';
  if (/^[0-9a-f]{8}-[0-9a-f]{4}/i.test(text)) return 'uuid';
  return 'plain';
}

// ─── Component ─────────────────────────────────────────────────────────────────

export default function BinaryDiffPanel({
  basePath,
  baseMetadata,
  baseStrings,
  baseDisassembly,
  baseCfg,
  baseVerdict,
  onJumpToAddress,
}: BinaryDiffPanelProps) {

  const [targetPath,    setTargetPath]    = useState('');
  const [targetLabel,   setTargetLabel]   = useState('Target');
  const [isLoading,     setIsLoading]     = useState(false);
  const [loadError,     setLoadError]     = useState<string | null>(null);
  const [diffResult,    setDiffResult]    = useState<BinaryDiffResult | null>(null);
  const [activeSubTab,  setActiveSubTab]  = useState<SubTab>('overview');
  const [expandedFns,   setExpandedFns]   = useState<Set<number>>(new Set());

  // ── Filters
  const [fnStatusFilter,  setFnStatusFilter]  = useState<DiffStatus | 'all'>('all');
  const [strStatusFilter, setStrStatusFilter] = useState<'added' | 'removed' | 'all'>('all');
  const [impStatusFilter, setImpStatusFilter] = useState<'added' | 'removed' | 'all'>('all');
  const [searchTerm,      setSearchTerm]      = useState('');

  // ── Load the target binary and run diff
  const runDiff = useCallback(async () => {
    if (!baseMetadata || !targetPath.trim()) return;
    setIsLoading(true);
    setLoadError(null);
    setDiffResult(null);

    try {
      const safeTargetPath = sanitizeBridgePath(targetPath, 'target path');
      // Step 1: metadata
      const targetMeta = await invoke<FileMetadata>('inspect_file_metadata', { path: safeTargetPath });

      // Step 2: strings (full file, min length 4)
      const targetStrings = await invoke<StringMatch[]>('find_strings', {
        path:       safeTargetPath,
        offset:     0,
        length:     Math.min(targetMeta.file_size, MAX_DIFF_STRING_SCAN_BYTES),
        minLength: 4,
      });

      // Step 3: disassembly (up to 4096 instructions from start)
      let targetInstructions: DisassembledInstruction[] = [];
      try {
        const disasmResp = await invoke<{
          instructions: DisassembledInstruction[];
          has_more: boolean;
        }>('disassemble_file_range', {
          path:             safeTargetPath,
          offset:           0,
          length:           Math.min(targetMeta.file_size, MAX_DIFF_STRING_SCAN_BYTES),
          max_instructions: 4096,
        });
        targetInstructions = disasmResp.instructions;
      } catch {
        // Disassembly may not be available for all formats — continue without it
      }

      // Step 4: CFG (best-effort)
      let targetCfg: { nodes: any[]; edges: any[] } | null = null;
      try {
        targetCfg = await invoke<{ nodes: any[]; edges: any[] }>('build_cfg', {
          path:   safeTargetPath,
          offset: 0,
          length: Math.min(targetMeta.file_size, MAX_DIFF_CFG_BYTES),
        });
      } catch {
        // CFG optional
      }

      // Step 5: compute verdict for target
      const targetVerdict = computeVerdict({
        sections: (targetMeta.sections ?? []).map(s => ({
          name:      s.name,
          entropy:   s.entropy ?? 0,
          file_size: s.file_size ?? 0,
        })),
        imports: targetMeta.imports ?? [],
        strings: targetStrings.map(s => ({ text: s.text })),
        patterns: [],
      });

      // Step 6: build snapshots & diff
      const baseLabel = basePath.split(/[/\\]/).pop() ?? 'Base';
      const targetLabelFinal = targetLabel.trim() || (targetPath.split(/[/\\]/).pop() ?? 'Target');

      const baseSnap = buildSnapshot(basePath,   baseLabel,       baseMetadata, baseStrings, baseDisassembly, baseCfg,   baseVerdict);
      const targSnap = buildSnapshot(safeTargetPath, targetLabelFinal, targetMeta, targetStrings, targetInstructions, targetCfg, targetVerdict);

      const result = diffSnapshots(baseSnap, targSnap);
      setDiffResult(result);
      setActiveSubTab('overview');
    } catch (err) {
      setLoadError(String(err));
    } finally {
      setIsLoading(false);
    }
  }, [basePath, baseMetadata, baseStrings, baseDisassembly, baseCfg, baseVerdict, targetPath, targetLabel]);

  // ── Toggle function row expansion
  const toggleFn = useCallback((address: number) => {
    setExpandedFns(prev => {
      const next = new Set(prev);
      if (next.has(address)) next.delete(address); else next.add(address);
      return next;
    });
  }, []);

  // ── Filtered data
  const filteredFunctions = useMemo(() => {
    if (!diffResult) return [];
    return diffResult.functionDiffs.filter(f => {
      if (fnStatusFilter !== 'all' && f.status !== fnStatusFilter) return false;
      if (searchTerm && !`${f.name ?? ''} 0x${f.address.toString(16)}`.toLowerCase().includes(searchTerm.toLowerCase())) return false;
      return true;
    });
  }, [diffResult, fnStatusFilter, searchTerm]);

  const filteredStrings = useMemo(() => {
    if (!diffResult) return [];
    return diffResult.stringDiffs.filter(s => {
      if (strStatusFilter !== 'all' && s.status !== strStatusFilter) return false;
      if (searchTerm && !s.text.toLowerCase().includes(searchTerm.toLowerCase())) return false;
      return true;
    });
  }, [diffResult, strStatusFilter, searchTerm]);

  const filteredImports = useMemo(() => {
    if (!diffResult) return [];
    return diffResult.importDiffs.filter(i => {
      if (impStatusFilter !== 'all' && i.status !== impStatusFilter) return false;
      if (searchTerm && !`${i.name} ${i.library}`.toLowerCase().includes(searchTerm.toLowerCase())) return false;
      return true;
    });
  }, [diffResult, impStatusFilter, searchTerm]);

  // ─────────────────────────────────────────────────────────────────────────────
  //  Render
  // ─────────────────────────────────────────────────────────────────────────────

  if (!baseMetadata) {
    return (
      <div className="panel">
        <h3>Binary Diff</h3>
        <p style={{ color: '#888' }}>Load and inspect a binary first (Base), then compare against a Target.</p>
      </div>
    );
  }

  return (
    <div className="panel" style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', minHeight: 0, flex: 1 }}>
      <h3 style={{ margin: 0 }}>Binary Diff</h3>

      {/* ── Load target UI ── */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', padding: '0.75rem', background: 'rgba(255,255,255,0.04)', borderRadius: '0.5rem', border: '1px solid rgba(255,255,255,0.08)' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: '0.5rem', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '0.72rem', color: '#888', marginBottom: '0.25rem' }}>BASE (loaded)</div>
            <div style={{ fontSize: '0.85rem', color: '#c9d1d9', fontFamily: 'monospace' }}>{basePath.split(/[/\\]/).pop()}</div>
            <div style={{ fontSize: '0.7rem', color: '#555' }}>{baseMetadata.sha256.slice(0, 12)}…  {baseMetadata.file_type} · {baseMetadata.architecture}</div>
          </div>
          <div style={{ fontSize: '1.5rem', color: '#555' }}>⇄</div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '6rem 1fr 6rem', gap: '0.4rem' }}>
          <input
            type="text"
            placeholder="Label..."
            value={targetLabel}
            onChange={e => setTargetLabel(e.target.value)}
            style={{ fontSize: '0.8rem', padding: '0.3rem 0.5rem', background: '#161b22', border: '1px solid #30363d', borderRadius: '0.35rem', color: '#c9d1d9' }}
          />
          <input
            type="text"
            placeholder="Target binary path..."
            value={targetPath}
            onChange={e => setTargetPath(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') void runDiff(); }}
            style={{ fontSize: '0.8rem', padding: '0.3rem 0.5rem', background: '#161b22', border: '1px solid #30363d', borderRadius: '0.35rem', color: '#c9d1d9', fontFamily: 'monospace' }}
          />
          <button
            onClick={() => void runDiff()}
            disabled={isLoading || !targetPath.trim()}
            style={{ fontSize: '0.8rem', padding: '0.3rem 0.75rem', background: isLoading ? '#30363d' : '#238636', border: 'none', borderRadius: '0.35rem', color: '#fff', cursor: isLoading ? 'default' : 'pointer' }}
          >
            {isLoading ? 'Analyzing…' : 'Compare'}
          </button>
        </div>

        {loadError && (
          <div style={{ color: '#f44336', fontSize: '0.8rem' }}>Error: {loadError}</div>
        )}
      </div>

      {/* ── Diff results ── */}
      {diffResult && (
        <>
          {/* Summary bar */}
          <SummaryBar result={diffResult} />

          {/* Sub-tab bar */}
          <div style={{ display: 'flex', gap: '0.25rem', borderBottom: '1px solid #21262d', paddingBottom: '0.25rem' }}>
            {(['overview', 'functions', 'strings', 'imports', 'signals', 'cfg'] as SubTab[]).map(tab => (
              <button
                key={tab}
                onClick={() => { setActiveSubTab(tab); setSearchTerm(''); }}
                style={{
                  padding:      '0.25rem 0.6rem',
                  fontSize:     '0.78rem',
                  background:   activeSubTab === tab ? '#161b22' : 'transparent',
                  border:       activeSubTab === tab ? '1px solid #30363d' : '1px solid transparent',
                  borderRadius: '0.3rem',
                  color:        activeSubTab === tab ? '#e6edf3' : '#888',
                  cursor:       'pointer',
                  textTransform: 'capitalize',
                }}
              >
                {tab}
                {tab === 'functions' && ` (${diffResult.summary.addedFunctions + diffResult.summary.removedFunctions + diffResult.summary.modifiedFunctions})`}
                {tab === 'strings'   && ` (${diffResult.summary.addedStrings + diffResult.summary.removedStrings})`}
                {tab === 'imports'   && ` (${diffResult.summary.addedImports + diffResult.summary.removedImports})`}
                {tab === 'signals'   && ` (${diffResult.summary.addedSignals + diffResult.summary.removedSignals + diffResult.summary.modifiedSignals})`}
                {tab === 'cfg'       && ` (${diffResult.summary.addedCfgBlocks + diffResult.summary.removedCfgBlocks + diffResult.summary.modifiedCfgBlocks})`}
              </button>
            ))}
          </div>

          {/* Search bar (shared) */}
          {activeSubTab !== 'overview' && (
            <input
              type="text"
              placeholder={`Filter ${activeSubTab}…`}
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              style={{ fontSize: '0.8rem', padding: '0.3rem 0.5rem', background: '#161b22', border: '1px solid #30363d', borderRadius: '0.35rem', color: '#c9d1d9', width: '100%', boxSizing: 'border-box' }}
            />
          )}

          {/* Tab content */}
          <div style={{ flex: 1, overflowY: 'auto', minHeight: 0 }}>
            {activeSubTab === 'overview' && (
              <OverviewTab result={diffResult} onJumpToAddress={onJumpToAddress} />
            )}
            {activeSubTab === 'functions' && (
              <FunctionsTab
                diffs={filteredFunctions}
                allDiffs={diffResult.functionDiffs}
                statusFilter={fnStatusFilter}
                onStatusFilter={setFnStatusFilter}
                expandedFns={expandedFns}
                onToggleFn={toggleFn}
                onJumpToAddress={onJumpToAddress}
              />
            )}
            {activeSubTab === 'strings' && (
              <StringsTab
                diffs={filteredStrings}
                statusFilter={strStatusFilter}
                onStatusFilter={setStrStatusFilter}
              />
            )}
            {activeSubTab === 'imports' && (
              <ImportsTab
                diffs={filteredImports}
                statusFilter={impStatusFilter}
                onStatusFilter={setImpStatusFilter}
              />
            )}
            {activeSubTab === 'signals' && (
              <SignalsTab diffs={diffResult.signalDiffs} />
            )}
            {activeSubTab === 'cfg' && (
              <CfgTab diffs={diffResult.cfgBlockDiffs} onJumpToAddress={onJumpToAddress} />
            )}
          </div>
        </>
      )}
    </div>
  );
}

// ─── Summary bar ───────────────────────────────────────────────────────────────

function SummaryBar({ result }: { result: BinaryDiffResult }) {
  const { summary, risk } = result;
  const scoreChange = summary.threatScoreChange;
  const scoreSign   = scoreChange > 0 ? '+' : '';
  const riskColor   = RISK_COLORS[risk] ?? '#888';

  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', padding: '0.6rem 0.75rem', background: 'rgba(255,255,255,0.04)', borderRadius: '0.5rem', border: `1px solid ${riskColor}33`, alignItems: 'center' }}>
      <span style={{ padding: '0.2rem 0.5rem', borderRadius: '0.3rem', background: riskColor + '22', color: riskColor, fontWeight: 700, fontSize: '0.78rem', textTransform: 'uppercase' }}>
        {risk}
      </span>
      <Chip color={DIFF_COLORS.added}   label={`+${summary.addedFunctions} fn`} />
      <Chip color={DIFF_COLORS.removed} label={`-${summary.removedFunctions} fn`} />
      <Chip color={DIFF_COLORS.modified} label={`~${summary.modifiedFunctions} fn`} />
      <span style={{ color: '#555', fontSize: '0.75rem' }}>|</span>
      <Chip color={DIFF_COLORS.added}   label={`+${summary.addedStrings} str`} />
      <Chip color={DIFF_COLORS.removed} label={`-${summary.removedStrings} str`} />
      <span style={{ color: '#555', fontSize: '0.75rem' }}>|</span>
      <Chip color={DIFF_COLORS.added}   label={`+${summary.addedImports} imp`} />
      <Chip color={DIFF_COLORS.removed} label={`-${summary.removedImports} imp`} />
      <span style={{ color: '#555', fontSize: '0.75rem' }}>|</span>
      <Chip
        color={scoreChange > 0 ? '#f44336' : scoreChange < 0 ? '#4caf50' : '#888'}
        label={`Threat ${scoreSign}${scoreChange}`}
      />
      {result.base.sha256 !== result.target.sha256 ? null : (
        <span style={{ fontSize: '0.72rem', color: '#888' }}>⚠ Identical files</span>
      )}
    </div>
  );
}

function Chip({ color, label }: { color: string; label: string }) {
  return (
    <span style={{ fontSize: '0.75rem', color, background: color + '18', padding: '0.15rem 0.45rem', borderRadius: '0.3rem', fontFamily: 'monospace' }}>
      {label}
    </span>
  );
}

// ─── Overview tab ──────────────────────────────────────────────────────────────

function OverviewTab({ result, onJumpToAddress }: { result: BinaryDiffResult; onJumpToAddress?: (addr: number) => void }) {
  const { summary } = result;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      {/* Metadata comparison */}
      <table style={{ width: '100%', fontSize: '0.8rem', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ color: '#888', borderBottom: '1px solid #21262d' }}>
            <th style={{ textAlign: 'left', padding: '0.25rem 0.5rem' }}>Property</th>
            <th style={{ textAlign: 'left', padding: '0.25rem 0.5rem', color: DIFF_COLORS.removed }}>Base: {result.base.label}</th>
            <th style={{ textAlign: 'left', padding: '0.25rem 0.5rem', color: DIFF_COLORS.added }}>Target: {result.target.label}</th>
          </tr>
        </thead>
        <tbody>
          {[
            ['SHA256', result.base.sha256.slice(0, 16) + '…', result.target.sha256.slice(0, 16) + '…'],
            ['File size', fmtBytes(result.base.fileSize), fmtBytes(result.target.fileSize)],
            ['Threat score', String(result.base.threatScore), String(result.target.threatScore)],
          ].map(([label, baseVal, targetVal]) => (
            <tr key={label} style={{ borderBottom: '1px solid #21262d11' }}>
              <td style={{ padding: '0.25rem 0.5rem', color: '#888' }}>{label}</td>
              <td style={{ padding: '0.25rem 0.5rem', fontFamily: 'monospace', color: baseVal !== targetVal ? DIFF_COLORS.removed : '#c9d1d9' }}>{baseVal}</td>
              <td style={{ padding: '0.25rem 0.5rem', fontFamily: 'monospace', color: baseVal !== targetVal ? DIFF_COLORS.added   : '#c9d1d9' }}>{targetVal}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* Hotspots */}
      {result.hotspots.length > 0 && (
        <div>
          <div style={{ fontSize: '0.78rem', color: '#888', marginBottom: '0.35rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Top Changed Functions</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
            {result.hotspots.map(h => {
              const sevColor = h.severity === 'critical' ? '#f44336' : h.severity === 'high' ? '#ffc107' : h.severity === 'medium' ? '#79c0ff' : '#888';
              return (
                <div
                  key={h.address}
                  style={{ display: 'flex', gap: '0.5rem', alignItems: 'baseline', padding: '0.35rem 0.5rem', background: 'rgba(255,255,255,0.03)', borderRadius: '0.35rem', cursor: onJumpToAddress ? 'pointer' : 'default' }}
                  onClick={() => onJumpToAddress?.(h.address)}
                  title={onJumpToAddress ? 'Jump to disassembly' : undefined}
                >
                  <span style={{ width: '0.5rem', height: '0.5rem', borderRadius: '50%', background: sevColor, flexShrink: 0, marginTop: '0.25rem', display: 'inline-block' }} />
                  <span style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: '#79c0ff' }}>{h.name ?? `sub_${h.address.toString(16)}`}</span>
                  <span style={{ fontFamily: 'monospace', fontSize: '0.72rem', color: '#555' }}>0x{h.address.toString(16)}</span>
                  <span style={{ fontSize: '0.75rem', color: '#888' }}>{h.reason}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* New / resolved capabilities */}
      {(summary.newCapabilities.length > 0 || summary.resolvedCapabilities.length > 0) && (
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
          {summary.newCapabilities.length > 0 && (
            <div>
              <div style={{ fontSize: '0.72rem', color: DIFF_COLORS.added, marginBottom: '0.25rem' }}>NEW SIGNALS</div>
              {summary.newCapabilities.map(id => (
                <div key={id} style={{ fontSize: '0.78rem', color: DIFF_COLORS.added, fontFamily: 'monospace' }}>+ {id}</div>
              ))}
            </div>
          )}
          {summary.resolvedCapabilities.length > 0 && (
            <div>
              <div style={{ fontSize: '0.72rem', color: DIFF_COLORS.removed, marginBottom: '0.25rem' }}>RESOLVED SIGNALS</div>
              {summary.resolvedCapabilities.map(id => (
                <div key={id} style={{ fontSize: '0.78rem', color: DIFF_COLORS.removed, fontFamily: 'monospace' }}>- {id}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Functions tab ─────────────────────────────────────────────────────────────

function FunctionsTab({
  diffs,
  allDiffs,
  statusFilter,
  onStatusFilter,
  expandedFns,
  onToggleFn,
  onJumpToAddress,
}: {
  diffs:           FunctionDiff[];
  allDiffs:        FunctionDiff[];
  statusFilter:    DiffStatus | 'all';
  onStatusFilter:  (s: DiffStatus | 'all') => void;
  expandedFns:     Set<number>;
  onToggleFn:      (addr: number) => void;
  onJumpToAddress?: (addr: number) => void;
}) {
  const counts = {
    added:     allDiffs.filter(f => f.status === 'added').length,
    removed:   allDiffs.filter(f => f.status === 'removed').length,
    modified:  allDiffs.filter(f => f.status === 'modified').length,
    unchanged: allDiffs.filter(f => f.status === 'unchanged').length,
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
      {/* Filter pills */}
      <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
        {(['all', 'added', 'removed', 'modified', 'unchanged'] as const).map(s => (
          <button
            key={s}
            onClick={() => onStatusFilter(s)}
            style={{
              fontSize: '0.72rem',
              padding:  '0.15rem 0.45rem',
              borderRadius: '0.3rem',
              border: statusFilter === s ? '1px solid rgba(121,192,255,0.4)' : '1px solid transparent',
              background: statusFilter === s ? 'rgba(121,192,255,0.12)' : 'rgba(255,255,255,0.04)',
              color:  s === 'all' ? '#c9d1d9' : DIFF_COLORS[s],
              cursor: 'pointer',
            }}
          >
            {s} {s !== 'all' ? `(${counts[s]})` : `(${allDiffs.length})`}
          </button>
        ))}
      </div>

      {diffs.length === 0 && <div style={{ color: '#555', fontSize: '0.8rem' }}>No functions match filter.</div>}

      {diffs.map(f => {
        const isExpanded = expandedFns.has(f.address);
        const color = DIFF_COLORS[f.status];
        const bg    = DIFF_BG[f.status];
        const label = f.name ?? `sub_${f.address.toString(16)}`;
        const hasDetail = f.addedPatterns.length > 0 || f.removedPatterns.length > 0 || f.loopAdded || f.loopRemoved;

        return (
          <div key={f.address} style={{ background: bg, borderLeft: `3px solid ${color}`, borderRadius: '0.35rem', overflow: 'hidden' }}>
            <div
              style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', padding: '0.35rem 0.6rem', cursor: hasDetail ? 'pointer' : 'default' }}
              onClick={() => hasDetail && onToggleFn(f.address)}
            >
              <span style={{ fontSize: '0.72rem', color, textTransform: 'uppercase', minWidth: '4.5rem' }}>{f.status}</span>
              <span
                style={{ fontFamily: 'monospace', fontSize: '0.82rem', color: '#79c0ff', cursor: onJumpToAddress ? 'pointer' : 'default' }}
                onClick={e => { e.stopPropagation(); onJumpToAddress?.(f.address); }}
                title={onJumpToAddress ? 'Jump to disassembly' : undefined}
              >
                {label}
              </span>
              <span style={{ fontFamily: 'monospace', fontSize: '0.72rem', color: '#555' }}>0x{f.address.toString(16)}</span>
              {f.sizeChange !== 0 && (
                <span style={{ fontSize: '0.72rem', color: f.sizeChange > 0 ? DIFF_COLORS.added : DIFF_COLORS.removed }}>
                  {f.sizeChange > 0 ? '+' : ''}{f.sizeChange}B
                </span>
              )}
              {f.complexityChange !== 0 && (
                <span style={{ fontSize: '0.72rem', color: f.complexityChange > 0 ? '#ffc107' : '#4caf50' }}>
                  cx{f.complexityChange > 0 ? '+' : ''}{f.complexityChange}
                </span>
              )}
              {f.addedPatterns.length > 0 && (
                <span style={{ fontSize: '0.7rem', color: '#f44336' }}>⚠ {f.addedPatterns.join(', ')}</span>
              )}
              {hasDetail && <span style={{ marginLeft: 'auto', color: '#555', fontSize: '0.72rem' }}>{isExpanded ? '▲' : '▼'}</span>}
            </div>
            {isExpanded && hasDetail && (
              <div style={{ padding: '0.35rem 0.6rem 0.5rem 1.5rem', borderTop: '1px solid rgba(255,255,255,0.04)', fontSize: '0.78rem' }}>
                {f.addedPatterns.length > 0   && <div style={{ color: '#f44336' }}>New patterns: {f.addedPatterns.join(', ')}</div>}
                {f.removedPatterns.length > 0 && <div style={{ color: '#4caf50' }}>Removed patterns: {f.removedPatterns.join(', ')}</div>}
                {f.loopAdded   && <div style={{ color: '#ffc107' }}>Loop introduced</div>}
                {f.loopRemoved && <div style={{ color: '#4caf50' }}>Loop removed</div>}
                {f.instructionDelta !== 0 && <div style={{ color: '#888' }}>Instruction delta: {f.instructionDelta > 0 ? '+' : ''}{f.instructionDelta}</div>}
                {f.similarity < 1 && f.status !== 'added' && f.status !== 'removed' && (
                  <div style={{ color: '#888' }}>Similarity: {(f.similarity * 100).toFixed(0)}%</div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─── Strings tab ───────────────────────────────────────────────────────────────

function StringsTab({
  diffs,
  statusFilter,
  onStatusFilter,
}: {
  diffs:          StringDiff[];
  statusFilter:   'added' | 'removed' | 'all';
  onStatusFilter: (s: 'added' | 'removed' | 'all') => void;
}) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
      <div style={{ display: 'flex', gap: '0.35rem' }}>
        {(['all', 'added', 'removed'] as const).map(s => (
          <button
            key={s}
            onClick={() => onStatusFilter(s)}
            style={{ fontSize: '0.72rem', padding: '0.15rem 0.45rem', borderRadius: '0.3rem', border: statusFilter === s ? '1px solid rgba(121,192,255,0.4)' : '1px solid transparent', background: statusFilter === s ? 'rgba(121,192,255,0.12)' : 'rgba(255,255,255,0.04)', color: s === 'all' ? '#c9d1d9' : DIFF_COLORS[s], cursor: 'pointer' }}
          >
            {s} ({diffs.filter(d => s === 'all' || d.status === s).length})
          </button>
        ))}
      </div>
      {diffs.filter(d => statusFilter === 'all' || d.status === statusFilter).map((s, i) => (
        <div
          key={`${s.text}-${i}`}
          style={{ display: 'flex', gap: '0.5rem', alignItems: 'baseline', padding: '0.25rem 0.5rem', background: DIFF_BG[s.status], borderLeft: `2px solid ${DIFF_COLORS[s.status]}`, borderRadius: '0.3rem', fontSize: '0.8rem' }}
        >
          <span style={{ color: DIFF_COLORS[s.status], minWidth: '3.5rem', fontSize: '0.7rem', textTransform: 'uppercase' }}>{s.status}</span>
          {s.kind !== 'plain' && <span style={{ fontSize: '0.65rem', color: '#888', background: 'rgba(255,255,255,0.06)', padding: '0.1rem 0.3rem', borderRadius: '0.25rem' }}>{s.kind}</span>}
          <span style={{ fontFamily: 'monospace', color: '#c9d1d9', wordBreak: 'break-all' }}>{s.text}</span>
          {s.baseOffset !== undefined && (
            <span style={{ marginLeft: 'auto', fontFamily: 'monospace', fontSize: '0.7rem', color: '#555' }}>@{s.baseOffset.toString(16)}</span>
          )}
        </div>
      ))}
      {diffs.length === 0 && <div style={{ color: '#555', fontSize: '0.8rem' }}>No string differences.</div>}
    </div>
  );
}

// ─── Imports tab ───────────────────────────────────────────────────────────────

function ImportsTab({
  diffs,
  statusFilter,
  onStatusFilter,
}: {
  diffs:          ImportDiff[];
  statusFilter:   'added' | 'removed' | 'all';
  onStatusFilter: (s: 'added' | 'removed' | 'all') => void;
}) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
      <div style={{ display: 'flex', gap: '0.35rem' }}>
        {(['all', 'added', 'removed'] as const).map(s => (
          <button
            key={s}
            onClick={() => onStatusFilter(s)}
            style={{ fontSize: '0.72rem', padding: '0.15rem 0.45rem', borderRadius: '0.3rem', border: statusFilter === s ? '1px solid rgba(121,192,255,0.4)' : '1px solid transparent', background: statusFilter === s ? 'rgba(121,192,255,0.12)' : 'rgba(255,255,255,0.04)', color: s === 'all' ? '#c9d1d9' : DIFF_COLORS[s], cursor: 'pointer' }}
          >
            {s} ({diffs.filter(d => s === 'all' || d.status === s).length})
          </button>
        ))}
      </div>
      {diffs.filter(d => statusFilter === 'all' || d.status === statusFilter).map((imp, i) => (
        <div
          key={`${imp.library}::${imp.name}-${i}`}
          style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', padding: '0.25rem 0.5rem', background: DIFF_BG[imp.status], borderLeft: `2px solid ${DIFF_COLORS[imp.status]}`, borderRadius: '0.3rem', fontSize: '0.8rem' }}
        >
          <span style={{ color: DIFF_COLORS[imp.status], minWidth: '3.5rem', fontSize: '0.7rem', textTransform: 'uppercase' }}>{imp.status}</span>
          <span style={{ fontFamily: 'monospace', color: '#c9d1d9' }}>{imp.name}</span>
          <span style={{ color: '#555', fontSize: '0.72rem' }}>from {imp.library}</span>
        </div>
      ))}
      {diffs.length === 0 && <div style={{ color: '#555', fontSize: '0.8rem' }}>No import differences.</div>}
    </div>
  );
}

// ─── Signals tab ───────────────────────────────────────────────────────────────

function SignalsTab({ diffs }: { diffs: SignalDiff[] }) {
  if (diffs.length === 0) {
    return <div style={{ color: '#555', fontSize: '0.8rem' }}>No signal changes.</div>;
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
      {diffs.map((s, i) => {
        const color = s.status === 'added' ? DIFF_COLORS.added : s.status === 'removed' ? DIFF_COLORS.removed : DIFF_COLORS.modified;
        const wChange = s.weightChange;
        return (
          <div
            key={`${s.signalId}-${i}`}
            style={{ display: 'flex', gap: '0.5rem', alignItems: 'baseline', padding: '0.3rem 0.5rem', background: DIFF_BG[s.status === 'modified' ? 'modified' : s.status], borderLeft: `2px solid ${color}`, borderRadius: '0.3rem', fontSize: '0.8rem' }}
          >
            <span style={{ color, minWidth: '4rem', fontSize: '0.7rem', textTransform: 'uppercase' }}>{s.status}</span>
            <span style={{ fontFamily: 'monospace', color: '#79c0ff' }}>{s.signalId}</span>
            <span style={{ color: '#888', fontSize: '0.78rem', flex: 1 }}>{s.finding}</span>
            <span style={{ fontFamily: 'monospace', fontSize: '0.72rem', color: wChange > 0 ? '#f44336' : '#4caf50' }}>
              {wChange > 0 ? '+' : ''}{wChange.toFixed(1)}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// ─── CFG tab ───────────────────────────────────────────────────────────────────

function CfgTab({
  diffs,
  onJumpToAddress,
}: {
  diffs:            CfgBlockDiff[];
  onJumpToAddress?: (addr: number) => void;
}) {
  const changed = diffs.filter(d => d.status !== 'unchanged');
  if (changed.length === 0) {
    return <div style={{ color: '#555', fontSize: '0.8rem' }}>No CFG block changes (or CFG not loaded for both binaries).</div>;
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
      {changed.map((b, i) => {
        const color = DIFF_COLORS[b.status];
        return (
          <div
            key={`${b.blockId}-${i}`}
            style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', padding: '0.25rem 0.5rem', background: DIFF_BG[b.status], borderLeft: `2px solid ${color}`, borderRadius: '0.3rem', fontSize: '0.8rem', cursor: onJumpToAddress ? 'pointer' : 'default' }}
            onClick={() => onJumpToAddress?.(b.start)}
            title={onJumpToAddress ? 'Jump to block start' : undefined}
          >
            <span style={{ color, minWidth: '4rem', fontSize: '0.7rem', textTransform: 'uppercase' }}>{b.status}</span>
            <span style={{ fontFamily: 'monospace', fontSize: '0.72rem', color: '#79c0ff' }}>0x{b.start.toString(16)}</span>
            <span style={{ color: '#555', fontSize: '0.7rem' }}>{b.blockType}</span>
            {b.sizeChange !== 0 && <span style={{ fontSize: '0.72rem', color: b.sizeChange > 0 ? DIFF_COLORS.added : DIFF_COLORS.removed }}>{b.sizeChange > 0 ? '+' : ''}{b.sizeChange} instrs</span>}
            {b.edgeChange !== 0 && <span style={{ fontSize: '0.72rem', color: '#ffc107' }}>{b.edgeChange > 0 ? '+' : ''}{b.edgeChange} edges</span>}
          </div>
        );
      })}
    </div>
  );
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(2)} MB`;
}
