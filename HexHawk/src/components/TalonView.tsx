import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  talonDecompile,
  type TalonResult,
  type TalonLine,
  type TalonFunctionSummary,
  type TalonIntent,
  type IntentCategory,
} from '../utils/talonEngine';
import type { BehavioralTag } from '../utils/correlationEngine';

// ─── Prop Types ───────────────────────────────────────────────────────────────

type DisassembledInstruction = {
  address: number;
  mnemonic: string;
  operands: string;
};

type CfgGraph = {
  nodes: Array<{ id: string; start?: number; end?: number; block_type?: string; layout_depth?: number }>;
  edges: Array<{ source: string; target: string; kind?: string; condition?: string }>;
};

type FunctionMetadata = {
  startAddress: number;
  endAddress: number;
  size: number;
  callCount: number;
  hasLoops: boolean;
  complexity: number;
};

interface Props {
  disassembly: DisassembledInstruction[];
  cfg: CfgGraph | null;
  functions: Map<number, FunctionMetadata>;
  currentAddress: number | null;
  onAddressSelect: (address: number) => void;
  metadata?: { architecture?: string } | null;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmt(v: number): string {
  return `0x${v.toString(16).toUpperCase()}`;
}

function confColor(c: number): string {
  if (c >= 85) return 'var(--tln-conf-high)';
  if (c >= 70) return 'var(--tln-conf-mid)';
  if (c >= 55) return 'var(--tln-conf-low)';
  return 'var(--tln-conf-very-low)';
}

function catIcon(cat: IntentCategory): string {
  switch (cat) {
    case 'security':   return '⚠';
    case 'memory':     return '◼';
    case 'control':    return '⟳';
    case 'io':         return '⇆';
    case 'arithmetic': return '±';
    case 'api':        return '⊞';
    default:           return '·';
  }
}

const TAG_LABELS: Partial<Record<BehavioralTag, string>> = {
  'anti-analysis':     'Anti-debug',
  'data-encryption':   'Crypto',
  'code-decryption':   'Unpack/Decrypt',
  'code-injection':    'Injection',
  'c2-communication':  'Network C2',
  'process-execution': 'Process exec',
  'persistence':       'Persistence',
  'dynamic-resolution':'Dyn. resolve',
  'data-exfiltration': 'File I/O',
  'self-contained':    'Self-contained',
};

const TAG_UNSAFE = new Set<BehavioralTag>([
  'anti-analysis', 'data-encryption', 'code-decryption',
  'code-injection', 'c2-communication', 'process-execution',
  'persistence', 'dynamic-resolution',
]);

// ─── Syntax highlight ─────────────────────────────────────────────────────────

const KEYWORDS = new Set(['if', 'else', 'while', 'do', 'for', 'return', 'goto', 'function', 'push', 'pop']);
const TOKEN_RE = /(\bfunction\b|\bif\b|\belse\b|\bwhile\b|\bdo\b|\bfor\b|\breturn\b|\bgoto\b|\/\/.*$|0x[0-9a-fA-F]+|\b\d+\b|[+\-*/<>=!&|^~?]+|[(){};,]|\b\w+\b)/g;

function highlight(text: string): React.ReactNode[] {
  const tokens: React.ReactNode[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  TOKEN_RE.lastIndex = 0;
  let key = 0;
  while ((m = TOKEN_RE.exec(text)) !== null) {
    if (m.index > last) tokens.push(text.slice(last, m.index));
    const tok = m[1];
    let cls = '';
    if (tok.startsWith('//'))        cls = 'tln-tok-comment';
    else if (KEYWORDS.has(tok))      cls = 'tln-tok-keyword';
    else if (/^0x[0-9a-fA-F]+$/.test(tok) || /^\d+$/.test(tok)) cls = 'tln-tok-number';
    else if (/^[+\-*/<>=!&|^~?]+$/.test(tok)) cls = 'tln-tok-op';
    else if (/^[(){};,]$/.test(tok)) cls = 'tln-tok-punct';
    else if (/^[a-z][a-z0-9_]*$/.test(tok) && !KEYWORDS.has(tok)) cls = 'tln-tok-var';
    else if (/^[A-Z_][A-Za-z0-9_]*$/.test(tok)) cls = 'tln-tok-func';
    if (cls) tokens.push(<span key={key++} className={cls}>{tok}</span>);
    else tokens.push(tok);
    last = m.index + tok.length;
  }
  if (last < text.length) tokens.push(text.slice(last));
  return tokens;
}

// ─── Intent Badge ─────────────────────────────────────────────────────────────

function IntentBadge({ intent }: { intent: TalonIntent }) {
  return (
    <span
      className={`tln-intent-badge tln-intent-badge--${intent.category}`}
      title={intent.detail ?? intent.label}
    >
      {catIcon(intent.category)} {intent.label} {intent.confidence}%
    </span>
  );
}

// ─── Confidence Bar ────────────────────────────────────────────────────────────

function ConfidenceBar({ value, label }: { value: number; label?: string }) {
  return (
    <div className="tln-conf-bar" title={`${value}% confidence`}>
      <div className="tln-conf-bar-fill" style={{ width: `${value}%`, background: confColor(value) }} />
      {label && <span className="tln-conf-bar-label">{label}</span>}
    </div>
  );
}

// ─── Behavioral Tag Chip ───────────────────────────────────────────────────────

function TagChip({ tag }: { tag: BehavioralTag }) {
  const unsafe = TAG_UNSAFE.has(tag);
  return (
    <span className={`tln-tag-chip${unsafe ? ' tln-tag-chip--unsafe' : ''}`}>
      {TAG_LABELS[tag] ?? tag}
    </span>
  );
}

// ─── Intent Sidebar ────────────────────────────────────────────────────────────

function IntentSidebar({ summary, onAddressClick }: {
  summary: TalonFunctionSummary;
  onAddressClick: (addr: number) => void;
}) {
  const grouped = useMemo(() => {
    const map = new Map<IntentCategory, TalonIntent[]>();
    for (const intent of summary.intents) {
      const list = map.get(intent.category) ?? [];
      list.push(intent);
      map.set(intent.category, list);
    }
    return map;
  }, [summary.intents]);

  const categoryOrder: IntentCategory[] = ['security', 'control', 'memory', 'io', 'arithmetic', 'api', 'unknown'];

  return (
    <div className="tln-sidebar">
      {/* Confidence summary */}
      <div className="tln-sidebar-section">
        <div className="tln-sidebar-title">Confidence</div>
        <ConfidenceBar value={summary.overallConfidence} label={`${summary.overallConfidence}%`} />
        <div className="tln-sidebar-meta">
          Lifting: {summary.liftingCoverage}% · {summary.complexityScore} blocks
        </div>
        {summary.uncertainStatements > 0 && (
          <div className="tln-sidebar-warn">
            {summary.uncertainStatements}/{summary.totalStatements} stmts uncertain
          </div>
        )}
      </div>

      {/* Behavioral tags */}
      {summary.behavioralTags.length > 0 && (
        <div className="tln-sidebar-section">
          <div className="tln-sidebar-title">Behavior</div>
          <div className="tln-tag-list">
            {summary.behavioralTags.map(tag => <TagChip key={tag} tag={tag} />)}
          </div>
        </div>
      )}

      {/* Intents by category */}
      {summary.intents.length > 0 && (
        <div className="tln-sidebar-section">
          <div className="tln-sidebar-title">Detected Patterns</div>
          {categoryOrder.map(cat => {
            const items = grouped.get(cat);
            if (!items || items.length === 0) return null;
            return (
              <div key={cat} className="tln-intent-group">
                <div className="tln-intent-group-label">
                  {catIcon(cat)} {cat}
                </div>
                {items.map((intent, i) => (
                  <div
                    key={i}
                    className="tln-intent-item"
                    onClick={() => onAddressClick(intent.address)}
                    title={`${fmt(intent.address)} — click to navigate`}
                  >
                    <span className="tln-intent-item-label">{intent.label}</span>
                    <span className="tln-intent-item-conf" style={{ color: confColor(intent.confidence) }}>
                      {intent.confidence}%
                    </span>
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      )}

      {/* Warnings */}
      {summary.warningCount > 0 && (
        <div className="tln-sidebar-section tln-sidebar-section--warn">
          <div className="tln-sidebar-title">⚠ Warnings</div>
          <div className="tln-sidebar-meta">{summary.warningCount} warning(s)</div>
        </div>
      )}
    </div>
  );
}

// ─── Code Display ─────────────────────────────────────────────────────────────

function TalonCodeDisplay({ lines, selectedAddress, onLineClick }: {
  lines: TalonLine[];
  selectedAddress: number | null;
  onLineClick: (addr: number) => void;
}) {
  const selectedRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    selectedRef.current?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }, [selectedAddress]);

  if (!lines.length) {
    return <div className="tln-empty">No instructions loaded. Open a binary and run Disassemble first.</div>;
  }

  return (
    <div className="tln-pseudocode">
      {lines.map((line, i) => {
        const isSelected = line.address !== undefined && line.address === selectedAddress;
        const clickable  = line.address !== undefined && line.kind !== 'intent-comment';
        const isIntent   = line.kind === 'intent-comment';
        const isUncertain = line.lineConfidence < 58 && line.kind !== 'comment' && line.kind !== 'intent-comment' && line.kind !== 'brace' && line.kind !== 'blank';
        const isControl  = line.kind === 'control';
        const isHeader   = line.kind === 'header';

        let cls = 'tln-line';
        if (isIntent)    cls += ' tln-line--intent';
        if (isUncertain) cls += ' tln-line--uncertain';
        if (isControl)   cls += ' tln-line--control';
        if (isHeader)    cls += ' tln-line--header';
        if (line.kind === 'comment') cls += ' tln-line--comment';
        if (isSelected)  cls += ' tln-line--selected';
        if (clickable)   cls += ' tln-line--clickable';

        return (
          <div
            key={i}
            ref={isSelected ? selectedRef : undefined}
            className={cls}
            style={{ paddingLeft: `${line.indent * 18 + 8}px` }}
            onClick={clickable ? () => onLineClick(line.address!) : undefined}
            title={line.address !== undefined ? fmt(line.address) : undefined}
          >
            {/* Address gutter */}
            {line.address !== undefined && !isIntent && (
              <span className="tln-line-addr">{fmt(line.address)}</span>
            )}
            {isIntent && <span className="tln-line-addr-spacer" />}

            {/* Line content */}
            <span className="tln-line-text">
              {isIntent
                ? <em className="tln-intent-text">{line.text}</em>
                : highlight(line.text)
              }
            </span>

            {/* Intent category badge inline */}
            {isIntent && line.intent && (
              <span className={`tln-cat-dot tln-cat-dot--${line.intent.category}`} />
            )}

            {/* Low-confidence indicator */}
            {isUncertain && (
              <span className="tln-uncertain-mark" title="Low confidence">??</span>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─── Function Selector ────────────────────────────────────────────────────────

function FunctionSelector({ functions, selectedAddr, onSelect }: {
  functions: Map<number, FunctionMetadata>;
  selectedAddr: number | null;
  onSelect: (addr: number | null) => void;
}) {
  const entries = [...functions.entries()].sort(([a], [b]) => a - b);
  if (!entries.length) return null;
  return (
    <div className="tln-func-selector">
      <select
        className="tln-func-select"
        value={selectedAddr ?? ''}
        onChange={e => onSelect(e.target.value ? Number(e.target.value) : null)}
      >
        <option value="">All ({entries.length} functions)</option>
        {entries.map(([addr, fn]) => (
          <option key={addr} value={addr}>
            {fmt(addr)} — {fn.size}b
            {fn.hasLoops ? ' ↺' : ''}
            {fn.complexity > 8 ? ' ⚠' : ''}
          </option>
        ))}
      </select>
    </div>
  );
}

// ─── Main Component ────────────────────────────────────────────────────────────

export default function TalonView({
  disassembly,
  cfg,
  functions,
  currentAddress,
  onAddressSelect,
  metadata,
}: Props) {
  const [selectedFuncAddr, setSelectedFuncAddr] = useState<number | null>(null);
  const [showSidebar, setShowSidebar] = useState(true);

  // Auto-select function containing currentAddress
  useEffect(() => {
    if (currentAddress === null) return;
    for (const [addr, fn] of functions.entries()) {
      if (currentAddress >= addr && currentAddress <= fn.endAddress) {
        setSelectedFuncAddr(addr);
        return;
      }
    }
  }, [currentAddress, functions]);

  const result: TalonResult = useMemo(() => {
    const emptyResult: TalonResult = {
      functionName: 'sub_unknown',
      startAddress: 0,
      lines: [{
        indent: 0,
        text: '// No disassembly loaded — open a binary and run Disassemble first',
        kind: 'comment',
        lineConfidence: 100,
      }],
      varMap: new Map(),
      irBlocks: [],
      warnings: [],
      instrCount: 0,
      summary: {
        name: 'sub_unknown',
        startAddress: 0,
        overallConfidence: 0,
        liftingCoverage: 0,
        intents: [],
        behavioralTags: [],
        uncertainStatements: 0,
        totalStatements: 0,
        complexityScore: 0,
        warningCount: 0,
      },
    };

    if (!disassembly.length) return emptyResult;

    const fn = selectedFuncAddr !== null ? functions.get(selectedFuncAddr) : null;
    const opts = fn
      ? { startAddress: selectedFuncAddr!, endAddress: fn.endAddress, functionName: `sub_${selectedFuncAddr!.toString(16)}` }
      : { startAddress: disassembly[0]?.address, functionName: `sub_${disassembly[0]?.address.toString(16) ?? '0'}` };

    try {
      return talonDecompile(disassembly as DisassembledInstruction[], cfg as CfgGraph | null, opts);
    } catch {
      return emptyResult;
    }
  }, [disassembly, cfg, selectedFuncAddr, functions]);

  const handleLineClick = useCallback((addr: number) => {
    onAddressSelect(addr);
  }, [onAddressSelect]);

  const { summary } = result;
  const statsText = result.instrCount > 0
    ? `${result.instrCount} instr · ${result.irBlocks.length} blocks · ${summary.overallConfidence}% conf`
    : '';

  return (
    <div className="tln-root">
      {/* ── Toolbar ── */}
      <div className="tln-toolbar">
        <div className="tln-toolbar-left">
          <span className="tln-brand">TALON</span>
          {metadata?.architecture && (
            <span className="tln-arch-badge">{metadata.architecture}</span>
          )}
          <FunctionSelector
            functions={functions}
            selectedAddr={selectedFuncAddr}
            onSelect={setSelectedFuncAddr}
          />
        </div>
        <div className="tln-toolbar-right">
          {statsText && <span className="tln-stats">{statsText}</span>}
          <button
            type="button"
            className={`tln-toggle-btn${showSidebar ? ' active' : ''}`}
            onClick={() => setShowSidebar(v => !v)}
            title="Toggle analysis sidebar"
          >
            Analysis
          </button>
        </div>
      </div>

      {/* ── Warnings ── */}
      {result.warnings.length > 0 && (
        <div className="tln-warnings">
          {result.warnings.map((w, i) => (
            <div key={i} className="tln-warning-item">⚠ {w}</div>
          ))}
        </div>
      )}

      {/* ── Body ── */}
      <div className="tln-body">
        <div className="tln-code-pane">
          <TalonCodeDisplay
            lines={result.lines}
            selectedAddress={currentAddress}
            onLineClick={handleLineClick}
          />
        </div>

        {showSidebar && summary.totalStatements > 0 && (
          <IntentSidebar
            summary={summary}
            onAddressClick={onAddressSelect}
          />
        )}
      </div>
    </div>
  );
}
