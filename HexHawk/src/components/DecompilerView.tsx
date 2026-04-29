import React, { useMemo, useState, useCallback, useRef, useEffect } from 'react';
import {
  decompile,
  type DecompileResult,
  type PseudoLine,
  type IRBlock,
  type IRStmt,
  type VarMap,
} from '../utils/decompilerEngine';

// ─── Types (matching App.tsx) ────────────────────────────

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

// ─── Helpers ─────────────────────────────────────────────

function formatHex(v: number): string {
  return `0x${v.toString(16).toUpperCase()}`;
}

function getIndentStyle(n: number): React.CSSProperties {
  return { paddingLeft: `${n * 18}px` };
}

function lineClass(line: PseudoLine): string {
  if (line.isUncertain) return 'dc-line dc-line--uncertain';
  switch (line.kind) {
    case 'header':    return 'dc-line dc-line--header';
    case 'comment':   return 'dc-line dc-line--comment';
    case 'control':   return 'dc-line dc-line--control';
    case 'brace':     return 'dc-line dc-line--brace';
    case 'blank':     return 'dc-line dc-line--blank';
    default:          return 'dc-line dc-line--stmt';
  }
}

// Very lightweight tokenizer for pseudo-code syntax highlighting
const KEYWORDS = new Set(['if', 'else', 'while', 'do', 'for', 'return', 'goto', 'function', 'push', 'pop']);
const TOKEN_RE = /(\bfunction\b|\bif\b|\belse\b|\bwhile\b|\bdo\b|\bfor\b|\breturn\b|\bgoto\b|\/\/.*$|"[^"]*"|'[^']*'|0x[0-9a-fA-F]+|\b\d+\b|[&|^~+\-*/<>=!]+|[(){};,]|\b\w+\b)/g;

function highlightLine(text: string): React.ReactNode[] {
  const tokens: React.ReactNode[] = [];
  let last = 0;
  let match: RegExpExecArray | null;
  TOKEN_RE.lastIndex = 0;
  let key = 0;

  while ((match = TOKEN_RE.exec(text)) !== null) {
    if (match.index > last) {
      tokens.push(text.slice(last, match.index));
    }
    const tok = match[1];
    let cls = '';
    if (tok.startsWith('//')) cls = 'dc-tok-comment';
    else if (KEYWORDS.has(tok)) cls = 'dc-tok-keyword';
    else if (/^0x[0-9a-fA-F]+$/.test(tok) || /^\d+$/.test(tok)) cls = 'dc-tok-number';
    else if (/^[+\-*/<>=!&|^~]+$/.test(tok)) cls = 'dc-tok-operator';
    else if (/^[(){};,]$/.test(tok)) cls = 'dc-tok-punct';
    else if (/^[a-z][a-z0-9_]*$/.test(tok) && !KEYWORDS.has(tok)) cls = 'dc-tok-var';
    else if (/^[A-Z_][A-Za-z0-9_]*$/.test(tok)) cls = 'dc-tok-func';

    if (cls) tokens.push(<span key={key++} className={cls}>{tok}</span>);
    else tokens.push(tok);
    last = match.index + tok.length;
  }
  if (last < text.length) tokens.push(text.slice(last));
  return tokens;
}

// ─── Raw IR Viewer ────────────────────────────────────────

function IRViewer({ blocks, varMap }: { blocks: IRBlock[]; varMap: VarMap }) {
  if (!blocks.length) return <div className="dc-empty">No IR blocks</div>;

  function renderIRValue(v: IRBlock['stmts'][0] extends { dest: infer V } ? V : never): string {
    return String(v);
  }

  function stmtText(s: IRStmt): string {
    switch (s.op) {
      case 'assign': return `${renderIRValueStr(s.dest)} = ${renderIRValueStr(s.src)}`;
      case 'binop': return `${renderIRValueStr(s.dest)} = ${renderIRValueStr(s.left)} ${s.operator} ${renderIRValueStr(s.right)}`;
      case 'uop': return `${renderIRValueStr(s.dest)} = ${s.operator}${renderIRValueStr(s.operand)}`;
      case 'cmp': return `CMP ${renderIRValueStr(s.left)}, ${renderIRValueStr(s.right)}`;
      case 'test': return `TEST ${renderIRValueStr(s.left)}, ${renderIRValueStr(s.right)}`;
      case 'cjmp': return `CJMP (${s.cond}) → 0x${s.trueTarget.toString(16)} / 0x${s.falseTarget.toString(16)}`;
      case 'jmp': return `JMP ${s.target !== null ? `0x${s.target.toString(16)}` : '*indirect'}`;
      case 'call': return `CALL ${s.name ?? (s.target !== null ? `0x${s.target.toString(16)}` : '*indirect')}`;
      case 'ret': return `RET`;
      case 'push': return `PUSH ${renderIRValueStr(s.value)}`;
      case 'pop': return `POP → ${renderIRValueStr(s.dest)}`;
      case 'prologue': return `[PROLOGUE]`;
      case 'epilogue': return `[EPILOGUE]`;
      case 'nop': return `NOP`;
      case 'unknown': return `?? ${s.raw}`;
    }
  }

  function renderIRValueStr(v: unknown): string {
    const val = v as { kind: string; name?: string; value?: number; base?: string; offset?: number; text?: string };
    switch (val.kind) {
      case 'reg': return val.name ?? '?';
      case 'const': return `0x${(val.value ?? 0).toString(16)}`;
      case 'mem': return `[${val.base}${val.offset !== 0 ? (val.offset! > 0 ? `+${val.offset}` : `${val.offset}`) : ''}]`;
      case 'expr': return val.text ?? '?';
      default: return '?';
    }
  }

  return (
    <div className="dc-ir-viewer">
      {blocks.map(block => (
        <div key={block.id} className="dc-ir-block">
          <div className="dc-ir-block-header">
            {block.id} [{formatHex(block.start)}–{formatHex(block.end)}]
            {block.blockType ? ` (${block.blockType})` : ''}
            {block.allSuccessors.length > 0 ? ` → ${block.allSuccessors.join(', ')}` : ''}
          </div>
          {block.stmts.map((stmt, i) => (
            <div key={i} className={`dc-ir-stmt${stmt.op === 'unknown' ? ' dc-ir-stmt--unknown' : ''}`}>
              <span className="dc-ir-addr">{formatHex(stmt.address)}</span>
              <span className="dc-ir-op">{stmtText(stmt)}</span>
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

// ─── Variable Dictionary ──────────────────────────────────

function VarDictionary({ varMap }: { varMap: VarMap }) {
  const entries = [...varMap.entries()];
  if (entries.length === 0) return null;

  const locals = entries.filter(([, v]) => v.startsWith('local_'));
  const params = entries.filter(([, v]) => v.startsWith('param_'));
  const args = entries.filter(([, v]) => v.startsWith('arg_'));

  function Section({ title, items }: { title: string; items: [string, string][] }) {
    if (!items.length) return null;
    return (
      <div className="dc-vardict-section">
        <div className="dc-vardict-title">{title}</div>
        {items.map(([key, name]) => {
          const desc = key.startsWith('mem:') ? `← ${key.replace('mem:', '').replace(/:/g, '][').replace(']', ' + ').replace('[', '[')}` : `← ${key.replace('reg:', '')}`;
          return (
            <div key={key} className="dc-vardict-row">
              <span className="dc-vardict-name">{name}</span>
              <span className="dc-vardict-key">{desc}</span>
            </div>
          );
        })}
      </div>
    );
  }

  return (
    <div className="dc-vardict">
      <div className="dc-vardict-header">Variables</div>
      <Section title="Parameters" items={params} />
      <Section title="Stack args" items={args} />
      <Section title="Locals" items={locals} />
    </div>
  );
}

// ─── Pseudo-code Display ──────────────────────────────────

interface PseudoCodeProps {
  lines: PseudoLine[];
  selectedAddress: number | null;
  onLineClick: (address: number) => void;
}

function PseudoCodeDisplay({ lines, selectedAddress, onLineClick }: PseudoCodeProps) {
  const selectedRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (selectedRef.current) {
      selectedRef.current.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
  }, [selectedAddress]);

  if (!lines.length) return <div className="dc-empty">Nothing to display</div>;

  return (
    <div className="dc-pseudocode">
      {lines.map((line, i) => {
        const isSelected = line.address !== undefined && line.address === selectedAddress;
        const clickable = line.address !== undefined;
        return (
          <div
            key={i}
            ref={isSelected ? selectedRef : undefined}
            className={`${lineClass(line)}${isSelected ? ' dc-line--selected' : ''}${clickable ? ' dc-line--clickable' : ''}`}
            style={getIndentStyle(line.indent)}
            onClick={clickable ? () => onLineClick(line.address!) : undefined}
            title={line.address !== undefined ? formatHex(line.address) : undefined}
          >
            {line.address !== undefined && (
              <span className="dc-line-addr">{formatHex(line.address)}</span>
            )}
            <span className="dc-line-text">
              {highlightLine(line.text)}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// ─── Function Selector ────────────────────────────────────

interface FuncSelectorProps {
  functions: Map<number, FunctionMetadata>;
  selectedAddr: number | null;
  onSelect: (addr: number | null) => void;
}

function FunctionSelector({ functions, selectedAddr, onSelect }: FuncSelectorProps) {
  const entries = [...functions.entries()].sort(([a], [b]) => a - b);
  if (entries.length === 0) return null;

  return (
    <div className="dc-func-selector">
      <div className="dc-func-selector-label">Function:</div>
      <select
        className="dc-func-select"
        value={selectedAddr ?? ''}
        onChange={e => onSelect(e.target.value ? Number(e.target.value) : null)}
      >
        <option value="">Full range ({entries.length} functions)</option>
        {entries.map(([addr, fn]) => (
          <option key={addr} value={addr}>
            {formatHex(addr)} — {fn.size}b{fn.hasLoops ? ' 🔄' : ''}{fn.complexity > 8 ? ' ⚠' : ''}
          </option>
        ))}
      </select>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────

type ViewMode = 'pseudocode' | 'ir';

export default function DecompilerView({
  disassembly,
  cfg,
  functions,
  currentAddress,
  onAddressSelect,
  metadata,
}: Props) {
  const [selectedFuncAddr, setSelectedFuncAddr] = useState<number | null>(null);
  const [viewMode, setViewMode] = useState<ViewMode>('pseudocode');
  const [showVarDict, setShowVarDict] = useState(true);

  // Auto-select function when currentAddress changes
  useEffect(() => {
    if (currentAddress === null) return;
    for (const [addr, fn] of functions.entries()) {
      if (currentAddress >= addr && currentAddress <= fn.endAddress) {
        setSelectedFuncAddr(addr);
        return;
      }
    }
  }, [currentAddress, functions]);

  const result: DecompileResult = useMemo(() => {
    if (!disassembly.length) {
      return {
        functionName: 'sub_unknown',
        startAddress: 0,
        lines: [{ indent: 0, text: '// No disassembly loaded — load a binary and run Disassemble first', kind: 'comment' as const }],
        varMap: new Map(),
        irBlocks: [],
        logicRegions: [],
        warnings: [],
        instrCount: 0,
      };
    }

    const opts =
      selectedFuncAddr !== null && functions.has(selectedFuncAddr)
        ? {
            startAddress: selectedFuncAddr,
            endAddress: functions.get(selectedFuncAddr)!.endAddress,
            functionName: `sub_${selectedFuncAddr.toString(16)}`,
          }
        : {
            startAddress: disassembly[0]?.address,
            functionName: `sub_${disassembly[0]?.address.toString(16) ?? '0'}`,
          };

    return decompile(disassembly as any, cfg as any, opts);
  }, [disassembly, cfg, selectedFuncAddr, functions]);

  const statsText = result.instrCount > 0
    ? `${result.instrCount} instr · ${result.irBlocks.length} blocks · ${result.varMap.size} vars`
    : '';

  return (
    <div className="dc-root">
      {/* Toolbar */}
      <div className="dc-toolbar">
        <div className="dc-toolbar-left">
          <span className="dc-toolbar-title">Decompiler</span>
          {metadata?.architecture && (
            <span className="dc-arch-badge">{metadata.architecture}</span>
          )}
          <FunctionSelector
            functions={functions}
            selectedAddr={selectedFuncAddr}
            onSelect={setSelectedFuncAddr}
          />
        </div>
        <div className="dc-toolbar-right">
          {statsText && <span className="dc-stats">{statsText}</span>}
          <div className="dc-view-toggle">
            <button
              type="button"
              className={`dc-toggle-btn${viewMode === 'pseudocode' ? ' active' : ''}`}
              onClick={() => setViewMode('pseudocode')}
            >
              Pseudo-code
            </button>
            <button
              type="button"
              className={`dc-toggle-btn${viewMode === 'ir' ? ' active' : ''}`}
              onClick={() => setViewMode('ir')}
            >
              Raw IR
            </button>
          </div>
          <button
            type="button"
            className={`dc-toggle-btn${showVarDict ? ' active' : ''}`}
            onClick={() => setShowVarDict(v => !v)}
            title="Toggle variable dictionary"
          >
            Vars
          </button>
        </div>
      </div>

      {/* Warnings */}
      {result.warnings.length > 0 && (
        <div className="dc-warnings">
          {result.warnings.map((w, i) => (
            <div key={i} className="dc-warning-item">⚠ {w}</div>
          ))}
        </div>
      )}

      {/* Main content */}
      <div className="dc-content">
        <div className="dc-main">
          {viewMode === 'pseudocode' ? (
            <PseudoCodeDisplay
              lines={result.lines}
              selectedAddress={currentAddress}
              onLineClick={onAddressSelect}
            />
          ) : (
            <IRViewer blocks={result.irBlocks} varMap={result.varMap} />
          )}
        </div>

        {showVarDict && viewMode === 'pseudocode' && (
          <div className="dc-sidebar">
            <VarDictionary varMap={result.varMap} />

            <div className="dc-sidebar-section">
              <div className="dc-sidebar-title">Structure</div>
              <div className="dc-sidebar-stat">Blocks: {result.irBlocks.length}</div>
              <div className="dc-sidebar-stat">Functions: {functions.size}</div>
              <div className="dc-sidebar-stat">
                Back edges: {result.irBlocks.reduce((n, b) => n + b.allSuccessors.filter(s => {
                  const target = result.irBlocks.find(x => x.id === s);
                  return target && target.start <= b.start;
                }).length, 0)}
              </div>
            </div>

            <div className="dc-sidebar-section">
              <div className="dc-sidebar-title">Legend</div>
              <div className="dc-legend-row"><span className="dc-tok-keyword">keyword</span> control flow</div>
              <div className="dc-legend-row"><span className="dc-tok-var">var</span> variable / register</div>
              <div className="dc-legend-row"><span className="dc-tok-number">0x1234</span> constant</div>
              <div className="dc-legend-row"><span className="dc-tok-comment">// comment</span> note</div>
              <div className="dc-legend-row"><span className="dc-line--uncertain" style={{ fontSize: '0.8em', color: '#888' }}>italic grey</span> uncertain</div>
            </div>

            <div className="dc-sidebar-section">
              <div className="dc-sidebar-title">Note</div>
              <div className="dc-note-text">
                Pseudo-code is lifted from disassembly and may be incomplete.
                Click any line to navigate to its source instruction.
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
