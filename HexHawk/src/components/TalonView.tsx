import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  talonDecompile,
  talonRefineWithLLM,
  type TalonResult,
  type TalonLine,
  type TalonFunctionSummary,
  type TalonIntent,
  type IntentCategory,
} from '../utils/talonEngine';
import type { BehavioralTag } from '../utils/correlationEngine';
import type { NaturalLoop, LoopClassification } from '../utils/cfgSignalExtractor';
import SettingsPanel, {
  DEFAULT_LLM_SETTINGS,
  settingsToConfig,
  type LLMSettings,
} from './SettingsPanel';

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
  callingConvention?: string;
  isThunk?: boolean;
  thunkTarget?: number;
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

// ─── Prototype header builder ──────────────────────────────────────────────
// Infers argument arity from the argument registers used in the function body.
// Scans the first 30 instructions looking for reads of calling-convention arg
// registers before they are written. Returns a C-style prototype comment.

const ARG_REGS_FASTCALL = ['rcx', 'rdx', 'r8', 'r9'];   // Windows x64
const ARG_REGS_CDECL    = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'];  // System V x64

function buildPrototypeHeader(
  fn: FunctionMetadata,
  funcAddr: number,
  disassembly: { address: number; mnemonic: string; operands: string }[],
): string {
  const name = `func_0x${funcAddr.toString(16).toUpperCase()}`;
  if (fn.isThunk) {
    const tgt = fn.thunkTarget !== undefined ? `0x${fn.thunkTarget.toString(16).toUpperCase()}` : '?';
    return `/* thunk → ${tgt} */`;
  }
  const cc = fn.callingConvention ?? 'unknown';
  const argRegs = cc === 'fastcall' ? ARG_REGS_FASTCALL : ARG_REGS_CDECL;
  // Scan first 30 instructions of this function for arg register reads
  const written = new Set<string>();
  const argsUsed = new Set<number>(); // indices into argRegs
  const funcInstrs = disassembly.filter(
    i => i.address >= fn.startAddress && i.address < fn.endAddress
  ).slice(0, 30);
  for (const instr of funcInstrs) {
    const ops = instr.operands.toLowerCase();
    // Skip writes to arg regs (first operand of mov/lea)
    const isWrite = /^(mov|lea|xor|sub|add|push|pop)/.test(instr.mnemonic.toLowerCase());
    for (let ai = 0; ai < argRegs.length; ai++) {
      const reg = argRegs[ai];
      if (!written.has(reg) && ops.includes(reg)) {
        // If it's a write to a register (dst), mark as written
        if (isWrite && ops.startsWith(reg)) {
          written.add(reg);
        } else {
          argsUsed.add(ai);
        }
      }
    }
  }
  const arity = argsUsed.size > 0 ? Math.max(...argsUsed) + 1 : 0;
  const params = arity === 0 ? 'void' : Array.from({ length: arity }, (_, i) => `param_${i}`).join(', ');
  return `/* ${cc} ${name}(${params}) */`;
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

// ─── Loop classification helpers ──────────────────────────────────────────────

function loopClassIcon(cls: LoopClassification): string {
  switch (cls) {
    case 'for':      return '↻';
    case 'while':    return '⤾';
    case 'do-while': return '⤿';
    case 'infinite': return '∞';
    default:         return '↺';
  }
}

function loopClassLabel(cls: LoopClassification): string {
  switch (cls) {
    case 'for':      return 'for';
    case 'while':    return 'while';
    case 'do-while': return 'do-while';
    case 'infinite': return 'infinite';
    default:         return 'loop';
  }
}

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
        {summary.ssaVarCount > 0 && (
          <div className="tln-sidebar-meta">
            SSA vars: {summary.ssaVarCount}
            {summary.loopNestingDepth > 0 && ` · Loop depth: ${summary.loopNestingDepth}`}
          </div>
        )}
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

      {/* Loop Structure */}
      {summary.naturalLoops.length > 0 && (
        <div className="tln-sidebar-section">
          <div className="tln-sidebar-title">Loop Structure</div>
          <div className="tln-sidebar-meta">
            {summary.naturalLoops.length} loop{summary.naturalLoops.length !== 1 ? 's' : ''}
            {summary.loopNestingDepth > 1 && ` · max depth ${summary.loopNestingDepth}`}
          </div>
          {summary.naturalLoops.map((loop: NaturalLoop, i: number) => (
            <div
              key={i}
              className="tln-loop-item"
              style={{ paddingLeft: `${(loop.depth - 1) * 12}px` }}
              onClick={() => loop.headerAddress > 0 && onAddressClick(loop.headerAddress)}
              title={`Back-edge: ${loop.backEdgeKey} · ${loop.body.size} block${loop.body.size !== 1 ? 's' : ''}`}
            >
              <span className="tln-loop-icon">{loopClassIcon(loop.classification)}</span>
              <span className="tln-loop-cls">{loopClassLabel(loop.classification)}</span>
              {loop.headerAddress > 0 && (
                <span className="tln-loop-addr">{fmt(loop.headerAddress)}</span>
              )}
              <span className="tln-loop-size">{loop.body.size}b</span>
            </div>
          ))}
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
  const [showSettings, setShowSettings] = useState(false);
  const [llmSettings, setLlmSettings] = useState<LLMSettings>(DEFAULT_LLM_SETTINGS);
  const [llmRefined, setLlmRefined] = useState<TalonResult | null>(null);
  const [llmLoading, setLlmLoading] = useState(false);
  const [llmError, setLlmError] = useState<string | null>(null);
  const [hasStoredApiKey, setHasStoredApiKey] = useState<Record<'open_ai' | 'anthropic' | 'ollama', boolean>>({
    open_ai: false,
    anthropic: false,
    ollama: true,
  });
  const [sessionTokensUsed, setSessionTokensUsed] = useState(0);

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
      logicRegions: [],
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
        ssaVarCount: 0,
        loopNestingDepth: 0,
        naturalLoops: [],
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

  useEffect(() => {
    setLlmRefined(null);
    setLlmError(null);
  }, [result]);

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      invoke<boolean>('has_llm_provider_key', { provider: 'open_ai', keyAlias: llmSettings.keyAlias || undefined }).catch(() => false),
      invoke<boolean>('has_llm_provider_key', { provider: 'anthropic', keyAlias: llmSettings.keyAlias || undefined }).catch(() => false),
    ])
      .then(([openAi, anthropic]) => {
        if (!cancelled) {
          setHasStoredApiKey({
            open_ai: openAi,
            anthropic,
            ollama: true,
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, [llmSettings.keyAlias]);

  const handleRunLlmRefinement = useCallback(() => {
    setLlmRefined(null);
    setLlmError(null);
    if (!llmSettings.enabled || !result.instrCount || llmLoading) return;
    if (!llmSettings.providerEnabled[llmSettings.provider]) {
      setLlmError(`LLM request blocked: provider ${llmSettings.provider} is disabled.`);
      return;
    }
    if (!llmSettings.featureEnabled[llmSettings.action]) {
      setLlmError(`LLM request blocked: feature ${llmSettings.action} is disabled.`);
      return;
    }
    if (!llmSettings.privacyDisclosureAccepted) {
      setLlmError('LLM request blocked: privacy disclosure acknowledgement is required.');
      return;
    }

    const approved = window.confirm(
      [
        'Send TALON prompt to LLM endpoint?',
        `Provider: ${llmSettings.provider}`,
        `Endpoint: ${llmSettings.endpointUrl || 'unset'}`,
        `Model: ${llmSettings.modelName || 'unset'}`,
        `Token budget/request: ${llmSettings.tokenBudget}`,
        `Session token usage: ${sessionTokensUsed}/${llmSettings.sessionTokenCap}`,
        `Prompt scope: current decompiled function (${result.lines.length} lines)`
      ].join('\n'),
    );

    if (!approved) {
      setLlmError('LLM request cancelled: user approval not granted.');
      return;
    }

    setLlmLoading(true);

    talonRefineWithLLM(result, {
      ...settingsToConfig(llmSettings),
      sessionTokensUsed,
      approvalGranted: approved,
    })
      .then(refined => {
        setLlmRefined(refined);
        const promptChars = result.lines.map(line => line.text).join('\n').length;
        const tokenEstimate = Math.ceil(promptChars / 4);
        setSessionTokensUsed(prev => prev + tokenEstimate);
      })
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : String(err);
        setLlmError(msg);
      })
      .finally(() => {
        setLlmLoading(false);
      });
  }, [llmLoading, llmSettings, result, sessionTokensUsed]);

  const handleSaveApiKey = useCallback(() => {
    const apiKey = llmSettings.apiKey.trim();
    if (llmSettings.provider === 'ollama') {
      setLlmError('Local Ollama does not require API key storage.');
      return;
    }
    if (!apiKey) {
      setLlmError('Enter an API key first, then click Save key securely.');
      return;
    }
    invoke<void>('store_llm_provider_key', {
      request: {
        provider: llmSettings.provider,
        keyAlias: llmSettings.keyAlias || undefined,
        apiKey,
      },
    })
      .then(() => {
        setHasStoredApiKey(prev => ({ ...prev, [llmSettings.provider]: true }));
        setLlmSettings(prev => ({ ...prev, apiKey: '' }));
        setLlmError(null);
      })
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : String(err);
        setLlmError(msg);
      });
  }, [llmSettings.apiKey, llmSettings.keyAlias, llmSettings.provider]);

  const handleClearApiKey = useCallback(() => {
    if (llmSettings.provider === 'ollama') {
      setLlmError('No stored API key is used for local Ollama.');
      return;
    }
    invoke<void>('clear_llm_provider_key', {
      provider: llmSettings.provider,
      keyAlias: llmSettings.keyAlias || undefined,
    })
      .then(() => {
        setHasStoredApiKey(prev => ({ ...prev, [llmSettings.provider]: false }));
      })
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : String(err);
        setLlmError(msg);
      });
  }, [llmSettings.keyAlias, llmSettings.provider]);

  const handleTestProvider = useCallback(() => {
    const approved = window.confirm(
      [
        'Run provider connectivity/key test?',
        `Provider: ${llmSettings.provider}`,
        `Endpoint: ${llmSettings.endpointUrl || 'unset'}`,
        'A tiny test prompt will be sent only after this confirmation.'
      ].join('\n'),
    );
    if (!approved) return;

    setLlmLoading(true);
    invoke('llm_query', {
      request: {
        provider: llmSettings.provider,
        action: 'signal_explainer',
        endpointUrl: llmSettings.endpointUrl,
        modelName: llmSettings.modelName,
        prompt: 'Respond with {"status":"ok"}',
        contextBlocks: [],
        timeoutMs: 8000,
        maxPromptChars: 1000,
        maxContextChars: 0,
        tokenBudget: Math.min(512, llmSettings.tokenBudget),
        approvalGranted: true,
        allowRemoteEndpoint: llmSettings.allowRemoteEndpoints,
        allowAgentTools: false,
        keyAlias: llmSettings.keyAlias || undefined,
      },
    })
      .then(() => {
        setLlmError('Provider test succeeded.');
      })
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : String(err);
        setLlmError(`Provider test failed: ${msg}`);
      })
      .finally(() => {
        setLlmLoading(false);
      });
  }, [llmSettings]);

  const handleLineClick = useCallback((addr: number) => {
    onAddressSelect(addr);
  }, [onAddressSelect]);

  // Use LLM-refined lines when available; fall back to TALON output
  const displayResult = llmRefined ?? result;
  const { summary } = displayResult;
  const statsText = result.instrCount > 0
    ? `${result.instrCount} instr · ${result.irBlocks.length} blocks · ${summary.overallConfidence}% conf${result.cseRewriteCount ? ` · ${result.cseRewriteCount} CSE` : ''}`
    : '';

  const llmRunBlockedReason = !llmSettings.enabled
    ? 'Enable the LLM decompilation pass first.'
    : !result.instrCount
      ? 'Run TALON on a function before requesting LLM refinement.'
      : !llmSettings.providerEnabled[llmSettings.provider]
        ? `Provider ${llmSettings.provider} is disabled in provider availability.`
        : !llmSettings.featureEnabled[llmSettings.action]
          ? `Active AI action ${llmSettings.action} is disabled in feature toggles.`
          : !llmSettings.privacyDisclosureAccepted
            ? 'Accept the privacy disclosure before sending model requests.'
            : null;

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
            className="tln-toggle-btn"
            onClick={handleRunLlmRefinement}
            disabled={Boolean(llmRunBlockedReason) || llmLoading}
            title={llmRunBlockedReason ?? 'Run LLM refinement now'}
          >
            Run LLM
          </button>
          {llmLoading && (
            <span className="tln-llm-loading" title="LLM refinement running…">⟳ LLM</span>
          )}
          {!llmLoading && llmRefined && (
            <span className="tln-llm-badge" title="LLM-refined variable names applied">✦ LLM</span>
          )}
          {!llmLoading && llmError && (
            <span className="tln-llm-error" title={llmError}>⚠ LLM</span>
          )}
          <button
            type="button"
            className={`tln-toggle-btn${showSettings ? ' active' : ''}`}
            onClick={() => setShowSettings(v => !v)}
            title="LLM decompilation settings"
            aria-pressed={showSettings}
          >
            ⚙ LLM
          </button>
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

      {/* ── LLM Settings Panel ── */}
      {showSettings && (
        <SettingsPanel
          settings={llmSettings}
          onChange={setLlmSettings}
          onClose={() => setShowSettings(false)}
          hasStoredApiKey={hasStoredApiKey}
          onSaveApiKey={handleSaveApiKey}
          onClearApiKey={handleClearApiKey}
          onTestApiKey={handleTestProvider}
          llmError={llmError}
        />
      )}

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
          {selectedFuncAddr !== null && functions.get(selectedFuncAddr) && (
            <div style={{ fontFamily: 'monospace', fontSize: '0.78rem', color: '#7a9fbf', padding: '0.35rem 0.7rem 0', userSelect: 'text' }}>
              {buildPrototypeHeader(
                functions.get(selectedFuncAddr)!,
                selectedFuncAddr,
                disassembly,
              )}
            </div>
          )}
          <TalonCodeDisplay
            lines={displayResult.lines}
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
