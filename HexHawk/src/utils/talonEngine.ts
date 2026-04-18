/**
 * TALON — Reasoning-Aware Decompilation Engine for HexHawk
 *
 * Wraps decompilerEngine with:
 *   - Intent detection  ("what is this code doing?")
 *   - Confidence scoring (per-statement certainty 0–100)
 *   - Uncertainty markers (??)
 *   - Behavioral tagging (feeds correlationEngine)
 *
 * Pipeline:
 *   decompile()           – base IR lift + structuring
 *   detectBlockIntents()  – classify each IRBlock by pattern
 *   annotateLines()       – inject intent comments + score each line
 *   buildSummary()        – aggregate behavioral tags + confidence
 */

import type { BehavioralTag } from './correlationEngine';
import {
  decompile,
  type DecompileResult,
  type PseudoLine,
  type PseudoLineKind,
  type IRBlock,
  type IRStmt,
  type IRValue,
  type CfgGraph,
  type DisassembledInstruction,
  type DecompileOptions,
} from './decompilerEngine';
import { buildSSAForm } from './ssaTransform';
import { runDataFlowPasses } from './dataFlowPasses';
import { computeNaturalLoops, type NaturalLoop } from './cfgSignalExtractor';

// ─── Intent Types ──────────────────────────────────────────────────────────────

export type IntentCategory =
  | 'control'     // branching, loops, guards
  | 'memory'      // alloc, free, copy, zero-fill, array access
  | 'security'    // anti-debug, crypto, obfuscation, syscalls
  | 'api'         // Windows API, libc
  | 'arithmetic'  // computation, transformation, bitfields
  | 'io'          // file, network, registry
  | 'unknown';

export interface TalonIntent {
  label: string;
  confidence: number;     // 0–100
  category: IntentCategory;
  address: number;
  blockId?: string;
  detail?: string;
}

export type TalonLineKind = PseudoLineKind | 'intent-comment';

export interface TalonLine extends Omit<PseudoLine, 'kind'> {
  kind: TalonLineKind;
  lineConfidence: number;  // 0–100 per-statement certainty
  intent?: TalonIntent;    // present only on 'intent-comment' lines
}

export interface TalonFunctionSummary {
  name: string;
  startAddress: number;
  overallConfidence: number;
  liftingCoverage: number;       // % of instrs with known IR ops
  intents: TalonIntent[];
  behavioralTags: BehavioralTag[];
  uncertainStatements: number;
  totalStatements: number;
  complexityScore: number;       // number of IR blocks
  warningCount: number;
  ssaVarCount: number;           // total SSA variables (0 if SSA not run)
  loopNestingDepth: number;      // maximum natural loop nesting depth
  naturalLoops: NaturalLoop[];   // detected natural loops
}

export interface TalonResult extends Omit<DecompileResult, 'lines'> {
  lines: TalonLine[];
  summary: TalonFunctionSummary;
}

// ─── Known API Pattern Sets ────────────────────────────────────────────────────

const ANTI_DEBUG_APIS = new Set([
  'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
  'NtSetInformationThread', 'OutputDebugStringA', 'OutputDebugStringW',
  'FindWindowA', 'FindWindowW', 'GetTickCount', 'QueryPerformanceCounter',
  'CreateToolhelp32Snapshot', 'Process32First', 'Process32Next',
]);

const CRYPTO_APIS = new Set([
  'CryptEncrypt', 'CryptDecrypt', 'CryptGenRandom', 'CryptHashData',
  'BCryptEncrypt', 'BCryptDecrypt', 'BCryptGenRandom', 'BCryptHashData',
  'MD5Update', 'MD5Final', 'SHA1Update', 'SHA1Final',
  'EVP_EncryptInit', 'EVP_DecryptInit', 'RC4', 'AES',
]);

const ALLOC_APIS = new Set([
  'malloc', 'calloc', 'realloc', '_malloc', '_calloc',
  'HeapAlloc', 'VirtualAlloc', 'VirtualAllocEx',
  'LocalAlloc', 'GlobalAlloc', 'CoTaskMemAlloc', 'new',
]);

const FREE_APIS = new Set([
  'free', '_free', 'HeapFree', 'VirtualFree', 'VirtualFreeEx',
  'LocalFree', 'GlobalFree', 'CoTaskMemFree', 'delete',
]);

const STRING_APIS = new Set([
  'strlen', 'strcpy', 'strncpy', 'strcat', 'strncat', 'strcmp', 'strncmp',
  'strstr', 'strchr', 'sprintf', 'snprintf', 'vsprintf', 'sscanf',
  'lstrcpyA', 'lstrcpyW', 'lstrcatA', 'lstrcatW', 'lstrlenA', 'lstrlenW',
  'lstrcmpA', 'lstrcmpW', 'wcscpy', 'wcslen', 'wcscat', 'wcscmp', 'wcsstr',
  'CharUpperA', 'CharUpperW', 'CharLowerA', 'CharLowerW',
]);

const INJECT_APIS = new Set([
  'WriteProcessMemory', 'CreateRemoteThread', 'NtCreateThreadEx',
  'RtlCreateUserThread', 'OpenProcess', 'SetWindowsHookEx',
  'VirtualAllocEx', 'NtWriteVirtualMemory', 'QueueUserAPC',
]);

const NETWORK_APIS = new Set([
  'connect', 'send', 'recv', 'sendto', 'recvfrom',
  'WSAConnect', 'WSASend', 'WSARecv', 'WSAStartup',
  'InternetOpen', 'InternetConnect', 'InternetOpenUrl', 'HttpSendRequest',
  'WinHttpOpen', 'WinHttpConnect', 'WinHttpSendRequest', 'WinHttpReadData',
  'socket', 'bind', 'listen', 'accept',
]);

const EXEC_APIS = new Set([
  'CreateProcess', 'CreateProcessA', 'CreateProcessW',
  'WinExec', 'ShellExecute', 'ShellExecuteA', 'ShellExecuteW',
  'system', 'popen', 'execv', 'execve', 'NtCreateProcess',
]);

const FILE_APIS = new Set([
  'CreateFile', 'CreateFileA', 'CreateFileW',
  'WriteFile', 'ReadFile', 'WriteFileEx', 'ReadFileEx',
  'DeleteFile', 'DeleteFileA', 'DeleteFileW',
  'CopyFile', 'MoveFile', 'MoveFileA', 'MoveFileW',
  'FindFirstFile', 'FindNextFile', 'GetFileSize', 'SetFilePointer',
  'fopen', 'fwrite', 'fread', 'fclose', 'remove',
]);

const REG_APIS = new Set([
  'RegSetValueEx', 'RegSetValueExA', 'RegSetValueExW',
  'RegCreateKey', 'RegCreateKeyEx', 'RegCreateKeyExA', 'RegCreateKeyExW',
  'RegOpenKey', 'RegOpenKeyEx', 'RegOpenKeyExA', 'RegOpenKeyExW',
  'RegDeleteKey', 'RegDeleteValue',
]);

const DYNAMIC_LOAD_APIS = new Set([
  'GetProcAddress', 'LoadLibrary', 'LoadLibraryA', 'LoadLibraryW',
  'LoadLibraryEx', 'dlopen', 'dlsym',
]);

// ─── Call Intent Classification ────────────────────────────────────────────────

interface CallIntentInfo {
  label: string;
  confidence: number;
  category: IntentCategory;
  tag?: BehavioralTag;
}

function detectCallIntent(name: string): CallIntentInfo | null {
  if (ANTI_DEBUG_APIS.has(name))   return { label: `Anti-debug: ${name}`,        confidence: 96, category: 'security', tag: 'anti-analysis' };
  if (INJECT_APIS.has(name))       return { label: `Process injection: ${name}`,  confidence: 96, category: 'security', tag: 'code-injection' };
  if (CRYPTO_APIS.has(name))       return { label: `Crypto: ${name}`,             confidence: 94, category: 'security', tag: 'data-encryption' };
  if (NETWORK_APIS.has(name))      return { label: `Network I/O: ${name}`,        confidence: 93, category: 'io',       tag: 'c2-communication' };
  if (EXEC_APIS.has(name))         return { label: `Process exec: ${name}`,       confidence: 94, category: 'io',       tag: 'process-execution' };
  if (REG_APIS.has(name))          return { label: `Registry write: ${name}`,     confidence: 91, category: 'io',       tag: 'persistence' };
  if (FILE_APIS.has(name))         return { label: `File I/O: ${name}`,           confidence: 92, category: 'io' };
  if (DYNAMIC_LOAD_APIS.has(name)) return { label: `Dynamic resolve: ${name}`,   confidence: 90, category: 'security', tag: 'dynamic-resolution' };
  if (ALLOC_APIS.has(name))        return { label: `Memory alloc: ${name}`,       confidence: 90, category: 'memory' };
  if (FREE_APIS.has(name))         return { label: `Memory free: ${name}`,        confidence: 90, category: 'memory' };
  if (STRING_APIS.has(name))       return { label: `String op: ${name}`,          confidence: 89, category: 'memory' };
  return null;
}

// ─── Block Intent Detection ────────────────────────────────────────────────────

function detectBlockIntent(
  block: IRBlock,
  instrMap: Map<number, DisassembledInstruction>
): TalonIntent | null {
  const stmts = block.stmts;

  // 1. Raw instruction patterns (anti-analysis, privileged)
  for (const stmt of stmts) {
    const ins = instrMap.get(stmt.address);
    if (!ins) continue;
    const mn = ins.mnemonic.toLowerCase().trim();

    if (mn === 'rdtsc') {
      return { label: 'RDTSC timing check (anti-debug)', confidence: 95, category: 'security', address: stmt.address, blockId: block.id };
    }
    if (mn === 'cpuid') {
      return { label: 'CPUID interrogation (VM/sandbox detect)', confidence: 91, category: 'security', address: stmt.address, blockId: block.id };
    }
    if (mn === 'int3' || (mn === 'int' && ins.operands.trim() === '3')) {
      return { label: 'INT3 breakpoint probe (anti-debug)', confidence: 93, category: 'security', address: stmt.address, blockId: block.id };
    }
    if (mn === 'sysenter' || mn === 'syscall') {
      return { label: 'Direct syscall (OS bypass)', confidence: 87, category: 'security', address: stmt.address, blockId: block.id };
    }
    if (mn.startsWith('rep') && (mn.includes('movs') || mn.includes('stos'))) {
      return {
        label: mn.includes('stos') ? 'Memory zero-fill (rep stosb/q)' : 'Memory block copy (rep movs)',
        confidence: 95, category: 'memory', address: stmt.address, blockId: block.id,
      };
    }
    if (mn === 'repne' && mn.includes('scas')) {
      return { label: 'String scan / strlen pattern (repne scasb)', confidence: 94, category: 'memory', address: stmt.address, blockId: block.id };
    }
  }

  // 2. Call-based intents
  for (const stmt of stmts) {
    if (stmt.op === 'call' && stmt.name) {
      const info = detectCallIntent(stmt.name);
      if (info) {
        return {
          label: info.label,
          confidence: info.confidence,
          category: info.category,
          address: stmt.address,
          blockId: block.id,
        };
      }
    }
  }

  const hasCjmp = stmts.some(s => s.op === 'cjmp');

  // 3. Null / zero check
  const nullCheckStmt = stmts.find(s =>
    (s.op === 'cmp' && s.right.kind === 'const' && s.right.value === 0) ||
    (s.op === 'test' && s.left.kind === 'reg' && s.right.kind === 'reg' &&
     s.left.name === s.right.name)
  );
  if (nullCheckStmt && hasCjmp) {
    return { label: 'Null / zero guard', confidence: 87, category: 'control', address: block.start, blockId: block.id };
  }

  // 4. Error / invalid handle check (cmp reg, -1 or INVALID_HANDLE_VALUE)
  const errCheckStmt = stmts.find(s =>
    s.op === 'cmp' && s.right.kind === 'const' &&
    (s.right.value === -1 || s.right.value === 0xFFFFFFFF || s.right.value === 0xFFFF ||
     s.right.value === 0xFFFFFFFFFFFFFFFF)
  );
  if (errCheckStmt && hasCjmp) {
    return { label: 'Error / INVALID_HANDLE check', confidence: 78, category: 'control', address: block.start, blockId: block.id };
  }

  // 5. Bounds check (two cmp statements)
  if (stmts.filter(s => s.op === 'cmp').length >= 2 && hasCjmp) {
    return { label: 'Bounds / range check', confidence: 74, category: 'control', address: block.start, blockId: block.id };
  }

  // 6. Bitfield / flag test (and/or with power-of-2 constants)
  for (const stmt of stmts) {
    if (stmt.op === 'binop' && (stmt.operator === '&' || stmt.operator === '|') &&
        stmt.right.kind === 'const' && stmt.right.value !== 0) {
      const v = stmt.right.value >>> 0;
      if ((v & (v - 1)) === 0 || v === 0xFF || v === 0xFFFF || v === 0xFFFFFF00) {
        return { label: 'Bitfield / flag operation', confidence: 72, category: 'arithmetic', address: stmt.address, blockId: block.id };
      }
    }
  }

  // 7. Indexed / array access (mem operand with scale > 1)
  for (const stmt of stmts) {
    const hasScaled = (v: IRValue) => v.kind === 'mem' && v.scale !== undefined && v.scale > 1;
    if (stmt.op === 'assign' && (hasScaled(stmt.dest) || hasScaled(stmt.src))) {
      return { label: 'Array / indexed access', confidence: 70, category: 'memory', address: stmt.address, blockId: block.id };
    }
  }

  return null;
}

// ─── Control Line Intent (from text analysis) ─────────────────────────────────

function analyzeControlLine(text: string, address: number): TalonIntent | null {
  // if (cond) { or while (cond) {
  const isIf    = text.trimStart().startsWith('if (');
  const isWhile = text.trimStart().startsWith('while (');
  if (!isIf && !isWhile) return null;

  const condMatch = text.match(/(?:if|while)\s*\((.+)\)\s*\{/);
  const cond = condMatch?.[1] ?? '';

  if (isWhile) {
    if (/[<>]=?\s*/.test(cond) && !/==/.test(cond)) {
      return { label: 'Counting / bounded loop', confidence: 82, category: 'control', address };
    }
    if (/!=\s*0|== 0/.test(cond)) {
      return { label: 'Sentinel / null-terminated loop', confidence: 77, category: 'control', address };
    }
    if (/!=/.test(cond)) {
      return { label: 'Loop until condition met', confidence: 73, category: 'control', address };
    }
    return { label: 'Loop', confidence: 68, category: 'control', address };
  }

  // if-branch patterns
  if (cond.includes('== 0') || cond.includes('=== 0')) {
    return { label: 'Null / zero guard', confidence: 85, category: 'control', address };
  }
  if (cond.includes('!= 0') || cond.includes('!== 0')) {
    return { label: 'Non-null / non-zero branch', confidence: 83, category: 'control', address };
  }
  if (/== -?1|== 0xff/.test(cond.toLowerCase())) {
    return { label: 'Error / failure check', confidence: 79, category: 'control', address };
  }
  if (cond.includes('overflow') || cond.includes('parity')) {
    return { label: 'Overflow / flags check', confidence: 74, category: 'arithmetic', address };
  }
  return null;
}

// ─── Statement Confidence ──────────────────────────────────────────────────────

function computeStmtConfidence(stmt: IRStmt): number {
  switch (stmt.op) {
    case 'assign':   return 88;
    case 'binop':    return 85;
    case 'uop':      return 82;
    case 'cjmp':     return stmt.cond.includes('?') ? 52 : 80;
    case 'jmp':      return stmt.target !== null ? 74 : 48;
    case 'call':     return stmt.name ? 92 : (stmt.target !== null ? 76 : 54);
    case 'ret':      return 95;
    case 'push':     return 60;
    case 'pop':      return 61;
    case 'cmp':
    case 'test':     return 88;
    case 'prologue':
    case 'epilogue': return 95;
    case 'nop':      return 99;
    case 'unknown':  return 35;
    default:         return 70;
  }
}

// ─── Address → Block Map ───────────────────────────────────────────────────────

function buildAddrToBlock(irBlocks: IRBlock[]): Map<number, string> {
  const map = new Map<number, string>();
  for (const block of irBlocks) {
    for (const stmt of block.stmts) {
      map.set(stmt.address, block.id);
    }
  }
  return map;
}

function buildAddrToStmt(irBlocks: IRBlock[]): Map<number, IRStmt> {
  const map = new Map<number, IRStmt>();
  for (const block of irBlocks) {
    for (const stmt of block.stmts) {
      map.set(stmt.address, stmt);
    }
  }
  return map;
}

// ─── Line Annotation ───────────────────────────────────────────────────────────

function annotateLines(
  lines: PseudoLine[],
  irBlocks: IRBlock[],
  blockIntentMap: Map<string, TalonIntent>,
  instrMap: Map<number, DisassembledInstruction>
): TalonLine[] {
  const addrToBlock = buildAddrToBlock(irBlocks);
  const addrToStmt = buildAddrToStmt(irBlocks);
  // Supress duplicate intents: track which intent labels we've already emitted
  const emittedIntents = new Set<string>();

  const result: TalonLine[] = [];

  for (const line of lines) {
    // ── Intent injection for control flow lines ──────────────────────────────
    if (line.kind === 'control' && line.address !== undefined) {
      let intent: TalonIntent | null = null;

      // Priority 1: block-level structural intent (known API, raw asm pattern)
      const blockId = addrToBlock.get(line.address);
      if (blockId) {
        intent = blockIntentMap.get(blockId) ?? null;
      }

      // Priority 2: control line text analysis (if/while condition)
      if (!intent) {
        intent = analyzeControlLine(line.text, line.address);
      }

      if (intent) {
        const key = `${intent.label}:${line.indent}`;
        if (!emittedIntents.has(key)) {
          emittedIntents.add(key);
          const pct = `${intent.confidence}%`;
          const sigil = intent.category === 'security' ? '⚠ ' : '';
          result.push({
            indent: line.indent,
            text: `// ── ${sigil}${intent.label} (${pct}) ──`,
            kind: 'intent-comment',
            lineConfidence: intent.confidence,
            intent,
          });
        }
      }
    }

    // ── Per-line confidence ───────────────────────────────────────────────────
    let lineConfidence = 90;
    if (line.address !== undefined) {
      const stmt = addrToStmt.get(line.address);
      if (stmt) lineConfidence = computeStmtConfidence(stmt);
    }
    if (line.kind === 'comment' || line.kind === 'brace' || line.kind === 'blank' || line.kind === 'header') {
      lineConfidence = 100;
    }
    if (line.isUncertain) {
      lineConfidence = Math.min(lineConfidence, 52);
    }

    // ── Uncertainty marker ────────────────────────────────────────────────────
    let { text } = line;
    if (line.isUncertain && !text.trim().startsWith('//') && !text.endsWith('// ??')) {
      text = `${text}  // ??`;
    }

    result.push({
      ...line,
      text,
      kind: line.kind as TalonLineKind,
      lineConfidence,
    });

    // ── Inline call annotation (stmt lines that are calls) ────────────────────
    if (line.kind === 'stmt' && line.address !== undefined) {
      const stmt = addrToStmt.get(line.address);
      if (stmt && stmt.op === 'call' && stmt.name) {
        const info = detectCallIntent(stmt.name);
        if (info && !emittedIntents.has(`call:${stmt.name}`)) {
          emittedIntents.add(`call:${stmt.name}`);
          const sigil = info.category === 'security' ? '⚠ ' : '';
          result.push({
            indent: line.indent,
            text: `// ← ${sigil}${info.label} (${info.confidence}%)`,
            kind: 'intent-comment',
            lineConfidence: info.confidence,
            intent: {
              label: info.label,
              confidence: info.confidence,
              category: info.category,
              address: stmt.address,
            },
          });
        }
      }
    }
  }

  return result;
}

// ─── Function Summary ──────────────────────────────────────────────────────────

function buildFunctionSummary(
  result: DecompileResult,
  talonLines: TalonLine[],
  blockIntentMap: Map<string, TalonIntent>,
): TalonFunctionSummary {
  const allIntents = [...blockIntentMap.values()];

  const totalStmts = talonLines.filter(l => l.kind === 'stmt' || l.kind === 'uncertain').length;
  const uncertainStmts = talonLines.filter(l => l.lineConfidence < 58).length;

  // Lifting coverage: fraction of IR stmts that are NOT 'unknown'
  const allIRStmts = result.irBlocks.flatMap(b => b.stmts);
  const unknownCount = allIRStmts.filter(s => s.op === 'unknown').length;
  const liftingCoverage = allIRStmts.length > 0
    ? Math.round(100 * (1 - unknownCount / allIRStmts.length))
    : 100;

  // Overall confidence = weighted avg of line confidences
  const stmtConfs = talonLines
    .filter(l => l.kind !== 'comment' && l.kind !== 'intent-comment' && l.kind !== 'blank' && l.kind !== 'brace' && l.kind !== 'header')
    .map(l => l.lineConfidence);
  const avgLineConf = stmtConfs.length > 0
    ? Math.round(stmtConfs.reduce((a, b) => a + b, 0) / stmtConfs.length)
    : 75;
  const overallConfidence = Math.round(0.35 * liftingCoverage + 0.65 * avgLineConf);

  // Collect behavioral tags from intents
  const tagSet = new Set<BehavioralTag>();
  for (const intent of allIntents) {
    const lbl = intent.label.toLowerCase();
    if (lbl.includes('anti-debug') || lbl.includes('rdtsc') || lbl.includes('cpuid') || lbl.includes('int3')) {
      tagSet.add('anti-analysis');
    }
    if (lbl.includes('crypto') || lbl.includes('encrypt') || lbl.includes('bcrypt') || lbl.includes('crypt')) {
      tagSet.add('data-encryption');
    }
    if (lbl.includes('decrypt') || lbl.includes('unpack')) {
      tagSet.add('code-decryption');
    }
    if (lbl.includes('inject') || lbl.includes('writepro') || lbl.includes('remote')) {
      tagSet.add('code-injection');
    }
    if (lbl.includes('network') || lbl.includes('connect') || lbl.includes('send') || lbl.includes('recv') || lbl.includes('winhttp') || lbl.includes('internet')) {
      tagSet.add('c2-communication');
    }
    if (lbl.includes('process exec') || lbl.includes('createprocess') || lbl.includes('shellexecute') || lbl.includes('winexec')) {
      tagSet.add('process-execution');
    }
    if (lbl.includes('registry')) {
      tagSet.add('persistence');
    }
    if (lbl.includes('dynamic resolve') || lbl.includes('getprocaddress') || lbl.includes('loadlibrary')) {
      tagSet.add('dynamic-resolution');
    }
    if (lbl.includes('file i/o')) {
      tagSet.add('data-exfiltration');
    }
  }

  return {
    name: result.functionName,
    startAddress: result.startAddress,
    overallConfidence,
    liftingCoverage,
    intents: allIntents,
    behavioralTags: [...tagSet],
    uncertainStatements: uncertainStmts,
    totalStatements: totalStmts,
    complexityScore: result.irBlocks.length,
    warningCount: result.warnings.length,
    ssaVarCount: 0,
    loopNestingDepth: 0,
    naturalLoops: [],
  };
}

// ─── Public API ────────────────────────────────────────────────────────────────

export function talonDecompile(
  instructions: DisassembledInstruction[],
  cfg: CfgGraph | null,
  options: DecompileOptions = {}
): TalonResult {
  // Phase 1: base decompile (IR lift + variable abstraction + structuring + emit)
  const base = decompile(instructions, cfg, options);

  // Phase 1.5: SSA construction + data-flow passes
  const ssaForm = buildSSAForm(base.irBlocks);
  const dataFlow = runDataFlowPasses(base.irBlocks, ssaForm);
  // Compute natural loops from CFG (if available)
  const naturalLoops = cfg ? computeNaturalLoops(cfg) : [];
  const loopNestingDepth = naturalLoops.reduce((max, l) => Math.max(max, l.depth), 0);

  // Build fast-lookup maps
  const instrMap = new Map<number, DisassembledInstruction>();
  for (const ins of instructions) instrMap.set(ins.address, ins);

  // Phase 2: intent detection per IRBlock
  const blockIntentMap = new Map<string, TalonIntent>();
  for (const block of base.irBlocks) {
    const intent = detectBlockIntent(block, instrMap);
    if (intent) blockIntentMap.set(block.id, intent);
  }

  // Phase 3: annotate lines (inject intent comments, add confidence, add ?? marks)
  const talonLines = annotateLines(base.lines, base.irBlocks, blockIntentMap, instrMap);

  // Phase 4: function summary
  const summary = buildFunctionSummary(base, talonLines, blockIntentMap);

  // Enrich summary with SSA + loop metrics
  summary.ssaVarCount = ssaForm.varCount;
  summary.loopNestingDepth = loopNestingDepth;
  summary.naturalLoops = naturalLoops;

  // Attach data-flow env to result for downstream consumers
  void dataFlow; // currently used implicitly; future: pass to annotateLines

  return { ...base, lines: talonLines, summary };
}

// ─── Correlation Bridge ────────────────────────────────────────────────────────

export interface TalonCorrelationSignal {
  hasAntiDebug: boolean;
  hasCrypto: boolean;
  hasNetworkOps: boolean;
  hasInjection: boolean;
  hasExec: boolean;
  hasPersistence: boolean;
  hasDynamicResolution: boolean;
  overallConfidence: number;
  uncertainRatio: number;  // 0–1
  functionCount: number;
}

export function extractCorrelationSignals(
  summaries: TalonFunctionSummary[]
): TalonCorrelationSignal {
  const tags = new Set<BehavioralTag>(summaries.flatMap(s => s.behavioralTags));

  const totalStmts = summaries.reduce((a, s) => a + s.totalStatements, 0);
  const uncertainStmts = summaries.reduce((a, s) => a + s.uncertainStatements, 0);
  const uncertainRatio = totalStmts > 0 ? uncertainStmts / totalStmts : 0;

  const avgConfidence = summaries.length > 0
    ? Math.round(summaries.reduce((a, s) => a + s.overallConfidence, 0) / summaries.length)
    : 0;

  return {
    hasAntiDebug:          tags.has('anti-analysis'),
    hasCrypto:             tags.has('data-encryption') || tags.has('code-decryption'),
    hasNetworkOps:         tags.has('c2-communication'),
    hasInjection:          tags.has('code-injection'),
    hasExec:               tags.has('process-execution'),
    hasPersistence:        tags.has('persistence'),
    hasDynamicResolution:  tags.has('dynamic-resolution'),
    overallConfidence:     avgConfidence,
    uncertainRatio,
    functionCount:         summaries.length,
  };
}
