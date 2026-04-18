/**
 * CorrelationEngine — Multi-Signal Binary Intelligence
 *
 * Correlates three previously separate signal classes into unified reasoning:
 *   - Structural signals  (section entropy, section names)
 *   - Import signals      (dangerous API usage, library fingerprint)
 *   - String signals      (URLs, IPs, base64, registry keys, file paths)
 *   - Disassembly signals (suspicious patterns, anti-analysis, loops)
 *   - Signature signals   (known-pattern matches from signatureEngine)
 *
 * Produces a BinaryVerdictResult that answers:
 *   1. "What IS this binary?"      (classification)
 *   2. "How sure are you?"         (confidence + corroboration)
 *   3. "Why?"                      (correlated evidence chain)
 *   4. "What should I do next?"    (ranked workflow steps)
 */

import type { SuspiciousPattern } from '../App';
import type { SignatureMatch } from './signatureEngine';
import type { TalonCorrelationSignal } from './talonEngine';
import type { StrikeCorrelationSignal } from './strikeEngine';
import type { EchoCorrelationSignal } from './echoEngine';

// ─── Public Types ─────────────────────────────────────────────────────────────

export type BinaryClassification =
  | 'clean'
  | 'suspicious'
  | 'packer'
  | 'dropper'
  | 'ransomware-like'
  | 'info-stealer'
  | 'rat'         // Remote access trojan
  | 'loader'
  | 'likely-malware'
  | 'unknown';

export type SignalSource = 'structure' | 'imports' | 'strings' | 'disassembly' | 'signatures';

export interface CorrelatedSignal {
  source: SignalSource;
  id: string;           // short unique key
  finding: string;      // human-readable description
  weight: number;       // 0–10 contribution to threat score
  corroboratedBy: string[];  // ids of other signals that strengthen this one
}

export interface WorkflowStep {
  priority: 'critical' | 'high' | 'medium' | 'low';
  action: string;       // "Unpack the binary with UPX"
  rationale: string;    // "High entropy in .text means packed code"
  tab?: 'hex' | 'strings' | 'disassembly' | 'cfg' | 'metadata' | 'plugins';
}

export interface BinaryVerdictResult {
  classification: BinaryClassification;
  threatScore: number;    // 0–100 composite
  confidence: number;     // 0–100
  signals: CorrelatedSignal[];
  negativeSignals: NegativeSignal[];
  amplifiers: string[];
  dismissals: string[];
  summary: string;
  explainability: ExplainabilityEntry[];
  nextSteps: WorkflowStep[];
  signalCount: number;
  // ── New stage-reasoning fields ────────────────────────────────────────────
  behaviors: BehavioralTag[];           // inferred behavioral capabilities
  reasoningChain: ReasoningStage[];     // stage-by-stage reasoning breakdown
  contradictions: Contradiction[];      // conflicting evidence pairs
  alternatives: AlternativeHypothesis[];// alternative interpretations
}

export interface NegativeSignal {
  id: string;
  finding: string;
  reduction: number;  // points subtracted from raw threat score
}

export interface ExplainabilityEntry {
  factor: string;
  contribution: 'increases' | 'decreases' | 'neutral';
  detail: string;
}

// ─── Stage Reasoning ─────────────────────────────────────────────────────────

export type BehavioralTag =
  | 'code-injection'      // injects code into another process
  | 'c2-communication'    // communicates with remote server
  | 'persistence'         // installs itself or a dropper for auto-start
  | 'anti-analysis'       // hinders reverse engineering
  | 'data-exfiltration'   // sends data outside
  | 'file-destruction'    // deletes or overwrites files (ransomware / wiper)
  | 'credential-theft'    // accesses stored credentials / auth tokens
  | 'code-decryption'     // decrypts/unpacks its own code at runtime
  | 'dynamic-resolution'  // resolves APIs at runtime (hidden capabilities)
  | 'process-execution'   // spawns child processes
  | 'data-encryption'     // encrypts user data
  | 'self-contained';     // no external communications / benign indicators

export interface ReasoningStage {
  stage: 1 | 2 | 3;
  name: string;
  findings: string[];
  conclusion: string;
  confidence: number;   // 0–100
}

export interface Contradiction {
  id: string;
  observation: string;    // what signal was found
  conflict: string;       // what signal is MISSING or contradicts it
  resolution: string;     // how to interpret the contradiction
  severity: 'high' | 'medium' | 'low';
}

export interface AlternativeHypothesis {
  classification: BinaryClassification;
  label: string;
  probability: number;    // 0–100 estimated likelihood
  reasoning: string;
  requiredEvidence: string[];  // "Would be confirmed by X"
}

// ─── Input Shape ──────────────────────────────────────────────────────────────

export interface CorrelationInput {
  sections: Array<{
    name: string;
    entropy: number;
    file_size: number;
  }>;
  imports: Array<{ name: string; library: string }>;
  strings: Array<{ text: string }>;
  patterns: SuspiciousPattern[];
  /** Optional: from signatureEngine.scanSignatures() */
  signatureMatches?: SignatureMatch[];
  /** Optional: from talonEngine.extractCorrelationSignals() */
  talonSignals?: TalonCorrelationSignal;
  /** Optional: from strikeEngine.extractCorrelationSignals() */
  strikeSignals?: StrikeCorrelationSignal;
  /** Optional: from echoEngine.extractCorrelationSignals() */
  echoSignals?: EchoCorrelationSignal;
  /**
   * Zero-based index of the current iteration in the NEST session.
   * When provided, the confidence score is dampened on early iterations to
   * reflect that high first-pass confidence comes from signal diversity
   * (many import families hit at once), not from multi-pass validated evidence.
   * Omit (or undefined) to skip dampening — used by standalone / UI calls.
   */
  iterationIndex?: number;
}

// ─── Dangerous Import Sets ────────────────────────────────────────────────────

/**
 * TRUE process-injection APIs: only APIs that write into or execute code inside
 * a DIFFERENT process. Current-process memory allocation (VirtualAlloc) and
 * process-handle queries (OpenProcess) are intentionally excluded:
 *   - VirtualAlloc allocates in the CURRENT process → standard C/C++ runtime
 *     behavior; removing it prevents false positives on every compiled binary.
 *   - OpenProcess alone only opens a handle; it is used by task managers,
 *     crash reporters, performance monitoring, and session management tools.
 *     It becomes relevant only when combined with WriteProcessMemory/VirtualAllocEx.
 */
const INJECTION_IMPORTS = new Set([
  'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
  'NtCreateThreadEx', 'SetWindowsHookEx',
]);

const NETWORK_IMPORTS = new Set([
  'InternetOpen', 'InternetConnect', 'HttpSendRequest', 'URLDownloadToFile',
  'WSAStartup', 'connect', 'send', 'recv', 'WinHttpOpen', 'WinHttpConnect',
]);

const CRYPTO_IMPORTS = new Set([
  'CryptEncrypt', 'CryptDecrypt', 'CryptGenRandom', 'BCryptEncrypt', 'BCryptDecrypt',
]);

const FILE_IMPORTS = new Set([
  'CreateFile', 'CreateFileA', 'CreateFileW', 'WriteFile', 'DeleteFile',
  'FindFirstFile', 'MoveFile', 'CopyFile',
]);

/**
 * Truly evasive anti-debug APIs — used almost exclusively by malware or
 * heavy DRM to detect and react to analysis environments. Presence of these
 * BLOCKS the Win32 standard-application profile detection.
 */
const EVASIVE_ANTI_DEBUG_IMPORTS = new Set([
  'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess', 'NtSetInformationThread',
]);

/**
 * CRT/SDK debug-check APIs that are present in virtually every compiled
 * Windows application (via the CRT init, OutputDebugString logging, etc.).
 * These still generate a mild signal but do NOT indicate evasive intent and
 * must NOT block the Win32 standard-application profile.
 */
const CRT_DEBUG_CHECK_IMPORTS = new Set([
  'IsDebuggerPresent', 'OutputDebugString', 'OutputDebugStringA', 'OutputDebugStringW',
]);

/** Full anti-debug set (evasive + CRT-level) for the import signal */
const ANTI_DEBUG_IMPORTS = new Set([
  ...EVASIVE_ANTI_DEBUG_IMPORTS,
  ...CRT_DEBUG_CHECK_IMPORTS,
]);

const EXEC_IMPORTS = new Set([
  'ShellExecute', 'ShellExecuteA', 'ShellExecuteW', 'CreateProcess',
  'CreateProcessA', 'CreateProcessW', 'WinExec', 'system',
]);

const DYNAMIC_LOAD_IMPORTS = new Set([
  'GetProcAddress', 'LoadLibrary', 'LoadLibraryA', 'LoadLibraryW',
]);

const REGISTRY_IMPORTS = new Set([
  'RegSetValueEx', 'RegSetValueExA', 'RegSetValueExW', 'RegCreateKey',
  'RegCreateKeyEx', 'RegOpenKey', 'RegOpenKeyEx',
]);

/** Shell/file-picker APIs — normal in any file-handling desktop app */
const SHELL_BROWSE_IMPORTS = new Set([
  'SHBrowseForFolderA', 'SHBrowseForFolderW', 'SHGetPathFromIDListA', 'SHGetPathFromIDListW',
  'SHGetFolderPathA', 'SHGetFolderPathW', 'SHGetSpecialFolderPathA', 'SHGetSpecialFolderPathW',
  'DragAcceptFiles', 'DragQueryFileA', 'DragQueryFileW', 'Shell_NotifyIconA', 'Shell_NotifyIconW',
]);

/** Common dialog (open/save/print/color/font) APIs */
const COMMON_DIALOG_IMPORTS = new Set([
  'GetOpenFileNameA', 'GetOpenFileNameW', 'GetSaveFileNameA', 'GetSaveFileNameW',
  'ChooseColorA', 'ChooseColorW', 'ChooseFontA', 'ChooseFontW',
  'PrintDlgA', 'PrintDlgW', 'PageSetupDlgA', 'PageSetupDlgW',
]);

/** Print GDI APIs */
const PRINT_IMPORTS = new Set([
  'StartDocA', 'StartDocW', 'EndDoc', 'StartPage', 'EndPage',
  'CreateDCA', 'CreateDCW', 'AbortDoc', 'EnumPrinters',
]);

/** COM initialisation and basic factory APIs */
const COM_INIT_IMPORTS = new Set([
  'CoInitialize', 'CoInitializeEx', 'CoUninitialize',
  'CoCreateInstance', 'CoGetClassObject', 'OleInitialize', 'OleUninitialize',
]);

// ─── Benign / negative indicator sets ────────────────────────────────────────

/** Imports that suggest a well-formed, non-malicious binary */
const GUI_IMPORTS = new Set([
  'MessageBoxA', 'MessageBoxW', 'DialogBoxParamA', 'DialogBoxParamW',
  'InitCommonControls', 'CreateWindowExA', 'CreateWindowExW',
  'DefWindowProcA', 'DefWindowProcW',
]);

const DEBUG_SYMBOL_IMPORTS = new Set([
  'SymInitialize', 'StackWalk64', 'MiniDumpWriteDump',
  'DbgHelp', 'SymFromAddr',
]);

// ─── Core Compute ─────────────────────────────────────────────────────────────

export function computeVerdict(input: CorrelationInput): BinaryVerdictResult {
  const signals: CorrelatedSignal[] = [];
  const negativeSignals: NegativeSignal[] = [];
  const explainability: ExplainabilityEntry[] = [];

  // ── 1. Structural signals ──────────────────────────────────────────────────
  // Resource sections (.rsrc, .reloc, .edata) legitimately contain compressed
  // image data, icons, manifest XML, and relocation tables — all with naturally
  // high entropy. Including them in the high-entropy count produces false positives
  // on virtually every icon-bearing Windows application. Only count code and data
  // sections (.text, .data, .rdata, .bss, unnamed sections) for this signal.
  const RESOURCE_SECTIONS = new Set(['.rsrc', '.reloc', '.edata', '.idata', '.tls', '.sxdata']);
  const entropyRelevantSections = input.sections.filter(s =>
    !RESOURCE_SECTIONS.has((s.name ?? '').toLowerCase())
  );
  const highEntropyCount = entropyRelevantSections.filter(s => s.entropy >= 7.0).length;
  const suspiciousEntropyCount = entropyRelevantSections.filter(s => s.entropy >= 6.0 && s.entropy < 7.0).length;
  const textSection = input.sections.find(s => s.name === '.text' || s.name === 'text');
  const dataSection = input.sections.find(s => s.name === '.data' || s.name === 'data');

  if (highEntropyCount > 0) {
    signals.push({
      source: 'structure',
      id: 'high-entropy',
      finding: `${highEntropyCount} section(s) with entropy ≥ 7.0 (likely packed or encrypted)`,
      weight: highEntropyCount >= 2 ? 8 : 6,
      corroboratedBy: [],
    });
  } else if (suspiciousEntropyCount > 0) {
    signals.push({
      source: 'structure',
      id: 'elevated-entropy',
      finding: `${suspiciousEntropyCount} section(s) with elevated entropy (6–7)`,
      weight: 3,
      corroboratedBy: [],
    });
  }

  if (textSection && textSection.entropy >= 7.0) {
    signals.push({
      source: 'structure',
      id: 'packed-text',
      finding: '.text section entropy ≥ 7.0 — executable code is packed or self-modifying',
      weight: 9,
      corroboratedBy: [],
    });
  }

  if (dataSection && dataSection.entropy >= 6.5) {
    signals.push({
      source: 'structure',
      id: 'encrypted-data',
      finding: '.data section has high entropy — possibly encrypted payload or config',
      weight: 5,
      corroboratedBy: [],
    });
  }

  // Section count anomaly (very few sections = hand-crafted / packed)
  if (input.sections.length > 0 && input.sections.length <= 2 &&
      input.sections.every(s => s.entropy >= 6.0)) {
    signals.push({
      source: 'structure',
      id: 'minimal-sections',
      finding: 'Only 1–2 sections, all high entropy — hallmark of packers or hand-crafted PE',
      weight: 7,
      corroboratedBy: [],
    });
  }

  // ── 2. Import signals ──────────────────────────────────────────────────────
  const importNames = new Set(input.imports.map(i => i.name));

  const injectionCount      = countInSet(importNames, INJECTION_IMPORTS);
  const networkCount        = countInSet(importNames, NETWORK_IMPORTS);
  const cryptoCount         = countInSet(importNames, CRYPTO_IMPORTS);
  const fileCount           = countInSet(importNames, FILE_IMPORTS);
  const antiDebugCount      = countInSet(importNames, ANTI_DEBUG_IMPORTS);
  // Evasive-only count: does NOT include CRT-level IsDebuggerPresent.
  // Used for win32StandardApp gating and the persistence amplifier.
  const evasiveAntiDebugCount = countInSet(importNames, EVASIVE_ANTI_DEBUG_IMPORTS);
  const execCount           = countInSet(importNames, EXEC_IMPORTS);
  const dynLoadCount        = countInSet(importNames, DYNAMIC_LOAD_IMPORTS);
  const registryCount       = countInSet(importNames, REGISTRY_IMPORTS);

  if (injectionCount > 0) {
    signals.push({
      source: 'imports',
      id: 'injection-imports',
      finding: `${injectionCount} process-injection API(s): ${matchingNames(importNames, INJECTION_IMPORTS).join(', ')}`,
      weight: 3 + injectionCount * 2,
      corroboratedBy: [],
    });
  }

  if (networkCount > 0) {
    signals.push({
      source: 'imports',
      id: 'network-imports',
      finding: `${networkCount} network API(s): ${matchingNames(importNames, NETWORK_IMPORTS).join(', ')}`,
      weight: 2 + networkCount,
      corroboratedBy: [],
    });
  }

  if (cryptoCount > 0) {
    signals.push({
      source: 'imports',
      id: 'crypto-imports',
      finding: `${cryptoCount} cryptography API(s): ${matchingNames(importNames, CRYPTO_IMPORTS).join(', ')}`,
      weight: 4 + cryptoCount,
      corroboratedBy: [],
    });
  }

  if (fileCount > 0) {
    signals.push({
      source: 'imports',
      id: 'file-imports',
      finding: `${fileCount} file-system API(s): ${matchingNames(importNames, FILE_IMPORTS).join(', ')}`,
      weight: 1 + fileCount,
      corroboratedBy: [],
    });
  }

  if (antiDebugCount > 0) {
    // CRT-level APIs (IsDebuggerPresent, OutputDebugString*) are present in virtually
    // every compiled Windows binary via the CRT startup sequence and debug logging.
    // Assign them a mild weight (2) rather than the full anti-debug weight, and only
    // apply the elevated threat weight when evasive kernel-level APIs are also present
    // (CheckRemoteDebuggerPresent, NtQueryInformationProcess, NtSetInformationThread).
    const signalWeight = evasiveAntiDebugCount > 0 ? 5 + antiDebugCount * 2 : 2;
    signals.push({
      source: 'imports',
      id: 'antidebug-imports',
      finding: `${antiDebugCount} anti-debugging API(s): ${matchingNames(importNames, ANTI_DEBUG_IMPORTS).join(', ')}`,
      weight: signalWeight,
      corroboratedBy: [],
    });
  }

  if (execCount > 0) {
    signals.push({
      source: 'imports',
      id: 'exec-imports',
      finding: `${execCount} process-execution API(s): ${matchingNames(importNames, EXEC_IMPORTS).join(', ')}`,
      weight: 2 + execCount,
      corroboratedBy: [],
    });
  }

  if (dynLoadCount > 0) {
    signals.push({
      source: 'imports',
      id: 'dynload-imports',
      finding: `Dynamic API resolution (${matchingNames(importNames, DYNAMIC_LOAD_IMPORTS).join(', ')}) — hides true capabilities`,
      weight: 4 + dynLoadCount,
      corroboratedBy: [],
    });
  }

  if (registryCount > 0) {
    signals.push({
      source: 'imports',
      id: 'registry-imports',
      finding: `${registryCount} registry modification API(s)`,
      weight: 2 + registryCount,
      corroboratedBy: [],
    });
  }

  // Very few imports with high entropy = packer
  if (input.imports.length > 0 && input.imports.length <= 5 && highEntropyCount > 0) {
    signals.push({
      source: 'imports',
      id: 'minimal-imports',
      finding: `Only ${input.imports.length} import(s) with high entropy — packer stub pattern`,
      weight: 6,
      corroboratedBy: ['high-entropy'],
    });
  }

  // ── 3. String signals ──────────────────────────────────────────────────────
  const texts = input.strings.map(s => s.text);

  const urls      = texts.filter(t => /^(https?|ftp|ftps|sftp|ws|wss):\/\/\S+/i.test(t));
  const ips       = texts.filter(t => /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/.test(t)
                      || /^\[?[0-9a-fA-F:]+\]?(:\d+)?$/.test(t));  // IPv4 + IPv6
  const regPaths  = texts.filter(t => /^HKEY_(LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT)/i.test(t));
  const b64Strs   = texts.filter(t => /^[A-Za-z0-9+/]{20,}={0,2}$/.test(t) && t.length % 4 === 0);
  const peNames   = texts.filter(t => /\.(exe|dll|sys|bat|cmd|ps1|vbs)$/i.test(t));
  const domains   = texts.filter(t => /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(t) && t.includes('.') && !urls.includes(t));

  if (urls.length > 0) {
    signals.push({
      source: 'strings',
      id: 'embedded-urls',
      finding: `${urls.length} embedded URL(s): ${urls.slice(0, 2).join(', ')}${urls.length > 2 ? '…' : ''}`,
      weight: 3 + Math.min(urls.length, 4),
      corroboratedBy: [],
    });
  }

  if (ips.length > 0) {
    signals.push({
      source: 'strings',
      id: 'hardcoded-ips',
      finding: `${ips.length} hardcoded IP address(es): ${ips.slice(0, 3).join(', ')}`,
      weight: 5 + ips.length,
      corroboratedBy: [],
    });
  }

  if (regPaths.length > 0) {
    signals.push({
      source: 'strings',
      id: 'registry-strings',
      finding: `${regPaths.length} registry path string(s) — potential persistence mechanism`,
      weight: 4 + regPaths.length,
      corroboratedBy: [],
    });
  }

  if (b64Strs.length >= 2) {
    signals.push({
      source: 'strings',
      id: 'base64-strings',
      finding: `${b64Strs.length} likely base64 strings — may encode payload or C2 config`,
      weight: 3 + Math.min(b64Strs.length, 4),
      corroboratedBy: [],
    });
  }

  if (peNames.length > 0) {
    signals.push({
      source: 'strings',
      id: 'pe-names',
      finding: `${peNames.length} embedded executable name(s): ${peNames.slice(0, 3).join(', ')}`,
      weight: 3 + Math.min(peNames.length, 3),
      corroboratedBy: [],
    });
  }

  if (domains.length > 0) {
    signals.push({
      source: 'strings',
      id: 'embedded-domains',
      finding: `${domains.length} embedded domain(s)`,
      weight: 2 + Math.min(domains.length, 4),
      corroboratedBy: [],
    });
  }

  // ── 4. Disassembly signals ─────────────────────────────────────────────────
  const criticalPatterns = input.patterns.filter(p => p.severity === 'critical');
  // Anti-analysis patterns: ONLY those with specific obfuscation-technique
  // descriptions in DISASSEMBLY patterns (not structure/import signals).
  // Critical-severity patterns are handled separately by criticalPatterns above
  // and MUST NOT be double-counted here.
  // CFG-generated unreachable-block descriptions mention "anti-analysis trampoline"
  // as a speculative note — excluded to prevent false positives on system binaries
  // where compilers routinely emit dead/unreachable code.
  // Generic indirect_call CFG patterns (vtable dispatch, COM calls, callbacks)
  // are excluded — they are normal in any compiled x64 Windows binary.
  const antiAnalysisPatterns = input.patterns.filter(p =>
    p.severity !== 'critical' &&   // already counted above — no double-counting
    (p.description && /obfuscated.dispatch|anti.debug.check|anti.vm.detect|self.modif/i.test(p.description))
  );
  const tightLoops       = input.patterns.filter(p => p.type === 'tight_loop');
  const indirectCalls    = input.patterns.filter(p => p.type === 'indirect_call');

  if (criticalPatterns.length > 0) {
    signals.push({
      source: 'disassembly',
      id: 'critical-patterns',
      finding: `${criticalPatterns.length} critical-severity disassembly pattern(s)`,
      weight: 5 + criticalPatterns.length * 2,
      corroboratedBy: [],
    });
  }

  if (antiAnalysisPatterns.length > 0) {
    signals.push({
      source: 'disassembly',
      id: 'anti-analysis-patterns',
      finding: `${antiAnalysisPatterns.length} anti-analysis / indirect-call pattern(s)`,
      weight: 4 + antiAnalysisPatterns.length,
      corroboratedBy: [],
    });
  }

  if (tightLoops.length >= 3) {
    signals.push({
      source: 'disassembly',
      id: 'tight-loops',
      finding: `${tightLoops.length} tight loops — potential encryption or data transformation`,
      weight: 3,
      corroboratedBy: [],
    });
  }

  if (indirectCalls.length >= 2) {
    signals.push({
      source: 'disassembly',
      id: 'indirect-calls',
      finding: `${indirectCalls.length} indirect calls — hides control flow`,
      weight: 3,
      corroboratedBy: [],
    });
  }

  // ── 5. Cross-signal corroboration ─────────────────────────────────────────
  const amplifiers: string[] = [];
  const dismissals: string[] = [];

  // High entropy + dangerous imports = strong malware signal
  const hasHighEntropy = signals.some(s => s.id === 'high-entropy' || s.id === 'packed-text');
  const hasDangerousImports = signals.some(s => s.source === 'imports' && s.weight >= 5);
  const hasNetworkSignal = signals.some(s => s.id === 'network-imports' || s.id === 'embedded-urls' || s.id === 'hardcoded-ips');
  const hasCryptoSignal = signals.some(s => s.id === 'crypto-imports');
  const hasInjectionSignal = signals.some(s => s.id === 'injection-imports');
  const hasFileSignal = signals.some(s => s.id === 'file-imports');
  const hasRegistrySignal = signals.some(s => s.id === 'registry-imports' || s.id === 'registry-strings');

  if (hasHighEntropy && hasDangerousImports) {
    amplifiers.push('High entropy + dangerous imports: packing is being used to conceal malicious capabilities');
    bumpWeights(signals, ['high-entropy', 'packed-text', 'injection-imports', 'antidebug-imports', 'dynload-imports'], 2);
  }

  if (hasNetworkSignal && hasInjectionSignal) {
    amplifiers.push('Network access + process injection: strong C2 dropper / RAT pattern');
    bumpWeights(signals, ['network-imports', 'injection-imports', 'embedded-urls', 'hardcoded-ips'], 3);
  }

  if (hasCryptoSignal && hasFileSignal && hasNetworkSignal) {
    amplifiers.push('Crypto + file I/O + network: matches ransomware-like behavior profile');
    bumpWeights(signals, ['crypto-imports', 'file-imports', 'network-imports'], 3);
  }

  if (hasCryptoSignal && signals.some(s => s.id === 'base64-strings')) {
    amplifiers.push('Crypto APIs + base64 strings: encrypted payload or obfuscated config likely');
    bumpWeights(signals, ['crypto-imports', 'base64-strings'], 2);
  }

  // Registry + execution amplifier: only fires when there are genuinely evasive
  // signals (injection, crypto, or EVASIVE anti-debug APIs). CRT-level
  // IsDebuggerPresent alone (present in every Windows app) must not trigger
  // the persistence amplifier — it produces too many false positives on
  // standard system utilities like notepad, explorer, or mspaint.
  if (hasRegistrySignal && hasExecSignal(signals) && (hasInjectionSignal || hasCryptoSignal || evasiveAntiDebugCount > 0)) {
    amplifiers.push('Registry modification + execution: persistence mechanism detected');
    bumpWeights(signals, ['registry-imports', 'registry-strings', 'exec-imports'], 2);
  }

  if (!hasNetworkSignal && hasHighEntropy) {
    dismissals.push('No network imports or strings — packer is more likely than dropper');
  }

  if (!hasDangerousImports && !hasHighEntropy && input.imports.length > 10) {
    dismissals.push('No dangerous imports and normal entropy — likely clean or benign-complex');
  }

  // ── 6. Negative signals (clean indicators that reduce threat score) ────────
  const guiCount           = countInSet(importNames, GUI_IMPORTS);
  const dbgHelpCount       = countInSet(importNames, DEBUG_SYMBOL_IMPORTS);
  const shellBrowseCount   = countInSet(importNames, SHELL_BROWSE_IMPORTS);
  const commonDialogCount  = countInSet(importNames, COMMON_DIALOG_IMPORTS);
  const printCount         = countInSet(importNames, PRINT_IMPORTS);
  const comInitCount       = countInSet(importNames, COM_INIT_IMPORTS);
  // Win32 App Score: points from benign API families (≥4 = clear Win32 desktop app)
  // Modern WinRT/XAML apps (Windows 10+ notepad, Settings, etc.) lack classic
  // MessageBox/CreateWindowEx imports but have COM init, large import tables from
  // api-ms-win-* API-sets, and COMCTL32 helpers. Count large import tables as a
  // strong benign indicator regardless of whether classic GUI APIs are present.
  const win32AppScore =
    (guiCount >= 1              ? 2 : 0) +
    (shellBrowseCount >= 1      ? 1 : 0) +
    (commonDialogCount >= 1     ? 2 : 0) +
    (printCount >= 1            ? 1 : 0) +
    (comInitCount >= 1          ? 1 : 0) +
    (input.imports.length > 25  ? 1 : 0) +
    // Extra point for very large import tables (> 100 entries) — malware rarely
    // needs 100+ imports; legitimate shell-integrated apps routinely do.
    (input.imports.length > 100 ? 1 : 0) +
    (!hasHighEntropy            ? 1 : 0);

  if (guiCount > 0) {
    const reduction = Math.min(guiCount * 4, 15);
    negativeSignals.push({
      id: 'gui-imports',
      finding: `${guiCount} GUI API(s) (MessageBox, CreateWindow…) — typical of legitimate desktop apps`,
      reduction,
    });
  }

  if (dbgHelpCount > 0) {
    negativeSignals.push({
      id: 'debug-symbol-imports',
      finding: `Debug-helper APIs (SymInitialize, MiniDumpWriteDump) — crash reporter or debugger`,
      reduction: 10,
    });
  }

  if (input.imports.length > 30 && !hasDangerousImports) {
    negativeSignals.push({
      id: 'large-clean-import-table',
      finding: `${input.imports.length} imports, none dangerous — rich API surface of a benign app`,
      reduction: 12,
    });
  }

  if (input.sections.length >= 4 && !hasHighEntropy) {
    negativeSignals.push({
      id: 'normal-section-count',
      finding: `${input.sections.length} sections with normal entropy — standard compiled binary`,
      reduction: 8,
    });
  }

  // Win32 standard-application profile: multiple benign API families + large
  // import table + no high entropy/injection/crypto/truly-evasive-anti-debug.
  // Covers Notepad, WordPad, Paint, Explorer, and common SDK utilities.
  //
  // NOTE: CRT-level IsDebuggerPresent is intentionally excluded from the gate
  // condition here (evasiveAntiDebugCount instead of antiDebugCount). Virtually
  // every CRT-linked Windows binary calls IsDebuggerPresent at startup — using
  // it to block Win32 app recognition produced false positives on system tools.
  const isWin32StandardApp =
    win32AppScore >= 4 &&
    input.imports.length > 20 &&
    !hasHighEntropy &&
    !hasInjectionSignal &&
    !hasCryptoSignal &&
    !evasiveAntiDebugCount;

  // Additional shell/dialog reduction (separately tracked so it appears in the
  // evidence audit trail alongside the primary win32-standard-app indicator).
  if ((shellBrowseCount > 0 || commonDialogCount > 0) && !isWin32StandardApp) {
    const r = Math.min(shellBrowseCount * 2 + commonDialogCount * 2, 10);
    if (r > 0) {
      negativeSignals.push({
        id: 'shell-dialog-imports',
        finding: `${shellBrowseCount + commonDialogCount} shell/common-dialog API(s) (file-open, save-as, browse folders) — expected in document-editing applications`,
        reduction: r,
      });
    }
  }
  if (isWin32StandardApp) {
    negativeSignals.push({
      id: 'win32-standard-app',
      finding: `Win32 standard-application profile (GUI APIs, large import table, no injection/crypto/anti-debug) — consistent with a legitimate compiled Windows utility`,
      reduction: 18,
    });
    dismissals.push('Win32 standard-app fingerprint — ShellExecute/CreateFile/RegOpenKey are ordinary OS integration calls in this context');
  }

  const totalNegativeReduction = negativeSignals.reduce((sum, s) => sum + s.reduction, 0);

  // ── 7. Threat score (with negative signal deduction) ──────────────────────
  const rawScore = signals.reduce((sum, s) => sum + Math.min(s.weight, 10), 0);
  const maxPossible = 80;
  const rawPct = Math.round((rawScore / maxPossible) * 100);
  const threatScore = Math.max(0, Math.min(100, rawPct - totalNegativeReduction));

  // ── 8. Confidence ─────────────────────────────────────────────────────────
  const sourceCount = new Set(signals.map(s => s.source)).size;
  // Negative signals add confidence (we have more complete picture).
  // A confirmed clean/benign profile has its own certainty boost — many
  // independent clean indicators pointing the same way is just as strong an
  // evidence chain as multiple threat signals.
  let confidence = Math.min(100, Math.round(
    20 +
    sourceCount * 18 +
    Math.min(signals.length, 6) * 5 +
    amplifiers.length * 8 +
    negativeSignals.length * 4 +
    (isWin32StandardApp ? 8 : 0)
  ));

  // ── Iteration dampening ───────────────────────────────────────────────────
  // On early iterations, high confidence reflects import-table signal DIVERSITY
  // (many API families detected simultaneously) rather than multi-pass validated
  // evidence. Scale confidence down so the progression is meaningful and the
  // minimum-iterations guard in assessConvergence produces a visible ramp.
  //   Iter 0 → ×0.65   (first pass: ≤70% regardless of signal count)
  //   Iter 1 → ×0.82   (second pass: partial credit)
  //   Iter 2+ → ×1.00  (third pass and beyond: full confidence)
  if (input.iterationIndex !== undefined) {
    const dampen =
      input.iterationIndex === 0 ? 0.65 :
      input.iterationIndex === 1 ? 0.82 :
      1.0;
    confidence = Math.round(Math.min(confidence, 99) * dampen);
  }

  // ── 9. Classification ──────────────────────────────────────────────────────
  // `negativesDominate` is true when the clean-indicator score reduction
  // exceeds the raw positive signal score — the negative evidence is
  // stronger than the threat evidence.
  const negativesDominate = totalNegativeReduction > rawPct;
  const classification = classify({
    threatScore,
    hasHighEntropy,
    hasDangerousImports,
    hasNetworkSignal,
    hasCryptoSignal,
    hasInjectionSignal,
    hasFileSignal,
    hasRegistrySignal,
    hasMinimalImports: signals.some(s => s.id === 'minimal-imports'),
    hasAntiDebug: signals.some(s => s.id === 'antidebug-imports' || s.id === 'anti-analysis-patterns'),
    hasExec: hasExecSignal(signals),
    signalCount: signals.length,
    negativesDominate,
    negativeSignalCount: negativeSignals.length,
    isWin32StandardApp,
  });

  // ── 10. Explainability breakdown ───────────────────────────────────────────
  // Add one entry per signal group explaining its contribution
  if (hasHighEntropy) {
    explainability.push({
      factor: 'High section entropy',
      contribution: 'increases',
      detail: `${highEntropyCount} section(s) with entropy ≥ 7.0. Packed, encrypted, or self-modifying code typically produces high entropy.`,
    });
  }
  if (hasInjectionSignal) {
    explainability.push({
      factor: 'Process injection APIs',
      contribution: 'increases',
      detail: 'Functions like WriteProcessMemory and CreateRemoteThread are almost exclusively used by malware to migrate into other processes.',
    });
  }
  if (hasCryptoSignal) {
    explainability.push({
      factor: 'Cryptography APIs',
      contribution: 'increases',
      detail: 'CryptEncrypt/BCryptEncrypt are present. Alone this may mean data protection; combined with network or file ops it suggests ransomware or encrypted C2.',
    });
  }
  if (hasNetworkSignal) {
    explainability.push({
      factor: 'Network capabilities',
      contribution: 'increases',
      detail: 'Network APIs or embedded URLs/IPs detected. Could indicate C2, download, or data exfiltration.',
    });
  }
  if (signals.some(s => s.id === 'antidebug-imports')) {
    explainability.push({
      factor: 'Anti-debugging imports',
      contribution: 'increases',
      detail: 'IsDebuggerPresent and related APIs are used to terminate or alter behavior when running under a debugger — a strong malware indicator.',
    });
  }
  if (signals.some(s => s.id === 'dynload-imports')) {
    explainability.push({
      factor: 'Dynamic API loading',
      contribution: 'increases',
      detail: 'GetProcAddress/LoadLibrary lets the binary hide its real capabilities from static analysis of the import table.',
    });
  }
  for (const neg of negativeSignals) {
    explainability.push({
      factor: neg.finding.split(' — ')[0],
      contribution: 'decreases',
      detail: neg.finding + `. Reduces threat score by ${neg.reduction} points.`,
    });
  }
  if (amplifiers.length > 0) {
    explainability.push({
      factor: 'Signal correlation',
      contribution: 'increases',
      detail: amplifiers.join('; '),
    });
  }
  if (explainability.length === 0) {
    explainability.push({
      factor: 'Insufficient signals',
      contribution: 'neutral',
      detail: 'Not enough data loaded. Run Inspect + Scan Strings + Disassemble to gather signals.',
    });
  }

  // ── 11. Summary ───────────────────────────────────────────────────────────
  const summary = buildSummary(classification, threatScore, confidence, signals, amplifiers, dismissals);

  // ── 12. Workflow steps ─────────────────────────────────────────────────────
  const nextSteps = buildWorkflow(classification, {
    hasHighEntropy,
    hasNetworkSignal,
    hasCryptoSignal,
    hasInjectionSignal,
    hasFileSignal,
    hasRegistrySignal,
    hasAntiDebug: signals.some(s => s.id === 'antidebug-imports' || s.id === 'anti-analysis-patterns'),
    hasExec: hasExecSignal(signals),
    hasMinimalImports: signals.some(s => s.id === 'minimal-imports'),
    threatScore,
  });

  // ── 13. Behavioral tags ───────────────────────────────────────────────────
  const behaviors: BehavioralTag[] = [];
  if (hasInjectionSignal)                                                          behaviors.push('code-injection');
  if (hasNetworkSignal)                                                            behaviors.push('c2-communication');
  // Persistence only fires with a meaningful threat score — every GUI app that
  // saves settings (RegSetValueEx) and opens files (ShellExecute) would
  // otherwise be incorrectly labelled as a persistence mechanism.
  if (hasRegistrySignal && hasExecSignal(signals) && threatScore >= 25)           behaviors.push('persistence');
  if (signals.some(s => s.id === 'antidebug-imports' || s.id === 'anti-analysis-patterns')) behaviors.push('anti-analysis');
  // data-exfiltration: file + network, but only when there is real threat signal
  if (hasNetworkSignal && hasFileSignal && threatScore >= 25)                     behaviors.push('data-exfiltration');
  if (hasCryptoSignal && hasFileSignal)                                            behaviors.push('file-destruction');
  // credential-theft: network + registry, but settings reads are not exfiltration
  if (hasNetworkSignal && hasRegistrySignal && threatScore >= 30)                 behaviors.push('credential-theft');
  if (hasHighEntropy && signals.some(s => s.id === 'minimal-imports'))            behaviors.push('code-decryption');
  // dynamic-resolution: only interesting when there is something to hide
  if (signals.some(s => s.id === 'dynload-imports') && threatScore >= 20)        behaviors.push('dynamic-resolution');
  // process-execution: only meaningful when the binary has some threat signal
  if (hasExecSignal(signals) && threatScore >= 20)                                behaviors.push('process-execution');
  if (hasCryptoSignal && hasFileSignal && !hasNetworkSignal)                      behaviors.push('data-encryption');
  if (negativeSignals.length >= 2 && behaviors.length === 0)                     behaviors.push('self-contained');

  // ── 14. Three-stage reasoning chain ───────────────────────────────────────
  const reasoningChain: ReasoningStage[] = buildReasoningChain(
    signals, negativeSignals, behaviors, classification, threatScore, amplifiers, {
      hasHighEntropy, hasNetworkSignal, hasCryptoSignal, hasInjectionSignal,
      hasFileSignal, hasRegistrySignal
    }
  );

  // ── 15. Contradiction detection ───────────────────────────────────────────
  // Determine if high entropy originates only from resource/data sections
  // (icons, bitmaps, embedded resources) rather than code sections — this is
  // normal in standard compiled applications and should not trigger C1 or C4.
  const resourceOnlyHighEntropy = hasHighEntropy &&
    input.sections.every(
      s => s.entropy < 7.0 || /^\.rsrc|^\.rdata|^\.data|^PAPYRUS|^\.idata/i.test(s.name)
    );

  const contradictions: Contradiction[] = detectContradictions(
    signals, negativeSignals, behaviors, {
      hasHighEntropy, hasNetworkSignal, hasCryptoSignal, hasInjectionSignal,
      hasFileSignal, hasRegistrySignal, importCount: input.imports.length,
      isWin32App: isWin32StandardApp,
      resourceOnlyHighEntropy,
    }
  );

  // ── 16. Signature signals (from signatureEngine) ──────────────────────────
  const sigMatches = input.signatureMatches ?? [];
  if (sigMatches.length > 0) {
    // Safe patterns (libc, compiler runtime) → negative signal that reduces noise
    const safeMatches = sigMatches.filter(m => m.signature.safe);
    if (safeMatches.length > 0) {
      const names = [...new Set(safeMatches.slice(0, 5).map(m => m.signature.name))].join(', ');
      const reduction = Math.min(15, safeMatches.length * 2);
      negativeSignals.push({
        id: 'sig-safe-patterns',
        finding: `${safeMatches.length} known-safe pattern(s) matched (${names}${safeMatches.length > 5 ? ', …' : ''})`,
        reduction,
      });
    }
    // Notable patterns (anti-debug, crypto, dynamic resolution) → positive signal
    const notableMatches = sigMatches.filter(m => !m.signature.safe);
    if (notableMatches.length > 0) {
      const names = [...new Set(notableMatches.map(m => m.signature.name))].join(', ');
      signals.push({
        source: 'signatures',
        id: 'sig-notable-patterns',
        finding: `${notableMatches.length} notable pattern(s) matched: ${names}`,
        weight: Math.min(8, notableMatches.length * 2),
        corroboratedBy: [],
      });
      // Propagate behaviors from notable matches
      for (const m of notableMatches) {
        for (const b of m.signature.behaviors) {
          if (!behaviors.includes(b)) behaviors.push(b);
        }
      }
    }
    // Anti-debug specifically → corroborate existing anti-analysis signal
    const antiDbgMatches = sigMatches.filter(m => m.signature.category === 'anti-debug');
    if (antiDbgMatches.length > 0) {
      const antiSig = signals.find(s => s.id === 'antidebug-imports' || s.id === 'anti-analysis-patterns' || s.id === 'sig-anti-debug');
      if (antiSig) {
        if (!antiSig.corroboratedBy.includes('sig-notable-patterns')) {
          antiSig.corroboratedBy.push('sig-notable-patterns');
        }
      } else {
        signals.push({
          source: 'signatures',
          id: 'sig-anti-debug',
          finding: `Anti-debug pattern(s) found in code: ${antiDbgMatches.map(m => m.signature.name).join(', ')}`,
          weight: 5,
          corroboratedBy: [],
        });
      }
    }
  }

  // ── 17. TALON decompiler signals ─────────────────────────────────────────
  const talon = input.talonSignals;
  if (talon) {
    // Anti-debug confirmed by decompiler analysis
    if (talon.hasAntiDebug) {
      const existing = signals.find(s => s.id === 'antidebug-imports' || s.id === 'sig-anti-debug' || s.id === 'anti-analysis-patterns');
      if (existing) {
        if (!existing.corroboratedBy.includes('talon-anti-debug')) {
          existing.corroboratedBy.push('talon-anti-debug');
          existing.weight = Math.min(10, existing.weight + 1);
        }
      } else {
        signals.push({ source: 'disassembly', id: 'talon-anti-debug', finding: 'TALON: anti-debug routine detected in decompiled code', weight: 5, corroboratedBy: [] });
      }
      if (!behaviors.includes('anti-analysis')) behaviors.push('anti-analysis');
    }
    // Crypto in decompiled code
    if (talon.hasCrypto) {
      const existing = signals.find(s => s.id.includes('crypto'));
      if (existing) {
        if (!existing.corroboratedBy.includes('talon-crypto')) existing.corroboratedBy.push('talon-crypto');
      } else {
        signals.push({ source: 'disassembly', id: 'talon-crypto', finding: 'TALON: cryptographic routine in decompiled code', weight: 4, corroboratedBy: [] });
      }
      if (!behaviors.includes('data-encryption')) behaviors.push('data-encryption');
    }
    // Injection / process exec
    if (talon.hasInjection) {
      signals.push({ source: 'disassembly', id: 'talon-injection', finding: 'TALON: process-injection API sequence in decompiled code', weight: 7, corroboratedBy: [] });
      if (!behaviors.includes('code-injection')) behaviors.push('code-injection');
    }
    if (talon.hasNetworkOps) {
      const existing = signals.find(s => s.id.includes('network') || s.id.includes('c2'));
      if (existing) {
        if (!existing.corroboratedBy.includes('talon-network')) existing.corroboratedBy.push('talon-network');
      } else {
        signals.push({ source: 'disassembly', id: 'talon-network', finding: 'TALON: network I/O sequence in decompiled code', weight: 5, corroboratedBy: [] });
        if (!behaviors.includes('c2-communication')) behaviors.push('c2-communication');
      }
    }
    if (talon.hasPersistence) {
      if (!behaviors.includes('persistence')) behaviors.push('persistence');
    }
    if (talon.hasDynamicResolution) {
      if (!behaviors.includes('dynamic-resolution')) behaviors.push('dynamic-resolution');
    }
    // High uncertainty → reduce confidence
    if (talon.uncertainRatio > 0.4) {
      confidence = Math.max(10, confidence - Math.round((talon.uncertainRatio - 0.4) * 30));
    }
    // High TALON confidence → small boost
    if (talon.overallConfidence > 80 && talon.functionCount >= 3) {
      confidence = Math.min(99, confidence + 3);
    }
  }

  // ── 18. STRIKE runtime signals ────────────────────────────────────────────
  if (input.strikeSignals) {
    const s = input.strikeSignals;
    // Anti-analysis: timing checks, exception probes, CPUID
    if (s.hasTimingCheck || s.hasAntiStep || s.hasCpuidCheck) {
      const existing = signals.find(sig => sig.id.includes('anti-debug') || sig.id.includes('talon-anti-debug'));
      if (existing) {
        if (!existing.corroboratedBy.includes('strike-runtime')) {
          existing.corroboratedBy.push('strike-runtime');
          existing.weight = Math.min(10, existing.weight + 2);
        }
      } else {
        signals.push({ source: 'disassembly', id: 'strike-anti-debug', finding: 'STRIKE: runtime anti-debug behavior observed (timing/exception/CPUID)', weight: 6, corroboratedBy: [] });
      }
      if (!behaviors.includes('anti-analysis')) behaviors.push('anti-analysis');
    }
    // Exception probing
    if (s.hasExceptionProbe) {
      signals.push({ source: 'disassembly', id: 'strike-exception-probe', finding: 'STRIKE: deliberate exception probe detected at runtime', weight: 5, corroboratedBy: [] });
    }
    // Stack pivot / ROP — high weight
    if (s.hasStackPivot || s.hasRopActivity) {
      signals.push({ source: 'disassembly', id: 'strike-rop', finding: 'STRIKE: stack pivot or ROP chain observed at runtime', weight: 8, corroboratedBy: [] });
      if (!behaviors.includes('code-injection')) behaviors.push('code-injection');
      confidence = Math.min(99, confidence + 5);
    }
    // High indirect-jump ratio → suspicious
    if (s.indirectJumpRatio > 0.3) {
      signals.push({ source: 'disassembly', id: 'strike-indirect-flow', finding: `STRIKE: ${Math.round(s.indirectJumpRatio * 100)}% indirect jumps — possible dynamic dispatch or obfuscation`, weight: 4, corroboratedBy: [] });
    }
    // Runtime data boosts confidence significantly
    if (s.stepCount >= 10) {
      confidence = Math.min(99, confidence + 4);
    }
  }

  // ── 19. ECHO fuzzy recognition signals ───────────────────────────────────
  if (input.echoSignals) {
    const e = input.echoSignals;
    if (e.hasCryptoAlgorithm) {
      const existing = signals.find(sig => sig.id.includes('crypto'));
      if (existing) {
        if (!existing.corroboratedBy.includes('echo-crypto')) existing.corroboratedBy.push('echo-crypto');
      } else {
        signals.push({ source: 'disassembly', id: 'echo-crypto', finding: 'ECHO: cryptographic algorithm identified by fuzzy matching', weight: 4, corroboratedBy: [] });
      }
      if (!behaviors.includes('data-encryption')) behaviors.push('data-encryption');
    }
    if (e.hasInjectionPattern) {
      const existing = signals.find(sig => sig.id.includes('injection') || sig.id.includes('inject'));
      if (existing) {
        if (!existing.corroboratedBy.includes('echo-inject')) existing.corroboratedBy.push('echo-inject');
        existing.weight = Math.min(10, existing.weight + 1);
      } else {
        signals.push({ source: 'disassembly', id: 'echo-injection', finding: 'ECHO: code injection pattern recognized by fuzzy matching', weight: 7, corroboratedBy: [] });
      }
      if (!behaviors.includes('code-injection')) behaviors.push('code-injection');
    }
    if (e.hasAntiDebugPattern) {
      const existing = signals.find(sig => sig.id.includes('anti-debug'));
      if (existing) {
        if (!existing.corroboratedBy.includes('echo-anti-debug')) existing.corroboratedBy.push('echo-anti-debug');
      } else {
        signals.push({ source: 'disassembly', id: 'echo-anti-debug', finding: 'ECHO: anti-debug pattern recognized by fuzzy matching', weight: 5, corroboratedBy: [] });
      }
      if (!behaviors.includes('anti-analysis')) behaviors.push('anti-analysis');
    }
    if (e.hasNetworkPattern) {
      const existing = signals.find(sig => sig.id.includes('network') || sig.id.includes('c2'));
      if (existing) {
        if (!existing.corroboratedBy.includes('echo-network')) existing.corroboratedBy.push('echo-network');
      } else {
        signals.push({ source: 'disassembly', id: 'echo-network', finding: 'ECHO: network I/O pattern recognized', weight: 5, corroboratedBy: [] });
        if (!behaviors.includes('c2-communication')) behaviors.push('c2-communication');
      }
    }
    if (e.hasPersistence) {
      if (!behaviors.includes('persistence')) behaviors.push('persistence');
    }
    if (e.hasDynamicLoad) {
      if (!behaviors.includes('dynamic-resolution')) behaviors.push('dynamic-resolution');
    }
    // High pattern diversity and average confidence → boost verdict confidence
    if (e.patternDiversity >= 4 && e.averageConfidence >= 70) {
      confidence = Math.min(99, confidence + 3);
    }
    // Known-safe library functions → reduce uncertainty
    if (e.hasLibcFunctions && e.hasCompilerArtifacts && !e.hasInjectionPattern) {
      confidence = Math.min(99, confidence + 2);
    }
    for (const tag of e.behavioralTags) {
      if (!behaviors.includes(tag)) behaviors.push(tag);
    }
  }

  // ── 20. Alternative hypotheses ────────────────────────────────────────────
  const alternatives = buildAlternatives(classification, behaviors, negativeSignals, {
    hasHighEntropy, hasNetworkSignal, hasCryptoSignal, hasInjectionSignal,
    hasFileSignal, hasRegistrySignal, threatScore, confidence
  });

  return {
    classification,
    threatScore,
    confidence,
    signals,
    negativeSignals,
    amplifiers,
    dismissals,
    summary,
    explainability,
    nextSteps,
    signalCount: signals.length,
    behaviors,
    reasoningChain,
    contradictions,
    alternatives,
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function countInSet(names: Set<string>, target: Set<string>): number {
  let n = 0;
  for (const name of names) { if (target.has(name)) n++; }
  return n;
}

function matchingNames(names: Set<string>, target: Set<string>): string[] {
  return Array.from(names).filter(n => target.has(n));
}

function bumpWeights(signals: CorrelatedSignal[], ids: string[], amount: number): void {
  for (const s of signals) {
    if (ids.includes(s.id)) {
      s.weight = Math.min(10, s.weight + amount);
    }
  }
}

function hasExecSignal(signals: CorrelatedSignal[]): boolean {
  return signals.some(s => s.id === 'exec-imports' || s.id === 'pe-names');
}

interface ClassifyInput {
  threatScore: number;
  hasHighEntropy: boolean;
  hasDangerousImports: boolean;
  hasNetworkSignal: boolean;
  hasCryptoSignal: boolean;
  hasInjectionSignal: boolean;
  hasFileSignal: boolean;
  hasRegistrySignal: boolean;
  hasMinimalImports: boolean;
  hasAntiDebug: boolean;
  hasExec: boolean;
  signalCount: number;
  /** True when the negative signals dominate the picture (e.g., large clean GUI app) */
  negativesDominate: boolean;
  /** Number of GUI-style negative indicators */
  negativeSignalCount: number;
  /** True when the binary matches the Win32 standard-application profile */
  isWin32StandardApp: boolean;
}

function classify(c: ClassifyInput): BinaryClassification {
  // ── Win32 standard-app early override ────────────────────────────────────
  // A confirmed Win32 desktop-application fingerprint (COM init, large import
  // table, no injection/crypto/evasive-anti-debug, no high entropy) overrides
  // the generic import-family heuristics. GetProcAddress, CreateFile, RegOpenKey,
  // CreateProcess, and IsDebuggerPresent are all normal in system utilities
  // like notepad, mspaint, explorer, and common SDK apps. Return clean when
  // the net threat score is below 25 and no genuinely malicious signals exist.
  if (
    c.isWin32StandardApp &&
    c.threatScore < 25 &&
    !c.hasInjectionSignal &&
    !c.hasCryptoSignal &&
    !c.hasNetworkSignal &&
    !c.hasHighEntropy
  ) {
    return 'clean';
  }

  // ── Early exits based on net threat score ────────────────────────────────
  // Net threat score already factors in negative (clean) signals. If it's very
  // low, the binary is benign regardless of which API families appear in its
  // import table — every real Windows application calls ShellExecute, CreateFile,
  // RegOpenKey, LoadLibrary, etc.
  if (c.threatScore < 15) {
    // A handful of positive signals that were overwhelmed by negative evidence
    return c.negativesDominate ? 'clean' : 'suspicious';
  }

  // ── Specific threat profiles ──────────────────────────────────────────────
  // All specific malware classes require a meaningful net threat score to
  // prevent misfiring on legitimate complex Windows applications.

  // Ransomware: crypto + file I/O + network (minimum meaningful score)
  if (c.hasCryptoSignal && c.hasFileSignal && c.hasNetworkSignal && c.threatScore >= 35) return 'ransomware-like';

  // RAT: injection + network
  if (c.hasInjectionSignal && c.hasNetworkSignal && c.threatScore >= 30) return 'rat';

  // Dropper: downloads/extracts a payload and executes it.
  //
  // Two distinct patterns:
  //  1. Network dropper  — downloads a file via network then executes it.
  //     This is the archetypal dropper pattern; network access is required
  //     because the payload originates externally.
  //  2. File+injection dropper — writes a payload file locally, then executes
  //     it using process injection (VirtualAllocEx+WriteProcessMemory or
  //     CreateRemoteThread). Requires a higher threat score to avoid flagging
  //     privileged system binaries (winlogon, lsass, services.exe) that
  //     legitimately create processes, write files, and use remote thread APIs
  //     for credential-provider/DLL loading.
  //
  // NOTE: exec + file alone (without network or injection) is intentionally
  // NOT dropper — every shell, installer, and document-viewer creates processes
  // and writes files as part of normal operation.
  if (c.hasExec && c.hasNetworkSignal && c.threatScore >= 35) return 'dropper';
  if (c.hasExec && c.hasFileSignal && c.hasInjectionSignal && c.threatScore >= 50) return 'dropper';

  // Info stealer: network + registry — requires real score, every GUI app
  // touches the registry for settings
  if (c.hasNetworkSignal && c.hasRegistrySignal && c.threatScore >= 35) return 'info-stealer';

  // Loader: minimal imports + high entropy + dynamic load
  if (c.hasMinimalImports && c.hasHighEntropy) return 'packer';

  // Packer: high entropy, few imports
  if (c.hasHighEntropy && !c.hasDangerousImports) return 'packer';

  if (c.threatScore >= 60) return 'likely-malware';
  if (c.threatScore >= 25) return 'suspicious';
  if (c.threatScore < 20) return 'clean';
  return 'unknown';
}

const CLASS_LABEL: Record<BinaryClassification, string> = {
  clean:           'Clean',
  suspicious:      'Suspicious',
  packer:          'Packer',
  dropper:         'Dropper',
  'ransomware-like': 'Ransomware-like',
  'info-stealer':  'Info Stealer',
  rat:             'RAT / Backdoor',
  loader:          'Loader',
  'likely-malware':'Likely Malware',
  unknown:         'Unknown',
};

function buildSummary(
  classification: BinaryClassification,
  threatScore: number,
  confidence: number,
  signals: CorrelatedSignal[],
  amplifiers: string[],
  dismissals: string[],
): string {
  if (signals.length === 0) {
    return 'No signals detected. Load a binary and run Inspect + Scan Strings + Disassemble to gather data.';
  }

  const label = CLASS_LABEL[classification];
  const scoreStr = `threat score ${threatScore}/100 (${confidence}% confidence)`;

  if (classification === 'clean') {
    return `No significant threat signals detected — ${scoreStr}. ${dismissals[0] ?? ''}`;
  }

  const topSignals = signals
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 3)
    .map(s => s.finding)
    .join('; ');

  const amp = amplifiers.length > 0 ? ` ${amplifiers[0]}.` : '';

  return `Classified as ${label} — ${scoreStr}. Key evidence: ${topSignals}.${amp}`;
}

interface WorkflowContext {
  hasHighEntropy: boolean;
  hasNetworkSignal: boolean;
  hasCryptoSignal: boolean;
  hasInjectionSignal: boolean;
  hasFileSignal: boolean;
  hasRegistrySignal: boolean;
  hasAntiDebug: boolean;
  hasExec: boolean;
  hasMinimalImports: boolean;
  threatScore: number;
}

function buildWorkflow(
  classification: BinaryClassification,
  ctx: WorkflowContext,
): WorkflowStep[] {
  const steps: WorkflowStep[] = [];

  // Universal first step when threat is detected
  if (ctx.threatScore >= 25) {
    steps.push({
      priority: 'critical',
      action: 'Review the Imports tab',
      rationale: 'Import table is the fastest way to understand declared capabilities before any execution.',
      tab: 'metadata',
    });
  }

  if (ctx.hasHighEntropy) {
    steps.push({
      priority: 'critical',
      action: 'Unpack or decrypt the binary before further analysis',
      rationale: 'High entropy means the real code is hidden. Static analysis of packed code gives incomplete results.',
      tab: 'hex',
    });
  }

  if (ctx.hasAntiDebug) {
    steps.push({
      priority: 'critical',
      action: 'Identify anti-debugging routines in Disassembly',
      rationale: 'Anti-debug APIs will abort analysis under a debugger. Locate and patch them first.',
      tab: 'disassembly',
    });
  }

  if (ctx.hasInjectionSignal) {
    steps.push({
      priority: 'high',
      action: 'Trace injection APIs to understand target process selection',
      rationale: 'Process injection (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread) indicates the malware migrates into another process.',
      tab: 'disassembly',
    });
  }

  if (ctx.hasNetworkSignal) {
    steps.push({
      priority: 'high',
      action: 'Extract all URLs, IPs, and domains from the Strings tab',
      rationale: 'Network strings reveal C2 servers, download URLs, and exfiltration endpoints.',
      tab: 'strings',
    });
  }

  if (ctx.hasCryptoSignal) {
    steps.push({
      priority: 'high',
      action: 'Identify what is being encrypted / decrypted',
      rationale: 'Crypto without network = possibly unpacking itself. Crypto + network = likely exfiltration or C2 comms.',
      tab: 'disassembly',
    });
  }

  if (ctx.hasRegistrySignal) {
    steps.push({
      priority: 'medium',
      action: 'Inspect registry strings for persistence locations',
      rationale: 'Registry modification strings (Run keys, services) reveal where the malware installs itself.',
      tab: 'strings',
    });
  }

  if (ctx.hasExec) {
    steps.push({
      priority: 'medium',
      action: 'Find what is being executed via ShellExecute / CreateProcess',
      rationale: 'Execution APIs often carry the dropped payload path. Look for string cross-references.',
      tab: 'disassembly',
    });
  }

  if (ctx.threatScore >= 50) {
    steps.push({
      priority: 'medium',
      action: 'Run all plugins for automated pattern matching',
      rationale: 'Plugin analysis may surface additional patterns not detected by static heuristics.',
      tab: 'plugins',
    });
  }

  steps.push({
    priority: 'low',
    action: 'Build and review the Control Flow Graph',
    rationale: 'CFG reveals program structure — dense graphs with few calls indicate encrypted/packed stubs.',
    tab: 'cfg',
  });

  return steps;
}

// ─── Stage-Reasoning Builder ──────────────────────────────────────────────────

function buildReasoningChain(
  signals: CorrelatedSignal[],
  negativeSignals: NegativeSignal[],
  behaviors: BehavioralTag[],
  classification: BinaryClassification,
  threatScore: number,
  amplifiers: string[],
  ctx: {
    hasHighEntropy: boolean; hasNetworkSignal: boolean; hasCryptoSignal: boolean;
    hasInjectionSignal: boolean; hasFileSignal: boolean; hasRegistrySignal: boolean;
  },
): ReasoningStage[] {
  const stages: ReasoningStage[] = [];

  // ── Stage 1: Raw signal inventory ──────────────────────────────────────────
  const s1Findings: string[] = [];
  const structSignals = signals.filter(s => s.source === 'structure');
  const importSignals = signals.filter(s => s.source === 'imports');
  const stringSignals = signals.filter(s => s.source === 'strings');
  const dasmSignals   = signals.filter(s => s.source === 'disassembly');

  if (structSignals.length > 0) s1Findings.push(`Structure: ${structSignals.map(s => s.finding).join('; ')}`);
  if (importSignals.length > 0) s1Findings.push(`Imports: ${importSignals.map(s => s.finding).join('; ')}`);
  if (stringSignals.length > 0) s1Findings.push(`Strings: ${stringSignals.map(s => s.finding).join('; ')}`);
  if (dasmSignals.length > 0)   s1Findings.push(`Disassembly: ${dasmSignals.map(s => s.finding).join('; ')}`);
  if (negativeSignals.length > 0) s1Findings.push(`Clean indicators: ${negativeSignals.map(s => s.finding).join('; ')}`);
  if (s1Findings.length === 0) s1Findings.push('No signals detected — run Inspect, Scan Strings, and Disassemble.');

  const s1Score = signals.length + negativeSignals.length;
  stages.push({
    stage: 1,
    name: 'Raw Signal Collection',
    findings: s1Findings,
    conclusion: s1Findings.length === 1 && s1Findings[0].startsWith('No signals')
      ? 'Insufficient data to proceed with analysis.'
      : `Collected ${signals.length} threat signal(s) and ${negativeSignals.length} clean indicator(s) from ${new Set(signals.map(s => s.source)).size} source(s).`,
    confidence: Math.min(80, s1Score * 12),
  });

  // ── Stage 2: Behavioral inference ──────────────────────────────────────────
  const s2Findings: string[] = [];
  if (behaviors.includes('code-injection'))    s2Findings.push('→ Code injection capability: can migrate into other processes.');
  if (behaviors.includes('c2-communication'))  s2Findings.push('→ C2 communication capability: connects to remote infrastructure.');
  if (behaviors.includes('persistence'))       s2Findings.push('→ Persistence mechanism: modifies registry or schedules tasks.');
  if (behaviors.includes('anti-analysis'))     s2Findings.push('→ Anti-analysis evasion: actively resists debuggers and sandboxes.');
  if (behaviors.includes('data-exfiltration')) s2Findings.push('→ Data exfiltration path: reads files AND sends data over network.');
  if (behaviors.includes('credential-theft'))  s2Findings.push('→ Credential theft: touches registry AND communicates externally.');
  if (behaviors.includes('code-decryption'))   s2Findings.push('→ Runtime self-decryption: uses minimal packed imports, high entropy.');
  if (behaviors.includes('dynamic-resolution'))s2Findings.push('→ Dynamic API resolution: hides true capabilities from import table.');
  if (behaviors.includes('process-execution')) s2Findings.push('→ Child process spawning: launches other executables.');
  if (behaviors.includes('data-encryption'))   s2Findings.push('→ Local data encryption without exfiltration: possible ransomware stub or archiver.');
  if (behaviors.includes('self-contained'))    s2Findings.push('→ Self-contained / benign profile: multiple clean indicators, no dangerous behaviors.');
  if (s2Findings.length === 0) s2Findings.push('No behavioral capabilities inferred from available signals.');
  if (amplifiers.length > 0) s2Findings.push(`Corroborated: ${amplifiers.join('; ')}`);

  stages.push({
    stage: 2,
    name: 'Behavioral Inference',
    findings: s2Findings,
    conclusion: behaviors.length === 0
      ? 'No malicious behaviors identified from current signals.'
      : `Identified ${behaviors.length} behavioral capability(-ies): ${behaviors.slice(0, 4).join(', ')}${behaviors.length > 4 ? '…' : ''}.`,
    // For benign profiles (multiple clean indicators, no malicious behaviors beyond
    // the generic 'self-contained' tag), the ABSENCE of threat indicators IS the
    // evidence — rate it highly so clean binaries pass the dominance confidence gate.
    confidence: Math.min(90,
      negativeSignals.length >= 2 && behaviors.filter(b => b !== 'self-contained').length === 0
        ? 65 + negativeSignals.length * 5
        : 30 + behaviors.length * 12 + amplifiers.length * 8),
  });

  // ── Stage 3: Intent classification ────────────────────────────────────────
  const CLASS_INTENT: Record<BinaryClassification, string> = {
    clean:             'Clean utility / legitimate software',
    suspicious:        'Suspicious — too few signals to classify precisely, warrants further investigation',
    packer:            'Packer / protector — conceals real code; may wrap benign OR malicious payload',
    dropper:           'Dropper — downloads or extracts and executes a secondary payload',
    'ransomware-like': 'Ransomware-like — encrypts files, communicates externally, likely extortionware',
    'info-stealer':    'Information stealer — collects and exfiltrates credentials or system data',
    rat:               'Remote Access Trojan (RAT) — full remote control backdoor with C2 connectivity',
    loader:            'Loader — loads and maps another module into memory',
    'likely-malware':  'Likely malware — score and signals strongly suggest malicious intent',
    unknown:           'Unknown / insufficient data for reliable classification',
  };
  const s3Findings = [
    `Classification: ${CLASS_INTENT[classification]}`,
    `Composite threat score: ${threatScore}/100`,
    `Primary behaviors: ${behaviors.length > 0 ? behaviors.slice(0, 3).join(', ') : 'none detected'}`,
  ];
  if (negativeSignals.length > 0) {
    s3Findings.push(`Mitigated by ${negativeSignals.length} clean indicator(s), reducing raw score by ${negativeSignals.reduce((s, n) => s + n.reduction, 0)} points.`);
  }

  stages.push({
    stage: 3,
    name: 'Intent Classification',
    findings: s3Findings,
    conclusion: `Final verdict: ${CLASS_INTENT[classification]}. Score ${threatScore}/100.`,
    confidence: Math.min(95, 20 + (signals.length + negativeSignals.length) * 8 + amplifiers.length * 6),
  });

  return stages;
}

// ─── Contradiction Detector ───────────────────────────────────────────────────

interface ContraContext {
  hasHighEntropy: boolean;
  hasNetworkSignal: boolean;
  hasCryptoSignal: boolean;
  hasInjectionSignal: boolean;
  hasFileSignal: boolean;
  hasRegistrySignal: boolean;
  importCount: number;
  /** True when the binary matches the Win32 standard-application profile */
  isWin32App: boolean;
  /** True when high entropy exists ONLY in resource/data sections (.rsrc, .rdata) */
  resourceOnlyHighEntropy: boolean;
}

function detectContradictions(
  signals: CorrelatedSignal[],
  negativeSignals: NegativeSignal[],
  behaviors: BehavioralTag[],
  ctx: ContraContext,
): Contradiction[] {
  const contradictions: Contradiction[] = [];

  const hasGuiImports = negativeSignals.some(n => n.id === 'gui-imports');
  const hasAntiDebug  = signals.some(s => s.id === 'antidebug-imports' || s.id === 'anti-analysis-patterns');
  const hasDynLoad    = signals.some(s => s.id === 'dynload-imports');
  const hasManyImports = ctx.importCount > 25;
  const hasNetworkStrings = signals.some(s => s.id === 'embedded-urls' || s.id === 'hardcoded-ips');
  const hasNetworkImports = signals.some(s => s.id === 'network-imports');

  // C1: High entropy but few / no dangerous imports
  // For Win32 apps, high entropy in resource sections is common (bitmap icons,
  // large manifests, embedded PNG/JPEG). Downgrade severity when it is a
  // recognised Win32 application OR when the entropy is resource-section-only.
  if (ctx.hasHighEntropy && !ctx.resourceOnlyHighEntropy &&
      !behaviors.includes('code-injection') && !behaviors.includes('c2-communication') &&
      !behaviors.includes('anti-analysis') && !hasDynLoad) {
    contradictions.push({
      id: 'entropy-no-threat-imports',
      observation: 'High section entropy detected (packed / encrypted code)',
      conflict: 'No dangerous imports or obfuscation signals visible in the import table',
      resolution: 'Two interpretations: (1) Packed BENIGN software with a commercial protector. (2) Imports are hidden — resolved dynamically at runtime, bypassing static analysis.',
      severity: ctx.isWin32App ? 'low' : 'high',
    });
  }

  // C2: Network strings but no network APIs
  // For GUI applications, embedded URLs are routinely used to open help pages
  // or update checks via ShellExecuteW, without the app importing network APIs
  // directly. Downgrade severity when GUI imports are present.
  if (hasNetworkStrings && !hasNetworkImports) {
    contradictions.push({
      id: 'network-strings-no-api',
      observation: 'Embedded URLs / IP addresses found in strings',
      conflict: 'No network API imports detected (no Winsock, WinHTTP, InternetConnect…)',
      resolution: hasGuiImports
        ? 'GUI application — URLs are likely opened via ShellExecuteW (browser delegation). This is normal for help links, update checks, and telemetry opt-out pages. No direct obfuscation evidence.'
        : 'Network APIs may be dynamically resolved (GetProcAddress) or the binary loads a network-capable DLL at runtime. This is a strong indicator of deliberate obfuscation.',
      severity: hasGuiImports ? 'low' : 'high',
    });
  }

  // C3: Anti-debug in otherwise clean-looking binary
  if (hasAntiDebug && hasGuiImports && !ctx.hasInjectionSignal) {
    contradictions.push({
      id: 'antidebug-gui-benign',
      observation: 'Anti-debugging APIs present (IsDebuggerPresent family)',
      conflict: 'GUI imports suggest a standard desktop application with no injection capability',
      resolution: 'Anti-debug is common in commercial DRM, license enforcement, and game protection. This alone does not indicate malware. Look for what behavior changes when a debugger IS detected.',
      severity: 'low',
    });
  }

  // C4: Rich import table + high entropy (normally mutually exclusive for packers)
  // Skip this contradiction when entropy originates only from resource sections —
  // a large .rsrc or .rdata with icons/bitmaps is entirely normal in Win32 apps.
  if (ctx.hasHighEntropy && hasManyImports && !ctx.resourceOnlyHighEntropy) {
    contradictions.push({
      id: 'many-imports-high-entropy',
      observation: `Large import table (${ctx.importCount} imports) visible to static analysis`,
      conflict: 'Sections also have high entropy, suggesting packed/encrypted code',
      resolution: 'Packed binaries typically have very few imports (just LoadLibrary/GetProcAddress). Many visible imports with high entropy may indicate a partially-packed binary, a protector that preserves the import table, or a false entropy reading from a large resource section.',
      severity: 'medium',
    });
  }

  // C5: Crypto without any exfiltration path
  if (ctx.hasCryptoSignal && !ctx.hasNetworkSignal && !ctx.hasFileSignal) {
    contradictions.push({
      id: 'crypto-no-exfiltration',
      observation: 'Cryptographic APIs detected (CryptEncrypt / BCryptEncrypt)',
      conflict: 'No file I/O or network activity detected alongside the crypto operations',
      resolution: 'Standalone crypto without an obvious exfiltration mechanism could mean: (1) self-unpacking code (decrypts own payload in memory), (2) credential hashing, or (3) legitimate data-protection library. Load disassembly to trace what data flows into/out of the crypto functions.',
      severity: 'medium',
    });
  }

  // C6: Injection + process execution but no network (lateral movement without C2)
  if (ctx.hasInjectionSignal && behaviors.includes('process-execution') && !ctx.hasNetworkSignal) {
    contradictions.push({
      id: 'injection-exec-no-network',
      observation: 'Process injection AND child process execution capability',
      conflict: 'No network communication signals detected',
      resolution: 'Injection without network suggests either: (1) purely local privilege escalation, (2) staged loader that fetches C2 config from an encrypted resource, or (3) legitimate process-hollowing tool (rare). Inspect CFG for decryption stubs before injection call sites.',
      severity: 'medium',
    });
  }

  return contradictions;
}

// ─── Alternative Hypothesis Builder ──────────────────────────────────────────

interface AltContext {
  hasHighEntropy: boolean;
  hasNetworkSignal: boolean;
  hasCryptoSignal: boolean;
  hasInjectionSignal: boolean;
  hasFileSignal: boolean;
  hasRegistrySignal: boolean;
  threatScore: number;
  confidence: number;
}

function buildAlternatives(
  primary: BinaryClassification,
  behaviors: BehavioralTag[],
  negativeSignals: NegativeSignal[],
  ctx: AltContext,
): AlternativeHypothesis[] {
  const alts: AlternativeHypothesis[] = [];
  const hasGui = negativeSignals.some(n => n.id === 'gui-imports');
  const hasDebugSymbols = negativeSignals.some(n => n.id === 'debug-symbol-imports');

  if (primary === 'packer') {
    alts.push({
      classification: 'clean',
      label: 'Packed Legitimate Software',
      probability: hasGui ? 55 : 30,
      reasoning: `High entropy alone does not mean malicious. Commercial protectors (Themida, VMProtect, MPRESS) produce the same entropy signature. ${hasGui ? 'GUI imports further support a benign app.' : ''}`,
      requiredEvidence: ['No dangerous imports found after unpacking', 'Debug strings or PDB path visible after unpack', 'Signed certificate or version info block'],
    });
    alts.push({
      classification: 'loader',
      label: 'Staged Loader / Dropper Stub',
      probability: 30,
      reasoning: 'Packer stubs that decode and jump to a second-stage payload look identical to legitimate packers until the payload is extracted.',
      requiredEvidence: ['VirtualAlloc → write → execute sequence in disassembly', 'Embedded PE signature (MZ/PE) in data section', 'Encrypted blob in .rsrc or .data section'],
    });
  }

  if (primary === 'rat') {
    alts.push({
      classification: 'clean',
      label: 'Legitimate Remote Management Tool',
      probability: hasGui ? 25 : 10,
      reasoning: 'Commercial RMM tools (TeamViewer, AnyDesk, VNC) combine injection-like capabilities with C2 communication. Without malicious intent indicators, classification as RAT may be a false positive.',
      requiredEvidence: ['Digital signature from known vendor', 'Installer UI or consent dialog', 'No anti-debugging or anti-VM code'],
    });
  }

  if (primary === 'dropper') {
    alts.push({
      classification: 'clean',
      label: 'Software Installer / Updater',
      probability: hasGui ? 40 : 15,
      reasoning: 'Legitimate installers (NSIS, Inno Setup, WiX) use the same pattern: download payload + execute child process. The distinguishing factor is user consent and code signing.',
      requiredEvidence: ['Installer wizard UI in disassembly strings', 'Version info / company name string', 'Code signature validates to trusted CA'],
    });
  }

  if (primary === 'ransomware-like') {
    alts.push({
      classification: 'clean',
      label: 'Backup / Archive Tool with Encryption',
      probability: hasGui ? 20 : 5,
      reasoning: 'Backup software encrypts files, communicates with remote storage, and may use registry for scheduling. Without ransom note strings or unusual file extension changes, this is possible but unlikely.',
      requiredEvidence: ['Ransom note template string absent', 'File extension rename pattern absent', 'User-visible UI with backup configuration'],
    });
  }

  if (primary === 'info-stealer') {
    alts.push({
      classification: 'suspicious',
      label: 'System Telemetry / Monitoring Agent',
      probability: hasDebugSymbols ? 30 : 15,
      reasoning: 'Security products, system monitoring agents, and enterprise telemetry tools read registry and send data externally. The difference is transparency and scope of data collection.',
      requiredEvidence: ['Vendor certificate', 'Limited scope of registry access (HKLM\\SOFTWARE only)', 'No browser credential paths or clipboard access'],
    });
  }

  // If confidence is low, always add an "unknown" alternative
  if (ctx.confidence < 50) {
    alts.push({
      classification: 'unknown',
      label: 'Insufficient Evidence — Verdict Unreliable',
      probability: 100 - ctx.confidence,
      reasoning: `Confidence is ${ctx.confidence}%. More data sources needed. Run: Inspect → Hex → Scan Strings → Disassemble to increase signal coverage before trusting this verdict.`,
      requiredEvidence: ['Load and inspect the binary (Inspect file)', 'Scan strings with minimum length 4', 'Disassemble at least 1024 bytes', 'Run all plugins'],
    });
  }

  return alts;
}

