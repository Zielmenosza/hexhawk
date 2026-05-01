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
import type { YaraRuleMatch } from './yaraEngine';
import type { MythosCapabilityMatch } from './mythosEngine';

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
  | 'wiper'        // File-destruction / wiper
  | 'likely-malware'
  | 'unknown';

export type SignalSource = 'structure' | 'imports' | 'strings' | 'disassembly' | 'signatures' | 'agent';

/**
 * Evidence quality tier — used to weight confidence so that weak heuristic
 * signals cannot inflate the score to the same level as runtime-confirmed or
 * import-declared evidence.
 *
 *   DIRECT  — observed at runtime (STRIKE execution traces)  — highest trust
 *   STRONG  — structural declarations / deep static analysis — medium trust
 *   WEAK    — heuristic / observational                      — lowest trust
 */
export type EvidenceTier = 'DIRECT' | 'STRONG' | 'WEAK';

/**
 * Certainty level for a single finding — answers "how do we know this?".
 *
 *   observed  — directly present in the binary (import name, string, section)
 *               Analyst can verify by opening the Hex/Strings/Metadata tab.
 *   inferred  — derived by combining two or more observed facts
 *               e.g. "packed" = high-entropy section + minimal imports
 *               Correct most of the time but a single observed fact could be coincidental.
 *   heuristic — pattern-matched; the rule is approximate and may produce false positives
 *               e.g. tight-loop detection; requires human confirmation before acting.
 */
export type CertaintyLevel = 'observed' | 'inferred' | 'heuristic';

/**
 * Per-tier confidence contribution breakdown — attached to every
 * BinaryVerdictResult so the UI and NEST iterations can show exactly
 * which tier of evidence is driving the confidence number.
 */
export interface EvidenceTierBreakdown {
  direct: { signalCount: number; contribution: number; signals: string[] };
  strong: { signalCount: number; contribution: number; signals: string[] };
  weak:   { signalCount: number; contribution: number; signals: string[] };
  /** Confidence value computed from tier formula, before iteration dampening */
  preDampenConfidence: number;
}

/**
 * A navigable reference to a specific location in the binary that contributed
 * to a signal.  Used by the UI to show "why this rule fired" and to let the
 * analyst jump directly to the relevant code.
 *
 *   address === 0  → import-table entry (no runtime address); show as static badge
 *   address > 0   → disassembly / function / pattern address; show as jump button
 */
export interface SignalLocation {
  address: number;
  kind: 'import' | 'string' | 'instruction' | 'function' | 'section' | 'pattern';
  /** Short label shown on the chip: "WriteProcessMemory", "fn@0x401000", "$s1@0xABCD" */
  label: string;
  /** One-sentence context note shown on hover / in the expanded evidence panel */
  context?: string;
}

export interface CorrelatedSignal {
  source: SignalSource;
  id: string;           // short unique key
  finding: string;      // human-readable description
  weight: number;       // 0–10 contribution to threat score
  corroboratedBy: string[];  // ids of other signals that strengthen this one
  /** Evidence tier — populated by computeVerdict after all signals are collected */
  tier?: EvidenceTier;
  /**
   * Certainty level — how the system knows this finding is true.
   * Absent on legacy signals; present on all signals generated since Prompt 10.
   *
   *   'observed'  — fact directly present in the binary; high trust
   *   'inferred'  — derived from combining 2+ observed facts; moderate trust
   *   'heuristic' — pattern-matched rule; needs human confirmation
   */
  certainty?: CertaintyLevel;
  /**
   * Navigable code locations that triggered this signal.
   * Populated for YARA (matched string offsets) and MYTHOS (imports, function
   * addresses, pattern addresses).  Empty for legacy signals.
   *
   * UI use: render location chips in SignalRow; chips with address > 0
   * are clickable → jumpToDisassembly(address).
   */
  locations?: SignalLocation[];
  /**
   * Full evidence sentences explaining WHY the signal fired.
   * Populated for MYTHOS capability signals (one sentence per matched condition).
   * Shown in the expandable "Why this fired" panel in BinaryVerdict.
   */
  evidence?: string[];
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
  /** Per-tier evidence quality breakdown — shows what drove confidence */
  evidenceTierBreakdown?: EvidenceTierBreakdown;
  /**
   * Trusted Acceleration — uncertainty flags (Prompt 10).
   *
   * Lists things the system is NOT certain about.  Each flag is a
   * human-readable sentence beginning with "Uncertain:" so the analyst
   * always knows when a finding requires verification.
   *
   * Empty array = system has no active uncertainty flags for this verdict.
   */
  uncertaintyFlags: string[];
  /**
   * Signals whose `certainty` is 'heuristic' — pulled out for quick access
   * so the UI can highlight them without filtering the full signals array.
   */
  heuristicSignalIds: string[];
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
   * Optional: YARA rule matches from yaraEngine.runYaraRules() or matchRules().
   * Each match is converted into a CorrelatedSignal in §16.5 of computeVerdict().
   * Built-in rules run on the raw binary; passing results in here allows the
   * UI/NEST layer to control when YARA scanning happens (e.g. only on iteration 1).
   */
  yaraMatches?: YaraRuleMatch[];
  /**
   * Optional: MYTHOS capability matches from mythosEngine.runMythosRules().
   * Capabilities are higher-level than YARA patterns — each match represents a
   * *behavioral capability* (process injection, C2 comms, file encryption, etc.)
   * derived from combinations of imports, strings, patterns, and TALON/ECHO/YARA.
   * Each match → one CorrelatedSignal in §16.6 of computeVerdict() with:
   *   - id: 'mythos-<capability-id>'
   *   - source: 'signatures'
   *   - certainty: 'inferred' (derived from multi-evidence combination)
   *   - finding text that includes the full evidence chain
   */
  mythosMatches?: MythosCapabilityMatch[];
  /**
   * Zero-based index of the current iteration in the NEST session.
   * When provided, the confidence score is dampened on early iterations to
   * reflect that high first-pass confidence comes from signal diversity
   * (many import families hit at once), not from multi-pass validated evidence.
   * Omit (or undefined) to skip dampening — used by standalone / UI calls.
   */
  iterationIndex?: number;
  /**
   * Optional: analyst-approved signals injected by an external AI agent via
   * the MCP `inject_agent_signal` tool.  These signals carry source:'agent'
   * and certainty:'heuristic' unless overridden by the agent's own value.
   *
   * Signals in this list have already passed the human approval gate in the
   * HexHawk UI; they are treated as trusted analyst input at this point.
   */
  agentSignals?: Array<{
    id: string;
    finding: string;
    weight: number;
    certainty?: 'observed' | 'inferred' | 'heuristic';
  }>;
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
  // WinINet / WinHTTP / URLMon APIs
  'InternetOpen', 'InternetConnect', 'HttpSendRequest', 'URLDownloadToFile',
  'WinHttpOpen', 'WinHttpConnect', 'WinHttpSendRequest', 'WinHttpReceiveResponse',
  // Winsock 2 core APIs — WSASocketW/A omitted from many older lists but equally significant
  'WSAStartup', 'WSACleanup', 'WSASocketA', 'WSASocketW', 'WSAIoctl', 'WSAPoll',
  'connect', 'send', 'recv', 'sendto', 'recvfrom',
  'socket', 'bind', 'listen', 'accept', 'closesocket', 'ioctlsocket',
  'setsockopt', 'getsockopt', 'getpeername', 'getsockname',
  // DNS / name resolution APIs
  'getaddrinfo', 'GetAddrInfoW', 'getnameinfo', 'GetNameInfoW',
  'freeaddrinfo', 'FreeAddrInfoW',
  'gethostbyname', 'gethostbyaddr',
]);

const CRYPTO_IMPORTS = new Set([
  // Classic CryptoAPI
  'CryptEncrypt', 'CryptDecrypt', 'CryptGenRandom', 'CryptAcquireContext',
  'CryptCreateHash', 'CryptHashData', 'CryptGetHashParam', 'CryptDeriveKey',
  'CryptImportKey', 'CryptExportKey', 'CryptSetKeyParam',
  // Modern CNG / BCrypt family — all indicate deliberate crypto usage
  'BCryptOpenAlgorithmProvider', 'BCryptCloseAlgorithmProvider',
  'BCryptCreateHash', 'BCryptHashData', 'BCryptFinishHash', 'BCryptDestroyHash',
  'BCryptGenerateSymmetricKey', 'BCryptImportKey', 'BCryptImportKeyPair',
  'BCryptExportKey', 'BCryptDestroyKey',
  'BCryptEncrypt', 'BCryptDecrypt',
  'BCryptSetProperty', 'BCryptGetProperty',
  'BCryptDeriveKey', 'BCryptKeyDerivation',
  'BCryptGenRandom', 'BCryptSignHash', 'BCryptVerifySignature',
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

/**
 * System-enumeration APIs: harvest host identity, hardware config, and process
 * list — the passive reconnaissance phase of RATs and info-stealers.
 */
const SYSTEM_ENUM_IMPORTS = new Set([
  'GetComputerNameA', 'GetComputerNameW', 'GetComputerNameExA', 'GetComputerNameExW',
  'GetUserNameA', 'GetUserNameW',
  'GetSystemInfo', 'GetNativeSystemInfo',
  'GlobalMemoryStatusEx', 'GlobalMemoryStatus',
  'GetVersionExA', 'GetVersionExW', 'RtlGetVersion',
  'GetSystemMetrics',
  'EnumProcesses', 'Process32First', 'Process32FirstW', 'Process32Next', 'Process32NextW',
  'CreateToolhelp32Snapshot',
]);

/**
 * System-shutdown APIs: ExitWindowsEx and NT equivalents — used by wipers to
 * guarantee the machine reboots or shuts down after payload delivery.
 */
const SHUTDOWN_IMPORTS = new Set([
  'ExitWindowsEx',
  'InitiateSystemShutdownA', 'InitiateSystemShutdownW',
  'InitiateSystemShutdownExA', 'InitiateSystemShutdownExW',
  'NtShutdownSystem', 'ZwShutdownSystem',
]);

/**
 * Thread-manipulation APIs: create, suspend, hijack, and resume threads in
 * other processes — core primitives for process hollowing and injection.
 */
const THREADING_IMPORTS = new Set([
  // Classic thread lifecycle
  'CreateThread', 'CreateRemoteThread', 'CreateRemoteThreadEx',
  'SuspendThread', 'ResumeThread', 'TerminateThread',
  // Thread context hijack (classic injection primitive)
  'SetThreadContext', 'GetThreadContext', 'Wow64SetThreadContext', 'Wow64GetThreadContext',
  // APC injection
  'QueueUserAPC', 'NtQueueApcThread',
  // SRW locks (used by modern multi-threaded malware C++ toolkits)
  'InitializeSRWLock', 'AcquireSRWLockExclusive', 'AcquireSRWLockShared',
  'ReleaseSRWLockExclusive', 'ReleaseSRWLockShared', 'TryAcquireSRWLockExclusive',
  // Condition variables (co-occur with SRW in multi-threaded RAT frameworks)
  'InitializeConditionVariable', 'SleepConditionVariableSRW', 'SleepConditionVariableCS',
  'WakeAllConditionVariable', 'WakeConditionVariable',
]);

/**
 * Known SDK/runtime framework DLL name patterns.  When ≥ 40 % of all IAT
 * entries come from these DLLs the binary is a framework-linked application
 * (Qt, MSVC C++ runtime) and the large import count should NOT inflate the
 * raw threat score.
 */
const FRAMEWORK_DLL_PATTERNS: RegExp[] = [
  /^qt[0-9]/i,        // Qt5, Qt6 …
  /^msvcp[0-9]/i,     // MSVCP140, MSVCP120 …
  /^vcruntime[0-9]/i, // vcruntime140 …
  /^msvcr[0-9]/i,     // msvcr120 …
  /^mfc[0-9]/i,       // MFC DLLs
];

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
  const textSection = input.sections.find(s => s.name === '.text' || s.name === 'text');
  const dataSection = input.sections.find(s => s.name === '.data' || s.name === 'data');
  // Exclude .text from generic high-entropy count when packed-text will fire — it is
  // strictly more specific (weight 9) and double-counting inflates the threat score.
  const textIsHighEntropy = !!(textSection && textSection.entropy >= 7.0);
  const highEntropyCount = entropyRelevantSections.filter(
    s => s.entropy >= 7.0 && !(textIsHighEntropy && (s.name === '.text' || s.name === 'text'))
  ).length;
  const suspiciousEntropyCount = entropyRelevantSections.filter(s => s.entropy >= 6.0 && s.entropy < 7.0).length;

  if (highEntropyCount > 0) {
    signals.push({
      source: 'structure',
      id: 'high-entropy',
      finding: `${highEntropyCount} section(s) with entropy ≥ 7.0 (likely packed or encrypted)`,
      weight: highEntropyCount >= 2 ? 8 : 6,
      corroboratedBy: [],
    });
  } else if (suspiciousEntropyCount >= 2) {
    // Require ≥ 2 sections with elevated entropy to suppress single-section noise.
    // A lone section in the 6–7 range is common in benign compressed resources.
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

  // Encrypted/compressed payload blob: non-.text section with near-maximum entropy
  // (> 7.5) AND substantive size (> 64 KB).  This is a concrete maliciousness
  // indicator distinct from the generic high-entropy signal — an encrypted 174 KB
  // .data section at entropy 7.997 is essentially impossible without deliberate
  // encryption.  .text sections are excluded (already covered by packed-text).
  // Resource sections are excluded via entropyRelevantSections.
  // Computed first so encrypted-data can be suppressed when this covers .data.
  const encryptedBlobSection = entropyRelevantSections.find(
    s => s.entropy > 7.5 && s.file_size > 65536 &&
         s.name !== '.text' && s.name !== 'text',
  );

  // Suppress encrypted-data when encrypted-section already fires for .data —
  // encrypted-section (entropy > 7.5, size > 64 KB) is strictly more specific.
  const encryptedBlobCoversData = !!(encryptedBlobSection && dataSection &&
    encryptedBlobSection.name === dataSection.name);
  if (dataSection && dataSection.entropy >= 6.5 && !encryptedBlobCoversData) {
    signals.push({
      source: 'structure',
      id: 'encrypted-data',
      finding: '.data section has high entropy — possibly encrypted payload or config',
      weight: 5,
      corroboratedBy: [],
    });
  }

  if (encryptedBlobSection) {
    signals.push({
      source: 'structure',
      id: 'encrypted-section',
      finding: `Section '${encryptedBlobSection.name}' (${(encryptedBlobSection.file_size / 1024).toFixed(0)} KB) entropy ${encryptedBlobSection.entropy.toFixed(3)}/8.0 — near-maximum entropy blob strongly indicates an encrypted or compressed payload`,
      weight: 9,
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

  // System-enumeration imports: host identity + hardware harvest (RAT / info-stealer)
  const systemEnumCount = countInSet(importNames, SYSTEM_ENUM_IMPORTS);
  if (systemEnumCount >= 2) {
    signals.push({
      source: 'imports',
      id: 'system-enum-imports',
      finding: `${systemEnumCount} system-enumeration API(s): ${matchingNames(importNames, SYSTEM_ENUM_IMPORTS).join(', ')} — host fingerprinting / reconnaissance`,
      weight: 3,
      corroboratedBy: [],
    });
  }

  // Shutdown imports: wiper / drastic-action pattern
  const shutdownCount = countInSet(importNames, SHUTDOWN_IMPORTS);
  if (shutdownCount > 0) {
    signals.push({
      source: 'imports',
      id: 'shutdown-imports',
      finding: `${shutdownCount} system-shutdown API(s): ${matchingNames(importNames, SHUTDOWN_IMPORTS).join(', ')} — wiper or forced-reboot pattern`,
      weight: 7,
      corroboratedBy: [],
    });
  }

  // Thread-manipulation imports: process hollowing / injection primitives
  const threadingCount = countInSet(importNames, THREADING_IMPORTS);
  if (threadingCount >= 2) {
    signals.push({
      source: 'imports',
      id: 'threading-imports',
      finding: `${threadingCount} thread-manipulation API(s): ${matchingNames(importNames, THREADING_IMPORTS).join(', ')}`,
      weight: 3,
      corroboratedBy: [],
    });
  }

  // Import-table anomaly: single-DLL IAT with high entropy = packer stub
  // crackme_shroud imports only from KERNEL32; the stub-like IAT combined with
  // high entropy strongly indicates a packer wrapping the real code.
  const uniqueLibraries = new Set(input.imports.map(i => (i.library ?? '').toLowerCase()));
  if (uniqueLibraries.size <= 1 && input.imports.length >= 1 && highEntropyCount > 0) {
    const dllName = [...uniqueLibraries][0] ?? 'unknown';
    signals.push({
      source: 'imports',
      id: 'import-table-anomaly',
      finding: `IAT references only ${uniqueLibraries.size === 0 ? 'no DLLs' : `one DLL (${dllName})`} — single-library packer stub with ${highEntropyCount} high-entropy section(s)`,
      weight: 8,
      corroboratedBy: ['high-entropy'],
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

  // ── 3b. Script / source-code signals ─────────────────────────────────────
  // Fires for Python, PowerShell, shell scripts, and other text-based files
  // that have no PE/ELF imports but whose source text reveals capabilities.
  const fullText = texts.join('\n');

  // Python dangerous built-ins
  const pyDangerous = (fullText.match(/\b(exec|eval|compile|__import__|execfile|subprocess\.Popen|subprocess\.run|subprocess\.call|os\.system|os\.popen|pty\.spawn)\s*\(/g) || []).length;
  if (pyDangerous > 0) {
    signals.push({
      source: 'strings',
      id: 'script-dangerous-calls',
      finding: `${pyDangerous} dangerous function call(s) in script (exec/eval/subprocess/os.system)`,
      weight: 5 + Math.min(pyDangerous, 4),
      corroboratedBy: [],
    });
  }

  // Python network modules
  const pyNetModules = ['socket', 'requests', 'urllib', 'http.client', 'ftplib', 'smtplib', 'imaplib', 'paramiko', 'scapy'];
  const pyNetHits = pyNetModules.filter(m => fullText.includes(`import ${m}`) || fullText.includes(`from ${m}`));
  if (pyNetHits.length > 0) {
    signals.push({
      source: 'strings',
      id: 'script-network-modules',
      finding: `Script imports network module(s): ${pyNetHits.join(', ')}`,
      weight: 3 + Math.min(pyNetHits.length * 2, 6),
      corroboratedBy: [],
    });
  }

  // Python crypto/obfuscation modules
  const pyCryptoModules = ['base64', 'binascii', 'hashlib', 'cryptography', 'Crypto', 'pycryptodome', 'nacl', 'hmac'];
  const pyCryptoHits = pyCryptoModules.filter(m => fullText.includes(`import ${m}`) || fullText.includes(`from ${m}`));
  if (pyCryptoHits.length > 0) {
    signals.push({
      source: 'strings',
      id: 'script-crypto-modules',
      finding: `Script imports crypto/encoding module(s): ${pyCryptoHits.join(', ')}`,
      weight: 3 + Math.min(pyCryptoHits.length * 2, 5),
      corroboratedBy: [],
    });
  }

  // Python system/process manipulation modules
  const pySysModules = ['ctypes', 'winreg', 'win32api', 'win32con', 'win32process', 'psutil', 'signal'];
  const pySysHits = pySysModules.filter(m => fullText.includes(`import ${m}`) || fullText.includes(`from ${m}`));
  if (pySysHits.length > 0) {
    signals.push({
      source: 'strings',
      id: 'script-system-modules',
      finding: `Script imports system/process module(s): ${pySysHits.join(', ')}`,
      weight: 4 + Math.min(pySysHits.length * 2, 6),
      corroboratedBy: [],
    });
  }

  // PowerShell dangerous patterns
  const psPatterns = (fullText.match(/\b(Invoke-Expression|IEX|Invoke-Command|Start-Process|DownloadString|DownloadFile|WebClient|Net\.WebClient|Reflection\.Assembly|FromBase64String|EncodedCommand|bypass|Hidden|NoProfile)\b/gi) || []).length;
  if (psPatterns > 0) {
    signals.push({
      source: 'strings',
      id: 'script-powershell-dangerous',
      finding: `${psPatterns} dangerous PowerShell pattern(s) detected (Invoke-Expression, WebClient, encoded commands)`,
      weight: 5 + Math.min(psPatterns, 5),
      corroboratedBy: [],
    });
  }

  // Shell script patterns (bash/sh)
  const shPatterns = (fullText.match(/\b(curl|wget|nc\b|ncat|netcat|python -c|perl -e|ruby -e|bash -[ic]|sh -[ic]|chmod \+x|\/dev\/tcp\/|base64 -d)\b/gi) || []).length;
  if (shPatterns > 0) {
    signals.push({
      source: 'strings',
      id: 'script-shell-dangerous',
      finding: `${shPatterns} suspicious shell command(s) detected (curl/wget/nc/base64 decode)`,
      weight: 4 + Math.min(shPatterns, 4),
      corroboratedBy: [],
    });
  }
  // ── 3c. Embedded-runtime / bundled-interpreter signal ─────────────────────
  // PyInstaller and similar tools (cx_Freeze, Nuitka, py2exe) produce executables
  // with an embedded Python interpreter + bytecode + all imported modules.  The
  // resulting binary has an extremely large string catalog: the module source paths,
  // class/function names, and constant strings from every bundled library are all
  // present as ASCII strings in the binary.  A unique-string count above 80,000
  // is essentially impossible for a natively compiled binary — it is a reliable
  // fingerprint of a PyInstaller-style bundle or similarly embedded runtime.
  // Weight 10 → contributes strongly to the "packer" verdict profile.
  if (input.strings.length > 80_000) {
    signals.push({
      source: 'strings',
      id: 'embedded-runtime-bundle',
      finding: `${input.strings.length.toLocaleString()} unique strings extracted — consistent with a PyInstaller / cx_Freeze / Nuitka bundled executable embedding a full Python (or other) interpreter runtime`,
      weight: 10,
      corroboratedBy: [],
    });
  } else if (input.strings.length > 30_000) {
    signals.push({
      source: 'strings',
      id: 'large-string-catalog',
      finding: `${input.strings.length.toLocaleString()} unique strings — unusually large string catalog; may contain embedded scripting runtime or extensive static data`,
      weight: 5,
      corroboratedBy: [],
    });
  }

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

  // Validation / gating logic: comparison-heavy regions or serial checks
  // detected by the static analysis layer (App.tsx detectSuspiciousPatterns).
  // Critical-severity validation regions indicate serial comparisons against
  // constants — characteristic of license checks, auth gates, or anti-tamper
  // routines that are prime targets for patching.
  const validationPatterns = input.patterns.filter(p => p.type === 'validation');
  if (validationPatterns.length > 0) {
    const criticalValidation = validationPatterns.filter(p => p.severity === 'critical');
    const weightBase = 4 + Math.min(validationPatterns.length, 3);
    const weightBoost = criticalValidation.length > 0 ? 3 : 0;
    signals.push({
      source: 'disassembly',
      id: 'validation-logic',
      finding: `${validationPatterns.length} validation/gating logic region(s)${criticalValidation.length > 0 ? ` — ${criticalValidation.length} serial-comparison check(s) (likely auth/license gate)` : ''}`,
      weight: weightBase + weightBoost,
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
    // Mark cross-signal corroboration so the UI can show the relationship
    const networkSigs  = signals.filter(s => ['network-imports', 'embedded-urls', 'hardcoded-ips'].includes(s.id));
    const injectionSig = signals.find(s => s.id === 'injection-imports');
    if (injectionSig) {
      for (const ns of networkSigs) {
        if (!ns.corroboratedBy.includes('injection-imports')) ns.corroboratedBy.push('injection-imports');
        if (!injectionSig.corroboratedBy.includes(ns.id))    injectionSig.corroboratedBy.push(ns.id);
      }
    }
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

  // ── RAT-composite signal ────────────────────────────────────────────────────
  // Fires when ≥ 3 of 5 RAT-characteristic signal categories co-occur.  Each
  // category alone is ambiguous; their conjunction is highly specific to
  // info-stealers and remote-access trojans.
  //   1. network      — network-imports, embedded-urls, or hardcoded-ips
  //   2. anti-debug   — antidebug-imports / talon-anti-debug / strike-anti-debug
  //   3. system-enum  — system-enum-imports present
  //   4. os-fingerprint — at least 2 system-enum APIs including GetVersionEx*
  //                       or GlobalMemoryStatusEx
  //   5. threading    — threading-imports present
  const OS_FINGERPRINT = new Set(['GetVersionExA','GetVersionExW','RtlGetVersion','GlobalMemoryStatusEx','GlobalMemoryStatus']);
  const ratHits = [
    hasNetworkSignal,
    signals.some(s => s.id === 'antidebug-imports' || s.id === 'talon-anti-debug' || s.id === 'strike-anti-debug'),
    signals.some(s => s.id === 'system-enum-imports'),
    systemEnumCount >= 1 && countInSet(importNames, OS_FINGERPRINT) > 0,
    signals.some(s => s.id === 'threading-imports'),
  ].filter(Boolean).length;

  if (ratHits >= 3) {
    const corrobIds = signals
      .filter(s => ['network-imports','antidebug-imports','system-enum-imports','threading-imports'].includes(s.id))
      .map(s => s.id);
    signals.push({
      source: 'imports',
      id: 'rat-composite',
      finding: `RAT/info-stealer composite: ${ratHits}/5 co-occurring characteristic signal categories (system-enum, OS-fingerprint, network, anti-debug, thread-manip) — high-specificity indicator`,
      weight: 12,
      corroboratedBy: corrobIds,
    });
    amplifiers.push('RAT composite: ≥3 RAT-characteristic signal families co-occurring — high specificity for info-stealer or remote-access trojan');
    bumpWeights(signals, ['network-imports','antidebug-imports','system-enum-imports','threading-imports'], 2);
  }

  // ── Wiper-composite signal ──────────────────────────────────────────────────
  // Fires when: cryptographic API(s) AND process-execution API(s) AND
  // system-shutdown API(s) all co-occur.  BCryptDecrypt + CreateProcessA +
  // ExitWindowsEx is the canonical wiper execution chain: decrypt payload,
  // run it, then force a reboot to hinder recovery.
  if (hasCryptoSignal && hasExecSignal(signals) && signals.some(s => s.id === 'shutdown-imports')) {
    const corrobIds = signals
      .filter(s => ['crypto-imports','exec-imports','shutdown-imports'].includes(s.id))
      .map(s => s.id);
    signals.push({
      source: 'imports',
      id: 'wiper-composite',
      finding: 'Wiper-composite: cryptographic decryption + process-execution + system-shutdown APIs co-occur — canonical dropper/wiper execution chain',
      weight: 11,
      corroboratedBy: corrobIds,
    });
    amplifiers.push('Wiper composite: decrypt → execute → shutdown triad matches destructive dropper or wiper profile');
    bumpWeights(signals, ['crypto-imports','exec-imports','shutdown-imports'], 3);
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

  // Framework-import suppression: when ≥ 40 % of all IAT entries come from
  // known SDK/runtime DLLs (Qt6, MSVC C++ runtime), the inflated import count
  // reflects statically-linked framework code, not malicious capability.  This
  // prevents the large-import heuristics from being fooled by Qt-based apps.
  const frameworkImports = input.imports.filter(i =>
    FRAMEWORK_DLL_PATTERNS.some(p => p.test(i.library ?? ''))
  );
  const frameworkFraction = input.imports.length > 0
    ? frameworkImports.length / input.imports.length
    : 0;
  if (frameworkFraction >= 0.4 && frameworkImports.length >= 20) {
    const frameworkPct = Math.round(frameworkFraction * 100);
    const reduction    = Math.min(15, Math.round(frameworkFraction * 20));
    negativeSignals.push({
      id: 'framework-imports',
      finding: `${frameworkPct}% of imports from known SDK/runtime DLLs (Qt6, MSVC C++ runtime) — large IAT is framework overhead, not malicious capability`,
      reduction,
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

  // ── 8. Evidence-tier confidence ───────────────────────────────────────────
  //
  // Confidence reflects evidence QUALITY, not signal count.
  // Signals are bucketed into three tiers; each tier has a per-signal point
  // value and a hard ceiling so that spam (e.g. many string matches) cannot
  // push confidence to levels that only runtime-confirmed evidence warrants.
  //
  //   DIRECT  — STRIKE runtime execution traces   20 pts each, ≤ 40 total
  //   STRONG  — imports, signatures, TALON/ECHO   10 pts each, ≤ 35 total
  //   WEAK    — strings, entropy, heuristics       3 pts each, ≤ 10 total
  //
  // Cross-signal amplifiers (corroboration) and negative signals add smaller
  // bonuses; they reward completeness rather than volume.
  // TALON/STRIKE/ECHO sections (17–19) may still add small conditional bonuses
  // to `confidence` after this point for specific high-quality conditions.

  const directSigsBase = signals.filter(s => signalEvidenceTier(s) === 'DIRECT');
  const strongSigsBase = signals.filter(s => signalEvidenceTier(s) === 'STRONG');
  const weakSigsBase   = signals.filter(s => signalEvidenceTier(s) === 'WEAK');

  const directContribBase = Math.min(directSigsBase.length * 20, 40);
  const strongContribBase = Math.min(strongSigsBase.length * 10, 35);
  const weakContribBase   = Math.min(weakSigsBase.length   *  3, 10);
  const ampContribBase    = amplifiers.length * 6;
  const negContribBase    = negativeSignals.length * 3;
  const win32ContribBase  = isWin32StandardApp ? 8 : 0;

  // `preDampenConfidence` is recorded for the breakdown output (computed again
  // after all signals including TALON/STRIKE/ECHO at the end of computeVerdict).
  let preDampenConfidence = Math.min(99, Math.round(
    15 +
    directContribBase + strongContribBase + weakContribBase +
    ampContribBase + negContribBase + win32ContribBase
  ));
  let confidence = preDampenConfidence;

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
    hasWiperSignal: signals.some(s => s.id === 'wiper-composite'),
    hasEmbeddedRuntime: signals.some(s => s.id === 'embedded-runtime-bundle'),
    hasRatComposite: signals.some(s => s.id === 'rat-composite'),
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
  // Composite behavioral tags derived from rat/wiper composites
  if (signals.some(s => s.id === 'rat-composite')) {
    if (!behaviors.includes('c2-communication'))   behaviors.push('c2-communication');
    if (!behaviors.includes('data-exfiltration'))  behaviors.push('data-exfiltration');
    if (!behaviors.includes('anti-analysis'))      behaviors.push('anti-analysis');
  }
  if (signals.some(s => s.id === 'wiper-composite')) {
    if (!behaviors.includes('file-destruction'))   behaviors.push('file-destruction');
    if (!behaviors.includes('process-execution'))  behaviors.push('process-execution');
    if (!behaviors.includes('code-decryption'))    behaviors.push('code-decryption');
  }
  if (signals.some(s => s.id === 'import-table-anomaly')) {
    if (!behaviors.includes('code-decryption'))    behaviors.push('code-decryption');
  }
  if (signals.some(s => s.id === 'encrypted-section')) {
    if (!behaviors.includes('code-decryption'))    behaviors.push('code-decryption');
  }

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

  // ── 16.5. YARA rule signals ───────────────────────────────────────────────
  // Each matching YARA rule becomes one CorrelatedSignal on source:'signatures'.
  // Rules with a `threat_class` that matches an existing signal ID corroborate
  // that signal (increasing its weight) rather than duplicating it.
  // Rules without a match create a fresh signal so every YARA hit is traceable.
  const SEVERITY_WEIGHT: Record<string, number> = {
    critical: 9, high: 7, medium: 5, low: 3,
  };
  const THREAT_CLASS_TO_SIGNAL: Record<string, string> = {
    packer:     'packer-stub',
    ransomware: 'ransomware-composite',
    injection:  'injection-imports',
    'anti-debug': 'antidebug-imports',
    c2:         'network-imports',
    crypto:     'crypto-imports',
    dropper:    'rat-composite',
    persistence:'registry-imports',
    rat:        'rat-composite',
    cryptominer:'network-imports',
  };

  for (const ym of input.yaraMatches ?? []) {
    const sigId = `yara-${ym.ruleName.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
    const weight = Math.min(10,
      ym.meta.weight ?? SEVERITY_WEIGHT[ym.meta.severity ?? ''] ?? 5,
    );

    // Build an offset list for the first 3 matched strings
    const topOffsets = ym.matchedStrings
      .slice(0, 3)
      .map(ms => `${ms.identifier}@0x${ms.offset.toString(16).toUpperCase()}`)
      .join(', ');
    const locationHint = topOffsets ? ` [${topOffsets}]` : '';

    const description = ym.meta.description ?? ym.ruleName;
    const finding = `YARA/${ym.ruleName}: ${description}${locationHint}`;

    // Propagate behavioral tags from meta.behaviors
    if (ym.meta.behaviors) {
      for (const b of ym.meta.behaviors) {
        if (!behaviors.includes(b)) behaviors.push(b);
      }
    }

    // Try to corroborate an existing signal matching this rule's threat_class
    const corrobTargetId = THREAT_CLASS_TO_SIGNAL[ym.meta.threat_class ?? ''];
    // Also check rule tags as fallback corroboration keys
    const tagCorrobId = ym.tags.length > 0
      ? THREAT_CLASS_TO_SIGNAL[ym.tags[0].toLowerCase().replace(/_/g, '-')] ?? null
      : null;
    const targetId = corrobTargetId ?? tagCorrobId ?? null;

    const existing = targetId ? signals.find(s => s.id === targetId) : null;

    if (existing) {
      // Corroborate the existing signal and add a lighter YARA signal
      if (!existing.corroboratedBy.includes(sigId)) {
        existing.corroboratedBy.push(sigId);
        existing.weight = Math.min(10, existing.weight + 1);
      }
      // Still emit the YARA signal separately so it's visible and traceable
      if (!signals.some(s => s.id === sigId)) {
        signals.push({
          source:        'signatures',
          id:            sigId,
          finding,
          weight:        Math.max(1, weight - 2),
          corroboratedBy: [existing.id],
          locations:     ym.matchedStrings.slice(0, 4).map(ms => ({
            address: ms.offset,
            kind:    'instruction' as const,
            label:   `${ms.identifier}@0x${ms.offset.toString(16).toUpperCase()}`,
            context: `Matched: ${ms.value} (${ms.length} bytes)`,
          })),
        });
      }
    } else {
      // No existing signal to corroborate — create a new one
      if (!signals.some(s => s.id === sigId)) {
        signals.push({
          source:        'signatures',
          id:            sigId,
          finding,
          weight,
          corroboratedBy: [],
          locations:     ym.matchedStrings.slice(0, 4).map(ms => ({
            address: ms.offset,
            kind:    'instruction' as const,
            label:   `${ms.identifier}@0x${ms.offset.toString(16).toUpperCase()}`,
            context: `Matched: ${ms.value} (${ms.length} bytes)`,
          })),
        });
      }
    }
  }

  // ── 16.6. MYTHOS capability signals ────────────────────────────────────────
  // Each MythosCapabilityMatch → one CorrelatedSignal on source:'signatures'.
  // Capabilities that overlap with existing signals corroborate them (+1 weight).
  // Each signal's finding includes the evidence chain and code locations so the
  // analyst can trace exactly WHY the capability was detected.
  for (const mc of input.mythosMatches ?? []) {
    const sigId = `mythos-${mc.id}`;

    // Build finding: capability name + evidence chain + top locations
    const topLocs = mc.locations
      .filter(l => l.address !== 0 || l.kind === 'import')
      .slice(0, 3)
      .map(l => l.label)
      .join(', ');
    const locText   = topLocs ? ` [${topLocs}]` : '';
    const evText    = mc.evidence.slice(0, 3).join('; ');
    const finding   = `MYTHOS/${mc.name}: ${mc.description}${locText} — ${evText}`;

    // Weight: use the capability's own weight, scaled by confidence
    const weight    = Math.round(mc.weight * (mc.confidence / 100));

    // Look for an existing signal to corroborate based on capability namespace
    const nsRoot    = mc.namespace.split('/')[0];
    const MYTHOS_CORROBORATION: Record<string, string> = {
      'host-interaction':  'injection-imports',
      'anti-analysis':     'antidebug-imports',
      'persistence':       'registry-imports',
      'communication':     'network-imports',
      'data-manipulation': 'crypto-imports',
      'malware':           'ransomware-composite',
      'credential-access': 'rat-composite',
      'impact':            'wiper-imports',
    };
    const corrobTargetId = MYTHOS_CORROBORATION[nsRoot] ?? null;
    const corrobTarget   = corrobTargetId ? signals.find(s => s.id === corrobTargetId) : null;

    if (corrobTarget) {
      if (!corrobTarget.corroboratedBy.includes(sigId)) {
        corrobTarget.corroboratedBy.push(sigId);
        corrobTarget.weight = Math.min(10, corrobTarget.weight + 1);
      }
    }

    // Always emit the Mythos signal itself (never de-weight — capabilities are primary evidence)
    if (!signals.some(s => s.id === sigId)) {
      signals.push({
        source:         'signatures',
        id:             sigId,
        finding,
        weight:         Math.max(1, weight),
        corroboratedBy: corrobTarget ? [corrobTarget.id] : [],
        // Attach all navigable locations from the Mythos capability match
        locations:      mc.locations.map(l => ({
          address: l.address,
          kind:    l.kind as SignalLocation['kind'],
          label:   l.label,
          context: l.context,
        })),
        // Full evidence chain so the UI can explain WHY this rule fired
        evidence:       mc.evidence,
      });
    }

    // Propagate behavioral tags
    for (const b of mc.behaviors) {
      if (!behaviors.includes(b)) behaviors.push(b);
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
    // RAT-composite corroboration: if runtime shows anti-debug + peb-walk +
    // dynamic-api-resolution together, corroborate the static rat-composite
    // signal (or create a runtime-only version if static analysis missed it).
    if (s.hasAntiDebugProbe && s.hasPebWalk && s.hasDynamicApiResolution) {
      const existing = signals.find(sig => sig.id === 'rat-composite');
      if (existing) {
        if (!existing.corroboratedBy.includes('strike-rat-runtime')) {
          existing.corroboratedBy.push('strike-rat-runtime');
          existing.weight = Math.min(10, existing.weight + 2);
        }
      } else {
        signals.push({ source: 'disassembly', id: 'strike-rat-runtime', finding: 'STRIKE: runtime anti-debug probe + PEB walk + dynamic API resolution co-observed — covert RAT behavior pattern', weight: 10, corroboratedBy: [] });
        if (!behaviors.includes('dynamic-resolution')) behaviors.push('dynamic-resolution');
        if (!behaviors.includes('anti-analysis'))      behaviors.push('anti-analysis');
      }
    }
    // Wiper-composite corroboration: unpacking + exception probe + ROP at runtime
    // is consistent with a wiper that decrypts and self-executes its payload.
    if ((s.hasUnpackingBehavior || s.hasRopActivity) && s.hasExceptionProbe) {
      const existing = signals.find(sig => sig.id === 'wiper-composite');
      if (existing) {
        if (!existing.corroboratedBy.includes('strike-wiper-runtime')) {
          existing.corroboratedBy.push('strike-wiper-runtime');
          existing.weight = Math.min(10, existing.weight + 2);
        }
      }
      if (!behaviors.includes('code-decryption')) behaviors.push('code-decryption');
    }
  } // end if (input.strikeSignals)

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
    if (e.hasStringDecode) {
      const existing = signals.find(sig => sig.id === 'echo-string-decode' || sig.id.includes('string-decode'));
      if (existing) {
        if (!existing.corroboratedBy.includes('echo-string-decode')) existing.corroboratedBy.push('echo-string-decode');
        existing.weight = Math.min(10, existing.weight + 1);
      } else {
        signals.push({ source: 'disassembly', id: 'echo-string-decode', finding: 'ECHO: runtime string decode/deobfuscation pattern recognized (stack strings, XOR decode, or lookup-table decode)', weight: 6, corroboratedBy: [] });
      }
      if (!behaviors.includes('code-decryption')) behaviors.push('code-decryption');
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

  // ── Evidence-tier breakdown (all signals, after TALON/STRIKE/ECHO) ─────────
  // Recompute using the complete signal set so the breakdown reflects every
  // signal source including TALON (§17), STRIKE (§18), and ECHO (§19).
  const directAll = signals.filter(s => signalEvidenceTier(s) === 'DIRECT');
  const strongAll = signals.filter(s => signalEvidenceTier(s) === 'STRONG');
  const weakAll   = signals.filter(s => signalEvidenceTier(s) === 'WEAK');

  const evidenceTierBreakdown: EvidenceTierBreakdown = {
    direct: {
      signalCount:  directAll.length,
      contribution: Math.min(directAll.length * 20, 40),
      signals:      directAll.map(s => s.id),
    },
    strong: {
      signalCount:  strongAll.length,
      contribution: Math.min(strongAll.length * 10, 35),
      signals:      strongAll.map(s => s.id),
    },
    weak: {
      signalCount:  weakAll.length,
      contribution: Math.min(weakAll.length * 3, 10),
      signals:      weakAll.map(s => s.id),
    },
    preDampenConfidence,
  };

  // Tag each signal with its evidence tier so downstream consumers can
  // display tier-annotated signal lists without re-computing.
  for (const sig of signals) {
    sig.tier = signalEvidenceTier(sig);
  }

  // ── Certainty annotation (Prompt 10 — Trusted Acceleration) ──────────────
  // Each signal receives a CertaintyLevel that answers "how do we know this?"
  for (const sig of signals) {
    if (sig.certainty != null) continue; // preserve if already set by caller

    // DIRECT runtime evidence is always 'observed'
    if (sig.id.startsWith('strike-')) {
      sig.certainty = 'observed';
      continue;
    }

    // Import-table entries and literal string finds are directly present in the binary
    if (sig.source === 'imports' || sig.source === 'strings') {
      sig.certainty = 'observed';
      continue;
    }

    // Certain structure signals are direct measurements
    if (sig.source === 'structure') {
      const observed = ['high-entropy', 'elevated-entropy', 'minimal-imports', 'unusual-section-names', 'import-table-anomaly'];
      sig.certainty = observed.includes(sig.id) ? 'observed' : 'inferred';
      continue;
    }

    // YARA rules matched literal bytes or hex patterns — directly observed
    if (sig.id.startsWith('yara-')) {
      sig.certainty = 'observed';
      continue;
    }

    // MYTHOS capability signals are derived from multiple evidence types — inferred
    // (each is the conclusion of a boolean-AND/OR rule over imports+strings+patterns)
    if (sig.id.startsWith('mythos-')) {
      sig.certainty = 'inferred';
      continue;
    }

    // TALON decompiler analysis: source-level derivation — inferred
    if (sig.id.startsWith('talon-')) {
      sig.certainty = 'inferred';
      continue;
    }

    // Composites are always inferred (require multiple confirmed inputs)
    if (sig.id.endsWith('-composite') || sig.source === 'signatures') {
      sig.certainty = 'inferred';
      continue;
    }

    // ECHO signals are fuzzy-matched — heuristic
    if (sig.id.startsWith('echo-')) {
      sig.certainty = 'heuristic';
      continue;
    }

    // Disassembly pattern matches are heuristic by nature
    sig.certainty = 'heuristic';
  }

  // ── Uncertainty flags (Prompt 10 — surface when system is guessing) ───────
  const uncertaintyFlags: string[] = [];
  const heuristicSignalIds: string[] = signals
    .filter(s => s.certainty === 'heuristic')
    .map(s => s.id);

  if (signals.length < 3) {
    uncertaintyFlags.push(
      `Uncertain: only ${signals.length} signal(s) collected — verdict may change with additional analysis passes.`,
    );
  }

  const heuristicFraction = signals.length > 0 ? heuristicSignalIds.length / signals.length : 0;
  if (heuristicFraction > 0.6 && signals.length >= 3) {
    uncertaintyFlags.push(
      `Uncertain: ${Math.round(heuristicFraction * 100)}% of signals are heuristic (pattern-matched) — human verification is recommended before acting on this verdict.`,
    );
  }

  const hasDirectEvidence = signals.some(s => s.id.startsWith('strike-'));
  if (!hasDirectEvidence && signals.length > 0) {
    uncertaintyFlags.push(
      'Uncertain: no runtime execution evidence (STRIKE) was collected — static analysis only; behaviour could differ at runtime.',
    );
  }

  if (contradictions.length > 2) {
    uncertaintyFlags.push(
      `Uncertain: ${contradictions.length} conflicting evidence pairs detected — verdict stability may be lower than confidence score suggests.`,
    );
  }

  if (confidence < 50 && signals.length > 0) {
    uncertaintyFlags.push(
      `Uncertain: confidence is ${confidence}% — below the 50% threshold; more disassembly passes are recommended.`,
    );
  }

  // ── 20. Alternative hypotheses ────────────────────────────────────────────
  const alternatives = buildAlternatives(classification, behaviors, negativeSignals, {
    hasHighEntropy, hasNetworkSignal, hasCryptoSignal, hasInjectionSignal,
    hasFileSignal, hasRegistrySignal, threatScore, confidence
  });

  // ── 21. Agent-injected signals (analyst-approved, source:'agent') ─────────
  if (input.agentSignals && input.agentSignals.length > 0) {
    for (const ag of input.agentSignals) {
      signals.push({
        source: 'agent',
        id: ag.id,
        finding: ag.finding,
        weight: Math.max(0, Math.min(10, ag.weight)),
        corroboratedBy: [],
        certainty: ag.certainty ?? 'heuristic',
        tier: ag.weight >= 7 ? 'DIRECT' : ag.weight >= 4 ? 'STRONG' : 'WEAK',
      });
    }
  }

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
    evidenceTierBreakdown,
    uncertaintyFlags,
    heuristicSignalIds,
  };
}

// ─── Evidence-tier classifier ─────────────────────────────────────────────────

/**
 * Classify a correlated signal into an evidence tier.
 *
 *   DIRECT — observed during live execution (STRIKE runtime traces).
 *            These are the most trustworthy signals: behaviour was confirmed
 *            by actually running the binary under a debugger.
 *
 *   STRONG — structural declarations or deep static analysis: import table
 *            entries (API capability declarations), known-pattern signature
 *            matches, TALON decompiler-confirmed code patterns, ECHO injection/
 *            crypto pattern matches, and corroborated multi-signal composites.
 *            Control-flow–anomaly signals (anti-analysis, indirect calls,
 *            critical disassembly patterns) also qualify.
 *
 *   WEAK   — heuristic / observational evidence: entropy measurements, string
 *            content (URLs, base64, registry paths, PE names), tight-loop
 *            counts, and ECHO string-decode observations.  Many of these fire
 *            on benign binaries; they add colour but must not inflate confidence
 *            on their own.
 */
export function signalEvidenceTier(signal: CorrelatedSignal): EvidenceTier {
  // DIRECT — runtime execution evidence (STRIKE debugger traces)
  if (signal.id.startsWith('strike-')) return 'DIRECT';

  // STRONG — structural / declaration-level / deep-analysis signals
  if (
    signal.source === 'imports'                   ||  // declared API capabilities
    signal.source === 'signatures'                ||  // known-pattern match
    signal.id.startsWith('talon-')               ||  // decompiler-confirmed
    signal.id.startsWith('yara-')                ||  // YARA rule: matched literal bytes
    signal.id === 'echo-crypto'                  ||  // ECHO: crypto algorithm
    signal.id === 'echo-injection'               ||  // ECHO: injection pattern
    signal.id === 'critical-patterns'            ||  // disasm: critical severity
    signal.id === 'anti-analysis-patterns'       ||  // disasm: anti-analysis
    signal.id === 'indirect-calls'               ||  // disasm: CFG hiding
    signal.id === 'validation-logic'             ||  // disasm: comparison/gating regions
    signal.id.endsWith('-composite')                 // multi-signal corroborated
  ) return 'STRONG';

  // WEAK — heuristic / observational (strings, entropy, loose pattern counts)
  return 'WEAK';
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
  hasWiperSignal: boolean;
  /** True when string count signals an embedded runtime bundle (PyInstaller, etc.) */
  hasEmbeddedRuntime: boolean;
  /** True when the rat-composite signal fired (≥3/5 RAT-characteristic categories) */
  hasRatComposite: boolean;
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
  // rat-composite fires when ≥3/5 RAT-characteristic signal families co-occur
  // (system-enum, OS-fingerprint, network, anti-debug, thread-manip).
  // This catches modern RATs that use SRW locks and WSA sockets but omit
  // classic injection APIs (VirtualAllocEx, WriteProcessMemory).
  if (c.hasRatComposite && c.hasNetworkSignal && c.threatScore >= 30) return 'rat';

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

  // Wiper: file-destruction + shutdown + crypto, no network or injection
  // (injection → dropper, network → could be ransomware if also file+crypto)
  // The wiper-composite signal guards the entry condition.
  if (c.hasWiperSignal && !c.hasInjectionSignal && !c.hasNetworkSignal && c.threatScore >= 35) return 'wiper';
  if (c.hasWiperSignal && c.hasFileSignal && c.threatScore >= 45) return 'wiper';

  // Loader: minimal imports + high entropy + dynamic load
  if (c.hasMinimalImports && c.hasHighEntropy) return 'packer';

  // PyInstaller / bundled runtime: large string catalog signals embedded interpreter
  if (c.hasEmbeddedRuntime) return 'packer';

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
  wiper:           'Wiper',
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
    wiper:             'Wiper — destroys or overwrites data; may corrupt filesystem or MBR',
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

