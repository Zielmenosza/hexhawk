/**
 * Auto-Annotation Engine
 *
 * Automatically generates meaningful annotations for binary artifacts
 * based on static heuristics. Each annotation carries a confidence score
 * and can be accepted/rejected by the analyst.
 *
 * Rules:
 * - Only annotate things the user hasn't explicitly annotated yet
 * - Every annotation must explain WHY it was created
 * - Confidence = 0–100; threshold for display = 40
 */

import type { SuspiciousPattern } from '../App';

// ─── Public types ─────────────────────────────────────────────────────────────

export type AnnotationCategory =
  | 'suspicious'
  | 'dangerous'
  | 'info'
  | 'network'
  | 'persistence'
  | 'evasion'
  | 'injection'
  | 'crypto'
  | 'execution';

export interface AutoAnnotation {
  id: string;
  /** Instruction address (for disassembly-level annotations) */
  address?: number;
  /** Offset into the strings table (for string-level annotations) */
  stringOffset?: number;
  /** Import name being annotated */
  importName?: string;
  /** The annotation text shown to the analyst */
  text: string;
  /** Short label shown in badges/chips */
  label: string;
  /** 0–100 confidence score */
  confidence: number;
  category: AnnotationCategory;
  /** null = not reviewed; true = accepted; false = rejected */
  accepted: boolean | null;
  /** One-sentence explanation of why this annotation was generated */
  rationale: string;
}

export interface AutoAnnotationInput {
  imports: Array<{ name: string; library: string }>;
  strings: Array<{ offset: number; text: string }>;
  disassembly: Array<{ address: number; mnemonic: string; operands: string }>;
  patterns: SuspiciousPattern[];
  averageEntropy?: number;
  sectionEntropies?: Array<{ name: string; entropy: number }>;
}

// ─── Import annotation rules ──────────────────────────────────────────────────

interface ImportRule {
  match: RegExp;
  text: string;
  label: string;
  confidence: number;
  category: AnnotationCategory;
  rationale: string;
}

const IMPORT_RULES: ImportRule[] = [
  // Injection trio
  { match: /^VirtualAllocEx$/,         text: 'Allocates memory in a remote process — first step in process injection.', label: 'Injection: remote alloc', confidence: 90, category: 'injection', rationale: 'VirtualAllocEx is exclusively used with a remote process handle for injection.' },
  { match: /^WriteProcessMemory$/,     text: 'Writes data into a remote process — second step in classic process injection.', label: 'Injection: write', confidence: 88, category: 'injection', rationale: 'WriteProcessMemory is almost always paired with VirtualAllocEx and CreateRemoteThread.' },
  { match: /^CreateRemoteThread(Ex)?$/, text: 'Starts execution in a remote process — final step in process injection.', label: 'Injection: execute', confidence: 92, category: 'injection', rationale: 'CreateRemoteThread completes the inject/write/execute injection triad.' },
  { match: /^NtCreateThreadEx$/,       text: 'NT-level remote thread creation — evasive process injection bypassing user-mode hooks.', label: 'Injection: NT-level', confidence: 95, category: 'injection', rationale: 'NtCreateThreadEx bypasses security product hooking on CreateRemoteThread.' },
  // Anti-debug
  { match: /^IsDebuggerPresent$/,          text: 'Checks if a debugger is attached — anti-analysis evasion technique.', label: 'Anti-debug check', confidence: 80, category: 'evasion', rationale: 'Used to alter behavior or terminate when debugged.' },
  { match: /^CheckRemoteDebuggerPresent$/, text: 'Checks for remote debugger presence — sophisticated anti-analysis evasion.', label: 'Anti-debug: remote', confidence: 85, category: 'evasion', rationale: 'Detects kernel-attached debuggers missed by IsDebuggerPresent.' },
  { match: /^NtQueryInformationProcess$/, text: 'Queries process internals — can detect debuggers via ProcessDebugPort flag.', label: 'Anti-debug: NT query', confidence: 75, category: 'evasion', rationale: 'Querying ProcessDebugPort (0x7) is a common anti-debug technique.' },
  // Dynamic loading
  { match: /^GetProcAddress$/,   text: 'Resolves API addresses at runtime — can hide imports from static analysis.', label: 'Dynamic API resolve', confidence: 70, category: 'evasion', rationale: 'Combined with LoadLibrary, enables import-hiding obfuscation.' },
  { match: /^LoadLibraryA?W?$/,  text: 'Loads a DLL at runtime — used by packers and obfuscated code to hide dependencies.', label: 'Dynamic DLL load', confidence: 65, category: 'evasion', rationale: 'Packers commonly import only LoadLibrary + GetProcAddress to hide all other APIs.' },
  // Persistence
  { match: /^RegSetValueEx[AW]?$/, text: 'Writes to registry — commonly used to install autorun persistence keys.', label: 'Registry write', confidence: 72, category: 'persistence', rationale: 'Writing to HKCU/HKLM Run keys is the most common registry persistence method.' },
  { match: /^CreateService[AW]?$/, text: 'Creates a Windows service — enables persistent execution even after reboot.', label: 'Service install', confidence: 85, category: 'persistence', rationale: 'Service creation provides system-level persistence and autostart.' },
  // Network
  { match: /^InternetConnect[AW]?$/,   text: 'Opens connection to remote server — enables command-and-control communication.', label: 'C2 connect', confidence: 78, category: 'network', rationale: 'WinINet connection to a remote host for data transfer or instructions.' },
  { match: /^WSAStartup$/,             text: 'Initializes Winsock — required before any socket-based network communication.', label: 'Winsock init', confidence: 60, category: 'network', rationale: 'WSAStartup is always the first call in socket-based network code.' },
  { match: /^URLDownloadToFile[AW]?$/, text: 'Downloads a file from a URL — classic dropper and payload-fetching technique.', label: 'URL download', confidence: 90, category: 'network', rationale: 'URLDownloadToFile downloads and saves remote files; used by many droppers.' },
  // Execution
  { match: /^ShellExecute[AW]?$/,   text: 'Launches a file or program — may execute a downloaded or extracted payload.', label: 'Shell launch', confidence: 65, category: 'execution', rationale: 'ShellExecute is commonly used to run dropped payloads or system commands.' },
  { match: /^CreateProcess[AW]?$/,  text: 'Creates a child process — may spawn a payload or command-line utility.', label: 'Process create', confidence: 60, category: 'execution', rationale: 'CreateProcess is used by droppers, launchers, and lateral movement tools.' },
  // Crypto
  { match: /^CryptEncrypt$/,         text: 'Encrypts data using CryptoAPI — may encrypt files (ransomware) or encode exfil data.', label: 'CryptoAPI encrypt', confidence: 75, category: 'crypto', rationale: 'CryptEncrypt operating on file data is a core ransomware pattern.' },
  { match: /^BCryptEncrypt$/,        text: 'Encrypts data via BCrypt — modern crypto API; used in ransomware and legitimate encryption.', label: 'BCrypt encrypt', confidence: 70, category: 'crypto', rationale: 'BCrypt is more commonly seen in modern ransomware variants.' },
];

// ─── String annotation rules ──────────────────────────────────────────────────

interface StringRule {
  match: RegExp;
  text: string;
  label: string;
  confidence: number;
  category: AnnotationCategory;
  rationale: string;
}

const STRING_RULES: StringRule[] = [
  // URLs / IPs
  { match: /^https?:\/\//i,           text: 'Hardcoded URL — potential command-and-control or payload download address.', label: 'Hardcoded URL', confidence: 82, category: 'network', rationale: 'Hardcoded URLs are commonly C2 endpoints or download locations.' },
  { match: /^\d{1,3}(\.\d{1,3}){3}$/, text: 'Hardcoded IP address — potential C2 or staging server.', label: 'Hardcoded IP', confidence: 85, category: 'network', rationale: 'Bare IPs (no domain) are common in malware trying to avoid DNS-based detection.' },
  // Registry paths
  { match: /HKEY_(LOCAL_MACHINE|CURRENT_USER).*\\Run/i, text: 'Autorun registry path — likely used for persistence installation.', label: 'Autorun path', confidence: 90, category: 'persistence', rationale: 'Run keys under HKLM/HKCU are the most common Windows persistence location.' },
  { match: /System\\CurrentControlSet\\Services/i, text: 'Service registry path — may be used for service-based persistence.', label: 'Service path', confidence: 85, category: 'persistence', rationale: 'Writing to Services registry key installs or modifies a Windows service.' },
  // Temp / dropped file paths
  { match: /%TEMP%.*\.(exe|dll|bat|ps1|vbs)/i, text: 'Dropped payload path in %TEMP% — file likely extracted and executed at runtime.', label: 'Dropped payload path', confidence: 88, category: 'execution', rationale: 'Writing executables to TEMP is a classic dropper staging technique.' },
  { match: /%APPDATA%.*\.(exe|dll)/i,           text: 'Persistence artifact path in %APPDATA% — common location for disguised executables.', label: 'AppData exe', confidence: 80, category: 'suspicious', rationale: 'Copying executables to AppData is a user-space persistence technique.' },
  // Anti-VM strings
  { match: /vmware|virtualbox|vbox|qemu|sandboxie|wireshark/i, text: 'Anti-VM / anti-sandbox artifact name — binary may check for analysis environments.', label: 'Anti-VM string', confidence: 88, category: 'evasion', rationale: 'Checking for these strings is used to detect and evade sandbox analysis.' },
  // Ransom note indicators
  { match: /bitcoin|monero|wallet|ransom|decrypt.*files|pay.*bitcoin/i, text: 'Ransomware payment string — suggests extortion message or wallet reference.', label: 'Ransom note', confidence: 92, category: 'suspicious', rationale: 'These terms are almost exclusively found in ransomware payment demand messages.' },
  // Password / credential terms
  { match: /password|credentials|passwd|login.*pass/i, text: 'Credential-related string — may indicate credential harvesting functionality.', label: 'Credential string', confidence: 70, category: 'suspicious', rationale: 'Password-related strings suggest credential access or credential prompt spoofing.' },
  // Command shell invocations
  { match: /cmd\.exe\s*(\/c|\/k)/i, text: 'Command prompt invocation — shell command likely executed via CreateProcess or WinExec.', label: 'cmd.exe invocation', confidence: 78, category: 'execution', rationale: 'cmd.exe /c is used to run system commands, often for lateral movement or persistence.' },
  { match: /powershell\.exe.*-[Ee]nc/i, text: 'PowerShell with Base64-encoded command — common obfuscation for PowerShell payloads.', label: 'PS encoded cmd', confidence: 92, category: 'execution', rationale: 'PowerShell -EncodedCommand hides the actual command from simple string scanning.' },
];

// ─── Disassembly annotation rules ────────────────────────────────────────────

const DANGEROUS_CALL_TARGETS = new Set([
  'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'NtCreateThreadEx',
  'GetProcAddress', 'LoadLibraryA', 'LoadLibraryW', 'ShellExecuteA', 'ShellExecuteW',
  'CreateProcessA', 'CreateProcessW', 'URLDownloadToFileA', 'URLDownloadToFileW',
  'RegSetValueExA', 'RegSetValueExW', 'CryptEncrypt', 'BCryptEncrypt',
  'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
]);

// ─── ID generation ────────────────────────────────────────────────────────────

let _counter = 0;
function mkId(prefix: string): string {
  return `aa-${prefix}-${++_counter}`;
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Generate auto-annotations for a binary. Call this after every new data load.
 * The `existingAddresses` set prevents double-annotating anything already annotated by the user.
 */
export function generateAutoAnnotations(
  input: AutoAnnotationInput,
  existingAddresses: Set<number | string> = new Set(),
): AutoAnnotation[] {
  _counter = 0;
  const result: AutoAnnotation[] = [];

  // ── Import annotations ────────────────────────────────────────────────────
  for (const imp of input.imports) {
    if (existingAddresses.has(imp.name)) continue;
    for (const rule of IMPORT_RULES) {
      if (rule.match.test(imp.name)) {
        result.push({
          id: mkId('imp'),
          importName: imp.name,
          text: rule.text,
          label: rule.label,
          confidence: rule.confidence,
          category: rule.category,
          accepted: null,
          rationale: rule.rationale,
        });
        break;  // one annotation per import
      }
    }
  }

  // ── String annotations ────────────────────────────────────────────────────
  for (const str of input.strings) {
    if (existingAddresses.has(str.offset)) continue;
    for (const rule of STRING_RULES) {
      if (rule.match.test(str.text)) {
        result.push({
          id: mkId('str'),
          stringOffset: str.offset,
          text: rule.text,
          label: rule.label,
          confidence: rule.confidence,
          category: rule.category,
          accepted: null,
          rationale: rule.rationale,
        });
        break;  // one annotation per string
      }
    }
  }

  // ── Disassembly pattern annotations ──────────────────────────────────────
  for (const pattern of input.patterns) {
    if (existingAddresses.has(pattern.address)) continue;

    if (pattern.type === 'tight_loop' && pattern.severity === 'critical') {
      result.push({
        id: mkId('dasm'),
        address: pattern.address,
        text: 'Critical tight loop — may be XOR/byte-cipher decryption routine or hash function.',
        label: 'XOR/crypto loop',
        confidence: 78,
        category: 'crypto',
        accepted: null,
        rationale: pattern.description,
      });
    }

    if (pattern.type === 'indirect_call') {
      result.push({
        id: mkId('dasm'),
        address: pattern.address,
        text: 'Indirect call through register — API likely resolved dynamically to hide from import table.',
        label: 'Dynamic dispatch',
        confidence: 72,
        category: 'evasion',
        accepted: null,
        rationale: pattern.description,
      });
    }

    if (pattern.type === 'obfuscation') {
      result.push({
        id: mkId('dasm'),
        address: pattern.address,
        text: 'Obfuscated instruction sequence detected — possibly junk code insertion or control-flow flattening.',
        label: 'Obfuscated code',
        confidence: 68,
        category: 'evasion',
        accepted: null,
        rationale: pattern.description,
      });
    }
  }

  // ── Disassembly call-site annotations ─────────────────────────────────────
  for (const ins of input.disassembly) {
    if (existingAddresses.has(ins.address)) continue;
    if (ins.mnemonic.toLowerCase() !== 'call') continue;

    // Check if the operand calls a known dangerous API
    const operand = ins.operands.trim();
    const targetName = operand.replace(/^\[|\]$/g, '').trim();
    if (DANGEROUS_CALL_TARGETS.has(targetName)) {
      result.push({
        id: mkId('call'),
        address: ins.address,
        text: `Call to ${targetName} at this address — see import annotation for details.`,
        label: `call ${targetName}`,
        confidence: 85,
        category: 'dangerous',
        accepted: null,
        rationale: `Direct call to ${targetName} identified in disassembly.`,
      });
    }
  }

  // ── High-entropy section annotations ─────────────────────────────────────
  if (input.sectionEntropies) {
    for (const section of input.sectionEntropies) {
      if (section.entropy >= 7.2) {
        result.push({
          id: mkId('sec'),
          text: `Section "${section.name}" has very high entropy (${section.entropy.toFixed(2)}) — likely packed or encrypted code/data.`,
          label: `High entropy: ${section.name}`,
          confidence: 80,
          category: 'suspicious',
          accepted: null,
          rationale: `Shannon entropy of ${section.entropy.toFixed(2)} indicates near-random data, typical of packed or encrypted payloads.`,
        });
      }
    }
  } else if (input.averageEntropy !== undefined && input.averageEntropy >= 7.0) {
    result.push({
      id: mkId('ent'),
      text: `Binary has high average entropy (${input.averageEntropy.toFixed(2)}) — packed, encrypted, or compressed sections present.`,
      label: `High entropy: ${input.averageEntropy.toFixed(2)}`,
      confidence: 75,
      category: 'suspicious',
      accepted: null,
      rationale: 'Average Shannon entropy ≥ 7.0 indicates that at least some sections contain non-human-readable/non-executable content.',
    });
  }

  // Sort: dangerous/suspicious first, then by confidence desc
  result.sort((a, b) => {
    const catOrder: Record<AnnotationCategory, number> = {
      dangerous: 0, injection: 1, evasion: 2, suspicious: 3, crypto: 4,
      network: 5, persistence: 6, execution: 7, info: 8,
    };
    const catDiff = catOrder[a.category] - catOrder[b.category];
    return catDiff !== 0 ? catDiff : b.confidence - a.confidence;
  });

  return result;
}

/**
 * Accept an annotation by ID.
 */
export function acceptAnnotation(annotations: AutoAnnotation[], id: string): AutoAnnotation[] {
  return annotations.map(a => a.id === id ? { ...a, accepted: true } : a);
}

/**
 * Reject an annotation by ID.
 */
export function rejectAnnotation(annotations: AutoAnnotation[], id: string): AutoAnnotation[] {
  return annotations.map(a => a.id === id ? { ...a, accepted: false } : a);
}

/**
 * Filter to only accepted/unreviewed annotations (exclude rejected).
 */
export function visibleAnnotations(annotations: AutoAnnotation[]): AutoAnnotation[] {
  return annotations.filter(a => a.accepted !== false);
}

/**
 * Get annotation for a specific address (for inline display in disassembly).
 */
export function getAnnotationForAddress(
  annotations: AutoAnnotation[],
  address: number,
): AutoAnnotation | null {
  return annotations.find(a => a.address === address && a.accepted !== false) ?? null;
}
