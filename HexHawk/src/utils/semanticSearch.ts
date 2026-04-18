/**
 * SemanticSearch — Intent-Based Binary Analysis Search
 *
 * Maps natural-language queries like "network activity" or "possible injection"
 * to actual binary artifacts: imports, strings, disassembly patterns, CFG blocks.
 *
 * This is NOT keyword search. The engine understands INTENT.
 */

import type { SuspiciousPattern } from '../App';

// ─── Public types ─────────────────────────────────────────────────────────────

export interface SemanticMatch {
  /** The canonical intent name, e.g. "Network Activity" */
  intentName: string;
  category: 'network' | 'injection' | 'persistence' | 'evasion' | 'crypto' | 'execution' | 'collection' | 'exfiltration' | 'general';
  confidence: number;      // 0–100
  explanation: string;
  matchedImports: string[];
  matchedStringOffsets: number[];  // indices into the strings array
  matchedPatternAddresses: number[];
  suggestedTab: 'metadata' | 'strings' | 'disassembly' | 'cfg' | 'hex';
}

export interface SemanticSearchResult {
  query: string;
  normalizedQuery: string;
  matches: SemanticMatch[];
  totalHits: number;
  bestMatch: SemanticMatch | null;
}

export interface SemanticSearchInput {
  imports: Array<{ name: string; library: string }>;
  strings: Array<{ offset: number; text: string }>;
  patterns: SuspiciousPattern[];
}

// ─── Intent Definitions ───────────────────────────────────────────────────────

interface IntentDef {
  name: string;
  aliases: string[];     // query words that trigger this intent
  category: SemanticMatch['category'];
  importPatterns: RegExp[];
  stringPatterns: RegExp[];
  patternTypes: SuspiciousPattern['type'][];
  baseConfidence: number;
  explanation: string;
  suggestedTab: SemanticMatch['suggestedTab'];
}

const INTENTS: IntentDef[] = [
  // ── Network / C2 ──────────────────────────────────────────────────────────
  {
    name: 'Network Activity',
    aliases: ['network', 'http', 'c2', 'command and control', 'internet', 'connect', 'download', 'communication', 'remote', 'beacon', 'phone home'],
    category: 'network',
    importPatterns: [/^(WSAStartup|connect|send|recv|InternetOpen|InternetConnect|HttpSendRequest|URLDownloadToFile|WinHttpOpen|WinHttpConnect|WinHttpSendRequest)$/i],
    stringPatterns: [/^https?:\/\//i, /^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/, /^ftp:\/\//i, /\.(php|aspx?|jsp)\?/i],
    patternTypes: [],
    baseConfidence: 75,
    explanation: 'Looks for network API imports and embedded URLs / IP addresses that suggest outbound connectivity.',
    suggestedTab: 'strings',
  },
  // ── Process injection ─────────────────────────────────────────────────────
  {
    name: 'Process Injection',
    aliases: ['inject', 'injection', 'hollow', 'process hollowing', 'thread injection', 'dll injection', 'shellcode', 'migrate'],
    category: 'injection',
    importPatterns: [/^(VirtualAlloc(Ex)?|WriteProcessMemory|CreateRemoteThread(Ex)?|NtCreateThreadEx|OpenProcess|SetWindowsHookEx|RtlCreateUserThread)$/],
    stringPatterns: [/VirtualAlloc/i, /ntdll/i, /\\Windows\\System32/i],
    patternTypes: ['indirect_call'],
    baseConfidence: 80,
    explanation: 'Looks for process injection APIs: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread are the classic injection trio.',
    suggestedTab: 'disassembly',
  },
  // ── Persistence ───────────────────────────────────────────────────────────
  {
    name: 'Persistence Mechanism',
    aliases: ['persist', 'persistence', 'startup', 'autorun', 'registry run', 'scheduled task', 'service install', 'boot'],
    category: 'persistence',
    importPatterns: [/^(RegSetValueEx[AW]?|RegCreateKey(Ex)?[AW]?|CreateService[AW]?|ChangeServiceConfig|StartService)$/],
    stringPatterns: [/HKEY_(LOCAL_MACHINE|CURRENT_USER)\\(SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|System\\CurrentControlSet\\Services)/i, /\\AppData\\Roaming/i, /schtasks/i, /SYSTEM\\CurrentControlSet/i],
    patternTypes: [],
    baseConfidence: 70,
    explanation: 'Searches for registry-based or service-based persistence: HKLM\\Run, HKCU\\Run, service creation.',
    suggestedTab: 'strings',
  },
  // ── Anti-analysis / evasion ───────────────────────────────────────────────
  {
    name: 'Anti-Analysis Evasion',
    aliases: ['anti-debug', 'anti debug', 'evasion', 'sandbox', 'vm detect', 'virtual machine', 'debugger', 'analysis evasion', 'obfusc'],
    category: 'evasion',
    importPatterns: [/^(IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|OutputDebugString|NtSetInformationThread|GetTickCount|QueryPerformanceCounter|NtDelayExecution)$/],
    stringPatterns: [/vbox|vmware|virtualbox|qemu|sandboxie/i, /HARDWARE\\ACPI\\DSDT/i],
    patternTypes: ['indirect_call', 'obfuscation'],
    baseConfidence: 75,
    explanation: 'Identifies anti-debugging, anti-VM, and sandbox-evasion techniques.',
    suggestedTab: 'disassembly',
  },
  // ── Cryptography / encryption ─────────────────────────────────────────────
  {
    name: 'Encryption / Cryptography',
    aliases: ['encrypt', 'crypto', 'cipher', 'aes', 'rsa', 'xor', 'ransom', 'decode', 'obfuscated payload', 'decrypt'],
    category: 'crypto',
    importPatterns: [/^(CryptEncrypt|CryptDecrypt|CryptGenRandom|BCryptEncrypt|BCryptDecrypt|BCryptGenRandom|CryptAcquireContext)$/],
    stringPatterns: [/AES|RC4|ChaCha|Salsa|Blowfish/i, /\.encrypted$/i, /ransom/i, /bitcoin|monero|wallet/i],
    patternTypes: ['tight_loop'],
    baseConfidence: 70,
    explanation: 'Finds cryptographic APIs, cipher name strings, and tight loops that suggest XOR or block-cipher loops.',
    suggestedTab: 'disassembly',
  },
  // ── Process / code execution ──────────────────────────────────────────────
  {
    name: 'Code / Process Execution',
    aliases: ['execute', 'run', 'spawn', 'shellexecute', 'createprocess', 'cmd', 'powershell', 'wscript', 'payload', 'dropper'],
    category: 'execution',
    importPatterns: [/^(ShellExecute[AW]?|CreateProcess[AW]?|WinExec|system|_exec|popen|CreateProcessWithToken[AW])$/],
    stringPatterns: [/cmd\.exe|powershell\.exe|wscript\.exe|mshta\.exe/i, /\.exe|\.bat|\.ps1|\.vbs/i, /%TEMP%|%APPDATA%/i],
    patternTypes: [],
    baseConfidence: 65,
    explanation: 'Searches for shell execution APIs and command-line artifacts suggesting secondary payload execution.',
    suggestedTab: 'strings',
  },
  // ── Data collection / stealing ────────────────────────────────────────────
  {
    name: 'Credential / Data Collection',
    aliases: ['steal', 'credential', 'password', 'cookie', 'browser', 'keylog', 'clipboard', 'screenshot', 'harvest'],
    category: 'collection',
    importPatterns: [/^(GetClipboardData|SetWindowsHookEx|OpenClipboard|FindFirstFileW?)$/],
    stringPatterns: [/password|passwd|credential|login|cookie|Chrome|Firefox|Edge|Brave/i, /DPAPI|CryptUnprotectData/i, /wallet\.dat/i],
    patternTypes: [],
    baseConfidence: 65,
    explanation: 'Searches for browser paths, credential terms, clipboard access APIs indicative of data harvesting.',
    suggestedTab: 'strings',
  },
  // ── Data exfiltration ─────────────────────────────────────────────────────
  {
    name: 'Data Exfiltration',
    aliases: ['exfiltrate', 'exfil', 'send data', 'upload', 'ftp upload', 'email send', 'leak'],
    category: 'exfiltration',
    importPatterns: [/^(URLDownloadToFile|InternetWriteFile|FtpPutFile|SmtpSend|HttpSendRequest)$/],
    stringPatterns: [/ftp:\/\//i, /\.php\?data=/i, /multipart\/form-data/i, /Content-Disposition: form-data/i],
    patternTypes: [],
    baseConfidence: 60,
    explanation: 'Looks for upload/FTP/HTTP POST patterns that indicate data being sent to a remote server.',
    suggestedTab: 'strings',
  },
  // ── Dynamic API loading ───────────────────────────────────────────────────
  {
    name: 'Hidden / Dynamic API Loading',
    aliases: ['dynamic', 'getprocaddress', 'loadlibrary', 'hidden api', 'reflective', 'resolve'],
    category: 'evasion',
    importPatterns: [/^(GetProcAddress|LoadLibrary[AW]?|LdrGetProcedureAddress|RtlGetProcedureAddress)$/],
    stringPatterns: [/ntdll\.dll|kernel32\.dll/i],
    patternTypes: ['indirect_call'],
    baseConfidence: 70,
    explanation: 'GetProcAddress + LoadLibrary are used to resolve APIs at runtime, hiding capabilities from static import analysis.',
    suggestedTab: 'disassembly',
  },
  // ── File system operations ────────────────────────────────────────────────
  {
    name: 'File System Operations',
    aliases: ['file', 'files', 'disk', 'write file', 'delete', 'enumerate', 'copy', 'rename', 'drop'],
    category: 'collection',
    importPatterns: [/^(CreateFile[AW]?|WriteFile|ReadFile|DeleteFile[AW]?|MoveFile[AW]?|CopyFile[AW]?|FindFirstFile[AW]?)$/],
    stringPatterns: [/[A-Za-z]:\\|%APPDATA%|%TEMP%|%SystemRoot%/i, /\.tmp|\.dat|\.bin/i],
    patternTypes: [],
    baseConfidence: 40,
    explanation: 'File APIs and path strings suggesting disk activity. Note: this alone is not malicious.',
    suggestedTab: 'strings',
  },
];

// ─── Scorer ───────────────────────────────────────────────────────────────────

function scoreIntent(intent: IntentDef, input: SemanticSearchInput): SemanticMatch | null {
  const matchedImports: string[] = [];
  const matchedStringOffsets: number[] = [];
  const matchedPatternAddresses: number[] = [];

  // Match imports
  for (const imp of input.imports) {
    for (const pat of intent.importPatterns) {
      if (pat.test(imp.name)) {
        if (!matchedImports.includes(imp.name)) matchedImports.push(imp.name);
        break;
      }
    }
  }

  // Match strings
  for (const str of input.strings) {
    for (const pat of intent.stringPatterns) {
      if (pat.test(str.text)) {
        matchedStringOffsets.push(str.offset);
        break;
      }
    }
  }

  // Match patterns
  for (const p of input.patterns) {
    if (intent.patternTypes.includes(p.type)) {
      matchedPatternAddresses.push(p.address);
    }
  }

  const totalHits = matchedImports.length + matchedStringOffsets.length + matchedPatternAddresses.length;
  if (totalHits === 0) return null;

  // Confidence: weighted hits
  const importScore  = Math.min(matchedImports.length * 20, 50);
  const stringScore  = Math.min(matchedStringOffsets.length * 10, 30);
  const patternScore = Math.min(matchedPatternAddresses.length * 10, 20);
  const confidence   = Math.min(95, intent.baseConfidence + importScore * 0.3 + stringScore * 0.4 + patternScore * 0.3);

  return {
    intentName: intent.name,
    category: intent.category,
    confidence: Math.round(confidence),
    explanation: intent.explanation,
    matchedImports,
    matchedStringOffsets,
    matchedPatternAddresses,
    suggestedTab: intent.suggestedTab,
  };
}

// ─── Normalizer ───────────────────────────────────────────────────────────────

function normalizeQuery(query: string): string {
  return query.toLowerCase().trim().replace(/[^a-z0-9 ]/g, ' ').replace(/\s+/g, ' ');
}

function matchesIntent(normalized: string, intent: IntentDef): boolean {
  for (const alias of intent.aliases) {
    if (normalized.includes(alias.toLowerCase())) return true;
  }
  // Also check if any word matches a single word in the aliases list
  const words = normalized.split(' ');
  for (const word of words) {
    if (word.length >= 4 && intent.aliases.some(a => a.toLowerCase().startsWith(word) || a.toLowerCase().includes(word))) {
      return true;
    }
  }
  return false;
}

// ─── Public API ───────────────────────────────────────────────────────────────

export function semanticSearch(query: string, input: SemanticSearchInput): SemanticSearchResult {
  const normalized = normalizeQuery(query);
  const matches: SemanticMatch[] = [];

  // Determine which intents to evaluate
  const candidateIntents = normalized.length < 3
    ? []
    : INTENTS.filter(intent => matchesIntent(normalized, intent));

  // If no intent matched by keyword, do a broad score of all intents
  const intentsToScore = candidateIntents.length > 0 ? candidateIntents : INTENTS;

  for (const intent of intentsToScore) {
    const match = scoreIntent(intent, input);
    if (match) {
      // Boost confidence for direct alias hits
      if (candidateIntents.includes(intent)) {
        match.confidence = Math.min(99, match.confidence + 15);
      }
      matches.push(match);
    }
  }

  // Sort by confidence descending
  matches.sort((a, b) => b.confidence - a.confidence);

  const totalHits = matches.reduce(
    (sum, m) => sum + m.matchedImports.length + m.matchedStringOffsets.length + m.matchedPatternAddresses.length,
    0
  );

  return {
    query,
    normalizedQuery: normalized,
    matches: matches.slice(0, 5),  // top 5 intents
    totalHits,
    bestMatch: matches[0] ?? null,
  };
}

/** Returns all intents that have ANY signal in the input (for the "what have we found" overview) */
export function getAllActiveIntents(input: SemanticSearchInput): SemanticMatch[] {
  const results: SemanticMatch[] = [];
  for (const intent of INTENTS) {
    const match = scoreIntent(intent, input);
    if (match && match.confidence >= 50) results.push(match);
  }
  return results.sort((a, b) => b.confidence - a.confidence);
}

/** Suggest what query to run based on what hasn't been explored yet */
export function suggestUnexploredAreas(
  input: SemanticSearchInput,
  exploredIntents: Set<string>,
): string[] {
  const active = getAllActiveIntents(input);
  return active
    .filter(m => !exploredIntents.has(m.intentName))
    .slice(0, 3)
    .map(m => `"${m.intentName}" — ${m.explanation.split('.')[0]}.`);
}
