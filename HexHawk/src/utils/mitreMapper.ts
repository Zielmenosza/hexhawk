/**
 * mitreMapper — MITRE ATT\&CK Technique Mapping + IOC Extraction
 *
 * Maps HexHawk behavioral tags and NEST signals to MITRE ATT&CK Enterprise
 * techniques, and extracts Indicators of Compromise from string lists.
 */

import type { BehavioralTag } from './correlationEngine';

// ─────────────────────────────────────────────────────────
// MITRE ATT&CK TYPES
// ─────────────────────────────────────────────────────────

export interface MitreTechnique {
  /** MITRE technique ID (e.g. "T1055"). */
  id:        string;
  /** Sub-technique ID if applicable (e.g. "T1055.012"). */
  subId?:    string;
  /** Full technique name. */
  name:      string;
  /** MITRE tactic(s) this falls under. */
  tactics:   string[];
  /** Short description. */
  desc:      string;
  /** Direct link to attack.mitre.org. */
  url:       string;
  /** Confidence of the mapping based on observed evidence (0–100). */
  confidence: number;
  /** Which behavioral signal(s) triggered this mapping. */
  sources:   string[];
}

// ─────────────────────────────────────────────────────────
// MITRE TECHNIQUE DATABASE
// ─────────────────────────────────────────────────────────

interface TechniqueSpec {
  id:      string;
  subId?:  string;
  name:    string;
  tactics: string[];
  desc:    string;
}

const TECHNIQUE_DB: Record<string, TechniqueSpec> = {
  'T1055':      { id: 'T1055',       name: 'Process Injection',                     tactics: ['Defense Evasion','Privilege Escalation'], desc: 'Injecting code into a running process to evade detection or gain elevated privileges.' },
  'T1055.001':  { id: 'T1055', subId: 'T1055.001', name: 'DLL Injection',           tactics: ['Defense Evasion','Privilege Escalation'], desc: 'Injecting a DLL into a running process.' },
  'T1055.002':  { id: 'T1055', subId: 'T1055.002', name: 'Portable Executable Injection', tactics: ['Defense Evasion','Privilege Escalation'], desc: 'Injecting a PE image into a running process.' },
  'T1055.012':  { id: 'T1055', subId: 'T1055.012', name: 'Process Hollowing',       tactics: ['Defense Evasion','Privilege Escalation'], desc: 'Replacing legitimate process memory with malicious code.' },
  'T1027':      { id: 'T1027',       name: 'Obfuscated Files or Information',        tactics: ['Defense Evasion'], desc: 'Obfuscating payloads to evade signature detection.' },
  'T1027.002':  { id: 'T1027', subId: 'T1027.002', name: 'Software Packing',        tactics: ['Defense Evasion'], desc: 'Using a packer/protector to compress or encrypt the payload.' },
  'T1620':      { id: 'T1620',       name: 'Reflective Code Loading',               tactics: ['Defense Evasion'], desc: 'Loading executable code into a process without writing to disk.' },
  'T1140':      { id: 'T1140',       name: 'Deobfuscate/Decode Files or Information', tactics: ['Defense Evasion'], desc: 'Decoding or deobfuscating files or information at runtime.' },
  'T1497':      { id: 'T1497',       name: 'Virtualization/Sandbox Evasion',         tactics: ['Defense Evasion','Discovery'], desc: 'Detecting virtualised or sandboxed environments to evade analysis.' },
  'T1497.001':  { id: 'T1497', subId: 'T1497.001', name: 'System Checks',           tactics: ['Defense Evasion','Discovery'], desc: 'Using CPUID or timing to detect virtualised environments.' },
  'T1497.003':  { id: 'T1497', subId: 'T1497.003', name: 'Time Based Evasion',      tactics: ['Defense Evasion','Discovery'], desc: 'Using timing checks (RDTSC) to detect sandbox execution.' },
  'T1562.001':  { id: 'T1562', subId: 'T1562.001', name: 'Disable or Modify Tools', tactics: ['Defense Evasion'], desc: 'Disabling security tools or anti-virus.' },
  'T1218':      { id: 'T1218',       name: 'System Binary Proxy Execution',         tactics: ['Defense Evasion'], desc: 'Using trusted system binaries to proxy execution of malicious code.' },
  'T1059':      { id: 'T1059',       name: 'Command and Scripting Interpreter',     tactics: ['Execution'], desc: 'Executing code via scripting interpreters or command shells.' },
  'T1106':      { id: 'T1106',       name: 'Native API',                            tactics: ['Execution'], desc: 'Using native OS APIs to execute code.' },
  'T1129':      { id: 'T1129',       name: 'Shared Modules',                        tactics: ['Execution'], desc: 'Loading shared modules (DLLs) for execution.' },
  'T1543':      { id: 'T1543',       name: 'Create or Modify System Process',       tactics: ['Persistence','Privilege Escalation'], desc: 'Abusing system mechanisms to maintain persistence.' },
  'T1547.001':  { id: 'T1547', subId: 'T1547.001', name: 'Registry Run Keys / Startup Folder', tactics: ['Persistence','Privilege Escalation'], desc: 'Adding registry run keys for persistence.' },
  'T1003':      { id: 'T1003',       name: 'OS Credential Dumping',                 tactics: ['Credential Access'], desc: 'Dumping credentials from the OS.' },
  'T1003.001':  { id: 'T1003', subId: 'T1003.001', name: 'LSASS Memory Dump',      tactics: ['Credential Access'], desc: 'Extracting credentials from LSASS memory.' },
  'T1557':      { id: 'T1557',       name: 'Adversary-in-the-Middle',               tactics: ['Credential Access','Collection'], desc: 'Intercepting network traffic to steal credentials.' },
  'T1071':      { id: 'T1071',       name: 'Application Layer Protocol',            tactics: ['Command and Control'], desc: 'Using common protocols for C2 communication.' },
  'T1071.001':  { id: 'T1071', subId: 'T1071.001', name: 'Web Protocols (HTTP/S)', tactics: ['Command and Control'], desc: 'Using HTTP or HTTPS for C2 communications.' },
  'T1573':      { id: 'T1573',       name: 'Encrypted Channel',                    tactics: ['Command and Control'], desc: 'Using encrypted communications for C2.' },
  'T1573.001':  { id: 'T1573', subId: 'T1573.001', name: 'Symmetric Cryptography', tactics: ['Command and Control'], desc: 'Using symmetric encryption for C2 traffic.' },
  'T1041':      { id: 'T1041',       name: 'Exfiltration Over C2 Channel',         tactics: ['Exfiltration'], desc: 'Exfiltrating data via the established C2 channel.' },
  'T1485':      { id: 'T1485',       name: 'Data Destruction',                     tactics: ['Impact'], desc: 'Destroying data on target systems.' },
  'T1486':      { id: 'T1486',       name: 'Data Encrypted for Impact',            tactics: ['Impact'], desc: 'Encrypting data for ransom or destructive purposes.' },
  'T1014':      { id: 'T1014',       name: 'Rootkit',                              tactics: ['Defense Evasion'], desc: 'Using rootkit techniques to hide malicious activity.' },
  'T1082':      { id: 'T1082',       name: 'System Information Discovery',         tactics: ['Discovery'], desc: 'Collecting information about the target system.' },
  'T1057':      { id: 'T1057',       name: 'Process Discovery',                    tactics: ['Discovery'], desc: 'Enumerating running processes.' },
  'T1012':      { id: 'T1012',       name: 'Query Registry',                       tactics: ['Discovery'], desc: 'Querying Windows Registry for information.' },
  'T1210':      { id: 'T1210',       name: 'Exploitation of Remote Services',      tactics: ['Lateral Movement'], desc: 'Exploiting remote services for lateral movement.' },
  'T1134':      { id: 'T1134',       name: 'Access Token Manipulation',            tactics: ['Defense Evasion','Privilege Escalation'], desc: 'Manipulating access tokens to gain higher privileges.' },
  'T1055.004':  { id: 'T1055', subId: 'T1055.004', name: 'Asynchronous Procedure Call', tactics: ['Defense Evasion','Privilege Escalation'], desc: 'Using APC queues to execute shellcode in another thread.' },
  'T1622':      { id: 'T1622',       name: 'Debugger Evasion',                     tactics: ['Defense Evasion'], desc: 'Detecting debuggers to change execution flow or halt.' },
};

// ─────────────────────────────────────────────────────────
// BEHAVIORAL TAG → TECHNIQUE MAPPING
// ─────────────────────────────────────────────────────────

interface MappingRule {
  techniques:  string[];
  confidence:  number;
}

const TAG_MAPPINGS: Partial<Record<BehavioralTag, MappingRule>> = {
  'code-injection':    { techniques: ['T1055', 'T1055.001', 'T1055.002'],           confidence: 85 },
  'code-decryption':  { techniques: ['T1027', 'T1027.002', 'T1140', 'T1620'],      confidence: 80 },
  'anti-analysis':    { techniques: ['T1497', 'T1622', 'T1497.001', 'T1497.003'],  confidence: 90 },
  'dynamic-resolution':{ techniques: ['T1129', 'T1106'],                            confidence: 75 },
  'persistence':      { techniques: ['T1547.001', 'T1543'],                         confidence: 80 },
  'credential-theft': { techniques: ['T1003', 'T1003.001'],                         confidence: 85 },
  'c2-communication': { techniques: ['T1071', 'T1071.001', 'T1041'],               confidence: 80 },
  'data-encryption':  { techniques: ['T1573', 'T1573.001', 'T1486'],               confidence: 70 },
  'file-destruction': { techniques: ['T1485', 'T1486'],                             confidence: 90 },
  'process-execution':{ techniques: ['T1059'],                                       confidence: 65 },
  'data-exfiltration':{ techniques: ['T1041'],                                       confidence: 80 },
};

// Extra signal-string → technique mapping (from NEST/TALON signal names)
const SIGNAL_MAPPINGS: Record<string, MappingRule> = {
  'IsDebuggerPresent':        { techniques: ['T1622'],           confidence: 95 },
  'VirtualAllocEx':           { techniques: ['T1055', 'T1055.002'], confidence: 90 },
  'WriteProcessMemory':       { techniques: ['T1055', 'T1055.002'], confidence: 90 },
  'CreateRemoteThread':       { techniques: ['T1055', 'T1055.001'], confidence: 90 },
  'QueueUserAPC':             { techniques: ['T1055.004'],        confidence: 90 },
  'NtUnmapViewOfSection':     { techniques: ['T1055.012'],        confidence: 95 },
  'SetThreadContext':          { techniques: ['T1055.012'],        confidence: 90 },
  'GetProcAddress':            { techniques: ['T1129', 'T1106'],   confidence: 75 },
  'LoadLibrary':               { techniques: ['T1129'],            confidence: 65 },
  'RegSetValueEx':             { techniques: ['T1547.001'],        confidence: 85 },
  'CryptEncrypt':              { techniques: ['T1573.001','T1486'], confidence: 75 },
  'BCryptEncrypt':             { techniques: ['T1573.001','T1486'], confidence: 75 },
  'RDTSC':                     { techniques: ['T1497.003'],        confidence: 85 },
  'CPUID':                     { techniques: ['T1497.001'],        confidence: 80 },
  'PEB walk':                  { techniques: ['T1129','T1106'],    confidence: 85 },
  'self-modifying':            { techniques: ['T1027','T1027.002'], confidence: 90 },
  'connect':                   { techniques: ['T1071'],            confidence: 60 },
  'send':                      { techniques: ['T1041'],            confidence: 65 },
  'WSAStartup':                { techniques: ['T1071'],            confidence: 60 },
  'AdjustTokenPrivileges':     { techniques: ['T1134'],            confidence: 90 },
  'LsaRetrievePrivateData':    { techniques: ['T1003'],            confidence: 95 },
  'SamOpenDatabase':           { techniques: ['T1003.001'],        confidence: 95 },
  'CreateProcess':             { techniques: ['T1059'],            confidence: 65 },
  'DeleteFile':                { techniques: ['T1485'],            confidence: 70 },
};

// ─────────────────────────────────────────────────────────
// PUBLIC: MAP TAGS → TECHNIQUES
// ─────────────────────────────────────────────────────────

/**
 * Map behavioral tags from GYRE/NEST/TALON → MITRE ATT&CK techniques.
 * De-duplicates by technique ID and picks the highest-confidence mapping.
 */
export function mapBehaviorToMitre(
  tags: BehavioralTag[],
  signals?: string[],
): MitreTechnique[] {
  const seen = new Map<string, MitreTechnique>();

  function addTechniques(techIds: string[], confidence: number, sources: string[]) {
    for (const techId of techIds) {
      const spec = TECHNIQUE_DB[techId];
      if (!spec) continue;
      const key = techId;
      const existing = seen.get(key);
      if (existing && existing.confidence >= confidence) continue;
      seen.set(key, {
        id:         spec.id,
        subId:      spec.subId,
        name:       spec.name,
        tactics:    spec.tactics,
        desc:       spec.desc,
        url:        `https://attack.mitre.org/techniques/${(spec.subId ?? spec.id).replace('.', '/')}`,
        confidence,
        sources,
      });
    }
  }

  for (const tag of tags) {
    const rule = TAG_MAPPINGS[tag];
    if (rule) addTechniques(rule.techniques, rule.confidence, [tag]);
  }

  for (const signal of (signals ?? [])) {
    // Check exact match or prefix match
    for (const [key, rule] of Object.entries(SIGNAL_MAPPINGS)) {
      if (signal.toLowerCase().includes(key.toLowerCase())) {
        addTechniques(rule.techniques, rule.confidence, [signal]);
      }
    }
  }

  return [...seen.values()].sort((a, b) => {
    // Sort by tactic priority then confidence
    const tacticOrder = ['Execution','Privilege Escalation','Persistence','Defense Evasion','Credential Access','Discovery','Lateral Movement','Collection','Command and Control','Exfiltration','Impact'];
    const aIdx = Math.min(...a.tactics.map(t => { const i = tacticOrder.indexOf(t); return i < 0 ? 99 : i; }));
    const bIdx = Math.min(...b.tactics.map(t => { const i = tacticOrder.indexOf(t); return i < 0 ? 99 : i; }));
    if (aIdx !== bIdx) return aIdx - bIdx;
    return b.confidence - a.confidence;
  });
}

// ─────────────────────────────────────────────────────────
// IOC EXTRACTION
// ─────────────────────────────────────────────────────────

export type IOCKind = 'ipv4' | 'ipv6' | 'url' | 'domain' | 'email' | 'registry' | 'filepath' | 'hash-md5' | 'hash-sha1' | 'hash-sha256' | 'mutex';

export interface IOC {
  kind:     IOCKind;
  value:    string;
  /** Source string from which this was extracted. */
  source:   string;
  /** Confidence 0–100 that this is a true IOC. */
  confidence: number;
}

// Compiled regexes — order matters: more specific first
const IOC_RULES: Array<{ kind: IOCKind; re: RegExp; confidence: number }> = [
  // SHA-256 hash (64 hex chars)
  { kind: 'hash-sha256', re: /\b[0-9a-f]{64}\b/gi, confidence: 95 },
  // MD5 hash (32 hex chars)
  { kind: 'hash-md5',    re: /\b[0-9a-f]{32}\b/gi, confidence: 80 },
  // SHA-1 hash (40 hex chars)
  { kind: 'hash-sha1',   re: /\b[0-9a-f]{40}\b/gi, confidence: 80 },
  // IPv4
  { kind: 'ipv4',  re: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g, confidence: 90 },
  // IPv6 (full form)
  { kind: 'ipv6',  re: /\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b/gi, confidence: 90 },
  // Full URL (http/https/ftp)
  { kind: 'url',   re: /https?:\/\/[^\s"'<>\x00-\x1f]{6,}/gi, confidence: 95 },
  // FTP URL
  { kind: 'url',   re: /ftp:\/\/[^\s"'<>\x00-\x1f]{4,}/gi, confidence: 90 },
  // Email address
  { kind: 'email', re: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, confidence: 85 },
  // Windows registry path
  { kind: 'registry', re: /\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_USERS|HKU|HKCR)\\[^\s"'\x00-\x1f]{3,}/gi, confidence: 90 },
  // Windows file path (absolute)
  { kind: 'filepath', re: /[A-Za-z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]{1,240}/g, confidence: 80 },
  // UNC path
  { kind: 'filepath', re: /\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9._$ -]+/g, confidence: 85 },
  // Domain names (2+ labels, known TLDs)
  { kind: 'domain', re: /\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|info|biz|ru|cn|de|uk|fr|cc|onion|xyz|top|tk|pw|club|live|online)\b/gi, confidence: 70 },
  // Mutex names (common patterns)
  { kind: 'mutex', re: /Global\\[A-Za-z0-9_\-{}\[\]]{6,}/g, confidence: 75 },
];

/** Strings to skip — common false positives. */
const IOC_BLOCKLIST = new Set([
  '0.0.0.0', '127.0.0.1', '255.255.255.255', '192.168.0.0', '10.0.0.0',
  'microsoft.com', 'windows.com', 'ntdll.dll', 'kernel32.dll',
]);

/**
 * Extract potential Indicators of Compromise from a list of strings
 * (e.g. the strings extracted from the binary by find_strings).
 *
 * Returns a de-duplicated list of IOCs sorted by confidence descending.
 */
export function extractIOCs(strings: string[]): IOC[] {
  const seen = new Set<string>();
  const results: IOC[] = [];

  for (const str of strings) {
    for (const rule of IOC_RULES) {
      const matches = str.matchAll(new RegExp(rule.re.source, rule.re.flags));
      for (const m of matches) {
        const value = m[0].trim();
        if (!value || value.length < 4) continue;
        if (IOC_BLOCKLIST.has(value.toLowerCase())) continue;
        const key = `${rule.kind}:${value.toLowerCase()}`;
        if (seen.has(key)) continue;
        seen.add(key);
        results.push({ kind: rule.kind, value, source: str, confidence: rule.confidence });
      }
    }
  }

  // De-duplicate: if same value appears under multiple kinds, keep highest confidence
  const byValue = new Map<string, IOC>();
  for (const ioc of results) {
    const k = ioc.value.toLowerCase();
    const ex = byValue.get(k);
    if (!ex || ex.confidence < ioc.confidence) byValue.set(k, ioc);
  }

  return [...byValue.values()].sort((a, b) => b.confidence - a.confidence);
}

// ─────────────────────────────────────────────────────────
// CONVENIENCE: FULL EVIDENCE ENRICHMENT
// ─────────────────────────────────────────────────────────

export interface EnrichedEvidence {
  mitreTechniques: MitreTechnique[];
  iocs:            IOC[];
  tacticSummary:   Record<string, number>;  // tactic → technique count
  highConfidenceTechniques: MitreTechnique[];
  criticalIOCs:    IOC[];
}

/**
 * One-stop enrichment: given behavioral tags, optional signal names, and
 * string list, return full ATT&CK + IOC analysis.
 */
export function enrichEvidence(
  tags:     BehavioralTag[],
  strings:  string[],
  signals?: string[],
): EnrichedEvidence {
  const mitreTechniques = mapBehaviorToMitre(tags, signals);
  const iocs            = extractIOCs(strings);

  const tacticSummary: Record<string, number> = {};
  for (const t of mitreTechniques) {
    for (const tactic of t.tactics) {
      tacticSummary[tactic] = (tacticSummary[tactic] ?? 0) + 1;
    }
  }

  return {
    mitreTechniques,
    iocs,
    tacticSummary,
    highConfidenceTechniques: mitreTechniques.filter(t => t.confidence >= 80),
    criticalIOCs:             iocs.filter(i => i.confidence >= 85 &&
      (i.kind === 'ipv4' || i.kind === 'url' || i.kind === 'domain' ||
       i.kind === 'registry' || i.kind === 'hash-sha256' || i.kind === 'hash-md5')),
  };
}
