/**
 * Operator Console — Intent Classifier + Workflow Generator
 *
 * Rule-based, deterministic. No ML.
 * Input:  free-text user objective + optional binary context
 * Output: structured workflow with actionable steps
 */

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export type OperatorIntent =
  | 'injection'
  | 'networking'
  | 'persistence'
  | 'unpacking'
  | 'obfuscation'
  | 'anti-analysis'
  | 'credential-theft'
  | 'lateral-movement'
  | 'ransomware'
  | 'general-analysis';

export type ConsoleTab =
  | 'metadata'
  | 'hex'
  | 'strings'
  | 'cfg'
  | 'disassembly'
  | 'talon'
  | 'strike'
  | 'echo'
  | 'nest'
  | 'signatures'
  | 'plugins'
  | 'report';

export type StepStatus = 'pending' | 'active' | 'done' | 'skipped';
export type StepPriority = 'critical' | 'high' | 'medium' | 'low';
export type ExecutionMode = 'guide-only' | 'guided-navigation' | 'auto-run';

export interface ConsoleStep {
  id: string;
  stepNumber: number;
  action: string;
  tool: string;
  tab: ConsoleTab | null;
  explanation: string;
  priority: StepPriority;
  autoRunnable: boolean;
  status: StepStatus;
  /** Optional context hint derived from the actual loaded binary */
  contextHint?: string;
}

export interface ConsoleWorkflow {
  intent: OperatorIntent;
  intentLabel: string;
  title: string;
  description: string;
  steps: ConsoleStep[];
  /** True when steps were refined using actual binary signals/metadata */
  contextApplied: boolean;
}

/** Minimal binary context passed in from App state (all optional) */
export interface BinaryContext {
  binaryPath?: string | null;
  fileType?: string;
  architecture?: string;
  importNames?: string[];
  stringTexts?: string[];
  verdictClassification?: string;
  verdictBehaviors?: string[];
  signalIds?: string[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 1 — Intent Classifier
// ─────────────────────────────────────────────────────────────────────────────

interface IntentRule {
  pattern: RegExp;
  intent: OperatorIntent;
}

const INTENT_RULES: IntentRule[] = [
  { pattern: /inject|shellcode|hollow|process.holl|dll.inject|thread.hijack|code.cave|reflective/i, intent: 'injection' },
  { pattern: /network|c2|command.and.control|beacon|connect|http|socket|download|upload|exfil|phone.home/i, intent: 'networking' },
  { pattern: /persist|startup|autorun|registry|reg.key|scheduled.task|service|boot|logon/i, intent: 'persistence' },
  { pattern: /unpack|packer|upx|compress|encoded|decode|decrypt|stub|unpacking|original.entry/i, intent: 'unpacking' },
  { pattern: /obfuscat|encrypt|xor|base64|mangle|virtuali[sz]|mutation|polymorphic/i, intent: 'obfuscation' },
  { pattern: /anti.?debug|anti.?vm|anti.?sandbox|evasion|detect.?debugger|timing.check|environment.check/i, intent: 'anti-analysis' },
  { pattern: /credential|password|hash|ntlm|kerberos|lsass|token|dump|mimikatz|sam.?hive/i, intent: 'credential-theft' },
  { pattern: /lateral|pivot|move|smb|wmi|psexec|spread|pass.?the|dcom|winrm/i, intent: 'lateral-movement' },
  { pattern: /ransom|encrypt.?file|lock.?file|crypt|demand|bitcoin|extension.?change/i, intent: 'ransomware' },
];

/**
 * Classify free-text user objective into an OperatorIntent.
 * Falls back to 'general-analysis' if no rule matches.
 */
export function classifyIntent(userPrompt: string): OperatorIntent {
  const trimmed = userPrompt.trim();
  for (const rule of INTENT_RULES) {
    if (rule.pattern.test(trimmed)) {
      return rule.intent;
    }
  }
  return 'general-analysis';
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 2 — Workflow Templates
// ─────────────────────────────────────────────────────────────────────────────

const INTENT_LABELS: Record<OperatorIntent, string> = {
  'injection':         'Process Injection',
  'networking':        'Network / C2 Activity',
  'persistence':       'Persistence Mechanisms',
  'unpacking':         'Unpacking / Deobfuscation',
  'obfuscation':       'Obfuscation Analysis',
  'anti-analysis':     'Anti-Analysis / Evasion',
  'credential-theft':  'Credential Theft',
  'lateral-movement':  'Lateral Movement',
  'ransomware':        'Ransomware Analysis',
  'general-analysis':  'General Analysis',
};

type WorkflowTemplate = Omit<ConsoleWorkflow, 'contextApplied' | 'intent' | 'intentLabel'> & {
  steps: Omit<ConsoleStep, 'id' | 'status'>[];
};

function makeTemplate(
  title: string,
  description: string,
  steps: Omit<ConsoleStep, 'id' | 'status'>[],
): WorkflowTemplate {
  return { title, description, steps };
}

const WORKFLOW_TEMPLATES: Record<OperatorIntent, WorkflowTemplate> = {

  'injection': makeTemplate(
    'Analyzing Process Injection',
    'Identify injection APIs, shellcode regions, and control-flow anomalies.',
    [
      { stepNumber: 1, action: 'Check imported APIs for injection primitives', tool: 'Metadata', tab: 'metadata', priority: 'critical', autoRunnable: true,
        explanation: 'Look for VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, NtCreateThreadEx, SetWindowsHookEx in the imports table.' },
      { stepNumber: 2, action: 'Search strings for target process names and PID patterns', tool: 'Strings', tab: 'strings', priority: 'high', autoRunnable: true,
        explanation: 'Injectors often embed target process names (explorer.exe, lsass.exe) or PID lookup strings.' },
      { stepNumber: 3, action: 'Examine CFG for indirect call clusters', tool: 'CFG', tab: 'cfg', priority: 'high', autoRunnable: false,
        explanation: 'Injection stubs frequently use indirect calls (call [rax]) to avoid static detection. Look for dense indirect-call subgraphs.' },
      { stepNumber: 4, action: 'Inspect entry region for shellcode patterns', tool: 'Disassembly', tab: 'disassembly', priority: 'high', autoRunnable: false,
        explanation: 'Shellcode loaders often start with a short decoder loop before any API calls. Look for XOR/ADD loops at the entry point.' },
      { stepNumber: 5, action: 'Run TALON behavioral classification', tool: 'TALON', tab: 'talon', priority: 'medium', autoRunnable: false,
        explanation: 'TALON detects injection-related behavioral patterns from control-flow shape without executing the binary.' },
      { stepNumber: 6, action: 'Run NEST full analysis', tool: 'NEST', tab: 'nest', priority: 'medium', autoRunnable: false,
        explanation: 'NEST correlates all signals and provides a final verdict with explainability chain.' },
    ],
  ),

  'networking': makeTemplate(
    'Analyzing Network / C2 Activity',
    'Identify hardcoded endpoints, protocol indicators, and download/upload logic.',
    [
      { stepNumber: 1, action: 'Check imports for networking APIs', tool: 'Metadata', tab: 'metadata', priority: 'critical', autoRunnable: true,
        explanation: 'Look for WinINet (InternetOpenUrl), WinHTTP (WinHttpOpen), WSA (WSAStartup), DNS (DnsQuery) in the imports table.' },
      { stepNumber: 2, action: 'Search strings for URLs, IPs, and domain patterns', tool: 'Strings', tab: 'strings', priority: 'critical', autoRunnable: true,
        explanation: 'C2 beacons embed endpoints. Filter for http://, https://, IP patterns (\\d+\\.\\d+\\.\\d+), User-Agent strings.' },
      { stepNumber: 3, action: 'Look for Base64 / encoded strings near network calls', tool: 'Strings', tab: 'strings', priority: 'high', autoRunnable: false,
        explanation: 'Encoded endpoints are common. Search for long alphanum strings (length > 32) that may be Base64-encoded URLs or keys.' },
      { stepNumber: 4, action: 'Trace network API call sites in disassembly', tool: 'Disassembly', tab: 'disassembly', priority: 'high', autoRunnable: false,
        explanation: 'Find where networking APIs are called and trace backwards to discover how the URL/IP is constructed at runtime.' },
      { stepNumber: 5, action: 'Run STRIKE string intelligence on network strings', tool: 'STRIKE', tab: 'strike', priority: 'medium', autoRunnable: false,
        explanation: 'STRIKE correlates suspicious strings with known threat patterns and highlights high-confidence IOCs.' },
      { stepNumber: 6, action: 'Run NEST for final verdict', tool: 'NEST', tab: 'nest', priority: 'low', autoRunnable: false,
        explanation: 'NEST will weight all network signals together and assess C2 likelihood.' },
    ],
  ),

  'persistence': makeTemplate(
    'Analyzing Persistence Mechanisms',
    'Identify registry keys, scheduled tasks, services, and startup locations.',
    [
      { stepNumber: 1, action: 'Check imports for persistence APIs', tool: 'Metadata', tab: 'metadata', priority: 'critical', autoRunnable: true,
        explanation: 'Look for RegSetValueEx, CreateService, OpenService, SHGetFolderPath, CreateScheduledTask.' },
      { stepNumber: 2, action: 'Search strings for registry paths', tool: 'Strings', tab: 'strings', priority: 'critical', autoRunnable: true,
        explanation: 'Persistence payloads embed paths: SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run, HKCU, HKLM, \\AppData\\.' },
      { stepNumber: 3, action: 'Search strings for service and task names', tool: 'Strings', tab: 'strings', priority: 'high', autoRunnable: false,
        explanation: 'Service display names and task XML fragments often appear as plaintext strings.' },
      { stepNumber: 4, action: 'Locate registry API call sites in disassembly', tool: 'Disassembly', tab: 'disassembly', priority: 'high', autoRunnable: false,
        explanation: 'Trace RegSetValueEx/RegCreateKeyEx calls to find what value is written and under which key.' },
      { stepNumber: 5, action: 'Examine CFG for initialization paths', tool: 'CFG', tab: 'cfg', priority: 'medium', autoRunnable: false,
        explanation: 'Persistence logic is usually in the first-run path. Look for a branch early in execution that creates registry keys.' },
      { stepNumber: 6, action: 'Run NEST for full persistence signal correlation', tool: 'NEST', tab: 'nest', priority: 'low', autoRunnable: false,
        explanation: 'NEST bundles registry + exec + file signals to assess persistence likelihood.' },
    ],
  ),

  'unpacking': makeTemplate(
    'Unpacking / Deobfuscation',
    'Identify the packer stub, decode loop, and original entry point (OEP).',
    [
      { stepNumber: 1, action: 'Inspect sections for packer indicators', tool: 'Metadata', tab: 'metadata', priority: 'critical', autoRunnable: true,
        explanation: 'Packed binaries have high-entropy sections (>7.0), unusual names (.UPX0, .text renamed), or executable+writable sections.' },
      { stepNumber: 2, action: 'Check raw hex at entry point for packer stubs', tool: 'Hex', tab: 'hex', priority: 'high', autoRunnable: false,
        explanation: 'UPX and similar packers start with a recognizable PUSHAD / SUB ESP or JMP pattern. Check the first 32–64 bytes.' },
      { stepNumber: 3, action: 'Look for decode loop in disassembly near entry', tool: 'Disassembly', tab: 'disassembly', priority: 'critical', autoRunnable: false,
        explanation: 'Packer stubs contain tight loops (XOR, ADD, ROL) that decode the real payload in memory. Look near the entry point.' },
      { stepNumber: 4, action: 'Run ECHO to detect dynamic loading patterns', tool: 'ECHO', tab: 'echo', priority: 'high', autoRunnable: false,
        explanation: 'ECHO identifies GetProcAddress/LoadLibrary patterns used to resolve APIs after unpacking without a static import table.' },
      { stepNumber: 5, action: 'Examine CFG for stub → OEP jump', tool: 'CFG', tab: 'cfg', priority: 'high', autoRunnable: false,
        explanation: 'Packer stubs end with a far JMP to the OEP. Look for a long unconditional jump from the stub region to a high-offset block.' },
      { stepNumber: 6, action: 'Run NEST to confirm packer classification', tool: 'NEST', tab: 'nest', priority: 'medium', autoRunnable: false,
        explanation: 'NEST will classify as "packer" if high-entropy sections, tight loops, and dynamic API resolution are all present.' },
    ],
  ),

  'obfuscation': makeTemplate(
    'Obfuscation Analysis',
    'Identify encoding schemes, control-flow obfuscation, and decryption routines.',
    [
      { stepNumber: 1, action: 'Calculate section entropy', tool: 'Metadata', tab: 'metadata', priority: 'critical', autoRunnable: true,
        explanation: 'Entropy >7.0 in a .text section is a strong indicator of encryption or heavy compression.' },
      { stepNumber: 2, action: 'Search strings for encoded payloads', tool: 'Strings', tab: 'strings', priority: 'high', autoRunnable: true,
        explanation: 'Long Base64, hex-encoded, or random-looking strings suggest embedded encoded blobs.' },
      { stepNumber: 3, action: 'Trace XOR/ROT loops in disassembly', tool: 'Disassembly', tab: 'disassembly', priority: 'critical', autoRunnable: false,
        explanation: 'Find XOR instructions inside loops — the operand is often the decode key. Note the key and loop bounds.' },
      { stepNumber: 4, action: 'Examine CFG for dispatcher / opaque predicates', tool: 'CFG', tab: 'cfg', priority: 'high', autoRunnable: false,
        explanation: 'Obfuscated CFGs show "spaghetti" graphs with many short blocks and unconditional jumps. Opaque predicates create fake branches.' },
      { stepNumber: 5, action: 'Run TALON for obfuscation behavioral classification', tool: 'TALON', tab: 'talon', priority: 'high', autoRunnable: false,
        explanation: 'TALON detects virtualized dispatch (switch-heavy control flow) and self-modifying code patterns.' },
      { stepNumber: 6, action: 'Run ECHO to check for dynamic API resolution', tool: 'ECHO', tab: 'echo', priority: 'medium', autoRunnable: false,
        explanation: 'Obfuscated binaries often resolve API names at runtime using hashed strings passed to custom GetProcAddress.' },
    ],
  ),

  'anti-analysis': makeTemplate(
    'Anti-Analysis / Evasion Detection',
    'Identify debugger detection, VM detection, timing checks, and sandbox evasion.',
    [
      { stepNumber: 1, action: 'Check imports for anti-debug / anti-VM APIs', tool: 'Metadata', tab: 'metadata', priority: 'critical', autoRunnable: true,
        explanation: 'IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess, CPUID, GetTickCount, QueryPerformanceCounter.' },
      { stepNumber: 2, action: 'Search strings for VM/sandbox artifact names', tool: 'Strings', tab: 'strings', priority: 'high', autoRunnable: true,
        explanation: 'VMware\\VMware Tools, VBoxService.exe, SandboxieRpcSS, wireshark.exe — environment probes are often string-compared.' },
      { stepNumber: 3, action: 'Find timing check patterns in disassembly', tool: 'Disassembly', tab: 'disassembly', priority: 'high', autoRunnable: false,
        explanation: 'RDTSC instructions or repeated QueryPerformanceCounter calls used to detect single-step debugging (timing delta too large).' },
      { stepNumber: 4, action: 'Examine CFG for evasion branches', tool: 'CFG', tab: 'cfg', priority: 'high', autoRunnable: false,
        explanation: 'Evasion checks create early-exit branches. Look for short conditional blocks near the entry that jump to TerminateProcess or ExitProcess.' },
      { stepNumber: 5, action: 'Run TALON for evasion behavioral patterns', tool: 'TALON', tab: 'talon', priority: 'high', autoRunnable: false,
        explanation: 'TALON flags anti-debug clusters and environment-check patterns from CFG shape analysis.' },
      { stepNumber: 6, action: 'Run NEST for full evasion signal report', tool: 'NEST', tab: 'nest', priority: 'medium', autoRunnable: false,
        explanation: 'NEST correlates anti-debug, anti-analysis, and evasion signals with behavioral tags.' },
    ],
  ),

  'credential-theft': makeTemplate(
    'Credential Theft Analysis',
    'Identify LSASS access, credential APIs, and dump artifacts.',
    [
      { stepNumber: 1, action: 'Check imports for credential/memory dump APIs', tool: 'Metadata', tab: 'metadata', priority: 'critical', autoRunnable: true,
        explanation: 'MiniDumpWriteDump, OpenProcess (PROCESS_VM_READ on lsass), LsaEnumerateLogonSessions, SamQueryInformationUser.' },
      { stepNumber: 2, action: 'Search strings for LSASS and credential artifacts', tool: 'Strings', tab: 'strings', priority: 'critical', autoRunnable: true,
        explanation: 'lsass.exe, sam, ntds.dit, \\SAM\\SAM\\Domains\\, sekurlsa — hardcoded strings are a strong indicator.' },
      { stepNumber: 3, action: 'Check imports for privilege escalation APIs', tool: 'Metadata', tab: 'metadata', priority: 'high', autoRunnable: true,
        explanation: 'AdjustTokenPrivileges, OpenProcessToken, LookupPrivilegeValue — elevating to SeDebugPrivilege is required before LSASS access.' },
      { stepNumber: 4, action: 'Find LSASS process enumeration in disassembly', tool: 'Disassembly', tab: 'disassembly', priority: 'high', autoRunnable: false,
        explanation: 'Trace CreateToolhelp32Snapshot / Process32Next calls — the loop usually compares process names against "lsass.exe".' },
      { stepNumber: 5, action: 'Run STRIKE for known credential dumper signatures', tool: 'STRIKE', tab: 'strike', priority: 'high', autoRunnable: false,
        explanation: 'STRIKE matches byte/string signatures of known tools (Mimikatz, ProcDump usage patterns).' },
      { stepNumber: 6, action: 'Run NEST for credential-theft verdict', tool: 'NEST', tab: 'nest', priority: 'medium', autoRunnable: false,
        explanation: 'NEST will tag behaviors as credential-access and produce a threat classification.' },
    ],
  ),

  'lateral-movement': makeTemplate(
    'Lateral Movement Analysis',
    'Identify network propagation, remote execution, and credential reuse.',
    [
      { stepNumber: 1, action: 'Check imports for remote execution APIs', tool: 'Metadata', tab: 'metadata', priority: 'critical', autoRunnable: true,
        explanation: 'WNetAddConnection, NetUseAdd, CreateProcessWithLogon, WMI (IWbemServices), Named Pipe client APIs.' },
      { stepNumber: 2, action: 'Search strings for UNC paths and remote targets', tool: 'Strings', tab: 'strings', priority: 'critical', autoRunnable: true,
        explanation: 'Lateral movement tools embed \\\\%s\\ADMIN$, \\\\%s\\IPC$, or remote IP/hostname patterns.' },
      { stepNumber: 3, action: 'Search strings for WMI queries and PowerShell cmdlets', tool: 'Strings', tab: 'strings', priority: 'high', autoRunnable: false,
        explanation: 'win32_process, SELECT * FROM Win32, powershell.exe -enc, Invoke-Command suggest WMI/remote PS lateral movement.' },
      { stepNumber: 4, action: 'Trace SMB connection setup in disassembly', tool: 'Disassembly', tab: 'disassembly', priority: 'high', autoRunnable: false,
        explanation: 'Find WNetAddConnection2/WNetAddConnection3 call sites and trace the remote name argument.' },
      { stepNumber: 5, action: 'Run ECHO for dynamic API patterns', tool: 'ECHO', tab: 'echo', priority: 'medium', autoRunnable: false,
        explanation: 'ECHO identifies runtime-resolved APIs like WMI COM interfaces that do not appear in the static import table.' },
      { stepNumber: 6, action: 'Run NEST for lateral movement verdict', tool: 'NEST', tab: 'nest', priority: 'low', autoRunnable: false,
        explanation: 'NEST correlates exec + network + credential signals to assess lateral movement capability.' },
    ],
  ),

  'ransomware': makeTemplate(
    'Ransomware Analysis',
    'Identify file enumeration, encryption routines, and ransom note artifacts.',
    [
      { stepNumber: 1, action: 'Check imports for file enumeration and crypto APIs', tool: 'Metadata', tab: 'metadata', priority: 'critical', autoRunnable: true,
        explanation: 'FindFirstFile/FindNextFile (recursive enumeration), CryptEncrypt/BCryptEncrypt, MoveFileEx (file rename to encrypted extension).' },
      { stepNumber: 2, action: 'Search strings for ransom note fragments', tool: 'Strings', tab: 'strings', priority: 'critical', autoRunnable: true,
        explanation: 'README.txt, YOUR_FILES_ARE_ENCRYPTED, bitcoin address pattern (1[a-zA-Z0-9]{25,34}), .onion URLs.' },
      { stepNumber: 3, action: 'Search strings for target file extensions', tool: 'Strings', tab: 'strings', priority: 'high', autoRunnable: false,
        explanation: 'Ransomware whitelists or blacklists extensions: .doc, .pdf, .xls, .jpg. Lists of extensions are strong indicators.' },
      { stepNumber: 4, action: 'Trace file enumeration loop in disassembly', tool: 'Disassembly', tab: 'disassembly', priority: 'high', autoRunnable: false,
        explanation: 'Find FindFirstFile call site and trace the loop — look for extension comparison and encryption call within the same loop body.' },
      { stepNumber: 5, action: 'Examine CFG for encryption dispatch pattern', tool: 'CFG', tab: 'cfg', priority: 'high', autoRunnable: false,
        explanation: 'Encryption dispatch: a loop node connects to a crypto call node then a rename/overwrite node. Classic ransomware CFG shape.' },
      { stepNumber: 6, action: 'Run NEST for ransomware classification', tool: 'NEST', tab: 'nest', priority: 'medium', autoRunnable: false,
        explanation: 'NEST will classify as ransomware-like when file + crypto + exec signals are all present above threshold.' },
    ],
  ),

  'general-analysis': makeTemplate(
    'General Binary Analysis',
    'Systematic walkthrough: metadata → strings → disassembly → behavior.',
    [
      { stepNumber: 1, action: 'Review file metadata and import table', tool: 'Metadata', tab: 'metadata', priority: 'high', autoRunnable: true,
        explanation: 'Check file type, architecture, size, section layout, and top imports. Establishes baseline before deeper analysis.' },
      { stepNumber: 2, action: 'Scan strings for IOCs and capabilities', tool: 'Strings', tab: 'strings', priority: 'high', autoRunnable: true,
        explanation: 'Strings reveal URLs, registry keys, API names, error messages, and embedded payloads without disassembly.' },
      { stepNumber: 3, action: 'Disassemble entry region and locate key functions', tool: 'Disassembly', tab: 'disassembly', priority: 'high', autoRunnable: false,
        explanation: 'Start at the entry point, identify the main function, and note any unusual patterns in the first few hundred instructions.' },
      { stepNumber: 4, action: 'Map control-flow graph for structural understanding', tool: 'CFG', tab: 'cfg', priority: 'medium', autoRunnable: false,
        explanation: 'CFG reveals complexity, loops, and dispatcher patterns. High block count with many indirect edges suggests obfuscation.' },
      { stepNumber: 5, action: 'Run NEST for automated signal correlation', tool: 'NEST', tab: 'nest', priority: 'medium', autoRunnable: false,
        explanation: 'NEST aggregates all signals and produces a verdict with confidence score, behavioral tags, and next-step recommendations.' },
      { stepNumber: 6, action: 'Review intelligence report', tool: 'Report', tab: 'report', priority: 'low', autoRunnable: false,
        explanation: 'The Report tab consolidates everything: verdict, behavioral tags, signal breakdown, and recommended follow-up actions.' },
    ],
  ),
};

// ─────────────────────────────────────────────────────────────────────────────
// Step 3 — Context Refinement
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Attach context hints to steps based on what the binary actually contains.
 * Mutates steps in-place (non-destructive — only adds contextHint).
 */
function applyContext(steps: ConsoleStep[], ctx: BinaryContext): boolean {
  let applied = false;
  const imports = ctx.importNames ?? [];
  const strings = ctx.stringTexts ?? [];
  const signals = ctx.signalIds ?? [];
  const behaviors = ctx.verdictBehaviors ?? [];

  for (const step of steps) {
    const hints: string[] = [];

    if (step.tab === 'metadata') {
      const injectionApis = imports.filter(n =>
        /VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx/i.test(n));
      if (injectionApis.length > 0) {
        hints.push(`Found injection API${injectionApis.length > 1 ? 's' : ''}: ${injectionApis.slice(0, 3).join(', ')}`);
      }
      const networkApis = imports.filter(n =>
        /InternetOpen|WinHttp|WSAStartup|connect|send|recv|socket/i.test(n));
      if (networkApis.length > 0) {
        hints.push(`Found networking API${networkApis.length > 1 ? 's' : ''}: ${networkApis.slice(0, 3).join(', ')}`);
      }
      const cryptoApis = imports.filter(n =>
        /CryptEncrypt|BCrypt|CryptDecrypt|CryptGenKey/i.test(n));
      if (cryptoApis.length > 0) {
        hints.push(`Found crypto API${cryptoApis.length > 1 ? 's' : ''}: ${cryptoApis.slice(0, 2).join(', ')}`);
      }
    }

    if (step.tab === 'strings') {
      const urlMatches = strings.filter(s => /https?:\/\//i.test(s)).slice(0, 2);
      if (urlMatches.length > 0) {
        hints.push(`URL${urlMatches.length > 1 ? 's' : ''} found: ${urlMatches.join(', ')}`);
      }
      const regKeyMatches = strings.filter(s =>
        /HKEY_|HKCU|HKLM|CurrentVersion\\Run/i.test(s)).slice(0, 2);
      if (regKeyMatches.length > 0) {
        hints.push(`Registry key${regKeyMatches.length > 1 ? 's' : ''}: ${regKeyMatches.join(', ')}`);
      }
      const ipMatches = strings.filter(s => /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(s)).slice(0, 2);
      if (ipMatches.length > 0) {
        hints.push(`IP address${ipMatches.length > 1 ? 'es' : ''}: ${ipMatches.join(', ')}`);
      }
    }

    if (step.tab === 'nest') {
      if (ctx.verdictClassification && ctx.verdictClassification !== 'unknown') {
        hints.push(`Current verdict: ${ctx.verdictClassification}`);
      }
      if (signals.length > 0) {
        hints.push(`${signals.length} active signal${signals.length > 1 ? 's' : ''} already detected`);
      }
      if (behaviors.length > 0) {
        hints.push(`Behaviors: ${behaviors.slice(0, 3).join(', ')}`);
      }
    }

    if (step.tab === 'cfg') {
      if (signals.includes('anti-analysis-patterns') || signals.includes('critical-patterns')) {
        hints.push('CFG has flagged patterns — inspect highlighted nodes');
      }
    }

    if (step.tab === 'disassembly') {
      if (imports.some(n => /IsDebuggerPresent|CheckRemoteDebugger/i.test(n))) {
        hints.push('Anti-debug API in imports — look near entry for evasion check');
      }
    }

    if (hints.length > 0) {
      step.contextHint = hints.join(' · ');
      applied = true;
    }
  }

  return applied;
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 4 — Auto-intent from binary context (no user prompt)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Suggest an intent based purely on available binary signals when the user
 * has not typed anything yet.
 */
export function suggestIntentFromContext(ctx: BinaryContext): OperatorIntent | null {
  const imports = ctx.importNames ?? [];
  const behaviors = ctx.verdictBehaviors ?? [];
  const classification = ctx.verdictClassification ?? '';

  if (classification === 'ransomware-like') return 'ransomware';
  if (classification === 'dropper' || classification === 'loader') return 'injection';
  if (classification === 'info-stealer') return 'credential-theft';

  if (behaviors.includes('code-injection')) return 'injection';
  if (behaviors.includes('c2-communication')) return 'networking';
  if (behaviors.includes('persistence')) return 'persistence';
  if (behaviors.includes('credential-access')) return 'credential-theft';
  if (behaviors.includes('defense-evasion')) return 'anti-analysis';
  if (behaviors.includes('file-encryption')) return 'ransomware';
  if (behaviors.includes('lateral-movement')) return 'lateral-movement';

  if (imports.some(n => /VirtualAllocEx|WriteProcessMemory|CreateRemoteThread/i.test(n))) return 'injection';
  if (imports.some(n => /InternetOpen|WinHttp|WSAStartup/i.test(n))) return 'networking';
  if (imports.some(n => /RegSetValueEx|CreateService/i.test(n))) return 'persistence';
  if (imports.some(n => /CryptEncrypt|BCryptEncrypt/i.test(n))) return 'ransomware';
  if (imports.some(n => /IsDebuggerPresent|CheckRemoteDebugger/i.test(n))) return 'anti-analysis';

  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 5 — Public API: generateWorkflow
// ─────────────────────────────────────────────────────────────────────────────

let _stepCounter = 0;
function makeId(): string {
  return `cs-${++_stepCounter}-${Date.now().toString(36)}`;
}

/**
 * Generate a complete ConsoleWorkflow from a user prompt and optional binary context.
 *
 * @param userPrompt  Free-text user objective (may be empty string for context-driven)
 * @param context     Optional binary data already loaded in HexHawk
 */
export function generateWorkflow(
  userPrompt: string,
  context: BinaryContext = {},
): ConsoleWorkflow {
  // Determine intent
  let intent: OperatorIntent;
  if (userPrompt.trim().length > 0) {
    intent = classifyIntent(userPrompt);
  } else {
    intent = suggestIntentFromContext(context) ?? 'general-analysis';
  }

  const template = WORKFLOW_TEMPLATES[intent];

  // Hydrate steps with IDs and initial status
  const steps: ConsoleStep[] = template.steps.map(s => ({
    ...s,
    id: makeId(),
    status: 'pending',
  }));

  // Apply binary context hints
  const contextApplied = applyContext(steps, context);

  return {
    intent,
    intentLabel: INTENT_LABELS[intent],
    title: template.title,
    description: template.description,
    steps,
    contextApplied,
  };
}

/**
 * Mark a step as active/done/skipped. Returns a new array (immutable update).
 */
export function updateStepStatus(
  steps: ConsoleStep[],
  stepId: string,
  status: StepStatus,
): ConsoleStep[] {
  return steps.map(s => s.id === stepId ? { ...s, status } : s);
}
