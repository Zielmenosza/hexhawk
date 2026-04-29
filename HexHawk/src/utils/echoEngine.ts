/**
 * echoEngine — ECHO Fuzzy Signature Recognition Engine
 *
 * Extends signatureEngine.ts with:
 *   - Fuzzy / approximate matching via Jaccard similarity on normalized token sets
 *   - Wildcard patterns: '??' tokens that match any single normalized instruction
 *   - Context boosting: import names and string fragments raise match confidence
 *   - Behavioral clustering: group matches into behavioral categories
 *   - Correlation signals: feed into correlationEngine
 *
 * Unlike signatureEngine.ts (exact FNV-1a hash equality), ECHO tolerates
 * inlined variants, register renames, and minor compiler differences.
 */

import { normalizeInstruction } from './signatureEngine';
import type { FunctionMetadata } from '../App';
import type { DisassembledInstruction } from './decompilerEngine';
import type { BehavioralTag } from './correlationEngine';

// ── Echo category ─────────────────────────────────────────────────────────────

export type EchoCategory =
  | 'libc-memory'
  | 'libc-string'
  | 'libc-io'
  | 'heap-management'
  | 'crypto-hash'
  | 'crypto-cipher'
  | 'compression'
  | 'network-io'
  | 'process-exec'
  | 'code-injection'
  | 'anti-debug'
  | 'compiler-runtime'
  | 'dynamic-load'
  | 'persistence'
  | 'encoding'
  | 'string-decode';

export const ECHO_CATEGORY_LABELS: Record<EchoCategory, string> = {
  'libc-memory':      'Memory Operations',
  'libc-string':      'String Handling',
  'libc-io':          'I/O & Formatting',
  'heap-management':  'Heap Management',
  'crypto-hash':      'Cryptographic Hash',
  'crypto-cipher':    'Cipher / Encryption',
  'compression':      'Compression',
  'network-io':       'Network I/O',
  'process-exec':     'Process Execution',
  'code-injection':   'Code Injection',
  'anti-debug':       'Anti-Debug',
  'compiler-runtime': 'Compiler Runtime',
  'dynamic-load':     'Dynamic Loading',
  'persistence':      'Persistence',
  'encoding':         'Encoding / Obfuscation',
  'string-decode':    'String Decode / Deobfuscation',
};

export const ECHO_CATEGORY_COLORS: Record<EchoCategory, string> = {
  'libc-memory':      '#4caf50',
  'libc-string':      '#66bb6a',
  'libc-io':          '#81c784',
  'heap-management':  '#a5d6a7',
  'crypto-hash':      '#ff9800',
  'crypto-cipher':    '#fb8c00',
  'compression':      '#ffb74d',
  'network-io':       '#2196f3',
  'process-exec':     '#ef5350',
  'code-injection':   '#b71c1c',
  'anti-debug':       '#e53935',
  'compiler-runtime': '#607d8b',
  'dynamic-load':     '#9c27b0',
  'persistence':      '#c62828',
  'encoding':         '#ff7043',
  'string-decode':    '#e040fb',
};

// ── Echo pattern types ────────────────────────────────────────────────────────

export interface EchoPattern {
  id:             string;
  name:           string;
  displayName:    string;
  category:       EchoCategory;
  /** Normalized instruction tokens; '??' = wildcard (match any) */
  tokens:         string[];
  /** Minimum Jaccard similarity to consider a match (0–1) */
  minSimilarity:  number;
  baseConfidence: number;    // 0–100
  behaviors:      BehavioralTag[];
  description:    string;
  safe:           boolean;
  contextClues: {
    importNames?:     string[];   // import names that boost confidence
    stringFragments?: string[];   // string literals that boost confidence
  };
}

export type MatchMethod = 'exact' | 'fuzzy' | 'wildcard';

export interface EchoMatch {
  pattern:         EchoPattern;
  functionAddress: number;
  similarity:      number;   // 0–1 (Jaccard or wildcard fraction)
  score:           number;   // 0–100 final confidence after context boost
  matchOffset:     number;   // instruction index within function
  windowSize:      number;   // instructions in matched window
  contextBoost:    number;   // points added from import/string context
  method:          MatchMethod;
}

export interface EchoContext {
  imports:          string[];   // import names from binary
  strings:          string[];   // string literals from binary
  knownSigMatches:  string[];   // ids of matches from signatureEngine (to avoid duplicate noise)
}

export interface EchoScanResult {
  matches:           EchoMatch[];
  scannedFunctions:  number;
  scannedInstructions: number;
  fuzzyMatchCount:   number;
  exactMatchCount:   number;
  wildcardMatchCount: number;
  contextBoostCount: number;
}

export interface EchoCorrelationSignal {
  hasLibcFunctions:       boolean;
  hasCryptoAlgorithm:     boolean;
  hasNetworkPattern:      boolean;
  hasInjectionPattern:    boolean;
  hasAntiDebugPattern:    boolean;
  hasCompilerArtifacts:   boolean;
  hasDynamicLoad:         boolean;
  hasPersistence:         boolean;
  hasStringDecode:        boolean;
  topMatchNames:          string[];   // top 5 display names
  averageConfidence:      number;
  patternDiversity:       number;     // unique category count
  behavioralTags:         BehavioralTag[];
}

// ── Echo pattern database ─────────────────────────────────────────────────────

function ep(
  id: string,
  name: string,
  displayName: string,
  category: EchoCategory,
  tokens: string[],
  minSimilarity: number,
  baseConfidence: number,
  behaviors: BehavioralTag[],
  description: string,
  safe = true,
  contextClues: EchoPattern['contextClues'] = {},
): EchoPattern {
  return {
    id, name, displayName, category,
    tokens: tokens.map(t => t === '??' ? '??' : t.toLowerCase().trim()),
    minSimilarity, baseConfidence, behaviors, description, safe, contextClues,
  };
}

export const ECHO_DB: EchoPattern[] = [

  // ── Compiler runtime ──────────────────────────────────────────────────────

  ep('echo-prologue-frame',
    'func_prologue',          'Standard Frame Prologue',
    'compiler-runtime',
    ['push %r', 'mov %r, %r', '??', 'sub %r, %imm'],
    0.60, 82, [], 'Frame-based function prologue with stack reservation'
  ),

  ep('echo-epilogue-any',
    'func_epilogue',          'Function Epilogue (any form)',
    'compiler-runtime',
    ['??', 'pop %r', 'ret'],
    0.65, 80, [], 'Function epilogue — pop saved register and return'
  ),

  ep('echo-stack-canary',
    'stack_canary',           'Stack Security Cookie',
    'compiler-runtime',
    ['mov %r, %sz %seg:[%imm]', '??', 'mov %sz [%r + %imm], %r', '??', 'xor %r, %sz %seg:[%imm]'],
    0.55, 85, [], 'MSVC/GCC stack canary setup + teardown',
    true, { importNames: ['__security_check_cookie', '__security_init_cookie'] }
  ),

  // ── Memory / string operations ────────────────────────────────────────────

  ep('echo-memcpy-repmovsb',
    'memcpy',                 'Memory Copy (rep movs)',
    'libc-memory',
    ['??', 'rep movsb %sz [%r], %sz [%r]'],
    0.70, 90, [], 'REP MOVSB bulk copy — likely memcpy or memmove'
  ),

  ep('echo-memset-repstosb',
    'memset',                 'Memory Set (rep stos)',
    'libc-memory',
    ['xor %r, %r', '??', 'rep stosb %sz [%r], %r'],
    0.60, 88, [], 'REP STOSB bulk set — likely memset or bzero'
  ),

  ep('echo-strlen-repne',
    'strlen',                 'String Length (repne scasb)',
    'libc-string',
    ['cld', 'repne scasb %r, %sz [%r]', 'not %r', 'dec %r'],
    0.65, 85, [], 'Classic strlen using REPNE SCASB + NOT/DEC pattern'
  ),

  ep('echo-strlen-loop',
    'strlen_loop',            'String Length (byte loop)',
    'libc-string',
    ['xor %r, %r', '??', 'cmp %sz [%r + %r], 0', '??', 'inc %r', 'jmp'],
    0.55, 72, [], 'strlen byte-scan loop variant'
  ),

  ep('echo-strcpy-loop',
    'strcpy',                 'String Copy Loop',
    'libc-string',
    ['mov %r, %sz [%r + %r]', 'mov %sz [%r + %r], %r', '??', 'test %r, %r', '??', 'jnz'],
    0.55, 70, [], 'strcpy/strncpy byte-by-byte copy loop'
  ),

  // ── Heap management ───────────────────────────────────────────────────────

  ep('echo-malloc-wrapper',
    'malloc_wrap',            'Heap Allocator Wrapper',
    'heap-management',
    ['??', 'mov %r, %imm', '??', 'call', '??', 'test %r, %r', '??'],
    0.50, 68, ['dynamic-resolution'],
    'malloc/HeapAlloc wrapper with null-check pattern',
    true, { importNames: ['HeapAlloc', 'malloc', 'LocalAlloc', 'GlobalAlloc', 'VirtualAlloc'] }
  ),

  ep('echo-free-wrapper',
    'free_wrap',              'Heap Free Wrapper',
    'heap-management',
    ['??', 'test %r, %r', '??', 'jz', '??', 'call'],
    0.55, 65, [],
    'free/HeapFree wrapper with null guard',
    true, { importNames: ['HeapFree', 'free', 'LocalFree', 'GlobalFree', 'VirtualFree'] }
  ),

  // ── Cryptographic patterns ────────────────────────────────────────────────

  ep('echo-xor-key-loop',
    'xor_cipher',             'XOR Key Schedule Loop',
    'crypto-cipher',
    ['xor %sz [%r + %r], %r', '??', 'inc %r', '??', 'cmp %r, %r', '??', 'jb'],
    0.55, 78, ['code-decryption'],
    'XOR cipher loop — decryption or encoding with repeating key',
    false, { stringFragments: ['key', 'encrypt', 'decrypt', 'cipher', 'xor'] }
  ),

  ep('echo-rol-hash-round',
    'rol_hash',               'Rotation Hash Round',
    'crypto-hash',
    ['rol %r, %imm', '??', 'xor %r, %r', '??', 'add %r, %r', '??'],
    0.50, 72, ['code-decryption'],
    'ROL/XOR/ADD pattern — one round of a hash function or block cipher',
    false
  ),

  ep('echo-crc32-loop',
    'crc32',                  'CRC32 Computation',
    'crypto-hash',
    ['xor %r, %r', '??', 'shr %r, %imm', '??', 'xor %r, %addr', '??', 'jnz'],
    0.55, 75, [],
    'CRC32 polynomial division loop',
    true, { importNames: ['crc32', 'RtlComputeCrc32'] }
  ),

  ep('echo-sha-sigma',
    'sha_sigma',              'SHA Sigma Permutation',
    'crypto-hash',
    ['ror %r, %imm', '??', 'ror %r, %imm', '??', 'shr %r, %imm', 'xor %r, %r', 'xor %r, %r'],
    0.58, 78, [],
    'SHA-256 Σ/σ permutation sequence (ROR + SHR + XOR)',
    true, { importNames: ['SHA256', 'CryptHashData', 'BCryptHashData'] }
  ),

  // ── Anti-debug patterns ───────────────────────────────────────────────────

  ep('echo-rdtsc-timing',
    'rdtsc_timing',           'RDTSC Timing Check',
    'anti-debug',
    ['rdtsc', '??', 'shl %r, %imm', 'or %r, %r', '??', 'rdtsc', '??', 'sub %r, %r'],
    0.55, 82, ['anti-analysis'],
    'Double RDTSC with delta comparison — detects debugger slowdown',
    false
  ),

  ep('echo-peb-debugger',
    'peb_debugger_flag',      'PEB.IsDebuggerPresent Check',
    'anti-debug',
    ['mov %r, %sz %seg:[%imm]', 'mov %r, %sz [%r + %imm]', 'movzx %r, %sz [%r + %imm]', '??', 'test %r, %r'],
    0.58, 85, ['anti-analysis'],
    'PEB->BeingDebugged byte check via GS:[0x60]+offset',
    false, { importNames: ['IsDebuggerPresent'] }
  ),

  ep('echo-nt-global-flag',
    'nt_global_flag',         'NtGlobalFlag Heap Check',
    'anti-debug',
    ['mov %r, %sz %seg:[%imm]', '??', 'mov %r, %sz [%r + %imm]', '??', 'and %r, %imm', 'test %r, %r'],
    0.55, 80, ['anti-analysis'],
    'NtGlobalFlag (PEB+0xBC) check — detects heap debug flags',
    false
  ),

  ep('echo-checkremotedebugger',
    'remote_debugger_check',  'Remote Debugger Check',
    'anti-debug',
    ['??', 'lea %r, [%r + %imm]', '??', 'call', '??', 'movzx %r, %sz [%r]', '??', 'test %r, %r'],
    0.52, 76, ['anti-analysis'],
    'CheckRemoteDebuggerPresent API call and result check',
    false, { importNames: ['CheckRemoteDebuggerPresent', 'NtQueryInformationProcess'] }
  ),

  // ── Code injection ────────────────────────────────────────────────────────

  ep('echo-virtualalloc-exec',
    'virtualalloc_exec',      'VirtualAlloc + Execute Pattern',
    'code-injection',
    ['??', 'mov %r, %imm', '??', 'call', '??', 'test %r, %r', '??', 'call %r'],
    0.50, 80, ['code-injection'],
    'VirtualAlloc PAGE_EXECUTE_READWRITE + indirect call into allocated buffer',
    false, { importNames: ['VirtualAlloc', 'VirtualAllocEx', 'NtAllocateVirtualMemory'] }
  ),

  ep('echo-writeprocessmemory',
    'wpm_sequence',           'WriteProcessMemory Sequence',
    'code-injection',
    ['??', 'mov %r, %r', '??', 'call', '??', 'test %r, %r', '??', 'call', '??'],
    0.50, 78, ['code-injection'],
    'WriteProcessMemory + CreateRemoteThread injection pattern',
    false, { importNames: ['WriteProcessMemory', 'CreateRemoteThread', 'NtWriteVirtualMemory'] }
  ),

  // ── Network I/O ───────────────────────────────────────────────────────────

  ep('echo-winsock-connect',
    'winsock_connect',        'Winsock Connect Sequence',
    'network-io',
    ['??', 'call', '??', 'lea %r, [%r + %imm]', '??', 'push %imm', '??', 'call'],
    0.52, 72, ['c2-communication'],
    'WSAStartup → socket → connect sequence',
    false, { importNames: ['WSAStartup', 'socket', 'connect', 'WSAConnect', 'WSASocket'] }
  ),

  ep('echo-http-request',
    'winhttp_request',        'WinHTTP Request Pattern',
    'network-io',
    ['??', 'call', '??', 'test %r, %r', '??', 'call', '??', 'test %r, %r', '??', 'call'],
    0.50, 70, ['c2-communication'],
    'WinHTTP or WinINet open/request/send sequence',
    false, { importNames: ['WinHttpOpen', 'WinHttpConnect', 'WinHttpSendRequest',
                            'InternetOpenA', 'InternetOpenUrlA', 'HttpSendRequestA'] }
  ),

  // ── Process execution ─────────────────────────────────────────────────────

  ep('echo-createprocess',
    'createprocess',          'Process Creation',
    'process-exec',
    ['??', 'lea %r, [%r + %imm]', '??', 'lea %r, [%r + %imm]', '??', 'call'],
    0.52, 75, ['process-execution'],
    'CreateProcess / ShellExecute process launch pattern',
    false, { importNames: ['CreateProcessA', 'CreateProcessW', 'ShellExecuteA', 'ShellExecuteW',
                            'WinExec', 'system'] }
  ),

  // ── Dynamic loading ───────────────────────────────────────────────────────

  ep('echo-loadlibrary-getproc',
    'loadlib_getproc',        'LoadLibrary + GetProcAddress',
    'dynamic-load',
    ['??', 'call', '??', 'test %r, %r', '??', 'lea %r, [%r + %imm]', '??', 'call'],
    0.50, 78, ['dynamic-resolution'],
    'LoadLibraryA/W + GetProcAddress dynamic import resolution',
    false, { importNames: ['LoadLibraryA', 'LoadLibraryW', 'GetProcAddress',
                            'LdrLoadDll', 'LdrGetProcedureAddress'] }
  ),

  ep('echo-api-hashing',
    'api_hash_resolve',       'API Hash Resolution',
    'dynamic-load',
    ['xor %r, %r', '??', 'ror %r, %imm', '??', 'add %r, %sz [%r]', '??', 'cmp %r, %addr'],
    0.55, 82, ['dynamic-resolution'],
    'API name hashing loop with ROR — common in shellcode/implants',
    false
  ),

  // ── Persistence ───────────────────────────────────────────────────────────

  ep('echo-reg-set-value',
    'registry_persist',       'Registry Persistence',
    'persistence',
    ['??', 'call', '??', 'test %r, %r', '??', 'lea %r, [%r + %imm]', '??', 'call', '??', 'call'],
    0.50, 75, ['persistence'],
    'RegOpenKey + RegSetValue — likely writing run key for persistence',
    false, { importNames: ['RegOpenKeyA', 'RegOpenKeyW', 'RegSetValueExA', 'RegSetValueExW',
                            'RegCreateKeyExA', 'RegCreateKeyExW'] }
  ),

  ep('echo-scheduled-task',
    'scheduled_task',         'Task Scheduler COM Pattern',
    'persistence',
    ['??', 'call', '??', 'test %r, %r', '??', 'mov %r, %imm', '??', 'call', '??', 'call'],
    0.48, 68, ['persistence'],
    'COM-based task scheduler sequence (ITaskService → ITask)',
    false, { stringFragments: ['Task Scheduler', 'ITask', 'ITaskService', '.job'] }
  ),

  // ── Encoding / obfuscation ────────────────────────────────────────────────

  ep('echo-base64-encode',
    'base64_encode',          'Base64 Encoding',
    'encoding',
    ['??', 'shr %r, %imm', 'and %r, %imm', '??', 'add %r, %addr', '??', 'movzx %r, %sz [%r]'],
    0.55, 73, [],
    'Base64 index-into-alphabet encoding pattern',
    true, { stringFragments: ['ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'] }
  ),

  ep('echo-rc4-ksa',
    'rc4_ksa',                'RC4 Key Schedule',
    'crypto-cipher',
    ['xor %r, %r', '??', 'mov %sz [%r + %r], %r', '??', 'inc %r', '??', 'cmp %r, %imm', '??', 'jb'],
    0.55, 80, ['code-decryption'],
    'RC4 Key Scheduling Algorithm — array initialization pattern',
    false
  ),

  ep('echo-rc4-prga',
    'rc4_prga',               'RC4 Pseudo-Random Generation',
    'crypto-cipher',
    ['inc %r', 'and %r, %imm', 'movzx %r, %sz [%r + %r]', '??', 'add %r, %r', 'and %r, %imm',
     'xchg %sz [%r + %r], %r', '??', 'add %r, %r', 'and %r, %imm'],
    0.58, 85, ['code-decryption'],
    'RC4 PRGA inner loop — i/j update and swap pattern',
    false
  ),

  // ── Crypto — FLARE-derived ────────────────────────────────────────────────

  ep('echo-aes-sbox-sub',
    'aes_subbytes',           'AES SubBytes S-box Lookup',
    'crypto-cipher',
    ['movzx %r, %sz [%addr + %r]', '??', 'movzx %r, %sz [%addr + %r]', '??',
     'movzx %r, %sz [%addr + %r]', 'xor %r, %r'],
    0.60, 83, ['code-decryption'],
    'AES SubBytes: multiple MOVZX table lookups into the Rijndael S-box followed by XOR mixing',
    false,
    { importNames:     ['AES_encrypt', 'AES_decrypt', 'BCryptEncrypt', 'BCryptDecrypt',
                        'CryptEncrypt', 'CryptDecrypt'],
      stringFragments: ['aes', 'rijndael', 'sbox', 'AES-'] }
  ),

  ep('echo-aes-keyschedule',
    'aes_keyschedule',        'AES Key Expansion (SubWord + RotWord)',
    'crypto-cipher',
    ['movzx %r, %sz [%addr + %r]', 'ror %r, %imm', '??', 'xor %r, %r', '??',
     'xor %r, %sz [%r + %imm]', '??', 'mov %sz [%r + %imm], %r'],
    0.50, 80, ['code-decryption'],
    'AES key schedule: SubWord (S-box lookup), RotWord (ROR 8), Rcon XOR',
    false,
    { importNames:     ['AES_set_encrypt_key', 'AES_set_decrypt_key', 'BCryptGenerateSymmetricKey'],
      stringFragments: ['aes', 'key', 'expand', 'schedule'] }
  ),

  ep('echo-chacha20-qr',
    'chacha20_quarter_round',  'ChaCha20 Quarter-Round',
    'crypto-cipher',
    ['add %r, %r', 'xor %r, %r', 'rol %r, %imm',
     'add %r, %r', 'xor %r, %r', 'rol %r, %imm',
     'add %r, %r', 'xor %r, %r', 'rol %r, %imm',
     'add %r, %r', 'xor %r, %r', 'rol %r, %imm'],
    0.70, 90, ['code-decryption'],
    'ChaCha20 quarter-round: four consecutive add→xor→rol chains',
    false,
    { stringFragments: ['chacha', 'chacha20', 'salsa', 'expand 32-byte k'] }
  ),

  ep('echo-tea-round',
    'tea_round',               'TEA / XTEA Round',
    'crypto-cipher',
    ['shl %r, %imm', '??', 'add %r, %r', 'xor %r, %r',
     'shr %r, %imm', '??', 'add %r, %r', 'xor %r, %r', 'add %r, %r'],
    0.58, 78, ['code-decryption'],
    'TEA/XTEA round: dual shl+shr Feistel structure with delta-key addition',
    false,
    { stringFragments: ['tea', 'xtea', 'xxtea', 'delta', 'feistel'] }
  ),

  ep('echo-galois-lfsr',
    'galois_lfsr',             'Galois LFSR Feedback',
    'crypto-hash',
    ['shr %r, %imm', '??', 'jnc', '??', 'xor %r, %imm', '??', 'dec %r', '??', 'jnz'],
    0.60, 72, [],
    'Galois-form LFSR: conditional polynomial XOR on carry-out of right-shift',
    false,
    { stringFragments: ['lfsr', 'polynomial', 'feedback', 'prng', 'crc'] }
  ),

  // ── String decode — FLARE-derived ─────────────────────────────────────────

  ep('echo-stack-string',
    'stack_string_build',      'Stack String Construction',
    'string-decode',
    ['mov %sz [%r + %imm], %imm', 'mov %sz [%r + %imm], %imm',
     'mov %sz [%r + %imm], %imm', 'mov %sz [%r + %imm], %imm',
     'mov %sz [%r + %imm], %imm', 'mov %sz [%r + %imm], %imm'],
    0.80, 74, ['code-decryption'],
    'Consecutive immediate-to-stack byte writes — string assembled on stack to avoid IAT/data-section scanning',
    false,
    { stringFragments: ['cmd', 'http', 'exe', 'dll', 'reg', 'run'] }
  ),

  ep('echo-xor-counter-key',
    'xor_counter_decode',      'XOR Counter-Keyed String Decode',
    'string-decode',
    ['movzx %r, %sz [%r + %r]', 'xor %r, %r', '??', 'mov %sz [%r + %r], %r',
     'inc %r', 'cmp %r, %imm', '??', 'jb'],
    0.55, 79, ['code-decryption'],
    'XOR decode loop where the loop counter contributes to the key — common FLARE obfuscation',
    false
  ),

  ep('echo-lookup-table-decode',
    'table_decode',            'Lookup-Table String Decode',
    'string-decode',
    ['and %r, %imm', 'movzx %r, %sz [%addr + %r]', '??',
     'shl %r, %imm', '??', 'or %r, %r', '??', 'inc %r'],
    0.52, 72, ['code-decryption'],
    'Custom decode-table lookup: mask bits, index table, accumulate — covers custom base64 alphabets and substitution ciphers',
    false,
    { stringFragments: ['ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                        'decode', 'charset', 'alphabet', 'table'] }
  ),

  ep('echo-wide-xor-decode',
    'wide_string_xor',         'Wide-String XOR Decode',
    'string-decode',
    ['movzx %r, %sz [%r + %r]', 'xor %r, %imm', 'mov %sz [%r + %r], %r',
     '??', 'add %r, %imm', '??', 'jl'],
    0.60, 75, ['code-decryption'],
    'UTF-16 / wide-character XOR decode loop — decodes wchar_t strings at runtime',
    false
  ),

  // ── Network — FLARE-derived ───────────────────────────────────────────────

  ep('echo-dns-exfil',
    'dns_tunnel',              'DNS Tunneling / TXT Record Exfil',
    'network-io',
    ['??', 'push %imm', '??', 'push %r', '??', 'call',
     '??', 'test %r, %r', '??', 'jnz', '??', 'mov %r, %sz [%r + %imm]'],
    0.48, 72, ['c2-communication', 'data-exfiltration'],
    'DnsQuery call with TXT record type and result pointer dereference — DNS tunnel or C2 over DNS',
    false,
    { importNames:     ['DnsQuery_A', 'DnsQuery_W', 'DnsQueryEx', 'DnsRecordListFree',
                        'DnsNameCompare_A', 'GetAddrInfoExW'],
      stringFragments: ['_dns.', '.txt', 'TXT', 'dns', 'tunnel'] }
  ),

  ep('echo-ssl-schannel',
    'ssl_schannel',            'SChannel / TLS Handshake',
    'network-io',
    ['??', 'call', '??', 'test %r, %r', '??', 'jne',
     '??', 'call', '??', 'cmp %r, %imm', '??', 'je'],
    0.48, 72, ['c2-communication'],
    'SChannel SSPI TLS handshake: AcquireCredentialsHandle → InitializeSecurityContext chain',
    false,
    { importNames:     ['AcquireCredentialsHandleA', 'AcquireCredentialsHandleW',
                        'InitializeSecurityContextA', 'InitializeSecurityContextW',
                        'EncryptMessage', 'DecryptMessage', 'FreeCredentialsHandle',
                        'SslStreamToContext'] }
  ),

  ep('echo-http-beacon',
    'http_beacon',             'Periodic HTTP Beacon',
    'network-io',
    ['push %imm', '??', 'call', '??', 'call', '??', 'test %r, %r', '??', 'call', '??', 'jmp'],
    0.48, 65, ['c2-communication'],
    'Sleep + HTTP open/request/send loop — periodic C2 beacon pattern',
    false,
    { importNames:     ['Sleep', 'WinHttpSendRequest', 'WinHttpOpenRequest',
                        'HttpSendRequestA', 'HttpSendRequestW', 'InternetOpenUrlA'],
      stringFragments: ['beacon', 'sleep', 'interval', 'check-in', 'callback'] }
  ),

  ep('echo-icmp-tunnel',
    'icmp_tunnel',             'ICMP Echo Tunnel',
    'network-io',
    ['??', 'call', '??', 'test %r, %r', '??', 'lea %r, [%r + %imm]',
     '??', 'call', '??', 'test %r, %r'],
    0.50, 70, ['c2-communication', 'data-exfiltration'],
    'IcmpCreateFile + IcmpSendEcho sequence — covert channel over ICMP echo',
    false,
    { importNames:     ['IcmpCreateFile', 'IcmpSendEcho', 'IcmpSendEcho2',
                        'Icmp6CreateFile', 'Icmp6SendEcho2'] }
  ),
];

// ── Normalization helpers ─────────────────────────────────────────────────────

/** Build array of normalized strings for a window of instructions */
function buildNormWindow(
  instructions: DisassembledInstruction[],
  start: number,
  size: number,
): string[] {
  return instructions
    .slice(start, start + size)
    .map(ins => normalizeInstruction(ins.mnemonic, ins.operands));
}

// ── Jaccard similarity ────────────────────────────────────────────────────────

function jaccardSimilarity(a: string[], b: string[]): number {
  if (a.length === 0 && b.length === 0) return 1;
  const setA = new Set(a);
  const setB = new Set(b);
  let inter = 0;
  for (const x of setA) { if (setB.has(x)) inter++; }
  const union = setA.size + setB.size - inter;
  return union === 0 ? 1 : inter / union;
}

// ── Wildcard match ────────────────────────────────────────────────────────────

/**
 * Match a window of normalized instructions against a wildcard pattern.
 * Returns fraction of non-wildcard positions that matched (0–1), or null if no match.
 */
function wildcardMatch(
  window: string[],
  pattern: string[],
  minFraction: number,
): number | null {
  if (window.length !== pattern.length) return null;
  let required = 0;
  let matched  = 0;
  for (let i = 0; i < pattern.length; i++) {
    if (pattern[i] === '??') continue;
    required++;
    if (window[i] === pattern[i]) matched++;
  }
  if (required === 0) return 1;   // all wildcards → trivial match
  const frac = matched / required;
  return frac >= minFraction ? frac : null;
}

// ── Context boost calculation ─────────────────────────────────────────────────

function computeContextBoost(pattern: EchoPattern, ctx: EchoContext): number {
  let boost = 0;
  const { importNames = [], stringFragments = [] } = pattern.contextClues;

  for (const imp of importNames) {
    if (ctx.imports.some(i => i.toLowerCase() === imp.toLowerCase())) {
      boost += 6;
    }
  }
  for (const frag of stringFragments) {
    if (ctx.strings.some(s => s.toLowerCase().includes(frag.toLowerCase()))) {
      boost += 4;
    }
  }
  return Math.min(20, boost);   // cap at +20 points
}

// ── Single-function scanner ───────────────────────────────────────────────────

function scanFunctionEcho(
  instructions: DisassembledInstruction[],
  funcAddr: number,
  ctx: EchoContext,
): EchoMatch[] {
  if (instructions.length === 0) return [];

  const normalized = instructions.map(ins =>
    normalizeInstruction(ins.mnemonic, ins.operands),
  );

  const matches: EchoMatch[] = [];
  const seenIds  = new Set<string>();
  const hasWild  = (tokens: string[]) => tokens.includes('??');

  for (const pattern of ECHO_DB) {
    // Skip if already matched this pattern in this function
    if (seenIds.has(pattern.id)) continue;

    const pLen = pattern.tokens.length;
    if (pLen > normalized.length) continue;

    const contextBoost = computeContextBoost(pattern, ctx);
    let bestMatch: EchoMatch | null = null;

    // Try windows of size pLen and pLen+1 (tolerate one extra instruction)
    const maxWin = Math.min(pLen + 1, normalized.length);

    for (let winLen = pLen; winLen <= maxWin; winLen++) {
      for (let i = 0; i <= normalized.length - winLen; i++) {
        const window = normalized.slice(i, i + winLen);
        let similarity: number;
        let method: MatchMethod;

        if (hasWild(pattern.tokens)) {
          // Wildcard matching — requires exact size
          if (winLen !== pLen) continue;
          const frac = wildcardMatch(window, pattern.tokens, pattern.minSimilarity);
          if (frac === null) continue;
          similarity = frac;
          method = 'wildcard';
        } else {
          // Jaccard similarity on normalized token sets
          const normPattern = pattern.tokens;
          similarity = jaccardSimilarity(window, normPattern);
          if (similarity < pattern.minSimilarity) continue;
          // Check if it's effectively an exact match (all tokens equal)
          const isExact = window.length === pLen &&
            window.every((t, idx) => t === normPattern[idx]);
          method = isExact ? 'exact' : 'fuzzy';
        }

        const rawScore = Math.round(pattern.baseConfidence * similarity) + contextBoost;
        const score    = Math.min(100, rawScore);

        if (!bestMatch || score > bestMatch.score) {
          bestMatch = {
            pattern,
            functionAddress: funcAddr,
            similarity,
            score,
            matchOffset: i,
            windowSize: winLen,
            contextBoost,
            method,
          };
        }
      }
    }

    if (bestMatch && bestMatch.score >= 50) {
      matches.push(bestMatch);
      seenIds.add(pattern.id);
    }
  }

  return matches.sort((a, b) => b.score - a.score);
}

// ── Public API ────────────────────────────────────────────────────────────────

export function echoScan(
  instructions:  DisassembledInstruction[],
  context:       EchoContext,
  functions?:    Map<number, FunctionMetadata>,
): EchoScanResult {
  const allMatches: EchoMatch[] = [];
  let scannedFunctions = 0;

  if (functions && functions.size > 0) {
    for (const [addr, fn] of functions) {
      const fnInstrs = instructions.filter(
        ins => ins.address >= fn.startAddress && ins.address <= fn.endAddress,
      );
      if (fnInstrs.length === 0) continue;
      scannedFunctions++;
      allMatches.push(...scanFunctionEcho(fnInstrs, addr, context));
    }
  } else {
    scannedFunctions = 1;
    allMatches.push(...scanFunctionEcho(instructions, instructions[0]?.address ?? 0, context));
  }

  const fuzzyMatchCount    = allMatches.filter(m => m.method === 'fuzzy').length;
  const exactMatchCount    = allMatches.filter(m => m.method === 'exact').length;
  const wildcardMatchCount = allMatches.filter(m => m.method === 'wildcard').length;
  const contextBoostCount  = allMatches.filter(m => m.contextBoost > 0).length;

  return {
    matches: allMatches.sort((a, b) => b.score - a.score),
    scannedFunctions,
    scannedInstructions: instructions.length,
    fuzzyMatchCount,
    exactMatchCount,
    wildcardMatchCount,
    contextBoostCount,
  };
}

export function groupEchoByCategory(
  matches: EchoMatch[],
): Map<EchoCategory, EchoMatch[]> {
  const grouped = new Map<EchoCategory, EchoMatch[]>();
  for (const m of matches) {
    const cat = m.pattern.category;
    if (!grouped.has(cat)) grouped.set(cat, []);
    grouped.get(cat)!.push(m);
  }
  return grouped;
}

// ── Correlation signal extraction ─────────────────────────────────────────────

export function extractCorrelationSignals(result: EchoScanResult): EchoCorrelationSignal {
  const { matches } = result;
  const cats   = new Set(matches.map(m => m.pattern.category));
  const allTags = new Set(matches.flatMap(m => m.pattern.behaviors));

  const avg = matches.length > 0
    ? Math.round(matches.reduce((s, m) => s + m.score, 0) / matches.length)
    : 0;

  const behavioralTags = Array.from(allTags);

  const topMatchNames = matches
    .slice(0, 5)
    .map(m => m.pattern.displayName);

  return {
    hasLibcFunctions:    cats.has('libc-memory') || cats.has('libc-string') || cats.has('libc-io'),
    hasCryptoAlgorithm:  cats.has('crypto-hash') || cats.has('crypto-cipher'),
    hasNetworkPattern:   cats.has('network-io'),
    hasInjectionPattern: cats.has('code-injection'),
    hasAntiDebugPattern: cats.has('anti-debug'),
    hasCompilerArtifacts: cats.has('compiler-runtime'),
    hasDynamicLoad:      cats.has('dynamic-load'),
    hasPersistence:      cats.has('persistence'),
    hasStringDecode:     cats.has('string-decode'),
    topMatchNames,
    averageConfidence:   avg,
    patternDiversity:    cats.size,
    behavioralTags,
  };
}
