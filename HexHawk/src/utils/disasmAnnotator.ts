/**
 * disasmAnnotator — TALON Disassembly Annotation Layer
 *
 * Enriches raw Capstone disassembly with:
 *   - Inline comments (import names, crypto constants, patterns)
 *   - Function boundary markers (prologue / epilogue)
 *   - Stack frame annotations (push/pop tracking)
 *   - Known Windows API categorisation
 *   - Suspicious pattern flags (shellcode, PEB access, etc.)
 */

import type { DisassembledInstruction } from './decompilerEngine';

// ─────────────────────────────────────────────────────────
// TYPES
// ─────────────────────────────────────────────────────────

export type BoundaryKind = 'prologue' | 'epilogue' | 'tail-call';
export type AnnotationKind = 'import' | 'crypto' | 'pattern' | 'boundary' | 'stack' | 'syscall' | 'string-ref';

export interface InstructionAnnotation {
  kind:     AnnotationKind;
  comment:  string;
  /** Risk level — used for colour-coding in the UI */
  severity: 'info' | 'warn' | 'critical';
}

export interface AnnotatedInstruction {
  /** Original disassembled instruction. */
  instr:            DisassembledInstruction;
  annotations:      InstructionAnnotation[];
  /** Detected function boundary at this instruction, if any. */
  boundary?:        BoundaryKind;
  /** Estimated stack depth change (+push, -pop, 0 = no change). */
  stackDelta:       number;
  /** Absolute stack depth relative to function entry (undefined if unknown). */
  stackDepth?:      number;
}

// ─────────────────────────────────────────────────────────
// KNOWN CRYPTO CONSTANTS
// ─────────────────────────────────────────────────────────

const CRYPTO_CONSTANTS = new Map<number, { name: string; algo: string }>([
  // MD5 init constants
  [0x67452301, { name: 'A',  algo: 'MD5' }],
  [0xefcdab89, { name: 'B',  algo: 'MD5' }],
  [0x98badcfe, { name: 'C',  algo: 'MD5' }],
  [0x10325476, { name: 'D',  algo: 'MD5' }],
  // SHA-1
  [0x67452301, { name: 'H0', algo: 'SHA-1' }],
  [0x5a827999, { name: 'K0', algo: 'SHA-1' }],
  [0x6ed9eba1, { name: 'K1', algo: 'SHA-1' }],
  [0x8f1bbcdc, { name: 'K2', algo: 'SHA-1' }],
  [0xca62c1d6, { name: 'K3', algo: 'SHA-1' }],
  // SHA-256 init
  [0x6a09e667, { name: 'H0', algo: 'SHA-256' }],
  [0xbb67ae85, { name: 'H1', algo: 'SHA-256' }],
  [0x3c6ef372, { name: 'H2', algo: 'SHA-256' }],
  [0xa54ff53a, { name: 'H3', algo: 'SHA-256' }],
  [0x510e527f, { name: 'H4', algo: 'SHA-256' }],
  [0x9b05688c, { name: 'H5', algo: 'SHA-256' }],
  [0x1f83d9ab, { name: 'H6', algo: 'SHA-256' }],
  [0x5be0cd19, { name: 'H7', algo: 'SHA-256' }],
  // RC4 / XOR key patterns
  [0x61C88647, { name: 'LOCK_XCHG',   algo: 'LOCK magic (NT)' }],
  // CRC-32 polynomial
  [0xEDB88320, { name: 'CRC-32 poly', algo: 'CRC-32' }],
  [0x04C11DB7, { name: 'CRC-32 poly (normal)', algo: 'CRC-32' }],
  // AES S-box first word
  [0x63636363, { name: 'S-box pattern', algo: 'AES (possible)' }],
  // TEA delta
  [0x9E3779B9, { name: 'DELTA', algo: 'TEA/XTEA' }],
  // FNV prime
  [0x01000193, { name: 'FNV-32 prime', algo: 'FNV hash' }],
  [0x811c9dc5, { name: 'FNV-32 offset', algo: 'FNV hash' }],
]);

// ─────────────────────────────────────────────────────────
// WINDOWS API CATEGORIES
// ─────────────────────────────────────────────────────────

type ApiCategory = {
  tag:      string;
  severity: 'info' | 'warn' | 'critical';
  comment:  string;
};

const WINDOWS_API_MAP = new Map<string, ApiCategory>([
  // Process / code injection
  ['VirtualAlloc',            { tag: 'mem-alloc',      severity: 'warn',     comment: 'Allocates executable memory (common in shellcode/unpacking)' }],
  ['VirtualAllocEx',          { tag: 'remote-alloc',   severity: 'critical', comment: 'Remote process memory allocation — code injection indicator' }],
  ['WriteProcessMemory',      { tag: 'code-inject',    severity: 'critical', comment: 'Write to another process — classic code injection' }],
  ['CreateRemoteThread',      { tag: 'remote-exec',    severity: 'critical', comment: 'Execute code in remote process — process injection' }],
  ['NtCreateThreadEx',        { tag: 'remote-exec',    severity: 'critical', comment: 'NT-level remote thread — stealthy code injection' }],
  ['QueueUserAPC',            { tag: 'apc-inject',     severity: 'critical', comment: 'APC injection — executes shellcode in queued context' }],
  // Anti-debug
  ['IsDebuggerPresent',       { tag: 'anti-debug',     severity: 'warn',     comment: 'Debugger detection check' }],
  ['CheckRemoteDebuggerPresent', { tag: 'anti-debug',  severity: 'warn',     comment: 'Remote debugger detection' }],
  ['NtQueryInformationProcess', { tag: 'anti-debug',   severity: 'warn',     comment: 'Process info query — used for anti-debug & sandbox evasion' }],
  ['OutputDebugStringA',      { tag: 'anti-debug',     severity: 'info',     comment: 'Debug output — may detect timing-based anti-analysis' }],
  ['OutputDebugStringW',      { tag: 'anti-debug',     severity: 'info',     comment: 'Debug output — may detect timing-based anti-analysis' }],
  // Persistence
  ['RegSetValueExA',          { tag: 'persistence',    severity: 'warn',     comment: 'Registry write — persistence / configuration store' }],
  ['RegSetValueExW',          { tag: 'persistence',    severity: 'warn',     comment: 'Registry write — persistence / configuration store' }],
  ['RegCreateKeyExA',         { tag: 'persistence',    severity: 'info',     comment: 'Registry key creation' }],
  ['RegCreateKeyExW',         { tag: 'persistence',    severity: 'info',     comment: 'Registry key creation' }],
  // Dynamic resolution
  ['GetProcAddress',          { tag: 'dynamic-res',    severity: 'warn',     comment: 'Dynamic API resolution — may be hiding imports' }],
  ['LoadLibraryA',            { tag: 'dynamic-load',   severity: 'info',     comment: 'Runtime DLL load' }],
  ['LoadLibraryW',            { tag: 'dynamic-load',   severity: 'info',     comment: 'Runtime DLL load' }],
  ['LdrLoadDll',              { tag: 'dynamic-load',   severity: 'warn',     comment: 'NT-level DLL load — direct NTDLL call' }],
  // Crypto
  ['CryptEncrypt',            { tag: 'crypto',         severity: 'warn',     comment: 'Windows CryptoAPI encryption' }],
  ['CryptDecrypt',            { tag: 'crypto',         severity: 'warn',     comment: 'Windows CryptoAPI decryption' }],
  ['BCryptEncrypt',           { tag: 'crypto',         severity: 'warn',     comment: 'BCrypt API encryption' }],
  ['BCryptDecrypt',           { tag: 'crypto',         severity: 'warn',     comment: 'BCrypt API decryption' }],
  ['BCryptGenRandom',         { tag: 'crypto',         severity: 'info',     comment: 'Cryptographically secure random number generation' }],
  // Network / C2
  ['WSAStartup',              { tag: 'network',        severity: 'info',     comment: 'Winsock initialisation — network activity' }],
  ['connect',                 { tag: 'network',        severity: 'warn',     comment: 'TCP/UDP connect — possible C2 callback' }],
  ['send',                    { tag: 'network',        severity: 'warn',     comment: 'Network send — data exfiltration / C2 channel' }],
  ['recv',                    { tag: 'network',        severity: 'info',     comment: 'Network receive' }],
  ['InternetOpenA',           { tag: 'network',        severity: 'warn',     comment: 'WinINet open — HTTP/FTP activity' }],
  ['InternetOpenUrlA',        { tag: 'network',        severity: 'warn',     comment: 'HTTP URL fetch — possible C2 or download' }],
  ['HttpSendRequestA',        { tag: 'network',        severity: 'warn',     comment: 'HTTP request send' }],
  // File system
  ['CreateFileA',             { tag: 'file-io',        severity: 'info',     comment: 'File create/open' }],
  ['CreateFileW',             { tag: 'file-io',        severity: 'info',     comment: 'File create/open' }],
  ['DeleteFileA',             { tag: 'file-destroy',   severity: 'warn',     comment: 'File deletion — possible artefact cleanup / wiper' }],
  ['DeleteFileW',             { tag: 'file-destroy',   severity: 'warn',     comment: 'File deletion — possible artefact cleanup / wiper' }],
  ['MoveFileExA',             { tag: 'file-io',        severity: 'info',     comment: 'File move / rename (may be drop + execute)' }],
  // Process execution
  ['CreateProcessA',          { tag: 'exec',           severity: 'warn',     comment: 'Spawns a new process' }],
  ['CreateProcessW',          { tag: 'exec',           severity: 'warn',     comment: 'Spawns a new process' }],
  ['ShellExecuteA',           { tag: 'exec',           severity: 'warn',     comment: 'Shell execute — may launch payload or browser' }],
  ['ShellExecuteW',           { tag: 'exec',           severity: 'warn',     comment: 'Shell execute — may launch payload or browser' }],
  ['WinExec',                 { tag: 'exec',           severity: 'warn',     comment: 'Legacy process exec — often used in exploits' }],
  // Credential
  ['LsaRetrievePrivateData',  { tag: 'credential',     severity: 'critical', comment: 'LSA secret retrieval — credential dumping' }],
  ['SamOpenDatabase',         { tag: 'credential',     severity: 'critical', comment: 'SAM database access — credential dumping' }],
  ['CryptUnprotectData',      { tag: 'credential',     severity: 'warn',     comment: 'DPAPI decrypt — may be harvesting browser/app credentials' }],
  // Privilege escalation
  ['AdjustTokenPrivileges',   { tag: 'priv-esc',       severity: 'critical', comment: 'Token privilege escalation' }],
  ['ImpersonateLoggedOnUser', { tag: 'priv-esc',       severity: 'critical', comment: 'Token impersonation' }],
  // Evasion
  ['SetThreadContext',        { tag: 'evasion',        severity: 'critical', comment: 'Thread context hijack — process hollowing / APC inject' }],
  ['NtUnmapViewOfSection',    { tag: 'evasion',        severity: 'critical', comment: 'Process hollowing — unmaps target image section' }],
  ['SuspendThread',           { tag: 'evasion',        severity: 'warn',     comment: 'Thread suspend — may be process hollowing setup' }],
]);

// ─────────────────────────────────────────────────────────
// KNOWN SUSPICIOUS x86 PATTERNS (operand-level)
// ─────────────────────────────────────────────────────────

/** Matches "gs:0x60" or "fs:0x30" — PEB pointer (x64/x86). */
const PEB_ACCESS_RE = /[gf]s:[x0]*6[0-9a-f]|[gf]s:[x0]*3[0-9a-f]/i;

/** INT3 (0xCC) as operand in push/mov — software breakpoint scan. */
const INT3_SCAN_RE = /\b0xcc\b/i;

/** Matches "seh" or "vectored" exception handler registration patterns. */
const SEH_RE = /SetUnhandledExceptionFilter|AddVectoredExceptionHandler/i;

// ─────────────────────────────────────────────────────────
// PROLOGUE / EPILOGUE DETECTION
// ─────────────────────────────────────────────────────────

function detectBoundary(
  instr: DisassembledInstruction,
  prev:  DisassembledInstruction | null,
  next:  DisassembledInstruction | null,
): BoundaryKind | undefined {
  const mn = instr.mnemonic.toLowerCase();
  const op = (instr.operands ?? '').toLowerCase();

  // Classic x86-64 prologue: push rbp / mov rbp,rsp
  if (mn === 'push' && op.includes('rbp') && !prev) return 'prologue';
  if (mn === 'push' && op.includes('rbp') && prev) {
    const pMn = prev.mnemonic.toLowerCase();
    if (pMn === 'ret' || pMn === 'jmp') return 'prologue';
  }
  // sub rsp, N (stack frame setup, standalone prologue)
  if (mn === 'sub' && op.includes('rsp') && !prev) return 'prologue';

  // Epilogue: leave / add rsp,N / ret
  if (mn === 'leave') return 'epilogue';
  if (mn === 'ret' || mn === 'retn') return 'epilogue';

  // Tail call: jmp to external address when next is null or jmp > 0x1000 away
  if ((mn === 'jmp') && !next) return 'tail-call';

  return undefined;
}

// ─────────────────────────────────────────────────────────
// STACK DELTA
// ─────────────────────────────────────────────────────────

function computeStackDelta(instr: DisassembledInstruction): number {
  const mn = instr.mnemonic.toLowerCase();
  const op = (instr.operands ?? '').toLowerCase();

  if (mn === 'push')  return -8;  // 64-bit push
  if (mn === 'pop')   return +8;
  if (mn === 'call')  return -8;  // pushes return address
  if (mn === 'ret' || mn === 'retn') return +8;
  if (mn === 'leave') return +8;  // mov rsp,rbp; pop rbp

  // sub rsp, N
  if (mn === 'sub' && op.includes('rsp,')) {
    const m = op.match(/rsp,\s*(-?(?:0x)?[\da-f]+)/i);
    if (m) {
      const v = m[1].startsWith('0x') ? parseInt(m[1], 16) : parseInt(m[1], 10);
      return isNaN(v) ? 0 : -v;
    }
  }
  // add rsp, N
  if (mn === 'add' && op.includes('rsp,')) {
    const m = op.match(/rsp,\s*(-?(?:0x)?[\da-f]+)/i);
    if (m) {
      const v = m[1].startsWith('0x') ? parseInt(m[1], 16) : parseInt(m[1], 10);
      return isNaN(v) ? 0 : +v;
    }
  }

  return 0;
}

// ─────────────────────────────────────────────────────────
// IMMEDIATE CONSTANT EXTRACTION
// ─────────────────────────────────────────────────────────

function extractImmediates(operands: string): number[] {
  const results: number[] = [];
  const hexRe = /0x([0-9a-f]+)/gi;
  const decRe = /\b(\d{6,})\b/g;  // only large decimal numbers are interesting
  let m: RegExpExecArray | null;
  while ((m = hexRe.exec(operands)) !== null) {
    results.push(parseInt(m[1], 16));
  }
  while ((m = decRe.exec(operands)) !== null) {
    results.push(parseInt(m[1], 10));
  }
  return results;
}

// ─────────────────────────────────────────────────────────
// MAIN ANNOTATION FUNCTION
// ─────────────────────────────────────────────────────────

/**
 * Annotate a disassembly listing with inline comments, boundary markers,
 * and stack depth tracking.
 *
 * @param insns      Raw disassembled instructions (from Capstone / disassemble.rs).
 * @param importMap  Optional map of { address → import name } built from
 *                   the binary's import table (passed from metadata analysis).
 * @param strings    Optional map of { address → string value } for string-ref comments.
 */
export function annotateInstructions(
  insns: DisassembledInstruction[],
  importMap?: Map<number, string>,
  strings?: Map<number, string>,
): AnnotatedInstruction[] {
  const result: AnnotatedInstruction[] = [];
  let stackDepth = 0;

  for (let i = 0; i < insns.length; i++) {
    const instr = insns[i];
    const prev  = i > 0 ? insns[i - 1] : null;
    const next  = i < insns.length - 1 ? insns[i + 1] : null;
    const annotations: InstructionAnnotation[] = [];
    const mn  = instr.mnemonic.toLowerCase();
    const ops = instr.operands ?? '';

    // ── Import name resolution ────────────────────────────────────────────────
    if (mn === 'call' || mn === 'jmp') {
      // Try to resolve call target address from operands
      const hexTarget = ops.match(/\[?0x([0-9a-f]+)\]?/i);
      if (hexTarget) {
        const addr = parseInt(hexTarget[1], 16);
        const name = importMap?.get(addr);
        if (name) {
          const apiInfo = WINDOWS_API_MAP.get(name);
          if (apiInfo) {
            annotations.push({
              kind: 'import',
              comment: `→ ${name}()  [${apiInfo.tag}] ${apiInfo.comment}`,
              severity: apiInfo.severity,
            });
          } else {
            annotations.push({
              kind: 'import',
              comment: `→ ${name}()`,
              severity: 'info',
            });
          }
        }
      }
      // Also scan the operand string for known API names directly
      for (const [apiName, apiInfo] of WINDOWS_API_MAP) {
        if (ops.includes(apiName)) {
          annotations.push({
            kind: 'import',
            comment: `→ ${apiName}()  [${apiInfo.tag}] ${apiInfo.comment}`,
            severity: apiInfo.severity,
          });
          break;
        }
      }
    }

    // ── Crypto constant detection ─────────────────────────────────────────────
    if (mn === 'mov' || mn === 'push' || mn === 'movabs' || mn === 'lea') {
      for (const imm of extractImmediates(ops)) {
        const cc = CRYPTO_CONSTANTS.get(imm >>> 0);
        if (cc) {
          annotations.push({
            kind:     'crypto',
            comment:  `↑ ${cc.algo} constant ${cc.name} (0x${(imm >>> 0).toString(16).toUpperCase()})`,
            severity: 'warn',
          });
        }
      }
    }

    // ── PEB walk detection ────────────────────────────────────────────────────
    if (PEB_ACCESS_RE.test(ops)) {
      annotations.push({
        kind:     'pattern',
        comment:  '⚠ PEB pointer access — manual import resolution or anti-debug check',
        severity: 'critical',
      });
    }

    // ── Software breakpoint scan ──────────────────────────────────────────────
    if ((mn === 'mov' || mn === 'cmp') && INT3_SCAN_RE.test(ops)) {
      annotations.push({
        kind:     'pattern',
        comment:  '⚠ 0xCC comparison — software breakpoint (INT3) detection attempt',
        severity: 'warn',
      });
    }

    // ── SEH registration ──────────────────────────────────────────────────────
    if (SEH_RE.test(ops)) {
      annotations.push({
        kind:     'pattern',
        comment:  '⚠ SEH / vectored exception handler registration',
        severity: 'warn',
      });
    }

    // ── RDTSC / CPUID (timing / hypervisor checks) ────────────────────────────
    if (mn === 'rdtsc') {
      annotations.push({
        kind:     'pattern',
        comment:  '⚠ RDTSC — timing check (anti-debug / sandbox detection)',
        severity: 'warn',
      });
    }
    if (mn === 'cpuid') {
      annotations.push({
        kind:     'pattern',
        comment:  '⚠ CPUID — hypervisor / VM detection',
        severity: 'warn',
      });
    }

    // ── String cross-reference ────────────────────────────────────────────────
    if (strings && (mn === 'lea' || mn === 'mov')) {
      const hexTarget = ops.match(/0x([0-9a-f]+)/i);
      if (hexTarget) {
        const addr = parseInt(hexTarget[1], 16);
        const str = strings.get(addr);
        if (str) {
          const preview = str.length > 40 ? str.slice(0, 40) + '…' : str;
          annotations.push({
            kind:     'string-ref',
            comment:  `→ "${preview}"`,
            severity: 'info',
          });
        }
      }
    }

    // ── Stack tracking ────────────────────────────────────────────────────────
    const delta = computeStackDelta(instr);
    stackDepth += delta;
    if (delta !== 0) {
      annotations.push({
        kind:     'stack',
        comment:  `stack ${delta > 0 ? '+' : ''}${delta} bytes (depth: ${stackDepth})`,
        severity: 'info',
      });
    }

    // ── Boundary detection ────────────────────────────────────────────────────
    const boundary = detectBoundary(instr, prev, next);
    if (boundary === 'prologue') stackDepth = 0; // reset at function entry

    result.push({
      instr,
      annotations,
      boundary,
      stackDelta: delta,
      stackDepth,
    });
  }

  return result;
}

// ─────────────────────────────────────────────────────────
// SUMMARY HELPERS
// ─────────────────────────────────────────────────────────

/** Collect all critical annotations across an annotated listing. */
export function getCriticalAnnotations(annotated: AnnotatedInstruction[]): Array<{
  address: number;
  mnemonic: string;
  operands: string;
  comment: string;
}> {
  const results: ReturnType<typeof getCriticalAnnotations> = [];
  for (const a of annotated) {
    for (const ann of a.annotations) {
      if (ann.severity === 'critical') {
        results.push({
          address:  a.instr.address,
          mnemonic: a.instr.mnemonic,
          operands: a.instr.operands ?? '',
          comment:  ann.comment,
        });
      }
    }
  }
  return results;
}

/** Count function boundaries (prologues) in the annotated listing. */
export function countFunctions(annotated: AnnotatedInstruction[]): number {
  return annotated.filter(a => a.boundary === 'prologue').length;
}
