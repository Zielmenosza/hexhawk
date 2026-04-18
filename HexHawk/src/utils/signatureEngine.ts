/**
 * signatureEngine — Binary Pattern Recognition
 *
 * Identifies known code sequences in disassembly to reduce noise and improve
 * verdict accuracy. Uses normalized instruction hashing against a built-in DB
 * of libc, compiler runtime, and Windows API stub patterns.
 *
 * Algorithm:
 *   1. Normalize each instruction (abstract register names, large immediates)
 *   2. Build n-gram hashes over sliding windows
 *   3. Match against known-pattern database
 *   4. Return match list with confidence scores
 */

import type { FunctionMetadata } from '../App';
import type { DisassembledInstruction } from './decompilerEngine';
import type { BehavioralTag } from './correlationEngine';

// ── Public types ──────────────────────────────────────────────────────────────

export type SignatureCategory =
  | 'libc-alloc'
  | 'libc-string'
  | 'libc-io'
  | 'libc-math'
  | 'compiler-prologue'
  | 'compiler-epilogue'
  | 'compiler-runtime'
  | 'windows-api-stub'
  | 'windows-crt'
  | 'crypto'
  | 'loop-construct'
  | 'anti-debug'
  | 'vectorized';

export interface SignatureEntry {
  id: string;
  name: string;           // e.g. "malloc", "memcpy"
  displayName: string;    // human-readable: "Heap Allocator (malloc)"
  category: SignatureCategory;
  minWindow: number;      // minimum matching instructions
  normalizedPattern: string[];
  hash: string;           // FNV-1a hash of joined normalized pattern
  confidence: number;     // 0–100 base confidence
  behaviors: BehavioralTag[];
  description: string;
  safe: boolean;          // true → lowers threat score when matched
}

export interface SignatureMatch {
  signature: SignatureEntry;
  functionAddress: number;   // start address of function
  matchOffset: number;       // instruction index within function where match begins
  instrCount: number;        // number of instructions matched
  score: number;             // 0–100 adjusted confidence
}

export interface SignatureScanResult {
  matches: SignatureMatch[];
  scannedFunctions: number;
  scannedInstructions: number;
  knownFunctionCount: number;   // functions fully identified (≥ 80% confidence)
  unknownFunctionCount: number;
  safePatternCount: number;     // matched patterns flagged as safe
}

// ── Normalization ─────────────────────────────────────────────────────────────

const REG64 = /\b(rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|r8|r9|r1[0-5])\b/g;
const REG32 = /\b(eax|ebx|ecx|edx|esi|edi|esp|ebp|r[89]d|r1[0-5]d)\b/g;
const REG16 = /\b(ax|bx|cx|dx|si|di|sp|bp|r[89]w|r1[0-5]w)\b/g;
const REG8  = /\b(al|bl|cl|dl|sil|dil|spl|bpl|r[89]b|r1[0-5]b|ah|bh|ch|dh)\b/g;
const XMMREG = /\b(xmm[0-9]|xmm1[0-5]|ymm[0-9]|ymm1[0-5])\b/g;
const SEGREG = /\b(cs|ds|es|fs|gs|ss)\b/g;
const HEX_LARGE = /\b0x[0-9a-f]{4,}\b/gi;
const HEX_SMALL = /\b0x[0-9a-f]{1,3}\b/gi;
const DEC_NUM   = /\b[0-9]{2,}\b/g;
const SIZE_PFX  = /\b(byte|word|dword|qword|xmmword|ymmword)\s+ptr\s+/gi;

function normalizeOperands(ops: string): string {
  let s = ops.toLowerCase();
  // Size prefixes: keep as abstract %SZ so prologue patterns match regardless of bitness
  s = s.replace(SIZE_PFX, '%sz ');
  // Registers (order matters — longest first to avoid partial replacement)
  s = s.replace(XMMREG, '%xmm');
  s = s.replace(SEGREG, '%seg');
  s = s.replace(REG64, '%r');
  s = s.replace(REG32, '%r');
  s = s.replace(REG16, '%r');
  s = s.replace(REG8,  '%r');
  // Large immediates/addresses
  s = s.replace(HEX_LARGE, '%addr');
  // Small hex immediates ≤ 0xFFF — keep values 0–9 as-is (semantic), replace rest
  s = s.replace(HEX_SMALL, (m) => (parseInt(m, 16) <= 9 ? m : '%imm'));
  // Decimal numbers with ≥ 2 digits
  s = s.replace(DEC_NUM, '%imm');
  return s.trim();
}

export function normalizeInstruction(mnemonic: string, operands: string): string {
  const mn = mnemonic.toLowerCase().trim();
  const ops = normalizeOperands(operands);
  return ops ? `${mn} ${ops}` : mn;
}

// ── FNV-1a hash ───────────────────────────────────────────────────────────────

function fnv1a(s: string): string {
  let h = 0x811c9dc5 >>> 0;
  for (let i = 0; i < s.length; i++) {
    h = (Math.imul(h ^ s.charCodeAt(i), 0x01000193)) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

function hashPattern(normalized: string[]): string {
  return fnv1a(normalized.join('\n'));
}

// ── Built-in signature database ───────────────────────────────────────────────

function sig(
  id: string,
  name: string,
  displayName: string,
  category: SignatureCategory,
  pattern: string[],
  confidence: number,
  behaviors: BehavioralTag[],
  description: string,
  safe = true,
): SignatureEntry {
  const normalizedPattern = pattern.map((p) => p.toLowerCase().trim());
  return {
    id,
    name,
    displayName,
    category,
    minWindow: normalizedPattern.length,
    normalizedPattern,
    hash: hashPattern(normalizedPattern),
    confidence,
    behaviors,
    description,
    safe,
  };
}

export const SIGNATURE_DB: SignatureEntry[] = [
  // ── Compiler runtime patterns ──────────────────────────────────────────────

  sig(
    'compiler-prologue-full',
    'function_prologue',
    'Standard Function Prologue',
    'compiler-prologue',
    ['push %r', 'mov %r, %r', 'sub %r, %imm'],
    90,
    [],
    'Standard x86-64 function prologue: save RBP, establish frame, reserve stack space',
  ),

  sig(
    'compiler-prologue-leaf',
    'leaf_prologue',
    'Leaf Function Prologue',
    'compiler-prologue',
    ['push %r', 'mov %r, %r'],
    80,
    [],
    'Leaf function prologue without stack reservation',
  ),

  sig(
    'compiler-epilogue',
    'function_epilogue',
    'Standard Function Epilogue',
    'compiler-epilogue',
    ['mov %r, %r', 'pop %r', 'ret'],
    88,
    [],
    'Standard x86-64 function epilogue: restore frame, return',
  ),

  sig(
    'compiler-epilogue-leave',
    'function_epilogue_leave',
    'Function Epilogue (leave/ret)',
    'compiler-epilogue',
    ['leave', 'ret'],
    85,
    [],
    'Function epilogue using LEAVE instruction',
  ),

  sig(
    'compiler-stack-canary',
    'stack_canary_setup',
    'Stack Cookie / Canary Setup',
    'compiler-runtime',
    ['mov %r, %sz %seg:[%imm]', 'mov %sz [%r + %imm], %r'],
    82,
    [],
    'MSVC/GCC stack canary: reads __security_cookie from TEB and stores on stack',
  ),

  sig(
    'compiler-stack-canary-check',
    'stack_canary_check',
    'Stack Cookie Check',
    'compiler-runtime',
    ['mov %r, %sz [%r + %imm]', 'xor %r, %sz %seg:[%imm]'],
    82,
    [],
    'Stack canary verification before return',
  ),

  // ── libc / CRT patterns ────────────────────────────────────────────────────

  sig(
    'libc-memcpy-rep',
    'memcpy',
    'Memory Copy (rep movsb)',
    'libc-string',
    ['rep movsb %sz [%r], %sz [%r]'],
    92,
    [],
    'Bulk memory copy using REP MOVSB',
  ),

  sig(
    'libc-memcpy-repq',
    'memcpy_qword',
    'Memory Copy (rep movsq)',
    'libc-string',
    ['rep movsq %sz [%r], %sz [%r]'],
    92,
    [],
    'Bulk memory copy using REP MOVSQ (64-bit aligned)',
  ),

  sig(
    'libc-memset-rep',
    'memset',
    'Memory Set (rep stosb)',
    'libc-string',
    ['rep stosb %sz [%r], %r'],
    92,
    [],
    'Bulk memory set using REP STOSB',
  ),

  sig(
    'libc-memset-repq',
    'memset_qword',
    'Memory Set (rep stosq)',
    'libc-string',
    ['rep stosq %sz [%r], %r'],
    92,
    [],
    'Bulk memory set using REP STOSQ',
  ),

  sig(
    'libc-strlen-loop',
    'strlen',
    'String Length (loop)',
    'libc-string',
    ['xor %r, %r', 'cmp %sz [%r + %r], 0', 'je', 'inc %r', 'jmp'],
    75,
    [],
    'strlen implementation using byte comparison loop',
  ),

  sig(
    'libc-strchr-scan',
    'repne-scasb',
    'String Scan (repne scasb)',
    'libc-string',
    ['cld', 'repne scasb %r, %sz [%r]'],
    88,
    [],
    'String scan using REPNE SCASB — common in strlen/strchr implementations',
  ),

  sig(
    'libc-alloc-pattern',
    'heap_alloc',
    'Heap Allocator Wrapper',
    'libc-alloc',
    ['push %r', 'mov %r, %r', 'sub %r, %imm', 'mov %r, %imm', 'call'],
    70,
    ['dynamic-resolution'],
    'Function matching common malloc/HeapAlloc wrapper pattern',
  ),

  sig(
    'libc-printf-fmt',
    'printf_format',
    'Format String Call',
    'libc-io',
    ['lea %r, [%r + %imm]', 'mov %r, %r', 'call'],
    68,
    [],
    'Load format string pointer and call printf-family function',
  ),

  // ── Windows API stubs ──────────────────────────────────────────────────────

  sig(
    'win-iat-thunk',
    'iat_thunk',
    'IAT Thunk (jmp [addr])',
    'windows-api-stub',
    ['jmp %sz [%addr]'],
    95,
    [],
    'Import Address Table thunk — single indirect jump through IAT entry',
  ),

  sig(
    'win-iat-thunk-mov',
    'iat_thunk_indirect',
    'IAT Thunk (mov r11 / jmp)',
    'windows-api-stub',
    ['mov %r, %addr', 'jmp %r'],
    88,
    [],
    'IAT thunk using register-indirect jump (common in MSVC release builds)',
  ),

  sig(
    'win-getprocaddress-pattern',
    'dynamic_resolve',
    'Dynamic API Resolution',
    'windows-api-stub',
    ['mov %r, %sz [%r + %imm]', 'call %r'],
    72,
    ['dynamic-resolution'],
    'Load function pointer from structure (vtable or IAT copy) and call it',
    false,
  ),

  sig(
    'win-seh-prologue',
    'seh_prologue',
    'SEH Frame Setup',
    'windows-crt',
    ['push %imm', 'push %sz [%addr]', 'mov %sz [%seg:%imm], %r'],
    80,
    [],
    'Structured Exception Handling frame setup (32-bit Windows)',
  ),

  sig(
    'win-teb-read',
    'teb_access',
    'TEB/PEB Access (gs:)',
    'windows-crt',
    ['mov %r, %sz %seg:[%imm]'],
    78,
    ['dynamic-resolution'],
    'Thread Environment Block access via GS segment — common in security cookies and PEB walks',
    false,
  ),

  // ── Anti-debug patterns ────────────────────────────────────────────────────

  sig(
    'anti-debug-int3',
    'int3_probe',
    'INT3 Anti-Debug Probe',
    'anti-debug',
    ['int3'],
    85,
    ['anti-analysis'],
    'INT3 instruction used as anti-debugger probe or deliberate exception trigger',
    false,
  ),

  sig(
    'anti-debug-rdtsc',
    'rdtsc_timing',
    'RDTSC Timing Check',
    'anti-debug',
    ['rdtsc', 'shl %r, %imm', 'or %r, %r'],
    80,
    ['anti-analysis'],
    'RDTSC instruction used for timing checks to detect debuggers',
    false,
  ),

  sig(
    'anti-debug-cpuid',
    'cpuid_check',
    'CPUID Hypervisor Check',
    'anti-debug',
    ['mov %r, %imm', 'cpuid', 'test %r, %imm'],
    77,
    ['anti-analysis'],
    'CPUID with EAX=1 checking hypervisor bit — common VM/sandbox detection',
    false,
  ),

  // ── Crypto / encoding ──────────────────────────────────────────────────────

  sig(
    'crypto-xor-loop',
    'xor_cipher',
    'XOR Cipher Loop',
    'crypto',
    ['xor %sz [%r + %r], %r', 'inc %r', 'cmp %r, %r', 'jb'],
    78,
    ['code-decryption'],
    'Simple XOR loop — decryption or obfuscation routine',
    false,
  ),

  sig(
    'crypto-rol-pattern',
    'rotation_cipher',
    'Rotation-based Cipher',
    'crypto',
    ['rol %r, %imm', 'xor %r, %r', 'add %r, %r'],
    72,
    ['code-decryption'],
    'ROL/XOR/ADD pattern — component of hash function or block cipher round',
    false,
  ),

  // ── Vectorized / SIMD ──────────────────────────────────────────────────────

  sig(
    'simd-movaps',
    'simd_copy',
    'SIMD Aligned Move',
    'vectorized',
    ['movaps %xmm, %sz [%r]', 'movaps %sz [%r], %xmm'],
    85,
    [],
    'SSE aligned 128-bit data move — vectorized copy or register spill',
  ),

  sig(
    'simd-pcmpeqb',
    'simd_strcmp',
    'SIMD String Compare',
    'vectorized',
    ['pcmpeqb %xmm, %sz [%r]', 'pmovmskb %r, %xmm'],
    82,
    [],
    'SSE byte comparison with mask extraction — vectorized strcmp/memchr',
  ),
];

// Pre-index by hash for O(1) lookups
const DB_BY_HASH = new Map<string, SignatureEntry>(
  SIGNATURE_DB.map((s) => [s.hash, s]),
);

// ── Matching engine ───────────────────────────────────────────────────────────

/**
 * Scan a single function's instructions for signature matches.
 * Uses a sliding window for each pattern length.
 */
function scanFunction(
  instructions: DisassembledInstruction[],
  funcAddr: number,
): SignatureMatch[] {
  if (instructions.length === 0) return [];

  // Normalize all instructions once
  const normalized = instructions.map((ins) =>
    normalizeInstruction(ins.mnemonic, ins.operands),
  );

  const matches: SignatureMatch[] = [];
  const seen = new Set<string>(); // de-dup by signature id

  for (const entry of SIGNATURE_DB) {
    const winLen = entry.normalizedPattern.length;
    if (winLen > normalized.length) continue;

    const targetHash = entry.hash;

    for (let i = 0; i <= normalized.length - winLen; i++) {
      const window = normalized.slice(i, i + winLen);
      const windowHash = hashPattern(window);
      if (windowHash === targetHash) {
        if (seen.has(entry.id)) continue;
        seen.add(entry.id);

        // Confidence adjustment: longer patterns → higher confidence
        const lenBonus = Math.min(10, (winLen - 1) * 2);
        const score = Math.min(100, entry.confidence + lenBonus);

        matches.push({
          signature: entry,
          functionAddress: funcAddr,
          matchOffset: i,
          instrCount: winLen,
          score,
        });
        break; // first match in this function is enough
      }
    }
  }

  return matches;
}

/**
 * Scan all known functions, or the full instruction list if no function map given.
 */
export function scanSignatures(
  instructions: DisassembledInstruction[],
  functions?: Map<number, FunctionMetadata>,
): SignatureScanResult {
  const allMatches: SignatureMatch[] = [];
  let scannedFunctions = 0;

  if (functions && functions.size > 0) {
    for (const [addr, fn] of functions) {
      const fnInstrs = instructions.filter(
        (ins) => ins.address >= fn.startAddress && ins.address <= fn.endAddress,
      );
      if (fnInstrs.length === 0) continue;
      scannedFunctions++;
      const m = scanFunction(fnInstrs, addr);
      allMatches.push(...m);
    }
  } else {
    // No function map — scan the entire instruction stream
    scannedFunctions = 1;
    const m = scanFunction(instructions, instructions[0]?.address ?? 0);
    allMatches.push(...m);
  }

  const knownFunctionCount = new Set(
    allMatches.filter((m) => m.score >= 80).map((m) => m.functionAddress),
  ).size;

  const safePatternCount = allMatches.filter((m) => m.signature.safe).length;

  return {
    matches: allMatches,
    scannedFunctions,
    scannedInstructions: instructions.length,
    knownFunctionCount,
    unknownFunctionCount: scannedFunctions - knownFunctionCount,
    safePatternCount,
  };
}

// ── Utility / display ─────────────────────────────────────────────────────────

/** Group matches by category for display */
export function groupMatchesByCategory(
  matches: SignatureMatch[],
): Map<SignatureCategory, SignatureMatch[]> {
  const grouped = new Map<SignatureCategory, SignatureMatch[]>();
  for (const m of matches) {
    const cat = m.signature.category;
    if (!grouped.has(cat)) grouped.set(cat, []);
    grouped.get(cat)!.push(m);
  }
  return grouped;
}

/** Category display name */
export const CATEGORY_LABELS: Record<SignatureCategory, string> = {
  'libc-alloc':         'Memory Allocation',
  'libc-string':        'String / Memory Ops',
  'libc-io':            'I/O & Formatting',
  'libc-math':          'Math',
  'compiler-prologue':  'Function Prologue',
  'compiler-epilogue':  'Function Epilogue',
  'compiler-runtime':   'Compiler Runtime',
  'windows-api-stub':   'Windows API Stubs',
  'windows-crt':        'Windows CRT',
  'crypto':             'Crypto / Encoding',
  'loop-construct':     'Loop Constructs',
  'anti-debug':         'Anti-Debug',
  'vectorized':         'Vectorized (SIMD)',
};

export const CATEGORY_COLORS: Record<SignatureCategory, string> = {
  'libc-alloc':         '#4caf50',
  'libc-string':        '#4caf50',
  'libc-io':            '#4caf50',
  'libc-math':          '#4caf50',
  'compiler-prologue':  '#2196f3',
  'compiler-epilogue':  '#2196f3',
  'compiler-runtime':   '#2196f3',
  'windows-api-stub':   '#9c27b0',
  'windows-crt':        '#9c27b0',
  'crypto':             '#ff9800',
  'loop-construct':     '#607d8b',
  'anti-debug':         '#f44336',
  'vectorized':         '#00bcd4',
};

/** Summary line for a scan result */
export function summarizeScan(result: SignatureScanResult): string {
  const { matches, scannedFunctions, knownFunctionCount } = result;
  if (matches.length === 0) return 'No known patterns matched.';
  const pct = scannedFunctions > 0
    ? Math.round((knownFunctionCount / scannedFunctions) * 100)
    : 0;
  return `${matches.length} pattern${matches.length !== 1 ? 's' : ''} matched across ${scannedFunctions} function${scannedFunctions !== 1 ? 's' : ''} (${pct}% identified).`;
}
