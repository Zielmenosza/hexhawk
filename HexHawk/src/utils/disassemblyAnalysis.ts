import type {
  AnalysisWarning,
  BasicBlock,
  ConfidenceLevel,
  FunctionEndReason,
  FunctionModel,
  FunctionStartReason,
  FunctionStartSource,
  Instruction,
  ProgramAnalysis,
  ProgramArchitecture,
  BackendImport,
  CallingConventionInfo,
  XRef,
  XRefKind,
} from './disassemblyModel';
import { resolveImportPrototype } from './importPrototypes';

export type DisassemblyAnalysisOptions = {
  /** Addresses known from export tables or equivalent trusted metadata. */
  exportedAddresses?: Iterable<number>;
  /** Advisory backend import-table entries parsed before instruction-derived xrefs. */
  imports?: Iterable<BackendImport>;
  /** Advisory jump-table targets detected by a prior pass. */
  jumpTableTargets?: Iterable<number>;
  /** Architecture reported by the backend disassembler. */
  architecture?: ProgramArchitecture | string | null;
};

export type FunctionStartCandidate = {
  address: number;
  reasons: FunctionStartReason[];
  confidence: ConfidenceLevel;
  warnings: AnalysisWarning[];
};

export type FunctionEndCandidate = {
  startAddress: number;
  endAddress: number;
  reason: FunctionEndReason;
  confidence: ConfidenceLevel;
  warnings: AnalysisWarning[];
};

export interface LibrarySignature {
  name: string;
  library: string;
  bytePattern: string;
  maskPattern?: string;
  minLength: number;
}

export const BUILTIN_LIBRARY_SIGNATURES: LibrarySignature[] = [
  { name: 'memcpy', library: 'msvcrt', bytePattern: '4883EC28488B4424', minLength: 8 },
  { name: 'memset', library: 'msvcrt', bytePattern: '4883EC28488B4C24', minLength: 8 },
  { name: 'strlen', library: 'msvcrt', bytePattern: '4883EC28488D0D00', maskPattern: 'FFFFFFFFFFFFFF??', minLength: 8 },
  { name: 'strcpy', library: 'msvcrt', bytePattern: '48895C2408574883', minLength: 8 },
  { name: 'strcmp', library: 'msvcrt', bytePattern: '4883EC284885C974', minLength: 8 },
  { name: 'malloc', library: 'msvcrt', bytePattern: '40534883EC208BC1', minLength: 8 },
  { name: 'free', library: 'msvcrt', bytePattern: '4885C9740C4883EC', minLength: 8 },
  { name: 'sprintf', library: 'msvcrt', bytePattern: '48895C2410574883', minLength: 8 },
  { name: 'printf', library: 'msvcrt', bytePattern: '4883EC28488D5424', minLength: 8 },
  { name: 'exit', library: 'msvcrt', bytePattern: '4883EC28488BCBE8', minLength: 8 },
];

function parsePatternBytes(pattern: string): number[] {
  const compact = pattern.replace(/\s+/g, '');
  const bytes: number[] = [];
  for (let index = 0; index < compact.length; index += 2) {
    bytes.push(Number.parseInt(compact.slice(index, index + 2), 16));
  }
  return bytes;
}

function instructionBytesFromStart(instructions: Instruction[], startAddress: number, maxBytes: number): number[] {
  const bytes: number[] = [];
  for (const instruction of instructions.filter(entry => entry.address >= startAddress).sort((left, right) => left.address - right.address)) {
    for (const byte of instruction.bytes ?? []) {
      if (bytes.length >= maxBytes) return bytes;
      bytes.push(byte & 0xff);
    }
    if (bytes.length >= maxBytes) return bytes;
  }
  return bytes;
}

function patternMatches(bytes: number[], signature: LibrarySignature): boolean {
  const pattern = parsePatternBytes(signature.bytePattern);
  if (pattern.length < signature.minLength || bytes.length < signature.minLength || bytes.length < pattern.length) return false;
  const mask = signature.maskPattern?.replace(/\s+/g, '') ?? 'F'.repeat(signature.bytePattern.replace(/\s+/g, '').length);
  for (let index = 0; index < pattern.length; index += 1) {
    const maskPair = mask.slice(index * 2, index * 2 + 2);
    if (maskPair === '??') continue;
    if (bytes[index] !== pattern[index]) return false;
  }
  return true;
}

export function matchLibrarySignatures(
  instructions: Instruction[],
  signatures: LibrarySignature[],
): Map<number, LibrarySignature> {
  const matches = new Map<number, LibrarySignature>();
  if (instructions.length === 0 || signatures.length === 0) return matches;
  const starts = detectFunctionStartCandidates(instructions, buildXRefs(instructions)).map(candidate => candidate.address);
  const maxPatternLength = Math.max(...signatures.map(signature => parsePatternBytes(signature.bytePattern).length));
  for (const start of starts) {
    const bytes = instructionBytesFromStart(instructions, start, maxPatternLength);
    const match = signatures.find(signature => patternMatches(bytes, signature));
    if (match) matches.set(start, match);
  }
  return matches;
}

function normalizeMnemonic(instruction: Pick<Instruction, 'mnemonic'>): string {
  return instruction.mnemonic.trim().toLowerCase();
}

function normalizeOperands(instruction: Pick<Instruction, 'operands'>): string {
  return instruction.operands.trim().toLowerCase();
}

function formatAddress(address: number): string {
  return `0x${address.toString(16).toUpperCase()}`;
}

function uniqueSorted(values: Iterable<number>): number[] {
  return Array.from(new Set(values)).sort((a, b) => a - b);
}

function uniqueInstructions(instructions: Instruction[]): Instruction[] {
  const byAddress = new Map<number, Instruction>();
  for (const instruction of instructions) byAddress.set(instruction.address, instruction);
  return Array.from(byAddress.values()).sort((a, b) => a.address - b.address);
}

function pushReason(map: Map<number, Set<FunctionStartReason>>, address: number, reason: FunctionStartReason): void {
  const existing = map.get(address) ?? new Set<FunctionStartReason>();
  existing.add(reason);
  map.set(address, existing);
}

function confidenceForStartReasons(reasons: Set<FunctionStartReason>): ConfidenceLevel {
  if (reasons.has('symbol') || reasons.has('export') || reasons.has('known-call-target') || reasons.has('call-target')) return 'high';
  if (reasons.has('prologue') || reasons.has('prologue-pattern') || reasons.has('jump-table-target')) return 'medium';
  if (reasons.has('alignment-gap') || reasons.has('entrypoint') || reasons.has('linear-sweep')) return 'low';
  return 'unknown';
}


function sourceForStartReasons(reasons: FunctionStartReason[]): FunctionStartSource {
  if (reasons.includes('known-call-target') || reasons.includes('call-target')) return 'call-target';
  if (reasons.includes('symbol')) return 'symbol';
  if (reasons.includes('export')) return 'export';
  if (reasons.includes('prologue-pattern') || reasons.includes('prologue')) return 'prologue-pattern';
  if (reasons.includes('jump-table-target')) return 'jump-table-target';
  if (reasons.includes('alignment-gap')) return 'alignment-gap';
  if (reasons.includes('entrypoint')) return 'entrypoint';
  return 'linear-sweep';
}

function warning(kind: AnalysisWarning['kind'], message: string, address?: number): AnalysisWarning {
  return { kind, message, address, severity: kind === 'empty-input' ? 'info' : 'warning' };
}

function symbolForAddress(instructions: Instruction[], address: number): string | undefined {
  return instructions.find(instruction => instruction.address === address)?.symbol;
}


function normalizeImportModuleName(dll: string | undefined): string | undefined {
  if (!dll) return undefined;
  return dll.trim() || undefined;
}

function importDisplayName(entry: BackendImport): string | undefined {
  if (entry.name && entry.name.trim()) return entry.name.trim();
  if (typeof entry.ordinal === 'number') return `ordinal_${entry.ordinal}`;
  return undefined;
}

function mergeImportCalls(
  tableImports: Iterable<BackendImport> | undefined,
  xrefImports: ProgramAnalysis['importCalls'],
): ProgramAnalysis['importCalls'] {
  const merged = new Map<string, ProgramAnalysis['importCalls'][number]>();
  const keyFor = (targetAddress: number | undefined, moduleName: string | undefined, importName: string | undefined) =>
    `${targetAddress ?? 'unknown'}:${moduleName ?? ''}:${importName ?? ''}`.toLowerCase();

  for (const entry of tableImports ?? []) {
    const importName = importDisplayName(entry);
    const moduleName = normalizeImportModuleName(entry.dll);
    if (!importName && typeof entry.thunk_va !== 'number') continue;
    const targetAddress = Number(entry.thunk_va);
    merged.set(keyFor(targetAddress, moduleName, importName), {
      callAddress: targetAddress,
      targetAddress,
      importName,
      moduleName,
      confidence: 'high',
      evidence: `PE import table ${moduleName ? `${moduleName}!` : ''}${importName ?? '<unnamed>'} IAT ${formatAddress(targetAddress)}`,
    });
  }

  for (const xrefImport of xrefImports) {
    const key = keyFor(xrefImport.targetAddress, xrefImport.moduleName, xrefImport.importName);
    if (merged.has(key)) continue;
    merged.set(key, xrefImport);
  }

  return Array.from(merged.values()).sort((a, b) => (a.targetAddress ?? a.callAddress) - (b.targetAddress ?? b.callAddress));
}

function parseImmediate(value: string): number | undefined {
  const trimmed = value.trim().toLowerCase();
  if (/^0x[0-9a-f]+$/.test(trimmed)) return Number.parseInt(trimmed, 16);
  if (/^\d+$/.test(trimmed)) return Number.parseInt(trimmed, 10);
  return undefined;
}

function parseStackAllocation(operands: string): number | undefined {
  const match = operands.match(/\brsp\s*,\s*(0x[0-9a-f]+|\d+)/i);
  if (!match) return undefined;
  return parseImmediate(match[1]);
}

function importNameForFunction(fnName: string, imports: Iterable<BackendImport> | undefined, startAddress: number): string | undefined {
  const direct = Array.from(imports ?? []).find(entry => Number(entry.thunk_va) === startAddress);
  return direct ? importDisplayName(direct) ?? fnName : fnName;
}

function inferCallingConvention(
  fnName: string,
  instructions: Instruction[],
  imports: Iterable<BackendImport> | undefined,
  startAddress: number,
  architecture: ProgramArchitecture,
): CallingConventionInfo {
  if (architecture === 'arm64') {
    return {
      name: 'arm64-unknown',
      confidence: 'low',
      source: 'arm64-limited',
      evidence: ['ARM64 — calling convention inference not yet implemented'],
    };
  }
  const evidence: string[] = [];
  const prototype = resolveImportPrototype(importNameForFunction(fnName, imports, startAddress));
  if (prototype?.callingConvention) {
    const name = prototype.callingConvention === 'cdecl' ? 'cdecl' : 'windows-x64';
    return {
      name,
      confidence: 'high',
      source: 'import-prototype',
      evidence: [`known import prototype ${prototype.name} uses ${prototype.callingConvention}`],
    };
  }

  const first = instructions.slice(0, 8);
  const firstOps = first.map(instruction => normalizeOperands(instruction));
  const firstText = firstOps.join(' ; ');
  const stackAllocations = first
    .filter(instruction => normalizeMnemonic(instruction).startsWith('sub'))
    .map(instruction => parseStackAllocation(normalizeOperands(instruction)))
    .filter((amount): amount is number => typeof amount === 'number');
  const hasWindowsShadowSpace = stackAllocations.some(amount => amount === 0x20 || amount === 0x28 || amount >= 0x20);
  const hasWindowsArgRegisterUse = /\b(rcx|rdx|r8|r9)\b/.test(firstText);
  const hasSysvRegisterUse = /\brdi\b/.test(firstText) || /\brsi\b/.test(firstText);
  const retWithStackCleanup = first.some(instruction => normalizeMnemonic(instruction).startsWith('ret') && parseImmediate(normalizeOperands(instruction)) !== undefined);
  const callerStyleStackCleanup = first.some(instruction => normalizeMnemonic(instruction) === 'add' && /\besp\s*,\s*(0x[0-9a-f]+|\d+)/i.test(normalizeOperands(instruction)));

  if (hasWindowsShadowSpace) {
    evidence.push(`early stack allocation reserves possible Windows x64 shadow space: ${stackAllocations.map(formatAddress).join(', ')}`);
  }
  if (hasWindowsArgRegisterUse) evidence.push('early use of Windows x64 argument registers rcx/rdx/r8/r9');
  if (hasSysvRegisterUse) evidence.push('early use of SysV x64 argument registers rdi/rsi');

  if ((hasWindowsShadowSpace || hasWindowsArgRegisterUse) && hasSysvRegisterUse) {
    return {
      name: 'unknown',
      confidence: 'low',
      source: 'default-unknown',
      evidence: [...evidence, 'conflicting Windows x64 and SysV x64 register/stack signals; kept conservative'],
    };
  }

  if (hasWindowsShadowSpace || hasWindowsArgRegisterUse) {
    return {
      name: 'windows-x64',
      confidence: 'medium',
      source: 'windows-x64-shadow-space',
      evidence: evidence.length > 0 ? evidence : ['possible Windows x64 calling pattern'],
    };
  }

  if (hasSysvRegisterUse) {
    return {
      name: 'sysv-x64',
      confidence: 'medium',
      source: 'sysv-register-use',
      evidence,
    };
  }

  if (retWithStackCleanup) {
    return { name: 'stdcall', confidence: 'medium', source: 'stack-cleanup', evidence: ['callee return includes stack-byte cleanup operand'] };
  }
  if (callerStyleStackCleanup) {
    return { name: 'cdecl', confidence: 'low', source: 'stack-cleanup', evidence: ['caller-style esp stack cleanup observed inside function window'] };
  }

  return { name: 'unknown', confidence: 'low', source: 'default-unknown', evidence: ['no calling-convention pattern matched'] };
}

function normalizeProgramArchitecture(architecture: ProgramArchitecture | string | null | undefined): ProgramArchitecture {
  const normalized = (architecture ?? 'x86-64').toString().trim().toLowerCase();
  if (normalized === 'arm64' || normalized === 'aarch64') return 'arm64';
  if (normalized === 'x64' || normalized === 'x86_64' || normalized === 'x86-64') return 'x86-64';
  if (normalized === 'x86' || normalized === 'i386') return 'x86';
  if (normalized.startsWith('arm')) return 'arm';
  if (normalized.startsWith('mips')) return 'mips';
  if (normalized.startsWith('powerpc') || normalized.startsWith('ppc')) return 'powerpc';
  return 'unknown';
}

function parseImportSymbol(symbol?: string): { importName: string; moduleName?: string } | undefined {
  if (!symbol) return undefined;
  const normalized = symbol.trim();
  if (!normalized) return undefined;

  const moduleQualified = normalized.match(/^([A-Za-z0-9_.-]+)!(.+)$/);
  if (moduleQualified) {
    return { moduleName: moduleQualified[1], importName: moduleQualified[2].replace(/^__imp_/, '') };
  }

  const importPrefixed = normalized.match(/^(?:__imp_|imp_|import[:_])(.+)$/i);
  if (importPrefixed) return { importName: importPrefixed[1] };

  return undefined;
}

function isReturn(mnemonic: string): boolean {
  return mnemonic === 'ret' || mnemonic === 'retq' || mnemonic === 'retn';
}

function isCall(mnemonic: string): boolean {
  return mnemonic === 'call' || mnemonic === 'callq' || mnemonic.startsWith('bl');
}

function isJump(mnemonic: string): boolean {
  return mnemonic === 'jmp' || mnemonic === 'jmpq' || (mnemonic.startsWith('b.') || mnemonic === 'b');
}

function isConditionalJump(mnemonic: string): boolean {
  if (mnemonic === 'jmp' || mnemonic === 'jmpq' || mnemonic === 'b') return false;
  return mnemonic.startsWith('j') || mnemonic.startsWith('b.');
}

function isTransfer(mnemonic: string): boolean {
  return isReturn(mnemonic) || isJump(mnemonic) || isConditionalJump(mnemonic);
}

function looksLikePrologue(current: Instruction, next?: Instruction): boolean {
  const mnemonic = normalizeMnemonic(current);
  const operands = normalizeOperands(current);
  const nextMnemonic = next ? normalizeMnemonic(next) : '';
  const nextOperands = next ? normalizeOperands(next) : '';

  if (mnemonic === 'push' && /\brbp\b/.test(operands) && nextMnemonic.startsWith('mov') && /\brbp\b/.test(nextOperands) && /\brsp\b/.test(nextOperands)) {
    return true;
  }

  if (mnemonic === 'push' && /\brdi\b/.test(operands) && nextMnemonic === 'push' && /\brsi\b/.test(nextOperands)) {
    return true;
  }

  if (mnemonic.startsWith('sub') && /\brsp\b/.test(operands)) {
    return true;
  }

  return false;
}


function isAlignmentPadding(instruction: Instruction): boolean {
  const mnemonic = normalizeMnemonic(instruction);
  const operands = normalizeOperands(instruction);
  return mnemonic === 'nop' || mnemonic === 'nopl' || mnemonic === 'nopw' || mnemonic === 'int3' || operands === '0xcc' || operands === '0xCC'.toLowerCase();
}

export function extractDirectTarget(operands: string): number | null {
  const direct = operands.match(/\b0x[0-9a-fA-F]+\b/);
  if (direct) return Number.parseInt(direct[0], 16);

  const decimalOnly = operands.trim().match(/^\d+$/);
  if (decimalOnly) return Number.parseInt(decimalOnly[0], 10);

  return null;
}

export function buildXRefs(instructions: Instruction[]): XRef[] {
  const xrefs: XRef[] = [];

  for (const instruction of instructions) {
    const mnemonic = normalizeMnemonic(instruction);
    const target = extractDirectTarget(instruction.operands);

    if (isCall(mnemonic)) {
      if (target === null) {
        continue;
      }
      xrefs.push({
        kind: 'call',
        from: instruction.address,
        to: target,
        confidence: 'high',
        evidence: `direct call operand ${instruction.operands}`,
      });
      continue;
    }

    if (isJump(mnemonic) || isConditionalJump(mnemonic)) {
      if (target === null) continue;
      const kind: XRefKind = isConditionalJump(mnemonic) ? 'conditional-jump' : 'jump';
      xrefs.push({
        kind,
        from: instruction.address,
        to: target,
        confidence: 'high',
        evidence: `direct ${kind} operand ${instruction.operands}`,
      });
    }
  }

  return xrefs;
}


export interface XRefIndex {
  callersOf(address: number): XRef[];
  calleesFrom(address: number): XRef[];
  jumpsTo(address: number): XRef[];
  dataRefsTo(address: number): XRef[];
  refsTo(address: number): XRef[];
  refsFrom(address: number): XRef[];
  refCount(address: number): number;
}

function readonlyRefs(refs: XRef[] | undefined): XRef[] {
  return refs ? [...refs] : [];
}

function addRef(map: Map<number, XRef[]>, address: number, xref: XRef): void {
  const refs = map.get(address) ?? [];
  refs.push(xref);
  map.set(address, refs);
}

export function buildXRefIndex(analysis: ProgramAnalysis): XRefIndex {
  const refs = [
    ...analysis.xrefs,
    ...analysis.dataReferences.map(ref => ({
      kind: 'data' as const,
      from: ref.from,
      to: ref.to,
      confidence: ref.confidence,
      evidence: ref.evidence,
    })),
    ...analysis.stringReferences.map(ref => ({
      kind: 'string' as const,
      from: ref.from,
      to: ref.to,
      confidence: ref.confidence,
      evidence: ref.evidence,
    })),
  ];

  const byTo = new Map<number, XRef[]>();
  const byFrom = new Map<number, XRef[]>();
  const callersByTo = new Map<number, XRef[]>();
  const calleesByFrom = new Map<number, XRef[]>();
  const jumpsByTo = new Map<number, XRef[]>();
  const dataByTo = new Map<number, XRef[]>();

  for (const ref of refs) {
    addRef(byTo, ref.to, ref);
    addRef(byFrom, ref.from, ref);
    if (ref.kind === 'call') {
      addRef(callersByTo, ref.to, ref);
      addRef(calleesByFrom, ref.from, ref);
    }
    if (ref.kind === 'jump' || ref.kind === 'conditional-jump') addRef(jumpsByTo, ref.to, ref);
    if (ref.kind === 'data' || ref.kind === 'string') addRef(dataByTo, ref.to, ref);
  }

  return {
    callersOf: (address: number) => readonlyRefs(callersByTo.get(address)),
    calleesFrom: (address: number) => readonlyRefs(calleesByFrom.get(address)),
    jumpsTo: (address: number) => readonlyRefs(jumpsByTo.get(address)),
    dataRefsTo: (address: number) => readonlyRefs(dataByTo.get(address)),
    refsTo: (address: number) => readonlyRefs(byTo.get(address)),
    refsFrom: (address: number) => readonlyRefs(byFrom.get(address)),
    refCount: (address: number) => (byTo.get(address)?.length ?? 0) + (byFrom.get(address)?.length ?? 0),
  };
}

export function detectFunctionStartCandidates(
  instructions: Instruction[],
  xrefs: XRef[] = buildXRefs(instructions),
  options: DisassemblyAnalysisOptions = {},
): FunctionStartCandidate[] {
  const starts = new Map<number, Set<FunctionStartReason>>();
  const addressSet = new Set(instructions.map(instruction => instruction.address));
  const exportedAddresses = new Set(options.exportedAddresses ?? []);

  if (instructions.length === 0) return [];

  pushReason(starts, instructions[0].address, 'entrypoint');

  for (const instruction of instructions) {
    if (instruction.symbol) pushReason(starts, instruction.address, 'symbol');
    if (exportedAddresses.has(instruction.address)) pushReason(starts, instruction.address, 'export');
  }

  for (const xref of xrefs) {
    if (xref.kind === 'call' && addressSet.has(xref.to)) {
      pushReason(starts, xref.to, 'known-call-target');
      pushReason(starts, xref.to, 'call-target');
    }
  }

  for (let index = 0; index < instructions.length; index += 1) {
    const instruction = instructions[index];
    if (looksLikePrologue(instruction, instructions[index + 1])) {
      pushReason(starts, instruction.address, 'prologue');
      pushReason(starts, instruction.address, 'prologue-pattern');
    }
  }



  for (const target of options.jumpTableTargets ?? []) {
    if (addressSet.has(target)) pushReason(starts, target, 'jump-table-target');
  }

  for (let index = 0; index < instructions.length; index += 1) {
    if (!isAlignmentPadding(instructions[index])) continue;
    const paddingStart = index;
    let cursor = index;
    while (cursor < instructions.length && isAlignmentPadding(instructions[cursor])) cursor += 1;
    const paddingLength = cursor - paddingStart;
    const next = instructions[cursor];
    const previous = instructions[paddingStart - 1];
    if (paddingLength >= 1 && paddingLength <= 15 && next && previous && isTransfer(normalizeMnemonic(previous))) {
      pushReason(starts, next.address, 'alignment-gap');
    }
    index = cursor;
  }

  return Array.from(starts.entries())
    .map(([address, reasons]) => {
      const confidence = confidenceForStartReasons(reasons);
      const warnings: AnalysisWarning[] = [];
      if (confidence === 'low') {
        warnings.push(warning('uncertain-function-start', `Function start at ${formatAddress(address)} is an entry/linear-sweep candidate only.`, address));
      }
      return { address, reasons: Array.from(reasons), confidence, warnings };
    })
    .sort((a, b) => a.address - b.address);
}

function findInstructionIndex(instructions: Instruction[], address: number): number {
  return instructions.findIndex(instruction => instruction.address === address);
}

export function detectFunctionEndCandidate(
  instructions: Instruction[],
  startAddress: number,
  nextStartAddress?: number,
  xrefs: XRef[] = buildXRefs(instructions),
): FunctionEndCandidate {
  const warnings: AnalysisWarning[] = [];
  const startIndex = findInstructionIndex(instructions, startAddress);
  if (startIndex < 0 || instructions.length === 0) {
    return {
      startAddress,
      endAddress: startAddress,
      reason: 'unknown',
      confidence: 'unknown',
      warnings: [warning('uncertain-function-end', `No instruction exists for function start ${formatAddress(startAddress)}.`, startAddress)],
    };
  }

  const nextStartIndex = nextStartAddress === undefined ? -1 : findInstructionIndex(instructions, nextStartAddress);
  const stopExclusive = nextStartIndex > startIndex ? nextStartIndex : instructions.length;

  for (let index = startIndex; index < stopExclusive; index += 1) {
    const instruction = instructions[index];
    const mnemonic = normalizeMnemonic(instruction);
    if (isReturn(mnemonic)) {
      return { startAddress, endAddress: instruction.address, reason: 'return', confidence: 'high', warnings };
    }

    if (isJump(mnemonic)) {
      const target = xrefs.find(xref => xref.from === instruction.address && xref.kind === 'jump')?.to;
      if (target !== undefined && (target < startAddress || (nextStartAddress !== undefined && target >= nextStartAddress))) {
        warnings.push(warning('uncertain-function-end', `Tail-jump style end at ${formatAddress(instruction.address)} targets ${formatAddress(target)}.`, instruction.address));
        return { startAddress, endAddress: instruction.address, reason: 'tail-jump', confidence: 'medium', warnings };
      }
    }
  }

  if (nextStartIndex > startIndex) {
    const endAddress = instructions[nextStartIndex - 1].address;
    warnings.push(warning('uncertain-function-end', `Function end before next candidate ${formatAddress(nextStartAddress!)} is inferred, not proven by return.`, endAddress));
    return { startAddress, endAddress, reason: 'before-next-function', confidence: 'medium', warnings };
  }

  const last = instructions[instructions.length - 1];
  warnings.push(warning('uncertain-function-end', `Function end at input end ${formatAddress(last.address)} is inferred, not proven by return.`, last.address));
  return { startAddress, endAddress: last.address, reason: 'end-of-input', confidence: 'low', warnings };
}

export function splitBasicBlocks(instructions: Instruction[], xrefs: XRef[] = buildXRefs(instructions)): BasicBlock[] {
  if (instructions.length === 0) return [];

  const addressToIndex = new Map(instructions.map((instruction, index) => [instruction.address, index] as const));
  const leaders = new Set<number>([instructions[0].address]);
  const targetAddresses = new Set(xrefs
    .filter(xref => xref.kind === 'jump' || xref.kind === 'conditional-jump' || xref.kind === 'call')
    .map(xref => xref.to));

  for (let index = 0; index < instructions.length; index += 1) {
    const instruction = instructions[index];
    const mnemonic = normalizeMnemonic(instruction);

    if (targetAddresses.has(instruction.address)) leaders.add(instruction.address);

    if (isJump(mnemonic) || isConditionalJump(mnemonic) || isReturn(mnemonic)) {
      const next = instructions[index + 1];
      if (next) leaders.add(next.address);
    }
  }

  const sortedLeaders = uniqueSorted(Array.from(leaders).filter(address => addressToIndex.has(address)));
  const blocks: BasicBlock[] = [];

  for (let leaderIndex = 0; leaderIndex < sortedLeaders.length; leaderIndex += 1) {
    const startAddress = sortedLeaders[leaderIndex];
    const startIndex = addressToIndex.get(startAddress)!;
    const nextLeader = sortedLeaders[leaderIndex + 1];
    const endExclusive = nextLeader === undefined ? instructions.length : addressToIndex.get(nextLeader)!;
    const blockInstructions = instructions.slice(startIndex, endExclusive);
    if (blockInstructions.length === 0) continue;
    const last = blockInstructions[blockInstructions.length - 1];
    const lastMnemonic = normalizeMnemonic(last);
    const successors = new Set<number>();
    const warnings: AnalysisWarning[] = [];

    for (const xref of xrefs.filter(ref => ref.from === last.address && (ref.kind === 'jump' || ref.kind === 'conditional-jump'))) {
      successors.add(xref.to);
    }

    const nextSequential = instructions[endExclusive];
    if (nextSequential && !isReturn(lastMnemonic) && !isJump(lastMnemonic)) {
      successors.add(nextSequential.address);
      if (!isConditionalJump(lastMnemonic)) {
        warnings.push(warning('fallthrough-estimated', `Fallthrough to ${formatAddress(nextSequential.address)} is estimated from instruction order.`, last.address));
      }
    }

    blocks.push({
      id: `block_${formatAddress(startAddress)}`,
      startAddress,
      endAddress: last.address,
      instructions: blockInstructions,
      predecessors: [],
      successors: uniqueSorted(successors),
      confidence: warnings.length > 0 ? 'medium' : 'high',
      warnings,
    });
  }

  const blockByStart = new Map(blocks.map(block => [block.startAddress, block] as const));
  for (const block of blocks) {
    for (const successor of block.successors) {
      const targetBlock = blockByStart.get(successor);
      if (targetBlock) targetBlock.predecessors = uniqueSorted([...targetBlock.predecessors, block.startAddress]);
    }
  }

  return blocks;
}

export function buildProgramAnalysis(instructions: Instruction[], options: DisassemblyAnalysisOptions = {}): ProgramAnalysis {
  const normalizedInstructions = [...instructions].sort((a, b) => a.address - b.address);
  const arch = normalizeProgramArchitecture(options.architecture);
  const warnings: AnalysisWarning[] = [];
  if (arch === 'arm64') {
    warnings.push(warning('architecture-limit', 'ARM64 architecture detected. Disassembly available. Import resolution and calling-convention inference are limited for ARM64 in this release.'));
  }

  if (normalizedInstructions.length === 0) {
    warnings.push(warning('empty-input', 'No disassembly instructions were supplied.'));
  }

  const xrefs = buildXRefs(normalizedInstructions);
  const signatureMatches = matchLibrarySignatures(normalizedInstructions, BUILTIN_LIBRARY_SIGNATURES);
  const startCandidates = detectFunctionStartCandidates(normalizedInstructions, xrefs, options);
  const basicBlocks = splitBasicBlocks(normalizedInstructions, xrefs);
  const functions: FunctionModel[] = [];

  for (let index = 0; index < startCandidates.length; index += 1) {
    const candidate = startCandidates[index];
    const nextCandidate = startCandidates[index + 1];
    const end = detectFunctionEndCandidate(normalizedInstructions, candidate.address, nextCandidate?.address, xrefs);
    const functionInstructions = normalizedInstructions.filter(instruction => instruction.address >= candidate.address && instruction.address <= end.endAddress);
    const functionBlocks = basicBlocks.filter(block => block.startAddress >= candidate.address && block.startAddress <= end.endAddress);
    const functionWarnings = [...candidate.warnings, ...end.warnings];
    const confidence: ConfidenceLevel = candidate.confidence === 'high' && end.confidence === 'high'
      ? 'high'
      : candidate.confidence === 'low' || end.confidence === 'low'
        ? 'low'
        : 'medium';

    const signatureMatch = signatureMatches.get(candidate.address);
    const symbolName = symbolForAddress(normalizedInstructions, candidate.address);
    const functionName = signatureMatch
      ? `${signatureMatch.library}!${signatureMatch.name}`
      : symbolName ?? `sub_${candidate.address.toString(16).toUpperCase()}`;
    const nameSource: FunctionModel['nameSource'] = signatureMatch
      ? 'library-signature'
      : symbolName
        ? 'symbol'
        : candidate.reasons.includes('known-call-target') || candidate.reasons.includes('call-target') || candidate.reasons.includes('prologue-pattern')
          ? 'heuristic'
          : 'generated';
    const callingConvention = inferCallingConvention(
      functionName,
      uniqueInstructions([...functionInstructions, ...functionBlocks.flatMap(block => block.instructions)]),
      options.imports,
      candidate.address,
      arch,
    );

    functions.push({
      id: `function_${formatAddress(candidate.address)}`,
      name: functionName,
      nameSource,
      startAddress: candidate.address,
      endAddress: end.endAddress,
      instructions: functionInstructions,
      basicBlocks: functionBlocks,
      startReasons: candidate.reasons,
      startSource: sourceForStartReasons(candidate.reasons),
      endReason: end.reason,
      confidence,
      callingConvention,
      warnings: signatureMatch
        ? [...functionWarnings, warning('library-signature-match', `Function name from pattern match — not cryptographically proven: ${signatureMatch.library}!${signatureMatch.name}.`, candidate.address)]
        : functionWarnings,
    });
  }

  const callGraphNodes = functions.map(fn => ({ address: fn.startAddress, name: fn.name, confidence: fn.confidence }));
  const functionStarts = new Set(functions.map(fn => fn.startAddress));
  const callGraphEdges = xrefs
    .filter(xref => xref.kind === 'call' && functionStarts.has(xref.to))
    .map(xref => ({ from: containingFunction(functions, xref.from)?.startAddress ?? xref.from, to: xref.to, callsite: xref.from, confidence: xref.confidence }));
  const xrefImportCalls = xrefs
    .filter(xref => xref.kind === 'call')
    .flatMap(xref => {
      const parsed = parseImportSymbol(symbolForAddress(normalizedInstructions, xref.to));
      if (!parsed) return [];
      return [{
        callAddress: xref.from,
        targetAddress: xref.to,
        importName: parsed.importName,
        moduleName: parsed.moduleName,
        confidence: xref.confidence,
        evidence: `direct call target symbol ${parsed.moduleName ? `${parsed.moduleName}!` : ''}${parsed.importName}`,
      }];
    });
  const importCalls = mergeImportCalls(options.imports, xrefImportCalls);

  return {
    schema: 'hexhawk.disassembly_program.v1',
    advisoryOnly: true,
    authority: 'analysis_evidence_not_gyre_verdict',
    arch,
    instructions: normalizedInstructions,
    functions,
    basicBlocks,
    xrefs,
    importCalls,
    dataReferences: [],
    stringReferences: [],
    jumpTableCandidates: [],
    callGraph: { nodes: callGraphNodes, edges: callGraphEdges },
    warnings: [...warnings, ...functions.flatMap(fn => fn.warnings), ...basicBlocks.flatMap(block => block.warnings)],
  };
}

function containingFunction(functions: FunctionModel[], address: number): FunctionModel | undefined {
  return functions.find(fn => address >= fn.startAddress && address <= fn.endAddress);
}
