import { buildProgramAnalysis } from './disassemblyAnalysis';
import type { AnalysisWarning, BackendImport, Instruction, ProgramAnalysis, XRefKind as ProgramXRefKind } from './disassemblyModel';

export type AppBackendImport = BackendImport;

export type AppDisassembledInstruction = {
  address: number;
  mnemonic: string;
  operands: string;
  symbol?: string;
};

export type LegacyXRefKind = 'CALL' | 'JMP' | 'JMP_COND' | 'DATA' | 'STRING' | 'RIP_REL';

export type LegacyReferenceStrength = {
  incomingCount: number;
  outgoingCount: number;
  importance: 'critical' | 'high' | 'medium' | 'low';
};

export type LegacyFunctionMetadata = {
  startAddress: number;
  endAddress: number;
  size: number;
  prologueType?: 'push_rbp' | 'sub_rsp' | 'custom' | 'leaf';
  callCount: number;
  incomingCalls: Set<number>;
  returnCount: number;
  hasLoops: boolean;
  complexity: number;
  suspiciousPatterns: string[];
  isRecursive: boolean;
  hasTailCall: boolean;
  callingConvention?: 'cdecl' | 'fastcall' | 'stdcall' | 'unknown';
  isThunk?: boolean;
  thunkTarget?: number;
};

export type LegacyLoopInfo = {
  startAddress: number;
  endAddress: number;
  backEdgeAddress: number;
  depth: number;
  iterationPattern?: string;
};

export type LegacySuspiciousPattern = {
  address: number;
  type:
    | 'tight_loop'
    | 'repeated_memory'
    | 'indirect_call'
    | 'jump_table'
    | 'switch_table'
    | 'obfuscation'
    | 'validation'
    | 'opaque_predicate'
    | 'flattened_cf'
    | 'anti_tamper'
    | 'self_modifying';
  severity: 'warning' | 'critical';
  description: string;
  relatedAddresses?: number[];
};

export type LegacyBlockAnalysis = {
  blockId: string;
  blockType: 'entry' | 'loop' | 'exit' | 'normal' | 'unreachable';
  branchingComplexity: number;
  loopDepth: number;
  callCount: number;
  suspiciousPatterns: LegacySuspiciousPattern[];
};

export type LegacyDisassemblyAnalysis = {
  functions: Map<number, LegacyFunctionMetadata>;
  loops: LegacyLoopInfo[];
  suspiciousPatterns: LegacySuspiciousPattern[];
  referenceStrength: Map<number, LegacyReferenceStrength>;
  blockAnalysis: Map<string, LegacyBlockAnalysis>;
};

export type AdapterCfgNode = {
  id: string;
  label?: string;
  start?: number;
  end?: number;
  instruction_count?: number;
  block_type?: string;
  layout_x?: number;
  layout_y?: number;
  layout_depth?: number;
};

export type AdapterCfgEdge = {
  source: string;
  target: string;
  kind?: string;
  condition?: string;
};

export type AdapterCfgGraph = {
  nodes: AdapterCfgNode[];
  edges: AdapterCfgEdge[];
};

export type ProgramAnalysisAdapterResult = {
  programAnalysis: ProgramAnalysis;
  legacyAnalysis: LegacyDisassemblyAnalysis;
  referencesMap: Map<number, Set<number>>;
  jumpTargetsMap: Map<number, Set<number>>;
  xrefTypes: Map<string, LegacyXRefKind>;
  addressToBlockMap: Map<number, { blockId: string; start: number; end: number }>;
  warnings: AnalysisWarning[];
};

export function toProgramInstructions(instructions: AppDisassembledInstruction[]): Instruction[] {
  return instructions.map((instruction) => ({
    address: instruction.address,
    mnemonic: instruction.mnemonic,
    operands: instruction.operands,
    symbol: instruction.symbol,
    source: 'backend',
  }));
}

function normalizeMnemonic(instruction: Pick<AppDisassembledInstruction, 'mnemonic'>): string {
  return instruction.mnemonic.toLowerCase().trim();
}

function buildLegacyReferenceMaps(instructions: AppDisassembledInstruction[]): Pick<ProgramAnalysisAdapterResult, 'referencesMap' | 'jumpTargetsMap' | 'xrefTypes'> {
  const referencesMap = new Map<number, Set<number>>();
  const jumpTargetsMap = new Map<number, Set<number>>();
  const xrefTypes = new Map<string, LegacyXRefKind>();

  const getInstructionType = (mnemonic: string): LegacyXRefKind | null => {
    const m = mnemonic.toLowerCase();
    if (m.startsWith('call')) return 'CALL';
    if (m.startsWith('j') && m !== 'jmp') return 'JMP_COND';
    if (m === 'jmp') return 'JMP';
    if (m.startsWith('mov') || m.startsWith('lea') || m.startsWith('add') || m.startsWith('sub')) return 'DATA';
    return null;
  };

  const extractAddressesFromOperands = (
    address: number,
    mnemonic: string,
    operands: string,
  ): { address: number; kind: LegacyXRefKind }[] => {
    const results: { address: number; kind: LegacyXRefKind }[] = [];
    const baseType = getInstructionType(mnemonic);

    const hexMatches = Array.from(operands.matchAll(/\b0x[0-9a-fA-F]+\b/g));
    for (const match of hexMatches) {
      const targetAddr = parseInt(match[0], 16);
      const kind = baseType || 'DATA';
      results.push({ address: targetAddr, kind });
    }

    const ripMatches = Array.from(operands.matchAll(/\[?rip\s*[+-]\s*0x([0-9a-fA-F]+)\]?/gi));
    for (const match of ripMatches) {
      const offset = parseInt(match[1], 16);
      const isNegative = match[0].includes('-');
      const nextInstructionAddr = address + 7;
      const targetAddr = isNegative ? nextInstructionAddr - offset : nextInstructionAddr + offset;
      results.push({ address: targetAddr, kind: 'RIP_REL' });
    }

    const negativeMatches = Array.from(operands.matchAll(/\b-0x([0-9a-fA-F]+)\b/g));
    for (const match of negativeMatches) {
      const offset = parseInt(match[1], 16);
      const targetAddr = address - offset;
      const kind = baseType || 'JMP_COND';
      results.push({ address: targetAddr, kind });
    }

    const memMatches = Array.from(operands.matchAll(/\[\s*(0x[0-9a-fA-F]+)\s*\]/g));
    for (const match of memMatches) {
      const targetAddr = parseInt(match[1], 16);
      results.push({ address: targetAddr, kind: 'DATA' });
    }

    return results;
  };

  instructions.forEach((instruction) => {
    if (!instruction.operands) return;
    const targets = extractAddressesFromOperands(instruction.address, instruction.mnemonic, instruction.operands);

    targets.forEach(({ address: targetAddr, kind }) => {
      if (!jumpTargetsMap.has(instruction.address)) {
        jumpTargetsMap.set(instruction.address, new Set());
      }
      jumpTargetsMap.get(instruction.address)!.add(targetAddr);

      if (!referencesMap.has(targetAddr)) {
        referencesMap.set(targetAddr, new Set());
      }
      referencesMap.get(targetAddr)!.add(instruction.address);

      xrefTypes.set(`${instruction.address}:${targetAddr}`, kind);
    });
  });

  return { referencesMap, jumpTargetsMap, xrefTypes };
}

function detectLoops(graph: AdapterCfgGraph): LegacyLoopInfo[] {
  const loops: LegacyLoopInfo[] = [];
  const visited = new Set<string>();
  const recursionStack = new Set<string>();
  const adjacency = new Map<string, string[]>();
  const nodeMap = new Map<string, AdapterCfgNode>();

  for (const node of graph.nodes) {
    nodeMap.set(node.id, node);
    adjacency.set(node.id, []);
  }
  for (const edge of graph.edges) {
    const list = adjacency.get(edge.source);
    if (list) list.push(edge.target);
  }

  const dfs = (nodeId: string, depth = 0) => {
    if (visited.has(nodeId)) return;
    visited.add(nodeId);
    recursionStack.add(nodeId);

    const node = nodeMap.get(nodeId);
    if (!node) {
      recursionStack.delete(nodeId);
      return;
    }

    for (const targetId of (adjacency.get(nodeId) ?? [])) {
      if (recursionStack.has(targetId)) {
        const targetNode = nodeMap.get(targetId);
        if (targetNode && node.start && targetNode.start) {
          loops.push({
            startAddress: Math.min(node.start, targetNode.start),
            endAddress: Math.max(node.end || 0, targetNode.end || 0),
            backEdgeAddress: node.start,
            depth,
          });
        }
      } else {
        dfs(targetId, depth + 1);
      }
    }

    recursionStack.delete(nodeId);
  };

  graph.nodes.forEach((node) => dfs(node.id));
  return loops;
}

function detectSuspiciousPatterns(instructions: AppDisassembledInstruction[]): LegacySuspiciousPattern[] {
  const patterns: LegacySuspiciousPattern[] = [];
  const memoryAccessCount = new Map<number, number>();

  for (let i = 0; i < instructions.length; i += 1) {
    const instruction = instructions[i];
    const mnemonic = normalizeMnemonic(instruction);

    if (mnemonic === 'jmp' && instruction.operands) {
      const matches = instruction.operands.match(/0x[0-9a-fA-F]+/);
      if (matches) {
        const targetAddr = parseInt(matches[0], 16);
        const distance = Math.abs(instruction.address - targetAddr);
        if (distance < 100 && distance > 0) {
          patterns.push({
            address: instruction.address,
            type: 'tight_loop',
            severity: 'warning',
            description: `Tight backward jump (${distance} bytes)`,
            relatedAddresses: [targetAddr],
          });
        }
      }
    }

    if (mnemonic.startsWith('mov') || mnemonic.startsWith('lea') || mnemonic.startsWith('cmp')) {
      const memMatch = instruction.operands.match(/\[([^\]]+)\]/);
      if (memMatch) {
        memoryAccessCount.set(instruction.address, (memoryAccessCount.get(instruction.address) || 0) + 1);
      }
    }

    if (mnemonic === 'call' && /r[0-9a-z]+/.test(instruction.operands)) {
      patterns.push({
        address: instruction.address,
        type: 'indirect_call',
        severity: 'warning',
        description: `Indirect call through register: ${instruction.operands}`,
      });
    }

    if ((mnemonic.startsWith('mov') || mnemonic.startsWith('lea')) && /0x[0-9a-fA-F]{6,}/.test(instruction.operands)) {
      patterns.push({
        address: instruction.address,
        type: 'jump_table',
        severity: 'critical',
        description: 'Large address constant (possible jump table)',
      });
    }
  }

  const CMP_MNS = new Set(['cmp', 'test', 'cmpl', 'cmpq', 'cmpb', 'cmpw', 'testl', 'testq', 'testb']);
  const CJMP_MNS = new Set(['je', 'jne', 'jz', 'jnz', 'jl', 'jle', 'jg', 'jge', 'ja', 'jae', 'jb', 'jbe', 'jns', 'js', 'jo', 'jno']);
  const WINDOW = 12;
  for (let i = 0; i < instructions.length; i += 1) {
    const slice = instructions.slice(i, i + WINDOW);
    const cmpCount = slice.filter((x) => CMP_MNS.has(normalizeMnemonic(x))).length;
    const cjmpCount = slice.filter((x) => CJMP_MNS.has(normalizeMnemonic(x))).length;
    if (cmpCount >= 3 && cjmpCount >= 1) {
      const prevFlagged = patterns.some(
        (p) => p.type === 'validation' && Math.abs(p.address - instructions[i].address) < 20,
      );
      if (!prevFlagged) {
        patterns.push({
          address: instructions[i].address,
          type: 'validation',
          severity: 'warning',
          description: `Comparison-dense region: ${cmpCount} cmp/test + ${cjmpCount} conditional branch(es) in ${WINDOW} instructions - likely validation or control gate`,
          relatedAddresses: slice
            .filter((x) => CMP_MNS.has(normalizeMnemonic(x)) || CJMP_MNS.has(normalizeMnemonic(x)))
            .map((x) => x.address),
        });
        i += WINDOW - 1;
      }
    }
  }

  const regConstHits = new Map<string, Set<number>>();
  const regFirstAddr = new Map<string, number>();
  for (const instruction of instructions) {
    const mnemonic = normalizeMnemonic(instruction);
    if (mnemonic === 'cmp' || mnemonic === 'cmpl' || mnemonic === 'cmpb' || mnemonic === 'cmpq') {
      const parts = instruction.operands.split(',').map((s) => s.trim());
      if (parts.length === 2) {
        const [left, right] = parts;
        const constMatch = right.match(/^(?:0x[0-9a-fA-F]+|\d+)$/);
        if (constMatch) {
          const constVal = constMatch[0].startsWith('0x')
            ? parseInt(constMatch[0], 16)
            : parseInt(constMatch[0], 10);
          if (!regConstHits.has(left)) {
            regConstHits.set(left, new Set());
            regFirstAddr.set(left, instruction.address);
          }
          regConstHits.get(left)!.add(constVal);
        }
      }
    }
  }
  for (const [reg, constants] of Array.from(regConstHits.entries())) {
    if (constants.size >= 3) {
      const firstAddr = regFirstAddr.get(reg)!;
      const alreadyFlagged = patterns.some(
        (p) => p.type === 'validation' && Math.abs(p.address - firstAddr) < 30,
      );
      if (!alreadyFlagged) {
        patterns.push({
          address: firstAddr,
          type: 'validation',
          severity: 'critical',
          description: `Serial comparison: '${reg}' compared against ${constants.size} distinct constants - probable auth, license, or dispatch check`,
          relatedAddresses: [],
        });
      }
    }
  }

  return patterns;
}

function mapProgramXRefKind(kind: ProgramXRefKind): LegacyXRefKind {
  switch (kind) {
    case 'call':
      return 'CALL';
    case 'jump':
      return 'JMP';
    case 'conditional-jump':
    case 'fallthrough':
      return 'JMP_COND';
    case 'string':
      return 'STRING';
    case 'data':
    case 'import':
    case 'unknown':
    default:
      return 'DATA';
  }
}

export function xrefMapsFromProgramAnalysis(programAnalysis: ProgramAnalysis): Pick<ProgramAnalysisAdapterResult, 'referencesMap' | 'jumpTargetsMap' | 'xrefTypes'> {
  const referencesMap = new Map<number, Set<number>>();
  const jumpTargetsMap = new Map<number, Set<number>>();
  const xrefTypes = new Map<string, LegacyXRefKind>();

  for (const xref of programAnalysis.xrefs) {
    if (!jumpTargetsMap.has(xref.from)) jumpTargetsMap.set(xref.from, new Set());
    jumpTargetsMap.get(xref.from)!.add(xref.to);

    if (!referencesMap.has(xref.to)) referencesMap.set(xref.to, new Set());
    referencesMap.get(xref.to)!.add(xref.from);

    xrefTypes.set(`${xref.from}:${xref.to}`, mapProgramXRefKind(xref.kind));
  }

  return { referencesMap, jumpTargetsMap, xrefTypes };
}

function detectLegacyFunctions(
  instructions: AppDisassembledInstruction[],
  referencesMap: Map<number, Set<number>>,
  jumpTargetsMap: Map<number, Set<number>>,
): Map<number, LegacyFunctionMetadata> {
  const functions = new Map<number, LegacyFunctionMetadata>();
  if (instructions.length === 0) return functions;

  const callTargets = new Set<number>();
  const jumpTargets = new Set<number>();
  const addrToIndex = new Map<number, number>();
  instructions.forEach((instruction, index) => {
    addrToIndex.set(instruction.address, index);
    const mnemonic = normalizeMnemonic(instruction);
    const targets = jumpTargetsMap.get(instruction.address) || new Set();
    if (mnemonic.startsWith('call')) targets.forEach((addr) => callTargets.add(addr));
    if (mnemonic.startsWith('j')) targets.forEach((addr) => jumpTargets.add(addr));
  });

  const candidateStarts = new Set<number>([instructions[0].address, ...Array.from(callTargets)]);
  for (let i = 0; i < instructions.length; i += 1) {
    const instruction = instructions[i];
    const mnemonic = normalizeMnemonic(instruction);
    if (
      mnemonic === 'push'
      && instruction.operands.includes('rbp')
      && i + 1 < instructions.length
      && normalizeMnemonic(instructions[i + 1]).startsWith('mov')
      && instructions[i + 1].operands.includes('rbp')
    ) {
      candidateStarts.add(instruction.address);
    }

    if (mnemonic.startsWith('sub') && instruction.operands.includes('rsp')) {
      candidateStarts.add(instruction.address);
    }
  }

  for (const target of Array.from(jumpTargets)) {
    const index = addrToIndex.get(target);
    if (index === undefined) continue;
    const current = instructions[index];
    const next = instructions[index + 1];
    const mnemonic = normalizeMnemonic(current);
    const looksLikePrologue =
      (mnemonic === 'push' && current.operands.includes('rbp') && !!next && normalizeMnemonic(next).startsWith('mov'))
      || (mnemonic.startsWith('sub') && current.operands.includes('rsp'));
    if (looksLikePrologue) candidateStarts.add(target);
  }

  const sortedStarts = Array.from(candidateStarts)
    .filter((addr) => addrToIndex.has(addr))
    .sort((a, b) => a - b);

  for (let startCursor = 0; startCursor < sortedStarts.length; startCursor += 1) {
    const funcStart = sortedStarts[startCursor];
    const startIndex = addrToIndex.get(funcStart);
    if (startIndex === undefined) continue;

    const nextStart = sortedStarts[startCursor + 1];
    const nextStartIndex = nextStart !== undefined ? addrToIndex.get(nextStart) : undefined;
    const endBoundIndex = nextStartIndex !== undefined ? Math.max(startIndex, nextStartIndex - 1) : instructions.length - 1;
    const funcInstructions = instructions.slice(startIndex, endBoundIndex + 1);
    if (funcInstructions.length === 0) continue;

    const first = funcInstructions[0];
    const second = funcInstructions[1];
    let prologueType: LegacyFunctionMetadata['prologueType'] = undefined;
    if (
      normalizeMnemonic(first) === 'push'
      && first.operands.includes('rbp')
      && !!second
      && normalizeMnemonic(second).startsWith('mov')
    ) {
      prologueType = 'push_rbp';
    } else if (normalizeMnemonic(first).startsWith('sub') && first.operands.includes('rsp')) {
      prologueType = 'sub_rsp';
    } else if (callTargets.has(funcStart)) {
      prologueType = 'custom';
    }

    let callCount = 0;
    let returnCount = 0;
    for (const instruction of funcInstructions) {
      const mnemonic = normalizeMnemonic(instruction);
      if (mnemonic.startsWith('call')) callCount += 1;
      if (mnemonic.startsWith('ret')) returnCount += 1;
    }

    const incomingCalls = referencesMap.get(funcStart) || new Set<number>();
    const hasRet = returnCount > 0;
    const isEntryCandidate = startCursor === 0;
    const strongEvidence = !!prologueType || hasRet || incomingCalls.size > 0 || isEntryCandidate;
    if (!strongEvidence) continue;

    const funcEnd = funcInstructions[funcInstructions.length - 1].address;
    const size = Math.max(0, funcEnd - funcStart);
    const isRecursive = incomingCalls.has(funcStart);

    let hasTailCall = false;
    for (let index = funcInstructions.length - 1; index >= 0; index -= 1) {
      const instruction = funcInstructions[index];
      const mnemonic = normalizeMnemonic(instruction);
      if (mnemonic === 'ret') break;
      if (mnemonic === 'jmp' || mnemonic === 'jmpq') {
        const jmpTargets = jumpTargetsMap.get(instruction.address);
        if (jmpTargets) {
          for (const target of Array.from(jmpTargets)) {
            if (target < funcStart || target > funcEnd) {
              hasTailCall = true;
              break;
            }
          }
        }
        break;
      }
    }

    let callingConvention: LegacyFunctionMetadata['callingConvention'] = 'unknown';
    if (prologueType === 'push_rbp') callingConvention = 'cdecl';
    else if (prologueType === 'sub_rsp') callingConvention = 'fastcall';

    let isThunk = false;
    let thunkTarget: number | undefined;
    const nonNopInstrs = funcInstructions.filter((instruction) => {
      const mnemonic = normalizeMnemonic(instruction);
      return mnemonic !== 'nop' && mnemonic !== 'nopl' && mnemonic !== 'nopw';
    });
    if (nonNopInstrs.length <= 2 && nonNopInstrs.length > 0) {
      const lastInstr = nonNopInstrs[nonNopInstrs.length - 1];
      const mnemonic = normalizeMnemonic(lastInstr);
      if (mnemonic === 'jmp' || mnemonic === 'jmpq') {
        const targets = jumpTargetsMap.get(lastInstr.address);
        if (targets && targets.size === 1) {
          const target = Array.from(targets)[0];
          if (target < funcStart || target > funcEnd) {
            isThunk = true;
            thunkTarget = target;
          }
        }
      }
    }

    functions.set(funcStart, {
      startAddress: funcStart,
      endAddress: funcEnd,
      size,
      prologueType,
      callCount,
      incomingCalls: new Set(incomingCalls),
      returnCount,
      hasLoops: false,
      complexity: Math.min(10, callCount + returnCount),
      suspiciousPatterns: [],
      isRecursive,
      hasTailCall,
      callingConvention,
      isThunk,
      thunkTarget,
    });
  }

  return functions;
}

function calculateReferenceStrength(
  referencesMap: Map<number, Set<number>>,
  jumpTargetsMap: Map<number, Set<number>>,
  functions: Map<number, LegacyFunctionMetadata>,
): Map<number, LegacyReferenceStrength> {
  const strength = new Map<number, LegacyReferenceStrength>();

  referencesMap.forEach((incoming, addr) => {
    const outgoing = jumpTargetsMap.get(addr) || new Set();
    const isFunctionStart = functions.has(addr);
    const incomingCount = incoming.size;
    const outgoingCount = outgoing.size;

    let importance: LegacyReferenceStrength['importance'] = 'low';
    if (isFunctionStart && incomingCount >= 5) importance = 'critical';
    else if (incomingCount >= 3) importance = 'high';
    else if (incomingCount >= 1) importance = 'medium';

    strength.set(addr, { incomingCount, outgoingCount, importance });
  });

  return strength;
}

function buildBlockAnalysis(
  graph: AdapterCfgGraph | null,
  loops: LegacyLoopInfo[],
  patterns: LegacySuspiciousPattern[],
): Map<string, LegacyBlockAnalysis> {
  const blockAnalysis = new Map<string, LegacyBlockAnalysis>();
  if (!graph) return blockAnalysis;

  graph.nodes.forEach((node) => {
    const blockType = node.block_type === 'entry'
      ? 'entry'
      : loops.some((loop) => loop.startAddress === node.start)
        ? 'loop'
        : node.block_type === 'external'
          ? 'exit'
          : 'normal';

    blockAnalysis.set(node.id, {
      blockId: node.id,
      blockType,
      branchingComplexity: graph.edges.filter((edge) => edge.source === node.id).length,
      loopDepth: loops.filter((loop) => loop.startAddress >= (node.start || 0) && loop.endAddress <= (node.end || 0)).length,
      callCount: 0,
      suspiciousPatterns: patterns.filter((pattern) => pattern.address >= (node.start || 0) && pattern.address <= (node.end || 0)),
    });
  });

  return blockAnalysis;
}

export function buildAddressToBlockMap(graph: AdapterCfgGraph | null): Map<number, { blockId: string; start: number; end: number }> {
  const map = new Map<number, { blockId: string; start: number; end: number }>();
  if (!graph) return map;

  graph.nodes.forEach((node) => {
    if (node.start !== undefined && node.end !== undefined) {
      for (let addr = node.start; addr < node.end; addr += 1) {
        map.set(addr, {
          blockId: node.id,
          start: node.start,
          end: node.end,
        });
      }
    }
  });

  return map;
}

export function buildProgramAnalysisAdapter(
  instructions: AppDisassembledInstruction[],
  graph: AdapterCfgGraph | null,
  imports: Iterable<AppBackendImport> = [],
): ProgramAnalysisAdapterResult {
  const programAnalysis = buildProgramAnalysis(toProgramInstructions(instructions), { imports });
  const { referencesMap, jumpTargetsMap, xrefTypes } = buildLegacyReferenceMaps(instructions);
  const functions = detectLegacyFunctions(instructions, referencesMap, jumpTargetsMap);
  const loops = detectLoops(graph || { nodes: [], edges: [] });
  const suspiciousPatterns = detectSuspiciousPatterns(instructions);
  const referenceStrength = calculateReferenceStrength(referencesMap, jumpTargetsMap, functions);
  const blockAnalysis = buildBlockAnalysis(graph, loops, suspiciousPatterns);
  const addressToBlockMap = buildAddressToBlockMap(graph);

  return {
    programAnalysis,
    legacyAnalysis: {
      functions,
      loops,
      suspiciousPatterns,
      referenceStrength,
      blockAnalysis,
    },
    referencesMap,
    jumpTargetsMap,
    xrefTypes,
    addressToBlockMap,
    warnings: programAnalysis.warnings,
  };
}
