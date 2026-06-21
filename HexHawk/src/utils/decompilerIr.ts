import type { DisassembledInstruction } from './decompilerEngine';
import type { DecompilerIrNode, DecompilerIrValue, ReachingDefs } from './decompilerTypes';
import { resolveImportPrototype } from './importPrototypes';

const BINOP: Record<string, string> = {
  add: '+', adc: '+', sub: '-', sbb: '-', imul: '*', mul: '*',
  and: '&', or: '|', xor: '^', shl: '<<', sal: '<<', shr: '>>', sar: '>>',
};

const COND: Record<string, string> = {
  je: '==', jz: '==', jne: '!=', jnz: '!=', jl: '<', jle: '<=', jg: '>', jge: '>=',
  ja: '>(u)', jae: '>=(u)', jb: '<(u)', jbe: '<=(u)', js: '<0', jns: '>=0',
};

const ARG_REGS = ['rcx', 'rdx', 'r8', 'r9', 'rdi', 'rsi'];

const CALL_ARGUMENT_REGISTER_ORDERS: ReadonlyArray<readonly string[]> = [
  // Windows x64: first four integer/pointer args are rcx, rdx, r8, r9.
  ['rcx', 'rdx', 'r8', 'r9'],
  // System V AMD64: first six integer/pointer args are rdi, rsi, rdx, rcx, r8, r9.
  ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'],
];

export function splitIrOperands(operands: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = '';
  for (const char of operands) {
    if (char === '[' || char === '(') depth += 1;
    if (char === ']' || char === ')') depth = Math.max(0, depth - 1);
    if (char === ',' && depth === 0) {
      parts.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }
  if (current.trim()) parts.push(current.trim());
  return parts;
}

function parseNumber(text: string): number | null {
  const cleaned = text.trim().replace(/^#/, '');
  if (/^-?0x[0-9a-f]+$/i.test(cleaned)) return Number.parseInt(cleaned, 16);
  if (/^-?\d+$/.test(cleaned)) return Number.parseInt(cleaned, 10);
  return null;
}

function stackCandidate(text: string): DecompilerIrValue | null {
  const normalized = text.toLowerCase().replace(/\s+/g, ' ');
  const match = normalized.match(/\[(r[bs]p|e[bs]p|rbp|rsp)\s*([+-])\s*(0x[0-9a-f]+|\d+)\]/i);
  if (!match) return null;
  const magnitude = parseNumber(match[3]) ?? 0;
  const offset = match[2] === '-' ? -magnitude : magnitude;
  const prefix = offset < 0 ? 'local' : 'arg';
  return {
    kind: 'stack-variable-candidate',
    base: match[1],
    offset,
    name: `${prefix}_${Math.abs(offset).toString(16)}`,
  };
}

export function parseDecompilerIrValue(text: string): DecompilerIrValue {
  const raw = text.trim();
  const lower = raw.toLowerCase();
  const stack = stackCandidate(raw);
  if (stack) return stack;

  const numeric = parseNumber(raw);
  if (numeric !== null) return { kind: 'constant', value: numeric, raw };

  if (/^(r(?:[abcd]x|[sd]i|[sb]p|[0-9]+)|e(?:[abcd]x|[sd]i|[sb]p)|[abcd][lh]|x[0-9]+|w[0-9]+)$/i.test(lower)) {
    return { kind: 'register', name: lower };
  }

  if (/^\[.*\]$/.test(raw) || /ptr\s+\[.*\]/i.test(raw)) {
    return { kind: 'memory', text: raw };
  }

  return { kind: 'expression', text: raw };
}

function directTarget(text: string | undefined): number | null {
  if (!text) return null;
  const match = text.match(/\b0x[0-9a-f]+\b/i);
  if (match) return Number.parseInt(match[0], 16);
  return parseNumber(text);
}

function valueIsMemory(value: DecompilerIrValue): boolean {
  return value.kind === 'memory' || value.kind === 'stack-variable-candidate';
}

function registerCandidate(value: DecompilerIrValue): DecompilerIrValue | null {
  if (value.kind !== 'register') return null;
  const idx = ARG_REGS.indexOf(value.name);
  if (idx < 0) return null;
  return { kind: 'register-variable-candidate', register: value.name, name: `param_${idx}` };
}

function definedRegister(value: DecompilerIrValue): string | null {
  return value.kind === 'register' ? value.name.toLowerCase() : null;
}

function recoverCallArgs(registerDefinitions: Map<string, DecompilerIrValue>): DecompilerIrValue[] {
  let best: DecompilerIrValue[] = [];
  for (const order of CALL_ARGUMENT_REGISTER_ORDERS) {
    const candidate: DecompilerIrValue[] = [];
    for (const register of order) {
      const value = registerDefinitions.get(register);
      if (!value) break;
      candidate.push(value);
    }
    if (candidate.length > best.length) best = candidate;
  }
  return best;
}

function updateRegisterDefinitions(
  registerDefinitions: Map<string, DecompilerIrValue>,
  node: DecompilerIrNode,
): void {
  if (node.kind === 'assignment' || node.kind === 'load') {
    const register = definedRegister(node.destination);
    if (register) registerDefinitions.set(register, node.source);
    return;
  }

  if (node.kind === 'arithmetic') {
    const register = definedRegister(node.destination);
    if (register) {
      registerDefinitions.set(register, {
        kind: 'expression',
        text: `${formatIrValue(node.left)} ${node.operator} ${formatIrValue(node.right)}`,
      });
    }
  }
}

function formatIrValue(value: DecompilerIrValue): string {
  switch (value.kind) {
    case 'register': return value.name;
    case 'constant': return value.raw;
    case 'memory': return value.text;
    case 'stack-variable-candidate': return value.name;
    case 'register-variable-candidate': return value.name;
    case 'expression': return value.text;
  }
}

export function liftInstructionToDecompilerIr(
  instruction: DisassembledInstruction,
  nextAddress?: number,
): DecompilerIrNode[] {
  const address = instruction.address;
  const mnemonic = instruction.mnemonic.trim().toLowerCase();
  const operands = splitIrOperands(instruction.operands);
  const raw = `${instruction.mnemonic} ${instruction.operands}`.trim();

  if (mnemonic === 'nop' || mnemonic === 'nopl' || mnemonic === 'nopw') {
    return [{ kind: 'side-effect-note', address, text: 'no operation', confidence: 'high' }];
  }

  if (mnemonic.startsWith('ret')) {
    return [{ kind: 'return', address, confidence: 'high' }];
  }

  if (mnemonic === 'call' || mnemonic === 'callq') {
    const target = directTarget(operands[0]);
    const name = target === null ? operands[0] : undefined;
    const resolvedPrototype = resolveImportPrototype(name);
    return [{ kind: 'call', address, target, name, args: [], confidence: target === null ? 'medium' : 'high', unresolved: target === null, resolvedPrototype }];
  }

  if (mnemonic === 'jmp' || mnemonic === 'jmpq') {
    const target = directTarget(operands[0]);
    if (target === null) {
      return [{ kind: 'unknown', address, raw, warning: 'Unresolved indirect jump; control flow is not proven.', confidence: 'unknown' }];
    }
    return [{ kind: 'side-effect-note', address, text: `jump to 0x${target.toString(16)}`, confidence: 'high' }];
  }

  if (mnemonic in COND) {
    return [{
      kind: 'conditional-branch',
      address,
      condition: COND[mnemonic],
      target: directTarget(operands[0]),
      fallthrough: nextAddress,
      confidence: directTarget(operands[0]) === null ? 'low' : 'medium',
    }];
  }

  if ((mnemonic === 'cmp' || mnemonic === 'test') && operands.length >= 2) {
    return [{ kind: 'compare', address, left: parseDecompilerIrValue(operands[0]), right: parseDecompilerIrValue(operands[1]), operator: mnemonic, confidence: 'high' }];
  }

  if ((mnemonic.startsWith('mov') || mnemonic === 'lea') && operands.length >= 2) {
    const destination = parseDecompilerIrValue(operands[0]);
    const source = parseDecompilerIrValue(operands[1]);
    const nodes: DecompilerIrNode[] = [];
    if (valueIsMemory(destination)) nodes.push({ kind: 'store', address, destination, source, confidence: 'medium' });
    else if (valueIsMemory(source)) nodes.push({ kind: 'load', address, destination, source, confidence: 'medium' });
    else nodes.push({ kind: 'assignment', address, destination, source, confidence: 'high' });

    const stackVar = destination.kind === 'stack-variable-candidate' ? destination : source.kind === 'stack-variable-candidate' ? source : null;
    if (stackVar) nodes.push({ kind: 'stack-variable-candidate', address, variable: stackVar, confidence: 'medium' });
    const regVar = registerCandidate(source);
    if (regVar) nodes.push({ kind: 'register-variable-candidate', address, variable: regVar, confidence: 'medium' });
    return nodes;
  }

  if (mnemonic === 'xor' && operands.length >= 2 && operands[0].toLowerCase() === operands[1].toLowerCase()) {
    return [{
      kind: 'assignment',
      address,
      destination: parseDecompilerIrValue(operands[0]),
      source: { kind: 'constant', value: 0, raw: '0' },
      confidence: 'high',
    }];
  }

  if (mnemonic in BINOP && operands.length >= 2) {
    const destination = parseDecompilerIrValue(operands[0]);
    return [{
      kind: 'arithmetic',
      address,
      operator: BINOP[mnemonic],
      destination,
      left: destination,
      right: parseDecompilerIrValue(operands[1]),
      confidence: 'high',
    }];
  }

  if ((mnemonic === 'push' || mnemonic === 'pop') && operands.length >= 1) {
    return [{ kind: 'side-effect-note', address, text: `${mnemonic} affects stack state: ${operands[0]}`, confidence: 'medium' }];
  }

  return [{ kind: 'unknown', address, raw, warning: `No explicit IR lift for instruction '${raw}'.`, confidence: 'unknown' }];
}

export function liftInstructionsToDecompilerIr(instructions: DisassembledInstruction[]): DecompilerIrNode[] {
  const registerDefinitions = new Map<string, DecompilerIrValue>();
  const lifted: DecompilerIrNode[] = [];

  for (let index = 0; index < instructions.length; index += 1) {
    const instructionNodes = liftInstructionToDecompilerIr(instructions[index], instructions[index + 1]?.address).map((node) => {
      if (node.kind !== 'call') return node;
      return { ...node, args: recoverCallArgs(registerDefinitions) };
    });

    lifted.push(...instructionNodes);
    for (const node of instructionNodes) updateRegisterDefinitions(registerDefinitions, node);
  }

  return lifted;
}

function variableKey(value: DecompilerIrValue): string | null {
  switch (value.kind) {
    case 'register': return value.name.toLowerCase();
    case 'register-variable-candidate': return value.name;
    case 'stack-variable-candidate': return value.name;
    case 'memory': return value.base ? `${value.base.toLowerCase()}${value.offset ?? 0}` : value.text;
    case 'constant': return null;
    case 'expression': return value.text;
  }
}

function nodeDefinition(node: DecompilerIrNode): string | null {
  if (node.kind === 'assignment' || node.kind === 'load' || node.kind === 'arithmetic') {
    return variableKey(node.destination);
  }
  return null;
}

function nodeUses(node: DecompilerIrNode): string[] {
  const uses: Array<string | null> = [];
  switch (node.kind) {
    case 'assignment': uses.push(variableKey(node.source)); break;
    case 'load': uses.push(variableKey(node.source)); break;
    case 'store': uses.push(variableKey(node.destination), variableKey(node.source)); break;
    case 'arithmetic': uses.push(variableKey(node.left), variableKey(node.right)); break;
    case 'compare': uses.push(variableKey(node.left), variableKey(node.right)); break;
    case 'call': uses.push(...node.args.map(variableKey)); break;
    case 'return': uses.push(node.value ? variableKey(node.value) : null); break;
    case 'stack-variable-candidate': uses.push(variableKey(node.variable)); break;
    case 'register-variable-candidate': uses.push(variableKey(node.variable)); break;
    case 'conditional-branch':
    case 'side-effect-note':
    case 'unknown':
      break;
  }
  return uses.filter((use): use is string => Boolean(use));
}

function constantValue(value: DecompilerIrValue, constants: Map<string, DecompilerIrValue>): DecompilerIrValue | null {
  if (value.kind === 'constant') return value;
  const key = variableKey(value);
  if (!key) return null;
  const known = constants.get(key);
  return known?.kind === 'constant' ? known : null;
}

function foldBinary(operator: string, left: number, right: number): number | null {
  switch (operator) {
    case '+': return left + right;
    case '-': return left - right;
    case '*': return left * right;
    case '&': return left & right;
    case '|': return left | right;
    case '^': return left ^ right;
    case '<<': return left << right;
    case '>>': return left >> right;
    default: return null;
  }
}

/** Constant folding pass. Pure transform: known constant arithmetic becomes assignment to a constant. */
export function constantFoldDecompilerIr(nodes: DecompilerIrNode[]): DecompilerIrNode[] {
  const constants = new Map<string, DecompilerIrValue>();
  return nodes.map((node) => {
    if (node.kind === 'assignment') {
      const def = nodeDefinition(node);
      if (def) {
        if (node.source.kind === 'constant') constants.set(def, node.source);
        else constants.delete(def);
      }
      return { ...node };
    }

    if (node.kind === 'arithmetic') {
      const left = constantValue(node.left, constants);
      const right = constantValue(node.right, constants);
      const def = nodeDefinition(node);
      if (left?.kind === 'constant' && right?.kind === 'constant') {
        const value = foldBinary(node.operator, left.value, right.value);
        if (value !== null) {
          const constant: DecompilerIrValue = { kind: 'constant', value, raw: String(value) };
          if (def) constants.set(def, constant);
          return {
            kind: 'assignment',
            address: node.address,
            destination: node.destination,
            source: constant,
            confidence: node.confidence,
          } satisfies DecompilerIrNode;
        }
      }
      if (def) constants.delete(def);
    }

    const def = nodeDefinition(node);
    if (def && node.kind !== 'arithmetic') constants.delete(def);
    return { ...node };
  });
}

/** Dead-store elimination pass. Removes variable definitions never used before redefinition or exit. */
export function eliminateDeadStores(nodes: DecompilerIrNode[]): DecompilerIrNode[] {
  const live = new Set<string>();
  const kept: DecompilerIrNode[] = [];

  for (let index = nodes.length - 1; index >= 0; index -= 1) {
    const node = nodes[index];
    const def = nodeDefinition(node);
    const uses = nodeUses(node);
    const removable = node.kind === 'assignment' || node.kind === 'load' || node.kind === 'arithmetic';

    if (def && removable && !live.has(def)) {
      continue;
    }

    if (def) live.delete(def);
    for (const use of uses) live.add(use);
    kept.push({ ...node });
  }

  return kept.reverse();
}

function mapsEqual(a: Map<string, Set<number>>, b: Map<string, Set<number>>): boolean {
  if (a.size !== b.size) return false;
  for (const [key, values] of a) {
    const other = b.get(key);
    if (!other || other.size !== values.size) return false;
    for (const value of values) if (!other.has(value)) return false;
  }
  return true;
}

function cloneDefs(input: Map<string, Set<number>>): Map<string, Set<number>> {
  return new Map(Array.from(input.entries()).map(([key, values]) => [key, new Set(values)]));
}

function mergeDefs(inputs: Array<Map<string, Set<number>>>): Map<string, Set<number>> {
  const merged = new Map<string, Set<number>>();
  for (const input of inputs) {
    for (const [key, values] of input) {
      const target = merged.get(key) ?? new Set<number>();
      for (const value of values) target.add(value);
      merged.set(key, target);
    }
  }
  return merged;
}

function successorsFor(nodes: DecompilerIrNode[], index: number, addressToIndex: Map<number, number>): number[] {
  const node = nodes[index];
  if (node.kind === 'return') return [];
  if (node.kind === 'conditional-branch') {
    const successors: number[] = [];
    if (node.target !== null && addressToIndex.has(node.target)) successors.push(addressToIndex.get(node.target)!);
    if (node.fallthrough !== undefined && addressToIndex.has(node.fallthrough)) successors.push(addressToIndex.get(node.fallthrough)!);
    else if (index + 1 < nodes.length) successors.push(index + 1);
    return Array.from(new Set(successors));
  }
  return index + 1 < nodes.length ? [index + 1] : [];
}

/** Reaching-definitions pass. Annotates each IR node with definitions reaching its uses. */
export function annotateReachingDefinitions(nodes: DecompilerIrNode[]): DecompilerIrNode[] {
  if (nodes.length === 0) return [];
  const addressToIndex = new Map(nodes.map((node, index) => [node.address, index]));
  const predecessors = new Map<number, number[]>();
  nodes.forEach((_, index) => predecessors.set(index, []));
  nodes.forEach((_, index) => {
    for (const successor of successorsFor(nodes, index, addressToIndex)) {
      predecessors.get(successor)?.push(index);
    }
  });

  const inDefs = nodes.map(() => new Map<string, Set<number>>());
  const outDefs = nodes.map(() => new Map<string, Set<number>>());
  let changed = true;
  while (changed) {
    changed = false;
    for (let index = 0; index < nodes.length; index += 1) {
      const predOuts = (predecessors.get(index) ?? []).map((pred) => outDefs[pred]);
      const nextIn = mergeDefs(predOuts);
      const nextOut = cloneDefs(nextIn);
      const def = nodeDefinition(nodes[index]);
      if (def) nextOut.set(def, new Set([nodes[index].address]));
      if (!mapsEqual(inDefs[index], nextIn) || !mapsEqual(outDefs[index], nextOut)) {
        inDefs[index] = nextIn;
        outDefs[index] = nextOut;
        changed = true;
      }
    }
  }

  return nodes.map((node, index) => {
    const reachingDefs: ReachingDefs = {};
    for (const use of nodeUses(node)) {
      const defs = Array.from(inDefs[index].get(use) ?? []).sort((a, b) => a - b);
      if (defs.length > 0) reachingDefs[use] = defs;
    }
    return Object.keys(reachingDefs).length > 0 ? { ...node, reachingDefs } : { ...node };
  });
}

/** Runs the mid-level IR tier in canonical order: fold → DSE → reaching definitions. */
export function runMidLevelIrPasses(nodes: DecompilerIrNode[]): DecompilerIrNode[] {
  return annotateReachingDefinitions(eliminateDeadStores(constantFoldDecompilerIr(nodes)));
}
