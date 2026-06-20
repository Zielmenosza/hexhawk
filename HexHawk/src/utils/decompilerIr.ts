import type { DisassembledInstruction } from './decompilerEngine';
import type { DecompilerIrNode, DecompilerIrValue } from './decompilerTypes';

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
    return [{ kind: 'call', address, target, name, args: [], confidence: target === null ? 'medium' : 'high', unresolved: target === null }];
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
