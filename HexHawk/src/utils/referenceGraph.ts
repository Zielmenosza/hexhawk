import type { ConfidenceLevel, ProgramAnalysis, XRef, XRefKind } from './disassemblyModel';

export type ReferenceGraphNodeType =
  | 'function'
  | 'import'
  | 'string'
  | 'basic-block'
  | 'address'
  | 'selected-address'
  | 'constant';

export type ReferenceGraphEdgeKind =
  | 'calls'
  | 'jumps'
  | 'conditional-jumps'
  | 'fallthrough'
  | 'references-data'
  | 'references-string'
  | 'references-import'
  | 'contains-block'
  | 'contains-address'
  | 'uses-constant'
  | 'selected-within-function'
  | 'selected-within-block'
  | 'unknown-reference';

export interface ReferenceGraphNode {
  id: string;
  type: ReferenceGraphNodeType;
  label: string;
  address?: number;
  value?: string;
  confidence: ConfidenceLevel;
  evidence: string;
}

export interface ReferenceGraphEdge {
  id: string;
  from: string;
  to: string;
  kind: ReferenceGraphEdgeKind;
  confidence: ConfidenceLevel;
  evidence: string;
}

export interface ReferenceGraphSummary {
  functions: number;
  imports: number;
  strings: number;
  basic_blocks: number;
  data_references: number;
  constants: number;
  selected_addresses: number;
  nodes: number;
  edges: number;
}

export interface ReferenceGraphLimits {
  nodeBudget: number;
  edgeBudget: number;
  omittedNodes: number;
  omittedEdges: number;
  truncated: boolean;
}

export interface ReferenceGraph {
  schema: 'hexhawk.reference_graph.v1';
  advisory_only: true;
  authority: 'reference_graph_not_gyre_verdict';
  generated_at: string;
  summary: ReferenceGraphSummary;
  limits: ReferenceGraphLimits;
  nodes: ReferenceGraphNode[];
  edges: ReferenceGraphEdge[];
  proof_limits: string[];
}

export interface BuildReferenceGraphOptions {
  selectedAddresses?: number[];
  nodeBudget?: number;
  edgeBudget?: number;
  generatedAt?: string;
}

const DEFAULT_NODE_BUDGET = 512;
const DEFAULT_EDGE_BUDGET = 1024;
const MAX_CONSTANTS = 96;

function hex(address: number): string {
  return `0x${address.toString(16).toUpperCase()}`;
}

function nodeId(type: ReferenceGraphNodeType, addressOrValue: number | string): string {
  return `${type}:${typeof addressOrValue === 'number' ? addressOrValue.toString(16) : addressOrValue}`;
}

function edgeId(kind: ReferenceGraphEdgeKind, from: string, to: string, evidence: string): string {
  return `${kind}:${from}->${to}:${evidence.slice(0, 40)}`;
}

function findFunction(program: ProgramAnalysis, address: number) {
  return program.functions.find(fn => address >= fn.startAddress && address <= fn.endAddress);
}

function findBlock(program: ProgramAnalysis, address: number) {
  return program.basicBlocks.find(block => address >= block.startAddress && address <= block.endAddress);
}

function mapXRefKind(kind: XRefKind): ReferenceGraphEdgeKind {
  switch (kind) {
    case 'call': return 'calls';
    case 'jump': return 'jumps';
    case 'conditional-jump': return 'conditional-jumps';
    case 'fallthrough': return 'fallthrough';
    case 'string': return 'references-string';
    case 'import': return 'references-import';
    case 'data': return 'references-data';
    default: return 'unknown-reference';
  }
}

function extractConstants(operands: string): number[] {
  const constants = new Set<number>();
  for (const match of operands.matchAll(/\b0x[0-9a-fA-F]+\b/g)) {
    const value = Number.parseInt(match[0].slice(2), 16);
    if (Number.isFinite(value) && value > 9) constants.add(value);
  }
  for (const match of operands.matchAll(/(?<![\w.])-?\b\d{2,}\b/g)) {
    const value = Number.parseInt(match[0], 10);
    if (Number.isFinite(value)) constants.add(value);
  }
  return Array.from(constants);
}

export function buildReferenceGraph(program: ProgramAnalysis, options: BuildReferenceGraphOptions = {}): ReferenceGraph {
  const nodeBudget = Math.max(1, options.nodeBudget ?? DEFAULT_NODE_BUDGET);
  const edgeBudget = Math.max(1, options.edgeBudget ?? DEFAULT_EDGE_BUDGET);
  const selectedAddresses = Array.from(new Set(options.selectedAddresses ?? [])).filter(Number.isFinite);
  const nodes = new Map<string, ReferenceGraphNode>();
  const edges = new Map<string, ReferenceGraphEdge>();
  let omittedNodes = 0;
  let omittedEdges = 0;

  function addNode(node: ReferenceGraphNode): string {
    if (nodes.has(node.id)) return node.id;
    if (nodes.size >= nodeBudget) {
      omittedNodes += 1;
      return node.id;
    }
    nodes.set(node.id, node);
    return node.id;
  }

  function addEdge(edge: ReferenceGraphEdge): void {
    if (edges.has(edge.id)) return;
    if (edges.size >= edgeBudget) {
      omittedEdges += 1;
      return;
    }
    if (!nodes.has(edge.from) || !nodes.has(edge.to)) return;
    edges.set(edge.id, edge);
  }

  for (const fn of program.functions) {
    addNode({
      id: nodeId('function', fn.startAddress),
      type: 'function',
      label: fn.name || `Function ${hex(fn.startAddress)}`,
      address: fn.startAddress,
      confidence: fn.confidence,
      evidence: `${fn.startSource}; ${fn.startReasons.join(', ') || 'function boundary heuristic'}`,
    });
  }

  for (const block of program.basicBlocks) {
    const blockNode = addNode({
      id: nodeId('basic-block', block.startAddress),
      type: 'basic-block',
      label: `Block ${hex(block.startAddress)}-${hex(block.endAddress)}`,
      address: block.startAddress,
      confidence: block.confidence,
      evidence: `basic block ${block.id}`,
    });
    const fn = findFunction(program, block.startAddress);
    if (fn) {
      const fnNode = nodeId('function', fn.startAddress);
      addEdge({
        id: edgeId('contains-block', fnNode, blockNode, block.id),
        from: fnNode,
        to: blockNode,
        kind: 'contains-block',
        confidence: block.confidence,
        evidence: `function contains basic block ${block.id}`,
      });
    }
  }

  for (const importCall of program.importCalls) {
    const address = importCall.targetAddress ?? importCall.callAddress;
    const importNode = addNode({
      id: nodeId('import', `${importCall.moduleName ?? 'unknown'}:${importCall.importName ?? address.toString(16)}`),
      type: 'import',
      label: importCall.moduleName ? `${importCall.moduleName}!${importCall.importName ?? hex(address)}` : importCall.importName ?? hex(address),
      address,
      confidence: importCall.confidence,
      evidence: importCall.evidence,
    });
    const caller = findFunction(program, importCall.callAddress);
    if (caller) {
      const callerNode = nodeId('function', caller.startAddress);
      addEdge({
        id: edgeId('references-import', callerNode, importNode, `${importCall.callAddress}`),
        from: callerNode,
        to: importNode,
        kind: 'references-import',
        confidence: importCall.confidence,
        evidence: `${importCall.importName ?? 'import'} at call site ${hex(importCall.callAddress)}`,
      });
    }
  }

  for (const str of program.stringReferences) {
    const stringNode = addNode({
      id: nodeId('string', str.to),
      type: 'string',
      label: str.value ? `"${str.value.slice(0, 64)}"` : `String ${hex(str.to)}`,
      address: str.to,
      value: str.value,
      confidence: str.confidence,
      evidence: str.evidence,
    });
    const owner = findFunction(program, str.from);
    const sourceNode = owner ? nodeId('function', owner.startAddress) : nodeId('address', str.from);
    if (!owner) {
      addNode({ id: sourceNode, type: 'address', label: hex(str.from), address: str.from, confidence: str.confidence, evidence: 'string xref source address' });
    }
    addEdge({
      id: edgeId('references-string', sourceNode, stringNode, `${str.from}:${str.to}`),
      from: sourceNode,
      to: stringNode,
      kind: 'references-string',
      confidence: str.confidence,
      evidence: `${str.evidence} from ${hex(str.from)}`,
    });
  }

  for (const dataRef of program.dataReferences) {
    const dataNode = addNode({
      id: nodeId('address', dataRef.to),
      type: 'address',
      label: `Data ${hex(dataRef.to)}`,
      address: dataRef.to,
      confidence: dataRef.confidence,
      evidence: dataRef.evidence,
    });
    const owner = findFunction(program, dataRef.from);
    const sourceNode = owner ? nodeId('function', owner.startAddress) : nodeId('address', dataRef.from);
    if (!owner) addNode({ id: sourceNode, type: 'address', label: hex(dataRef.from), address: dataRef.from, confidence: dataRef.confidence, evidence: 'data xref source address' });
    addEdge({
      id: edgeId('references-data', sourceNode, dataNode, `${dataRef.from}:${dataRef.to}`),
      from: sourceNode,
      to: dataNode,
      kind: 'references-data',
      confidence: dataRef.confidence,
      evidence: `${dataRef.access} data reference from ${hex(dataRef.from)}; ${dataRef.evidence}`,
    });
  }

  for (const xref of program.xrefs) {
    const sourceFn = findFunction(program, xref.from);
    const targetFn = findFunction(program, xref.to);
    const importCall = program.importCalls.find(entry => entry.callAddress === xref.from || entry.targetAddress === xref.to);
    const sourceNode = sourceFn ? nodeId('function', sourceFn.startAddress) : nodeId('address', xref.from);
    const targetNode = targetFn ? nodeId('function', targetFn.startAddress) : nodeId('address', xref.to);
    if (!sourceFn) addNode({ id: sourceNode, type: 'address', label: hex(xref.from), address: xref.from, confidence: xref.confidence, evidence: 'xref source address' });
    if (!targetFn) addNode({ id: targetNode, type: 'address', label: hex(xref.to), address: xref.to, confidence: xref.confidence, evidence: 'xref target address' });
    addEdge({
      id: edgeId(mapXRefKind(xref.kind), sourceNode, targetNode, xref.evidence),
      from: sourceNode,
      to: targetNode,
      kind: mapXRefKind(xref.kind),
      confidence: xref.confidence,
      evidence: importCall?.importName ? `${xref.evidence}; ${importCall.importName}` : xref.evidence,
    });
  }

  let constantsAdded = 0;
  for (const instruction of program.instructions) {
    if (constantsAdded >= MAX_CONSTANTS) break;
    const owner = findFunction(program, instruction.address);
    if (!owner) continue;
    const sourceNode = nodeId('function', owner.startAddress);
    for (const constant of extractConstants(instruction.operands)) {
      if (constantsAdded >= MAX_CONSTANTS) break;
      const constantNode = addNode({
        id: nodeId('constant', constant),
        type: 'constant',
        label: constant < 0 ? String(constant) : hex(constant),
        value: String(constant),
        confidence: 'low',
        evidence: `immediate operand at ${hex(instruction.address)}`,
      });
      if (nodes.has(constantNode)) constantsAdded += 1;
      addEdge({
        id: edgeId('uses-constant', sourceNode, constantNode, `${instruction.address}:${constant}`),
        from: sourceNode,
        to: constantNode,
        kind: 'uses-constant',
        confidence: 'low',
        evidence: `${instruction.mnemonic} ${instruction.operands} at ${hex(instruction.address)}`,
      });
    }
  }

  for (const address of selectedAddresses) {
    const selectedNode = addNode({
      id: nodeId('selected-address', address),
      type: 'selected-address',
      label: `Selected ${hex(address)}`,
      address,
      confidence: 'high',
      evidence: 'analyst-selected pivot address',
    });
    const fn = findFunction(program, address);
    if (fn) {
      const fnNode = nodeId('function', fn.startAddress);
      addEdge({
        id: edgeId('selected-within-function', selectedNode, fnNode, String(address)),
        from: selectedNode,
        to: fnNode,
        kind: 'selected-within-function',
        confidence: 'high',
        evidence: `${hex(address)} is within function ${fn.name}`,
      });
    }
    const block = findBlock(program, address);
    if (block) {
      const blockNode = nodeId('basic-block', block.startAddress);
      addEdge({
        id: edgeId('selected-within-block', selectedNode, blockNode, String(address)),
        from: selectedNode,
        to: blockNode,
        kind: 'selected-within-block',
        confidence: block.confidence,
        evidence: `${hex(address)} is within basic block ${block.id}`,
      });
    }
  }

  const nodeList = Array.from(nodes.values());
  const edgeList = Array.from(edges.values());
  return {
    schema: 'hexhawk.reference_graph.v1',
    advisory_only: true,
    authority: 'reference_graph_not_gyre_verdict',
    generated_at: options.generatedAt ?? new Date().toISOString(),
    summary: {
      functions: nodeList.filter(node => node.type === 'function').length,
      imports: nodeList.filter(node => node.type === 'import').length,
      strings: nodeList.filter(node => node.type === 'string').length,
      basic_blocks: nodeList.filter(node => node.type === 'basic-block').length,
      data_references: edgeList.filter(edge => edge.kind === 'references-data').length,
      constants: nodeList.filter(node => node.type === 'constant').length,
      selected_addresses: nodeList.filter(node => node.type === 'selected-address').length,
      nodes: nodeList.length,
      edges: edgeList.length,
    },
    limits: {
      nodeBudget,
      edgeBudget,
      omittedNodes,
      omittedEdges,
      truncated: omittedNodes > 0 || omittedEdges > 0,
    },
    nodes: nodeList,
    edges: edgeList,
    proof_limits: [
      'Reference graphs are advisory static-analysis evidence and do not prove verdict correctness.',
      'Edges are derived from decoded instructions, imports, strings, CFG blocks, and selected addresses within declared node/edge budgets.',
      'Indirect calls, unresolved jumps, dynamic behavior, packed code, and truncated graphs require analyst review.',
      'GYRE remains sole verdict authority; this graph must not change verdict fields or base confidence by itself.',
    ],
  };
}

export function exportReferenceGraphJson(graph: ReferenceGraph): string {
  return JSON.stringify(graph, null, 2);
}

export function formatReferenceGraphMarkdown(graph: ReferenceGraph): string {
  const lines: string[] = [];
  lines.push('## Reference Graph');
  lines.push('');
  lines.push('Advisory static-analysis graph connecting functions, imports, strings, blocks, data references, constants, and analyst-selected addresses.');
  lines.push('');
  lines.push('| Metric | Count |');
  lines.push('|--------|------:|');
  lines.push(`| Functions | ${graph.summary.functions} |`);
  lines.push(`| Imports | ${graph.summary.imports} |`);
  lines.push(`| Strings | ${graph.summary.strings} |`);
  lines.push(`| Basic blocks | ${graph.summary.basic_blocks} |`);
  lines.push(`| Data references | ${graph.summary.data_references} |`);
  lines.push(`| Constants | ${graph.summary.constants} |`);
  lines.push(`| Selected addresses | ${graph.summary.selected_addresses} |`);
  lines.push(`| Nodes | ${graph.summary.nodes} |`);
  lines.push(`| Edges | ${graph.summary.edges} |`);
  lines.push('');
  lines.push('| Limit | Value |');
  lines.push('|-------|------:|');
  lines.push(`| Node budget | ${graph.limits.nodeBudget} |`);
  lines.push(`| Edge budget | ${graph.limits.edgeBudget} |`);
  lines.push(`| Omitted nodes | ${graph.limits.omittedNodes} |`);
  lines.push(`| Omitted edges | ${graph.limits.omittedEdges} |`);
  lines.push(`| Truncated | ${graph.limits.truncated ? 'yes' : 'no'} |`);
  lines.push('');
  lines.push('Proof limits:');
  for (const limit of graph.proof_limits) lines.push(`- ${limit}`);
  lines.push('');
  return lines.join('\n');
}
