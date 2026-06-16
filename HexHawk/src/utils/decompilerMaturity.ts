import type { DisassembledInstruction } from './decompilerEngine';
import type { DecompilerIrNode, DecompilerMaturitySummary } from './decompilerTypes';

export type MaturityBlockLike = {
  id?: string;
  blockType?: string;
  stmts?: Array<{ op: string; target?: number | null; args?: unknown[] }>;
  successors?: string[];
  allSuccessors?: string[];
};

export type MaturityLineLike = {
  kind?: string;
  isUncertain?: boolean;
};

export type ComputeDecompilerMaturityInput = {
  instructions: DisassembledInstruction[];
  irNodes: DecompilerIrNode[];
  irBlocks?: MaturityBlockLike[];
  lines?: MaturityLineLike[];
  warnings?: string[];
  fallbackPartitioningUsed?: boolean;
};

function pct(part: number, total: number): number {
  if (total <= 0) return 0;
  return Math.round((part / total) * 100);
}

function uniqueVariableCount(nodes: DecompilerIrNode[]): number {
  const names = new Set<string>();
  for (const node of nodes) {
    if (node.kind === 'stack-variable-candidate') {
      if ('name' in node.variable) names.add(node.variable.name);
    }
    if (node.kind === 'register-variable-candidate') {
      if ('name' in node.variable) names.add(node.variable.name);
    }
  }
  return names.size;
}

function structuredPercentage(blocks: MaturityBlockLike[], lines: MaturityLineLike[]): number {
  if (blocks.length === 0) return 0;
  const structuredLines = lines.filter(line => line.kind === 'control' || line.kind === 'header' || line.kind === 'brace').length;
  if (structuredLines > 0 && blocks.length <= 1) return 100;
  const structuredBlocks = blocks.filter(block => block.blockType === 'entry' || block.blockType === 'exit' || block.blockType === 'body' || block.blockType === 'condition').length;
  if (structuredBlocks > 0) return pct(structuredBlocks, blocks.length);
  return structuredLines > 0 ? Math.max(1, pct(structuredLines, Math.max(lines.length, 1))) : 0;
}

function fallbackMode(args: {
  blockCount: number;
  structuredBlockPercentage: number;
  fallbackPartitioningUsed: boolean;
}): DecompilerMaturitySummary['fallbackMode'] {
  if (args.blockCount === 0) return 'instruction-fallback';
  if (args.fallbackPartitioningUsed) return 'block-level-fallback';
  if (args.structuredBlockPercentage >= 75) return 'structured';
  return 'partially-structured';
}

function confidence(args: {
  total: number;
  unknown: number;
  unresolvedCalls: number;
  unresolvedIndirectJumps: number;
  fallbackMode: DecompilerMaturitySummary['fallbackMode'];
}): DecompilerMaturitySummary['confidence'] {
  if (args.total === 0) return 'unknown';
  const unknownRatio = args.unknown / args.total;
  if (unknownRatio === 0 && args.unresolvedCalls === 0 && args.unresolvedIndirectJumps === 0 && args.fallbackMode === 'structured') return 'high';
  if (unknownRatio <= 0.2 && args.unresolvedIndirectJumps === 0 && args.fallbackMode !== 'instruction-fallback') return 'medium';
  return 'low';
}

export function computeDecompilerMaturitySummary(input: ComputeDecompilerMaturityInput): DecompilerMaturitySummary {
  const warnings = [...(input.warnings ?? [])];
  const unknownInstructionCount = input.irNodes.filter(node => node.kind === 'unknown').length;
  const callNodes = input.irNodes.filter((node): node is Extract<DecompilerIrNode, { kind: 'call' }> => node.kind === 'call');
  const recoveredCallsCount = callNodes.filter(node => !node.unresolved).length;
  const recoveredArgsCount = callNodes.reduce((count, node) => count + node.args.length, 0);
  const unresolvedCalls = callNodes.filter(node => node.unresolved).length;
  const unresolvedIndirectJumps = input.irNodes.filter(node => node.kind === 'unknown' && node.warning.toLowerCase().includes('indirect jump')).length;
  const structuredBlockPercentage = structuredPercentage(input.irBlocks ?? [], input.lines ?? []);
  const mode = fallbackMode({
    blockCount: input.irBlocks?.length ?? 0,
    structuredBlockPercentage,
    fallbackPartitioningUsed: input.fallbackPartitioningUsed ?? false,
  });
  const liftedInstructionCount = Math.max(0, input.instructions.length - unknownInstructionCount);

  if (unknownInstructionCount > 0) {
    warnings.push(`${unknownInstructionCount} instruction(s) were not lifted into explicit IR and remain visible as unknown nodes.`);
  }
  if (unresolvedCalls > 0) {
    warnings.push(`${unresolvedCalls} call site(s) have unresolved/non-address targets.`);
  }
  if (unresolvedIndirectJumps > 0) {
    warnings.push(`${unresolvedIndirectJumps} indirect jump(s) remain unresolved; CFG/decompiler structure is incomplete.`);
  }

  return {
    schema: 'hexhawk.decompiler_maturity.explicit_ir.v1',
    advisoryOnly: true,
    authority: 'talon_decompiler_advisory_not_gyre_verdict',
    liftedInstructionCount,
    unknownInstructionCount,
    recoveredCallsCount,
    recoveredArgsCount,
    recoveredVariablesCount: uniqueVariableCount(input.irNodes),
    unresolvedIndirectJumps,
    unresolvedCalls,
    structuredBlockPercentage,
    fallbackMode: mode,
    confidence: confidence({
      total: input.instructions.length,
      unknown: unknownInstructionCount,
      unresolvedCalls,
      unresolvedIndirectJumps,
      fallbackMode: mode,
    }),
    warnings: Array.from(new Set(warnings)),
    proofLimits: [
      'Decompiler maturity is advisory only and does not change GYRE final decisions, malware-family labels, engine markers, or authority markers.',
      'Pseudo-C is a readable analyst aid, not recovered source truth.',
      'Unknown and weakly lifted instructions must remain reviewable as warnings/comments.',
      'Structured-block percentage is a maturity signal, not proof that control flow was fully recovered.',
    ],
  };
}
