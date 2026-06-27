import type { DebugSnapshot } from '../components/DebuggerPanel';
import type { DecompileResult, IRStmt } from './decompilerEngine';
import type { FunctionModel, ImportCall, ProgramAnalysis, XRef } from './disassemblyModel';
import { resolveConstantAnnotation } from './importPrototypes';

export type ProgramAnalysisFunction = FunctionModel;

export interface FunctionIntelligenceSource {
  hasImportTableEntry: boolean;
  hasXRefIndex: boolean;
  hasBoundaryHeuristic: boolean;
  hasConstantAnnotation: boolean;
  hasDecompilerOutput: boolean;
  hasDebuggerCallStack: boolean;
  hasConditionalBreakpointHit: boolean;
  hasCallingConvention: boolean;
}

export interface FunctionIntelligenceLimit {
  kind:
    | 'unresolved-call-target'
    | 'inferred-boundary'
    | 'unproven-call-convention'
    | 'unresolved-thunk'
    | 'no-debugger-observation'
    | 'partial-decompile'
    | 'ordinal-only-import'
    | 'indirect-call'
    | 'architecture-limit';
  address?: number;
  detail: string;
}

export interface FunctionCallEdge {
  targetAddress: number;
  targetName?: string;
  importName?: string;
  moduleName?: string;
  constantAnnotations?: string[];
  evidenceBasis: 'static-only' | 'import-table-proven' | 'debugger-observed' | 'static-and-observed';
}

export interface ConditionalBreakpointHit {
  address: number;
  condition: string;
  hitCount: number;
}

export interface FunctionDebugCorrelation {
  functionId: string;
  observedInCallStack: boolean;
  callStackDepth?: number;
  conditionalBreakpointHits: ConditionalBreakpointHit[];
  correlationBasis: 'address-range-match' | 'symbol-name-match' | 'import-stub-match' | 'no-correlation';
}

export interface FunctionIntelligence {
  id: string;
  address: number;
  endAddress: number;
  name: string;
  nameSource: 'symbol' | 'import-table' | 'heuristic' | 'generated';

  callingConvention?: {
    abi: 'windows-x64' | 'sysv-amd64' | 'cdecl' | 'stdcall' | 'unknown';
    analysisConfidence: 'high' | 'medium' | 'low';
    evidence: string;
  };
  instructionCount: number;
  boundarySource: 'call-target' | 'prologue-pattern' | 'jump-table-target' | 'alignment-gap' | 'import-stub';

  callers: FunctionCallEdge[];
  callees: FunctionCallEdge[];
  xrefCount: number;

  importCalls: {
    importName: string;
    moduleName?: string;
    callAddress: number;
    constantAnnotations: string[];
  }[];

  pseudocode?: string;
  pseudocodeAnnotated?: string;

  debuggerCallStack?: {
    observedAt: number;
    frames: { returnAddress: number; symbolName?: string; moduleName?: string }[];
  }[];
  conditionalBreakpointHits?: {
    address: number;
    condition: string;
    hitCount: number;
  }[];

  debugCorrelation?: FunctionDebugCorrelation;
  sources: FunctionIntelligenceSource;
  limits: FunctionIntelligenceLimit[];

  gyre_is_sole_verdict_authority: true;
  advisory_analysis_only: true;
}

function formatFunctionId(address: number): string {
  return `function_${address.toString(16)}`;
}

function containsAddress(fn: ProgramAnalysisFunction, address: number): boolean {
  return address >= fn.startAddress && address <= fn.endAddress;
}

function functionForAddress(analysis: ProgramAnalysis, address: number): ProgramAnalysisFunction | undefined {
  return analysis.functions.find(candidate => containsAddress(candidate, address));
}

function importForTarget(analysis: ProgramAnalysis, targetAddress: number | undefined): ImportCall | undefined {
  if (typeof targetAddress !== 'number') return undefined;
  return analysis.importCalls.find(entry => entry.targetAddress === targetAddress || entry.callAddress === targetAddress);
}

function importForCallsite(analysis: ProgramAnalysis, callAddress: number): ImportCall | undefined {
  return analysis.importCalls.find(entry => entry.callAddress === callAddress);
}

function breakpointHitsForFunction(fn: ProgramAnalysisFunction, snapshot?: DebugSnapshot): ConditionalBreakpointHit[] {
  return (snapshot?.breakpoints ?? [])
    .filter((bp): bp is Exclude<DebugSnapshot['breakpoints'][number], number> => typeof bp !== 'number')
    .filter(bp => Boolean(bp.condition) && bp.hitCount > 0 && containsAddress(fn, bp.address))
    .map(bp => ({ address: bp.address, condition: bp.condition ?? '', hitCount: bp.hitCount }));
}

export function correlateDebuggerToFunctions(
  analysis: ProgramAnalysis,
  snapshot: DebugSnapshot,
): Map<string, FunctionDebugCorrelation> {
  const correlations = new Map<string, FunctionDebugCorrelation>();
  for (const fn of analysis.functions) {
    const frames = snapshot.callStack ?? [];
    const symbolDepth = frames.findIndex(frame => frame.symbolName === fn.name);
    const addressDepth = frames.findIndex(frame => containsAddress(fn, frame.returnAddress));
    const importThunkAddresses = new Set(analysis.importCalls
      .filter(entry => entry.targetAddress === fn.startAddress || entry.callAddress === fn.startAddress || entry.importName === fn.name)
      .flatMap(entry => [entry.targetAddress, entry.callAddress])
      .filter((address): address is number => typeof address === 'number'));
    const importDepth = importThunkAddresses.size > 0
      ? frames.findIndex(frame => importThunkAddresses.has(frame.returnAddress))
      : -1;
    const callStackDepth = symbolDepth >= 0 ? symbolDepth : addressDepth >= 0 ? addressDepth : importDepth >= 0 ? importDepth : undefined;
    const correlationBasis: FunctionDebugCorrelation['correlationBasis'] = symbolDepth >= 0
      ? 'symbol-name-match'
      : addressDepth >= 0
        ? 'address-range-match'
        : importDepth >= 0
          ? 'import-stub-match'
          : 'no-correlation';
    correlations.set(fn.id || formatFunctionId(fn.startAddress), {
      functionId: fn.id || formatFunctionId(fn.startAddress),
      observedInCallStack: callStackDepth !== undefined,
      callStackDepth,
      conditionalBreakpointHits: breakpointHitsForFunction(fn, snapshot),
      correlationBasis,
    });
  }
  return correlations;
}

function nameSourceFor(fn: ProgramAnalysisFunction, analysis: ProgramAnalysis): FunctionIntelligence['nameSource'] {
  if (analysis.importCalls.some(entry => entry.targetAddress === fn.startAddress || entry.callAddress === fn.startAddress)) return 'import-table';
  if (fn.startReasons.includes('symbol') || fn.startReasons.includes('export')) return 'symbol';
  if (fn.startReasons.some(reason => reason === 'prologue' || reason === 'prologue-pattern' || reason === 'call-target' || reason === 'known-call-target')) return 'heuristic';
  return 'generated';
}

type FunctionIntelligenceCallingConvention = NonNullable<FunctionIntelligence['callingConvention']>;

function boundarySourceFor(fn: ProgramAnalysisFunction, analysis: ProgramAnalysis): FunctionIntelligence['boundarySource'] {
  if (analysis.importCalls.some(entry => entry.targetAddress === fn.startAddress || entry.callAddress === fn.startAddress)) return 'import-stub';
  if (fn.startSource === 'call-target') return 'call-target';
  if (fn.startSource === 'prologue-pattern') return 'prologue-pattern';
  if (fn.startSource === 'jump-table-target') return 'jump-table-target';
  return 'alignment-gap';
}

function normalizeAbi(name: string): FunctionIntelligenceCallingConvention['abi'] {
  if (name === 'sysv-x64' || name === 'sysv-amd64') return 'sysv-amd64';
  if (name === 'windows-x64' || name === 'cdecl' || name === 'stdcall') return name;
  if (name === 'arm64-unknown') return 'unknown';
  return 'unknown';
}

function renderPseudocode(result: DecompileResult | undefined, annotated: boolean): string | undefined {
  if (!result) return undefined;
  return result.lines
    .filter(line => annotated || line.kind !== 'comment')
    .map(line => `${'  '.repeat(Math.max(0, line.indent))}${line.text}`)
    .join('\n')
    .trimEnd();
}

function collectIrStatements(result: DecompileResult | undefined): IRStmt[] {
  return result?.irBlocks.flatMap(block => block.stmts) ?? [];
}

function constantAnnotationsForImport(importCall: ImportCall, result?: DecompileResult): string[] {
  const importName = importCall.importName;
  if (!importName) return [];
  const annotations = new Set<string>();
  for (const stmt of collectIrStatements(result)) {
    if (stmt.op !== 'call' || stmt.address !== importCall.callAddress) continue;
    for (const [index, arg] of (stmt.args ?? []).entries()) {
      if (arg.kind !== 'const') continue;
      const annotation = resolveConstantAnnotation(importName, index, arg.value);
      if (annotation) annotations.add(annotation);
    }
  }
  return Array.from(annotations);
}

function edgeForXRef(xref: XRef, analysis: ProgramAnalysis, decompileResult: DecompileResult | undefined, observedAddresses: Set<number>): FunctionCallEdge {
  const importCall = importForTarget(analysis, xref.to) ?? importForCallsite(analysis, xref.from);
  const targetFn = functionForAddress(analysis, xref.to);
  const importProven = Boolean(importCall?.importName);
  const debuggerObserved = observedAddresses.has(xref.to) || (targetFn ? observedAddresses.has(targetFn.startAddress) : false);
  return {
    targetAddress: targetFn?.startAddress ?? importCall?.targetAddress ?? xref.to,
    targetName: targetFn?.name ?? importCall?.importName,
    importName: importCall?.importName,
    moduleName: importCall?.moduleName,
    constantAnnotations: importCall ? constantAnnotationsForImport(importCall, decompileResult) : [],
    evidenceBasis: importProven && debuggerObserved
      ? 'static-and-observed'
      : importProven
        ? 'import-table-proven'
        : debuggerObserved
          ? 'debugger-observed'
          : 'static-only',
  };
}

function appendDebuggerObservedCallees(
  existing: FunctionCallEdge[],
  fn: ProgramAnalysisFunction,
  analysis: ProgramAnalysis,
  debugSnapshot: DebugSnapshot | undefined,
): FunctionCallEdge[] {
  if (!debugSnapshot?.callStack?.length) return existing;
  const seen = new Set(existing.map(edge => edge.targetAddress));
  const appended: FunctionCallEdge[] = [];
  for (const frame of debugSnapshot.callStack) {
    const observed = functionForAddress(analysis, frame.returnAddress)
      ?? analysis.functions.find(candidate => frame.symbolName === candidate.name);
    if (!observed || observed.startAddress === fn.startAddress || seen.has(observed.startAddress)) continue;
    const hasStaticXref = analysis.xrefs.some(ref => ref.kind === 'call' && containsAddress(fn, ref.from) && containsAddress(observed, ref.to));
    if (hasStaticXref) continue;
    seen.add(observed.startAddress);
    appended.push({
      targetAddress: observed.startAddress,
      targetName: observed.name,
      evidenceBasis: 'debugger-observed',
    });
  }
  return appended.length ? [...existing, ...appended] : existing;
}

function observedFunctionAddresses(snapshot: DebugSnapshot | undefined, analysis: ProgramAnalysis): Set<number> {
  const observed = new Set<number>();
  if (snapshot) {
    for (const [functionId, correlation] of correlateDebuggerToFunctions(analysis, snapshot)) {
      if (!correlation.observedInCallStack) continue;
      const fn = analysis.functions.find(candidate => (candidate.id || formatFunctionId(candidate.startAddress)) === functionId);
      if (fn) observed.add(fn.startAddress);
    }
  }
  for (const frame of snapshot?.callStack ?? []) {
    const fn = functionForAddress(analysis, frame.returnAddress);
    if (fn) observed.add(fn.startAddress);
    observed.add(frame.returnAddress);
  }
  if (snapshot?.registers?.rip !== undefined) {
    const ripFn = functionForAddress(analysis, snapshot.registers.rip);
    if (ripFn) observed.add(ripFn.startAddress);
  }
  return observed;
}

function debuggerStacksForFunction(fn: ProgramAnalysisFunction, snapshot?: DebugSnapshot): FunctionIntelligence['debuggerCallStack'] {
  if (!snapshot?.callStack?.length) return undefined;
  const observedAt = snapshot.registers?.rip ?? fn.startAddress;
  const matched = snapshot.callStack.some(frame => containsAddress(fn, frame.returnAddress) || frame.symbolName === fn.name) || containsAddress(fn, observedAt);
  if (!matched) return undefined;
  return [{
    observedAt,
    frames: snapshot.callStack.map(frame => ({
      returnAddress: frame.returnAddress,
      symbolName: frame.symbolName ?? undefined,
      moduleName: frame.moduleName ?? undefined,
    })),
  }];
}

function conditionalHits(snapshot?: DebugSnapshot): FunctionIntelligence['conditionalBreakpointHits'] {
  const hits = (snapshot?.breakpoints ?? [])
    .filter(bp => typeof bp !== 'number' && bp.condition && bp.hitCount > 0)
    .map(bp => {
      const info = bp as Exclude<DebugSnapshot['breakpoints'][number], number>;
      return { address: info.address, condition: info.condition ?? '', hitCount: info.hitCount };
    });
  return hits.length ? hits : undefined;
}

function buildLimits(fn: ProgramAnalysisFunction, analysis: ProgramAnalysis, decompileResult?: DecompileResult, debugSnapshot?: DebugSnapshot): FunctionIntelligenceLimit[] {
  const limits: FunctionIntelligenceLimit[] = [];
  if (fn.startSource === 'prologue-pattern' || fn.startSource === 'alignment-gap' || fn.confidence === 'low' || fn.confidence === 'unknown') {
    limits.push({ kind: 'inferred-boundary', address: fn.startAddress, detail: `Function boundary was inferred from ${fn.startSource} evidence.` });
  }
  if (analysis.arch === 'arm64') {
    limits.push({ kind: 'architecture-limit', address: fn.startAddress, detail: 'ARM64 architecture detected. Disassembly available. Import resolution and calling-convention inference are limited for ARM64 in this release.' });
  }
  if (!fn.callingConvention || fn.callingConvention.name === 'unknown' || fn.callingConvention.name === 'arm64-unknown' || fn.callingConvention.confidence === 'low') {
    limits.push({ kind: 'unproven-call-convention', address: fn.startAddress, detail: fn.callingConvention?.source === 'arm64-limited' ? 'ARM64 — calling convention inference not yet implemented.' : 'Calling convention is not fully proven by current static evidence.' });
  }
  for (const warning of fn.warnings) {
    if (warning.kind === 'indirect-call') limits.push({ kind: 'indirect-call', address: warning.address, detail: warning.message });
    if (warning.kind === 'unresolved-target') limits.push({ kind: 'unresolved-call-target', address: warning.address, detail: warning.message });
  }
  for (const instruction of fn.instructions) {
    if (/^callq?$/i.test(instruction.mnemonic.trim()) && !/\b0x[0-9a-f]+\b/i.test(instruction.operands) && !/^\d+$/.test(instruction.operands.trim())) {
      limits.push({ kind: 'indirect-call', address: instruction.address, detail: `Indirect call target '${instruction.operands}' could not be resolved to a known function or import.` });
    }
  }
  for (const importCall of analysis.importCalls.filter(entry => containsAddress(fn, entry.callAddress))) {
    if (importCall.importName?.startsWith('ordinal_')) {
      limits.push({ kind: 'ordinal-only-import', address: importCall.callAddress, detail: `${importCall.moduleName ?? 'module'} import is ordinal-only and has no symbolic API name.` });
    }
    if (!importCall.importName) {
      limits.push({ kind: 'unresolved-thunk', address: importCall.callAddress, detail: 'Import thunk was detected without a resolved import name.' });
    }
  }
  if (decompileResult?.warnings.length) {
    limits.push(...decompileResult.warnings.map(detail => ({ kind: 'partial-decompile' as const, address: decompileResult.startAddress, detail })));
  }
  if (!debugSnapshot?.callStack?.length) {
    limits.push({ kind: 'no-debugger-observation', address: fn.startAddress, detail: 'No debugger call-stack observation is attached to this function.' });
  }
  return limits;
}

export function buildFunctionIntelligence(
  fn: ProgramAnalysisFunction,
  analysis: ProgramAnalysis,
  decompileResult?: DecompileResult,
  debugSnapshot?: DebugSnapshot,
): FunctionIntelligence {
  const debugCorrelation = debugSnapshot ? correlateDebuggerToFunctions(analysis, debugSnapshot).get(fn.id || formatFunctionId(fn.startAddress)) : undefined;
  const observedAddresses = observedFunctionAddresses(debugSnapshot, analysis);
  const incoming = analysis.xrefs.filter(ref => ref.kind === 'call' && containsAddress(fn, ref.to));
  const outgoing = analysis.xrefs.filter(ref => ref.kind === 'call' && containsAddress(fn, ref.from));
  const importCalls = analysis.importCalls
    .filter(entry => containsAddress(fn, entry.callAddress))
    .map(entry => ({
      importName: entry.importName ?? '<unknown import>',
      moduleName: entry.moduleName,
      callAddress: entry.callAddress,
      constantAnnotations: constantAnnotationsForImport(entry, decompileResult),
    }));
  const debuggerCallStack = debugCorrelation?.observedInCallStack ? debuggerStacksForFunction(fn, debugSnapshot) : undefined;
  const conditionalBreakpointHits = debugCorrelation?.conditionalBreakpointHits.length ? debugCorrelation.conditionalBreakpointHits : conditionalHits(debugSnapshot);
  const hasBoundaryHeuristic = fn.startSource === 'prologue-pattern' || fn.startSource === 'alignment-gap' || fn.startSource === 'jump-table-target';
  const hasConstantAnnotation = importCalls.some(entry => entry.constantAnnotations.length > 0);
  const compactPseudocode = renderPseudocode(decompileResult, false);
  const annotatedPseudocode = renderPseudocode(decompileResult, true);

  return {
    id: fn.id || formatFunctionId(fn.startAddress),
    address: fn.startAddress,
    endAddress: fn.endAddress,
    name: fn.name || `sub_${fn.startAddress.toString(16)}`,
    nameSource: nameSourceFor(fn, analysis),
    callingConvention: fn.callingConvention ? {
      abi: normalizeAbi(fn.callingConvention.name),
      analysisConfidence: fn.callingConvention.confidence,
      evidence: fn.callingConvention.evidence.join('; '),
    } : undefined,
    instructionCount: fn.instructions.length,
    boundarySource: boundarySourceFor(fn, analysis),
    callers: incoming.map(ref => edgeForXRef(ref, analysis, decompileResult, observedAddresses)),
    callees: appendDebuggerObservedCallees(outgoing.map(ref => edgeForXRef(ref, analysis, decompileResult, observedAddresses)), fn, analysis, debugSnapshot),
    xrefCount: analysis.xrefs.filter(ref => containsAddress(fn, ref.from) || containsAddress(fn, ref.to)).length,
    importCalls,
    pseudocode: compactPseudocode || undefined,
    pseudocodeAnnotated: annotatedPseudocode || undefined,
    debuggerCallStack,
    conditionalBreakpointHits,
    debugCorrelation,
    sources: {
      hasImportTableEntry: importCalls.length > 0 || analysis.importCalls.some(entry => entry.targetAddress === fn.startAddress || entry.callAddress === fn.startAddress),
      hasXRefIndex: analysis.xrefs.length > 0,
      hasBoundaryHeuristic,
      hasConstantAnnotation,
      hasDecompilerOutput: Boolean(decompileResult),
      hasDebuggerCallStack: Boolean(debuggerCallStack?.length),
      hasConditionalBreakpointHit: Boolean(conditionalBreakpointHits?.length),
      hasCallingConvention: Boolean(fn.callingConvention && fn.callingConvention.name !== 'unknown'),
    },
    limits: buildLimits(fn, analysis, decompileResult, debugSnapshot),
    gyre_is_sole_verdict_authority: true,
    advisory_analysis_only: true,
  };
}


function formatHex(address: number): string {
  return `0x${address.toString(16).toUpperCase()}`;
}

function markdownEdgeRows(edges: FunctionCallEdge[]): string[] {
  if (edges.length === 0) return ['| None observed | None observed | None observed |'];
  return edges.map(edge => `| ${formatHex(edge.targetAddress)} | ${edge.targetName ?? edge.importName ?? 'Unknown'} | ${edge.evidenceBasis} |`);
}

function markdownImportRows(importCalls: FunctionIntelligence['importCalls']): string[] {
  if (importCalls.length === 0) return ['| None observed | None observed | None observed | None observed |'];
  return importCalls.map(entry => `| ${entry.importName} | ${entry.moduleName ?? 'Unknown'} | ${formatHex(entry.callAddress)} | ${entry.constantAnnotations.length ? entry.constantAnnotations.join(', ') : 'None observed'} |`);
}

function markdownRuntime(fi: FunctionIntelligence): string[] {
  const lines: string[] = [];
  if (!fi.debuggerCallStack?.length && !fi.conditionalBreakpointHits?.length) return ['None observed'];
  for (const observation of fi.debuggerCallStack ?? []) {
    lines.push(`- Call stack observed at ${formatHex(observation.observedAt)}`);
    for (const frame of observation.frames) {
      lines.push(`  - ${formatHex(frame.returnAddress)} ${frame.moduleName ? `${frame.moduleName}!` : ''}${frame.symbolName ?? 'unknown symbol'}`);
    }
  }
  for (const hit of fi.conditionalBreakpointHits ?? []) {
    lines.push(`- Conditional breakpoint ${formatHex(hit.address)} hit ${hit.hitCount} time(s): ${hit.condition}`);
  }
  return lines;
}

function markdownLimits(limits: FunctionIntelligenceLimit[]): string[] {
  if (limits.length === 0) return ['- None observed'];
  return limits.map(limit => `- ${limit.address !== undefined ? `${formatHex(limit.address)}: ` : ''}${limit.detail}`);
}

export function exportFunctionIntelligenceJSON(fi: FunctionIntelligence): string {
  return JSON.stringify({
    export_schema: 'hexhawk.function_intelligence.v1',
    generated_at: new Date().toISOString(),
    source_evidence_per_claim: true,
    ...fi,
    gyre_is_sole_verdict_authority: true,
    advisory_analysis_only: true,
  }, null, 2);
}

export function exportFunctionIntelligenceMarkdown(fi: FunctionIntelligence): string {
  const generatedAt = new Date().toISOString();
  const lines: string[] = [
    `# Function: ${fi.name} @ ${formatHex(fi.address)}`,
    '',
    '## Identity',
    `Name: ${fi.name} (${fi.nameSource})`,
    `Address range: ${formatHex(fi.address)} – ${formatHex(fi.endAddress)}`,
    `Calling convention: ${fi.callingConvention ? `${fi.callingConvention.abi} (${fi.callingConvention.analysisConfidence} confidence)` : 'Unknown (not proven)'}`,
    `Boundary source: ${fi.boundarySource}`,
    '',
    `## Callers (${fi.callers.length})`,
    '| Address | Name | Basis |',
    '|---------|------|-------|',
    ...markdownEdgeRows(fi.callers),
    '',
    `## Callees (${fi.callees.length})`,
    '| Address | Name | Basis |',
    '|---------|------|-------|',
    ...markdownEdgeRows(fi.callees),
    '',
    '## Import Calls',
    '| Import | Module | Address | Constants |',
    '|--------|--------|---------|-----------|',
    ...markdownImportRows(fi.importCalls),
    '',
    '## Pseudocode (advisory — not recovered source)',
    fi.pseudocode ?? 'None observed',
    '',
    '## Runtime Observations',
    ...markdownRuntime(fi),
    '',
    '## Analysis Limits',
    ...markdownLimits(fi.limits),
    '',
    '---',
    '*Advisory analysis only. GYRE is sole verdict authority.*',
    `*Generated: ${generatedAt}*`,
  ];
  return lines.join('\n');
}
