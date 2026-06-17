import type { BasicBlock, FunctionModel, ImportCall, Instruction, ProgramAnalysis } from './disassemblyModel';
import type { TraceEvent, TraceImportWarning, TraceSession } from './traceModel';

export interface TraceImportLike {
  name: string;
  library?: string;
  moduleName?: string;
  address?: number;
}

export interface TraceEventCorrelation {
  eventId: string;
  eventIndex: number;
  eventKind: TraceEvent['kind'];
  address?: number;
  instruction?: Instruction;
  function?: Pick<FunctionModel, 'id' | 'name' | 'startAddress' | 'endAddress'>;
  basicBlock?: Pick<BasicBlock, 'id' | 'startAddress' | 'endAddress'>;
  apiImport?: ImportCall | TraceImportLike;
  resolved: boolean;
  warnings: TraceImportWarning[];
}

export interface TraceCorrelationSummary {
  eventCount: number;
  addressedEventCount: number;
  resolvedAddressCount: number;
  unresolvedAddressCount: number;
  functionCoverageCount: number;
  basicBlockCoverageCount: number;
  apiCallCount: number;
  resolvedApiCallCount: number;
}

export interface TraceCorrelationReport {
  advisoryOnly: true;
  authority: 'runtime_trace_correlation_not_gyre_verdict';
  session: TraceSession;
  eventCorrelations: TraceEventCorrelation[];
  summary: TraceCorrelationSummary;
  warnings: TraceImportWarning[];
}

function formatAddress(address: number): string {
  return `0x${address.toString(16).toUpperCase()}`;
}

function containsAddress<T extends { startAddress: number; endAddress: number }>(item: T, address: number): boolean {
  return address >= item.startAddress && address <= item.endAddress;
}

function normalizeName(value: string | undefined): string {
  return (value ?? '').trim().toLowerCase().replace(/\.dll$/i, '');
}

function correlateApiImport(event: TraceEvent, imports: TraceImportLike[], program: ProgramAnalysis): ImportCall | TraceImportLike | undefined {
  if (event.kind !== 'api-call') return undefined;
  const eventApi = normalizeName(event.apiName);
  const eventModule = normalizeName(event.moduleName);

  const programImport = program.importCalls.find(importCall => {
    const apiMatches = normalizeName(importCall.importName) === eventApi;
    const moduleMatches = !eventModule || normalizeName(importCall.moduleName) === eventModule;
    const targetMatches = event.targetAddress !== undefined && importCall.targetAddress === event.targetAddress;
    return targetMatches || (apiMatches && moduleMatches);
  });
  if (programImport) return programImport;

  return imports.find(importEntry => {
    const apiMatches = normalizeName(importEntry.name) === eventApi;
    const moduleName = importEntry.library ?? importEntry.moduleName;
    const moduleMatches = !eventModule || normalizeName(moduleName) === eventModule;
    const targetMatches = event.targetAddress !== undefined && importEntry.address === event.targetAddress;
    return targetMatches || (apiMatches && moduleMatches);
  });
}

export function correlateTraceSession(
  session: TraceSession,
  program: ProgramAnalysis,
  imports: TraceImportLike[] = [],
): TraceCorrelationReport {
  const instructionByAddress = new Map(program.instructions.map(instruction => [instruction.address, instruction] as const));
  const warnings: TraceImportWarning[] = [...session.warnings];
  const coveredFunctions = new Set<number>();
  const coveredBlocks = new Set<string>();
  let addressedEventCount = 0;
  let resolvedAddressCount = 0;
  let unresolvedAddressCount = 0;
  let apiCallCount = 0;
  let resolvedApiCallCount = 0;

  const eventCorrelations = session.events.map((event): TraceEventCorrelation => {
    const eventWarnings: TraceImportWarning[] = [];
    const address = event.address;
    const instruction = address === undefined ? undefined : instructionByAddress.get(address);
    const containingFunction = address === undefined ? undefined : program.functions.find(fn => containsAddress(fn, address));
    const containingBlock = address === undefined ? undefined : program.basicBlocks.find(block => containsAddress(block, address));
    const apiImport = correlateApiImport(event, imports, program);

    if (address !== undefined) {
      addressedEventCount += 1;
      if (instruction || containingFunction || containingBlock) {
        resolvedAddressCount += 1;
      } else {
        unresolvedAddressCount += 1;
        eventWarnings.push({
          kind: 'invalid-address',
          severity: 'warning',
          eventIndex: event.index,
          field: 'address',
          message: `Trace address ${formatAddress(address)} did not match disassembly, function, or basic block evidence.`,
        });
      }
    }

    if (containingFunction) coveredFunctions.add(containingFunction.startAddress);
    if (containingBlock) coveredBlocks.add(containingBlock.id);

    if (event.kind === 'api-call') {
      apiCallCount += 1;
      if (apiImport) {
        resolvedApiCallCount += 1;
      } else {
        eventWarnings.push({
          kind: 'invalid-event',
          severity: 'warning',
          eventIndex: event.index,
          field: 'apiName',
          message: `API call ${event.apiName} did not match known imports.`,
        });
      }
    }

    warnings.push(...eventWarnings);

    return {
      eventId: event.id,
      eventIndex: event.index,
      eventKind: event.kind,
      address,
      instruction,
      function: containingFunction
        ? {
            id: containingFunction.id,
            name: containingFunction.name,
            startAddress: containingFunction.startAddress,
            endAddress: containingFunction.endAddress,
          }
        : undefined,
      basicBlock: containingBlock
        ? {
            id: containingBlock.id,
            startAddress: containingBlock.startAddress,
            endAddress: containingBlock.endAddress,
          }
        : undefined,
      apiImport,
      resolved: Boolean(instruction || containingFunction || containingBlock || apiImport),
      warnings: eventWarnings,
    };
  });

  return {
    advisoryOnly: true,
    authority: 'runtime_trace_correlation_not_gyre_verdict',
    session,
    eventCorrelations,
    summary: {
      eventCount: session.events.length,
      addressedEventCount,
      resolvedAddressCount,
      unresolvedAddressCount,
      functionCoverageCount: coveredFunctions.size,
      basicBlockCoverageCount: coveredBlocks.size,
      apiCallCount,
      resolvedApiCallCount,
    },
    warnings,
  };
}
