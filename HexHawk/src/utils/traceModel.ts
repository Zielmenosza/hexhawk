// traceModel — imported debugger/trace evidence model for STRIKE.
//
// Imported traces are advisory runtime evidence. They do not carry GYRE verdict
// authority and must not mutate classification or confidence.

export type TraceEventKind =
  | 'module-load'
  | 'thread-event'
  | 'breakpoint-hit'
  | 'call'
  | 'branch'
  | 'api-call'
  | 'memory-access'
  | 'unknown';

export type TraceImportWarningKind =
  | 'malformed-json'
  | 'unsupported-schema'
  | 'invalid-event'
  | 'missing-address'
  | 'invalid-address'
  | 'unknown-event-kind';

export interface TraceImportWarning {
  kind: TraceImportWarningKind;
  message: string;
  eventIndex?: number;
  field?: string;
  severity: 'warning' | 'error';
}

interface TraceEventBase {
  id: string;
  index: number;
  timestamp?: string | number;
  address?: number;
  threadId?: string | number;
  raw: unknown;
}

export interface ModuleLoad extends TraceEventBase {
  kind: 'module-load';
  moduleName: string;
  baseAddress?: number;
  size?: number;
}

export interface ThreadEvent extends TraceEventBase {
  kind: 'thread-event';
  action: 'start' | 'exit' | 'unknown';
}

export interface BreakpointHit extends TraceEventBase {
  kind: 'breakpoint-hit';
  breakpointAddress?: number;
}

export interface CallEvent extends TraceEventBase {
  kind: 'call';
  targetAddress?: number;
  targetName?: string;
}

export interface BranchEvent extends TraceEventBase {
  kind: 'branch';
  targetAddress?: number;
  taken?: boolean;
}

export interface ApiCallEvent extends TraceEventBase {
  kind: 'api-call';
  apiName: string;
  moduleName?: string;
  targetAddress?: number;
}

export interface MemoryAccessEvent extends TraceEventBase {
  kind: 'memory-access';
  access: 'read' | 'write' | 'read-write' | 'unknown';
  memoryAddress?: number;
  size?: number;
}

export interface UnknownTraceEvent extends TraceEventBase {
  kind: 'unknown';
  label?: string;
}

export type TraceEvent =
  | ModuleLoad
  | ThreadEvent
  | BreakpointHit
  | CallEvent
  | BranchEvent
  | ApiCallEvent
  | MemoryAccessEvent
  | UnknownTraceEvent;

export interface TraceSession {
  schema: 'hexhawk.trace.v1';
  advisoryOnly: true;
  authority: 'runtime_trace_evidence_not_gyre_verdict';
  sourceFormat: 'hexhawk-json-v1';
  importedAt: string;
  tool?: string;
  target?: string;
  events: TraceEvent[];
  warnings: TraceImportWarning[];
}

export class TraceParseError extends Error {
  warnings: TraceImportWarning[];

  constructor(message: string, warnings: TraceImportWarning[]) {
    super(message);
    this.name = 'TraceParseError';
    this.warnings = warnings;
  }
}

type RawTraceEvent = Record<string, unknown>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function asBoolean(value: unknown): boolean | undefined {
  return typeof value === 'boolean' ? value : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

export function parseTraceAddress(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value) && value >= 0) return value;
  if (typeof value !== 'string') return undefined;
  const text = value.trim();
  if (!text) return undefined;
  if (/^0x[0-9a-f]+$/i.test(text)) return Number.parseInt(text.slice(2), 16);
  if (/^[0-9a-f]{8,16}$/i.test(text) && /[a-f]/i.test(text)) return Number.parseInt(text, 16);
  if (/^\d+$/.test(text)) return Number.parseInt(text, 10);
  return undefined;
}

function getAddress(raw: RawTraceEvent, keys: string[]): number | undefined {
  for (const key of keys) {
    const parsed = parseTraceAddress(raw[key]);
    if (parsed !== undefined) return parsed;
  }
  return undefined;
}

function normalizeKind(value: unknown): TraceEventKind {
  const text = String(value ?? '').trim().toLowerCase().replace(/[_\s]+/g, '-');
  if (['module-load', 'module', 'load-module'].includes(text)) return 'module-load';
  if (['thread-event', 'thread', 'thread-start', 'thread-exit'].includes(text)) return 'thread-event';
  if (['breakpoint-hit', 'breakpoint', 'bp', 'int3'].includes(text)) return 'breakpoint-hit';
  if (['call', 'call-event'].includes(text)) return 'call';
  if (['branch', 'jump', 'jmp', 'conditional-branch'].includes(text)) return 'branch';
  if (['api-call', 'api', 'import-call'].includes(text)) return 'api-call';
  if (['memory-access', 'mem', 'memory', 'read', 'write'].includes(text)) return 'memory-access';
  return 'unknown';
}

export function classifyRawTraceEvent(raw: unknown): TraceEventKind {
  if (!isRecord(raw)) return 'unknown';
  const explicit = normalizeKind(raw.kind ?? raw.type ?? raw.event);
  if (explicit !== 'unknown') return explicit;

  const label = String(raw.label ?? raw.text ?? raw.instruction ?? '').toLowerCase();
  if (raw.apiName || raw.api || raw.importName || /\b(api|kernel32|ntdll|user32)!/.test(label)) return 'api-call';
  if (/\bcall\b/.test(label)) return 'call';
  if (/\b(jmp|je|jne|jg|jl|branch)\b/.test(label)) return 'branch';
  if (/\b(breakpoint|int3)\b/.test(label)) return 'breakpoint-hit';
  return 'unknown';
}

function eventBase(raw: RawTraceEvent, index: number): TraceEventBase {
  const address = getAddress(raw, ['address', 'rip', 'ip', 'pc', 'instructionAddress']);
  return {
    id: asString(raw.id) ?? `trace-event-${index}`,
    index,
    timestamp: (typeof raw.timestamp === 'string' || typeof raw.timestamp === 'number') ? raw.timestamp : undefined,
    address,
    threadId: (typeof raw.threadId === 'string' || typeof raw.threadId === 'number') ? raw.threadId : undefined,
    raw,
  };
}

function classifyThreadAction(raw: RawTraceEvent): ThreadEvent['action'] {
  const text = String(raw.action ?? raw.type ?? raw.event ?? '').toLowerCase();
  if (text.includes('start') || text.includes('create')) return 'start';
  if (text.includes('exit') || text.includes('end')) return 'exit';
  return 'unknown';
}

function classifyMemoryAccess(raw: RawTraceEvent): MemoryAccessEvent['access'] {
  const text = String(raw.access ?? raw.operation ?? raw.type ?? '').toLowerCase();
  const read = text.includes('read');
  const write = text.includes('write');
  if (read && write) return 'read-write';
  if (read) return 'read';
  if (write) return 'write';
  return 'unknown';
}

export function normalizeTraceEvent(raw: unknown, index: number, warnings: TraceImportWarning[]): TraceEvent | null {
  if (!isRecord(raw)) {
    warnings.push({ kind: 'invalid-event', severity: 'error', eventIndex: index, message: `Trace event ${index} is not an object.` });
    return null;
  }

  const base = eventBase(raw, index);
  const kind = classifyRawTraceEvent(raw);
  if (kind === 'unknown') {
    warnings.push({ kind: 'unknown-event-kind', severity: 'warning', eventIndex: index, message: `Trace event ${index} has an unknown kind and was kept as advisory evidence.` });
    return { ...base, kind, label: asString(raw.label ?? raw.text ?? raw.instruction) };
  }

  if (base.address === undefined && !['module-load', 'thread-event'].includes(kind)) {
    warnings.push({ kind: 'missing-address', severity: 'warning', eventIndex: index, field: 'address', message: `Trace event ${index} has no instruction address.` });
  }

  switch (kind) {
    case 'module-load':
      return {
        ...base,
        kind,
        moduleName: asString(raw.moduleName ?? raw.module ?? raw.name) ?? 'unknown-module',
        baseAddress: getAddress(raw, ['baseAddress', 'base', 'moduleBase']),
        size: asNumber(raw.size),
      };
    case 'thread-event':
      return { ...base, kind, action: classifyThreadAction(raw) };
    case 'breakpoint-hit':
      return { ...base, kind, breakpointAddress: getAddress(raw, ['breakpointAddress', 'bp', 'address']) };
    case 'call':
      return {
        ...base,
        kind,
        targetAddress: getAddress(raw, ['targetAddress', 'target', 'to']),
        targetName: asString(raw.targetName ?? raw.function ?? raw.symbol),
      };
    case 'branch':
      return {
        ...base,
        kind,
        targetAddress: getAddress(raw, ['targetAddress', 'target', 'to']),
        taken: asBoolean(raw.taken),
      };
    case 'api-call':
      return {
        ...base,
        kind,
        apiName: asString(raw.apiName ?? raw.api ?? raw.importName ?? raw.function) ?? 'unknown-api',
        moduleName: asString(raw.moduleName ?? raw.module ?? raw.library),
        targetAddress: getAddress(raw, ['targetAddress', 'target', 'to']),
      };
    case 'memory-access':
      return {
        ...base,
        kind,
        access: classifyMemoryAccess(raw),
        memoryAddress: getAddress(raw, ['memoryAddress', 'memAddress', 'effectiveAddress', 'target']),
        size: asNumber(raw.size),
      };
    default:
      return { ...base, kind: 'unknown', label: asString(raw.label ?? raw.text ?? raw.instruction) };
  }
}

export function parseHexHawkTraceJson(input: string | unknown): TraceSession {
  const warnings: TraceImportWarning[] = [];
  let parsed: unknown = input;

  if (typeof input === 'string') {
    try {
      parsed = JSON.parse(input) as unknown;
    } catch (error) {
      warnings.push({ kind: 'malformed-json', severity: 'error', message: `Trace JSON could not be parsed: ${String(error)}` });
      throw new TraceParseError('Malformed trace JSON', warnings);
    }
  }

  if (!isRecord(parsed)) {
    warnings.push({ kind: 'unsupported-schema', severity: 'error', message: 'Trace root must be an object using schema hexhawk.trace.v1.' });
    throw new TraceParseError('Unsupported trace schema', warnings);
  }

  if (parsed.schema !== 'hexhawk.trace.v1' || !Array.isArray(parsed.events)) {
    warnings.push({ kind: 'unsupported-schema', severity: 'error', message: 'Expected schema hexhawk.trace.v1 with an events array.' });
    throw new TraceParseError('Unsupported trace schema', warnings);
  }

  const events = parsed.events
    .map((event, index) => normalizeTraceEvent(event, index, warnings))
    .filter((event): event is TraceEvent => event !== null);

  return {
    schema: 'hexhawk.trace.v1',
    advisoryOnly: true,
    authority: 'runtime_trace_evidence_not_gyre_verdict',
    sourceFormat: 'hexhawk-json-v1',
    importedAt: new Date().toISOString(),
    tool: asString(parsed.tool),
    target: asString(parsed.target),
    events,
    warnings,
  };
}

export const HEXHAWK_TRACE_SCHEMA_EXAMPLE = {
  schema: 'hexhawk.trace.v1',
  tool: 'analyst-saved-trace',
  target: 'sample.exe',
  events: [
    { kind: 'module-load', moduleName: 'sample.exe', baseAddress: '0x140000000' },
    { kind: 'call', address: '0x140001010', targetAddress: '0x140001080' },
    { kind: 'api-call', address: '0x140001020', moduleName: 'kernel32.dll', apiName: 'VirtualAlloc' },
    { kind: 'branch', address: '0x140001030', targetAddress: '0x140001050', taken: true },
  ],
} as const;
