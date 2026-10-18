export type DynamicSessionMode = 'offline-trace' | 'attach-readonly' | 'sandbox-remote';
export type DynamicEventKind = 'module-load' | 'thread-create' | 'breakpoint-hit' | 'register-snapshot' | 'memory-read' | 'api-call' | 'note';

export interface DynamicSessionConsent {
  required: true;
  granted: boolean;
  grantedAt?: string;
  userFacingWarning: string;
}

export interface DynamicTraceEvent {
  schema: 'hexhawk.dynamic_trace_event.v1';
  id: string;
  kind: DynamicEventKind;
  timestamp: string;
  address?: number;
  threadId?: string;
  moduleName?: string;
  summary: string;
  observed: true;
  evidenceBasis: string[];
}

export interface DynamicSessionTrace {
  schema: 'hexhawk.dynamic_session_trace.v1';
  sessionId: string;
  binary: {
    path?: string;
    sha256: string;
    architecture?: string;
  };
  mode: DynamicSessionMode;
  consent: DynamicSessionConsent;
  events: DynamicTraceEvent[];
  replayable: true;
  liveExecutionPerformed: boolean;
  provenance: {
    hexhawkBuildId?: string;
    traceSource: 'fixture' | 'imported' | 'native-debugger' | 'remote-sandbox';
    createdAt: string;
  };
  gyre_is_sole_verdict_authority: true;
  advisory_analysis_only: true;
}

const SHA256_RE = /^[a-f0-9]{64}$/;

export function buildOfflineDynamicTrace(params: {
  sessionId: string;
  binarySha256: string;
  binaryPath?: string;
  architecture?: string;
  events?: Omit<DynamicTraceEvent, 'schema' | 'observed'>[];
  createdAt?: string;
  traceSource?: DynamicSessionTrace['provenance']['traceSource'];
}): DynamicSessionTrace {
  if (!SHA256_RE.test(params.binarySha256)) {
    throw new Error('binarySha256 must be 64 lowercase hex characters.');
  }
  const createdAt = params.createdAt ?? new Date().toISOString();
  return {
    schema: 'hexhawk.dynamic_session_trace.v1',
    sessionId: params.sessionId,
    binary: {
      path: params.binaryPath,
      sha256: params.binarySha256,
      architecture: params.architecture,
    },
    mode: 'offline-trace',
    consent: {
      required: true,
      granted: false,
      userFacingWarning: 'Offline trace replay does not execute the specimen. Live attach/debug requires separate explicit consent.',
    },
    events: (params.events ?? []).map(event => ({
      ...event,
      schema: 'hexhawk.dynamic_trace_event.v1',
      observed: true,
    })),
    replayable: true,
    liveExecutionPerformed: false,
    provenance: {
      traceSource: params.traceSource ?? 'fixture',
      createdAt,
    },
    gyre_is_sole_verdict_authority: true,
    advisory_analysis_only: true,
  };
}

export function assertReplayableDynamicTrace(trace: DynamicSessionTrace): void {
  if (trace.schema !== 'hexhawk.dynamic_session_trace.v1') throw new Error('Unsupported dynamic trace schema.');
  if (!trace.replayable) throw new Error('Dynamic trace is not replayable.');
  if (trace.liveExecutionPerformed && trace.mode === 'offline-trace') {
    throw new Error('Offline trace cannot mark liveExecutionPerformed=true.');
  }
  if (!SHA256_RE.test(trace.binary.sha256)) throw new Error('Trace binary hash is invalid.');
  for (const event of trace.events) {
    if (event.schema !== 'hexhawk.dynamic_trace_event.v1') throw new Error(`Event ${event.id} has unsupported schema.`);
    if (!event.observed) throw new Error(`Event ${event.id} must be an observed event.`);
    if (!event.evidenceBasis.length) throw new Error(`Event ${event.id} requires evidenceBasis.`);
  }
}

export function summarizeDynamicTrace(trace: DynamicSessionTrace): string {
  assertReplayableDynamicTrace(trace);
  const execution = trace.liveExecutionPerformed ? 'live execution recorded' : 'offline replay only';
  return `${trace.events.length} dynamic event(s), ${execution}, source ${trace.provenance.traceSource}`;
}
