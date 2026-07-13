import { invoke } from '@tauri-apps/api/core';
import type { BinaryVerdictResult } from './correlationEngine';

export const GYRE_RENDERER_BUILD_ID = '1.0.0+renderer-gyre';
export const GYRE_SCHEMA_VERSION = '1.0.0';

export interface GyreRecordedVerdictSnapshot {
  schemaName: 'gyre.recorded_verdict_snapshot';
  schemaVersion: string;
  snapshotId: string;
  provenance: 'renderer_gyre_backend_recorded';
  binarySha256: string;
  classification: string;
  baseConfidence: number;
  threatScore: number;
  summary: string;
  signalCount: number;
  contradictionCount: number;
  reasoningChainHash: string;
  gyreBuildId: string;
  gyreSchemaVersion: string;
  createdAt: string;
}

export interface GyreSnapshotBinding {
  snapshotId: string;
  binaryPath: string;
  binarySha256: string;
  generation: number;
}

export interface NestFinalizeAdvisoryFields {
  linkedIterationId?: string | null;
  nestSummary?: string | null;
  runtimeProof?: unknown | null;
  notes?: string[] | null;
}

export function buildNestFinalizeRequest(
  sessionId: string,
  gyreSnapshotId: string,
  advisory: NestFinalizeAdvisoryFields = {},
) {
  return {
    sessionId,
    gyreSnapshotId,
    linkedIterationId: advisory.linkedIterationId ?? null,
    nestSummary: advisory.nestSummary ?? null,
    runtimeProof: advisory.runtimeProof ?? null,
    notes: advisory.notes ?? null,
  };
}

export interface NestAppendIterationResponse {
  sessionId: string;
  iterationCount: number;
  iterationId: string;
  replayed: boolean;
}

export interface NestProjectLinkage {
  sessionId: string;
  finalIterationId: string;
  finalVerdictSnapshotId: string;
}

export interface NestLifecycleWork<TStep> {
  step: TStep;
  terminal: boolean;
  appendRequest: Record<string, unknown>;
  finalizeAdvisory?: Omit<NestFinalizeAdvisoryFields, 'linkedIterationId'>;
}

export interface NestLifecycleResult<TStep> {
  step: TStep;
  terminal: boolean;
  append: NestAppendIterationResponse;
  finalized: boolean;
  projectLinkage: NestProjectLinkage | null;
}

type NativeInvoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>;

type PendingNestLifecycleWork<TStep> = NestLifecycleWork<TStep> & {
  sessionId: string;
  gyreSnapshotId: string | null;
  clientIterationKey: string;
  appendResponse?: NestAppendIterationResponse;
  appendPromise?: Promise<NestAppendIterationResponse>;
  finalizePromise?: Promise<unknown>;
  finalized: boolean;
};

export class NestLifecycleOperationError extends Error {
  constructor(
    public readonly stage: 'append' | 'finalize' | 'snapshot',
    message: string,
  ) {
    super(message);
    this.name = 'NestLifecycleOperationError';
  }
}

function boundedLifecycleError(error: unknown): string {
  const text = String(error).replace(/[\r\n\t]+/g, ' ');
  return text.length <= 500 ? text : `${text.slice(0, 500)}…`;
}

function defaultClientIterationKey(): string {
  return `nestclient_${crypto.randomUUID().replace(/-/g, '')}`;
}

/**
 * Owns one renderer logical iteration at a time. The backend remains the sole
 * owner of canonical iteration IDs; renderer retries retain only the stable
 * client idempotency key and the exact append payload.
 */
export class NestLifecycleCoordinator<TStep> {
  private pending: PendingNestLifecycleWork<TStep> | null = null;
  private creating: Promise<PendingNestLifecycleWork<TStep>> | null = null;
  private generation = 0;

  constructor(
    private readonly nativeInvoke: NativeInvoke = invoke,
    private readonly createClientKey: () => string = defaultClientIterationKey,
  ) {}

  reset(): void {
    this.generation += 1;
    this.pending = null;
    this.creating = null;
  }

  async processNext(
    sessionId: string,
    gyreSnapshotId: string | null,
    createWork: () => Promise<NestLifecycleWork<TStep>>,
  ): Promise<NestLifecycleResult<TStep>> {
    if (this.pending && this.pending.sessionId !== sessionId) {
      throw new NestLifecycleOperationError(
        'append',
        'NEST lifecycle state is stale for the active session.',
      );
    }

    if (!this.pending) {
      if (!this.creating) {
        const generation = this.generation;
        this.creating = createWork().then(work => {
          if (generation !== this.generation) {
            throw new NestLifecycleOperationError(
              'append',
              'NEST lifecycle session changed while preparing an iteration.',
            );
          }
          const pending: PendingNestLifecycleWork<TStep> = {
            ...work,
            sessionId,
            gyreSnapshotId,
            clientIterationKey: this.createClientKey(),
            finalized: false,
          };
          this.pending = pending;
          return pending;
        });
      }
      try {
        await this.creating;
      } finally {
        this.creating = null;
      }
    }

    const pending = this.pending;
    if (!pending) {
      throw new NestLifecycleOperationError('append', 'NEST lifecycle iteration is unavailable.');
    }
    if (!pending.gyreSnapshotId && gyreSnapshotId) {
      pending.gyreSnapshotId = gyreSnapshotId;
    } else if (pending.gyreSnapshotId && gyreSnapshotId && pending.gyreSnapshotId !== gyreSnapshotId) {
      throw new NestLifecycleOperationError(
        'snapshot',
        'Recorded GYRE snapshot changed while a NEST iteration was pending.',
      );
    }

    if (!pending.appendResponse) {
      if (!pending.appendPromise) {
        pending.appendPromise = this.nativeInvoke(
          'nest_append_iteration',
          {
            request: {
              ...pending.appendRequest,
              sessionId,
              clientIterationKey: pending.clientIterationKey,
            },
          },
        ).then(result => result as NestAppendIterationResponse);
      }
      try {
        pending.appendResponse = await pending.appendPromise;
      } catch (error) {
        throw new NestLifecycleOperationError(
          'append',
          `NEST lifecycle iteration persistence failed: ${boundedLifecycleError(error)}`,
        );
      } finally {
        pending.appendPromise = undefined;
      }
    }

    if (!pending.terminal) {
      const result = {
        step: pending.step,
        terminal: false,
        append: pending.appendResponse,
        finalized: false,
        projectLinkage: null,
      };
      this.pending = null;
      return result;
    }

    if (!pending.gyreSnapshotId) {
      throw new NestLifecycleOperationError(
        'snapshot',
        'NEST lifecycle finalization requires a recorded GYRE snapshot for this binary.',
      );
    }

    if (!pending.finalized) {
      if (!pending.finalizePromise) {
        pending.finalizePromise = this.nativeInvoke('nest_finalize_session', {
          request: buildNestFinalizeRequest(sessionId, pending.gyreSnapshotId, {
            ...pending.finalizeAdvisory,
            linkedIterationId: pending.appendResponse.iterationId,
          }),
        });
      }
      try {
        await pending.finalizePromise;
        pending.finalized = true;
      } catch (error) {
        throw new NestLifecycleOperationError(
          'finalize',
          `NEST lifecycle finalization failed: ${boundedLifecycleError(error)}`,
        );
      } finally {
        pending.finalizePromise = undefined;
      }
    }

    const result = {
      step: pending.step,
      terminal: true,
      append: pending.appendResponse,
      finalized: true,
      projectLinkage: {
        sessionId,
        finalIterationId: pending.appendResponse.iterationId,
        finalVerdictSnapshotId: pending.gyreSnapshotId,
      },
    };
    this.pending = null;
    return result;
  }
}


export function formatGyreSnapshotRecordingError(error: unknown): string {
  const text = String(error).replace(/[\r\n\t]+/g, ' ');
  return text.length <= 500 ? text : `${text.slice(0, 500)}...`;
}

export type GyreSnapshotRecordFunction = (
  clientRecordKey: string,
  binarySha256: string,
  verdict: BinaryVerdictResult,
) => Promise<GyreRecordedVerdictSnapshot>;

function defaultClientRecordKey(): string {
  return `gyrerecord_${crypto.randomUUID().replace(/-/g, '')}`;
}

interface GyreSelectedIdentity {
  binaryPath: string;
  binarySha256: string;
  generation: number;
  clientRecordKey: string;
}

interface GyreInFlightRecording {
  binaryPath: string;
  binarySha256: string;
  generation: number;
  promise: Promise<GyreSnapshotBinding | null>;
}

/**
 * Coordinates one immutable recorded GYRE snapshot per selected path/hash
 * identity. Effect replay and ordinary rerenders reuse the same in-flight or
 * accepted result. Native responses are accepted only while their exact
 * identity generation remains current.
 */
export class GyreSnapshotRecordingCoordinator {
  private generation = 0;
  private currentIdentity: GyreSelectedIdentity | null = null;
  private acceptedBinding: GyreSnapshotBinding | null = null;
  private inFlight: GyreInFlightRecording | null = null;

  constructor(
    private readonly recordSnapshot: GyreSnapshotRecordFunction = recordGyreVerdictSnapshot,
    private readonly createClientRecordKey: () => string = defaultClientRecordKey,
  ) {}

  clear(): void {
    this.generation += 1;
    this.currentIdentity = null;
    this.acceptedBinding = null;
    this.inFlight = null;
  }

  currentBinding(
    binaryPath: string,
    binarySha256: string,
  ): GyreSnapshotBinding | null {
    const current = this.currentIdentity;
    const binding = this.acceptedBinding;
    if (!current || !binding) return null;

    return current.binaryPath === binaryPath
      && current.binarySha256 === binarySha256
      && binding.binaryPath === binaryPath
      && binding.binarySha256 === binarySha256
      && binding.generation === current.generation
      ? binding
      : null;
  }

  async record(
    binaryPath: string,
    binarySha256: string,
    verdict: BinaryVerdictResult,
  ): Promise<GyreSnapshotBinding | null> {
    const selected = this.selectIdentity(binaryPath, binarySha256);
    if (!selected) return null;

    const accepted = this.currentBinding(binaryPath, binarySha256);
    if (accepted) return accepted;

    const existing = this.inFlight;
    if (
      existing
      && existing.binaryPath === selected.binaryPath
      && existing.binarySha256 === selected.binarySha256
      && existing.generation === selected.generation
    ) {
      return existing.promise;
    }

    const generation = selected.generation;
    const promise = this.recordSnapshot(selected.clientRecordKey, binarySha256, verdict)
      .then((recorded) => {
        if (!this.isCurrent(binaryPath, binarySha256, generation)) {
          return null;
        }

        const binding: GyreSnapshotBinding = {
          snapshotId: recorded.snapshotId,
          binaryPath,
          binarySha256,
          generation,
        };
        this.acceptedBinding = binding;
        return binding;
      })
      .finally(() => {
        if (this.inFlight?.promise === promise) {
          this.inFlight = null;
        }
      });

    this.inFlight = {
      binaryPath,
      binarySha256,
      generation,
      promise,
    };

    return promise;
  }

  private selectIdentity(
    binaryPath: string,
    binarySha256: string,
  ): GyreSelectedIdentity | null {
    if (!binaryPath || !binarySha256) {
      this.clear();
      return null;
    }

    const current = this.currentIdentity;
    if (
      current
      && current.binaryPath === binaryPath
      && current.binarySha256 === binarySha256
    ) {
      return current;
    }

    this.generation += 1;
    this.currentIdentity = {
      binaryPath,
      binarySha256,
      generation: this.generation,
      clientRecordKey: this.createClientRecordKey(),
    };
    this.acceptedBinding = null;
    this.inFlight = null;
    return this.currentIdentity;
  }

  private isCurrent(
    binaryPath: string,
    binarySha256: string,
    generation: number,
  ): boolean {
    const current = this.currentIdentity;
    return current?.binaryPath === binaryPath
      && current.binarySha256 === binarySha256
      && current.generation === generation;
  }
}

export function isCurrentGyreSnapshotResponse(
  expected: Pick<GyreSnapshotBinding, 'binaryPath' | 'binarySha256' | 'generation'>,
  current: Pick<GyreSnapshotBinding, 'binaryPath' | 'binarySha256' | 'generation'>,
): boolean {
  return expected.generation === current.generation
    && expected.binaryPath === current.binaryPath
    && expected.binarySha256 === current.binarySha256;
}

async function sha256Hex(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}

export async function recordGyreVerdictSnapshot(
  clientRecordKey: string,
  binarySha256: string,
  verdict: BinaryVerdictResult,
): Promise<GyreRecordedVerdictSnapshot> {
  const reasoningChainHash = await sha256Hex(JSON.stringify(verdict.reasoningChain));
  return invoke<GyreRecordedVerdictSnapshot>('gyre_record_verdict_snapshot', {
    request: {
      clientRecordKey,
      binarySha256,
      classification: verdict.classification,
      baseConfidence: verdict.confidence,
      threatScore: verdict.threatScore,
      summary: verdict.summary,
      signalCount: verdict.signalCount,
      contradictionCount: verdict.contradictions.length,
      reasoningChainHash,
      gyreBuildId: GYRE_RENDERER_BUILD_ID,
      gyreSchemaVersion: GYRE_SCHEMA_VERSION,
    },
  });
}
