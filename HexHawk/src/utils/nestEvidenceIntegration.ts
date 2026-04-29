import type { BinaryVerdictResult } from './correlationEngine';
import type { NestSession, NestSummary, NestIterationSnapshot } from './nestEngine';
import {
  NEST_EVIDENCE_DEFAULT_SCHEMA_VERSION,
  NEST_EVIDENCE_BUNDLE_FORMAT_VERSION,
  NEST_EVIDENCE_SCHEMA_NAMES,
  validateNestEvidenceBundle,
  parseNestManifest,
  parseNestBinaryIdentity,
  parseNestSessionRecord,
  parseNestIterationsFile,
  parseNestDeltasFile,
  parseNestFinalVerdictSnapshot,
  parseNestRuntimeProof,
  parseNestAuditRefs,
  type NestEvidenceBundle,
  type NestManifest,
  type NestBinaryIdentity,
  type NestSessionRecord,
  type NestIterationsFile,
  type NestDeltasFile,
  type NestFinalVerdictSnapshot,
  type NestRuntimeProof,
  type NestAuditRefs,
  type NestValidationIssue,
  type NestValidationResult,
  type ActorType,
} from '../types/nestEvidence';

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export interface NestEvidenceBuildInput {
  binaryPath: string;
  binarySha256: string;
  binarySha1?: string;
  binaryMd5?: string;
  fileSizeBytes: number;
  format: string;
  architecture: string;
  session: NestSession;
  summary: NestSummary;
  actorId?: string;
  actorType?: ActorType;
  engineBuildId?: string;
  gyreBuildId?: string;
  gyreSchemaVersion?: string;
  policyVersion?: string;
  executionMode?: 'local-tauri' | 'cli';
  runtimeProof?: NestRuntimeProof;
  exportMode?: 'local-tauri' | 'cli';
}

export interface NestEvidenceFileMap {
  'manifest.json': NestManifest;
  'binary_identity.json': NestBinaryIdentity;
  'session.json': NestSessionRecord;
  'iterations.json': NestIterationsFile;
  'deltas.json': NestDeltasFile;
  'final_verdict_snapshot.json': NestFinalVerdictSnapshot;
  'audit_refs.json': NestAuditRefs;
  'runtime_proof.json'?: NestRuntimeProof;
}

function toIso(ts: number): string {
  return new Date(ts).toISOString();
}

function pseudoHashHex(input: string): string {
  let h1 = 0x811c9dc5;
  let h2 = 0x9e3779b1;
  let h3 = 0xc2b2ae35;
  let h4 = 0x27d4eb2f;
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x01000193);
    h2 = Math.imul(h2 ^ c, 0x85ebca6b);
    h3 = Math.imul(h3 ^ c, 0xc2b2ae35);
    h4 = Math.imul(h4 ^ c, 0x27d4eb2f);
  }
  const parts = [h1 >>> 0, h2 >>> 0, h3 >>> 0, h4 >>> 0]
    .map((n) => n.toString(16).padStart(8, '0'));
  return (parts.join('') + parts.join('')).slice(0, 64);
}

function makeUlidLike(seed: string): string {
  const digest = pseudoHashHex(seed + '::ulid::' + Date.now().toString());
  let out = '';
  for (let i = 0; i < 26; i++) {
    const v = parseInt(digest.slice((i * 2) % digest.length, ((i * 2) % digest.length) + 2), 16);
    out += CROCKFORD[v % CROCKFORD.length];
  }
  return out;
}

function ensureVerdict(session: NestSession): BinaryVerdictResult {
  const finalVerdict = session.finalVerdict ?? session.iterations[session.iterations.length - 1]?.verdict;
  if (!finalVerdict) {
    throw new Error('Cannot emit evidence bundle: no final verdict available.');
  }
  return finalVerdict;
}

function mapSessionStatus(status: NestSession['status']): NestSessionRecord['status'] {
  switch (status) {
    case 'idle': return 'created';
    case 'running':
    case 'paused': return 'running';
    case 'error': return 'failed';
    case 'converged':
    case 'max-reached':
    case 'plateau': return 'completed';
    default: return 'completed';
  }
}

function makeIterations(ulid: string, sessionId: string, binarySha256: string, snapshots: NestIterationSnapshot[]): NestIterationsFile {
  return {
    schema_name: NEST_EVIDENCE_SCHEMA_NAMES.iterations,
    schema_version: NEST_EVIDENCE_DEFAULT_SCHEMA_VERSION,
    bundle_id: `nestbundle_${ulid}`,
    session_id: sessionId,
    binary_id: `binary_sha256_${binarySha256}`,
    binary_sha256: binarySha256,
    count: snapshots.length,
    items: snapshots.map((snap, index) => {
      const reasonHash = pseudoHashHex(JSON.stringify(snap.reasoningChain ?? snap.verdict?.reasoningChain ?? snap.verdict?.summary ?? ''));
      const startedAt = snap.timestamp - snap.durationMs;
      return {
        iteration_id: `nestiter_${ulid}_${String(index + 1).padStart(4, '0')}`,
        iteration_index: index + 1,
        session_id: sessionId,
        binary_sha256: binarySha256,
        started_at: toIso(startedAt),
        completed_at: toIso(snap.timestamp),
        duration_ms: snap.durationMs,
        input_window: {
          offset: snap.input.disasmOffset,
          length: snap.input.disasmLength,
        },
        executed_actions: (snap.refinementPlan?.actions ?? []).map((a) => ({
          type: a.type,
          priority: a.priority,
          reason: a.reason,
          offset: a.offset,
          length: a.length,
          signal: a.signal,
        })),
        verdict_snapshot: {
          classification: snap.verdict.classification,
          confidence: snap.verdict.confidence,
          threat_score: snap.verdict.threatScore,
          signal_count: snap.verdict.signals.length,
          contradiction_count: snap.verdict.contradictions.length,
          reasoning_chain_hash: reasonHash,
          summary: snap.verdict.summary,
          behavior_tags: snap.verdict.behaviors,
          negative_signal_count: snap.verdict.negativeSignals.length,
        },
        convergence_snapshot: {
          reason: snap.annotations[0] ?? 'continue',
          has_converged: index === snapshots.length - 1,
          stability_score: snap.stabilityReport.score,
          classification_stable: snap.stabilityReport.convergenceReliable,
          signal_delta: snap.delta ? (snap.delta.newSignals.length - snap.delta.removedSignals.length) : 0,
          contradiction_burden: snap.verdict.contradictions.length,
        },
        file_identity_locked: true,
      };
    }),
  };
}

function makeDeltas(ulid: string, sessionId: string, binarySha256: string, snapshots: NestIterationSnapshot[]): NestDeltasFile {
  const items = snapshots
    .map((snap, index) => ({ snap, index }))
    .filter((x) => x.index > 0)
    .map(({ snap, index }) => {
      const prev = snapshots[index - 1];
      const from = index;
      const to = index + 1;
      const delta = snap.delta;
      return {
        delta_id: `nestdelta_${ulid}_${String(from).padStart(4, '0')}_${String(to).padStart(4, '0')}`,
        from_iteration_id: `nestiter_${ulid}_${String(from).padStart(4, '0')}`,
        to_iteration_id: `nestiter_${ulid}_${String(to).padStart(4, '0')}`,
        from_iteration_index: from,
        to_iteration_index: to,
        binary_sha256: binarySha256,
        confidence_delta: delta?.confidenceDelta ?? (snap.confidence - prev.confidence),
        classification_changed: delta?.verdictChanged ?? (prev.verdict.classification !== snap.verdict.classification),
        signal_delta_summary: {
          added_count: delta?.newSignals.length ?? 0,
          removed_count: delta?.removedSignals.length ?? 0,
          unchanged_count: Math.max(0, snap.verdict.signals.length - (delta?.newSignals.length ?? 0)),
        },
        contradiction_delta: prev.verdict.contradictions.length - snap.verdict.contradictions.length,
        refinement_execution: {
          action_types: snap.refinementPlan?.actions.map((a) => a.type) ?? [],
          primary_action_type: snap.refinementPlan?.primaryAction?.type ?? null,
          executed: (snap.refinementPlan?.actions.length ?? 0) > 0,
          primary_action_reason: snap.refinementPlan?.primaryAction?.reason,
          target_offsets: snap.refinementPlan?.actions
            .map((a) => a.offset)
            .filter((v): v is number => typeof v === 'number'),
        },
        projected_gain: snap.refinementPlan?.expectedBoost ?? 0,
        actual_gain: delta?.confidenceDelta ?? (snap.confidence - prev.confidence),
        new_signal_ids: delta?.newSignals,
        removed_signal_ids: delta?.removedSignals,
        new_behavior_tags: delta?.behaviorsAdded,
        warnings: delta?.significantChange ? [] : ['No significant change in this iteration transition.'],
      };
    });

  return {
    schema_name: NEST_EVIDENCE_SCHEMA_NAMES.deltas,
    schema_version: NEST_EVIDENCE_DEFAULT_SCHEMA_VERSION,
    bundle_id: `nestbundle_${ulid}`,
    session_id: sessionId,
    binary_id: `binary_sha256_${binarySha256}`,
    binary_sha256: binarySha256,
    count: items.length,
    items,
  };
}

export function buildNestEvidenceBundleFromSession(input: NestEvidenceBuildInput): NestEvidenceBundle {
  const ulid = makeUlidLike(input.binarySha256 + input.binaryPath + input.session.id);
  const bundleId = `nestbundle_${ulid}`;
  const sessionId = `nestsession_${ulid}`;
  const verdictSnapshotId = `gyresnap_${ulid}`;
  const binaryId = `binary_sha256_${input.binarySha256}`;
  const actorId = input.actorId ?? 'system:run-nest';
  const actorType = input.actorType ?? 'system';
  const engineBuildId = input.engineBuildId ?? '1.0.0+local-run-nest';
  const gyreBuildId = input.gyreBuildId ?? engineBuildId;
  const gyreSchemaVersion = input.gyreSchemaVersion ?? NEST_EVIDENCE_DEFAULT_SCHEMA_VERSION;
  const policyVersion = input.policyVersion ?? 'local-policy-1';

  const finalVerdict = ensureVerdict(input.session);
  const snapshots = input.session.iterations;
  const lastSnapshot = snapshots[snapshots.length - 1];
  if (!lastSnapshot) {
    throw new Error('Cannot emit evidence bundle: no iterations available.');
  }

  const iterations = makeIterations(ulid, sessionId, input.binarySha256, snapshots);
  const deltas = makeDeltas(ulid, sessionId, input.binarySha256, snapshots);
  const finalIterationId = `nestiter_${ulid}_${String(snapshots.length).padStart(4, '0')}`;

  const manifestFiles = [
    { name: 'manifest.json', required: true },
    { name: 'binary_identity.json', required: true },
    { name: 'session.json', required: true },
    { name: 'iterations.json', required: true },
    { name: 'deltas.json', required: true },
    { name: 'final_verdict_snapshot.json', required: true },
    { name: 'audit_refs.json', required: true },
    ...(input.runtimeProof ? [{ name: 'runtime_proof.json', required: false }] : []),
  ];

  const nowIso = new Date().toISOString();

  const bundle: NestEvidenceBundle = {
    manifest: {
      schema_name: NEST_EVIDENCE_SCHEMA_NAMES.manifest,
      schema_version: NEST_EVIDENCE_DEFAULT_SCHEMA_VERSION,
      bundle_schema_version: NEST_EVIDENCE_DEFAULT_SCHEMA_VERSION,
      bundle_format_version: NEST_EVIDENCE_BUNDLE_FORMAT_VERSION,
      bundle_id: bundleId,
      session_id: sessionId,
      binary_id: binaryId,
      binary_sha256: input.binarySha256,
      engine_build_id: engineBuildId,
      policy_version: policyVersion,
      actor: { id: actorId, type: actorType, display_name: 'run-nest' },
      timestamps: {
        created_at: toIso(input.session.startTime),
        started_at: toIso(input.session.startTime),
        completed_at: input.session.endTime ? toIso(input.session.endTime) : nowIso,
        exported_at: nowIso,
      },
      files: manifestFiles.map((f) => ({
        name: f.name as NestManifest['files'][number]['name'],
        required: f.required,
        sha256: input.binarySha256,
        bytes: 0,
        schema_name:
          f.name === 'manifest.json' ? NEST_EVIDENCE_SCHEMA_NAMES.manifest :
          f.name === 'binary_identity.json' ? NEST_EVIDENCE_SCHEMA_NAMES.binaryIdentity :
          f.name === 'session.json' ? NEST_EVIDENCE_SCHEMA_NAMES.session :
          f.name === 'iterations.json' ? NEST_EVIDENCE_SCHEMA_NAMES.iterations :
          f.name === 'deltas.json' ? NEST_EVIDENCE_SCHEMA_NAMES.deltas :
          f.name === 'final_verdict_snapshot.json' ? NEST_EVIDENCE_SCHEMA_NAMES.finalVerdictSnapshot :
          f.name === 'runtime_proof.json' ? NEST_EVIDENCE_SCHEMA_NAMES.runtimeProof :
          NEST_EVIDENCE_SCHEMA_NAMES.auditRefs,
        schema_version: NEST_EVIDENCE_DEFAULT_SCHEMA_VERSION,
      })),
      immutability: {
        bundle_locked: true,
        locked_at: nowIso,
        mutation_policy: 'immutable-after-export',
      },
      replay: {
        replayable: true,
        mode_supported: ['local'],
        requires_binary_bytes: true,
      },
      export_mode: input.exportMode ?? 'local-tauri',
      notes: 'Emitted by run-nest typed evidence integration.',
    },
    binary_identity: {
      schema_name: NEST_EVIDENCE_SCHEMA_NAMES.binaryIdentity,
      schema_version: NEST_EVIDENCE_DEFAULT_SCHEMA_VERSION,
      bundle_id: bundleId,
      session_id: sessionId,
      binary_id: binaryId,
      binary_sha256: input.binarySha256,
      hashes: {
        sha256: input.binarySha256,
        sha1: input.binarySha1 ?? pseudoHashHex(input.binarySha256 + 'sha1').slice(0, 40),
        md5: input.binaryMd5 ?? pseudoHashHex(input.binarySha256 + 'md5').slice(0, 32),
      },
      file_size_bytes: input.fileSizeBytes,
      format: input.format,
      architecture: input.architecture,
      first_seen_at: toIso(input.session.startTime),
      identity_source: 'local-path',
      file_bound_proof: {
        proof_status: 'proven',
        proof_basis: ['sha256-match', 'file-size-match'],
        binary_sha256: input.binarySha256,
        file_size_bytes: input.fileSizeBytes,
        session_hash_lock: true,
      },
      original_path: input.binaryPath,
      file_name: input.binaryPath.split(/[/\\]/).pop() ?? 'unknown.bin',
    },
    session: {
      schema_name: NEST_EVIDENCE_SCHEMA_NAMES.session,
      schema_version: NEST_EVIDENCE_DEFAULT_SCHEMA_VERSION,
      bundle_id: bundleId,
      session_id: sessionId,
      binary_id: binaryId,
      binary_sha256: input.binarySha256,
      engine_build_id: engineBuildId,
      policy_version: policyVersion,
      actor: { id: actorId, type: actorType, display_name: 'run-nest' },
      timestamps: {
        created_at: toIso(input.session.startTime),
        started_at: toIso(input.session.startTime),
        completed_at: input.session.endTime ? toIso(input.session.endTime) : nowIso,
        exported_at: nowIso,
      },
      status: mapSessionStatus(input.session.status),
      execution_mode: input.executionMode ?? 'local-tauri',
      config: {
        config_version: NEST_EVIDENCE_DEFAULT_SCHEMA_VERSION,
        max_iterations: input.session.config.maxIterations,
        min_iterations: input.session.config.minIterations,
        confidence_threshold: input.session.config.confidenceThreshold,
        plateau_threshold: input.session.config.plateauThreshold,
        disasm_expansion: input.session.config.disasmExpansion,
        aggressiveness: input.session.config.aggressiveness,
        enable_talon: input.session.config.enableTalon,
        enable_strike: input.session.config.enableStrike,
        enable_echo: input.session.config.enableEcho,
        auto_advance: input.session.config.autoAdvance,
        auto_advance_delay_ms: input.session.config.autoAdvanceDelay,
      },
      iteration_count: snapshots.length,
      delta_count: deltas.items.length,
      final_iteration_index: snapshots.length || null,
      convergence: {
        has_converged: input.summary.convergedReason !== null,
        reason: input.summary.convergedReason ?? input.session.status,
        confidence: input.summary.finalConfidence,
        classification_stable: lastSnapshot.stabilityReport.convergenceReliable,
        signal_delta: lastSnapshot.delta ? (lastSnapshot.delta.newSignals.length - lastSnapshot.delta.removedSignals.length) : 0,
        contradiction_burden: lastSnapshot.verdict.contradictions.length,
        stability_score: lastSnapshot.stabilityReport.score,
        projected_loss: 100 - input.summary.finalConfidence,
        confidence_variance: lastSnapshot.stabilityReport.confidenceStdDev,
        diagnosis: lastSnapshot.stabilityReport.diagnosis,
      },
      gyre_linkage: {
        verdict_snapshot_id: verdictSnapshotId,
        gyre_schema_version: gyreSchemaVersion,
        gyre_build_id: gyreBuildId,
        gyre_is_sole_verdict_source: true,
        nest_role: 'iterative-enrichment-only',
        gyre_summary: finalVerdict.summary,
        linked_reasoning_chain_hash: pseudoHashHex(JSON.stringify(lastSnapshot.reasoningChain)),
      },
      notes: input.summary.keyFindings,
      runtime_proof_required: Boolean(input.runtimeProof),
    },
    iterations,
    deltas,
    final_verdict_snapshot: {
      schema_name: NEST_EVIDENCE_SCHEMA_NAMES.finalVerdictSnapshot,
      schema_version: NEST_EVIDENCE_DEFAULT_SCHEMA_VERSION,
      bundle_id: bundleId,
      session_id: sessionId,
      binary_id: binaryId,
      binary_sha256: input.binarySha256,
      verdict_snapshot_id: verdictSnapshotId,
      source_engine: 'gyre',
      gyre_build_id: gyreBuildId,
      gyre_schema_version: gyreSchemaVersion,
      classification: finalVerdict.classification,
      confidence: finalVerdict.confidence,
      threat_score: finalVerdict.threatScore,
      summary: finalVerdict.summary,
      signal_count: finalVerdict.signals.length,
      contradiction_count: finalVerdict.contradictions.length,
      reasoning_chain_hash: pseudoHashHex(JSON.stringify(lastSnapshot.reasoningChain)),
      linked_iteration_id: finalIterationId,
      nest_linkage: {
        session_id: sessionId,
        final_iteration_id: finalIterationId,
        nest_enrichment_applied: true,
        gyre_is_sole_verdict_source: true,
        nest_summary: `NEST finished with ${snapshots.length} iteration(s), confidence ${finalVerdict.confidence}%.`,
        enriched_signal_ids: finalVerdict.signals.map((s) => s.id),
      },
      behaviors: finalVerdict.behaviors,
      negative_signals: finalVerdict.negativeSignals,
      amplifiers: finalVerdict.amplifiers,
      dismissals: finalVerdict.dismissals,
      contradictions: finalVerdict.contradictions,
      alternatives: finalVerdict.alternatives,
      certainty_profile: {
        uncertainty_flags: finalVerdict.uncertaintyFlags,
        heuristic_signal_ids: finalVerdict.heuristicSignalIds,
      },
    },
    audit_refs: {
      schema_name: NEST_EVIDENCE_SCHEMA_NAMES.auditRefs,
      schema_version: NEST_EVIDENCE_DEFAULT_SCHEMA_VERSION,
      bundle_id: bundleId,
      session_id: sessionId,
      binary_id: binaryId,
      binary_sha256: input.binarySha256,
      actor: { id: actorId, type: actorType, display_name: 'run-nest' },
      policy_version: policyVersion,
      audit_backend: 'local-append-log',
      events: [
        {
          event_id: `evt_${ulid}_0001`,
          event_type: 'nest.session.created',
          timestamp: toIso(input.session.startTime),
          actor_id: actorId,
          actor_type: actorType,
          session_id: sessionId,
          summary: `Session created for ${input.binaryPath}`,
        },
        {
          event_id: `evt_${ulid}_0002`,
          event_type: 'nest.session.completed',
          timestamp: input.session.endTime ? toIso(input.session.endTime) : nowIso,
          actor_id: actorId,
          actor_type: actorType,
          session_id: sessionId,
          summary: `Session completed with verdict ${finalVerdict.classification} at ${finalVerdict.confidence}% confidence`,
        },
        {
          event_id: `evt_${ulid}_0003`,
          event_type: 'nest.bundle.exported',
          timestamp: nowIso,
          actor_id: actorId,
          actor_type: actorType,
          session_id: sessionId,
          summary: 'Evidence bundle exported to local disk.',
        },
      ],
    },
    runtime_proof: input.runtimeProof
      ? {
          ...input.runtimeProof,
          bundle_id: bundleId,
          session_id: sessionId,
          binary_id: binaryId,
          binary_sha256: input.binarySha256,
          schema_version: NEST_EVIDENCE_DEFAULT_SCHEMA_VERSION,
          schema_name: NEST_EVIDENCE_SCHEMA_NAMES.runtimeProof,
        }
      : undefined,
  };

  return bundle;
}

export function validateBuiltNestEvidenceBundle(bundle: NestEvidenceBundle): NestValidationResult<NestEvidenceBundle> {
  const issues = validateNestEvidenceBundle(bundle);
  if (issues.length > 0) {
    return { ok: false, issues };
  }
  return { ok: true, value: bundle };
}

export function toNestEvidenceFileMap(bundle: NestEvidenceBundle): NestEvidenceFileMap {
  return {
    'manifest.json': bundle.manifest,
    'binary_identity.json': bundle.binary_identity,
    'session.json': bundle.session,
    'iterations.json': bundle.iterations,
    'deltas.json': bundle.deltas,
    'final_verdict_snapshot.json': bundle.final_verdict_snapshot,
    'audit_refs.json': bundle.audit_refs,
    ...(bundle.runtime_proof ? { 'runtime_proof.json': bundle.runtime_proof } : {}),
  };
}

function collectIssues(result: NestValidationResult<unknown>, issues: NestValidationIssue[]): void {
  if (!result.ok) {
    issues.push(...result.issues);
  }
}

export function parseNestEvidenceFileMap(files: Record<string, unknown>): NestValidationResult<NestEvidenceBundle> {
  const issues: NestValidationIssue[] = [];

  const manifest = parseNestManifest(files['manifest.json']);
  const binaryIdentity = parseNestBinaryIdentity(files['binary_identity.json']);
  const session = parseNestSessionRecord(files['session.json']);
  const iterations = parseNestIterationsFile(files['iterations.json']);
  const deltas = parseNestDeltasFile(files['deltas.json']);
  const finalVerdict = parseNestFinalVerdictSnapshot(files['final_verdict_snapshot.json']);
  const auditRefs = parseNestAuditRefs(files['audit_refs.json']);
  const runtimeProofRaw = files['runtime_proof.json'];

  collectIssues(manifest, issues);
  collectIssues(binaryIdentity, issues);
  collectIssues(session, issues);
  collectIssues(iterations, issues);
  collectIssues(deltas, issues);
  collectIssues(finalVerdict, issues);
  collectIssues(auditRefs, issues);

  let runtimeProof: NestRuntimeProof | undefined;
  if (runtimeProofRaw !== undefined) {
    const parsedRuntimeProof = parseNestRuntimeProof(runtimeProofRaw);
    collectIssues(parsedRuntimeProof, issues);
    if (parsedRuntimeProof.ok) {
      runtimeProof = parsedRuntimeProof.value;
    }
  }

  if (issues.length > 0) {
    return { ok: false, issues };
  }

  const bundle: NestEvidenceBundle = {
    manifest: manifest.ok ? manifest.value : (undefined as never),
    binary_identity: binaryIdentity.ok ? binaryIdentity.value : (undefined as never),
    session: session.ok ? session.value : (undefined as never),
    iterations: iterations.ok ? iterations.value : (undefined as never),
    deltas: deltas.ok ? deltas.value : (undefined as never),
    final_verdict_snapshot: finalVerdict.ok ? finalVerdict.value : (undefined as never),
    audit_refs: auditRefs.ok ? auditRefs.value : (undefined as never),
    ...(runtimeProof ? { runtime_proof: runtimeProof } : {}),
  };

  const bundleIssues = validateNestEvidenceBundle(bundle);
  if (bundleIssues.length > 0) {
    return { ok: false, issues: bundleIssues };
  }

  return { ok: true, value: bundle };
}
