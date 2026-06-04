import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  decideBoundary,
  evaluateConfidence,
  exportPackageOnlyLineage,
  makeFrame,
  makeReplayBundle,
  planMutation,
  replayStrict,
  validateFrame,
  generateReviewQueue,
  detectReplayDrift,
  explainReplay,
  counterfactualReplay,
  loadFrameFile,
  loadEvidenceGraphFile,
  loadMutationLedgerFile,
  loadReplayBundleFile,
  validateAdapterContract,
  makeHexHawkAdapterContract,
  makeHexHawkAdapterFrame,
  runAetherFrameCli,
  createAdapterRegistry,
  registerAdapterContract,
  validateAdapterFrameAgainstContract,
  negotiateSchemaVersion,
  migrateAetherFrameArtifact,
  saveReplayBundleFile,
  loadPersistentReplayBundleFile,
  appendAuditLogEntry,
  readAuditLogFile,
  createReplayBundleStore,
  verifyAuditLogChain,
  createMigrationRegistry,
  registerMigration,
  dryRunMigration,
  discoverAdapterManifests,
  loadAdapterRegistryFromManifests,
  type AetherFrameEvidenceGraph,
  type AetherFrameMutationProposal,
} from '../index';

const __dirname = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(__dirname, '../..');

const frame = makeFrame({
  frameId: 'frame-hexhawk-adapter-example',
  frameName: 'HexHawk adapter boundary example',
  domain: 'security-analysis',
  objective: 'Package HexHawk evidence without altering GYRE verdict truth.',
  operatingMode: 'package_only',
  authorityModel: {
    soleAuthorityFields: ['classification', 'base_confidence', 'source_engine'],
    advisoryFields: ['aetherframe_lineage', 'proof_limits'],
    derivedFields: ['confidence_breakdown'],
    inheritedFields: ['binary_identity'],
    blockedFields: ['gyre_is_sole_verdict_source'],
    humanReviewRequiredFields: ['external_public_claim'],
  },
  protectedFields: ['classification', 'base_confidence', 'source_engine', 'gyre_is_sole_verdict_source'],
  mutableFields: ['aetherframe_lineage', 'proof_limits'],

});
const graph: AetherFrameEvidenceGraph = {
  schemaVersion: 'aetherframe.evidence_graph.v1',
  graphId: 'graph-fixture-001',
  frameId: frame.frameId,
  nodes: [
    {
      id: 'source-gyre-verdict',
      kind: 'SourceNode',
      timestamp: '2026-06-03T00:00:00.000Z',
      source: 'gyre',
      sourceReliability: 0.95,
      rawValue: { classification: 'suspicious' },
      normalizedValue: 'suspicious',
      confidence: 0.84,
      uncertaintyInterval: { low: 0.78, high: 0.9 },
      provenance: ['fixture'],
      redactionLevel: 'none',
      replaySafe: true,
      reportable: true,
      protectedFieldInteraction: ['classification'],
      frameId: frame.frameId,
      proofLimits: ['fixture verdict source only'],
    },
    {
      id: 'contradiction-weak-source',
      kind: 'ContradictionNode',
      timestamp: '2026-06-03T00:00:01.000Z',
      source: 'low-reliability-secondary-source',
      sourceReliability: 0.35,
      rawValue: 'secondary source disagrees without reproducible measurement',
      normalizedValue: 'weak contradiction',
      confidence: 0.4,
      uncertaintyInterval: { low: 0.2, high: 0.75 },
      provenance: ['fixture'],
      redactionLevel: 'none',
      replaySafe: true,
      reportable: true,
      protectedFieldInteraction: [],
      frameId: frame.frameId,
      proofLimits: ['contradiction is intentionally weak but must still clamp uplift'],
    },
  ],
  edges: [
    {
      id: 'edge-gyre-to-breakdown',
      fromNodeIds: ['source-gyre-verdict'],
      toNodeId: 'confidence-breakdown',
      relationshipType: 'supports',
      transformationName: 'fixture-confidence-input',
      transformationVersion: '1.0.0',
      transformationKind: 'deterministic',
      confidenceContribution: 0.84,
      proofLimits: ['fixture support only'],
    },
  ],
};

describe('AetherFrame core vNext scaffold', () => {
  it('creates a product-agnostic frame with explicit authority boundaries', () => {
    expect(frame.schemaVersion).toBe('aetherframe.frame.v1');
    expect(frame.operatingMode).toBe('package_only');
    expect(frame.authorityModel.soleAuthorityFields).toContain('classification');
    expect(frame.protectedFields).toContain('gyre_is_sole_verdict_source');
    expect(frame.adapterKind).toBe('core');
  });

  it('blocks protected-field mutation and records the blocked decision as lineage', () => {
    const decision = decideBoundary(frame, {
      field: 'classification',
      operation: 'mutate',
      reason: 'attempted adapter override',
    });

    expect(decision.decision).toBe('blocked');
    expect(decision.lineageNode.kind).toBe('PolicyGateNode');
    expect(decision.lineageNode.protectedFieldInteraction).toContain('classification');
    expect(decision.proofLimits.join(' ')).toContain('protected');
  });

  it('allows package-only metadata while preserving core content mutation boundaries', () => {
    const decision = decideBoundary(frame, {
      field: 'aetherframe_lineage',
      operation: 'attach_metadata',
      reason: 'append lineage appendix',
    });

    expect(decision.decision).toBe('allowed_metadata_only');
    expect(decision.requiresReview).toBe(false);
  });

  it('decomposes confidence with contradiction dominance and policy clamp', () => {
    const confidence = evaluateConfidence(frame, graph, {
      baseAuthorityConfidence: 84,
      evidenceSupport: 18,
      sourceReliability: 0.95,
      measurementQuality: 0.82,
      reproducibility: 0.7,
      contradictionBurden: 0.62,
      recencyDays: 0,
      consensusStrength: 0.55,
      modelUncertainty: 0.35,
      humanReviewStatus: 'not_reviewed',
      domainRisk: 0.4,
      mutationRisk: 0.2,
      rollbackConfidence: 0.9,
      maximumAllowedDelta: 5,
    });

    expect(confidence.baseConfidence).toBe(84);
    expect(confidence.allowedConfidence).toBeLessThanOrEqual(84);
    expect(confidence.upliftDelta).toBeLessThanOrEqual(0);
    expect(confidence.contradictionPenalty).toBeGreaterThan(confidence.sourceReliabilityAdjustment);
    expect(confidence.policyClampReason).toContain('package_only');
    expect(confidence.requiredNextEvidence.length).toBeGreaterThan(0);
  });

  it('requires rollback for destructive mutation proposals and records blocked lineage', () => {
    const proposal: AetherFrameMutationProposal = {
      mutationId: 'mutation-delete-authority-field',
      frameId: frame.frameId,
      target: 'classification',
      mutationType: 'code_edit',
      proposedChange: 'replace classification',
      rationale: 'test unsafe mutation',
      evidenceUsed: ['source-gyre-verdict'],
      protectedFieldsTouched: ['classification'],
      riskLevel: 'high',
      reversibility: 'none',
      rollbackPlan: null,
      requiredApproval: 'human',
      stopConditions: ['protected field touched'],
      expectedOutcome: 'should be blocked',
      failureSignal: 'policy allowed unsafe mutation',
    };

    const plan = planMutation(frame, proposal);
    expect(plan.policyDecision.decision).toBe('blocked');
    expect(plan.blockedLineage.kind).toBe('MutationBlockedNode');
    expect(plan.blockedLineage.proofLimits.join(' ')).toContain('rollback');
  });

  it('exports package-only lineage without altering authoritative content', () => {
    const exported = exportPackageOnlyLineage(frame, graph, 'authoritative report body');
    expect(exported.content).toBe('authoritative report body');
    expect(exported.lineage.frameId).toBe(frame.frameId);
    expect(exported.lineage.protectedFields).toContain('classification');
    expect(exported.lineage.mutationsBlocked).toEqual(expect.arrayContaining(['classification']));
  });

  it('replays deterministically except for explicitly generated timestamps', () => {
    const bundle = makeReplayBundle({
      replayId: 'replay-fixture-001',
      frame,
      evidenceGraph: graph,
      generatedAt: '2026-06-03T00:00:02.000Z',
    });

    const first = replayStrict(bundle);
    const second = replayStrict({ ...bundle, generatedAt: '2026-06-03T00:01:02.000Z' });

    expect(first.stableDigest).toBe(second.stableDigest);
    expect(first.boundaryDecisions).toEqual(second.boundaryDecisions);
    expect(first.lineage.frameId).toBe(frame.frameId);
  });

  it('provides a HexHawk adapter stub that keeps GYRE/NEST fields protected without making AetherFrame product-specific', () => {
    const adapterFrame = makeHexHawkAdapterFrame();
    expect(adapterFrame.adapterKind).toBe('hexhawk');
    expect(adapterFrame.operatingMode).toBe('package_only');
    expect(adapterFrame.protectedFields).toEqual(expect.arrayContaining([
      'classification',
      'source_engine',
      'gyre_is_sole_verdict_source',
      'nest_evidence_selection',
    ]));

    const decision = decideBoundary(adapterFrame, {
      field: 'classification',
      operation: 'mutate',
      reason: 'adapter must not alter GYRE truth',
    });
    expect(decision.decision).toBe('blocked');
  });

  it('validates frame schemas and rejects unknown high-risk operating modes', () => {
    const valid = validateFrame(frame);
    expect(valid.valid).toBe(true);

    const invalid = validateFrame({
      ...frame,
      operatingMode: 'unbounded_auto_mutation',
    } as unknown);

    expect(invalid.valid).toBe(false);
    expect(invalid.errors.join(' ')).toContain('operatingMode');
    expect(invalid.errors.join(' ')).toContain('unknown');
  });

  it('generates review queue items for contradictions, uncertainty, protected mutation risk, and boundary warnings', () => {
    const proposal: AetherFrameMutationProposal = {
      mutationId: 'mutation-review-risk',
      frameId: frame.frameId,
      target: 'classification',
      mutationType: 'text_refinement',
      proposedChange: 'soften verdict wording',
      rationale: 'unsafe review fixture',
      evidenceUsed: ['source-gyre-verdict', 'contradiction-weak-source'],
      protectedFieldsTouched: ['classification'],
      riskLevel: 'high',
      reversibility: 'manual',
      rollbackPlan: 'restore authoritative source text',
      requiredApproval: 'human',
      stopConditions: ['protected field touched'],
      expectedOutcome: 'should be queued for review',
      failureSignal: 'protected mutation silently allowed',
    };

    const queue = generateReviewQueue(frame, graph, [proposal]);
    expect(queue.map(item => item.kind)).toEqual(expect.arrayContaining([
      'contradiction_map',
      'uncertainty_hotspot',
      'highest_risk_mutation',
      'authority_boundary_warning',
    ]));
    expect(queue.some(item => item.blocksMutation && item.requiresHumanReview)).toBe(true);
    expect(queue.every(item => item.affectedNodeIds.length > 0 || item.affectedFields.length > 0)).toBe(true);
  });

  it('detects strict replay drift when replay-relevant evidence changes but ignores generated timestamps', () => {
    const bundle = makeReplayBundle({
      replayId: 'replay-drift-fixture',
      frame,
      evidenceGraph: graph,
      generatedAt: '2026-06-03T00:00:02.000Z',
    });
    const unchanged = detectReplayDrift(bundle, { ...bundle, generatedAt: '2026-06-03T00:09:02.000Z' });
    expect(unchanged.driftDetected).toBe(false);

    const changedGraph: AetherFrameEvidenceGraph = {
      ...graph,
      nodes: graph.nodes.map(node => node.id === 'source-gyre-verdict' ? { ...node, normalizedValue: 'changed' } : node),
    };
    const changed = detectReplayDrift(bundle, { ...bundle, evidenceGraph: changedGraph });
    expect(changed.driftDetected).toBe(true);
    expect(changed.changedSections).toContain('evidenceGraph');
  });

  it('ships versioned JSON schemas and validates runtime-loaded fixture files', () => {
    for (const schemaName of ['frame.schema.json', 'evidence_graph.schema.json', 'mutation_ledger.schema.json', 'replay_bundle.schema.json']) {
      expect(existsSync(join(packageRoot, 'schemas', schemaName))).toBe(true);
    }

    const fixtureDir = join(packageRoot, 'fixtures');
    expect(readdirSync(fixtureDir).sort()).toEqual(expect.arrayContaining([
      'empty_evidence_graph.json',
      'single_strong_source.json',
      'conflicting_sources.json',
      'stale_evidence.json',
      'low_reliability_source.json',
      'protected_field_mutation_attempt.json',
      'package_only_export.json',
      'high_assurance_clamp.json',
      'replay_exact_match.json',
      'replay_drift.json',
      'invalid_unknown_operating_mode.json',
      'invalid_missing_authority_model.json',
      'invalid_malformed_evidence_node.json',
      'invalid_replay_frame_graph_mismatch.json',
      'invalid_protected_mutation_without_rollback.json',
    ]));

    expect(loadFrameFile(join(fixtureDir, 'single_strong_source.json')).valid).toBe(true);
    expect(loadEvidenceGraphFile(join(fixtureDir, 'empty_evidence_graph.json')).value.nodes).toHaveLength(0);
    expect(loadMutationLedgerFile(join(fixtureDir, 'protected_field_mutation_attempt.json')).value.mutations).toHaveLength(1);
    expect(loadReplayBundleFile(join(fixtureDir, 'replay_exact_match.json')).value.schemaVersion).toBe('aetherframe.replay_bundle.v1');
  });

  it('supports explain replay and counterfactual replay without transferring authority', () => {
    const bundle = makeReplayBundle({
      replayId: 'replay-explain-fixture',
      frame,
      evidenceGraph: graph,
      generatedAt: '2026-06-03T00:00:02.000Z',
    });

    const explained = explainReplay(bundle);
    expect(explained.mode).toBe('explain_replay');
    expect(explained.commentary.join(' ')).toContain('does not prove external-world truth');
    expect(explained.strict.stableDigest).toBe(replayStrict(bundle).stableDigest);

    const counterfactual = counterfactualReplay(bundle, {
      operatingMode: 'high_assurance',
      confidencePolicy: { ...frame.confidencePolicy, maximumAllowedDelta: 0 },
    });
    expect(counterfactual.mode).toBe('counterfactual_replay');
    expect(counterfactual.counterfactualFrame.operatingMode).toBe('high_assurance');
    expect(counterfactual.changedSections).toContain('frame');
    expect(counterfactual.proofLimits.join(' ')).toContain('counterfactual');
  });

  it('defines an adapter contract separate from the HexHawk adapter frame', () => {
    const contract = makeHexHawkAdapterContract();
    expect(contract.schemaVersion).toBe('aetherframe.adapter_contract.v1');
    expect(contract.adapterKind).toBe('hexhawk');
    expect(contract.authorityModel.soleAuthorityFields).toContain('classification');
    expect(contract.validationCommands).toContain('yarn workspace @hexhawk/aetherframe-core test');
    expect(contract.stopConditions).toContain('attempted mutation of GYRE verdict fields');
    expect(validateAdapterContract(contract).valid).toBe(true);

    const invalid = validateAdapterContract({ ...contract, authorityModel: { ...contract.authorityModel, soleAuthorityFields: [] } });
    expect(invalid.valid).toBe(false);
    expect(invalid.errors.join(' ')).toContain('soleAuthorityFields');
  });

  it('rejects schema negative fixtures with real schema validation errors', () => {
    const fixtureDir = join(packageRoot, 'fixtures');

    const unknownMode = loadFrameFile(join(fixtureDir, 'invalid_unknown_operating_mode.json'));
    expect(unknownMode.valid).toBe(false);
    expect(unknownMode.errors.join(' ')).toContain('/operatingMode');

    const missingAuthority = loadFrameFile(join(fixtureDir, 'invalid_missing_authority_model.json'));
    expect(missingAuthority.valid).toBe(false);
    expect(missingAuthority.errors.join(' ')).toContain("must have required property 'authorityModel'");

    const malformedGraph = loadEvidenceGraphFile(join(fixtureDir, 'invalid_malformed_evidence_node.json'));
    expect(malformedGraph.valid).toBe(false);
    expect(malformedGraph.errors.join(' ')).toContain('/nodes/0');

    const mismatchedReplay = loadReplayBundleFile(join(fixtureDir, 'invalid_replay_frame_graph_mismatch.json'));
    expect(mismatchedReplay.valid).toBe(false);
    expect(mismatchedReplay.errors.join(' ')).toContain('evidenceGraph.frameId must match frame.frameId');

    const unsafeLedger = loadMutationLedgerFile(join(fixtureDir, 'invalid_protected_mutation_without_rollback.json'));
    expect(unsafeLedger.valid).toBe(false);
    expect(unsafeLedger.errors.join(' ')).toContain('rollback');
  });

  it('validates applied mutation ledger entries with before/after/diff/approval/verification/rollback fields', () => {
    const ledger = loadMutationLedgerFile(join(packageRoot, 'fixtures', 'protected_field_mutation_attempt.json'));
    expect(ledger.valid).toBe(true);
    expect(ledger.value.appliedMutations).toHaveLength(1);
    expect(ledger.value.appliedMutations[0]).toMatchObject({
      mutationId: 'mutation-lineage-annotation-applied',
      actor: 'aetherframe.fixture',
      approvalSource: 'package_only metadata policy',
      rollbackStatus: 'not_required',
    });
    expect(ledger.value.appliedMutations[0].beforeSnapshot).toBeDefined();
    expect(ledger.value.appliedMutations[0].afterSnapshot).toBeDefined();
    expect(ledger.value.appliedMutations[0].diff).toContain('+');
    expect(ledger.value.appliedMutations[0].verificationResult.passed).toBe(true);
  });

  it('returns structured CLI failures for invalid inputs', () => {
    const fixtureDir = join(packageRoot, 'fixtures');
    const frameFailure = runAetherFrameCli(['validate-frame', join(fixtureDir, 'invalid_unknown_operating_mode.json')]);
    expect(frameFailure.exitCode).toBe(2);
    expect(frameFailure.stdout.valid).toBe(false);
    expect((frameFailure.stdout.errors as string[]).join(' ')).toContain('/operatingMode');

    const schemaDriftFailure = runAetherFrameCli(['validate-frame', join(fixtureDir, 'invalid_schema_major_drift.json')]);
    expect(schemaDriftFailure.exitCode).toBe(2);
    expect((schemaDriftFailure.stdout.errors as string[]).join(' ')).toContain('unsupported major schema version');

    const replayFailure = runAetherFrameCli(['replay-strict', join(fixtureDir, 'invalid_replay_frame_graph_mismatch.json')]);
    expect(replayFailure.exitCode).toBe(2);
    expect(replayFailure.stdout.valid).toBe(false);
    expect((replayFailure.stdout.errors as string[]).join(' ')).toContain('evidenceGraph.frameId must match frame.frameId');

    const missingArgs = runAetherFrameCli(['review']);
    expect(missingArgs.exitCode).toBe(1);
    expect(missingArgs.stderr).toContain('Usage:');
  });

  it('registers adapter contracts and validates frames against adapter authority contracts', () => {
    const registry = createAdapterRegistry();
    const contract = makeHexHawkAdapterContract();
    registerAdapterContract(registry, contract);

    const adapterFrame = makeHexHawkAdapterFrame();
    expect(validateAdapterFrameAgainstContract(registry, adapterFrame).valid).toBe(true);

    const unsafeFrame = makeFrame({
      frameId: 'unsafe.hexhawk.frame',
      frameName: adapterFrame.frameName,
      frameVersion: adapterFrame.frameVersion,
      domain: adapterFrame.domain,
      objective: adapterFrame.objective,
      operatingMode: adapterFrame.operatingMode,
      adapterKind: adapterFrame.adapterKind,
      authorityModel: { ...adapterFrame.authorityModel, soleAuthorityFields: [] },
      protectedFields: adapterFrame.protectedFields.filter(field => field !== 'classification'),
      mutableFields: adapterFrame.mutableFields,
    });
    const unsafe = validateAdapterFrameAgainstContract(registry, unsafeFrame);
    expect(unsafe.valid).toBe(false);
    expect(unsafe.errors.join(' ')).toContain('classification');
  });

  it('negotiates schema versions, rejects unknown major versions, and exposes explicit migration stubs', () => {
    expect(negotiateSchemaVersion('aetherframe.frame.v1', 'frame')).toMatchObject({ valid: true, major: 1, needsMigration: false });

    const drift = loadFrameFile(join(packageRoot, 'fixtures', 'invalid_schema_major_drift.json'));
    expect(drift.valid).toBe(false);
    expect(drift.errors.join(' ')).toContain('unsupported major schema version');

    const migration = migrateAetherFrameArtifact({ schemaVersion: 'aetherframe.frame.v1', frameId: 'fixture' }, 'aetherframe.frame.v1');
    expect(migration.valid).toBe(true);
    expect(migration.migrated).toBe(false);
    expect(migration.proofLimits.join(' ')).toContain('migration stub');

    const blockedMigration = migrateAetherFrameArtifact({ schemaVersion: 'aetherframe.frame.v2', frameId: 'future' }, 'aetherframe.frame.v1');
    expect(blockedMigration.valid).toBe(false);
    expect(blockedMigration.errors.join(' ')).toContain('unsupported major schema version');
  });

  it('persists replay bundles, verifies stable digest after save/load, and appends audit log entries', () => {
    const dir = mkdtempSync(join(tmpdir(), 'aetherframe-replay-'));
    try {
      const bundle = makeReplayBundle({ replayId: 'persist-fixture', frame, evidenceGraph: graph, generatedAt: '2026-06-03T00:00:02.000Z' });
      const save = saveReplayBundleFile(bundle, join(dir, 'persist-fixture.replay.json'));
      expect(save.valid).toBe(true);
      expect(existsSync(save.path)).toBe(true);
      expect(save.stableDigest).toBe(replayStrict(bundle).stableDigest);

      const loaded = loadPersistentReplayBundleFile(save.path);
      expect(loaded.valid).toBe(true);
      expect(loaded.persistedDigest).toBe(save.stableDigest);
      expect(loaded.recomputedDigest).toBe(save.stableDigest);
      expect(loaded.digestMatches).toBe(true);

      const cliSaved = runAetherFrameCli(['save-replay-bundle', join(packageRoot, 'fixtures', 'replay_exact_match.json'), join(dir, 'cli.replay.json')]);
      expect(cliSaved.exitCode).toBe(0);
      expect(cliSaved.stdout.valid).toBe(true);
      expect(existsSync(join(dir, 'cli.replay.json'))).toBe(true);

      const auditPath = join(dir, 'audit.ndjson');
      const entry = appendAuditLogEntry(auditPath, {
        eventType: 'replay_bundle_saved',
        actor: 'aetherframe.test',
        replayId: bundle.replayId,
        stableDigest: save.stableDigest,
        proofLimits: ['audit log is append-only prototype fixture'],
      });
      expect(entry.sequence).toBe(1);
      const second = appendAuditLogEntry(auditPath, {
        eventType: 'replay_bundle_loaded',
        actor: 'aetherframe.test',
        replayId: bundle.replayId,
        stableDigest: loaded.recomputedDigest,
        proofLimits: ['load event fixture'],
      });
      expect(second.sequence).toBe(2);
      const entries = readAuditLogFile(auditPath);
      expect(entries).toHaveLength(2);
      expect(entries[0].stableDigest).toBe(save.stableDigest);
      expect(readFileSync(auditPath, 'utf8').trim().split('\n')).toHaveLength(2);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('hardens adapter registry against duplicates, incompatible contract versions, and frame diagnostics', () => {
    const registry = createAdapterRegistry();
    const contract = makeHexHawkAdapterContract();
    expect(registerAdapterContract(registry, contract).valid).toBe(true);

    const duplicate = registerAdapterContract(registry, contract);
    expect(duplicate.valid).toBe(false);
    expect(duplicate.errors.join(' ')).toContain('already registered');

    const incompatible = registerAdapterContract(registry, { ...contract, adapterKind: 'hexhawk-future', schemaVersion: 'aetherframe.adapter_contract.v2' as 'aetherframe.adapter_contract.v1' });
    expect(incompatible.valid).toBe(false);
    expect(incompatible.errors.join(' ')).toContain('unsupported major schema version');

    const adapterFrame = makeHexHawkAdapterFrame();
    const diagnosticFrame = makeFrame({
      frameId: 'diagnostic.hexhawk.frame',
      frameName: adapterFrame.frameName,
      frameVersion: '9.0.0',
      domain: adapterFrame.domain,
      objective: adapterFrame.objective,
      operatingMode: adapterFrame.operatingMode,
      adapterKind: adapterFrame.adapterKind,
      protectedFields: ['classification'],
      authorityModel: { ...adapterFrame.authorityModel, blockedFields: [] },
      mutableFields: ['classification'],
    });
    const diagnostics = validateAdapterFrameAgainstContract(registry, diagnosticFrame);
    expect(diagnostics.valid).toBe(false);
    expect(diagnostics.errors.join(' ')).toContain('adapter frame version 9.0.0 is incompatible');
    expect(diagnostics.errors.join(' ')).toContain('must not list protected contract field classification as mutable');
    expect(diagnostics.errors.join(' ')).toContain('missing protected contract fields');
  });

  it('stores replay bundles through a store abstraction and compares persisted versions', () => {
    const dir = mkdtempSync(join(tmpdir(), 'aetherframe-store-'));
    try {
      const store = createReplayBundleStore(dir);
      const original = makeReplayBundle({ replayId: 'store-fixture', frame, evidenceGraph: graph, generatedAt: '2026-06-03T00:00:02.000Z' });
      const changed = makeReplayBundle({
        replayId: 'store-fixture',
        frame: { ...frame, mutableFields: [...frame.mutableFields, 'review_note'] },
        evidenceGraph: graph,
        generatedAt: '2026-06-03T00:00:03.000Z',
      });

      const first = store.save(original);
      const second = store.save(changed);
      expect(first.valid).toBe(true);
      expect(second.valid).toBe(true);
      expect(store.listBundles().map(item => item.replayId)).toEqual(['store-fixture', 'store-fixture']);

      const loaded = store.loadByReplayId('store-fixture');
      expect(loaded.valid).toBe(true);
      expect(loaded.value.replayId).toBe('store-fixture');
      expect(store.verifyDigest(loaded.path).digestMatches).toBe(true);

      const comparison = store.compareVersions(first.path, second.path);
      expect(comparison.driftDetected).toBe(true);
      expect(comparison.changedSections).toContain('frame');

      const summary = store.exportAuditSummary();
      expect(summary.bundleCount).toBe(2);
      expect(summary.replayIds).toEqual(['store-fixture']);
      expect(summary.proofLimits.join(' ')).toContain('external-world truth');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('hash-chains audit log entries and detects tampering', () => {
    const dir = mkdtempSync(join(tmpdir(), 'aetherframe-audit-chain-'));
    try {
      const auditPath = join(dir, 'audit.ndjson');
      const first = appendAuditLogEntry(auditPath, {
        eventType: 'bundle_saved',
        actor: 'test',
        replayId: 'audit-fixture',
        proofLimits: ['fixture event'],
      });
      const second = appendAuditLogEntry(auditPath, {
        eventType: 'bundle_verified',
        actor: 'test',
        replayId: 'audit-fixture',
        proofLimits: ['fixture event'],
      });
      expect(first.previousEntryDigest).toBeNull();
      expect(first.previous_entry_digest).toBeNull();
      expect(first.entryDigest).toMatch(/^fnv1a32:/);
      expect(first.entry_digest).toBe(first.entryDigest);
      expect(second.previousEntryDigest).toBe(first.entryDigest);
      expect(second.previous_entry_digest).toBe(first.entryDigest);

      const verification = verifyAuditLogChain(auditPath);
      expect(verification.valid).toBe(true);
      expect(verification.entryCount).toBe(2);

      const tampered = readFileSync(auditPath, 'utf8').replace('bundle_verified', 'bundle_tampered');
      writeFileSync(auditPath, tampered, 'utf8');
      const tamperCheck = verifyAuditLogChain(auditPath);
      expect(tamperCheck.valid).toBe(false);
      expect(tamperCheck.errors.join(' ')).toContain('entry_digest mismatch');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('hash-chains signed audit log entries and detects signature verification failures', () => {
    const dir = mkdtempSync(join(tmpdir(), 'aetherframe-signed-audit-chain-'));
    try {
      const auditPath = join(dir, 'audit.ndjson');
      const signed = appendAuditLogEntry(auditPath, {
        eventType: 'bundle_saved',
        actor: 'test',
        replayId: 'signed-audit-fixture',
        proofLimits: ['fixture signed event'],
        signingKey: 'fixture-local-signing-key',
      });
      expect(signed.auditSignature).toMatch(/^hmac-sha256:/);
      expect(signed.audit_signature).toBe(signed.auditSignature);
      expect(signed.signatureAlgorithm).toBe('hmac-sha256');
      expect(verifyAuditLogChain(auditPath, 'fixture-local-signing-key').valid).toBe(true);
      const missingKey = verifyAuditLogChain(auditPath);
      expect(missingKey.valid).toBe(false);
      expect(missingKey.errors.join(' ')).toContain('audit_signature present but no verification key was provided');
      const wrongKey = verifyAuditLogChain(auditPath, 'wrong-key');
      expect(wrongKey.valid).toBe(false);
      expect(wrongKey.errors.join(' ')).toContain('audit_signature mismatch');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('registers migrations, dry-runs them, and reports blocked migration diagnostics with proof limits', () => {
    const registry = createMigrationRegistry();
    const registered = registerMigration(registry, 'aetherframe.frame.v1', 'aetherframe.frame.v1', artifact => artifact);
    expect(registered.valid).toBe(true);

    const dryRun = dryRunMigration(registry, { schemaVersion: 'aetherframe.frame.v1', frameId: 'migrate-fixture' }, 'aetherframe.frame.v1');
    expect(dryRun.valid).toBe(true);
    expect(dryRun.dryRun).toBe(true);
    expect(dryRun.migrated).toBe(false);
    expect(dryRun.proofLimits.join(' ')).toContain('dry-run');

    const blocked = dryRunMigration(registry, { schemaVersion: 'aetherframe.frame.v1', frameId: 'blocked-fixture' }, 'aetherframe.frame.v2');
    expect(blocked.valid).toBe(false);
    expect(blocked.blockedDiagnostics.join(' ')).toContain('no registered migration');
    expect(blocked.proofLimits.join(' ')).toContain('blocked');
  });

  it('discovers local adapter manifests, validates schema compatibility, and reports registry loading diagnostics', () => {
    const dir = mkdtempSync(join(tmpdir(), 'aetherframe-adapter-manifest-'));
    try {
      writeFileSync(join(dir, 'hexhawk.adapter.json'), JSON.stringify(makeHexHawkAdapterContract(), null, 2), 'utf8');
      writeFileSync(join(dir, 'invalid.adapter.json'), JSON.stringify({ schemaVersion: 'aetherframe.adapter_contract.v9', adapterKind: 'bad' }, null, 2), 'utf8');

      const discovery = discoverAdapterManifests(dir);
      expect(discovery.manifests).toHaveLength(2);
      expect(discovery.compatibilityReport.validManifests).toBe(1);
      expect(discovery.compatibilityReport.invalidManifests).toBe(1);
      expect(discovery.compatibilityReport.diagnostics.join(' ')).toContain('unsupported major schema version');

      const loaded = loadAdapterRegistryFromManifests(dir);
      expect(loaded.registry.contracts.has('hexhawk')).toBe(true);
      expect(loaded.valid).toBe(false);
      expect(loaded.errors.join(' ')).toContain('unsupported major schema version');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('emits non-UI replay report JSON with boundary decisions, blocked actions, digest, and proof limits', () => {
    const result = runAetherFrameCli(['replay-report', join(packageRoot, 'fixtures', 'replay_exact_match.json')]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout.command).toBe('replay-report');
    expect(result.stdout.valid).toBe(true);
    const report = result.stdout.report as {
      replayId: string;
      stableDigest: string;
      boundaryDecisions: unknown[];
      blockedActions: unknown[];
      proofLimits: string[];
    };
    expect(report.replayId).toBe('fixture.replay.exact');
    expect(report.stableDigest).toMatch(/^fnv1a32:/);
    expect(report.boundaryDecisions.length).toBeGreaterThan(0);
    expect(report.blockedActions.length).toBeGreaterThan(0);
    expect(report.proofLimits.join(' ')).toContain('external-world truth');
  });

});
