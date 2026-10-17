import { describe, expect, it } from 'vitest';
import {
  assertVerifiedRequiresEvidence,
  createFiniteSetCoverage,
  createReadinessAccessGate,
  makeReadinessFinding,
  summarizeReadinessAudit,
  validateReadinessFinding,
  type AetherFrameReadinessAudit,
} from '../index';

describe('AetherFrame TRAP-inspired readiness audit primitives', () => {
  it('refuses to audit when repository access is not proven', () => {
    const gate = createReadinessAccessGate({ canReadRepository: false, rootPaths: [] });

    expect(gate.allowed).toBe(false);
    expect(gate.verdict).toBe('blocked_no_repository_access');
    expect(gate.message).toContain('BLOCKED');
  });

  it('records repository access without treating access as runtime proof', () => {
    const gate = createReadinessAccessGate({
      canReadRepository: true,
      rootPaths: ['D:/Project/HexHawk'],
      approximateFileCount: 1200,
    });

    expect(gate.allowed).toBe(true);
    expect(gate.message).toContain('D:/Project/HexHawk');
    expect(gate.proofLimits.join(' ')).toMatch(/does not prove runtime/i);
  });

  it('requires VERIFIED findings to cite reproducible evidence', () => {
    const finding = makeReadinessFinding({
      id: 'installer-signing-status',
      phase: 'release_checklist',
      title: 'Installer signing status',
      claim: 'The installer is signed.',
      verdict: 'verified',
      severity: 'high',
      evidenceRefs: [],
      citations: [],
      searchTerms: [],
      requiredProof: [],
      affectedFields: ['release_signing_claim'],
    });

    const validation = validateReadinessFinding(finding);
    expect(validation.valid).toBe(false);
    expect(validation.errors.join(' ')).toMatch(/VERIFIED.*evidenceRefs|VERIFIED.*citations/i);
  });

  it('treats NOT_PRESENT as a finding that must include reproducible search terms', () => {
    const finding = makeReadinessFinding({
      id: 'rate-limit-not-present',
      phase: 'security_review',
      title: 'Rate limiting is not present',
      claim: 'No rate limiting control was found for the API surface.',
      verdict: 'not_present',
      severity: 'medium',
      evidenceRefs: [],
      citations: [],
      searchTerms: ['rateLimit', 'throttle', '429'],
      requiredProof: [],
      affectedFields: ['api_release_gate'],
    });

    expect(validateReadinessFinding(finding)).toMatchObject({ valid: true });
    expect(finding.blocksRelease).toBe(false);
  });

  it('requires UNKNOWN findings to name the proof that would resolve them', () => {
    const finding = makeReadinessFinding({
      id: 'installer-smoke-unknown',
      phase: 'release_checklist',
      title: 'Installer smoke is unknown',
      claim: 'Install/uninstall behavior on a clean VM is not proven.',
      verdict: 'unknown',
      severity: 'high',
      evidenceRefs: [],
      citations: [],
      searchTerms: [],
      requiredProof: ['Run the approved VM-only installer smoke plan and attach the result artifact.'],
      affectedFields: ['installer_release_gate'],
    });

    expect(validateReadinessFinding(finding)).toMatchObject({ valid: true });
    expect(finding.blocksRelease).toBe(true);
  });

  it('self-challenges unsupported VERIFIED findings down to UNKNOWN', () => {
    const unsupported = makeReadinessFinding({
      id: 'unsupported-green',
      phase: 'self_challenge',
      title: 'Unsupported green status',
      claim: 'Everything is ready.',
      verdict: 'verified',
      severity: 'critical',
      evidenceRefs: [],
      citations: [],
      searchTerms: [],
      requiredProof: [],
      affectedFields: ['release_readiness'],
    });

    const [challenged] = assertVerifiedRequiresEvidence([unsupported]);
    expect(challenged.verdict).toBe('unknown');
    expect(challenged.confidence).toBeLessThanOrEqual(50);
    expect(challenged.blocksRelease).toBe(true);
  });

  it('tracks finite-set coverage so samples cannot imply full coverage', () => {
    const coverage = createFiniteSetCoverage({
      id: 'installer-artifacts',
      label: 'Release artifact signing checks',
      expectedItems: ['nsis', 'msi', 'backend-exe'],
      auditedItems: ['backend-exe'],
    });

    expect(coverage.complete).toBe(false);
    expect(coverage.missingItems).toEqual(['nsis', 'msi']);
  });

  it('summarizes advisory release blockers without replacing product authority', () => {
    const accessGate = createReadinessAccessGate({
      canReadRepository: true,
      rootPaths: ['D:/Project/HexHawk'],
      approximateFileCount: 1200,
    });
    const audit: AetherFrameReadinessAudit = {
      auditId: 'hh-af-trap-slice',
      product: 'AetherFrame',
      generatedAt: '2026-07-26T14:50:00.000Z',
      accessGate,
      findings: [
        makeReadinessFinding({
          id: 'vm-installer-smoke',
          phase: 'release_checklist',
          title: 'VM installer smoke is not yet proven',
          claim: 'Clean VM install/uninstall evidence is missing.',
          verdict: 'unknown',
          severity: 'high',
          evidenceRefs: [],
          citations: [],
          searchTerms: [],
          requiredProof: ['Run VM-only installer smoke and attach logs/hashes.'],
          affectedFields: ['release_readiness'],
        }),
        makeReadinessFinding({
          id: 'legacy-parser-tests',
          phase: 'automated_cross_check',
          title: 'Legacy parser tests passed',
          claim: 'Focused tests passed for the legacy record metadata parser.',
          verdict: 'verified',
          severity: 'info',
          evidenceRefs: ['yarn workspace hexhawk-ui exec vitest run src/utils/__tests__/legacyRecordMetadata.test.ts'],
          citations: [],
          searchTerms: [],
          requiredProof: [],
          affectedFields: ['adapter_evidence'],
        }),
      ],
      finiteSetCoverage: [
        createFiniteSetCoverage({
          id: 'signed-artifacts',
          label: 'Signed release artifacts',
          expectedItems: ['nsis', 'msi'],
          auditedItems: [],
        }),
      ],
      proofLimits: ['AetherFrame readiness summary is advisory only.'],
    };

    const summary = summarizeReadinessAudit(audit);
    expect(summary.blocked).toBe(true);
    expect(summary.highestSeverity).toBe('high');
    expect(summary.counts.verified).toBe(1);
    expect(summary.counts.unknown).toBe(1);
    expect(summary.releaseBlockers.map(finding => finding.id)).toContain('vm-installer-smoke');
    expect(summary.finiteSetGaps).toHaveLength(1);
    expect(summary.proofLimits.join(' ')).toMatch(/not product verdict authority/i);
  });
});
