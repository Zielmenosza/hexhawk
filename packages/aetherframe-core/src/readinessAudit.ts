export type AetherFrameReadinessVerdict = 'verified' | 'not_present' | 'unknown';

export type AetherFrameReadinessSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type AetherFrameReadinessPhase =
  | 'access_gate'
  | 'system_map'
  | 'threat_model'
  | 'security_review'
  | 'privacy_compliance'
  | 'failure_testing'
  | 'attack_mode'
  | 'performance_scale'
  | 'code_quality'
  | 'out_of_repo_controls'
  | 'release_checklist'
  | 'automated_cross_check'
  | 'self_challenge';

export type AetherFrameReadinessAccessGateInput = {
  canReadRepository: boolean;
  rootPaths: string[];
  approximateFileCount?: number;
};

export type AetherFrameReadinessAccessGate = {
  allowed: boolean;
  verdict: 'ready_for_audit' | 'blocked_no_repository_access';
  rootPaths: string[];
  approximateFileCount?: number;
  message: string;
  proofLimits: string[];
};

export type AetherFrameReadinessFinding = {
  id: string;
  phase: AetherFrameReadinessPhase;
  title: string;
  claim: string;
  verdict: AetherFrameReadinessVerdict;
  severity: AetherFrameReadinessSeverity;
  confidence: number;
  evidenceRefs: string[];
  citations: string[];
  searchTerms: string[];
  requiredProof: string[];
  affectedFields: string[];
  blocksRelease: boolean;
  advisoryOnly: true;
  authorityBoundary: string[];
  proofLimits: string[];
};

export type AetherFrameReadinessFindingInput = Omit<
  AetherFrameReadinessFinding,
  'advisoryOnly' | 'authorityBoundary' | 'blocksRelease' | 'confidence' | 'proofLimits'
> & {
  confidence?: number;
  blocksRelease?: boolean;
  authorityBoundary?: string[];
  proofLimits?: string[];
};

export type AetherFrameReadinessFindingValidation = {
  valid: boolean;
  errors: string[];
  warnings: string[];
};

export type AetherFrameReadinessAudit = {
  auditId: string;
  product: string;
  generatedAt: string;
  accessGate: AetherFrameReadinessAccessGate;
  findings: AetherFrameReadinessFinding[];
  finiteSetCoverage: AetherFrameFiniteSetCoverage[];
  proofLimits: string[];
};

export type AetherFrameFiniteSetCoverage = {
  id: string;
  label: string;
  expectedItems: string[];
  auditedItems: string[];
  missingItems: string[];
  complete: boolean;
  proofLimits: string[];
};

export type AetherFrameReadinessSummary = {
  blocked: boolean;
  highestSeverity: AetherFrameReadinessSeverity;
  counts: Record<AetherFrameReadinessVerdict, number>;
  releaseBlockers: AetherFrameReadinessFinding[];
  unknowns: AetherFrameReadinessFinding[];
  notPresent: AetherFrameReadinessFinding[];
  finiteSetGaps: AetherFrameFiniteSetCoverage[];
  proofLimits: string[];
};

const severityRank: Record<AetherFrameReadinessSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const DEFAULT_AUTHORITY_BOUNDARY = [
  'AetherFrame readiness findings are advisory and do not replace product authority owners.',
  'A verified finding proves only the cited evidence, not global release readiness.',
  'UNKNOWN and NOT_PRESENT are findings, never silent passes.',
];

const DEFAULT_PROOF_LIMITS = [
  'This readiness layer checks evidence discipline and release blockers; it is not a compliance certificate.',
  'Findings that require runtime, live-service, or human review remain UNKNOWN until the named proof is produced.',
  'AetherFrame may package, rank, and block advisory release gates; it must not mutate protected verdict authority fields.',
];

export function createReadinessAccessGate(input: AetherFrameReadinessAccessGateInput): AetherFrameReadinessAccessGate {
  if (!input.canReadRepository || input.rootPaths.length === 0) {
    return {
      allowed: false,
      verdict: 'blocked_no_repository_access',
      rootPaths: input.rootPaths,
      approximateFileCount: input.approximateFileCount,
      message: 'BLOCKED — no repository access. AetherFrame will not produce a readiness audit for code it cannot read.',
      proofLimits: ['No repo-readable evidence was available, so any readiness report would be speculative.'],
    };
  }

  const countText = typeof input.approximateFileCount === 'number'
    ? `; roughly ${input.approximateFileCount} files visible`
    : '';
  return {
    allowed: true,
    verdict: 'ready_for_audit',
    rootPaths: input.rootPaths,
    approximateFileCount: input.approximateFileCount,
    message: `Repository access confirmed at ${input.rootPaths.join(', ')}${countText}.`,
    proofLimits: ['Repository readability only proves source access; it does not prove runtime or out-of-repo controls.'],
  };
}

export function makeReadinessFinding(input: AetherFrameReadinessFindingInput): AetherFrameReadinessFinding {
  const proofLimits = input.proofLimits?.length ? input.proofLimits : DEFAULT_PROOF_LIMITS;
  const authorityBoundary = input.authorityBoundary?.length ? input.authorityBoundary : DEFAULT_AUTHORITY_BOUNDARY;
  const confidence = clampPercent(input.confidence ?? defaultConfidenceForVerdict(input.verdict));
  return {
    ...input,
    confidence,
    blocksRelease: input.blocksRelease ?? shouldBlockRelease(input.verdict, input.severity),
    advisoryOnly: true,
    authorityBoundary,
    proofLimits,
  };
}

export function validateReadinessFinding(finding: AetherFrameReadinessFinding): AetherFrameReadinessFindingValidation {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!finding.id.trim()) errors.push('finding id is required');
  if (!finding.title.trim()) errors.push('finding title is required');
  if (!finding.claim.trim()) errors.push('finding claim is required');
  if (finding.confidence < 0 || finding.confidence > 100) errors.push('finding confidence must be between 0 and 100');
  if (!finding.advisoryOnly) errors.push('readiness findings must remain advisoryOnly');

  if (finding.verdict === 'verified') {
    if (finding.evidenceRefs.length === 0 && finding.citations.length === 0) {
      errors.push('VERIFIED finding requires evidenceRefs or citations');
    }
    if (finding.requiredProof.length > 0) {
      warnings.push('VERIFIED finding still lists requiredProof; consider downgrading to UNKNOWN if proof is incomplete');
    }
  }

  if (finding.verdict === 'not_present') {
    if (finding.searchTerms.length === 0) {
      errors.push('NOT_PRESENT finding requires searchTerms so the absence can be reproduced');
    }
    if (finding.evidenceRefs.length > 0 && finding.citations.length > 0) {
      warnings.push('NOT_PRESENT finding has positive citations; verify this is not a partially implemented control');
    }
  }

  if (finding.verdict === 'unknown') {
    if (finding.requiredProof.length === 0) {
      errors.push('UNKNOWN finding requires requiredProof explaining how to resolve it');
    }
  }

  if (finding.verdict !== 'verified' && finding.confidence > 70) {
    warnings.push('non-VERIFIED findings should not carry high confidence; confidence will not make them release proof');
  }

  return { valid: errors.length === 0, errors, warnings };
}

export function assertVerifiedRequiresEvidence(findings: AetherFrameReadinessFinding[]): AetherFrameReadinessFinding[] {
  return findings.map(finding => {
    if (finding.verdict !== 'verified') return finding;
    const validation = validateReadinessFinding(finding);
    if (validation.valid) return finding;
    return {
      ...finding,
      verdict: 'unknown',
      confidence: Math.min(finding.confidence, 50),
      blocksRelease: shouldBlockRelease('unknown', finding.severity),
      requiredProof: finding.requiredProof.length > 0
        ? finding.requiredProof
        : ['Attach reproducible evidenceRefs or file:line/command citations before restoring VERIFIED status.'],
      proofLimits: [...finding.proofLimits, 'Self-challenge downgraded VERIFIED to UNKNOWN because proof was missing.'],
    };
  });
}

export function createFiniteSetCoverage(input: Omit<AetherFrameFiniteSetCoverage, 'missingItems' | 'complete' | 'proofLimits'> & { proofLimits?: string[] }): AetherFrameFiniteSetCoverage {
  const audited = new Set(input.auditedItems);
  const missingItems = input.expectedItems.filter(item => !audited.has(item));
  return {
    ...input,
    missingItems,
    complete: missingItems.length === 0,
    proofLimits: input.proofLimits?.length ? input.proofLimits : [
      'Finite-set coverage prevents implying full audit coverage from a sample.',
    ],
  };
}

export function summarizeReadinessAudit(audit: AetherFrameReadinessAudit): AetherFrameReadinessSummary {
  const challengedFindings = assertVerifiedRequiresEvidence(audit.findings);
  const counts: Record<AetherFrameReadinessVerdict, number> = { verified: 0, not_present: 0, unknown: 0 };
  for (const finding of challengedFindings) counts[finding.verdict] += 1;

  const releaseBlockers = challengedFindings.filter(finding => finding.blocksRelease);
  const unknowns = challengedFindings.filter(finding => finding.verdict === 'unknown');
  const notPresent = challengedFindings.filter(finding => finding.verdict === 'not_present');
  const finiteSetGaps = audit.finiteSetCoverage.filter(coverage => !coverage.complete);
  const highestSeverity = challengedFindings.reduce<AetherFrameReadinessSeverity>((highest, finding) => {
    return severityRank[finding.severity] > severityRank[highest] ? finding.severity : highest;
  }, 'info');

  return {
    blocked: !audit.accessGate.allowed || releaseBlockers.length > 0 || finiteSetGaps.length > 0,
    highestSeverity,
    counts,
    releaseBlockers,
    unknowns,
    notPresent,
    finiteSetGaps,
    proofLimits: [
      ...audit.proofLimits,
      ...DEFAULT_PROOF_LIMITS,
      'Summary blocking is an advisory release gate signal, not product verdict authority.',
    ],
  };
}

function shouldBlockRelease(verdict: AetherFrameReadinessVerdict, severity: AetherFrameReadinessSeverity): boolean {
  if (severity === 'critical' || severity === 'high') return verdict !== 'verified';
  return false;
}

function defaultConfidenceForVerdict(verdict: AetherFrameReadinessVerdict): number {
  if (verdict === 'verified') return 85;
  if (verdict === 'not_present') return 70;
  return 40;
}

function clampPercent(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}
