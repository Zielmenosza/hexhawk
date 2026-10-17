import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

export type AetherFrameCapsuleStatus = 'proposed' | 'approved' | 'in_progress' | 'verified' | 'stopped' | 'rejected';
export type AetherFrameCapsuleEvidenceKind =
  | 'repo_state'
  | 'test_result'
  | 'command_output'
  | 'artifact'
  | 'user_feedback'
  | 'external_context';

export type AetherFrameCapsuleEvidence = {
  id: string;
  kind: AetherFrameCapsuleEvidenceKind;
  reference: string;
  claim: string;
  capturedAt: string;
  reproducible: boolean;
};

export type AetherFrameImprovementCapsule = {
  schemaVersion: 'aetherframe.improvement_capsule.v1';
  capsuleId: string;
  title: string;
  product: string;
  objective: string;
  hypothesis: string;
  status: AetherFrameCapsuleStatus;
  authorityBoundary: {
    protectedFields: string[];
    forbiddenActions: string[];
    requiredApprovals: string[];
  };
  scope: {
    targetPaths: string[];
    maxFilesChanged: number;
    maxChangedLines: number;
    allowedChangeKinds: Array<'code' | 'tests' | 'schema' | 'documentation' | 'configuration'>;
  };
  budget: {
    maxDurationMinutes: number;
    maxIterations: number;
    maxTestCommands: number;
  };
  evidence: AetherFrameCapsuleEvidence[];
  uncertainty: {
    level: 'low' | 'medium' | 'high';
    unresolvedQuestions: string[];
    proofLimits: string[];
  };
  verification: {
    requiredCommands: string[];
    successCriteria: string[];
    failureSignals: string[];
    evidenceRefs: string[];
  };
  reviewCheckpoints: string[];
  stopConditions: string[];
  rollbackPlan: string;
  approval?: {
    grantedBy: string;
    scope: string;
    grantedAt: string;
  };
};

export type AetherFrameCapsuleValidationResult = {
  valid: boolean;
  errors: string[];
};

export type AetherFrameCapsuleLoadResult = AetherFrameCapsuleValidationResult & {
  value: AetherFrameImprovementCapsule;
  schemaPath: 'schemas/improvement_capsule.schema.json';
};

export type AetherFrameCapsuleScore = {
  score: number;
  executionEligible: boolean;
  breakdown: {
    evidence: number;
    verification: number;
    authoritySafety: number;
    boundedScope: number;
    rollbackAndStops: number;
    uncertaintyHonesty: number;
  };
  awarded: string[];
  blockers: string[];
  proofLimits: string[];
};

const moduleDir = dirname(fileURLToPath(import.meta.url));
const schemaCandidates = [
  join(moduleDir, '..', 'schemas', 'improvement_capsule.schema.json'),
  join(moduleDir, '..', '..', 'schemas', 'improvement_capsule.schema.json'),
];
const ajv = new Ajv2020({ allErrors: true, strict: false });
let cachedValidator: ReturnType<Ajv2020['compile']> | null = null;

function schemaPath(): string {
  for (const candidate of schemaCandidates) {
    try {
      readFileSync(candidate, 'utf8');
      return candidate;
    } catch {
      // Try source and compiled layouts before surfacing the read error.
    }
  }
  return schemaCandidates[0];
}

function schemaValidator(): ReturnType<Ajv2020['compile']> {
  if (!cachedValidator) {
    cachedValidator = ajv.compile(JSON.parse(readFileSync(schemaPath(), 'utf8')));
  }
  return cachedValidator;
}

function isExecutionStatus(status: AetherFrameCapsuleStatus): boolean {
  return status === 'approved' || status === 'in_progress' || status === 'verified';
}

function hasBroadTarget(path: string): boolean {
  const normalized = path.trim().replace(/\\/g, '/');
  return normalized === '.' || normalized === '/' || normalized === '*' || normalized.endsWith('/**');
}

export function validateImprovementCapsule(value: unknown): AetherFrameCapsuleValidationResult {
  const validate = schemaValidator();
  const schemaValid = Boolean(validate(value));
  const errors = schemaValid
    ? []
    : (validate.errors ?? []).map(error => `${error.instancePath || '/'} ${error.message ?? 'failed schema validation'}`.trim());

  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return { valid: false, errors };
  }

  const capsule = value as AetherFrameImprovementCapsule;
  if (capsule.schemaVersion !== 'aetherframe.improvement_capsule.v1') {
    errors.push('schemaVersion must be aetherframe.improvement_capsule.v1');
  }

  if (capsule.scope) {
    if (capsule.scope.targetPaths.length > capsule.scope.maxFilesChanged) {
      errors.push('/scope/maxFilesChanged is lower than the number of declared targetPaths');
    }
    if (new Set(capsule.scope.targetPaths).size !== capsule.scope.targetPaths.length) {
      errors.push('/scope/targetPaths must not contain duplicates');
    }
    capsule.scope.targetPaths.forEach((path, index) => {
      if (hasBroadTarget(path)) errors.push(`/scope/targetPaths/${index} is too broad for a bounded capsule`);
    });
  }

  const evidenceIds = capsule.evidence?.map(item => item.id) ?? [];
  if (new Set(evidenceIds).size !== evidenceIds.length) {
    errors.push('/evidence ids must be unique');
  }
  const evidenceById = new Map((capsule.evidence ?? []).map(item => [item.id, item]));
  for (const reference of capsule.verification?.evidenceRefs ?? []) {
    if (!evidenceById.has(reference)) errors.push(`/verification/evidenceRefs references unknown evidence id ${reference}`);
  }

  if (isExecutionStatus(capsule.status) && !capsule.approval) {
    errors.push(`/${capsule.status} capsule requires explicit approval metadata`);
  }
  if (capsule.status === 'verified' && (capsule.verification?.evidenceRefs.length ?? 0) === 0) {
    errors.push('/verified capsule requires verification evidence references');
  }
  if (capsule.status === 'verified') {
    const admissible = capsule.verification.evidenceRefs.some(reference => {
      const evidence = evidenceById.get(reference);
      return evidence?.reproducible && ['test_result', 'command_output', 'artifact'].includes(evidence.kind);
    });
    if (!admissible) errors.push('/verified capsule requires reproducible test, command, or artifact evidence');
  }

  return { valid: errors.length === 0, errors };
}

export function loadImprovementCapsuleFile(path: string | URL): AetherFrameCapsuleLoadResult {
  const value = JSON.parse(readFileSync(path, 'utf8')) as AetherFrameImprovementCapsule;
  return {
    ...validateImprovementCapsule(value),
    value,
    schemaPath: 'schemas/improvement_capsule.schema.json',
  };
}

export function scoreImprovementCapsule(capsule: AetherFrameImprovementCapsule): AetherFrameCapsuleScore {
  const validation = validateImprovementCapsule(capsule);
  const awarded: string[] = [];
  const blockers = [...validation.errors];

  const repoLocalEvidence = capsule.evidence.filter(item => item.reproducible && item.kind !== 'external_context');
  const verificationEvidence = capsule.verification.evidenceRefs
    .map(reference => capsule.evidence.find(item => item.id === reference))
    .filter((item): item is AetherFrameCapsuleEvidence => Boolean(item?.reproducible));

  const evidence = Math.min(20, (repoLocalEvidence.length * 7) + (capsule.evidence.length > 1 ? 6 : 0));
  if (evidence > 0) awarded.push('repo-local or reproducible evidence is attached');
  if (repoLocalEvidence.length === 0) blockers.push('execution requires repo-local or reproducible non-external evidence');

  let verification = 0;
  if (capsule.verification.requiredCommands.length > 0) verification += 5;
  if (capsule.verification.successCriteria.length > 0) verification += 5;
  if (capsule.verification.failureSignals.length > 0) verification += 5;
  if (verificationEvidence.length > 0) verification += 5;
  if (verification >= 15) awarded.push('verification has commands, success criteria, and failure signals');

  let authoritySafety = 0;
  if (capsule.authorityBoundary.protectedFields.length > 0) authoritySafety += 8;
  if (capsule.authorityBoundary.forbiddenActions.length > 0) authoritySafety += 6;
  if (capsule.authorityBoundary.requiredApprovals.length > 0) authoritySafety += 6;
  if (authoritySafety === 20) awarded.push('authority fields, forbidden actions, and approval gates are explicit');

  let boundedScope = 0;
  if (capsule.scope.targetPaths.length > 0 && capsule.scope.targetPaths.length <= capsule.scope.maxFilesChanged) boundedScope += 6;
  if (capsule.scope.maxChangedLines > 0) boundedScope += 3;
  if (capsule.budget.maxDurationMinutes > 0 && capsule.budget.maxIterations > 0 && capsule.budget.maxTestCommands > 0) boundedScope += 6;
  if (boundedScope === 15) awarded.push('path, line, iteration, duration, and test budgets are bounded');

  let rollbackAndStops = 0;
  if (capsule.rollbackPlan.trim().length > 0) rollbackAndStops += 5;
  if (capsule.stopConditions.length > 0) rollbackAndStops += 5;
  if (capsule.reviewCheckpoints.length > 0) rollbackAndStops += 5;
  if (rollbackAndStops === 15) awarded.push('rollback, checkpoints, and stop conditions are present');

  let uncertaintyHonesty = 0;
  if (capsule.uncertainty.proofLimits.length > 0) uncertaintyHonesty += 5;
  if (capsule.uncertainty.unresolvedQuestions.length > 0 || capsule.uncertainty.level === 'low') uncertaintyHonesty += 5;
  if (uncertaintyHonesty === 10) awarded.push('uncertainty and proof limits are explicit');

  if (!isExecutionStatus(capsule.status)) blockers.push(`capsule status ${capsule.status} is not execution eligible`);
  if (!capsule.approval) blockers.push('execution requires explicit approval metadata');

  const executionEligible = validation.valid
    && isExecutionStatus(capsule.status)
    && Boolean(capsule.approval)
    && repoLocalEvidence.length > 0;
  const rawScore = evidence + verification + authoritySafety + boundedScope + rollbackAndStops + uncertaintyHonesty;

  return {
    score: executionEligible ? Math.min(100, rawScore) : Math.min(79, rawScore),
    executionEligible,
    breakdown: { evidence, verification, authoritySafety, boundedScope, rollbackAndStops, uncertaintyHonesty },
    awarded,
    blockers: [...new Set(blockers)],
    proofLimits: [
      'Capsule points measure execution readiness and evidence discipline, not product correctness or external-world truth.',
      'Approval metadata is a recorded claim and must be checked against the real human approval source before execution.',
      'Declared path, line, iteration, duration, and test budgets are not filesystem or process enforcement by themselves.',
      'A high score never replaces required human approval, verification, release gates, or authority-owner decisions.',
    ],
  };
}
