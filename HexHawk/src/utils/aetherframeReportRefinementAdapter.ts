import {
  createAdapterRegistry,
  makeHexHawkAdapterContract,
  makeHexHawkAdapterFrame,
  registerAdapterContract,
  validateAdapterFrameAgainstContract,
} from '@hexhawk/aetherframe-core/browser';

export type AetherframeReportRefinementPolicy = {
  enabled: boolean;
  reason?: string;
};

export type AetherframeReportVerdictGuard = {
  classification: string;
  threatScore: number;
  confidence: number;
  sourceEngine?: string;
};

export type AetherframeReportRefinementInput = {
  markdown: string;
  verdict: AetherframeReportVerdictGuard;
  policy?: AetherframeReportRefinementPolicy;
};

export type AetherframeReportRefinementResult = {
  markdown: string;
  lineage: {
    adapter: 'hexhawk.report.markdown';
    passId: 'hexhawk-report-authority-lineage-package' | 'aetherframe-disabled';
    category: 'package-output' | 'disabled';
    mutationScope: 'package' | 'none';
    deterministic: true;
    applied: boolean;
    policyReason: string;
    protectedFields: string[];
    blockedMutations: string[];
    proofLimits: string[];
    coreFrameId: string;
    coreSchemaVersion: 'aetherframe.frame.v1';
    coreAdapterKind: 'hexhawk';
    coreAdapterContractValid: boolean;
    coreAdapterContractErrors: string[];
  };
};

export type HexHawkReportLineageSidecar = {
  schemaVersion: 'hexhawk.aetherframe_report_lineage_sidecar.v1';
  reportId: string;
  generatedAt: string;
  lineage: AetherframeReportRefinementResult['lineage'];
  verdictCopy: AetherframeReportVerdictGuard;
  preservedVerdictFields: {
    classification: { source: 'copied_from_gyre_report_export'; value: string; recomputedByAetherFrame: false };
    threatScore: { source: 'copied_from_gyre_report_export'; value: number; recomputedByAetherFrame: false };
    confidence: { source: 'copied_from_gyre_report_export'; value: number; recomputedByAetherFrame: false };
    sourceEngine: { source: 'copied_from_gyre_report_export'; value: string; recomputedByAetherFrame: false };
  };
  verdictIntegrity: {
    gyreRemainsSoleVerdictSource: true;
    nestRemainsEvidenceOrchestrator: true;
    aetherframeRecomputedVerdict: false;
    bodyMutationAllowed: false;
  };
  proofLimits: string[];
};

const LINEAGE_HEADING = '## AETHERFRAME Report Refinement Lineage';

const PROTECTED_FIELDS = [
  'classification',
  'threatScore',
  'confidence',
  'source_engine',
  'gyre_is_sole_verdict_source',
  'malware_family',
  'verdictTruth',
  'nestEvidenceSelection',
];

const PROOF_LIMITS = [
  'This pass packages lineage and authority-boundary disclosure only.',
  'It does not recompute verdict truth, classify malware, infer family, or validate evidence quality.',
  'Typed NEST evidence bundles must still come from the NEST evidence export path after real NEST completion.',
];

function enabledPolicy(policy?: AetherframeReportRefinementPolicy): AetherframeReportRefinementPolicy {
  return policy ?? { enabled: true, reason: 'default-report-packaging' };
}

function coreAdapterValidation() {
  const registry = createAdapterRegistry();
  const contract = makeHexHawkAdapterContract();
  const registration = registerAdapterContract(registry, contract);
  const frame = makeHexHawkAdapterFrame();
  const frameValidation = validateAdapterFrameAgainstContract(registry, frame);
  const errors = [...registration.errors, ...frameValidation.errors];
  return {
    frame,
    valid: registration.valid && frameValidation.valid,
    errors,
  };
}

function baseLineage(policyReason: string): AetherframeReportRefinementResult['lineage'] {
  const core = coreAdapterValidation();
  return {
    adapter: 'hexhawk.report.markdown',
    passId: 'hexhawk-report-authority-lineage-package',
    category: 'package-output',
    mutationScope: 'package',
    deterministic: true,
    applied: true,
    policyReason,
    protectedFields: [...PROTECTED_FIELDS],
    blockedMutations: [...PROTECTED_FIELDS],
    proofLimits: [...PROOF_LIMITS, ...core.frame.proofLimitTemplate],
    coreFrameId: core.frame.frameId,
    coreSchemaVersion: core.frame.schemaVersion,
    coreAdapterKind: 'hexhawk',
    coreAdapterContractValid: core.valid,
    coreAdapterContractErrors: core.errors,
  };
}

function disabledLineage(policyReason: string): AetherframeReportRefinementResult['lineage'] {
  return {
    ...baseLineage(policyReason),
    passId: 'aetherframe-disabled',
    category: 'disabled',
    mutationScope: 'none',
    applied: false,
  };
}

export function describeHexHawkReportRefinement(
  policy?: AetherframeReportRefinementPolicy,
): AetherframeReportRefinementResult['lineage'] {
  const resolvedPolicy = enabledPolicy(policy);
  const policyReason = resolvedPolicy.reason ?? (resolvedPolicy.enabled ? 'enabled' : 'disabled');
  return resolvedPolicy.enabled ? baseLineage(policyReason) : disabledLineage(policyReason);
}

export function makeHexHawkReportLineageSidecar(input: {
  reportId: string;
  verdict: AetherframeReportVerdictGuard;
  policy?: AetherframeReportRefinementPolicy;
  generatedAt?: string;
}): HexHawkReportLineageSidecar {
  const lineage = describeHexHawkReportRefinement(input.policy);
  const sourceEngine = input.verdict.sourceEngine ?? 'gyre';
  return {
    schemaVersion: 'hexhawk.aetherframe_report_lineage_sidecar.v1',
    reportId: input.reportId,
    generatedAt: input.generatedAt ?? 'generated',
    lineage,
    verdictCopy: { ...input.verdict },
    preservedVerdictFields: {
      classification: { source: 'copied_from_gyre_report_export', value: input.verdict.classification, recomputedByAetherFrame: false },
      threatScore: { source: 'copied_from_gyre_report_export', value: input.verdict.threatScore, recomputedByAetherFrame: false },
      confidence: { source: 'copied_from_gyre_report_export', value: input.verdict.confidence, recomputedByAetherFrame: false },
      sourceEngine: { source: 'copied_from_gyre_report_export', value: sourceEngine, recomputedByAetherFrame: false },
    },
    verdictIntegrity: {
      gyreRemainsSoleVerdictSource: true,
      nestRemainsEvidenceOrchestrator: true,
      aetherframeRecomputedVerdict: false,
      bodyMutationAllowed: false,
    },
    proofLimits: [
      ...lineage.proofLimits,
      'The JSON sidecar copies GYRE/NEST-owned fields for lineage; it does not prove GYRE correctness or NEST completeness.',
      'AetherFrame did not recompute classification, threat score, confidence, source engine, or NEST-owned evidence selection.',
    ],
  };
}

export function refineHexHawkReportMarkdown(
  input: AetherframeReportRefinementInput,
): AetherframeReportRefinementResult {
  const lineage = describeHexHawkReportRefinement(input.policy);

  if (!lineage.applied) {
    return {
      markdown: input.markdown,
      lineage,
    };
  }

  if (input.markdown.includes(LINEAGE_HEADING)) {
    return {
      markdown: input.markdown,
      lineage,
    };
  }

  const sourceEngine = input.verdict.sourceEngine ?? 'gyre';
  const appendix = [
    '',
    '---',
    '',
    LINEAGE_HEADING,
    '',
    '| Field | Value |',
    '|-------|-------|',
    `| Adapter | ${lineage.adapter} |`,
    `| Pass | ${lineage.passId} |`,
    `| Category | ${lineage.category} |`,
    `| Allowed mutation scope | ${lineage.mutationScope} only |`,
    `| Deterministic | ${lineage.deterministic ? 'yes' : 'no'} |`,
    `| Policy reason | ${lineage.policyReason} |`,
    `| Core frame | ${lineage.coreFrameId} |`,
    `| Core schema | ${lineage.coreSchemaVersion} |`,
    `| Core adapter contract valid | ${lineage.coreAdapterContractValid ? 'yes' : 'no'} |`,
    `| Protected classification | ${input.verdict.classification} |`,
    `| Protected threat score | ${input.verdict.threatScore} |`,
    `| Protected confidence | ${input.verdict.confidence}% |`,
    `| Protected source engine | ${sourceEngine} |`,
    '',
    'Authority boundary:',
    '',
    '- GYRE remains the sole verdict authority for classification and base confidence.',
    '- NEST remains evidence orchestration/convergence only and does not replace GYRE.',
    '- AETHERFRAME/Forge only packaged this report lineage disclosure; it did not change verdict truth.',
    '- NEXUS remains an assistant/consumer/proposal layer and is not a verdict source.',
    '',
    'Blocked mutations:',
    '',
    ...lineage.blockedMutations.map(field => `- ${field}`),
    '',
    'Proof limits:',
    '',
    ...lineage.proofLimits.map(limit => `- ${limit}`),
  ].join('\n');

  return {
    markdown: `${input.markdown}${appendix}`,
    lineage,
  };
}

export const AETHERFRAME_REPORT_LINEAGE_HEADING = LINEAGE_HEADING;
