import { makeFrame, type AetherFrameAdapterContract, type AetherFrameFrame } from '../index.js';

const hexhawkAuthorityModel = {
  soleAuthorityFields: ['classification', 'threat_score', 'base_confidence', 'source_engine'],
  advisoryFields: ['aetherframe_lineage', 'proof_limits', 'review_checkpoints'],
  derivedFields: ['confidence_breakdown', 'uncertainty_summary'],
  inheritedFields: ['binary_identity', 'nest_bundle_id'],
  blockedFields: ['gyre_is_sole_verdict_source', 'nest_evidence_selection'],
  humanReviewRequiredFields: ['public_claim', 'external_distribution_claim'],
};

const hexhawkProtectedFields = [
  'classification',
  'threat_score',
  'base_confidence',
  'source_engine',
  'gyre_is_sole_verdict_source',
  'nest_evidence_selection',
];

export function makeHexHawkAdapterContract(): AetherFrameAdapterContract {
  return {
    schemaVersion: 'aetherframe.adapter_contract.v1',
    adapterKind: 'hexhawk',
    adapterVersion: '0.1.0',
    authorityModel: hexhawkAuthorityModel,
    evidenceSources: [
      'GYRE verdict snapshot',
      'NEST evidence bundle status when available',
      'binary identity metadata',
      'report export authority markers',
    ],
    protectedFields: hexhawkProtectedFields,
    mutationTypes: ['evidence_packaging', 'report_annotation', 'recommendation_ranking'],
    validationCommands: ['yarn workspace @hexhawk/aetherframe-core test'],
    exportFormat: 'HexHawk report lineage appendix and JSON authority-envelope metadata',
    proofLimitLanguage: [
      'HexHawk GYRE remains sole verdict authority.',
      'NEST remains evidence orchestration and is not replaced by AetherFrame.',
      'AetherFrame packages lineage/proof limits only in this adapter frame.',
    ],
    stopConditions: [
      'attempted mutation of GYRE verdict fields',
      'attempted replacement of NEST evidence selection',
      'missing source_engine authority marker',
    ],
  };
}

export function makeHexHawkAdapterFrame(): AetherFrameFrame {
  return makeFrame({
    frameId: 'adapter.hexhawk.verdict-lineage.v1',
    frameName: 'HexHawk verdict lineage adapter',
    frameVersion: '0.1.0',
    adapterKind: 'hexhawk',
    domain: 'reverse-engineering-security-analysis',
    objective: 'Package AetherFrame lineage around HexHawk report outputs without changing GYRE verdict truth or NEST evidence orchestration.',
    operatingMode: 'package_only',
    authorityModel: hexhawkAuthorityModel,
    protectedFields: hexhawkProtectedFields,
    mutableFields: ['aetherframe_lineage', 'proof_limits', 'review_checkpoints'],
    evidenceRequirements: [
      'GYRE verdict snapshot',
      'NEST evidence bundle status when available',
      'explicit proof-limit disclosure',
    ],
    stopConditions: [
      'attempted mutation of GYRE verdict fields',
      'attempted replacement of NEST evidence selection',
      'missing source_engine authority marker',
    ],
    proofLimitTemplate: [
      'HexHawk GYRE remains sole verdict authority.',
      'NEST remains evidence orchestration and is not replaced by AetherFrame.',
      'AetherFrame packages lineage/proof limits only in this adapter frame.',
    ],
  });
}
