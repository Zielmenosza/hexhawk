export type AetherFrameOperatingMode = 'package_only';

export type AetherFrameAuthorityModel = {
  soleAuthorityFields: string[];
  advisoryFields: string[];
  derivedFields: string[];
  inheritedFields: string[];
  blockedFields: string[];
  humanReviewRequiredFields: string[];
};

export type AetherFrameAdapterContract = {
  schemaVersion: 'aetherframe.adapter_contract.v1';
  adapterKind: string;
  adapterVersion: string;
  authorityModel: AetherFrameAuthorityModel;
  protectedFields: string[];
};

export type AetherFrameAdapterFrame = {
  schemaVersion: 'aetherframe.frame.v1';
  frameId: string;
  frameVersion: string;
  operatingMode: AetherFrameOperatingMode;
  adapterKind: string;
  authorityModel: AetherFrameAuthorityModel;
  protectedFields: string[];
  mutableFields: string[];
  proofLimitTemplate: string[];
};

export type AetherFrameAdapterRegistry = {
  contracts: Map<string, AetherFrameAdapterContract>;
};

export type AetherFrameValidationResult = {
  valid: boolean;
  errors: string[];
};

const hexhawkAuthorityModel: AetherFrameAuthorityModel = {
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
    protectedFields: hexhawkProtectedFields,
  };
}

export function makeHexHawkAdapterFrame(): AetherFrameAdapterFrame {
  return {
    schemaVersion: 'aetherframe.frame.v1',
    frameId: 'adapter.hexhawk.verdict-lineage.v1',
    frameVersion: '0.1.0',
    operatingMode: 'package_only',
    adapterKind: 'hexhawk',
    authorityModel: hexhawkAuthorityModel,
    protectedFields: hexhawkProtectedFields,
    mutableFields: ['aetherframe_lineage', 'proof_limits', 'review_checkpoints'],
    proofLimitTemplate: [
      'HexHawk GYRE remains sole verdict authority.',
      'NEST remains evidence orchestration and is not replaced by AetherFrame.',
      'AetherFrame packages lineage/proof limits only in this adapter frame.',
    ],
  };
}

export function createAdapterRegistry(): AetherFrameAdapterRegistry {
  return { contracts: new Map<string, AetherFrameAdapterContract>() };
}

export function registerAdapterContract(registry: AetherFrameAdapterRegistry, contract: AetherFrameAdapterContract): AetherFrameValidationResult {
  const errors: string[] = [];
  if (contract.schemaVersion !== 'aetherframe.adapter_contract.v1') errors.push('schemaVersion must be aetherframe.adapter_contract.v1');
  if (registry.contracts.has(contract.adapterKind)) errors.push(`adapter contract already registered for ${contract.adapterKind}`);
  if (errors.length === 0) registry.contracts.set(contract.adapterKind, contract);
  return { valid: errors.length === 0, errors };
}

function semverMajor(version: string): number | null {
  const match = version.match(/^(\d+)\./);
  return match ? Number(match[1]) : null;
}

export function validateAdapterFrameAgainstContract(registry: AetherFrameAdapterRegistry, frame: AetherFrameAdapterFrame): AetherFrameValidationResult {
  const errors: string[] = [];
  const contract = registry.contracts.get(frame.adapterKind);
  if (!contract) return { valid: false, errors: [`adapter contract not registered for ${frame.adapterKind}`] };
  if (semverMajor(contract.adapterVersion) !== semverMajor(frame.frameVersion)) {
    errors.push(`adapter frame version ${frame.frameVersion} is incompatible with contract version ${contract.adapterVersion}`);
  }
  const missingProtectedFields = contract.protectedFields.filter(field => !frame.protectedFields.includes(field));
  if (missingProtectedFields.length > 0) errors.push(`missing protected contract fields: ${missingProtectedFields.join(', ')}`);
  for (const field of contract.protectedFields) {
    if (frame.mutableFields.includes(field)) errors.push(`adapter frame must not list protected contract field ${field} as mutable`);
  }
  for (const field of contract.authorityModel.soleAuthorityFields) {
    if (!frame.authorityModel.soleAuthorityFields.includes(field)) errors.push(`adapter frame must preserve sole authority field ${field}`);
  }
  for (const field of contract.authorityModel.blockedFields) {
    if (!frame.authorityModel.blockedFields.includes(field)) errors.push(`adapter frame must preserve blocked field ${field}`);
  }
  return { valid: errors.length === 0, errors };
}
