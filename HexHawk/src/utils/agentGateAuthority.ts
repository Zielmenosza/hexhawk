import type { AgentGateProposal } from '../components/AgentGatePanel';

export type AgentGateDecision = 'approved' | 'rejected';

export interface AgentGateAuthorityPacket {
  action_class: 'agent_gate.approve_note';
  proposal_id: string;
  proposal_kind: AgentGateProposal['proposalKind'];
  source: AgentGateProposal['source'];
  function_id: string | null;
  observation_id: string | null;
  address: number | null;
  proposed_value_hash: string;
  evidence_basis_hash: string;
  authority_fingerprint: string;
  consumed_once: true;
  advisory_only: true;
  does_not_affect_verdict: true;
  gyre_is_sole_verdict_authority: true;
  created_at: string;
}

export interface AgentGateActionRecord {
  action_class: 'agent_gate.approve_note';
  proposal_id: string;
  decision: AgentGateDecision;
  authority_fingerprint: string;
  consumed_once: true;
  advisory_only: true;
  does_not_affect_verdict: true;
  gyre_is_sole_verdict_authority: true;
  timestamp: string;
  result: 'accepted' | 'rejected';
  reason?: 'tamper_rejected' | 'replay_rejected' | 'missing_authority_fields' | 'analyst_rejected';
}

export interface AgentGateApprovalResult {
  ok: boolean;
  record: AgentGateActionRecord;
}

type FingerprintMaterial = {
  proposal_id: string;
  proposal_kind: AgentGateProposal['proposalKind'];
  source: AgentGateProposal['source'];
  function_id: string | null;
  observation_id: string | null;
  address: number | null;
  proposed_value_hash: string;
  evidence_basis_hash: string;
  advisory_only: true;
  does_not_affect_verdict: true;
  gyre_is_sole_verdict_authority: true;
};

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map(key => `${JSON.stringify(key)}:${stableStringify(record[key])}`).join(',')}}`;
}

async function sha256Hex(input: string): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error('SHA-256 authority hashing is unavailable in this environment.');
  }
  const digest = await subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}

export function hasRequiredAgentGateAuthorityFields(proposal: AgentGateProposal): boolean {
  return proposal.advisory_only === true
    && proposal.does_not_affect_verdict === true
    && proposal.gyre_is_sole_verdict_authority === true
    && typeof proposal.id === 'string'
    && proposal.id.trim().length > 0
    && typeof proposal.proposedValue === 'string'
    && proposal.proposedValue.trim().length > 0
    && typeof proposal.evidenceBasis === 'string'
    && proposal.evidenceBasis.trim().length > 0
    && typeof proposal.source === 'string'
    && proposal.source.trim().length > 0;
}

export async function createAgentGateAuthorityPacket(
  proposal: AgentGateProposal,
  createdAt = new Date().toISOString(),
): Promise<AgentGateAuthorityPacket> {
  if (!hasRequiredAgentGateAuthorityFields(proposal)) {
    throw new Error('missing_agent_gate_authority_fields');
  }

  const proposedValueHash = await sha256Hex(proposal.proposedValue);
  const evidenceBasisHash = await sha256Hex(proposal.evidenceBasis);
  const material: FingerprintMaterial = {
    proposal_id: proposal.id,
    proposal_kind: proposal.proposalKind,
    source: proposal.source,
    function_id: proposal.functionId ?? null,
    observation_id: proposal.observationId ?? null,
    address: proposal.address ?? null,
    proposed_value_hash: proposedValueHash,
    evidence_basis_hash: evidenceBasisHash,
    advisory_only: true,
    does_not_affect_verdict: true,
    gyre_is_sole_verdict_authority: true,
  };

  return {
    action_class: 'agent_gate.approve_note',
    proposal_id: material.proposal_id,
    proposal_kind: material.proposal_kind,
    source: material.source,
    function_id: material.function_id,
    observation_id: material.observation_id,
    address: material.address,
    proposed_value_hash: material.proposed_value_hash,
    evidence_basis_hash: material.evidence_basis_hash,
    authority_fingerprint: await sha256Hex(stableStringify(material)),
    consumed_once: true,
    advisory_only: true,
    does_not_affect_verdict: true,
    gyre_is_sole_verdict_authority: true,
    created_at: createdAt,
  };
}

export async function validateAgentGateApproval(
  currentProposal: AgentGateProposal | undefined,
  packet: AgentGateAuthorityPacket | undefined,
  consumedFingerprints: ReadonlySet<string>,
  timestamp = new Date().toISOString(),
): Promise<AgentGateApprovalResult> {
  const fallbackFingerprint = packet?.authority_fingerprint ?? 'missing-authority-packet';
  const baseRecord = (reason: AgentGateActionRecord['reason']): AgentGateActionRecord => ({
    action_class: 'agent_gate.approve_note',
    proposal_id: currentProposal?.id ?? packet?.proposal_id ?? 'unknown',
    decision: 'approved',
    authority_fingerprint: fallbackFingerprint,
    consumed_once: true,
    advisory_only: true,
    does_not_affect_verdict: true,
    gyre_is_sole_verdict_authority: true,
    timestamp,
    result: 'rejected',
    reason,
  });

  if (!currentProposal || !packet || !hasRequiredAgentGateAuthorityFields(currentProposal)) {
    return { ok: false, record: baseRecord('missing_authority_fields') };
  }

  const expected = await createAgentGateAuthorityPacket(currentProposal, packet.created_at);
  if (expected.authority_fingerprint !== packet.authority_fingerprint) {
    return { ok: false, record: baseRecord('tamper_rejected') };
  }

  if (consumedFingerprints.has(packet.authority_fingerprint)) {
    return { ok: false, record: baseRecord('replay_rejected') };
  }

  return {
    ok: true,
    record: {
      action_class: 'agent_gate.approve_note',
      proposal_id: currentProposal.id,
      decision: 'approved',
      authority_fingerprint: packet.authority_fingerprint,
      consumed_once: true,
      advisory_only: true,
      does_not_affect_verdict: true,
      gyre_is_sole_verdict_authority: true,
      timestamp,
      result: 'accepted',
    },
  };
}

export function createAgentGateRejectionRecord(
  proposal: AgentGateProposal,
  timestamp = new Date().toISOString(),
): AgentGateActionRecord {
  return {
    action_class: 'agent_gate.approve_note',
    proposal_id: proposal.id,
    decision: 'rejected',
    authority_fingerprint: 'not-issued-for-rejection',
    consumed_once: true,
    advisory_only: true,
    does_not_affect_verdict: true,
    gyre_is_sole_verdict_authority: true,
    timestamp,
    result: 'rejected',
    reason: 'analyst_rejected',
  };
}
