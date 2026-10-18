import { describe, expect, it } from 'vitest';
import type { AgentGateProposal } from '../../components/AgentGatePanel';
import {
  createAgentGateAuthorityPacket,
  validateAgentGateApproval,
} from '../agentGateAuthority';

function proposal(overrides: Partial<AgentGateProposal> = {}): AgentGateProposal {
  return {
    id: 'prop-1',
    proposalKind: 'add-function-note',
    title: 'Add review note?',
    rationale: 'Imports and strings point to configuration file handling.',
    evidenceBasis: 'CreateFileW + config.json string at 0x401020',
    proposedValue: 'Possible configuration file handling helper.',
    source: 'aetherframe-static',
    functionId: 'function_401000',
    observationId: 'obs-1',
    address: 0x401000,
    gyre_is_sole_verdict_authority: true,
    advisory_only: true,
    does_not_affect_verdict: true,
    ...overrides,
  };
}

describe('agent gate authority packets', () => {
  it('creates a deterministic fingerprint bound to exact proposal fields', async () => {
    const first = await createAgentGateAuthorityPacket(proposal(), '2026-08-02T00:00:00.000Z');
    const second = await createAgentGateAuthorityPacket(proposal(), '2026-08-02T00:00:00.000Z');

    expect(first.authority_fingerprint).toMatch(/^[a-f0-9]{64}$/);
    expect(first).toMatchObject({
      action_class: 'agent_gate.approve_note',
      proposal_id: 'prop-1',
      proposal_kind: 'add-function-note',
      source: 'aetherframe-static',
      function_id: 'function_401000',
      observation_id: 'obs-1',
      address: 0x401000,
      advisory_only: true,
      does_not_affect_verdict: true,
      gyre_is_sole_verdict_authority: true,
      consumed_once: true,
    });
    expect(second.authority_fingerprint).toBe(first.authority_fingerprint);
  });

  it('rejects changed input after a packet was issued', async () => {
    const issued = await createAgentGateAuthorityPacket(proposal(), '2026-08-02T00:00:00.000Z');
    const result = await validateAgentGateApproval(
      proposal({ proposedValue: 'Malware verdict confirmed.' }),
      issued,
      new Set(),
      '2026-08-02T00:01:00.000Z',
    );

    expect(result.ok).toBe(false);
    expect(result.record).toMatchObject({
      decision: 'approved',
      result: 'rejected',
      reason: 'tamper_rejected',
      advisory_only: true,
      does_not_affect_verdict: true,
      gyre_is_sole_verdict_authority: true,
    });
  });

  it('accepts the exact packet once and rejects replay', async () => {
    const issued = await createAgentGateAuthorityPacket(proposal(), '2026-08-02T00:00:00.000Z');
    const consumed = new Set<string>();
    const first = await validateAgentGateApproval(proposal(), issued, consumed);
    expect(first.ok).toBe(true);

    consumed.add(issued.authority_fingerprint);
    const replay = await validateAgentGateApproval(proposal(), issued, consumed);
    expect(replay.ok).toBe(false);
    expect(replay.record.reason).toBe('replay_rejected');
  });

  it('fails closed when authority fields are missing or unknown', async () => {
    const unsafe = proposal({ advisory_only: false as true });

    await expect(createAgentGateAuthorityPacket(unsafe)).rejects.toThrow('missing_agent_gate_authority_fields');
    const result = await validateAgentGateApproval(unsafe, undefined, new Set());
    expect(result.ok).toBe(false);
    expect(result.record.reason).toBe('missing_authority_fields');
  });
});
