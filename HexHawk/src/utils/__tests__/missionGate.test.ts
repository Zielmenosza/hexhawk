import { evaluateMissionGateProposal, setMissionGateProvider, MissionGateProvider } from '../missionGate';
import { AgentGateProposal } from '../../components/AgentGatePanel';

describe('Mission Gate Proposal Tests', () => {
  it('should evaluate a proposal through the Mission Gate', async () => {
    let recordedPacket: any = null;
    const mockProvider: MissionGateProvider = {
      evaluate: async (packet) => {
        recordedPacket = packet;
        return false;
      }
    };
    setMissionGateProvider(mockProvider);

    const mockProposal: AgentGateProposal = {
      id: 'prop-123',
      proposalKind: 'add-function-note',
      title: 'Note',
      rationale: 'Testing',
      evidenceBasis: 'None',
      proposedValue: 'A test note',
      source: 'agent',
      functionId: 'func-456',
      gyre_is_sole_verdict_authority: true,
      advisory_only: true,
      does_not_affect_verdict: true,
    };

    const isAllowed = await evaluateMissionGateProposal(mockProposal);
    expect(isAllowed).toBe(false);
    expect(recordedPacket).not.toBeNull();
    expect(recordedPacket.proposalId).toBe('prop-123');
    expect(recordedPacket.source).toBe('agent');
    expect(recordedPacket.proposalKind).toBe('add-function-note');
    expect(recordedPacket.targetFunctionId).toBe('func-456');
    expect(recordedPacket.findingHash).toBeTruthy();
  });
});
