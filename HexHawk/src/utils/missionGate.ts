import type { AgentGateProposal } from '../components/AgentGatePanel';

export interface MissionGateAuthorityPacket {
  proposalId: string;
  source: string;
  proposalKind: string;
  targetFunctionId?: string;
  findingHash: string;
}

export interface MissionGateProvider {
  evaluate(packet: MissionGateAuthorityPacket): Promise<boolean>;
}

export class DefaultMissionGateProvider implements MissionGateProvider {
  async evaluate(packet: MissionGateAuthorityPacket): Promise<boolean> {
    // In production, this would call the Tauri backend or @gomission/mcp.
    return true;
  }
}

let activeProvider: MissionGateProvider = new DefaultMissionGateProvider();

export function setMissionGateProvider(provider: MissionGateProvider) {
  activeProvider = provider;
}

// Simple hash implementation for the text finding
async function computeHash(text: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function evaluateMissionGateProposal(proposal: AgentGateProposal): Promise<boolean> {
  const hash = await computeHash(proposal.proposedValue || proposal.rationale || '');
  const packet: MissionGateAuthorityPacket = {
    proposalId: proposal.id,
    source: String(proposal.source),
    proposalKind: proposal.proposalKind,
    targetFunctionId: proposal.functionId,
    findingHash: hash,
  };
  
  return await activeProvider.evaluate(packet);
}
