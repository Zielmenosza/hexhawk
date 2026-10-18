import React from 'react';
import type { AiObservationSource } from '../types/aiObservation';
import {
  createAgentGateAuthorityPacket,
  type AgentGateActionRecord,
  type AgentGateAuthorityPacket,
} from '../utils/agentGateAuthority';

export interface AgentGateProposal {
  id: string;
  proposalKind:
    | 'add-function-note'
    | 'rename-function'
    | 'add-xref-note'
    | 'flag-for-review'
    | 'add-import-context';
  title: string;
  rationale: string;
  evidenceBasis: string;
  proposedValue: string;
  currentValue?: string;
  source: AiObservationSource;
  functionId?: string;
  observationId?: string;
  address?: number;
  gyre_is_sole_verdict_authority: true;
  advisory_only: true;
  does_not_affect_verdict: true;
}

interface AgentGatePanelProps {
  proposals: AgentGateProposal[];
  approvedProposals: AgentGateProposal[];
  actionLog?: AgentGateActionRecord[];
  onApprove: (proposal: AgentGateProposal, packet: AgentGateAuthorityPacket) => void | Promise<void>;
  onReject: (proposal: AgentGateProposal) => void;
}

function effectText(proposal: AgentGateProposal): string {
  switch (proposal.proposalKind) {
    case 'rename-function':
      return `adds analyst note "suggested name: ${proposal.proposedValue}" to the function. Does not rename the disassembly.`;
    case 'flag-for-review':
      return `adds a review flag note: ${proposal.proposedValue}.`;
    case 'add-import-context':
      return `adds import context note: ${proposal.proposedValue}.`;
    case 'add-xref-note':
      return `adds cross-reference note: ${proposal.proposedValue}.`;
    default:
      return `adds analyst note: ${proposal.proposedValue}.`;
  }
}

export function AgentGatePanel({ proposals, approvedProposals, actionLog = [], onApprove, onReject }: AgentGatePanelProps) {
  const [packets, setPackets] = React.useState<Record<string, AgentGateAuthorityPacket>>({});

  React.useEffect(() => {
    if (proposals.length === 0) return;
    let cancelled = false;
    void Promise.all(proposals.map(async proposal => [proposal.id, await createAgentGateAuthorityPacket(proposal)] as const))
      .then(entries => {
        if (!cancelled) setPackets(Object.fromEntries(entries));
      })
      .catch(() => {
        if (!cancelled) setPackets({});
      });
    return () => { cancelled = true; };
  }, [proposals]);

  return (
    <div className="agent-gate-panel" data-testid="agent-gate-panel">
      <h2 className="agent-gate-title">AI Suggestions Review</h2>
      <div className="agent-gate-desc" role="note">
        Review optional AI suggestions before they become notes. Approval creates a one-time receipt tied to the exact suggestion text and evidence. These notes help your review but never change HexHawk’s file assessment.
      </div>

      <section className="agent-gate-section">
        <h3 className="agent-gate-section-title">Pending suggestions ({proposals.length})</h3>
        {proposals.length === 0 ? (
          <p className="agent-gate-empty">No pending AI suggestions.</p>
        ) : (
          <ul className="agent-signal-list">
            {proposals.map(proposal => {
              const packet = packets[proposal.id];
              return (
              <li key={proposal.id} className="agent-signal-item agent-proposal-card">
                <div className="agent-signal-meta">
                  <span className="agent-signal-id">{proposal.proposalKind}</span>
                  <span className="agent-signal-certainty agent-cert-heuristic">{proposal.source}</span>
                </div>
                <h4>{proposal.title}</h4>
                {proposal.currentValue && <p><strong>Current:</strong> {proposal.currentValue}</p>}
                <p><strong>Proposed:</strong> {proposal.proposedValue}</p>
                <p><strong>Reason:</strong> {proposal.rationale}</p>
                <p><strong>Evidence basis:</strong> {proposal.evidenceBasis}</p>
                <p><strong>Effect:</strong> {effectText(proposal)}</p>
                <p className="agent-proposal-boundary">Receipt: {packet ? packet.authority_fingerprint.slice(0, 16) : 'preparing…'} · one use only · does not change the file assessment.</p>
                <div className="agent-signal-actions">
                  <button
                    type="button"
                    className="agent-btn-approve"
                    disabled={!packet}
                    onClick={() => { if (packet) void onApprove(proposal, packet); }}
                  >Approve — add as note</button>
                  <button type="button" className="agent-btn-reject" onClick={() => onReject(proposal)}>Reject</button>
                </div>
              </li>
              );
            })}
          </ul>
        )}
      </section>

      <section className="agent-gate-section">
        <h3 className="agent-gate-section-title">Approved notes ({approvedProposals.length})</h3>
        {approvedProposals.length === 0 ? (
          <p className="agent-gate-empty">No analyst-accepted AI suggestions — advisory only.</p>
        ) : (
          <ul className="agent-signal-list agent-signal-list--approved">
            {approvedProposals.map(proposal => (
              <li key={proposal.id} className="agent-signal-item agent-signal-item--approved">
                <span className="agent-signal-id">{proposal.functionId ?? proposal.id}</span>
                <span className="agent-signal-finding">
                  {proposal.proposalKind === 'rename-function' ? `Suggested name: ${proposal.proposedValue}` : proposal.proposedValue}
                  {' '} (analyst-accepted AI suggestion)
                </span>
                <span className="agent-proposal-boundary">Advisory note only · file assessment unchanged</span>
              </li>
            ))}
          </ul>
        )}
      </section>

      {actionLog.length > 0 && (
        <section className="agent-gate-section">
          <h3 className="agent-gate-section-title">Decision log ({actionLog.length})</h3>
          <ul className="agent-signal-list agent-signal-list--approved">
            {actionLog.slice(-5).map((entry, index) => (
              <li key={`${entry.proposal_id}-${entry.timestamp}-${index}`} className="agent-signal-item agent-signal-item--approved">
                <span className="agent-signal-id">{entry.decision}</span>
                <span className="agent-signal-finding">
                  {entry.result === 'accepted' ? 'accepted once' : (entry.reason?.replace(/_/g, ' ') ?? 'rejected')}
                </span>
                <span className="agent-proposal-boundary">{entry.authority_fingerprint.slice(0, 16)}</span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

export default AgentGatePanel;
