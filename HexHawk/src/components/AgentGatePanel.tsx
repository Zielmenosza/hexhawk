import React from 'react';
import type { AiObservationSource } from '../types/aiObservation';

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
  address?: number;
  gyre_is_sole_verdict_authority: true;
  advisory_only: true;
  does_not_affect_verdict: true;
}

interface AgentGatePanelProps {
  proposals: AgentGateProposal[];
  approvedProposals: AgentGateProposal[];
  onApprove: (proposal: AgentGateProposal) => void;
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

export function AgentGatePanel({ proposals, approvedProposals, onApprove, onReject }: AgentGatePanelProps) {
  return (
    <div className="agent-gate-panel" data-testid="agent-gate-panel">
      <h2 className="agent-gate-title">Agent Gate — Evidence Review Queue</h2>
      <div className="agent-gate-desc" role="note">
        These are suggestions from AETHERFRAME. Approving adds a note to your evidence. It does not change the GYRE verdict.
      </div>

      <section className="agent-gate-section">
        <h3 className="agent-gate-section-title">Pending suggestions ({proposals.length})</h3>
        {proposals.length === 0 ? (
          <p className="agent-gate-empty">No pending AI suggestions.</p>
        ) : (
          <ul className="agent-signal-list">
            {proposals.map(proposal => (
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
                <p className="agent-proposal-boundary">Does not affect GYRE verdict.</p>
                <div className="agent-signal-actions">
                  <button type="button" className="agent-btn-approve" onClick={() => onApprove(proposal)}>Approve — add as note</button>
                  <button type="button" className="agent-btn-reject" onClick={() => onReject(proposal)}>Reject</button>
                </div>
              </li>
            ))}
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
                <span className="agent-proposal-boundary">does_not_affect_verdict: true</span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

export default AgentGatePanel;
