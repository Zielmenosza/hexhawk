import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { AgentGatePanel, type AgentGateProposal } from '../AgentGatePanel';

function proposal(overrides: Partial<AgentGateProposal> = {}): AgentGateProposal {
  return {
    id: 'prop-1',
    proposalKind: 'rename-function',
    title: 'Rename function?',
    rationale: 'CreateFileW with OPEN_EXISTING suggests this is a file open wrapper.',
    evidenceBasis: 'CreateFileW + OPEN_EXISTING',
    proposedValue: 'open_config_file',
    currentValue: 'sub_401000',
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

describe('AgentGatePanel', () => {
  it('renders empty queue message', () => {
    render(<AgentGatePanel proposals={[]} approvedProposals={[]} onApprove={vi.fn()} onReject={vi.fn()} />);

    expect(screen.getByText('No pending AI suggestions.')).toBeInTheDocument();
  });

  it('approve rename adds note-shaped proposal with an authority packet and does not rename directly', async () => {
    const onApprove = vi.fn();
    render(<AgentGatePanel proposals={[proposal()]} approvedProposals={[]} onApprove={onApprove} onReject={vi.fn()} />);

    await waitFor(() => expect(screen.getByText(/Receipt: [a-f0-9]{16}/i)).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /Approve — add as note/i }));

    expect(onApprove).toHaveBeenCalledWith(
      expect.objectContaining({
        proposalKind: 'rename-function',
        proposedValue: 'open_config_file',
        does_not_affect_verdict: true,
      }),
      expect.objectContaining({
        action_class: 'agent_gate.approve_note',
        authority_fingerprint: expect.stringMatching(/^[a-f0-9]{64}$/),
        consumed_once: true,
        does_not_affect_verdict: true,
      }),
    );
    expect(screen.getByText(/Does not rename the disassembly/i)).toBeInTheDocument();
  });

  it('reject removes item through parent callback', () => {
    const onReject = vi.fn();
    render(<AgentGatePanel proposals={[proposal()]} approvedProposals={[]} onApprove={vi.fn()} onReject={onReject} />);

    fireEvent.click(screen.getByRole('button', { name: /^Reject$/i }));

    expect(onReject).toHaveBeenCalledWith(expect.objectContaining({ id: 'prop-1' }));
  });

  it('approved item is displayed as an advisory note without internal verdict jargon', () => {
    render(<AgentGatePanel proposals={[]} approvedProposals={[proposal()]} onApprove={vi.fn()} onReject={vi.fn()} />);

    expect(screen.getByText(/Suggested name: open_config_file/i)).toBeInTheDocument();
    expect(screen.getByText(/Advisory note only · file assessment unchanged/i)).toBeInTheDocument();
  });

  it('queue badge count is visible in heading', () => {
    render(<AgentGatePanel proposals={[proposal(), proposal({ id: 'prop-2' })]} approvedProposals={[]} onApprove={vi.fn()} onReject={vi.fn()} />);

    expect(screen.getByText('Pending suggestions (2)')).toBeInTheDocument();
  });

  it('does not display GYRE verdict field mutations', () => {
    render(<AgentGatePanel proposals={[proposal()]} approvedProposals={[proposal()]} onApprove={vi.fn()} onReject={vi.fn()} />);

    const text = document.body.textContent ?? '';
    expect(text).not.toContain('threatScore');
    expect(text).not.toContain('classification');
    expect(text).not.toContain('agentSignals');
  });

  it('renders machine-readable rejection reasons from the decision log', () => {
    render(
      <AgentGatePanel
        proposals={[]}
        approvedProposals={[]}
        actionLog={[{
          action_class: 'agent_gate.approve_note',
          proposal_id: 'prop-1',
          decision: 'approved',
          authority_fingerprint: 'a'.repeat(64),
          consumed_once: true,
          advisory_only: true,
          does_not_affect_verdict: true,
          gyre_is_sole_verdict_authority: true,
          timestamp: '2026-08-02T00:00:00.000Z',
          result: 'rejected',
          reason: 'replay_rejected',
        }]}
        onApprove={vi.fn()}
        onReject={vi.fn()}
      />,
    );

    expect(screen.getByText(/replay rejected/i)).toBeInTheDocument();
    expect(screen.getByText('aaaaaaaaaaaaaaaa')).toBeInTheDocument();
  });
});
