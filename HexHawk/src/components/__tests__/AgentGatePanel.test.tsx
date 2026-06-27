import { fireEvent, render, screen } from '@testing-library/react';
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

  it('approve rename adds note-shaped proposal and does not rename directly', () => {
    const onApprove = vi.fn();
    render(<AgentGatePanel proposals={[proposal()]} approvedProposals={[]} onApprove={onApprove} onReject={vi.fn()} />);

    fireEvent.click(screen.getByRole('button', { name: /Approve — add as note/i }));

    expect(onApprove).toHaveBeenCalledWith(expect.objectContaining({
      proposalKind: 'rename-function',
      proposedValue: 'open_config_file',
      does_not_affect_verdict: true,
    }));
    expect(screen.getByText(/Does not rename the disassembly/i)).toBeInTheDocument();
  });

  it('reject removes item through parent callback', () => {
    const onReject = vi.fn();
    render(<AgentGatePanel proposals={[proposal()]} approvedProposals={[]} onApprove={vi.fn()} onReject={onReject} />);

    fireEvent.click(screen.getByRole('button', { name: /^Reject$/i }));

    expect(onReject).toHaveBeenCalledWith(expect.objectContaining({ id: 'prop-1' }));
  });

  it('approved item carries does_not_affect_verdict in evidence display', () => {
    render(<AgentGatePanel proposals={[]} approvedProposals={[proposal()]} onApprove={vi.fn()} onReject={vi.fn()} />);

    expect(screen.getByText(/Suggested name: open_config_file/i)).toBeInTheDocument();
    expect(screen.getByText(/does_not_affect_verdict: true/i)).toBeInTheDocument();
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
});
