import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import WorkflowNav from '../WorkflowNav';

describe('WorkflowNav Function Notebook and AI observations wiring', () => {
  it('renders Function details navigation with plain-language description', () => {
    render(
      <WorkflowNav
        activeView="function-notebook"
        workflowState="analyzed"
        tier="enterprise"
        fileName="sample.exe"
        onSelect={vi.fn()}
        onLoadFile={vi.fn()}
      />,
    );

    expect(screen.getByTestId('nav-function-notebook')).toBeInTheDocument();
    expect(screen.getByText('Function details')).toBeInTheDocument();
    expect(screen.getByText(/Imports, calls, pseudocode, and evidence for the selected function/i)).toBeInTheDocument();
  });

  it('selects function-notebook view when clicked', () => {
    const onSelect = vi.fn();
    render(
      <WorkflowNav
        activeView="disassembly"
        workflowState="analyzed"
        tier="enterprise"
        fileName="sample.exe"
        onSelect={onSelect}
        onLoadFile={vi.fn()}
      />,
    );

    fireEvent.click(screen.getByTestId('nav-function-notebook'));

    expect(onSelect).toHaveBeenCalledWith('function-notebook');
  });

  it('renders AI observations navigation with advisory AETHERFRAME description', () => {
    render(
      <WorkflowNav
        activeView="ai-observations"
        workflowState="analyzed"
        tier="enterprise"
        fileName="sample.exe"
        onSelect={vi.fn()}
        onLoadFile={vi.fn()}
      />,
    );

    expect(screen.getByTestId('nav-ai-observations')).toBeInTheDocument();
    expect(screen.getByText('AI observations')).toBeInTheDocument();
    expect(screen.getByText(/Suggestions from AETHERFRAME — not verdicts/i)).toBeInTheDocument();
  });

  it('selects ai-observations view when clicked', () => {
    const onSelect = vi.fn();
    render(
      <WorkflowNav
        activeView="function-notebook"
        workflowState="analyzed"
        tier="enterprise"
        fileName="sample.exe"
        onSelect={onSelect}
        onLoadFile={vi.fn()}
      />,
    );

    fireEvent.click(screen.getByTestId('nav-ai-observations'));

    expect(onSelect).toHaveBeenCalledWith('ai-observations');
  });

  it('describes Agent Gate approvals as advisory notes that do not affect verdicts or signals', () => {
    render(
      <WorkflowNav
        activeView="agent"
        workflowState="analyzed"
        tier="enterprise"
        fileName="sample.exe"
        onSelect={vi.fn()}
        onLoadFile={vi.fn()}
        agentQueueCount={2}
      />,
    );

    expect(screen.getByTestId('nav-agent')).toHaveTextContent(/Approving adds analyst notes only/i);
    expect(screen.getByTestId('nav-agent')).toHaveTextContent(/does not affect GYRE verdicts or analysis signals/i);
    expect(screen.getByLabelText('2 pending agent suggestions')).toBeInTheDocument();
  });
});
