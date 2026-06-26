import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import WorkflowNav from '../WorkflowNav';

describe('WorkflowNav Function Notebook wiring', () => {
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
});
