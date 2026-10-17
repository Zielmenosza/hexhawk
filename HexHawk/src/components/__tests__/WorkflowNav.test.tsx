import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import WorkflowNav, { getWorkflowViewPresentation } from '../WorkflowNav';
import type { NavView } from '../WorkflowNav';
import WelcomeScreen from '../WelcomeScreen';

const ALL_NAV_VIEWS: NavView[] = [
  'load', 'metadata', 'inspect', 'hex', 'strings', 'disassembly', 'cfg',
  'function-notebook', 'decompile', 'talon', 'ai-observations', 'verdict',
  'signals', 'report', 'history', 'nest', 'activity', 'patch', 'constraint',
  'sandbox', 'debugger', 'diff', 'repl', 'agent', 'plugins', 'strike-api',
  'help', 'about',
];

describe('WorkflowNav beginner-facing names and descriptions', () => {
  it('introduces only the bounded PE input scope without advertising raw or ELF intake', () => {
    render(<WelcomeScreen onDismiss={vi.fn()} />);
    const card = document.querySelector('.welcome-card')!;
    expect(card).toHaveTextContent('PE32/x86');
    expect(card).toHaveTextContent('PE32+/x64');
    expect(card).toHaveTextContent('64 MiB');
    expect(card).not.toHaveTextContent(/raw binary|ELF file/i);
  });

  it('walks through included analysis/report/limits rather than excluded advisory or execution workspaces', () => {
    const dismiss = vi.fn();
    render(<WelcomeScreen onDismiss={dismiss} />);
    const titles: string[] = [];
    for (let step = 0; step < 6; step++) {
      titles.push(document.querySelector('.welcome-card h2')!.textContent!);
      if (step < 5) fireEvent.click(screen.getByRole('button', { name: 'Next →' }));
    }
    expect(titles).toEqual(['Load a binary', 'Read the GYRE verdict', 'Review instructions', 'NEST — evidence organization', 'Export a report', 'Release limits']);
    expect(document.querySelector('.welcome-card')).toHaveTextContent(/not.*safety certificate/i);
    fireEvent.click(screen.getByRole('button', { name: 'Get started' }));
    expect(dismiss).toHaveBeenCalledWith(true);
  });

  it('keeps excluded workflows unavailable in the bounded native release without bypassing tier gates', () => {
    const onSelect = vi.fn();
    render(<WorkflowNav activeView="inspect" workflowState="analyzed" tier="enterprise"
      fileName="sample.exe" onSelect={onSelect} onLoadFile={vi.fn()} boundedRelease />);
    for (const view of ['repl', 'sandbox', 'plugins', 'debugger', 'patch', 'constraint', 'diff', 'agent',
      'ai-observations', 'talon', 'decompile', 'function-notebook', 'history', 'strike-api']) {
      const button = screen.getByTestId(`nav-${view}`);
      expect(button).toBeDisabled();
      expect(button).toHaveAttribute('title', expect.stringMatching(/excluded.*first release/i));
      fireEvent.click(button);
    }
    expect(onSelect).not.toHaveBeenCalled();
    for (const view of ['load', 'inspect', 'metadata', 'hex', 'strings', 'disassembly', 'cfg', 'verdict', 'signals', 'report', 'nest', 'activity', 'help', 'about']) {
      expect(screen.getByTestId(`nav-${view}`)).not.toBeDisabled();
    }
  });

  it('provides a main-window title and description for every navigation view', () => {
    const presentations = ALL_NAV_VIEWS.map(getWorkflowViewPresentation);

    expect(presentations).toHaveLength(28);
    expect(new Set(presentations.map((item) => item.title)).size).toBe(28);
    presentations.forEach((item) => {
      expect(item.title.trim()).not.toBe('');
      expect(item.technicalLabel.trim()).not.toBe('');
      expect(item.description.trim()).not.toBe('');
      expect(item.icon.trim()).not.toBe('');
    });
  });

  it('renders the function view as a clear action with an outcome-focused description', () => {
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
    expect(screen.getByText('Examine one function')).toBeInTheDocument();
    expect(screen.getByText(/Collect everything known about the selected function in one place/i)).toBeInTheDocument();
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

  it('renders AI observations as suggestions the user must check', () => {
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
    expect(screen.getByText('Review AI suggestions')).toBeInTheDocument();
    expect(screen.getByText(/suggestions for you to check, not HexHawk’s final assessment/i)).toBeInTheDocument();
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

  it('explains that accepted AI notes cannot change the assessment or evidence signals', () => {
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

    expect(screen.getByTestId('nav-agent')).toHaveTextContent(/Accept or reject notes suggested by AI/i);
    expect(screen.getByTestId('nav-agent')).toHaveTextContent(/cannot change HexHawk’s assessment or its evidence signals/i);
    expect(screen.getByLabelText('2 pending agent suggestions')).toBeInTheDocument();
  });

  it('names the debugger by what it does and warns that it executes the file', () => {
    render(
      <WorkflowNav
        activeView="debugger"
        workflowState="analyzed"
        tier="enterprise"
        fileName="sample.exe"
        onSelect={vi.fn()}
        onLoadFile={vi.fn()}
      />,
    );

    const debuggerItem = screen.getByTestId('nav-debugger');
    expect(debuggerItem).toHaveTextContent('Live Debugger');
    expect(debuggerItem).toHaveTextContent(/pause it, step through instructions/i);
    expect(debuggerItem).toHaveTextContent(/This executes the file—only use software you trust/i);
    expect(screen.queryByText('Runtime trace review')).not.toBeInTheDocument();
  });
});
