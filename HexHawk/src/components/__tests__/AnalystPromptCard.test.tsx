import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { AnalystPromptCard } from '../AnalystPromptCard';
import { getAnalystPrompt } from '../../utils/analystPrompts';

describe('AnalystPromptCard', () => {
  it('renders accessible prompt markup', () => {
    render(<AnalystPromptCard prompt={getAnalystPrompt('after-inspect')} onDismiss={vi.fn()} />);

    expect(screen.getByRole('complementary', { name: /What imports does this binary use/i })).toBeInTheDocument();
    expect(screen.getByText(/Why it matters:/i)).toBeInTheDocument();
    expect(screen.getByText(/Suggested action:/i)).toBeInTheDocument();
  });

  it('dismiss removes the prompt through parent callback', () => {
    const onDismiss = vi.fn();
    render(<AnalystPromptCard prompt={getAnalystPrompt('after-disassemble')} onDismiss={onDismiss} />);

    fireEvent.click(screen.getByRole('button', { name: /Dismiss/i }));

    expect(onDismiss).toHaveBeenCalledWith('after-disassemble');
  });

  it('suggested action can navigate to the correct UI element', () => {
    const onNavigate = vi.fn();
    render(<AnalystPromptCard prompt={getAnalystPrompt('after-dynamic-resolution')} onDismiss={vi.fn()} onNavigate={onNavigate} />);

    fireEvent.click(screen.getByRole('button', { name: /Go to suggested view/i }));

    expect(onNavigate).toHaveBeenCalledWith('strings');
  });

  it('renders nothing when no prompt is selected', () => {
    const { container } = render(<AnalystPromptCard prompt={null} onDismiss={vi.fn()} />);
    expect(container).toBeEmptyDOMElement();
  });
});
