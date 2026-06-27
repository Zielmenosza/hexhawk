import { fireEvent, render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { AiInsightPanel } from '../AiInsightPanel';
import type { AiObservation } from '../../types/aiObservation';

function obs(overrides: Partial<AiObservation> = {}): AiObservation {
  return {
    id: 'obs-1',
    kind: 'likely-purpose',
    title: 'File read operation',
    body: 'This function appears to open a file for reading based on observed import calls.',
    evidenceBasis: 'import prototype: CreateFileW + GENERIC_READ',
    source: 'aetherframe-static',
    analysisConfidence: 'high',
    functionId: 'function_401000',
    address: 0x401000,
    accepted: false,
    dismissed: false,
    generatedAt: '2026-06-27T00:00:00.000Z',
    gyre_is_sole_verdict_authority: true,
    advisory_only: true,
    ...overrides,
  };
}

describe('AiInsightPanel', () => {
  it('renders empty state when observations array is empty', () => {
    render(<AiInsightPanel observations={[]} />);

    expect(screen.getByTestId('ai-insight-empty')).toHaveTextContent('Run analysis to generate AI observations');
  });

  it('renders observation card with all required fields', () => {
    render(<AiInsightPanel observations={[obs()]} />);

    const card = screen.getByTestId('ai-observation-obs-1');
    expect(within(card).getByText('File read operation')).toBeInTheDocument();
    expect(within(card).getByText(/appears to open a file for reading/i)).toBeInTheDocument();
    expect(within(card).getByText('import prototype: CreateFileW + GENERIC_READ')).toBeInTheDocument();
    expect(within(card).getByText('Source: AETHERFRAME static pattern')).toBeInTheDocument();
    expect(within(card).getByText('high')).toBeInTheDocument();
    expect(within(card).getByText('function_401000')).toBeInTheDocument();
    expect(within(card).getByText('0x401000')).toBeInTheDocument();
    expect(within(card).getByText(/GYRE remains the sole verdict authority/i)).toBeInTheDocument();
  });

  it('accept button sets accepted true and removes from visible list after parent update', () => {
    const onObservationChange = vi.fn();
    const onAcceptAsNote = vi.fn();
    const { rerender } = render(
      <AiInsightPanel observations={[obs()]} onObservationChange={onObservationChange} onAcceptAsNote={onAcceptAsNote} />,
    );

    fireEvent.click(screen.getByText('Accept as note'));

    expect(onObservationChange).toHaveBeenCalledWith(expect.objectContaining({ accepted: true, dismissed: false }));
    expect(onAcceptAsNote).toHaveBeenCalledWith(expect.objectContaining({
      accepted: true,
      gyre_is_sole_verdict_authority: true,
      advisory_only: true,
    }));

    rerender(<AiInsightPanel observations={[obs({ accepted: true })]} />);
    expect(screen.queryByTestId('ai-observation-obs-1')).not.toBeInTheDocument();
  });

  it('dismiss button sets dismissed true and removes from visible list after parent update', () => {
    const onObservationChange = vi.fn();
    const { rerender } = render(<AiInsightPanel observations={[obs()]} onObservationChange={onObservationChange} />);

    fireEvent.click(screen.getByText('Dismiss'));

    expect(onObservationChange).toHaveBeenCalledWith(expect.objectContaining({ accepted: false, dismissed: true }));
    rerender(<AiInsightPanel observations={[obs({ dismissed: true })]} />);
    expect(screen.queryByTestId('ai-observation-obs-1')).not.toBeInTheDocument();
  });

  it('accepted card callback preserves authority envelope fields', () => {
    const onAcceptAsNote = vi.fn();
    render(<AiInsightPanel observations={[obs()]} onAcceptAsNote={onAcceptAsNote} />);

    fireEvent.click(screen.getByText('Accept as note'));

    expect(onAcceptAsNote).toHaveBeenCalledWith(expect.objectContaining({
      gyre_is_sole_verdict_authority: true,
      advisory_only: true,
    }));
  });

  it('does not render classification or verdict-claiming language', () => {
    render(<AiInsightPanel observations={[obs({ kind: 'decompiler-note' })]} />);

    const text = screen.getByTestId('ai-insight-panel').textContent?.toLowerCase() ?? '';
    expect(text).not.toContain('classification');
    expect(text).not.toContain('classified as');
    expect(text).not.toContain('confirmed malware');
  });

  it('LLM-sourced cards render with amber border class', () => {
    render(<AiInsightPanel observations={[obs({ source: 'aetherframe-llm' })]} />);

    expect(screen.getByTestId('ai-observation-obs-1')).toHaveClass('ai-observation-card--llm');
  });

  it('static-pattern cards render with blue border class', () => {
    render(<AiInsightPanel observations={[obs({ source: 'aetherframe-static' })]} />);

    expect(screen.getByTestId('ai-observation-obs-1')).toHaveClass('ai-observation-card--static');
  });

  it('suspicious and technique cards show explicit not-verdict language', () => {
    render(<AiInsightPanel observations={[obs({ kind: 'suspicious-pattern' })]} />);

    expect(screen.getByText(/Not a verdict. GYRE decides verdicts./i)).toBeInTheDocument();
  });
});
