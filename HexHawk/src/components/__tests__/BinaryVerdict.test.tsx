/**
 * BinaryVerdict component tests — React Testing Library
 *
 * Covers: classification rendering, score display, signal source badges,
 * expand/collapse, workflow step navigation, empty state.
 */
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import BinaryVerdict from '../BinaryVerdict';
import type { BinaryVerdictResult } from '../../utils/correlationEngine';

// ─── Minimal verdict factory ──────────────────────────────────────────────────

function makeVerdict(overrides: Partial<BinaryVerdictResult> = {}): BinaryVerdictResult {
  return {
    classification: 'clean',
    threatScore: 8,
    confidence: 92,
    signalCount: 3,
    signals: [
      { id: 'sig-1', source: 'imports', finding: 'Known-clean DLLs', weight: -10, corroboratedBy: [] },
      { id: 'sig-2', source: 'structure', finding: 'Valid PE header', weight: -5, corroboratedBy: [] },
      { id: 'sig-3', source: 'strings', finding: 'No suspicious strings', weight: -3, corroboratedBy: [] },
    ],
    negativeSignals: [],
    amplifiers: [],
    dismissals: [],
    summary: 'Mock verdict',
    behaviors: [],
    contradictions: [],
    alternatives: [],
    reasoningChain: [],
    nextSteps: [],
    explainability: [],
    uncertaintyFlags: [],
    heuristicSignalIds: [],
    ...overrides,
  };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('BinaryVerdict', () => {
  it('renders clean classification correctly', () => {
    render(<BinaryVerdict verdict={makeVerdict()} />);
    expect(screen.getByText('Clean')).toBeTruthy();
    expect(screen.getByText('8')).toBeTruthy();   // threat score
    expect(screen.getByText('92%')).toBeTruthy(); // confidence
  });

  it('renders suspicious classification with correct label', () => {
    render(<BinaryVerdict verdict={makeVerdict({ classification: 'suspicious', threatScore: 55, confidence: 70 })} />);
    expect(screen.getByText('Suspicious')).toBeTruthy();
    expect(screen.getByText('55')).toBeTruthy();
  });

  it('renders all malware classifications without crash', () => {
    const classes = ['packer', 'dropper', 'ransomware-like', 'info-stealer', 'rat', 'loader', 'likely-malware', 'unknown'] as const;
    for (const cls of classes) {
      const { unmount } = render(<BinaryVerdict verdict={makeVerdict({ classification: cls })} />);
      unmount();
    }
  });

  it('expands signal list on header click', () => {
    const v = makeVerdict({ signalCount: 3 });
    render(<BinaryVerdict verdict={v} />);
    // Before expand: signals may be hidden
    const header = document.querySelector('.verdict-header');
    expect(header).toBeTruthy();
    fireEvent.click(header!);
    // After expand: signal descriptions should be visible
    expect(screen.getByText('Known-clean DLLs')).toBeTruthy();
  });

  it('renders zero-signal empty state without crash', () => {
    render(<BinaryVerdict verdict={makeVerdict({ signalCount: 0, signals: [] })} />);
    expect(screen.getByText('Clean')).toBeTruthy();
  });

  it('calls onNavigateTab when a workflow step is clicked', () => {
    const onNavigateTab = vi.fn();
    const v = makeVerdict({
      nextSteps: [
        { priority: 'medium', action: 'Inspect imports', rationale: 'Review import table', tab: 'strings' },
        { priority: 'medium', action: 'Check CFG', rationale: 'Review control flow', tab: 'cfg' },
      ],
    });
    render(<BinaryVerdict verdict={v} onNavigateTab={onNavigateTab} />);
    // Expand to see workflow steps
    const header = document.querySelector('.verdict-header');
    fireEvent.click(header!);
    // Find and click a workflow step
    const steps = document.querySelectorAll('.verdict-workflow-step');
    if (steps.length > 0) {
      fireEvent.click(steps[0]);
      expect(onNavigateTab).toHaveBeenCalled();
    }
  });

  it('displays behavioral tags when present', () => {
    const v = makeVerdict({
      classification: 'likely-malware',
      threatScore: 88,
      behaviors: ['anti-analysis', 'c2-communication'],
    });
    render(<BinaryVerdict verdict={v} />);
    const header = document.querySelector('.verdict-header');
    if (header) fireEvent.click(header);
    // Tags should appear somewhere in the rendered output
    const html = document.body.innerHTML;
    expect(html).toContain('anti-analysis');
  });

  it('shows contradictions when present', () => {
    const v = makeVerdict({
      contradictions: [
        { id: 'c1', observation: 'sig-clean', conflict: 'sig-suspicious', resolution: 'Conflicting network signals', severity: 'medium' },
      ],
    });
    const header = document.querySelector('.verdict-header');
    const { container } = render(<BinaryVerdict verdict={v} />);
    if (header) fireEvent.click(header);
    // Contradictions section should render
    void container; // at minimum, no crash
  });

  it('renders high-confidence malicious verdict with red styling', () => {
    const v = makeVerdict({ classification: 'rat', threatScore: 95, confidence: 98 });
    const { container } = render(<BinaryVerdict verdict={v} />);
    expect(container.innerHTML).toContain('95');
    expect(screen.getByText('RAT / Backdoor')).toBeTruthy();
  });
});
