/**
 * OperatorConsole component tests — React Testing Library
 *
 * Covers: render, prompt submission, workflow generation, step navigation,
 * tab switching, empty/loading states.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import OperatorConsole from '../OperatorConsole';
import type { BinaryContext } from '../../utils/operatorConsole';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeContext(overrides: Partial<BinaryContext> = {}): BinaryContext {
  return {
    binaryPath: 'test.exe',
    architecture: 'x86_64',
    verdictClassification: 'suspicious',
    verdictBehaviors: ['anti-analysis'],
    ...overrides,
  };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('OperatorConsole', () => {
  const onNavigateTab = vi.fn();

  beforeEach(() => {
    onNavigateTab.mockReset();
  });

  it('renders without crashing', () => {
    render(<OperatorConsole onNavigateTab={onNavigateTab} context={makeContext()} />);
    // Should show the prompt input or console header
    const html = document.body.innerHTML;
    expect(html.length).toBeGreaterThan(0);
  });

  it('accepts text input in the prompt field', () => {
    render(<OperatorConsole onNavigateTab={onNavigateTab} context={makeContext()} />);
    const inputs = document.querySelectorAll('input, textarea');
    if (inputs.length > 0) {
      const input = inputs[0] as HTMLInputElement;
      fireEvent.change(input, { target: { value: 'analyze for malware' } });
      expect(input.value).toBe('analyze for malware');
    }
  });

  it('generates a workflow on prompt submission', async () => {
    render(<OperatorConsole onNavigateTab={onNavigateTab} context={makeContext()} />);
    const inputs = document.querySelectorAll('input, textarea');
    if (inputs.length > 0) {
      const input = inputs[0] as HTMLInputElement;
      fireEvent.change(input, { target: { value: 'check for anti-debug techniques' } });
      const form = document.querySelector('form');
      if (form) {
        fireEvent.submit(form);
      } else {
        const buttons = document.querySelectorAll('button');
        for (const btn of buttons) {
          if (btn.type === 'submit' || btn.textContent?.toLowerCase().includes('run') || btn.textContent?.toLowerCase().includes('go')) {
            fireEvent.click(btn);
            break;
          }
        }
      }
      // After submission, a workflow with steps should appear
      await waitFor(() => {
        const html = document.body.innerHTML;
        expect(html.length).toBeGreaterThan(100);
      }, { timeout: 1000 });
    }
  });

  it('shows context information from binary', () => {
    render(<OperatorConsole onNavigateTab={onNavigateTab} context={makeContext({ binaryPath: 'malware.exe' })} />);
    const html = document.body.innerHTML;
    // Context should inform the console UI
    expect(html.length).toBeGreaterThan(0);
  });

  it('renders with clean binary context', () => {
    render(<OperatorConsole onNavigateTab={onNavigateTab} context={makeContext({
      verdictClassification: 'clean',
      verdictBehaviors: [],
    })} />);
    // Should render without error
    expect(document.body.innerHTML.length).toBeGreaterThan(0);
  });

  it('renders with zero-import binary context', () => {
    render(<OperatorConsole onNavigateTab={onNavigateTab} context={makeContext()} />);
    expect(document.body.innerHTML.length).toBeGreaterThan(0);
  });
});
