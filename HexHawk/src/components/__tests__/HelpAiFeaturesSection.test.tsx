import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { HelpAiFeaturesSection } from '../HelpAiFeaturesSection';

describe('HelpAiFeaturesSection', () => {
  it('renders AI features section', () => {
    render(<HelpAiFeaturesSection />);
    expect(screen.getByRole('heading', { name: /AI features in HexHawk/i })).toBeInTheDocument();
  });

  it('contains What AI never does list', () => {
    render(<HelpAiFeaturesSection />);
    expect(screen.getByText(/What AI never does in HexHawk/i)).toBeInTheDocument();
    expect(screen.getByText(/Add evidence to NEST without your approval/i)).toBeInTheDocument();
    expect(screen.getByText(/Override the static analysis/i)).toBeInTheDocument();
  });

  it('contains all three feature descriptions', () => {
    render(<HelpAiFeaturesSection />);
    expect(screen.getByText(/Pattern recognition \(AETHERFRAME\)/i)).toBeInTheDocument();
    expect(screen.getByText(/Plain-English summaries/i)).toBeInTheDocument();
    expect(screen.getByText(/Evidence suggestions \(Agent Gate\)/i)).toBeInTheDocument();
  });

  it('does not claim AI produces verdicts', () => {
    render(<HelpAiFeaturesSection />);
    const text = document.body.textContent?.toLowerCase() ?? '';
    expect(text).not.toContain('ai produces verdict');
    expect(text).not.toContain('ai decides verdict');
    expect(text).not.toContain('classified as');
    expect(text).not.toContain('confirmed malware');
  });
});
