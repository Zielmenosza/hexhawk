import { render, screen, fireEvent } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import StrikeApiReferencePanel from '../StrikeApiReferencePanel';

describe('StrikeApiReferencePanel', () => {
  it('renders searchable STRIKE API method references with authority boundary labels', () => {
    render(<StrikeApiReferencePanel />);

    expect(screen.getByText('STRIKE API Reference')).toBeInTheDocument();
    expect(screen.getByText('matchIL')).toBeInTheDocument();
    expect(screen.getAllByText('not verdict authority').length).toBeGreaterThan(0);

    fireEvent.change(screen.getByLabelText('Search STRIKE API methods'), { target: { value: 'FunctionIntelligence' } });

    expect(screen.getByText('buildFunctionIntelligence')).toBeInTheDocument();
    expect(screen.queryByText('matchIL')).not.toBeInTheDocument();
  });
});
