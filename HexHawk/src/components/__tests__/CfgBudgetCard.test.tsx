import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import CfgBudgetCard from '../CfgBudgetCard';

describe('CfgBudgetCard', () => {
  it('shows CFG budgets and truncation proof when graph was truncated', () => {
    render(<CfgBudgetCard nodes={2000} edges={4000} nodeBudget={2000} edgeBudget={4000} omittedNodes={12} omittedEdges={20} truncated />);

    expect(screen.getByText('CFG budget proof')).toBeTruthy();
    expect(screen.getByText('truncated')).toBeTruthy();
    expect(screen.getAllByText('2000')).toHaveLength(2);
    expect(screen.getAllByText('4000')).toHaveLength(2);
    expect(screen.getByText(/12 omitted node/i)).toBeTruthy();
    expect(screen.getByText(/20 omitted edge/i)).toBeTruthy();
  });

  it('shows complete-within-budget state when CFG was not truncated', () => {
    render(<CfgBudgetCard nodes={10} edges={9} nodeBudget={2000} edgeBudget={4000} omittedNodes={0} omittedEdges={0} truncated={false} />);
    expect(screen.getByText('complete within budget')).toBeTruthy();
  });
});
