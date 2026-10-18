import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { ControlFlowGraph } from '../ControlFlowGraph';

describe('ControlFlowGraph nullable native node fields', () => {
  it('renders external nodes with null address ranges instead of crashing the workspace', () => {
    render(
      <div style={{ width: 900, height: 500 }}>
        <ControlFlowGraph
          graph={{
            nodes: [{
              id: 'external-exit',
              label: 'External exit',
              start: null,
              end: null,
              address: null,
              instruction_count: 0,
              block_type: 'external',
              layout_x: 0,
              layout_y: 0,
            }],
            edges: [],
          }}
        />
      </div>,
    );

    expect(screen.getByText('External exit')).toBeInTheDocument();
    expect(screen.getByText('EXTERNAL')).toBeInTheDocument();
  });
});
