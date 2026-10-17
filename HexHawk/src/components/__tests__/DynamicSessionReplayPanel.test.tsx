import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import DynamicSessionReplayPanel from '../DynamicSessionReplayPanel';
import { buildOfflineDynamicTrace } from '../../utils/dynamicSessionTrace';

const SHA = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210';

describe('DynamicSessionReplayPanel', () => {
  it('renders replay-first safety copy when no trace is loaded', () => {
    render(<DynamicSessionReplayPanel trace={null} />);

    expect(screen.getByText('Dynamic Session Replay')).toBeInTheDocument();
    expect(screen.getByText(/Offline traces are replayable without executing the specimen/i)).toBeInTheDocument();
    expect(screen.getByText(/Live attach\/debug requires separate explicit consent/i)).toBeInTheDocument();
  });

  it('renders replayable trace events as advisory evidence', () => {
    const trace = buildOfflineDynamicTrace({
      sessionId: 'dyn_test',
      binarySha256: SHA,
      createdAt: '2026-07-16T00:00:00.000Z',
      events: [{
        id: 'evt_001',
        kind: 'register-snapshot',
        timestamp: '2026-07-16T00:00:01.000Z',
        address: 0x401000,
        summary: 'RIP observed at function entry.',
        evidenceBasis: ['fixture-registers'],
      }],
    });

    render(<DynamicSessionReplayPanel trace={trace} />);

    expect(screen.getByText(/1 dynamic event\(s\), offline replay only/i)).toBeInTheDocument();
    expect(screen.getByText(/RIP observed at function entry/i)).toBeInTheDocument();
    expect(screen.getByText(/Evidence: fixture-registers/i)).toBeInTheDocument();
    expect(screen.getByText(/GYRE remains the sole verdict authority/i)).toBeInTheDocument();
  });
});
