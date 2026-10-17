import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import PacketIntelligencePanel from '../PacketIntelligencePanel';

const safeHar = JSON.stringify({
  log: {
    entries: [{
      startedDateTime: '2026-08-12T10:00:00.000Z', time: 42,
      request: { method: 'GET', url: 'https://example.test/api?token=secret', headers: [], headersSize: 10, bodySize: 0 },
      response: { status: 200, headers: [], headersSize: 10, bodySize: 20, content: { size: 20, mimeType: 'application/json', text: '{"secret":true}' } },
    }],
  },
});

describe('PacketIntelligencePanel', () => {
  it('imports sanitized HAR metadata and keeps replay/mutation locked', async () => {
    render(<PacketIntelligencePanel />);
    expect(screen.getByText(/Replay\/mutation stays locked/i)).toBeInTheDocument();
    const file = new File([safeHar], 'traffic.har', { type: 'application/json' });
    fireEvent.change(screen.getByTestId('packet-har-input'), { target: { files: [file] } });
    await waitFor(() => expect(screen.getByText('1 requests')).toBeInTheDocument());
    expect(screen.getByText(/token=%5BREDACTED%5D/)).toBeInTheDocument();
    expect(screen.queryByText(/"secret":true/)).not.toBeInTheDocument();
  });
});
