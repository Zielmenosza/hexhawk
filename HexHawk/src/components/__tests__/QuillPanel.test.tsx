import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import QuillPanel from '../QuillPanel';

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

vi.mock('@tauri-apps/plugin-dialog', () => ({
  open: vi.fn(),
}));

describe('QuillPanel Phase 1 plugin safety copy', () => {
  it('renders browser simulated advisory manifest plugin without native extension guidance', async () => {
    render(<QuillPanel />);

    await waitFor(() => expect(screen.getByText('DemoRules')).toBeInTheDocument());
    expect(screen.getByText('demo_rules.hexhawk-plugin.json')).toBeInTheDocument();
    expect(screen.getByText(/Simulated advisory-only manifest plugin/i)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('demo_rules.dll');
  });

  it('uses browser simulation for install without invoking native install', async () => {
    const changed = vi.fn();
    render(<QuillPanel onPluginListChanged={changed} />);

    fireEvent.click(await screen.findByRole('button', { name: /Install Plugin/i }));

    await waitFor(() => expect(screen.getByText(/Browser mode: simulated plugin installation complete/i)).toBeInTheDocument());
    expect(changed).toHaveBeenCalled();
  });
});
