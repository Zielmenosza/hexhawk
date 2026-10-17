import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import App from '../../App';

describe('analysis workspace accessibility', () => {
  async function loadBrowserSample() {
    fireEvent.click(screen.getByTestId('nav-load'));
    fireEvent.change(screen.getByTestId('load-path-input'), {
      target: { value: 'D:/Samples/ui-accessibility.exe' },
    });
    fireEvent.click(screen.getByTestId('load-apply-path'));
    fireEvent.click(screen.getByTestId('nav-inspect'));
    await screen.findByTestId('panel-inspect');
  }

  beforeEach(() => {
    localStorage.clear();
    window.history.replaceState(null, '', '/?qa=1&qaTier=enterprise&qaView=disassembly');
  });

  afterEach(() => {
    window.history.replaceState(null, '', '/');
  });

  it('shows the active tool name in the main window and updates it when tools change', async () => {
    render(<App />);

    const scrollOwner = screen.getByTestId('workspace-scroll-owner');
    expect(scrollOwner).toHaveClass('wf-panel--scroll-owner');
    expect(scrollOwner).toHaveAttribute('data-scroll-contract', 'primary');

    const header = screen.getByTestId('active-tool-header');
    expect(header.querySelector('h1')).toHaveTextContent('Read program instructions');
    expect(header).toHaveTextContent('Disassembly');

    fireEvent.click(screen.getByTestId('workspace-tab-cfg'));

    await waitFor(() => {
      expect(header.querySelector('h1')).toHaveTextContent('See possible code paths');
      expect(header).toHaveTextContent('CFG');
    });
  });

  it('builds the Branch map when selected instead of leaving an empty canvas', async () => {
    render(<App />);

    await loadBrowserSample();
    fireEvent.click(screen.getByTestId('nav-disassembly'));
    await screen.findByTestId('workspace-tabbar');
    fireEvent.click(screen.getByTestId('workspace-tab-cfg'));

    await waitFor(() => {
      const cfgPanel = screen.getByTestId('panel-cfg');
      expect(cfgPanel).toBeInTheDocument();
      expect(cfgPanel.closest('.wf-panel')).toBe(screen.getByTestId('workspace-scroll-owner'));
      expect(cfgPanel.closest('.wf-panel')).toHaveClass('wf-panel--scroll-owner');
      expect(cfgPanel.closest('.wf-panel')).not.toHaveClass('wf-panel--cfg');
      expect(screen.queryByTestId('cfg-build-empty-state')).not.toBeInTheDocument();
    });
    expect(screen.getByText(/blocks · .*edges/i)).toBeInTheDocument();
  });

  it('renders Raw bytes as a labelled sixteen-column table', async () => {
    render(<App />);

    await loadBrowserSample();
    fireEvent.click(screen.getByTestId('nav-hex'));

    const header = await screen.findByText('Offset');
    const columnHeader = header.closest('.hex-column-header');
    expect(columnHeader).not.toBeNull();
    expect(columnHeader).toHaveTextContent('00');
    expect(columnHeader).toHaveTextContent('0F');
    expect(columnHeader).toHaveTextContent('ASCII');
    expect(document.querySelectorAll('.hex-row .hex-cell').length).toBeGreaterThanOrEqual(16);
  });

  it('keeps workspace guidance collapsed so the working canvas owns the viewport', () => {
    render(<App />);

    const guide = screen.getByTestId('feature-guide-card');
    expect(guide.tagName).toBe('DETAILS');
    expect(guide).not.toHaveAttribute('open');
    expect(screen.getByTestId('workspace-tabbar')).toBeInTheDocument();
  });

  it('uses one primary scroll owner for every tool instead of clipping workspace roots', async () => {
    render(<App />);

    const owner = screen.getByTestId('workspace-scroll-owner');
    expect(owner).toHaveClass('wf-panel--scroll-owner');
    expect(owner).not.toHaveStyle({ overflow: 'hidden' });

    fireEvent.click(screen.getByTestId('workspace-tab-cfg'));
    await screen.findByTestId('panel-cfg');
    expect(screen.getByTestId('workspace-scroll-owner')).toBe(owner);
  });
});
