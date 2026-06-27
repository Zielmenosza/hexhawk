import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import FirstRunWelcomePanel from '../FirstRunWelcomePanel';

describe('FirstRunWelcomePanel', () => {
  it('renders the local-first welcome copy and browse action', () => {
    const onBrowse = vi.fn();
    render(<FirstRunWelcomePanel onBrowse={onBrowse} onDropFile={vi.fn()} />);

    expect(screen.getByTestId('first-run-panel')).toHaveTextContent('HexHawk Reverse-Engineering Workbench');
    expect(screen.getByText('Your files never leave this machine.')).toBeInTheDocument();
    expect(screen.getByText(/It does not execute them/)).toBeInTheDocument();

    fireEvent.click(screen.getByTestId('first-run-browse'));
    expect(onBrowse).toHaveBeenCalledOnce();
  });

  it('accepts executable drag-and-drop paths', () => {
    const onDropFile = vi.fn();
    render(<FirstRunWelcomePanel onBrowse={vi.fn()} onDropFile={onDropFile} />);

    fireEvent.drop(screen.getByTestId('first-run-panel'), {
      dataTransfer: {
        files: [{ name: 'sample.exe', path: 'C:/tmp/sample.exe' }],
        getData: () => '',
      },
    });

    expect(onDropFile).toHaveBeenCalledWith('C:/tmp/sample.exe');
  });

  it('rejects unsupported dropped file types', () => {
    const onDropFile = vi.fn();
    render(<FirstRunWelcomePanel onBrowse={vi.fn()} onDropFile={onDropFile} />);

    fireEvent.drop(screen.getByTestId('first-run-panel'), {
      dataTransfer: {
        files: [{ name: 'notes.txt', path: 'C:/tmp/notes.txt' }],
        getData: () => '',
      },
    });

    expect(onDropFile).not.toHaveBeenCalled();
    expect(screen.getByRole('alert')).toHaveTextContent('.exe, .dll, .sys, or .bin');
  });
});
