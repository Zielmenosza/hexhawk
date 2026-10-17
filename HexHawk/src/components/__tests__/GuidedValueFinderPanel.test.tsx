import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import GuidedValueFinderPanel from '../GuidedValueFinderPanel';
import { invoke } from '@tauri-apps/api/core';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));

const processList = [{ pid: 77, name: 'owned-test.exe' }, { pid: 88, name: 'another.exe' }];
const firstScan = {
  scanId: 1, pid: 77, processName: 'owned-test.exe', valueType: 'i32', candidateCount: 1,
  scannedBytes: 4096, scannedRegions: 1, complete: true, warnings: [],
  authority: 'runtime_observation_not_gyre_verdict',
  matches: [{ address: '0x0000000000001000', currentValue: 100, previousValue: null }],
};

async function chooseOwnedProcess() {
  fireEvent.click(screen.getByRole('button', { name: 'Choose process' }));
  fireEvent.click(await screen.findByRole('option', { name: 'owned-test.exe PID 77' }));
  await waitFor(() => expect(screen.getByText(/owned-test\.exe/)).toBeInTheDocument());
}

beforeEach(() => {
  vi.resetAllMocks();
});

describe('GuidedValueFinderPanel simple value workflow', () => {
  it('uses three plain-language steps and treats process choice as the one authorization action', async () => {
    vi.mocked(invoke).mockResolvedValueOnce(processList);
    render(<GuidedValueFinderPanel />);

    expect(screen.getByText('1. Choose a process')).toBeInTheDocument();
    expect(screen.getByText('2. Find the value')).toBeInTheDocument();
    expect(screen.getByText('3. Set or freeze')).toBeInTheDocument();
    await chooseOwnedProcess();

    expect(screen.getByText(/owned-test\.exe/)).toHaveTextContent('owned-test.exe · PID 77');
    expect(screen.queryByRole('checkbox', { name: /authorized/i })).not.toBeInTheDocument();
    expect(invoke).toHaveBeenCalledWith('value_process_list');
  });

  it('keeps the process chooser dismissible from the keyboard', async () => {
    vi.mocked(invoke).mockResolvedValueOnce(processList);
    render(<GuidedValueFinderPanel />);
    fireEvent.click(screen.getByRole('button', { name: 'Choose process' }));
    expect(await screen.findByRole('dialog', { name: 'Choose a running process' })).toBeInTheDocument();
    fireEvent.keyDown(window, { key: 'Escape' });
    expect(screen.queryByRole('dialog', { name: 'Choose a running process' })).not.toBeInTheDocument();
  });

  it('finds and automatically selects a single exact candidate', async () => {
    vi.mocked(invoke).mockResolvedValueOnce(processList).mockResolvedValueOnce(firstScan);
    render(<GuidedValueFinderPanel />);
    await chooseOwnedProcess();
    fireEvent.change(screen.getByLabelText('current visible value'), { target: { value: '100' } });
    fireEvent.click(screen.getByRole('button', { name: 'First scan' }));

    expect((await screen.findAllByText('1 candidate')).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('Selected address: 0x0000000000001000')).toBeInTheDocument();
    expect(invoke).toHaveBeenCalledWith('value_scan_start', {
      pid: 77,
      request: expect.objectContaining({ value: 100, authorized: true }),
    });
  });

  it('sets one selected value with one click while preserving backend preview-token custody', async () => {
    vi.mocked(invoke)
      .mockResolvedValueOnce(processList)
      .mockResolvedValueOnce(firstScan)
      .mockResolvedValueOnce({
        confirmationToken: 'preview-token', scanId: 1, pid: 77, processName: 'owned-test.exe',
        address: '0x0000000000001000', originalValue: 100, newValue: 250,
        originalBytesLe: [100, 0, 0, 0], newBytesLe: [250, 0, 0, 0], expiresInSeconds: 60,
      })
      .mockResolvedValueOnce({
        pid: 77, processName: 'owned-test.exe', address: '0x0000000000001000',
        originalValue: 100, currentValue: 250, rollbackToken: 'rollback-token',
      });
    render(<GuidedValueFinderPanel />);
    await chooseOwnedProcess();
    fireEvent.change(screen.getByLabelText('current visible value'), { target: { value: '100' } });
    fireEvent.click(screen.getByRole('button', { name: 'First scan' }));
    await screen.findByText('Selected address: 0x0000000000001000');
    fireEvent.change(screen.getByLabelText('new value'), { target: { value: '250' } });
    fireEvent.click(screen.getByRole('button', { name: 'Set value' }));

    expect(await screen.findByText('Set successfully: 100 → 250')).toBeInTheDocument();
    expect(screen.queryByLabelText('edit confirmation')).not.toBeInTheDocument();
    await waitFor(() => expect(invoke).toHaveBeenCalledWith('value_edit_commit', {
      request: { confirmationToken: 'preview-token' },
    }));
  });

  it('explains temporary or display-copy failures with a direct rescan action', async () => {
    vi.mocked(invoke)
      .mockResolvedValueOnce(processList)
      .mockResolvedValueOnce(firstScan)
      .mockRejectedValueOnce(new Error('Write verification failed; the target did not retain the requested value.'));
    render(<GuidedValueFinderPanel />);
    await chooseOwnedProcess();
    fireEvent.change(screen.getByLabelText('current visible value'), { target: { value: '100' } });
    fireEvent.click(screen.getByRole('button', { name: 'First scan' }));
    await screen.findByText('Selected address: 0x0000000000001000');
    fireEvent.change(screen.getByLabelText('new value'), { target: { value: '250' } });
    fireEvent.click(screen.getByRole('button', { name: 'Set value' }));

    expect(await screen.findByText(/temporary or display copy/i)).toBeInTheDocument();
    expect(screen.getByText(/run Next Scan/i)).toBeInTheDocument();
  });

  it('starts a responsive Freeze with one click and gives an immediate stop control', async () => {
    vi.mocked(invoke)
      .mockResolvedValueOnce(processList)
      .mockResolvedValueOnce(firstScan)
      .mockResolvedValueOnce({
        confirmationToken: 'freeze-preview-token', scanId: 1, pid: 77, processName: 'owned-test.exe',
        address: '0x0000000000001000', originalValue: 100, frozenValue: 250,
        intervalMilliseconds: 50, expiresInSeconds: 60,
      })
      .mockResolvedValueOnce({
        freezeId: 'freeze-id', pid: 77, processName: 'owned-test.exe', address: '0x0000000000001000',
        originalValue: 100, frozenValue: 250, intervalMilliseconds: 50, active: true,
        verifiedWrites: 1, lastObservedValue: 250, stopReason: null, restoredOriginal: false,
      })
      .mockResolvedValueOnce({
        freezeId: 'freeze-id', pid: 77, processName: 'owned-test.exe', address: '0x0000000000001000',
        originalValue: 100, frozenValue: 250, intervalMilliseconds: 50, active: false,
        verifiedWrites: 2, lastObservedValue: 250, stopReason: 'Stopped by user.', restoredOriginal: false,
      });
    render(<GuidedValueFinderPanel />);
    await chooseOwnedProcess();
    fireEvent.change(screen.getByLabelText('current visible value'), { target: { value: '100' } });
    fireEvent.click(screen.getByRole('button', { name: 'First scan' }));
    await screen.findByText('Selected address: 0x0000000000001000');
    fireEvent.change(screen.getByLabelText('new value'), { target: { value: '250' } });
    fireEvent.change(screen.getByLabelText('freeze speed'), { target: { value: '50' } });
    fireEvent.click(screen.getByRole('button', { name: 'Freeze value' }));

    expect(await screen.findByText(/Freeze active/)).toBeInTheDocument();
    expect(invoke).toHaveBeenCalledWith('value_freeze_preview', {
      request: expect.objectContaining({ intervalMilliseconds: 50 }),
    });
    fireEvent.click(screen.getByRole('button', { name: 'Stop Freeze' }));
    await waitFor(() => expect(invoke).toHaveBeenCalledWith('value_freeze_stop', {
      request: { freezeId: 'freeze-id', restoreOriginal: false },
    }));
  });
});
