import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { IntelligenceReport } from '../IntelligenceReport';
import type { BinaryVerdictResult } from '../../utils/correlationEngine';

function makeVerdict(overrides: Partial<BinaryVerdictResult> = {}): BinaryVerdictResult {
  return {
    classification: 'clean',
    threatScore: 12,
    confidence: 78,
    signalCount: 2,
    signals: [
      { id: 'sig-1', source: 'strings', finding: 'No suspicious strings', weight: 1, corroboratedBy: [] },
      { id: 'sig-2', source: 'imports', finding: 'Kernel32 only', weight: 1, corroboratedBy: [] },
    ],
    negativeSignals: [],
    amplifiers: [],
    dismissals: [],
    summary: 'Initial report summary',
    explainability: [],
    nextSteps: [],
    behaviors: [],
    reasoningChain: [],
    contradictions: [],
    alternatives: [],
    uncertaintyFlags: [],
    heuristicSignalIds: [],
    ...overrides,
  };
}

describe('IntelligenceReport', () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it('saves the current report as a local snapshot', async () => {
    render(
      <IntelligenceReport
        verdict={makeVerdict()}
        binaryPath="D:\\Project\\HexHawk\\Challenges\\sample.exe"
        binarySize={4096}
        architecture="x86_64"
        fileType="PE32+ EXE"
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: /save snapshot/i }));

    await waitFor(() => {
      const raw = window.localStorage.getItem('hexhawk.reportSnapshots');
      expect(raw).toBeTruthy();
      const snapshots = JSON.parse(raw ?? '[]') as Array<{ binaryName: string; threatScore: number }>;
      expect(snapshots).toHaveLength(1);
      expect(snapshots[0]).toMatchObject({ binaryName: 'sample.exe', threatScore: 12 });
    });
  });

  it('compares the current report against a saved snapshot for the same binary', async () => {
    const { rerender } = render(
      <IntelligenceReport
        verdict={makeVerdict()}
        binaryPath="D:\\Project\\HexHawk\\Challenges\\sample.exe"
        binarySize={4096}
        architecture="x86_64"
        fileType="PE32+ EXE"
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: /save snapshot/i }));

    await waitFor(() => {
      expect(JSON.parse(window.localStorage.getItem('hexhawk.reportSnapshots') ?? '[]')).toHaveLength(1);
    });

    rerender(
      <IntelligenceReport
        verdict={makeVerdict({
          classification: 'rat',
          threatScore: 91,
          confidence: 96,
          signalCount: 5,
          behaviors: ['anti-analysis', 'c2-communication'],
          summary: 'Escalated report summary',
          signals: [
            { id: 'sig-1', source: 'strings', finding: 'Beacon URL found', weight: 5, corroboratedBy: [] },
            { id: 'sig-2', source: 'imports', finding: 'VirtualAlloc present', weight: 5, corroboratedBy: [] },
            { id: 'sig-3', source: 'disassembly', finding: 'PEB walk observed', weight: 8, corroboratedBy: [] },
            { id: 'sig-4', source: 'signatures', finding: 'RAT family overlap', weight: 7, corroboratedBy: [] },
            { id: 'sig-5', source: 'strings', finding: 'https://mal.example.com/c2', weight: 6, corroboratedBy: [] },
          ],
        })}
        binaryPath="D:\\Project\\HexHawk\\Challenges\\sample.exe"
        binarySize={4096}
        architecture="x86_64"
        fileType="PE32+ EXE"
      />,
    );

    expect(await screen.findByText(/snapshot comparison/i)).toBeTruthy();
    expect(screen.getByText('Threat score delta')).toBeTruthy();
    expect(screen.getByText('+79')).toBeTruthy();
    expect(screen.getByText('clean → rat')).toBeTruthy();
    expect(screen.getByText('anti-analysis, c2-communication')).toBeTruthy();
  });
});