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
  let lastBlob: Blob | null = null;

  beforeEach(() => {
    window.localStorage.clear();
    lastBlob = null;
    URL.createObjectURL = ((blob: Blob) => {
      lastBlob = blob;
      return 'blob:hexhawk-test';
    }) as typeof URL.createObjectURL;
    URL.revokeObjectURL = (() => undefined) as typeof URL.revokeObjectURL;
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

  it('exports JSON with GYRE authority envelope markers', async () => {
    render(
      <IntelligenceReport
        verdict={makeVerdict({
          classification: 'suspicious',
          threatScore: 66,
          confidence: 83,
          signalCount: 4,
          summary: 'Authority envelope regression test snapshot',
        })}
        binaryPath="D:\\Project\\HexHawk\\Challenges\\sample.exe"
        binarySize={8192}
        architecture="x86_64"
        fileType="PE32+ EXE"
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: /json/i }));

    await waitFor(() => {
      expect(lastBlob).toBeTruthy();
    });

    const payload = JSON.parse(await lastBlob!.text()) as {
      final_verdict_snapshot: {
        source_engine: string;
        gyre_is_sole_verdict_source: boolean;
        nest_linkage: { gyre_is_sole_verdict_source: boolean };
      };
      authority_doctrine: { gyre_is_sole_verdict_source: boolean };
    };

    expect(payload.final_verdict_snapshot.source_engine).toBe('gyre');
    expect(payload.final_verdict_snapshot.gyre_is_sole_verdict_source).toBe(true);
    expect(payload.final_verdict_snapshot.nest_linkage.gyre_is_sole_verdict_source).toBe(true);
    expect(payload.authority_doctrine.gyre_is_sole_verdict_source).toBe(true);
  });
});