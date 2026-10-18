import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { IntelligenceReport, createReportSnapshot, REPORT_SNAPSHOTS_STORAGE_KEY } from '../IntelligenceReport';
import type { AnalysisSessionProvenance } from '../../utils/analysisProvenance';
import type { BinaryVerdictResult } from '../../utils/correlationEngine';
import { appendEvidenceJournalEntry } from '../../utils/evidenceJournal';

const path = 'C:\\samples\\sample.exe';
const sha = 'a'.repeat(64);
const verdict: BinaryVerdictResult = {
  classification: 'suspicious', threatScore: 66, confidence: 83, signalCount: 1,
  signals: [{ id: 'url', source: 'strings', finding: 'https://sample.example.com/c2', weight: 5, corroboratedBy: [] }],
  negativeSignals: [], amplifiers: [], dismissals: [], summary: 'Bounded static finding',
  explainability: [], nextSteps: [], behaviors: [], reasoningChain: [], contradictions: [],
  alternatives: [], uncertaintyFlags: [], heuristicSignalIds: [],
};
function provenance(metadataLoaded = true): AnalysisSessionProvenance {
  const cliCommand = `nest_cli inspect ${JSON.stringify(path)}`;
  return {
    schema: 'hexhawk.analysis.provenance.v1', runtime: 'tauri-native', binaryPath: path, binarySha256: sha, dataSource: 'real-backend',
    binaryIdentity: { path, sha256: sha, source: 'real-backend', artifactOrigin: 'tauri.inspect_file_metadata', tauriCommand: 'inspect_file_metadata', cliCommand },
    commands: metadataLoaded ? [cliCommand] : [],
    operationJournal: metadataLoaded ? appendEvidenceJournalEntry([], {
      action: 'inspect', binaryPath: path, binarySha256: sha, command: cliCommand,
      timestamp: '2026-10-13T17:17:17.000Z', artifactSource: 'tauri.inspect_file_metadata', analysisLimits: {},
    }) : [],
    artifacts: metadataLoaded ? [{ kind: 'metadata', source: 'real-backend', binarySha256: sha, artifactOrigin: 'tauri.inspect_file_metadata', tauriCommand: 'inspect_file_metadata', cliCommand, count: 1 }] : [],
    warnings: [],
  };
}
const download = vi.fn((_blob: Blob) => 'blob:report-boundary');
const copy = vi.fn(async () => undefined);
function assertBlocked() {
  for (const name of ['↓ JSON', '↓ Markdown', '↓ IOCs', '⎘ Copy', '☆ Save Snapshot']) {
    const button = screen.getByRole('button', { name });
    expect(button).toBeDisabled();
    fireEvent.click(button);
  }
  expect(screen.getByRole('alert')).toHaveTextContent(/export.*blocked|blocked.*export/i);
  expect(download).not.toHaveBeenCalled();
  expect(copy).not.toHaveBeenCalled();
}
beforeEach(() => {
  window.localStorage.clear();
  vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: download, revokeObjectURL: vi.fn() }));
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: copy } });
  vi.stubGlobal('__TAURI_INTERNALS__', {});
  download.mockClear(); copy.mockClear();
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe('report file identity boundary', () => {
  it('blocks uninspected native sessions even when restored labels and SHA exist', () => {
    render(<IntelligenceReport verdict={verdict} binaryPath={path} provenance={provenance(false)} />);
    assertBlocked();
    expect(screen.getByRole('alert')).toHaveTextContent(/inspect/i);
  });
  it('blocks legacy labeled metadata without an Inspect File receipt', () => {
    const p = provenance(); p.operationJournal = [];
    render(<IntelligenceReport verdict={verdict} binaryPath={path} provenance={p} />);
    assertBlocked();
    expect(screen.getByRole('alert')).toHaveTextContent(/Inspect File receipt/i);
  });
  it('blocks native runtime without provenance', () => {
    render(<IntelligenceReport verdict={verdict} binaryPath={path} />);
    assertBlocked();
  });
  it('blocks native exports without a SHA', () => {
    const p = provenance(); p.binarySha256 = null; p.binaryIdentity.sha256 = null;
    p.artifacts[0].binarySha256 = null;
    render(<IntelligenceReport verdict={verdict} binaryPath={path} provenance={p} />);
    assertBlocked();
    expect(screen.getByRole('alert')).toHaveTextContent(/identity|SHA/i);
  });
  it.each(['report path', 'identity path', 'artifact SHA', 'session SHA', 'source', 'receipt path', 'receipt SHA', 'identity origin'])(
    'blocks inconsistent %s', mismatch => {
      const p = provenance();
      if (mismatch === 'identity path') p.binaryIdentity.path = 'C:\\elsewhere\\sample.exe';
      if (mismatch === 'artifact SHA') p.artifacts[0].binarySha256 = 'b'.repeat(64);
      if (mismatch === 'session SHA') p.binarySha256 = 'b'.repeat(64);
      if (mismatch === 'source') p.binaryIdentity.source = 'simulation';
      if (mismatch === 'identity origin') p.binaryIdentity.artifactOrigin = 'tauri.find_strings';
      if (mismatch === 'receipt path') p.operationJournal![0].binaryPath = 'C:\\other\\sample.exe';
      if (mismatch === 'receipt SHA') p.operationJournal![0].binarySha256 = 'b'.repeat(64);
      render(<IntelligenceReport verdict={verdict} binaryPath={mismatch === 'report path' ? 'C:\\elsewhere\\sample.exe' : path} provenance={p} />);
      assertBlocked();
    });
  it('stores SHA and does not compare basename aliases, changed content, or legacy path-only snapshots', () => {
    const current = createReportSnapshot(verdict, { verdict, binaryPath: path, provenance: provenance() });
    expect(current).toHaveProperty('sha256', sha);
    const baselines = [
      { ...current, id: 'alias', binaryPath: 'C:\\elsewhere\\sample.exe', sha256: 'b'.repeat(64) },
      { ...current, id: 'changed', sha256: 'b'.repeat(64) },
      { ...current, id: 'legacy', sha256: undefined },
    ];
    window.localStorage.setItem(REPORT_SNAPSHOTS_STORAGE_KEY, JSON.stringify(baselines));
    render(<IntelligenceReport verdict={verdict} binaryPath={path} provenance={provenance()} />);
    expect(screen.queryByText('Snapshot Comparison')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '↓ Diff JSON' })).not.toBeInTheDocument();
  });
  it('disables comparison exports when current provenance becomes inconsistent', () => {
    const baseline = { ...createReportSnapshot(verdict, { verdict, binaryPath: path, provenance: provenance() }), sha256: sha };
    window.localStorage.setItem(REPORT_SNAPSHOTS_STORAGE_KEY, JSON.stringify([baseline]));
    const p = provenance(); p.artifacts[0].binarySha256 = 'b'.repeat(64);
    render(<IntelligenceReport verdict={verdict} binaryPath={path} provenance={p} />);
    for (const name of ['↓ Diff MD', '↓ Diff JSON']) {
      const button = screen.getByRole('button', { name });
      expect(button).toBeDisabled(); fireEvent.click(button);
    }
    expect(download).not.toHaveBeenCalled();
  });
  it('allows honestly truncated CFG with declared limits and preserves GYRE fields', async () => {
    let blob: Blob | undefined;
    download.mockImplementationOnce(value => { blob = value as unknown as Blob; return 'blob:report-boundary'; });
    render(<IntelligenceReport verdict={verdict} binaryPath={path} provenance={provenance()}
      cfgBudget={{ nodes: 2, edges: 1, nodeBudget: 2, edgeBudget: 2, omittedNodes: 8, omittedEdges: 9, truncated: true }} />);
    const button = screen.getByRole('button', { name: '↓ JSON' });
    expect(button).toBeEnabled(); fireEvent.click(button);
    expect(blob).toBeDefined();
    const payload = JSON.parse(await blob!.text());
    expect(payload.final_verdict_snapshot).toMatchObject({ classification: 'suspicious', confidence: 83, threat_score: 66, source_engine: 'gyre' });
    expect(payload.crest_evidence_bundle.native_evidence_contract.canClaimFileBackedEvidence).toBe(true);
    expect(payload.crest_evidence_bundle.cfg_budget.truncated).toBe(true);
    expect(payload.crest_evidence_bundle.proof_limits.join(' ')).toMatch(/not.*complete|not.*full CFG/i);
  });
  it('blocks truncated CFG when the CREST validator requires missing declared limits', () => {
    render(<IntelligenceReport verdict={verdict} binaryPath={path} provenance={provenance()} cfgBudget={{ nodes: 2, edges: 1, truncated: true }} />);
    assertBlocked();
    expect(screen.getByRole('alert')).toHaveTextContent(/CFG truncation/i);
  });
  it('blocks a missing report path even with inspected provenance', () => {
    render(<IntelligenceReport verdict={verdict} provenance={provenance()} />);
    assertBlocked();
  });
  it.each(['↓ JSON', '↓ Markdown', '↓ IOCs', '⎘ Copy', '☆ Save Snapshot'])(
    'rechecks the shared boundary inside the enabled %s handler', name => {
      const p = provenance();
      render(<IntelligenceReport verdict={verdict} binaryPath={path} provenance={p} />);
      const button = screen.getByRole('button', { name });
      expect(button).toBeEnabled();
      p.artifacts[0].binarySha256 = 'b'.repeat(64);
      fireEvent.click(button);
      expect(download).not.toHaveBeenCalled();
      expect(copy).not.toHaveBeenCalled();
      expect(JSON.parse(window.localStorage.getItem(REPORT_SNAPSHOTS_STORAGE_KEY) ?? '[]')).toHaveLength(0);
    });
  it.each(['↓ Diff MD', '↓ Diff JSON'])('rechecks the shared boundary in the enabled %s handler', name => {
    const p = provenance();
    const baseline = createReportSnapshot(verdict, { verdict, binaryPath: path, provenance: p });
    window.localStorage.setItem(REPORT_SNAPSHOTS_STORAGE_KEY, JSON.stringify([baseline]));
    render(<IntelligenceReport verdict={verdict} binaryPath={path} provenance={p} />);
    const button = screen.getByRole('button', { name });
    expect(button).toBeEnabled();
    p.artifacts[0].binarySha256 = 'b'.repeat(64);
    fireEvent.click(button);
    expect(download).not.toHaveBeenCalled();
  });
  it('compares and exports only a matching SHA baseline even at a different path', async () => {
    let blob: Blob | undefined;
    download.mockImplementationOnce(value => { blob = value; return 'blob:report-boundary'; });
    const baseline = { ...createReportSnapshot(verdict, { verdict, binaryPath: path, provenance: provenance() }), binaryPath: 'C:\\other\\sample.exe' };
    window.localStorage.setItem(REPORT_SNAPSHOTS_STORAGE_KEY, JSON.stringify([baseline]));
    render(<IntelligenceReport verdict={verdict} binaryPath={path} provenance={provenance()} />);
    expect(screen.getByText('Snapshot Comparison')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '↓ Diff JSON' }));
    const payload = JSON.parse(await blob!.text());
    expect(payload.current.sha256).toBe(sha);
    expect(payload.baseline.sha256).toBe(sha);
    expect(payload.comparison.confidenceDelta).toBe(0);
  });
  it('keeps hook order stable across empty, populated, and empty reports', () => {
    const { rerender } = render(<IntelligenceReport verdict={null} />);
    expect(() => rerender(<IntelligenceReport verdict={verdict} binaryPath={path} provenance={provenance()} />)).not.toThrow();
    expect(() => rerender(<IntelligenceReport verdict={null} />)).not.toThrow();
  });
});
