import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { IntelligenceReport, formatMarkdown } from '../IntelligenceReport';
import type { AnalysisSessionProvenance } from '../../utils/analysisProvenance';
import type { BinaryVerdictResult } from '../../utils/correlationEngine';
import { appendEvidenceJournalEntry, type EvidenceJournalAction } from '../../utils/evidenceJournal';

// Presentation contracts use authored DTOs, not real-binary/native IPC proof.
const path = 'C:\\samples\\guide.exe';
const sha = 'a'.repeat(64);
const verdict: BinaryVerdictResult = {
  classification: 'suspicious', threatScore: 66, confidence: 83, signalCount: 0,
  signals: [], negativeSignals: [], amplifiers: [], dismissals: [], summary: 'Bounded finding',
  explainability: [], nextSteps: [], behaviors: [], reasoningChain: [], contradictions: [],
  alternatives: [], uncertaintyFlags: [], heuristicSignalIds: [],
};
function provenance(): AnalysisSessionProvenance {
  const p: AnalysisSessionProvenance = {
    schema: 'hexhawk.analysis.provenance.v1', runtime: 'tauri-native', binaryPath: path,
    binarySha256: sha, dataSource: 'real-backend',
    binaryIdentity: { path, sha256: sha, source: 'real-backend', artifactOrigin: 'tauri.inspect_file_metadata', tauriCommand: 'inspect_file_metadata' },
    commands: [], artifacts: [{ kind: 'metadata', source: 'real-backend', binarySha256: sha, artifactOrigin: 'tauri.inspect_file_metadata', tauriCommand: 'inspect_file_metadata', count: 1 }],
    operationJournal: [], warnings: [],
  };
  receipt(p, 'inspect');
  return p;
}
function receipt(p: AnalysisSessionProvenance, action: EvidenceJournalAction, truncated = false) {
  const artifactSource = action === 'inspect' ? 'tauri.inspect_file_metadata' : action === 'strings' ? 'tauri.find_strings' : 'tauri.disassemble_file_range';
  p.operationJournal = appendEvidenceJournalEntry(p.operationJournal ?? [], {
    action, binaryPath: path, binarySha256: sha, command: action,
    timestamp: '2026-10-17T22:05:00.000Z', artifactSource, analysisLimits: { truncated },
  });
}
beforeEach(() => { window.localStorage.clear(); vi.stubGlobal('__TAURI_INTERNALS__', {}); });
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe('identity-bound investigation guidance', () => {
  it('offers the next missing check without dispatching navigation on render', () => {
    const navigate = vi.fn();
    render(<IntelligenceReport verdict={verdict} binaryPath={path} provenance={provenance()} onNavigate={navigate} />);
    const guide = screen.getByRole('region', { name: 'Evidence checklist' });
    expect(guide).toHaveTextContent(/not.*safety|not.*safe/i);
    expect(within(guide).getByTestId('guide-step-strings')).toHaveTextContent('No recorded completion');
    expect(navigate).not.toHaveBeenCalled();
    fireEvent.click(within(guide).getByRole('button', { name: 'Open Strings' }));
    expect(navigate).toHaveBeenCalledExactlyOnceWith('strings');
  });
  it('does not infer completed scans from artifact counts without receipts', () => {
    const p = provenance();
    p.artifacts.push({ kind: 'strings', source: 'real-backend', binarySha256: sha, artifactOrigin: 'tauri.find_strings', count: 99 });
    render(<IntelligenceReport verdict={verdict} binaryPath={path} provenance={p} />);
    expect(screen.getByTestId('guide-step-strings')).toHaveTextContent('No recorded completion');
  });
  it('recognizes a recorded zero-result scan and suggests disassembly next', () => {
    const p = provenance(); receipt(p, 'strings');
    render(<IntelligenceReport verdict={verdict} binaryPath={path} provenance={p} onNavigate={vi.fn()} />);
    expect(screen.getByTestId('guide-step-strings')).toHaveTextContent('Recorded');
    expect(screen.getByRole('button', { name: 'Open Disassembly' })).toBeEnabled();
  });
  it.each(['path', 'SHA', 'source'])('prioritizes identity repair over other steps on %s mismatch', mismatch => {
    const p = provenance(); receipt(p, 'strings');
    if (mismatch === 'path') p.operationJournal![0].binaryPath = 'C:\\other\\guide.exe';
    if (mismatch === 'SHA') p.operationJournal![0].binarySha256 = 'b'.repeat(64);
    if (mismatch === 'source') p.binaryIdentity.source = 'simulation';
    const navigate = vi.fn();
    render(<IntelligenceReport verdict={verdict} binaryPath={path} provenance={p} onNavigate={navigate} />);
    const guide = screen.getByRole('region', { name: 'Evidence checklist' });
    expect(guide).toHaveTextContent('Repair evidence identity');
    expect(within(guide).queryByText(/^Recorded$/)).not.toBeInTheDocument();
    fireEvent.click(within(guide).getByRole('button', { name: 'Open Inspect' }));
    expect(navigate).toHaveBeenCalledExactlyOnceWith('inspect');
    expect(screen.getByRole('button', { name: '↓ JSON' })).toBeDisabled();
  });
  it('labels bounded results as limited rather than whole-file completion', () => {
    const p = provenance(); receipt(p, 'strings'); receipt(p, 'disassembly', true);
    render(<IntelligenceReport verdict={verdict} binaryPath={path} provenance={p} onNavigate={vi.fn()} />);
    expect(screen.getByTestId('guide-step-disassembly')).toHaveTextContent('Recorded — limited');
    expect(screen.getByRole('button', { name: 'Review Verdict' })).toBeEnabled();
    expect(screen.getByRole('region', { name: 'Evidence checklist' })).toHaveTextContent(/whole.file|whole.program/i);
  });
  it('keeps a browser demonstration explicitly separate from native evidence', () => {
    vi.unstubAllGlobals();
    const p = provenance(); p.runtime = 'browser-simulation';
    render(<IntelligenceReport verdict={verdict} binaryPath={path} provenance={p} />);
    expect(screen.getByRole('region', { name: 'Evidence checklist' })).toHaveTextContent('Demo only');
    expect(screen.queryByText('Recorded — limited')).not.toBeInTheDocument();
  });
  it('provides useful inspection guidance before a verdict exists', () => {
    render(<IntelligenceReport verdict={null} binaryPath={path} onNavigate={vi.fn()} />);
    expect(screen.getByRole('region', { name: 'Evidence checklist' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Open Inspect' })).toBeEnabled();
  });
  it('does not describe an unrecorded CFG as complete in saved Markdown', () => {
    const markdown = formatMarkdown(verdict, { verdict, binaryPath: path, provenance: provenance(), cfgBudget: null });
    expect(markdown).toContain('| CFG status | Not recorded |');
    expect(markdown).not.toContain('CFG complete within budget');
  });
  it('exports the same bounded guidance without changing GYRE fields', async () => {
    let blob: Blob | undefined;
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: vi.fn((value: Blob) => { blob = value; return 'blob:guide'; }), revokeObjectURL: vi.fn() }));
    const p = provenance();
    render(<IntelligenceReport verdict={verdict} binaryPath={path} provenance={p} />);
    fireEvent.click(screen.getByRole('button', { name: '↓ JSON' }));
    const data = JSON.parse(await blob!.text());
    expect(data.investigation_guidance.steps.find((step: { action: string }) => step.action === 'strings').status).toBe('missing');
    expect(data.final_verdict_snapshot).toMatchObject({ source_engine: 'gyre', confidence: 83, threat_score: 66, classification: 'suspicious' });
    expect(formatMarkdown(verdict, { verdict, binaryPath: path, provenance: p })).toContain('Strings: No recorded completion');
  });
});
