import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { IntelligenceReport, formatMarkdown, type AiContributions } from '../IntelligenceReport';
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

  it('packages Markdown export with bounded AETHERFRAME lineage while preserving verdict fields', () => {
    const verdict = makeVerdict({
      classification: 'suspicious',
      threatScore: 66,
      confidence: 83,
      summary: 'Markdown authority boundary regression test snapshot',
    });

    const md = formatMarkdown(verdict, {
      verdict,
      binaryPath: 'D:\\Project\\HexHawk\\Challenges\\sample.exe',
      binarySize: 8192,
      architecture: 'x86_64',
      fileType: 'PE32+ EXE',
    });

    expect(md).toContain('| Classification | **SUSPICIOUS** |');
    expect(md).toContain('| Threat Score | 66/100 |');
    expect(md).toContain('| Confidence | 83% (high) |');
    expect(md).toContain('## AETHERFRAME Report Refinement Lineage');
    expect(md).toContain('| Allowed mutation scope | package only |');
    expect(md).toContain('| Protected classification | suspicious |');
    expect(md).toContain('| Protected threat score | 66 |');
    expect(md).toContain('| Protected confidence | 83% |');
    expect(md).toContain('- classification');
    expect(md).toContain('AETHERFRAME/Forge only packaged this report lineage disclosure; it did not change verdict truth.');
  });

  it('can leave Markdown unchanged when AETHERFRAME is disabled for high-assurance policy', () => {
    const verdict = makeVerdict();
    const md = formatMarkdown(
      verdict,
      { verdict, binaryPath: 'sample.exe' },
      { aetherframe: { enabled: false, reason: 'high-assurance-mode' } },
    );

    expect(md).not.toContain('## AETHERFRAME Report Refinement Lineage');
    expect(md).toContain('| Classification | **CLEAN** |');
    expect(md).toContain('## AI Contributions (advisory only)');
    expect(md).toContain('No AI observations were generated for this analysis.');
  });

  it('Markdown export includes AI contributions when supplied', () => {
    const verdict = makeVerdict();
    const aiContributions: AiContributions = {
      present: true,
      sections: [
        { section: 'function_summary', source: 'aetherframe-static-only', advisory_only: true, gyre_is_sole_verdict_authority: true },
        { section: 'pattern_observations', source: 'aetherframe-static', count: 2, advisory_only: true, gyre_is_sole_verdict_authority: true },
        { section: 'analyst_accepted_suggestions', source: 'agent-gate-approved', count: 1, advisory_only: true, gyre_is_sole_verdict_authority: true },
      ],
      ai_did_not_affect_verdict: true,
      gyre_is_sole_verdict_authority: true,
    };

    const md = formatMarkdown(
      verdict,
      { verdict, binaryPath: 'sample.exe', aiContributions },
      { aiContributions },
    );

    expect(md).toContain('## AI Contributions (advisory only)');
    expect(md).toContain('| Function summary | AETHERFRAME static-only | Interpretation |');
    expect(md).toContain('| Pattern observations (2) | AETHERFRAME static | Pattern match |');
    expect(md).toContain('| Accepted suggestions (1) | Analyst-approved | Notes only |');
    expect(md).not.toContain('classified as');
    expect(md).not.toContain('confirmed malware');
  });

  it('uses the visible report policy toggle to disable AETHERFRAME Markdown packaging', async () => {
    render(
      <IntelligenceReport
        verdict={makeVerdict({ classification: 'suspicious', threatScore: 66, confidence: 83 })}
        binaryPath="D:\\Project\\HexHawk\\Challenges\\sample.exe"
        binarySize={8192}
        architecture="x86_64"
        fileType="PE32+ EXE"
      />,
    );

    const toggle = screen.getByLabelText(/apply aetherframe lineage to markdown and copy exports/i);
    expect(toggle).toBeChecked();
    fireEvent.click(toggle);
    expect(toggle).not.toBeChecked();

    fireEvent.click(screen.getByRole('button', { name: /markdown/i }));

    await waitFor(() => {
      expect(lastBlob).toBeTruthy();
    });

    const md = await lastBlob!.text();
    expect(md).toContain('| Classification | **SUSPICIOUS** |');
    expect(md).not.toContain('## AETHERFRAME Report Refinement Lineage');
    expect(screen.getByText(/High-assurance export mode/i)).toBeTruthy();
  });

  it('keeps AETHERFRAME Markdown lineage enabled by default from the report panel', async () => {
    render(
      <IntelligenceReport
        verdict={makeVerdict({ classification: 'suspicious', threatScore: 66, confidence: 83 })}
        binaryPath="D:\\Project\\HexHawk\\Challenges\\sample.exe"
        binarySize={8192}
        architecture="x86_64"
        fileType="PE32+ EXE"
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: /markdown/i }));

    await waitFor(() => {
      expect(lastBlob).toBeTruthy();
    });

    const md = await lastBlob!.text();
    expect(md).toContain('## AETHERFRAME Report Refinement Lineage');
    expect(md).toContain('| Policy reason | report-panel-analyst-enabled |');
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
      aetherframe_report_packaging: {
        enabled: boolean;
        adapter: string;
        pass_id: string;
        mutation_scope: string;
        policy_reason: string;
        protected_verdict_fields: {
          classification: string;
          threat_score: number;
          confidence: number;
          source_engine: string;
          gyre_is_sole_verdict_source: boolean;
        };
        blocked_mutations: string[];
        proof_limits: string[];
      };
    };

    expect(payload.final_verdict_snapshot.source_engine).toBe('gyre');
    expect(payload.final_verdict_snapshot.gyre_is_sole_verdict_source).toBe(true);
    expect(payload.final_verdict_snapshot.nest_linkage.gyre_is_sole_verdict_source).toBe(true);
    expect(payload.authority_doctrine.gyre_is_sole_verdict_source).toBe(true);
    expect(payload.aetherframe_report_packaging.enabled).toBe(true);
    expect(payload.aetherframe_report_packaging.adapter).toBe('hexhawk.report.markdown');
    expect(payload.aetherframe_report_packaging.pass_id).toBe('hexhawk-report-authority-lineage-package');
    expect(payload.aetherframe_report_packaging.mutation_scope).toBe('package');
    expect(payload.aetherframe_report_packaging.policy_reason).toBe('report-panel-analyst-enabled');
    expect(payload.aetherframe_report_packaging.protected_verdict_fields).toMatchObject({
      classification: 'suspicious',
      threat_score: 66,
      confidence: 83,
      source_engine: 'gyre',
      gyre_is_sole_verdict_source: true,
    });
    expect(payload.aetherframe_report_packaging.blocked_mutations).toEqual(expect.arrayContaining([
      'classification',
      'threatScore',
      'confidence',
      'source_engine',
      'gyre_is_sole_verdict_source',
      'nestEvidenceSelection',
    ]));
    expect(payload.aetherframe_report_packaging.proof_limits).toEqual(expect.arrayContaining([
      'This pass packages lineage and authority-boundary disclosure only.',
    ]));
    expect((payload as any).ai_contributions).toMatchObject({
      present: false,
      ai_did_not_affect_verdict: true,
      gyre_is_sole_verdict_authority: true,
    });
  });

  it('records disabled AETHERFRAME report packaging metadata in JSON export without changing GYRE authority', async () => {
    render(
      <IntelligenceReport
        verdict={makeVerdict({ classification: 'suspicious', threatScore: 66, confidence: 83 })}
        binaryPath="D:\\Project\\HexHawk\\Challenges\\sample.exe"
        binarySize={8192}
        architecture="x86_64"
        fileType="PE32+ EXE"
      />,
    );

    fireEvent.click(screen.getByLabelText(/apply aetherframe lineage to markdown and copy exports/i));
    fireEvent.click(screen.getByRole('button', { name: /json/i }));

    await waitFor(() => {
      expect(lastBlob).toBeTruthy();
    });

    const payload = JSON.parse(await lastBlob!.text()) as {
      final_verdict_snapshot: { source_engine: string; gyre_is_sole_verdict_source: boolean };
      aetherframe_report_packaging: {
        enabled: boolean;
        pass_id: string;
        mutation_scope: string;
        policy_reason: string;
        protected_verdict_fields: { classification: string; source_engine: string; gyre_is_sole_verdict_source: boolean };
      };
    };

    expect(payload.final_verdict_snapshot.source_engine).toBe('gyre');
    expect(payload.final_verdict_snapshot.gyre_is_sole_verdict_source).toBe(true);
    expect(payload.aetherframe_report_packaging.enabled).toBe(false);
    expect(payload.aetherframe_report_packaging.pass_id).toBe('aetherframe-disabled');
    expect(payload.aetherframe_report_packaging.mutation_scope).toBe('none');
    expect(payload.aetherframe_report_packaging.policy_reason).toBe('high-assurance-report-panel-disabled');
    expect(payload.aetherframe_report_packaging.protected_verdict_fields).toMatchObject({
      classification: 'suspicious',
      source_engine: 'gyre',
      gyre_is_sole_verdict_source: true,
    });
  });

  it('exports JSON with supplied AI contribution provenance and visible panel summary', async () => {
    const aiContributions: AiContributions = {
      present: true,
      sections: [
        { section: 'function_summary', source: 'aetherframe-llm', advisory_only: true, gyre_is_sole_verdict_authority: true },
        { section: 'pattern_observations', source: 'aetherframe-static', count: 3, advisory_only: true, gyre_is_sole_verdict_authority: true },
      ],
      ai_did_not_affect_verdict: true,
      gyre_is_sole_verdict_authority: true,
    };

    render(
      <IntelligenceReport
        verdict={makeVerdict()}
        binaryPath="sample.exe"
        aiContributions={aiContributions}
      />,
    );

    expect(screen.getByText('How AI contributed')).toBeTruthy();
    expect(screen.getByText(/This report includes labelled AI interpretation sections/i)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: /json/i }));

    await waitFor(() => {
      expect(lastBlob).toBeTruthy();
    });

    const payload = JSON.parse(await lastBlob!.text()) as { ai_contributions: AiContributions };
    expect(payload.ai_contributions.present).toBe(true);
    expect(payload.ai_contributions.ai_did_not_affect_verdict).toBe(true);
    expect(payload.ai_contributions.sections).toEqual(expect.arrayContaining([
      expect.objectContaining({ section: 'function_summary', source: 'aetherframe-llm', advisory_only: true }),
      expect.objectContaining({ section: 'pattern_observations', source: 'aetherframe-static', count: 3, advisory_only: true }),
    ]));
    expect(JSON.stringify(payload.ai_contributions)).not.toContain('classified as');
    expect(JSON.stringify(payload.ai_contributions)).not.toContain('confirmed malware');
  });

});