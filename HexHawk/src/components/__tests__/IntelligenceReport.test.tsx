import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { IntelligenceReport, formatMarkdown, type AiContributions } from '../IntelligenceReport';
import type { BinaryVerdictResult } from '../../utils/correlationEngine';
import { appendEvidenceJournalEntry } from '../../utils/evidenceJournal';
import type { AnalysisSessionProvenance } from '../../utils/analysisProvenance';
import type { ReferenceGraph } from '../../utils/referenceGraph';

const nativeProvenance: AnalysisSessionProvenance = {
  schema: 'hexhawk.analysis.provenance.v1',
  runtime: 'tauri-native',
  binaryPath: 'D:\\Project\\HexHawk\\Challenges\\sample.exe',
  binarySha256: '7b4a27599f48bc7edcbe52e7cad688c92b1a0241b0e5e95b94355a2d50607b28',
  dataSource: 'real-backend',
  binaryIdentity: {
    path: 'D:\\Project\\HexHawk\\Challenges\\sample.exe',
    sha256: '7b4a27599f48bc7edcbe52e7cad688c92b1a0241b0e5e95b94355a2d50607b28',
    source: 'real-backend',
    artifactOrigin: 'tauri.inspect_file_metadata',
    tauriCommand: 'inspect_file_metadata',
    cliCommand: 'nest_cli inspect "D:\\\\Project\\\\HexHawk\\\\Challenges\\\\sample.exe"',
  },
  commands: ['nest_cli inspect "D:\\\\Project\\\\HexHawk\\\\Challenges\\\\sample.exe"'],
  artifacts: [
    {
      kind: 'metadata',
      source: 'real-backend',
      command: 'nest_cli inspect "D:\\\\Project\\\\HexHawk\\\\Challenges\\\\sample.exe"',
      count: 1,
      binarySha256: '7b4a27599f48bc7edcbe52e7cad688c92b1a0241b0e5e95b94355a2d50607b28',
      artifactOrigin: 'tauri.inspect_file_metadata',
      tauriCommand: 'inspect_file_metadata',
      cliCommand: 'nest_cli inspect "D:\\\\Project\\\\HexHawk\\\\Challenges\\\\sample.exe"',
    },
  ],
  warnings: [],
};

nativeProvenance.operationJournal = appendEvidenceJournalEntry([], {
  action: 'inspect', binaryPath: nativeProvenance.binaryPath, binarySha256: nativeProvenance.binarySha256,
  command: nativeProvenance.binaryIdentity.cliCommand!, timestamp: '2026-10-13T17:17:17.000Z',
  artifactSource: 'tauri.inspect_file_metadata', analysisLimits: {},
});

const referenceGraph: ReferenceGraph = {
  schema: 'hexhawk.reference_graph.v1',
  advisory_only: true,
  authority: 'reference_graph_not_gyre_verdict',
  generated_at: '2026-07-25T00:00:00.000Z',
  summary: { functions: 2, imports: 1, strings: 1, basic_blocks: 1, data_references: 1, constants: 1, selected_addresses: 1, nodes: 7, edges: 6 },
  limits: { nodeBudget: 256, edgeBudget: 512, omittedNodes: 0, omittedEdges: 0, truncated: false },
  nodes: [],
  edges: [],
  proof_limits: ['Reference graph is advisory static-analysis evidence; it does not prove verdict correctness.'],
};

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
        binaryPath={nativeProvenance.binaryPath}
        provenance={nativeProvenance}
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
        binaryPath={nativeProvenance.binaryPath}
        provenance={nativeProvenance}
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

  it('Markdown export includes an advisory reference graph section with proof limits', () => {
    const md = formatMarkdown(
      makeVerdict(),
      { verdict: makeVerdict(), binaryPath: 'sample.exe', referenceGraph },
      { referenceGraph },
    );

    expect(md).toContain('## Reference Graph');
    expect(md).toContain('Advisory static-analysis graph');
    expect(md).toContain('| Functions | 2 |');
    expect(md).toContain('| Imports | 1 |');
    expect(md).toContain('| Strings | 1 |');
    expect(md).toContain('Reference graph is advisory static-analysis evidence');
    expect(md).not.toContain('reference graph changed classification');
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

  it('renders and exports the same typed native evidence provenance shown by the GUI', async () => {
    render(
      <IntelligenceReport
        verdict={makeVerdict()}
        binaryPath={nativeProvenance.binaryPath}
        binarySize={8192}
        architecture="x86_64"
        fileType="PE32+ EXE"
        provenance={nativeProvenance}
        cfgBudget={{ nodes: 2000, edges: 4000, nodeBudget: 2000, edgeBudget: 4000, omittedNodes: 12, omittedEdges: 20, truncated: true }}
      />,
    );

    expect(screen.getByText(/Native evidence provenance/i)).toBeTruthy();
    expect(screen.getByText(/Evidence Resources and Capability Matrix/i)).toBeTruthy();
    expect(screen.getByText(/fail-closed-no-substitution/i)).toBeTruthy();
    expect(screen.getByText(/File identity \/ inspect/i)).toBeTruthy();
    expect(screen.getByText(/CFG budget proof/i)).toBeTruthy();
    expect(screen.getAllByText(/truncated/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/tauri\.inspect_file_metadata/i)).toBeTruthy();
    expect(screen.getAllByText(/7b4a27599f48bc7edcbe52e7cad688c92b1a0241b0e5e95b94355a2d50607b28/i).length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole('button', { name: /json/i }));

    await waitFor(() => {
      expect(lastBlob).toBeTruthy();
    });

    const payload = JSON.parse(await lastBlob!.text()) as {
      binary: { sha256?: string; artifact_origin?: string; tauri_command?: string; cli_command?: string };
      evidence_provenance: AnalysisSessionProvenance;
      evidence_replay_manifest: { schema: string; entries: Array<{ binaryPath: string; binarySha256: string; command: string; artifactSource: string; analysisLimits: Record<string, unknown> }> };
      crest_evidence_bundle: {
        schema: string;
        file_identity: { sha256: string };
        native_evidence_contract: { kind: string; canClaimFileBackedEvidence: boolean };
        selected_analysis_provider: { provider: string; silentFallbackAllowed: boolean; failurePolicy: string };
        evidence_records: Array<{ evidenceId: string; operation: string; evidenceMode: string }>;
        capability_matrix: { schema: string; entries: Array<{ capability: string; availability: string }> };
        replay_manifest: { schema: string; entries: Array<{ binarySha256: string }> };
        evidence_provenance: AnalysisSessionProvenance;
        cfg_budget: { truncated: boolean; nodeBudget: number; edgeBudget: number };
        reproducibility: { same_sha256_across_bundle: boolean; replay_manifest_matches_file_identity: boolean; cfg_limits_declared_when_truncated: boolean };
      };
      cfg_budget: { nodes: number; edges: number; nodeBudget: number; edgeBudget: number; omittedNodes: number; omittedEdges: number; truncated: boolean };
    };

    expect(payload.binary.sha256).toBe(nativeProvenance.binaryIdentity.sha256);
    expect(payload.binary.artifact_origin).toBe('tauri.inspect_file_metadata');
    expect(payload.binary.tauri_command).toBe('inspect_file_metadata');
    expect(payload.binary.cli_command).toBe(nativeProvenance.binaryIdentity.cliCommand);
    expect(payload.evidence_provenance.binaryIdentity.sha256).toBe(payload.binary.sha256);
    expect(payload.evidence_provenance.artifacts[0]).toMatchObject({
      kind: 'metadata',
      source: 'real-backend',
      binarySha256: payload.binary.sha256,
      artifactOrigin: 'tauri.inspect_file_metadata',
      tauriCommand: 'inspect_file_metadata',
    });
    expect(payload.evidence_replay_manifest.schema).toBe('hexhawk.evidence_replay_manifest.v1');
    expect(payload.evidence_replay_manifest.entries[0]).toMatchObject({
      binaryPath: nativeProvenance.binaryPath,
      binarySha256: payload.binary.sha256,
      command: nativeProvenance.binaryIdentity.cliCommand,
      artifactSource: 'tauri.inspect_file_metadata',
    });
    expect(payload.cfg_budget).toMatchObject({
      nodes: 2000,
      edges: 4000,
      nodeBudget: 2000,
      edgeBudget: 4000,
      omittedNodes: 12,
      omittedEdges: 20,
      truncated: true,
    });
    expect(payload.crest_evidence_bundle).toMatchObject({
      schema: 'hexhawk.crest_evidence_bundle.v1',
      file_identity: { sha256: payload.binary.sha256 },
      native_evidence_contract: { kind: 'native', canClaimFileBackedEvidence: true },
      selected_analysis_provider: { provider: 'hexhawk-native', silentFallbackAllowed: false, failurePolicy: 'fail-closed-no-substitution' },
      cfg_budget: { truncated: true, nodeBudget: 2000, edgeBudget: 4000 },
      reproducibility: {
        same_sha256_across_bundle: true,
        replay_manifest_matches_file_identity: true,
        cfg_limits_declared_when_truncated: true,
      },
    });
    expect(payload.crest_evidence_bundle.evidence_records[0]).toMatchObject({
      operation: 'inspect_file_metadata',
      evidenceMode: 'native',
    });
    expect(payload.crest_evidence_bundle.capability_matrix).toMatchObject({
      schema: 'hexhawk.capability_matrix.v1',
    });
    expect(payload.crest_evidence_bundle.capability_matrix.entries.find((entry) => entry.capability === 'File identity / inspect')).toMatchObject({ availability: 'available' });
    expect(payload.crest_evidence_bundle.replay_manifest.entries[0].binarySha256).toBe(payload.binary.sha256);
    expect(JSON.stringify(payload.evidence_provenance)).not.toContain('classification');
    expect(JSON.stringify(payload.evidence_replay_manifest)).not.toContain('classification');
    expect(JSON.stringify(payload.crest_evidence_bundle.evidence_provenance)).not.toContain('classification');
    expect(JSON.stringify(payload.crest_evidence_bundle.replay_manifest)).not.toContain('classification');
    expect(JSON.stringify(payload.evidence_provenance)).not.toContain('threatScore');
    expect(JSON.stringify(payload.evidence_replay_manifest)).not.toContain('threatScore');
    expect(JSON.stringify(payload.crest_evidence_bundle.evidence_provenance)).not.toContain('threatScore');
    expect(JSON.stringify(payload.crest_evidence_bundle.replay_manifest)).not.toContain('threatScore');
  });

});