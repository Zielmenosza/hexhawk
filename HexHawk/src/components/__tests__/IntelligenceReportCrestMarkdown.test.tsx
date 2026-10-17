import { describe, expect, it } from 'vitest';
import { formatMarkdown } from '../IntelligenceReport';
import type { BinaryVerdictResult } from '../../utils/correlationEngine';
import { appendEvidenceJournalEntry } from '../../utils/evidenceJournal';
import type { AnalysisSessionProvenance } from '../../utils/analysisProvenance';
import type { LegacyRecordMetadata } from '../../utils/legacyRecordMetadata';

function verdict(): BinaryVerdictResult {
  return {
    classification: 'clean', threatScore: 12, confidence: 78, signalCount: 1,
    signals: [{ id: 'sig-1', source: 'strings', finding: 'No suspicious strings', weight: 1, corroboratedBy: [] }],
    negativeSignals: [], amplifiers: [], dismissals: [], summary: 'Safe fixture markdown test', explainability: [], nextSteps: [], behaviors: [], reasoningChain: [], contradictions: [], alternatives: [], uncertaintyFlags: [], heuristicSignalIds: [],
  };
}

const provenance: AnalysisSessionProvenance = {
  schema: 'hexhawk.analysis.provenance.v1', runtime: 'tauri-native', binaryPath: 'HexHawk/package.json', binarySha256: '676807a587aaed5e3c070e7595f5fb1480790b8312c53e202bf6830dd7789251', dataSource: 'real-backend',
  binaryIdentity: { path: 'HexHawk/package.json', sha256: '676807a587aaed5e3c070e7595f5fb1480790b8312c53e202bf6830dd7789251', source: 'real-backend', artifactOrigin: 'tauri.inspect_file_metadata', tauriCommand: 'inspect_file_metadata', cliCommand: 'nest_cli inspect "HexHawk/package.json"' },
  commands: ['nest_cli inspect "HexHawk/package.json"'],
  artifacts: [{ kind: 'metadata', source: 'real-backend', binarySha256: '676807a587aaed5e3c070e7595f5fb1480790b8312c53e202bf6830dd7789251', artifactOrigin: 'tauri.inspect_file_metadata', tauriCommand: 'inspect_file_metadata', cliCommand: 'nest_cli inspect "HexHawk/package.json"', count: 1 }],
  warnings: [],
};

provenance.operationJournal = appendEvidenceJournalEntry([], {
  action: 'inspect', binaryPath: provenance.binaryPath, binarySha256: provenance.binarySha256,
  command: provenance.binaryIdentity.cliCommand!, timestamp: '2026-10-13T17:17:17.000Z',
  artifactSource: 'tauri.inspect_file_metadata', analysisLimits: {},
});

const legacyRecordMetadata: LegacyRecordMetadata = {
  schema: 'hexhawk.legacy_record_metadata.v1',
  format: 'motorola-srec',
  recordCount: 2,
  dataRecordCount: 1,
  byteCount: 10,
  ranges: [{ start: 0x1000, endInclusive: 0x1009, byteLength: 10 }],
  entryAddress: 0x1000,
  strings: [{ address: 0x1000, value: 'HELLO-SREC' }],
  errors: [],
  warnings: [],
  authorityBoundary: 'Metadata-first legacy record adapter: validates records and maps bytes only. It does not execute content, recover source, decompile, or assign GYRE verdict authority.',
  noExecution: true,
};

describe('CREST Markdown hardening', () => {
  it('cites CREST evidence bundle ID, SHA-256, CFG limits, and replay commands', () => {
    const md = formatMarkdown(verdict(), {
      verdict: verdict(),
      binaryPath: 'HexHawk/package.json',
      binarySize: 2247,
      fileType: 'JSON',
      architecture: 'text',
      provenance,
      cfgBudget: { nodes: 0, edges: 0, nodeBudget: 0, edgeBudget: 0, omittedNodes: 0, omittedEdges: 0, truncated: false },
    });

    expect(md).toContain('## CREST Evidence Bundle');
    expect(md).toContain('crest-676807a587aa-1');
    expect(md).toContain('676807a587aaed5e3c070e7595f5fb1480790b8312c53e202bf6830dd7789251');
    expect(md).toContain('nest_cli inspect "HexHawk/package.json"');
    expect(md).toContain('CFG complete within budget');
    expect(md).toContain('does not prove verdict correctness');
  });

  it('includes legacy record metadata provenance in CREST Markdown without execution or verdict claims', () => {
    const md = formatMarkdown(verdict(), {
      verdict: verdict(),
      binaryPath: 'work/sprint0-fixtures/legacy-records/safe_hello.srec',
      binarySize: 42,
      fileType: 'Motorola S-record firmware record',
      architecture: 'legacy firmware record (addressed bytes)',
      provenance: {
        ...provenance,
        binaryPath: 'work/sprint0-fixtures/legacy-records/safe_hello.srec',
        binaryIdentity: {
          ...provenance.binaryIdentity,
          path: 'work/sprint0-fixtures/legacy-records/safe_hello.srec',
          cliCommand: 'nest_cli inspect "work/sprint0-fixtures/legacy-records/safe_hello.srec"',
        },
        commands: ['nest_cli inspect "work/sprint0-fixtures/legacy-records/safe_hello.srec"'],
        operationJournal: provenance.operationJournal!.map(entry => ({
          ...entry,
          binaryPath: 'work/sprint0-fixtures/legacy-records/safe_hello.srec',
          command: 'nest_cli inspect "work/sprint0-fixtures/legacy-records/safe_hello.srec"',
        })),
        artifacts: provenance.artifacts.map(artifact => ({
          ...artifact,
          cliCommand: 'nest_cli inspect "work/sprint0-fixtures/legacy-records/safe_hello.srec"',
        })),
      },
      cfgBudget: { nodes: 0, edges: 0, nodeBudget: 0, edgeBudget: 0, omittedNodes: 0, omittedEdges: 0, truncated: false },
      legacyRecordMetadata,
    });

    expect(md).toContain('| Legacy record metadata | motorola-srec (10 decoded bytes) |');
    expect(md).toContain('Legacy record metadata:');
    expect(md).toContain('- Format: motorola-srec');
    expect(md).toContain('- No execution: yes — text records only');
    expect(md).toContain('HELLO-SREC');
    expect(md).toContain('does not execute content, recover source, decompile, or assign GYRE verdict authority');
  });
});
