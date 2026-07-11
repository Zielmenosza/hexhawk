import { describe, expect, it } from 'vitest';
import { buildAetherframeRunLedger, parseGitStatusShort } from '../aetherframeRunLedger';

describe('aetherframe run-ledger commit readiness', () => {
  it('parses synthetic git-status text with safe files only as commit-ready', () => {
    const ledger = buildAetherframeRunLedger({
      repo: 'D:/Project/HexHawk',
      currentBranch: 'main',
      gitStatusShort: [
        ' M HexHawk/src/utils/aetherframeRunLedger.ts',
        '?? HexHawk/src/utils/__tests__/aetherframeRunLedger.test.ts',
      ].join('\n'),
      agentReport: [
        'Implemented a read-only AetherFrame run-ledger prototype.',
        'Validation evidence: yarn workspace hexhawk-ui test -- aetherframeRunLedger',
        'Result: 5 passed; 0 failed.',
      ].join('\n'),
      allowedPaths: ['HexHawk/src/utils/'],
    });

    expect(ledger.changed_files).toEqual([
      'HexHawk/src/utils/aetherframeRunLedger.ts',
      'HexHawk/src/utils/__tests__/aetherframeRunLedger.test.ts',
    ]);
    expect(ledger.staged_files).toEqual([]);
    expect(ledger.forbidden_path_hits).toEqual([]);
    expect(ledger.claimed_tests).toEqual(expect.arrayContaining([
      'Validation evidence: yarn workspace hexhawk-ui test -- aetherframeRunLedger',
      'Result: 5 passed; 0 failed.',
    ]));
    expect(ledger.test_evidence).toEqual([{
      claim: '',
      command: 'Validation evidence: yarn workspace hexhawk-ui test -- aetherframeRunLedger',
      result: 'Result: 5 passed; 0 failed.',
      evidence_kind: 'command_and_result',
    }]);
    expect(ledger.commit_ready).toBe(true);
    expect(ledger.reasons_not_ready).toEqual([]);
  });

  it('parses synthetic git-status text with work or target as not commit-ready', () => {
    const ledger = buildAetherframeRunLedger({
      repo: 'D:/Project/HexHawk',
      currentBranch: 'main',
      gitStatusShort: [
        ' M work/agent-notes.md',
        '?? target/debug/build.log',
      ].join('\n'),
      agentReport: 'No source changes claimed.',
    });

    expect(ledger.changed_files).toEqual(['work/agent-notes.md', 'target/debug/build.log']);
    expect(ledger.forbidden_path_hits).toEqual(['work/agent-notes.md', 'target/debug/build.log']);
    expect(ledger.commit_ready).toBe(false);
    expect(ledger.reasons_not_ready.join(' ')).toContain('forbidden paths changed');
  });

  it('requires command evidence when a synthetic report claims tests passed', () => {
    const ledger = buildAetherframeRunLedger({
      repo: 'D:/Project/HexHawk',
      currentBranch: 'main',
      gitStatusShort: ' M HexHawk/src/utils/aetherframeRunLedger.ts',
      agentReport: 'All tests passed.',
      allowedPaths: ['HexHawk/src/utils/'],
    });

    expect(ledger.claimed_tests).toEqual(['All tests passed.']);
    expect(ledger.test_evidence).toEqual([{
      claim: 'All tests passed.',
      command: null,
      result: null,
      evidence_kind: 'claim_only',
    }]);
    expect(ledger.commit_ready).toBe(false);
    expect(ledger.reasons_not_ready).toContain(
      'agent report claims tests/checks passed but includes no recognizable test command evidence',
    );
  });

  it('classifies a recognizable command without result evidence as command-only and not ready', () => {
    const ledger = buildAetherframeRunLedger({
      repo: 'D:/Project/HexHawk',
      currentBranch: 'main',
      gitStatusShort: ' M HexHawk/src/utils/aetherframeRunLedger.ts',
      agentReport: 'cargo test --workspace',
      allowedPaths: ['HexHawk/src/utils/'],
    });

    expect(ledger.test_evidence).toEqual([{
      claim: '',
      command: 'cargo test --workspace',
      result: null,
      evidence_kind: 'command_only',
    }]);
    expect(ledger.commit_ready).toBe(false);
  });

  it('classifies concrete result text without a command as result-only and not ready', () => {
    const ledger = buildAetherframeRunLedger({
      repo: 'D:/Project/HexHawk',
      currentBranch: 'main',
      gitStatusShort: ' M HexHawk/src/utils/aetherframeRunLedger.ts',
      agentReport: '94 passed; 0 failed',
      allowedPaths: ['HexHawk/src/utils/'],
    });

    expect(ledger.test_evidence).toEqual([{
      claim: '',
      command: null,
      result: '94 passed; 0 failed',
      evidence_kind: 'result_only',
    }]);
    expect(ledger.commit_ready).toBe(false);
  });

  it('classifies a command followed by a passing concrete result as command-and-result', () => {
    const ledger = buildAetherframeRunLedger({
      repo: 'D:/Project/HexHawk',
      currentBranch: 'main',
      gitStatusShort: ' M HexHawk/src/utils/aetherframeRunLedger.ts',
      agentReport: 'cargo test --workspace\n94 passed; 0 failed',
      allowedPaths: ['HexHawk/src/utils/'],
    });

    expect(ledger.test_evidence).toEqual([{
      claim: '',
      command: 'cargo test --workspace',
      result: '94 passed; 0 failed',
      evidence_kind: 'command_and_result',
    }]);
    expect(ledger.commit_ready).toBe(true);
  });

  it('classifies command evidence with failure output as contradicted and not ready', () => {
    const ledger = buildAetherframeRunLedger({
      repo: 'D:/Project/HexHawk',
      currentBranch: 'main',
      gitStatusShort: ' M HexHawk/src/utils/aetherframeRunLedger.ts',
      agentReport: 'cargo test --workspace\nFAILED\nexit code 1',
      allowedPaths: ['HexHawk/src/utils/'],
    });

    expect(ledger.test_evidence).toEqual([{
      claim: '',
      command: 'cargo test --workspace',
      result: 'FAILED',
      evidence_kind: 'contradicted',
    }]);
    expect(ledger.commit_ready).toBe(false);
    expect(ledger.reasons_not_ready).toContain('agent report contains contradicted test evidence');
  });

  it('requires human approval when synthetic report touches GYRE verdict or classification authority', () => {
    const ledger = buildAetherframeRunLedger({
      repo: 'D:/Project/HexHawk',
      currentBranch: 'main',
      gitStatusShort: ' M HexHawk/src/utils/aetherframeRunLedger.ts',
      agentReport: [
        'Updated GYRE verdict classification handling.',
        'Validation evidence: yarn workspace hexhawk-ui test -- aetherframeRunLedger',
        'Result: 5 passed; 0 failed.',
      ].join('\n'),
      allowedPaths: ['HexHawk/src/utils/'],
    });

    expect(ledger.detected_human_approval_requests).toEqual(expect.arrayContaining([
      'authority-boundary review required: Updated GYRE verdict classification handling.',
    ]));
    expect(ledger.commit_ready).toBe(false);
    expect(ledger.reasons_not_ready).toContain(
      'agent report references GYRE/verdict/classification authority; human approval required before commit readiness',
    );
  });

  it('extracts staged files without changing custody state', () => {
    const parsed = parseGitStatusShort('M  HexHawk/src/utils/aetherframeRunLedger.ts\nA  HexHawk/src/utils/__tests__/aetherframeRunLedger.test.ts');

    expect(parsed.changedFiles).toEqual([
      'HexHawk/src/utils/aetherframeRunLedger.ts',
      'HexHawk/src/utils/__tests__/aetherframeRunLedger.test.ts',
    ]);
    expect(parsed.stagedFiles).toEqual([
      'HexHawk/src/utils/aetherframeRunLedger.ts',
      'HexHawk/src/utils/__tests__/aetherframeRunLedger.test.ts',
    ]);
  });
});
