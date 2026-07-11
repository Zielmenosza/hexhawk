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
        'Result: tests passed.',
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
      'Result: tests passed.',
    ]));
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
      agentReport: 'All tests passed and the suite is green.',
      allowedPaths: ['HexHawk/src/utils/'],
    });

    expect(ledger.claimed_tests).toEqual(['All tests passed and the suite is green.']);
    expect(ledger.commit_ready).toBe(false);
    expect(ledger.reasons_not_ready).toContain(
      'agent report claims tests/checks passed but includes no recognizable test command evidence',
    );
  });

  it('requires human approval when synthetic report touches GYRE verdict or classification authority', () => {
    const ledger = buildAetherframeRunLedger({
      repo: 'D:/Project/HexHawk',
      currentBranch: 'main',
      gitStatusShort: ' M HexHawk/src/utils/aetherframeRunLedger.ts',
      agentReport: [
        'Updated GYRE verdict classification handling.',
        'Validation evidence: yarn workspace hexhawk-ui test -- aetherframeRunLedger',
        'Result: tests passed.',
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
