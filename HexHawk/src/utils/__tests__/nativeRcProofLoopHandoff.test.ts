import { describe, expect, it } from 'vitest';
import { buildNativeRcProofReadme } from '../nativeRcProofLoop';

describe('Native RC proof handoff README', () => {
  it('states what is proven and explicitly blocks release-ready/verdict-correctness claims', () => {
    const readme = buildNativeRcProofReadme({
      bundleId: 'crest-676807a587aa-1',
      fixturePath: 'HexHawk/package.json',
      sha256: '676807a587aaed5e3c070e7595f5fb1480790b8312c53e202bf6830dd7789251',
      signingStatus: 'unsigned technical preview',
      nativeRuntime: 'tauri-native',
      blocker: null,
    });
    expect(readme).toContain('Native Product Release Candidate Proof Loop');
    expect(readme).toContain('What this proof loop proves');
    expect(readme).toContain('What this proof loop does not prove');
    expect(readme).toContain('not release-ready');
    expect(readme).toContain('does not prove verdict correctness');
    expect(readme).toContain('crest-676807a587aa-1');
  });
});
