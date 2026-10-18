import { describe, expect, it } from 'vitest';
import { buildNativeRcProofLoop, validateNativeRcProofLoop } from '../nativeRcProofLoop';

describe('Native Product RC proof loop', () => {
  it('records native app, fixture, CREST bundle, package, screenshot, handoff, and SHA agreement without claiming release readiness', () => {
    const proof = buildNativeRcProofLoop({
      generatedAt: '2026-07-24T00:00:00.000Z',
      branch: 'fix/gyre-nest-snapshot-boundary',
      head: 'c6d78dc60fefc2aa034d8fd16092d108fa1019af',
      fixture: {
        path: 'HexHawk/package.json',
        directSha256: '676807a587aaed5e3c070e7595f5fb1480790b8312c53e202bf6830dd7789251',
        backendSha256: '676807a587aaed5e3c070e7595f5fb1480790b8312c53e202bf6830dd7789251',
        guiSha256: '676807a587aaed5e3c070e7595f5fb1480790b8312c53e202bf6830dd7789251',
        exportedBundleSha256: '676807a587aaed5e3c070e7595f5fb1480790b8312c53e202bf6830dd7789251',
      },
      nativeApp: { attempted: true, runtime: 'tauri-native', screenshotPath: 'docs/native-rc-proof/evidence-card.png', blocker: null },
      crestBundle: { path: 'docs/native-rc-proof/crest-bundle.json', bundleId: 'crest-676807a587aa-1' },
      packageCandidate: { path: 'target/debug/hexhawk-backend.exe', sha256: 'a'.repeat(64), signingStatus: 'unsigned technical preview' },
      handoffKitPath: 'docs/native-rc-proof/handoff',
    });

    expect(proof.schema).toBe('hexhawk.native_rc_proof_loop.v1');
    expect(proof.sha256_chain.all_match).toBe(true);
    expect(proof.release_claim.release_ready).toBe(false);
    expect(proof.release_claim.verdict_correctness_proven).toBe(false);
    expect(proof.proof_artifacts.screenshot_path).toBe('docs/native-rc-proof/evidence-card.png');
    expect(validateNativeRcProofLoop(proof).ok).toBe(true);
    expect(JSON.stringify(proof)).not.toContain('threatScore');
  });

  it('fails validation for SHA mismatches or browser-only smoke marked as complete', () => {
    const proof = buildNativeRcProofLoop({
      generatedAt: '2026-07-24T00:00:00.000Z',
      branch: 'branch',
      head: 'head',
      fixture: {
        path: 'HexHawk/package.json',
        directSha256: '1'.repeat(64),
        backendSha256: '2'.repeat(64),
        guiSha256: '1'.repeat(64),
        exportedBundleSha256: '1'.repeat(64),
      },
      nativeApp: { attempted: true, runtime: 'browser-simulation', screenshotPath: null, blocker: null },
      crestBundle: { path: '', bundleId: '' },
      packageCandidate: null,
      handoffKitPath: '',
    });
    const validation = validateNativeRcProofLoop(proof);
    expect(validation.ok).toBe(false);
    expect(validation.errors.join(' ')).toMatch(/SHA-256/i);
    expect(validation.errors.join(' ')).toMatch(/tauri-native/i);
  });
});
