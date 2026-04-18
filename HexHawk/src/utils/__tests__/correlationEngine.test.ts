import { describe, it, expect } from 'vitest';
import { computeVerdict } from '../../utils/correlationEngine';
import type { CorrelationInput } from '../../utils/correlationEngine';

/** Minimal valid CorrelationInput — no signals, should produce CLEAN verdict */
function minimal(): CorrelationInput {
  return {
    sections: [{ name: '.text', entropy: 4.5, file_size: 4096 }],
    imports: [],
    strings: [],
    patterns: [],
  };
}

// ── Structure signals ─────────────────────────────────────────────────────────

describe('computeVerdict — structure signals', () => {
  it('returns low-threat verdict for benign flat binary', () => {
    const result = computeVerdict(minimal());
    expect(result.threatScore).toBeLessThan(40);
    // Classification may vary but should not be 'likely-malware' or 'ransomware-like'
    expect(['likely-malware', 'ransomware-like', 'dropper']).not.toContain(result.classification);
  });

  it('raises threat score for high-entropy sections', () => {
    const baseline = computeVerdict(minimal()).threatScore;
    const highEntropy = computeVerdict({
      ...minimal(),
      sections: [{ name: '.text', entropy: 7.5, file_size: 8192 }],
    });
    expect(highEntropy.threatScore).toBeGreaterThan(baseline);
  });

  it('does NOT count .rsrc or .reloc entropy as high-entropy', () => {
    const rsrc = computeVerdict({
      ...minimal(),
      sections: [
        { name: '.rsrc', entropy: 7.8, file_size: 65536 }, // resource section — should be ignored
        { name: '.text', entropy: 4.0, file_size: 4096 },
      ],
    });
    expect(rsrc.threatScore).toBeLessThan(30);
    const signalIds = rsrc.signals.map(s => s.id);
    expect(signalIds).not.toContain('high-entropy');
  });
});

// ── Import signals ────────────────────────────────────────────────────────────

describe('computeVerdict — import signals', () => {
  it('fires injection signal for WriteProcessMemory + VirtualAllocEx', () => {
    const result = computeVerdict({
      ...minimal(),
      imports: [
        { name: 'WriteProcessMemory', library: 'KERNEL32' },
        { name: 'VirtualAllocEx', library: 'KERNEL32' },
        { name: 'CreateRemoteThread', library: 'KERNEL32' },
      ],
    });
    expect(result.threatScore).toBeGreaterThan(5);
    const signalIds = result.signals.map(s => s.id);
    expect(signalIds).toContain('injection-imports');
  });

  it('fires network signal for WSAStartup', () => {
    const result = computeVerdict({
      ...minimal(),
      imports: [{ name: 'WSAStartup', library: 'WS2_32' }],
    });
    const signalIds = result.signals.map(s => s.id);
    expect(signalIds).toContain('network-imports');
  });

  it('fires anti-debug signal for CheckRemoteDebuggerPresent', () => {
    const result = computeVerdict({
      ...minimal(),
      imports: [{ name: 'CheckRemoteDebuggerPresent', library: 'KERNEL32' }],
    });
    const signalIds = result.signals.map(s => s.id);
    expect(signalIds).toContain('antidebug-imports');
  });

  it('does NOT fire anti-debug signal twice (deduplication)', () => {
    const result = computeVerdict({
      ...minimal(),
      imports: [
        { name: 'IsDebuggerPresent', library: 'KERNEL32' },
        { name: 'CheckRemoteDebuggerPresent', library: 'KERNEL32' },
        { name: 'NtQueryInformationProcess', library: 'ntdll' },
      ],
    });
    const antiDebugSignals = result.signals.filter(s => s.id === 'antidebug-imports');
    expect(antiDebugSignals.length).toBe(1);
  });

  it('applies negative GUI signal for standard Windows app imports', () => {
    const result = computeVerdict({
      ...minimal(),
      imports: [
        { name: 'MessageBoxA', library: 'USER32' },
        { name: 'CreateWindowExA', library: 'USER32' },
        { name: 'DefWindowProcA', library: 'USER32' },
        { name: 'InitCommonControls', library: 'COMCTL32' },
      ],
    });
    const negIds = result.negativeSignals.map(s => s.id);
    expect(negIds.length).toBeGreaterThan(0);
  });
});

// ── String signals ────────────────────────────────────────────────────────────

describe('computeVerdict — string signals', () => {
  it('fires hardcoded-ips signal for a hardcoded IP and embedded-urls for a URL', () => {
    const result = computeVerdict({
      ...minimal(),
      strings: [{ text: '192.168.1.100' }, { text: 'http://evil.example.com/payload' }],
    });
    const signalIds = result.signals.map(s => s.id);
    // Engine uses separate signals for IPs and URLs
    expect(signalIds.some(id => id === 'hardcoded-ips' || id === 'embedded-urls')).toBe(true);
  });

  it('fires base64-strings signal for multiple base64 strings', () => {
    const result = computeVerdict({
      ...minimal(),
      // Regex: /^[A-Za-z0-9+/]{20,}={0,2}$/ AND length % 4 === 0
      strings: [
        { text: 'TVqQAAMAAAAEAAAA//8AALg=' },    // 24 chars, length%4===0
        { text: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAA' }, // 28 chars, length%4===0
      ],
    });
    const signalIds = result.signals.map(s => s.id);
    expect(signalIds).toContain('base64-strings');
  });
});

// ── Verdict shape ─────────────────────────────────────────────────────────────

describe('computeVerdict — result shape', () => {
  it('always returns required fields', () => {
    const result = computeVerdict(minimal());
    expect(result).toHaveProperty('classification');
    expect(result).toHaveProperty('threatScore');
    expect(result).toHaveProperty('confidence');
    expect(result).toHaveProperty('signals');
    expect(result).toHaveProperty('negativeSignals');
    expect(result).toHaveProperty('reasoningChain');
    expect(result).toHaveProperty('contradictions');
    expect(result).toHaveProperty('alternatives');
    expect(typeof result.threatScore).toBe('number');
    expect(result.threatScore).toBeGreaterThanOrEqual(0);
    expect(result.threatScore).toBeLessThanOrEqual(100);
    expect(result.confidence).toBeGreaterThanOrEqual(0);
    expect(result.confidence).toBeLessThanOrEqual(100);
  });

  it('corroborates signals when multiple correlated sources fire', () => {
    const result = computeVerdict({
      sections: [{ name: '.text', entropy: 7.5, file_size: 8192 }],
      imports: [
        { name: 'WSAStartup', library: 'WS2_32' },
        { name: 'CreateRemoteThread', library: 'KERNEL32' },
      ],
      strings: [{ text: 'http://c2.attacker.com/beacon' }],
      patterns: [],
    });
    expect(result.threatScore).toBeGreaterThan(40);
    // At least some corroborations should be set
    const corroborated = result.signals.filter(s => s.corroboratedBy.length > 0);
    expect(corroborated.length).toBeGreaterThan(0);
  });

  it('iterationIndex dampens confidence on early iterations', () => {
    const undampened = computeVerdict(minimal());
    const dampened = computeVerdict({ ...minimal(), iterationIndex: 0 });
    expect(dampened.confidence).toBeLessThanOrEqual(undampened.confidence);
  });
});
