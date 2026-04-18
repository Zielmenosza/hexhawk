import { describe, it, expect } from 'vitest';
import { classifyIntent, generateWorkflow } from '../../utils/operatorConsole';
import type { BinaryContext } from '../../utils/operatorConsole';

// ── classifyIntent ────────────────────────────────────────────────────────────

describe('classifyIntent', () => {
  it('returns general-analysis for empty string', () => {
    expect(classifyIntent('')).toBe('general-analysis');
  });

  it('classifies injection keywords', () => {
    expect(classifyIntent('Looking for shellcode injection')).toBe('injection');
    expect(classifyIntent('process hollowing suspected')).toBe('injection');
    expect(classifyIntent('DLL inject into svchost')).toBe('injection');
  });

  it('classifies networking keywords', () => {
    expect(classifyIntent('check for C2 communication')).toBe('networking');
    expect(classifyIntent('beacon traffic analysis')).toBe('networking');
    expect(classifyIntent('looks like it downloads a payload')).toBe('networking');
  });

  it('classifies persistence keywords', () => {
    expect(classifyIntent('autorun registry key')).toBe('persistence');
    expect(classifyIntent('scheduled task creation')).toBe('persistence');
    expect(classifyIntent('startup folder modification')).toBe('persistence');
  });

  it('classifies unpacking keywords', () => {
    expect(classifyIntent('UPX packed binary')).toBe('unpacking');
    expect(classifyIntent('encoded payload needs decoding')).toBe('unpacking');
  });

  it('classifies obfuscation keywords', () => {
    expect(classifyIntent('XOR obfuscated strings')).toBe('obfuscation');
    // 'base64' matches obfuscation rule; 'encrypted' also matches obfuscation
    expect(classifyIntent('base64 mangle obfuscation')).toBe('obfuscation');
  });

  it('classifies anti-analysis keywords', () => {
    expect(classifyIntent('anti-debug techniques present')).toBe('anti-analysis');
    // Must use exact keyword: 'anti-vm' (not 'checks for VM')
    expect(classifyIntent('anti-vm checks')).toBe('anti-analysis');
  });

  it('classifies credential-theft keywords', () => {
    expect(classifyIntent('lsass memory dump')).toBe('credential-theft');
    expect(classifyIntent('NTLM hash extraction')).toBe('credential-theft');
  });

  it('classifies lateral-movement keywords', () => {
    expect(classifyIntent('SMB lateral movement')).toBe('lateral-movement');
    // 'wmi' matches lateral-movement; avoid 'spread across network' which hits networking first
    expect(classifyIntent('wmi lateral pivot')).toBe('lateral-movement');
  });

  it('classifies ransomware keywords', () => {
    expect(classifyIntent('ransom demand for bitcoin')).toBe('ransomware');
    // 'lock-file' matches ransomware
    expect(classifyIntent('lock-file ransomware variant')).toBe('ransomware');
  });

  it('falls back to general-analysis for unrecognized input', () => {
    expect(classifyIntent('what is this binary doing')).toBe('general-analysis');
    expect(classifyIntent('analyze the binary')).toBe('general-analysis');
  });
});

// ── generateWorkflow ──────────────────────────────────────────────────────────

describe('generateWorkflow', () => {
  it('returns a workflow with the correct intent', () => {
    const wf = generateWorkflow('shellcode injection suspected');
    expect(wf.intent).toBe('injection');
    expect(wf.intentLabel).toBe('Process Injection');
  });

  it('returns non-empty steps for every intent', () => {
    const intents = [
      'injection', 'check for C2', 'autorun persistence',
      'UPX unpack', 'XOR obfuscation', 'anti-debug check',
      'lsass credential dump', 'SMB lateral pivot', 'file encryption ransom',
      'general binary review',
    ];
    for (const prompt of intents) {
      const wf = generateWorkflow(prompt);
      expect(wf.steps.length).toBeGreaterThan(0);
    }
  });

  it('all steps have required fields', () => {
    const wf = generateWorkflow('check for C2 beaconing');
    for (const step of wf.steps) {
      expect(step).toHaveProperty('id');
      expect(step).toHaveProperty('action');
      expect(step).toHaveProperty('status', 'pending');
      expect(step).toHaveProperty('priority');
      expect(['critical', 'high', 'medium', 'low']).toContain(step.priority);
    }
  });

  it('uses context to fill binaryPath hint', () => {
    const context: BinaryContext = {
      binaryPath: 'C:\\malware\\sample.exe',
      importNames: ['CreateRemoteThread', 'VirtualAllocEx'],
    };
    const wf = generateWorkflow('injection', context);
    expect(wf.contextApplied).toBe(true);
    // Step hints should mention the binary path or relevant imports
    const hints = wf.steps.flatMap(s => s.contextHint ?? []);
    expect(hints.length).toBeGreaterThan(0);
  });

  it('returns general-analysis workflow for empty prompt with no context', () => {
    const wf = generateWorkflow('');
    expect(wf.intent).toBe('general-analysis');
    expect(wf.steps.length).toBeGreaterThan(0);
  });
});
