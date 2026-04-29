import { describe, expect, it } from 'vitest';
import {
  getPanelFidelityForView,
  getQaSubsystemStatuses,
  normalizeActivityMessage,
  sourceLabel,
  splitActivityMessage,
} from '../qaUx';

describe('qaUx', () => {
  it('normalizes known activity events to stable codes', () => {
    const normalized = normalizeActivityMessage('Simulated CFG build for sample.bin');
    expect(normalized.startsWith('CFG_BUILD_SIMULATION | ')).toBe(true);
  });

  it('keeps pre-normalized event strings unchanged', () => {
    const input = 'INSPECT_COMPLETE | Inspected file: sample.bin';
    expect(normalizeActivityMessage(input)).toBe(input);
  });

  it('splits event code and detail', () => {
    const parsed = splitActivityMessage('DISASSEMBLY_COMPLETE | Disassembled sample.bin');
    expect(parsed.eventCode).toBe('DISASSEMBLY_COMPLETE');
    expect(parsed.detail).toBe('Disassembled sample.bin');
  });

  it('returns panel fidelity source per view in browser mode', () => {
    expect(getPanelFidelityForView('cfg', true).source).toBe('simulation');
    expect(getPanelFidelityForView('help', true).source).toBe('ui-only');
  });

  it('returns panel fidelity source per view in tauri mode', () => {
    expect(getPanelFidelityForView('cfg', false).source).toBe('real-backend');
  });

  it('builds QA subsystem statuses and includes UI-only export', () => {
    const browserStatuses = getQaSubsystemStatuses(true);
    const exportStatus = browserStatuses.find((s) => s.subsystem === 'Export JSON');
    expect(browserStatuses.length).toBeGreaterThan(5);
    expect(exportStatus?.source).toBe('ui-only');
  });

  it('renders expected source labels', () => {
    expect(sourceLabel('real-backend')).toBe('REAL BACKEND');
    expect(sourceLabel('simulation')).toBe('SIMULATION');
    expect(sourceLabel('ui-only')).toBe('UI ONLY');
  });
});