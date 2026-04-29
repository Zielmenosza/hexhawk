import { describe, expect, it } from 'vitest';
import { getPanelFidelityForView, normalizeActivityMessage } from '../utils/qaUx';

describe('qaUx activity normalization', () => {
  it('normalizes seeded hex preview events', () => {
    const normalized = normalizeActivityMessage('Seeded browser hex preview for C:/tmp/a.exe at 0x0.');
    expect(normalized.startsWith('HEX_PREVIEW_SEEDED |')).toBe(true);
  });

  it('normalizes semantic query events', () => {
    const normalized = normalizeActivityMessage('Semantic query matched "Process Injection" (86% confidence).');
    expect(normalized.startsWith('SEMANTIC_QUERY |')).toBe(true);
  });

  it('normalizes status-strip toggle events', () => {
    const normalized = normalizeActivityMessage('Toggled QA source matrix: open.');
    expect(normalized.startsWith('QA_MATRIX_TOGGLED |')).toBe(true);
  });
});

describe('qaUx panel fidelity detail', () => {
  it('provides strong simulation transparency for hex panel', () => {
    const fidelity = getPanelFidelityForView('hex', true);
    expect(fidelity.source).toBe('simulation');
    expect(fidelity.detail.toLowerCase()).toContain('read_hex_range');
  });

  it('provides explicit simulation detail for signals panel', () => {
    const fidelity = getPanelFidelityForView('signals', true);
    expect(fidelity.source).toBe('simulation');
    expect(fidelity.detail.toLowerCase()).toContain('client-side');
  });

  it('keeps ui-only detail for activity panel', () => {
    const fidelity = getPanelFidelityForView('activity', true);
    expect(fidelity.source).toBe('ui-only');
    expect(fidelity.detail.toLowerCase()).toContain('client-side ui');
  });
});
