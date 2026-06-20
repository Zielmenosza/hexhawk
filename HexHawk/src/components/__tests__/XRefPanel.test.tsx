import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { XRefPanel, type XRefKind } from '../XRefPanel';

function makeMap(entries: Array<[number, number[]]>): Map<number, Set<number>> {
  return new Map(entries.map(([addr, refs]) => [addr, new Set(refs)]));
}

describe('XRefPanel Code map clarity', () => {
  it('frames cross-references as Code map links while preserving advisory boundary language', () => {
    render(
      <XRefPanel
        selectedAddress={0x2000}
        xrefTypes={new Map<string, XRefKind>([
          [`${0x1004}:${0x2000}`, 'CALL'],
          [`${0x2000}:${0x2010}`, 'JMP_COND'],
        ])}
        referencesMap={makeMap([[0x2000, [0x1004]]])}
        jumpTargetsMap={makeMap([[0x2000, [0x2010]]])}
        onNavigate={vi.fn()}
      />,
    );

    expect(screen.getByText('Code map: References (XRefs)')).toBeInTheDocument();
    expect(screen.getByText(/Follow who points here and what this instruction points to/i)).toBeInTheDocument();
    expect(screen.getByText(/Advisory static-analysis links only/i)).toBeInTheDocument();
    expect(screen.getByText(/not a GYRE\/NEST verdict/i)).toBeInTheDocument();
  });

  it('keeps expert XRef labels and raw addresses visible', () => {
    render(
      <XRefPanel
        selectedAddress={0x2000}
        xrefTypes={new Map<string, XRefKind>([
          [`${0x1004}:${0x2000}`, 'CALL'],
          [`${0x2000}:${0x2010}`, 'JMP_COND'],
        ])}
        referencesMap={makeMap([[0x2000, [0x1004]]])}
        jumpTargetsMap={makeMap([[0x2000, [0x2010]]])}
      />,
    );

    expect(screen.getAllByText('CALL').length).toBeGreaterThan(0);
    expect(screen.getAllByText('JCC').length).toBeGreaterThan(0);
    expect(screen.getByText('0x00001004')).toBeInTheDocument();
    expect(screen.getByText('0x00002010')).toBeInTheDocument();
    expect(document.body.textContent).toMatch(/CALL\s*=\s*direct/i);
    expect(document.body.textContent).toMatch(/JCC\s*=\s*conditional/i);
  });

  it('shows the same Code map framing before an instruction is selected', () => {
    render(
      <XRefPanel
        selectedAddress={null}
        xrefTypes={new Map()}
        referencesMap={new Map()}
        jumpTargetsMap={new Map()}
      />,
    );

    expect(screen.getByTestId('xref-panel')).toBeInTheDocument();
    expect(screen.getByText('Code map: References (XRefs)')).toBeInTheDocument();
    expect(screen.getByText(/Select an instruction to see its xrefs/i)).toBeInTheDocument();
    expect(screen.getByText(/not a GYRE\/NEST verdict/i)).toBeInTheDocument();
  });
});
