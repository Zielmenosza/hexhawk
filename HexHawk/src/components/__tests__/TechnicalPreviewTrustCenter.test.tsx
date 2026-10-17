import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import TechnicalPreviewTrustCenter from '../TechnicalPreviewTrustCenter';

describe('TechnicalPreviewTrustCenter', () => {
  it('tells testers what HexHawk proves and does not prove', () => {
    render(<TechnicalPreviewTrustCenter signingStatus="unsigned technical preview" localMode="local-first with explicit online features" />);

    expect(screen.getByText('Technical Preview Trust Center')).toBeTruthy();
    expect(screen.getByText(/What HexHawk proves/i)).toBeTruthy();
    expect(screen.getByText(/What HexHawk does not prove/i)).toBeTruthy();
    expect(screen.getByText(/same SHA-256/i)).toBeTruthy();
    expect(screen.getByText(/does not prove malware verdict correctness/i)).toBeTruthy();
    expect(screen.getByText(/unsigned technical preview/i)).toBeTruthy();
    expect(screen.getByText(/GYRE remains the sole verdict authority/i)).toBeTruthy();
  });
});
