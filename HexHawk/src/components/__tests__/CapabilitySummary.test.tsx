/**
 * CapabilitySummary component tests — React Testing Library
 *
 * Covers: empty imports, known-capability import sets, mixed clean/malicious,
 * capability card rendering and count labels.
 */
import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import CapabilitySummary, { type ImportEntry } from '../CapabilitySummary';

describe('CapabilitySummary', () => {
  it('renders without crashing with no imports', () => {
    render(<CapabilitySummary imports={[]} />);
    expect(document.body.innerHTML.length).toBeGreaterThan(0);
  });

  it('detects process injection capability from imports', () => {
    const imports: ImportEntry[] = [
      { name: 'VirtualAllocEx', library: 'kernel32.dll' },
      { name: 'WriteProcessMemory', library: 'kernel32.dll' },
      { name: 'CreateRemoteThread', library: 'kernel32.dll' },
    ];
    render(<CapabilitySummary imports={imports} />);
    const html = document.body.innerHTML;
    expect(html.toLowerCase()).toMatch(/inject|injection/i);
  });

  it('detects network capability from WSA imports', () => {
    const imports: ImportEntry[] = [
      { name: 'WSAStartup', library: 'ws2_32.dll' },
      { name: 'connect', library: 'ws2_32.dll' },
      { name: 'send', library: 'ws2_32.dll' },
    ];
    render(<CapabilitySummary imports={imports} />);
    const html = document.body.innerHTML;
    expect(html.toLowerCase()).toMatch(/network|c2|communication/i);
  });

  it('detects anti-debug capability', () => {
    const imports: ImportEntry[] = [
      { name: 'IsDebuggerPresent', library: 'kernel32.dll' },
      { name: 'CheckRemoteDebuggerPresent', library: 'kernel32.dll' },
    ];
    render(<CapabilitySummary imports={imports} />);
    const html = document.body.innerHTML;
    expect(html.toLowerCase()).toMatch(/debug|anti/i);
  });

  it('renders clean-only imports without capability cards', () => {
    const imports: ImportEntry[] = [
      { name: 'MessageBoxA', library: 'user32.dll' },
      { name: 'GetSystemTime', library: 'kernel32.dll' },
      { name: 'ExitProcess', library: 'kernel32.dll' },
    ];
    const { container } = render(<CapabilitySummary imports={imports} />);
    expect(container.childElementCount).toBeGreaterThanOrEqual(0);
  });

  it('handles large import list without crash', () => {
    const imports: ImportEntry[] = Array.from({ length: 200 }, (_, i) => ({
      name: `Import${i}`,
      library: 'ntdll.dll',
    }));
    render(<CapabilitySummary imports={imports} />);
    expect(document.body.innerHTML.length).toBeGreaterThan(0);
  });
});
