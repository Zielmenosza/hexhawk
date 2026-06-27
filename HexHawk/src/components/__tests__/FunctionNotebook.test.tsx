import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { FunctionNotebook } from '../FunctionNotebook';
import type { FunctionIntelligence } from '../../utils/functionIntelligence';

function makeFi(): FunctionIntelligence {
  return {
    id: 'function_401000',
    address: 0x401000,
    endAddress: 0x401050,
    name: 'sub_401000',
    nameSource: 'heuristic',
    callingConvention: { abi: 'windows-x64', analysisConfidence: 'medium', evidence: 'uses rcx' },
    instructionCount: 12,
    boundarySource: 'call-target',
    callers: [{ targetAddress: 0x400100, targetName: 'main', evidenceBasis: 'static-only' }],
    callees: [{ targetAddress: 0x402000, targetName: 'CreateFileW', importName: 'CreateFileW', moduleName: 'kernel32.dll', constantAnnotations: ['GENERIC_READ'], evidenceBasis: 'import-table-proven' }],
    xrefCount: 2,
    importCalls: [{ importName: 'CreateFileW', moduleName: 'kernel32.dll', callAddress: 0x401010, constantAnnotations: ['GENERIC_READ', 'OPEN_EXISTING'] }],
    pseudocode: 'CreateFileW(path, GENERIC_READ);',
    pseudocodeAnnotated: '// annotated\nCreateFileW(path, GENERIC_READ);',
    debuggerCallStack: [{ observedAt: 0x401010, frames: [{ returnAddress: 0x401020, symbolName: 'sub_401000', moduleName: 'sample.exe' }] }],
    conditionalBreakpointHits: [{ address: 0x401010, condition: 'hit_count >= 1', hitCount: 1 }],
    sources: {
      hasImportTableEntry: true,
      hasXRefIndex: true,
      hasBoundaryHeuristic: true,
      hasConstantAnnotation: true,
      hasDecompilerOutput: true,
      hasDebuggerCallStack: true,
      hasConditionalBreakpointHit: true,
      hasCallingConvention: true,
      hasLibrarySignatureMatch: false,
    },
    limits: [{ kind: 'unresolved-call-target', address: 0x401020, detail: 'call rax' }],
    gyre_is_sole_verdict_authority: true,
    advisory_analysis_only: true,
  };
}

function mockDownloadCapture() {
  const blobs: Blob[] = [];
  Object.defineProperty(URL, 'createObjectURL', {
    configurable: true,
    value: vi.fn((blob: Blob) => { blobs.push(blob); return 'blob:hexhawk'; }),
  });
  Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: vi.fn() });
  const click = vi.fn();
  const realCreateElement = document.createElement.bind(document);
  vi.spyOn(document, 'createElement').mockImplementation((tagName: string) => {
    const element = realCreateElement(tagName);
    if (tagName.toLowerCase() === 'a') {
      Object.defineProperty(element, 'click', { value: click });
    }
    return element;
  });
  return { blobs, click };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('FunctionNotebook', () => {
  it('renders no-selection prompt when prop is null', () => {
    render(<FunctionNotebook functionIntelligence={null} />);

    expect(screen.getByText('Function details')).toBeInTheDocument();
    expect(screen.getByText(/No function selected/i)).toBeInTheDocument();
  });

  it('renders function identity, address, convention, and summary section', async () => {
    render(<FunctionNotebook functionIntelligence={makeFi()} />);

    expect(screen.getByText(/Function: sub_401000 @ 0x401000/i)).toBeInTheDocument();
    expect(screen.getByText(/windows-x64 \(medium\)/i)).toBeInTheDocument();
    expect(screen.getByText('heuristic')).toBeInTheDocument();
    expect(await screen.findByRole('heading', { name: /What this function does/i })).toBeInTheDocument();
    expect(screen.getByText(/AETHERFRAME — advisory, not a verdict/i)).toBeInTheDocument();
    await waitFor(() => expect(screen.getAllByText('File read operation').length).toBeGreaterThan(0));
  });

  it('renders callers and callees tables', () => {
    render(<FunctionNotebook functionIntelligence={makeFi()} />);

    expect(screen.getByRole('table', { name: /Callers table/i })).toBeInTheDocument();
    expect(screen.getByRole('table', { name: /Callees table/i })).toBeInTheDocument();
    expect(screen.getByText('main')).toBeInTheDocument();
    expect(screen.getAllByText('CreateFileW').length).toBeGreaterThan(0);
  });

  it('renders pseudocode with advisory label', () => {
    render(<FunctionNotebook functionIntelligence={makeFi()} />);

    expect(screen.getByText(/advisory — not recovered source/i)).toBeInTheDocument();
    expect(screen.getByText(/CreateFileW\(path, GENERIC_READ\);/i)).toBeInTheDocument();
  });

  it('Export JSON button triggers a download', () => {
    const { click } = mockDownloadCapture();
    const revokeObjectURL = vi.mocked(URL.revokeObjectURL);

    render(<FunctionNotebook functionIntelligence={makeFi()} />);
    fireEvent.click(screen.getByRole('button', { name: /Export JSON/i }));

    expect(URL.createObjectURL).toHaveBeenCalled();
    expect(click).toHaveBeenCalled();
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:hexhawk');
  });

  it('Export JSON includes summary section', async () => {
    const { blobs } = mockDownloadCapture();

    render(<FunctionNotebook functionIntelligence={makeFi()} />);
    await waitFor(() => expect(screen.getAllByText('File read operation').length).toBeGreaterThan(0));
    fireEvent.click(screen.getByRole('button', { name: /Export JSON/i }));

    const exported = JSON.parse(await blobs[0].text());
    expect(exported.function_summary.oneLiner).toBe('File read operation');
    expect(exported.function_summary.advisory_only).toBe(true);
  });

  it('Export Markdown includes summary with advisory label', async () => {
    const { blobs } = mockDownloadCapture();

    render(<FunctionNotebook functionIntelligence={makeFi()} />);
    await waitFor(() => expect(screen.getAllByText('File read operation').length).toBeGreaterThan(0));
    fireEvent.click(screen.getByRole('button', { name: /Export Markdown/i }));

    const markdown = await blobs[0].text();
    expect(markdown).toContain('## What this function does (AETHERFRAME — advisory, not a verdict)');
    expect(markdown).toContain('File read operation');
  });

  it('Refresh triggers re-generation', async () => {
    render(<FunctionNotebook functionIntelligence={makeFi()} />);
    await waitFor(() => expect(screen.getAllByText('File read operation').length).toBeGreaterThan(0));

    fireEvent.click(screen.getByRole('button', { name: /Refresh/i }));

    await waitFor(() => expect(screen.getByText(/Basis:/i)).toBeInTheDocument());
  });

  it('Copy summary writes to clipboard', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });

    render(<FunctionNotebook functionIntelligence={makeFi()} />);
    await waitFor(() => expect(screen.getAllByText('File read operation').length).toBeGreaterThan(0));
    fireEvent.click(screen.getByRole('button', { name: /Copy summary/i }));

    await waitFor(() => expect(writeText).toHaveBeenCalledWith(expect.stringContaining('File read operation')));
  });

  it('shows plain-language limit descriptions', () => {
    render(<FunctionNotebook functionIntelligence={makeFi()} />);

    expect(screen.getByText(/One or more call targets could not be resolved to a known function or import/i)).toBeInTheDocument();
  });

  it('does not render forbidden verdict field names', async () => {
    render(<FunctionNotebook functionIntelligence={makeFi()} />);
    await waitFor(() => expect(screen.getAllByText('File read operation').length).toBeGreaterThan(0));

    expect(document.body.textContent).not.toContain('classification');
    expect(document.body.textContent).not.toContain('threatScore');
  });
});
