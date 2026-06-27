import React, { useState } from 'react';
import {
  exportFunctionIntelligenceJSON,
  exportFunctionIntelligenceMarkdown,
  type FunctionCallEdge,
  type FunctionIntelligence,
  type FunctionIntelligenceLimit,
} from '../utils/functionIntelligence';

interface FunctionNotebookProps {
  functionIntelligence: FunctionIntelligence | null;
}

function hex(address: number): string {
  return `0x${address.toString(16).toUpperCase()}`;
}

function evidenceBadgeColor(basis: FunctionCallEdge['evidenceBasis'] | 'no-correlation'): string {
  if (basis === 'import-table-proven' || basis === 'static-and-observed') return '#4dff91';
  if (basis === 'static-only') return '#7aa2f7';
  if (basis === 'debugger-observed') return '#ffcc66';
  return '#8a8f98';
}

function EvidenceBadge({ basis }: { basis: FunctionCallEdge['evidenceBasis'] | 'no-correlation' }) {
  const color = evidenceBadgeColor(basis);
  return <span style={{ border: `1px solid ${color}66`, color, background: `${color}18`, borderRadius: 4, padding: '0.12rem 0.35rem', fontSize: '0.72rem' }}>{basis}</span>;
}

const LIMIT_TEXT: Record<FunctionIntelligenceLimit['kind'], string> = {
  'unresolved-call-target': 'One or more call targets could not be resolved to a known function or import.',
  'inferred-boundary': 'The function boundary was inferred and may need analyst review.',
  'unproven-call-convention': 'The calling convention is not fully proven by current evidence.',
  'unresolved-thunk': 'An import thunk was detected but not fully resolved.',
  'no-debugger-observation': 'No debugger call-stack observation is attached to this function.',
  'partial-decompile': 'Pseudocode is partial and should not be treated as recovered source.',
  'ordinal-only-import': 'An import was identified by ordinal only, without a symbolic API name.',
  'indirect-call': 'One or more indirect call targets could not be resolved to a known function or import.',
  'architecture-limit': 'This architecture is supported with explicit analysis limits in this release.',
};

function plainLimit(limit: FunctionIntelligenceLimit): string {
  return `${LIMIT_TEXT[limit.kind]} ${limit.detail}`.trim();
}

function download(filename: string, content: string, type: string): void {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function safeFilePart(value: string): string {
  return value.replace(/[^a-z0-9_.-]+/gi, '_').replace(/^_+|_+$/g, '') || 'function';
}

function functionFilename(fi: FunctionIntelligence, extension: 'json' | 'md'): string {
  return `function_${safeFilePart(fi.name)}_${fi.address.toString(16)}.${extension}`;
}

function EdgeTable({ label, edges }: { label: string; edges: FunctionCallEdge[] }) {
  return (
    <section aria-labelledby={`${label.toLowerCase()}-heading`}>
      <h3 id={`${label.toLowerCase()}-heading`}>{label}</h3>
      <table aria-label={`${label} table`}>
        <thead><tr><th>Address</th><th>Name</th><th>Basis</th><th>Constants</th></tr></thead>
        <tbody>
          {edges.length === 0 ? (
            <tr><td colSpan={4}>None observed</td></tr>
          ) : edges.map((edge, index) => (
            <tr key={`${edge.targetAddress}-${index}`}>
              <td>{hex(edge.targetAddress)}</td>
              <td>{edge.targetName ?? edge.importName ?? 'Unknown'}</td>
              <td><EvidenceBadge basis={edge.evidenceBasis} /></td>
              <td>{edge.constantAnnotations?.length ? edge.constantAnnotations.join(', ') : 'None observed'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

export function FunctionNotebook({ functionIntelligence }: FunctionNotebookProps) {
  const [mode, setMode] = useState<'compact' | 'annotated'>('compact');

  if (!functionIntelligence) {
    return (
      <section className="panel function-notebook" data-testid="function-notebook" aria-labelledby="function-notebook-heading">
        <h2 id="function-notebook-heading">Function details</h2>
        <p>No function selected. Select a function in the Code map or Branch map to see its details.</p>
        <p>This notebook combines imports, calls, pseudocode, runtime observations, and analysis limits as advisory evidence only.</p>
      </section>
    );
  }

  const fi = functionIntelligence;
  const shownPseudocode = mode === 'annotated' ? fi.pseudocodeAnnotated ?? fi.pseudocode : fi.pseudocode;
  const topBasis = fi.callees[0]?.evidenceBasis ?? 'no-correlation';

  return (
    <section className="panel function-notebook" data-testid="function-notebook" aria-labelledby="function-notebook-heading">
      <header>
        <h2 id="function-notebook-heading">Function: {fi.name} @ {hex(fi.address)}</h2>
        <p>{fi.callingConvention?.abi ?? 'unknown convention'} {fi.callingConvention ? `(${fi.callingConvention.analysisConfidence})` : ''}</p>
        <div aria-label="function evidence badges" style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
          <span>{fi.nameSource}</span>
          <span>{fi.boundarySource}</span>
          <EvidenceBadge basis={topBasis} />
        </div>
        <p><strong>Advisory analysis only.</strong> GYRE remains the sole verdict authority.</p>
      </header>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <EdgeTable label="Callers" edges={fi.callers} />
        <EdgeTable label="Callees" edges={fi.callees} />
      </div>

      <section aria-labelledby="pseudocode-heading">
        <h3 id="pseudocode-heading">Pseudocode <span>(advisory — not recovered source)</span></h3>
        <button type="button" onClick={() => setMode(mode === 'compact' ? 'annotated' : 'compact')}>Show {mode === 'compact' ? 'annotated' : 'compact'} pseudocode</button>
        <pre>{shownPseudocode ?? 'Run analysis first to see pseudocode'}</pre>
      </section>

      <section aria-labelledby="imports-heading">
        <h3 id="imports-heading">Import Calls</h3>
        <table aria-label="Import calls table">
          <thead><tr><th>Name</th><th>Module</th><th>Constants</th></tr></thead>
          <tbody>
            {fi.importCalls.length === 0 ? <tr><td colSpan={3}>None observed</td></tr> : fi.importCalls.map(entry => (
              <tr key={`${entry.callAddress}-${entry.importName}`}><td>{entry.importName}</td><td>{entry.moduleName ?? 'Unknown'}</td><td>{entry.constantAnnotations.length ? entry.constantAnnotations.join(', ') : 'None observed'}</td></tr>
            ))}
          </tbody>
        </table>
      </section>

      <section aria-labelledby="runtime-heading">
        <h3 id="runtime-heading">Runtime Observations <span>(advisory only)</span></h3>
        {(!fi.debuggerCallStack?.length && !fi.conditionalBreakpointHits?.length) ? <p>None observed</p> : (
          <ul>
            {(fi.debuggerCallStack ?? []).map((stack, index) => <li key={index}>Call stack at {hex(stack.observedAt)}: {stack.frames.map(frame => frame.symbolName ?? hex(frame.returnAddress)).join(' → ')}</li>)}
            {(fi.conditionalBreakpointHits ?? []).map(hit => <li key={`${hit.address}-${hit.condition}`}>Breakpoint {hex(hit.address)} hit {hit.hitCount} time(s): {hit.condition}</li>)}
          </ul>
        )}
      </section>

      <section aria-labelledby="limits-heading">
        <h3 id="limits-heading">Analysis Limits</h3>
        {fi.limits.length === 0 ? <p>None observed</p> : <ul>{fi.limits.map((limit, index) => <li key={index}>{plainLimit(limit)}</li>)}</ul>}
      </section>

      <footer>
        <button type="button" onClick={() => download(functionFilename(fi, 'json'), exportFunctionIntelligenceJSON(fi), 'application/json')}>Export JSON</button>
        <button type="button" onClick={() => download(functionFilename(fi, 'md'), exportFunctionIntelligenceMarkdown(fi), 'text/markdown')}>Export Markdown</button>
      </footer>
    </section>
  );
}

export default FunctionNotebook;
