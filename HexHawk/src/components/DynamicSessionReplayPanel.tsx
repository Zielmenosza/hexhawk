import React from 'react';
import { summarizeDynamicTrace, type DynamicSessionTrace } from '../utils/dynamicSessionTrace';

function hex(address: number): string {
  return `0x${address.toString(16).toUpperCase()}`;
}

interface DynamicSessionReplayPanelProps {
  trace: DynamicSessionTrace | null;
}

export function DynamicSessionReplayPanel({ trace }: DynamicSessionReplayPanelProps) {
  if (!trace) {
    return (
      <section className="dbg-empty-state" aria-labelledby="dynamic-session-replay-heading">
        <div id="dynamic-session-replay-heading" className="dbg-empty-title">Dynamic Session Replay</div>
        <div className="dbg-empty-body">
          <p>Phase 1 supports replay/import contracts before live execution expansion.</p>
          <ul>
            <li>Offline traces are replayable without executing the specimen.</li>
            <li>Runtime observations are evidence/advisory only.</li>
            <li>Live attach/debug requires separate explicit consent.</li>
          </ul>
          <p className="dbg-note">No trace loaded. Import or generate a trace fixture to review observed runtime evidence safely.</p>
        </div>
      </section>
    );
  }

  const summary = summarizeDynamicTrace(trace);
  return (
    <section className="dbg-empty-state" aria-labelledby="dynamic-session-replay-heading">
      <div id="dynamic-session-replay-heading" className="dbg-empty-title">Dynamic Session Replay</div>
      <div className="dbg-empty-body">
        <p><strong>{summary}</strong></p>
        <p>Binary hash: <code>{trace.binary.sha256}</code></p>
        <p>Mode: {trace.mode}; consent granted: {trace.consent.granted ? 'yes' : 'no'}</p>
        <ul>
          {trace.events.map(event => (
            <li key={event.id}>
              <strong>{event.kind}</strong>{event.address !== undefined ? ` @ ${hex(event.address)}` : ''}: {event.summary}
              <br />
              <small>Evidence: {event.evidenceBasis.join(', ')}</small>
            </li>
          ))}
        </ul>
        <p className="dbg-note">Advisory runtime evidence only. GYRE remains the sole verdict authority.</p>
      </div>
    </section>
  );
}

export default DynamicSessionReplayPanel;
