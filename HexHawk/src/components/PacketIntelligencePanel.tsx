import React, { useMemo, useRef, useState } from 'react';
import { analyzeHarText, type PacketIntelligenceReport } from '../utils/harPacketIntelligence';

const PacketIntelligencePanel: React.FC = () => {
  const inputRef = useRef<HTMLInputElement>(null);
  const [report, setReport] = useState<PacketIntelligenceReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');

  const visibleEntries = useMemo(() => {
    if (!report) return [];
    const needle = filter.trim().toLowerCase();
    if (!needle) return report.entries.slice(0, 200);
    return report.entries.filter(entry =>
      entry.host.toLowerCase().includes(needle)
      || entry.url.toLowerCase().includes(needle)
      || entry.method.toLowerCase().includes(needle)
      || String(entry.status).includes(needle),
    ).slice(0, 200);
  }, [filter, report]);

  const handleFile = async (file: File | null) => {
    if (!file) return;
    setError(null);
    try {
      if (file.size > 25 * 1024 * 1024) throw new Error('HAR file is too large (25 MiB maximum).');
      setReport(analyzeHarText(await file.text()));
    } catch (caught) {
      setReport(null);
      setError(String(caught));
    } finally {
      if (inputRef.current) inputRef.current.value = '';
    }
  };

  return (
    <section className="pkt-root" aria-label="Packet intelligence — advisory evidence">
      <div className="pkt-header">
        <div>
          <div className="stk-pane-title">Packet Intelligence</div>
          <div className="pkt-subtitle">Smart, metadata-first traffic triage for applications, browsers, and sites you are authorized to inspect.</div>
        </div>
        <input
          ref={inputRef}
          type="file"
          accept=".har,application/json"
          hidden
          data-testid="packet-har-input"
          onChange={event => { void handleFile(event.target.files?.[0] ?? null); }}
        />
        <button type="button" className="stk-btn stk-btn--nav" onClick={() => inputRef.current?.click()}>
          Import HAR
        </button>
      </div>

      <div className="pkt-boundary">
        Inspection is advisory. Headers, bodies, cookies, and all query values are discarded. Replay/mutation stays locked until an authorized target is declared and the exact action is confirmed.
      </div>
      {error && <div className="stk-error-banner">⚠ {error}</div>}

      {!report ? (
        <div className="stk-empty">Export a HAR from browser DevTools or an authorized capture tool, then import it here. No TLS bypass or credential capture is required.</div>
      ) : (
        <>
          <div className="pkt-metrics">
            <span>{report.totalRequests} requests</span>
            <span>{report.hosts.length} hosts</span>
            <span>{report.statusGroups.clientError + report.statusGroups.serverError} errors</span>
            <span>slowest {Math.round(report.slowRequests[0]?.durationMs ?? 0)} ms</span>
          </div>
          <div className="pkt-hosts">
            {report.hosts.slice(0, 8).map(host => <span key={host.host}>{host.host} · {host.count}</span>)}
          </div>
          <input
            className="stk-bp-field pkt-filter"
            value={filter}
            onChange={event => setFilter(event.target.value)}
            placeholder="Filter host, URL, method, or status"
            aria-label="packet filter"
          />
          <div className="pkt-table" role="table" aria-label="Sanitized packet metadata">
            {visibleEntries.map((entry, index) => (
              <div className="pkt-row" role="row" key={`${entry.startedDateTime}-${index}`}>
                <span className="pkt-method">{entry.method}</span>
                <span className={`pkt-status${entry.status >= 400 ? ' pkt-status--error' : ''}`}>{entry.status}</span>
                <span className="pkt-url" title={entry.url}>{entry.url}</span>
                <span className="pkt-time">{Math.round(entry.durationMs)} ms</span>
              </div>
            ))}
          </div>
        </>
      )}
    </section>
  );
};

export default PacketIntelligencePanel;
