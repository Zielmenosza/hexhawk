import type { CapabilityMatrixV1, EvidenceRecordV1, SelectedAnalysisProviderV1 } from '../utils/evidenceRecord';

export type EvidenceResourceBrowserProps = {
  provider: SelectedAnalysisProviderV1;
  records: EvidenceRecordV1[];
  capabilityMatrix: CapabilityMatrixV1;
};

function availabilityLabel(value: string): string {
  return value.replace(/-/g, ' ');
}

export function EvidenceResourceBrowser({ provider, records, capabilityMatrix }: EvidenceResourceBrowserProps) {
  const visibleRecords = records.slice(0, 8);
  return (
    <section className="report-section evidence-resource-browser" data-testid="evidence-resource-browser">
      <div className="report-section-title">Evidence Resources and Capability Matrix</div>
      <p className="report-policy-note">
        Provider is fixed for this analysis run. Silent fallback is disabled; unavailable, partial, and simulation-only states are treated as evidence states.
      </p>

      <div className="metadata-grid">
        <div className="metadata-row"><span>Provider</span><span>{provider.provider}</span></div>
        <div className="metadata-row"><span>Runtime</span><span>{provider.runtime}</span></div>
        <div className="metadata-row"><span>Profile</span><span>{provider.analysisProfile}</span></div>
        <div className="metadata-row"><span>Failure policy</span><span>{provider.failurePolicy}</span></div>
        <div className="metadata-row"><span>Silent fallback</span><span>{provider.silentFallbackAllowed ? 'allowed' : 'disabled'}</span></div>
      </div>

      <h4>Capabilities for this session</h4>
      <div className="metadata-grid">
        {capabilityMatrix.entries.map((entry) => (
          <div className="metadata-row" key={entry.capability}>
            <span>{entry.capability}</span>
            <span>
              <strong>{availabilityLabel(entry.availability)}</strong>
              {' — '}
              {entry.reason}
            </span>
          </div>
        ))}
      </div>

      <h4>Evidence records</h4>
      {records.length === 0 ? (
        <p className="report-policy-note">No evidence records have been generated yet. Run Inspect or another analysis action.</p>
      ) : (
        <div className="metadata-grid">
          {visibleRecords.map((record) => (
            <div className="metadata-row" key={record.evidenceId}>
              <span>{record.operation}</span>
              <span>
                <code>{record.evidenceId}</code>
                {' · '}
                {record.evidenceMode}
                {' · '}
                {record.confidenceKind}
              </span>
            </div>
          ))}
        </div>
      )}
      {records.length > visibleRecords.length && (
        <p className="report-policy-note">Showing {visibleRecords.length} of {records.length} evidence records; full records are included in JSON/CREST export.</p>
      )}
      <p className="report-policy-note">
        These records package operation identity, producer, parameters, limits, and links. They do not change final file assessment authority.
      </p>
    </section>
  );
}

export default EvidenceResourceBrowser;
