import type { AnalysisSessionProvenance } from '../utils/analysisProvenance';

export type EvidenceIdentityCardProps = {
  provenance: AnalysisSessionProvenance;
  exportSha256?: string | null;
  exportArtifactOrigin?: string | null;
};

function sourceLabel(provenance: AnalysisSessionProvenance): string {
  if (provenance.runtime === 'tauri-native' && provenance.dataSource === 'real-backend') return 'Native backend evidence';
  if (provenance.runtime === 'browser-simulation') return 'Browser simulation';
  return provenance.dataSource;
}

export function EvidenceIdentityCard({ provenance, exportSha256, exportArtifactOrigin }: EvidenceIdentityCardProps) {
  const identity = provenance.binaryIdentity;
  const exportMatches = identity.sha256 === (exportSha256 ?? identity.sha256)
    && identity.artifactOrigin === (exportArtifactOrigin ?? identity.artifactOrigin);
  const native = provenance.runtime === 'tauri-native' && provenance.dataSource === 'real-backend' && identity.artifactOrigin.startsWith('tauri.');

  return (
    <section className="report-section evidence-identity-card" data-testid="evidence-identity-card">
      <div className="report-section-title">Evidence Identity Card</div>
      <p>{sourceLabel(provenance)}</p>
      <div className="metadata-grid">
        <div className="metadata-row"><span>Runtime</span><span>{provenance.runtime}</span></div>
        <div className="metadata-row"><span>Source</span><span>{identity.source}</span></div>
        <div className="metadata-row"><span>Artifact origin</span><span>{identity.artifactOrigin}</span></div>
        <div className="metadata-row"><span>Tauri command</span><span>{identity.tauriCommand ?? 'not-native'}</span></div>
        <div className="metadata-row"><span>CLI equivalent</span><span><code>{identity.cliCommand ?? 'not-available'}</code></span></div>
        <div className="metadata-row"><span>SHA-256</span><span style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{identity.sha256 ?? 'not available'}</span></div>
        <div className="metadata-row"><span>Export check</span><span>{exportMatches ? 'GUI/export identity match' : 'GUI/export identity mismatch'}</span></div>
      </div>
      <p className="report-policy-note">
        {native
          ? 'This card identifies native backend evidence only; GYRE remains sole verdict authority.'
          : 'This is not native backend evidence. Browser simulation must not be presented as file-backed native proof.'}
      </p>
    </section>
  );
}

export default EvidenceIdentityCard;
