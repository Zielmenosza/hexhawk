export type TechnicalPreviewTrustCenterProps = {
  signingStatus: string;
  localMode: string;
};

export function TechnicalPreviewTrustCenter({ signingStatus, localMode }: TechnicalPreviewTrustCenterProps) {
  return (
    <section className="report-section technical-preview-trust-center" data-testid="technical-preview-trust-center">
      <div className="report-section-title">Technical Preview Trust Center</div>
      <div className="metadata-grid">
        <div className="metadata-row"><span>Signing status</span><span>{signingStatus}</span></div>
        <div className="metadata-row"><span>Operation model</span><span>{localMode}</span></div>
      </div>

      <h4>What HexHawk proves</h4>
      <ul>
        <li>GUI, backend/CLI, and report export can be tied to the same SHA-256 evidence identity.</li>
        <li>Native backend evidence is labelled separately from browser simulation and UI-only presentation.</li>
        <li>CFG budgets and truncation metadata are visible when graph rendering is bounded.</li>
        <li>Replay manifests can record file path, SHA-256, command, timestamp, artifact source, and analysis limits.</li>
      </ul>

      <h4>What HexHawk does not prove</h4>
      <ul>
        <li>It does not prove malware verdict correctness by provenance alone.</li>
        <li>It does not claim full CFG coverage when budgets or truncation apply.</li>
        <li>It does not make AI, AETHERFRAME, STRIKE, TALON, ECHO, plugins, or UI copy the verdict authority.</li>
        <li>It does not prove a file never leaves the machine if an explicit online feature or user export is used.</li>
      </ul>

      <p className="report-policy-note">GYRE remains the sole verdict authority. NEST remains evidence lifecycle authority. AETHERFRAME remains bounded advisory metadata.</p>
    </section>
  );
}

export default TechnicalPreviewTrustCenter;
