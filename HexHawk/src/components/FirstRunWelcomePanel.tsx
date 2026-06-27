import React from 'react';

const SUPPORTED_EXTENSIONS = new Set(['.exe', '.dll', '.sys', '.bin']);

interface FirstRunWelcomePanelProps {
  onBrowse: () => void;
  onDropFile: (path: string) => void;
}

function extensionOf(path: string): string {
  const dot = path.lastIndexOf('.');
  return dot >= 0 ? path.slice(dot).toLowerCase() : '';
}

function pathFromDrop(event: React.DragEvent): string | null {
  const files = Array.from(event.dataTransfer.files ?? []);
  const filePath = files
    .map(file => (file as File & { path?: string }).path || file.name)
    .find(Boolean);
  if (filePath) return filePath;
  const uri = event.dataTransfer.getData('text/uri-list') || event.dataTransfer.getData('text/plain');
  return uri.trim() || null;
}

export default function FirstRunWelcomePanel({ onBrowse, onDropFile }: FirstRunWelcomePanelProps) {
  const [dragActive, setDragActive] = React.useState(false);
  const [dropError, setDropError] = React.useState<string | null>(null);

  const handleDrop = (event: React.DragEvent) => {
    event.preventDefault();
    setDragActive(false);
    const path = pathFromDrop(event);
    if (!path) {
      setDropError('No file path found in drop.');
      return;
    }
    if (!SUPPORTED_EXTENSIONS.has(extensionOf(path))) {
      setDropError('Drop a .exe, .dll, .sys, or .bin file.');
      return;
    }
    setDropError(null);
    onDropFile(path);
  };

  return (
    <section
      className={`first-run-panel${dragActive ? ' first-run-panel--drag' : ''}`}
      data-testid="first-run-panel"
      onDragOver={(event) => { event.preventDefault(); setDragActive(true); }}
      onDragLeave={() => setDragActive(false)}
      onDrop={handleDrop}
      style={{ border: '1px solid #2d3548', borderRadius: 12, padding: '1.5rem', background: 'rgba(12, 16, 28, 0.92)', marginBottom: '1rem' }}
    >
      <h2>HexHawk Reverse-Engineering Workbench</h2>
      <p>Analyse a Windows executable locally.</p>
      <p><strong>Your files never leave this machine.</strong></p>

      <div
        aria-label="Drop a .exe or .dll here"
        style={{ border: '1px dashed #4f6b9a', borderRadius: 10, padding: '1rem', margin: '1rem 0', textAlign: 'center', background: dragActive ? 'rgba(77, 255, 145, 0.08)' : 'rgba(255, 255, 255, 0.03)' }}
      >
        Drop a .exe or .dll here
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
        <span>or</span>
        <button type="button" className="browse-btn" onClick={onBrowse} data-testid="first-run-browse">Browse for file</button>
      </div>

      <h3>What HexHawk will show you:</h3>
      <ul>
        <li>✓ File facts and hashes</li>
        <li>✓ Imported functions and libraries</li>
        <li>✓ Disassembled code (Code map)</li>
        <li>✓ Function details and call graph</li>
        <li>✓ Decompiled pseudocode (advisory)</li>
        <li>✓ Evidence report you can export</li>
      </ul>
      <p role="note">⚠ HexHawk opens files for inspection only. It does not execute them.</p>
      {dropError && <div role="alert" style={{ color: '#ff8a8a' }}>{dropError}</div>}
    </section>
  );
}
