import React, { useMemo } from 'react';

interface XRef {
  address: number;
  kind: 'CALL' | 'JMP' | 'JMP_COND' | 'DATA' | 'STRING' | 'RIP_REL';
  mnemonic?: string;
}

interface ReferencesPanelProps {
  address: number | null;
  incomingRefs: XRef[];
  outgoingRefs: XRef[];
  onNavigate: (address: number) => void;
  formatHex: (n: number) => string;
}

export function ReferencesPanel({
  address,
  incomingRefs,
  outgoingRefs,
  onNavigate,
  formatHex,
}: ReferencesPanelProps) {
  const getRefTypeColor = (kind: string): string => {
    switch (kind) {
      case 'CALL':
        return '#ff9f64';  // Orange
      case 'JMP':
        return '#ff9f64';  // Orange
      case 'JMP_COND':
        return '#f7768e';  // Red
      case 'DATA':
        return '#7aa2f7';  // Blue
      case 'STRING':
        return '#9ece6a';  // Green
      case 'RIP_REL':
        return '#7dcfff';  // Cyan
      default:
        return '#9d9d9d';  // Gray
    }
  };

  const getRefTypeLabel = (kind: string): string => {
    switch (kind) {
      case 'CALL':
        return 'CALL';
      case 'JMP':
        return 'JMP';
      case 'JMP_COND':
        return 'JMP_COND';
      case 'DATA':
        return 'DATA';
      case 'STRING':
        return 'STR';
      case 'RIP_REL':
        return 'RIP';
      default:
        return kind;
    }
  };

  if (!address) {
    return (
      <div className="references-panel-empty">
        <p>Select an instruction to view references</p>
      </div>
    );
  }

  return (
    <div className="references-panel">
      <div className="references-panel-header">
        <strong>References for {formatHex(address)}</strong>
      </div>

      {incomingRefs.length > 0 && (
        <div className="references-section">
          <strong className="references-section-title">⬅ Incoming ({incomingRefs.length})</strong>
          <div className="references-list">
            {incomingRefs.map((ref, idx) => (
              <div key={`in-${idx}`} className="reference-item">
                <button
                  type="button"
                  className="reference-link"
                  onClick={() => onNavigate(ref.address)}
                  title={`Jump to ${formatHex(ref.address)}${ref.mnemonic ? ` (${ref.mnemonic})` : ''}`}
                >
                  <span className="reference-addr">{formatHex(ref.address)}</span>
                  {ref.mnemonic && <span className="reference-instr">{ref.mnemonic}</span>}
                </button>
                <span
                  className="reference-kind"
                  style={{
                    backgroundColor: `${getRefTypeColor(ref.kind)}22`,
                    color: getRefTypeColor(ref.kind),
                  }}
                  title={ref.kind}
                >
                  {getRefTypeLabel(ref.kind)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {outgoingRefs.length > 0 && (
        <div className="references-section">
          <strong className="references-section-title">➡ Outgoing ({outgoingRefs.length})</strong>
          <div className="references-list">
            {outgoingRefs.map((ref, idx) => (
              <div key={`out-${idx}`} className="reference-item">
                <button
                  type="button"
                  className="reference-link"
                  onClick={() => onNavigate(ref.address)}
                  title={`Jump to ${formatHex(ref.address)}`}
                >
                  <span className="reference-addr">{formatHex(ref.address)}</span>
                  {ref.mnemonic && <span className="reference-instr">{ref.mnemonic}</span>}
                </button>
                <span
                  className="reference-kind"
                  style={{
                    backgroundColor: `${getRefTypeColor(ref.kind)}22`,
                    color: getRefTypeColor(ref.kind),
                  }}
                  title={ref.kind}
                >
                  {getRefTypeLabel(ref.kind)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {incomingRefs.length === 0 && outgoingRefs.length === 0 && (
        <div className="references-empty">
          <p>No references found for this instruction</p>
        </div>
      )}
    </div>
  );
}
