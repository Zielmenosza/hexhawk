/**
 * XRefPanel.tsx — Cross-Reference (XRef) viewer
 *
 * Shows incoming and outgoing references for the currently selected address.
 * Renders both directions with typed badges so analysts can understand the
 * nature of each reference without reading source code.
 *
 * RE concepts exposed:
 *   - cross-reference (xref):  any address-to-address reference in disassembly
 *   - incoming xrefs:          who references this address (callers, jumpers, data readers)
 *   - outgoing xrefs:          what this address references (callees, jump targets, data writes)
 *   - call site:               an instruction that performs a CALL to this address
 *   - caller:                  function that contains a call site pointing here
 *   - callee:                  function called by an instruction at this address
 */

import React, { useMemo, useState } from 'react';

// ─── Types ────────────────────────────────────────────────────────────────────

export type XRefKind = 'CALL' | 'JMP' | 'JMP_COND' | 'DATA' | 'STRING' | 'RIP_REL';

interface XRefEntry {
  /** Address of the instruction that is the source of this reference. */
  sourceAddress: number;
  /** Address that is being referenced (the target). */
  targetAddress: number;
  kind: XRefKind;
}

interface Props {
  /** Currently selected address in the disassembly view. */
  selectedAddress: number | null;
  /**
   * Flat map of all xrefs: key = `"src:dst"` (both as decimal strings),
   * value = xref kind.  Built by App.tsx `buildReferenceMaps`.
   */
  xrefTypes: Map<string, XRefKind>;
  /**
   * Incoming reference map: targetAddress → Set<sourceAddress>.
   * Built by App.tsx `buildReferenceMaps`.
   */
  referencesMap: Map<number, Set<number>>;
  /**
   * Outgoing reference map: sourceAddress → Set<targetAddress>.
   * Built by App.tsx `buildReferenceMaps` (jumpTargetsMap).
   */
  jumpTargetsMap: Map<number, Set<number>>;
  /** Navigate to an address (switches to disassembly + scrolls). */
  onNavigate?: (address: number) => void;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const KIND_META: Record<XRefKind, { label: string; color: string; title: string }> = {
  CALL:    { label: 'CALL',  color: '#ff9f64', title: 'Direct function call — this is a call site' },
  JMP:     { label: 'JMP',   color: '#f7bb6b', title: 'Unconditional jump' },
  JMP_COND:{ label: 'JCC',   color: '#f7768e', title: 'Conditional jump (true/false edge)' },
  DATA:    { label: 'DATA',  color: '#7aa2f7', title: 'Data reference (mov/lea/add/sub)' },
  STRING:  { label: 'STR',   color: '#9ece6a', title: 'String reference' },
  RIP_REL: { label: 'RIP',   color: '#bb9af7', title: 'RIP-relative addressing (x86-64)' },
};

function KindBadge({ kind }: { kind: XRefKind }) {
  const meta = KIND_META[kind] ?? { label: kind, color: '#888', title: kind };
  return (
    <span
      title={meta.title}
      style={{
        fontSize: '0.62rem',
        fontFamily: 'monospace',
        fontWeight: 700,
        padding: '1px 4px',
        borderRadius: 3,
        background: meta.color + '22',
        color: meta.color,
        border: `1px solid ${meta.color}55`,
        flexShrink: 0,
      }}
    >
      {meta.label}
    </span>
  );
}

function AddrRow({
  addr,
  kind,
  onNavigate,
  dimmed = false,
}: {
  addr: number;
  kind: XRefKind | undefined;
  onNavigate?: (a: number) => void;
  dimmed?: boolean;
}) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '0.35rem',
        padding: '2px 4px',
        borderRadius: 3,
        opacity: dimmed ? 0.5 : 1,
      }}
    >
      {kind && <KindBadge kind={kind} />}
      <button
        type="button"
        onClick={() => onNavigate?.(addr)}
        style={{
          background: 'none',
          border: 'none',
          color: '#7aa2f7',
          cursor: 'pointer',
          padding: 0,
          fontFamily: 'monospace',
          fontSize: '0.78rem',
          textDecoration: 'underline',
          textUnderlineOffset: 2,
        }}
        title={`Navigate to 0x${addr.toString(16).toUpperCase()}`}
      >
        {`0x${addr.toString(16).toUpperCase().padStart(8, '0')}`}
      </button>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

const MAX_VISIBLE = 12;

export function XRefPanel({
  selectedAddress,
  xrefTypes,
  referencesMap,
  jumpTargetsMap,
  onNavigate,
}: Props) {
  const [showAllIn, setShowAllIn] = useState(false);
  const [showAllOut, setShowAllOut] = useState(false);

  const incomingXrefs = useMemo((): XRefEntry[] => {
    if (selectedAddress === null) return [];
    const sources = referencesMap.get(selectedAddress);
    if (!sources) return [];
    return Array.from(sources).map(src => ({
      sourceAddress: src,
      targetAddress: selectedAddress,
      kind: xrefTypes.get(`${src}:${selectedAddress}`) ?? 'DATA',
    }));
  }, [selectedAddress, referencesMap, xrefTypes]);

  const outgoingXrefs = useMemo((): XRefEntry[] => {
    if (selectedAddress === null) return [];
    const targets = jumpTargetsMap.get(selectedAddress);
    if (!targets) return [];
    return Array.from(targets).map(dst => ({
      sourceAddress: selectedAddress,
      targetAddress: dst,
      kind: xrefTypes.get(`${selectedAddress}:${dst}`) ?? 'DATA',
    }));
  }, [selectedAddress, jumpTargetsMap, xrefTypes]);

  if (selectedAddress === null) {
    return (
      <div className="panel" style={{ padding: '0.75rem' }}>
        <h4 style={{ margin: '0 0 0.4rem', fontSize: '0.85rem' }}>Cross-References</h4>
        <p style={{ color: '#666', fontSize: '0.78rem' }}>Select an instruction to see its xrefs.</p>
      </div>
    );
  }

  const totalIn  = incomingXrefs.length;
  const totalOut = outgoingXrefs.length;
  const visIn    = showAllIn  ? incomingXrefs : incomingXrefs.slice(0, MAX_VISIBLE);
  const visOut   = showAllOut ? outgoingXrefs : outgoingXrefs.slice(0, MAX_VISIBLE);

  // Summarise by kind for the "incoming calls" special case
  const callSites = incomingXrefs.filter(x => x.kind === 'CALL');

  return (
    <div className="panel" style={{ padding: '0.6rem 0.75rem', fontSize: '0.8rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.5rem', marginBottom: '0.5rem' }}>
        <h4 style={{ margin: 0, fontSize: '0.85rem' }}>Cross-References</h4>
        <span style={{ color: '#888', fontSize: '0.72rem' }}>
          {`0x${selectedAddress.toString(16).toUpperCase()}`}
        </span>
      </div>

      {/* Call site callout — highlighted when address is a function entry */}
      {callSites.length > 0 && (
        <div style={{ background: 'rgba(255,159,100,0.08)', border: '1px solid rgba(255,159,100,0.25)', borderRadius: 4, padding: '0.35rem 0.5rem', marginBottom: '0.5rem', fontSize: '0.75rem', color: '#ff9f64' }}>
          <strong>{callSites.length}</strong> call site{callSites.length !== 1 ? 's' : ''} — this address is called by {callSites.length} caller{callSites.length !== 1 ? 's' : ''}
        </div>
      )}

      {/* Incoming xrefs */}
      <div style={{ marginBottom: '0.6rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.25rem' }}>
          <span style={{ color: '#9ece6a', fontWeight: 600, fontSize: '0.75rem' }}>
            ↓ Incoming ({totalIn})
          </span>
          <span style={{ color: '#555', fontSize: '0.68rem' }}>who references here</span>
        </div>
        {totalIn === 0 ? (
          <span style={{ color: '#555', fontSize: '0.75rem', paddingLeft: 4 }}>No incoming references</span>
        ) : (
          <>
            {visIn.map((x, i) => (
              <AddrRow key={i} addr={x.sourceAddress} kind={x.kind} onNavigate={onNavigate} />
            ))}
            {!showAllIn && totalIn > MAX_VISIBLE && (
              <button type="button" onClick={() => setShowAllIn(true)} style={{ background: 'none', border: 'none', color: '#7aa2f7', cursor: 'pointer', fontSize: '0.72rem', padding: '2px 4px' }}>
                +{totalIn - MAX_VISIBLE} more…
              </button>
            )}
          </>
        )}
      </div>

      {/* Outgoing xrefs */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.25rem' }}>
          <span style={{ color: '#f7768e', fontWeight: 600, fontSize: '0.75rem' }}>
            ↑ Outgoing ({totalOut})
          </span>
          <span style={{ color: '#555', fontSize: '0.68rem' }}>what this references</span>
        </div>
        {totalOut === 0 ? (
          <span style={{ color: '#555', fontSize: '0.75rem', paddingLeft: 4 }}>No outgoing references</span>
        ) : (
          <>
            {visOut.map((x, i) => (
              <AddrRow key={i} addr={x.targetAddress} kind={x.kind} onNavigate={onNavigate} />
            ))}
            {!showAllOut && totalOut > MAX_VISIBLE && (
              <button type="button" onClick={() => setShowAllOut(true)} style={{ background: 'none', border: 'none', color: '#7aa2f7', cursor: 'pointer', fontSize: '0.72rem', padding: '2px 4px' }}>
                +{totalOut - MAX_VISIBLE} more…
              </button>
            )}
          </>
        )}
      </div>

      {/* Glossary footer */}
      <div style={{ marginTop: '0.6rem', paddingTop: '0.4rem', borderTop: '1px solid #222', display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
        {(Object.keys(KIND_META) as XRefKind[]).map(k => (
          <span key={k} title={KIND_META[k].title} style={{ fontSize: '0.62rem', color: KIND_META[k].color, cursor: 'help' }}>
            <span style={{ fontWeight: 700 }}>{KIND_META[k].label}</span>
            {' '}= {KIND_META[k].title.split(' ')[0].toLowerCase()}
          </span>
        ))}
      </div>
    </div>
  );
}

export default XRefPanel;
