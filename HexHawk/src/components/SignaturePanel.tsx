/**
 * SignaturePanel — Pattern Recognition Results UI
 *
 * Displays results from signatureEngine.scanSignatures():
 *   - Summary stats (functions scanned, patterns matched, coverage)
 *   - Grouped by category with color-coded badges
 *   - Per-match: name, function address, confidence, description
 *   - Click any match to navigate to that function in Disassembly
 */

import React, { useMemo, useState } from 'react';
import type { FunctionMetadata } from '../App';
import type { DisassembledInstruction } from '../utils/decompilerEngine';
import {
  scanSignatures,
  groupMatchesByCategory,
  summarizeScan,
  CATEGORY_LABELS,
  CATEGORY_COLORS,
  type SignatureScanResult,
  type SignatureMatch,
  type SignatureCategory,
} from '../utils/signatureEngine';

// ── Props ─────────────────────────────────────────────────────────────────────

interface SignaturePanelProps {
  disassembly: DisassembledInstruction[];
  functions: Map<number, FunctionMetadata>;
  onAddressSelect: (address: number) => void;
}

// ── Sub-components ────────────────────────────────────────────────────────────

const ConfidenceBar: React.FC<{ score: number }> = ({ score }) => {
  const color =
    score >= 90 ? '#4caf50' :
    score >= 75 ? '#8bc34a' :
    score >= 60 ? '#ff9800' :
    '#f44336';
  return (
    <div className="sig-conf-bar" title={`${score}% confidence`}>
      <div
        className="sig-conf-fill"
        style={{ width: `${score}%`, background: color }}
      />
      <span className="sig-conf-label">{score}%</span>
    </div>
  );
};

const CategoryBadge: React.FC<{ category: SignatureCategory }> = ({ category }) => (
  <span
    className="sig-cat-badge"
    style={{
      background: CATEGORY_COLORS[category] + '22',
      borderColor: CATEGORY_COLORS[category] + '66',
      color: CATEGORY_COLORS[category],
    }}
  >
    {CATEGORY_LABELS[category]}
  </span>
);

interface MatchCardProps {
  match: SignatureMatch;
  onNavigate: (addr: number) => void;
}

const MatchCard: React.FC<MatchCardProps> = ({ match, onNavigate }) => {
  const { signature, functionAddress, matchOffset, instrCount, score } = match;
  const [expanded, setExpanded] = useState(false);

  return (
    <div className={`sig-match-card${signature.safe ? '' : ' sig-match-card--unsafe'}`}>
      <div className="sig-match-header" onClick={() => setExpanded((x) => !x)}>
        <div className="sig-match-title-row">
          <span className="sig-match-name">{signature.displayName}</span>
          {!signature.safe && <span className="sig-match-unsafe-badge">⚠ notable</span>}
        </div>
        <div className="sig-match-meta">
          <CategoryBadge category={signature.category} />
          <ConfidenceBar score={score} />
          <span className="sig-match-chevron">{expanded ? '▲' : '▼'}</span>
        </div>
      </div>

      <div className="sig-match-addr-row">
        <span className="sig-match-addr-label">Function:</span>
        <span
          className="sig-match-addr clickable"
          onClick={() => onNavigate(functionAddress)}
          title="Navigate to function in Disassembly"
        >
          0x{functionAddress.toString(16).toUpperCase().padStart(8, '0')}
        </span>
        <span className="sig-match-loc">+{matchOffset} instr, {instrCount} matched</span>
      </div>

      {expanded && (
        <div className="sig-match-details">
          <p className="sig-match-desc">{signature.description}</p>
          {signature.behaviors.length > 0 && (
            <div className="sig-match-behaviors">
              {signature.behaviors.map((b) => (
                <span key={b} className="sig-behavior-tag">{b}</span>
              ))}
            </div>
          )}
          <div className="sig-match-pattern">
            <div className="sig-pattern-title">Normalized pattern:</div>
            {signature.normalizedPattern.map((line, i) => (
              <div key={i} className="sig-pattern-line">
                <span className="sig-pattern-num">{i + 1}</span>
                <span className="sig-pattern-text">{line}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

// ── Main component ────────────────────────────────────────────────────────────

const SignaturePanel: React.FC<SignaturePanelProps> = ({
  disassembly,
  functions,
  onAddressSelect,
}) => {
  const [filterSafe, setFilterSafe] = useState<'all' | 'safe' | 'notable'>('all');
  const [filterCategory, setFilterCategory] = useState<SignatureCategory | 'all'>('all');
  const [sortBy, setSortBy] = useState<'score' | 'address' | 'category'>('score');

  const result: SignatureScanResult = useMemo(
    () => scanSignatures(disassembly, functions),
    [disassembly, functions],
  );

  const grouped = useMemo(
    () => groupMatchesByCategory(result.matches),
    [result.matches],
  );

  const categories = useMemo(
    () => [...grouped.keys()].sort(),
    [grouped],
  );

  const filtered = useMemo(() => {
    let ms = result.matches;
    if (filterSafe === 'safe') ms = ms.filter((m) => m.signature.safe);
    if (filterSafe === 'notable') ms = ms.filter((m) => !m.signature.safe);
    if (filterCategory !== 'all') ms = ms.filter((m) => m.signature.category === filterCategory);
    if (sortBy === 'score') ms = [...ms].sort((a, b) => b.score - a.score);
    if (sortBy === 'address') ms = [...ms].sort((a, b) => a.functionAddress - b.functionAddress);
    if (sortBy === 'category') ms = [...ms].sort((a, b) => a.signature.category.localeCompare(b.signature.category));
    return ms;
  }, [result.matches, filterSafe, filterCategory, sortBy]);

  const summary = useMemo(() => summarizeScan(result), [result]);

  const isEmpty = disassembly.length === 0;

  return (
    <div className="sig-root">
      {/* Header */}
      <div className="sig-header">
        <div className="sig-header-left">
          <span className="sig-title">🔍 Signature Analysis</span>
          {!isEmpty && (
            <span className="sig-summary">{summary}</span>
          )}
        </div>
      </div>

      {isEmpty ? (
        <div className="sig-empty">
          Disassemble a binary first to run signature analysis.
        </div>
      ) : (
        <>
          {/* Stats bar */}
          <div className="sig-stats-bar">
            <div className="sig-stat">
              <span className="sig-stat-val">{result.scannedFunctions}</span>
              <span className="sig-stat-lbl">Functions Scanned</span>
            </div>
            <div className="sig-stat">
              <span className="sig-stat-val">{result.matches.length}</span>
              <span className="sig-stat-lbl">Patterns Matched</span>
            </div>
            <div className="sig-stat">
              <span className="sig-stat-val">{result.knownFunctionCount}</span>
              <span className="sig-stat-lbl">Functions Identified</span>
            </div>
            <div className="sig-stat sig-stat--safe">
              <span className="sig-stat-val">{result.safePatternCount}</span>
              <span className="sig-stat-lbl">Safe Patterns</span>
            </div>
            <div className="sig-stat sig-stat--note">
              <span className="sig-stat-val">{result.matches.length - result.safePatternCount}</span>
              <span className="sig-stat-lbl">Notable Patterns</span>
            </div>
          </div>

          {/* Category overview */}
          {categories.length > 0 && (
            <div className="sig-category-overview">
              {categories.map((cat) => {
                const count = grouped.get(cat)?.length ?? 0;
                return (
                  <button
                    key={cat}
                    className={`sig-cat-chip${filterCategory === cat ? ' active' : ''}`}
                    style={{
                      borderColor: CATEGORY_COLORS[cat] + '88',
                      color: filterCategory === cat ? CATEGORY_COLORS[cat] : undefined,
                    }}
                    onClick={() => setFilterCategory(filterCategory === cat ? 'all' : cat)}
                  >
                    {CATEGORY_LABELS[cat]}
                    <span className="sig-cat-count">{count}</span>
                  </button>
                );
              })}
              {filterCategory !== 'all' && (
                <button className="sig-cat-chip sig-cat-clear" onClick={() => setFilterCategory('all')}>
                  × Clear
                </button>
              )}
            </div>
          )}

          {/* Filters */}
          <div className="sig-filters">
            <div className="sig-filter-group">
              <span className="sig-filter-label">Show:</span>
              {(['all', 'safe', 'notable'] as const).map((f) => (
                <button
                  key={f}
                  className={`sig-filter-btn${filterSafe === f ? ' active' : ''}`}
                  onClick={() => setFilterSafe(f)}
                >
                  {f === 'all' ? 'All' : f === 'safe' ? '✓ Safe' : '⚠ Notable'}
                </button>
              ))}
            </div>
            <div className="sig-filter-group">
              <span className="sig-filter-label">Sort:</span>
              {(['score', 'address', 'category'] as const).map((s) => (
                <button
                  key={s}
                  className={`sig-filter-btn${sortBy === s ? ' active' : ''}`}
                  onClick={() => setSortBy(s)}
                >
                  {s === 'score' ? 'Confidence' : s === 'address' ? 'Address' : 'Category'}
                </button>
              ))}
            </div>
          </div>

          {/* Match list */}
          <div className="sig-match-list">
            {filtered.length === 0 ? (
              <div className="sig-empty">No matches for current filter.</div>
            ) : (
              filtered.map((m, i) => (
                <MatchCard key={`${m.signature.id}-${m.functionAddress}-${i}`} match={m} onNavigate={onAddressSelect} />
              ))
            )}
          </div>
        </>
      )}
    </div>
  );
};

export default SignaturePanel;
