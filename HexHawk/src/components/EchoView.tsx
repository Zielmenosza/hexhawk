/**
 * EchoView — ECHO Fuzzy Signature Recognition UI
 *
 * Enhanced signature display with:
 *   - Fuzzy / wildcard / exact method badges
 *   - Similarity bars (Jaccard + context boost breakdown)
 *   - Context correlation panel (which imports/strings triggered boost)
 *   - Behavioral tag cloud
 *   - Category filter + search
 *
 * Complements SignaturePanel (which uses exact hash matching).
 * ECHO surfaces approximate matches, obfuscated variants, and context-rich results.
 */

import React, { useMemo, useState } from 'react';
import type { FunctionMetadata } from '../App';
import type { DisassembledInstruction } from '../utils/decompilerEngine';
import {
  echoScan,
  groupEchoByCategory,
  ECHO_CATEGORY_LABELS,
  ECHO_CATEGORY_COLORS,
  type EchoCategory,
  type EchoMatch,
  type EchoContext,
  type EchoScanResult,
} from '../utils/echoEngine';

// ── Props ─────────────────────────────────────────────────────────────────────

interface EchoViewProps {
  disassembly:     DisassembledInstruction[];
  functions:       Map<number, FunctionMetadata>;
  imports:         Array<{ name: string; library: string }>;
  strings:         Array<{ text: string }>;
  onAddressSelect: (address: number) => void;
}

// ── Sub-components ────────────────────────────────────────────────────────────

const MethodBadge: React.FC<{ method: EchoMatch['method'] }> = ({ method }) => {
  const styles: Record<string, { label: string; color: string }> = {
    exact:    { label: 'EXACT',    color: '#4caf50' },
    fuzzy:    { label: 'FUZZY',    color: '#2196f3' },
    wildcard: { label: 'WILDCARD', color: '#9c27b0' },
  };
  const { label, color } = styles[method] ?? styles.fuzzy;
  return (
    <span
      className="echo-method-badge"
      style={{ background: color + '22', color, borderColor: color + '55' }}
    >
      {label}
    </span>
  );
};

const SimilarityBar: React.FC<{ score: number; similarity: number; boost: number }> = ({
  score, similarity, boost,
}) => {
  const simPct   = Math.round(similarity * 100);
  const basePct  = score - boost;
  const boostPct = boost;

  const barColor =
    score >= 85 ? '#4caf50' :
    score >= 70 ? '#8bc34a' :
    score >= 55 ? '#ff9800' :
    '#ef5350';

  return (
    <div className="echo-sim-bar-wrap" title={`${simPct}% similarity + ${boostPct}pt context boost = ${score}% final`}>
      <div className="echo-sim-bar">
        <div
          className="echo-sim-fill"
          style={{ width: `${Math.min(100, basePct)}%`, background: barColor }}
        />
        {boostPct > 0 && (
          <div
            className="echo-sim-boost"
            style={{ width: `${boostPct}%`, left: `${Math.min(100, basePct)}%` }}
          />
        )}
      </div>
      <span className="echo-sim-label">{score}%</span>
    </div>
  );
};

const CategoryTag: React.FC<{ category: EchoCategory }> = ({ category }) => {
  const color = ECHO_CATEGORY_COLORS[category];
  return (
    <span
      className="echo-cat-tag"
      style={{ background: color + '1a', color, borderColor: color + '44' }}
    >
      {ECHO_CATEGORY_LABELS[category]}
    </span>
  );
};

const ContextBoostPanel: React.FC<{
  pattern: EchoMatch['pattern'];
  availableImports: string[];
  availableStrings: string[];
}> = ({ pattern, availableImports, availableStrings }) => {
  const { importNames = [], stringFragments = [] } = pattern.contextClues;
  const matchedImports  = importNames.filter(imp =>
    availableImports.some(i => i.toLowerCase() === imp.toLowerCase())
  );
  const matchedStrings  = stringFragments.filter(frag =>
    availableStrings.some(s => s.toLowerCase().includes(frag.toLowerCase()))
  );

  if (matchedImports.length === 0 && matchedStrings.length === 0) return null;

  return (
    <div className="echo-ctx-panel">
      {matchedImports.length > 0 && (
        <div className="echo-ctx-row">
          <span className="echo-ctx-label">imports:</span>
          {matchedImports.map(imp => (
            <span key={imp} className="echo-ctx-chip echo-ctx-chip--import">{imp}</span>
          ))}
        </div>
      )}
      {matchedStrings.length > 0 && (
        <div className="echo-ctx-row">
          <span className="echo-ctx-label">strings:</span>
          {matchedStrings.map(frag => (
            <span key={frag} className="echo-ctx-chip echo-ctx-chip--string">"{frag}"</span>
          ))}
        </div>
      )}
    </div>
  );
};

interface MatchCardProps {
  match:            EchoMatch;
  availableImports: string[];
  availableStrings: string[];
  onNavigate:       (addr: number) => void;
}

const MatchCard: React.FC<MatchCardProps> = ({
  match, availableImports, availableStrings, onNavigate,
}) => {
  const [expanded, setExpanded] = useState(false);
  const { pattern, functionAddress, matchOffset, windowSize, score, similarity, contextBoost, method } = match;
  const isUnsafe = !pattern.safe;
  const simPct = Math.round(similarity * 100);

  return (
    <div className={`echo-match-card${isUnsafe ? ' echo-match-card--unsafe' : ''}`}>
      <div className="echo-match-header" onClick={() => setExpanded(x => !x)}>
        <div className="echo-match-title-row">
          <span className="echo-match-name">{pattern.displayName}</span>
          {isUnsafe && <span className="echo-unsafe-badge">⚠ notable</span>}
          <MethodBadge method={method} />
        </div>
        <div className="echo-match-meta">
          <CategoryTag category={pattern.category} />
          <SimilarityBar score={score} similarity={similarity} boost={contextBoost} />
          <span className="echo-match-chevron">{expanded ? '▲' : '▼'}</span>
        </div>
      </div>

      <div className="echo-match-addr-row">
        <span className="echo-addr-label">Function:</span>
        <span
          className="echo-addr clickable"
          onClick={() => onNavigate(functionAddress)}
          title="Navigate to function"
        >
          0x{functionAddress.toString(16).toUpperCase().padStart(8, '0')}
        </span>
        <span className="echo-match-loc">
          +{matchOffset} instr, {windowSize} matched, {simPct}% similar
        </span>
        {contextBoost > 0 && (
          <span className="echo-boost-badge" title="Context evidence boosted score">
            +{contextBoost} ctx
          </span>
        )}
      </div>

      {expanded && (
        <div className="echo-match-detail">
          <div className="echo-match-desc">{pattern.description}</div>
          {pattern.behaviors.length > 0 && (
            <div className="echo-match-tags">
              {pattern.behaviors.map(b => (
                <span key={b} className="echo-behavior-tag">{b}</span>
              ))}
            </div>
          )}
          <ContextBoostPanel
            pattern={pattern}
            availableImports={availableImports}
            availableStrings={availableStrings}
          />
        </div>
      )}
    </div>
  );
};

// ── Stats bar ─────────────────────────────────────────────────────────────────

const StatsBar: React.FC<{ result: EchoScanResult }> = ({ result }) => (
  <div className="echo-stats">
    <span className="echo-stat">
      <span className="echo-stat-val">{result.matches.length}</span>
      <span className="echo-stat-label">matches</span>
    </span>
    <span className="echo-stat-sep" />
    <span className="echo-stat">
      <span className="echo-stat-val">{result.exactMatchCount}</span>
      <span className="echo-stat-label">exact</span>
    </span>
    <span className="echo-stat">
      <span className="echo-stat-val">{result.fuzzyMatchCount}</span>
      <span className="echo-stat-label">fuzzy</span>
    </span>
    <span className="echo-stat">
      <span className="echo-stat-val">{result.wildcardMatchCount}</span>
      <span className="echo-stat-label">wildcard</span>
    </span>
    <span className="echo-stat-sep" />
    <span className="echo-stat">
      <span className="echo-stat-val">{result.contextBoostCount}</span>
      <span className="echo-stat-label">ctx-boosted</span>
    </span>
    <span className="echo-stat-sep" />
    <span className="echo-stat">
      <span className="echo-stat-val">{result.scannedFunctions}</span>
      <span className="echo-stat-label">fns scanned</span>
    </span>
    <span className="echo-stat">
      <span className="echo-stat-val">{result.scannedInstructions}</span>
      <span className="echo-stat-label">instrs</span>
    </span>
  </div>
);

// ── Main component ────────────────────────────────────────────────────────────

const EchoView: React.FC<EchoViewProps> = ({
  disassembly,
  functions,
  imports,
  strings,
  onAddressSelect,
}) => {
  const [filterCat,  setFilterCat]  = useState<EchoCategory | 'all'>('all');
  const [filterText, setFilterText] = useState('');
  const [sortBy,     setSortBy]     = useState<'score' | 'category' | 'function'>('score');
  const [minScore,   setMinScore]   = useState(50);

  const importNames = useMemo(() => imports.map(i => i.name), [imports]);
  const stringTexts = useMemo(() => strings.map(s => s.text), [strings]);

  const ctx: EchoContext = useMemo(() => ({
    imports:         importNames,
    strings:         stringTexts,
    knownSigMatches: [],
  }), [importNames, stringTexts]);

  const result = useMemo<EchoScanResult>(() => {
    if (disassembly.length === 0) {
      return {
        matches: [], scannedFunctions: 0, scannedInstructions: 0,
        fuzzyMatchCount: 0, exactMatchCount: 0, wildcardMatchCount: 0, contextBoostCount: 0,
      };
    }
    try {
      return echoScan(disassembly, ctx, functions);
    } catch {
      return {
        matches: [], scannedFunctions: 0, scannedInstructions: 0,
        fuzzyMatchCount: 0, exactMatchCount: 0, wildcardMatchCount: 0, contextBoostCount: 0,
      };
    }
  }, [disassembly, functions, ctx]);

  const grouped = useMemo(() => groupEchoByCategory(result.matches), [result.matches]);
  const categories = useMemo(() => Array.from(grouped.keys()).sort(), [grouped]);

  const filteredMatches = useMemo(() => {
    let matches = result.matches.filter(m => m.score >= minScore);

    if (filterCat !== 'all') {
      matches = matches.filter(m => m.pattern.category === filterCat);
    }
    if (filterText.trim()) {
      const q = filterText.toLowerCase();
      matches = matches.filter(m =>
        m.pattern.displayName.toLowerCase().includes(q) ||
        m.pattern.description.toLowerCase().includes(q) ||
        m.pattern.name.toLowerCase().includes(q),
      );
    }

    if (sortBy === 'score') {
      matches = [...matches].sort((a, b) => b.score - a.score);
    } else if (sortBy === 'category') {
      matches = [...matches].sort((a, b) =>
        a.pattern.category.localeCompare(b.pattern.category) || b.score - a.score
      );
    } else {
      matches = [...matches].sort((a, b) =>
        a.functionAddress - b.functionAddress || b.score - a.score
      );
    }

    return matches;
  }, [result.matches, filterCat, filterText, sortBy, minScore]);

  // Category distribution for the tag cloud
  const catCounts = useMemo(() => {
    const counts = new Map<EchoCategory, number>();
    for (const m of result.matches) {
      counts.set(m.pattern.category, (counts.get(m.pattern.category) ?? 0) + 1);
    }
    return counts;
  }, [result.matches]);

  if (disassembly.length === 0) {
    return (
      <div className="echo-root">
        <div className="echo-splash">
          <div className="echo-splash-title">ECHO</div>
          <div className="echo-splash-sub">Fuzzy pattern recognition + behavioral fingerprinting</div>
          <div className="echo-splash-hint">Disassemble a binary to begin analysis</div>
        </div>
      </div>
    );
  }

  return (
    <div className="echo-root">
      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <div className="echo-header">
        <span className="echo-brand">ECHO</span>
        <span className="echo-brand-sub">fuzzy recognition</span>
        <div className="echo-header-spacer" />
        <StatsBar result={result} />
      </div>

      {/* ── Category tag cloud ───────────────────────────────────────────────── */}
      {categories.length > 0 && (
        <div className="echo-cat-cloud">
          <button
            className={`echo-cat-pill${filterCat === 'all' ? ' echo-cat-pill--active' : ''}`}
            onClick={() => setFilterCat('all')}
          >
            All ({result.matches.length})
          </button>
          {categories.map(cat => {
            const color = ECHO_CATEGORY_COLORS[cat];
            const count = catCounts.get(cat) ?? 0;
            return (
              <button
                key={cat}
                className={`echo-cat-pill${filterCat === cat ? ' echo-cat-pill--active' : ''}`}
                style={filterCat === cat
                  ? { background: color + '33', borderColor: color + '88', color }
                  : { borderColor: color + '44', color }}
                onClick={() => setFilterCat(filterCat === cat ? 'all' : cat)}
              >
                {ECHO_CATEGORY_LABELS[cat]} ({count})
              </button>
            );
          })}
        </div>
      )}

      {/* ── Toolbar ─────────────────────────────────────────────────────────── */}
      <div className="echo-toolbar">
        <input
          className="echo-search"
          value={filterText}
          onChange={e => setFilterText(e.target.value)}
          placeholder="Search patterns…"
          spellCheck={false}
        />
        <label className="echo-toolbar-label">
          Min score
          <input
            type="range"
            className="echo-slider"
            min={30}
            max={90}
            step={5}
            value={minScore}
            onChange={e => setMinScore(Number(e.target.value))}
          />
          <span className="echo-slider-val">{minScore}%</span>
        </label>
        <div className="echo-sort-group">
          <span className="echo-sort-label">Sort:</span>
          {(['score', 'category', 'function'] as const).map(s => (
            <button
              key={s}
              className={`echo-sort-btn${sortBy === s ? ' echo-sort-btn--active' : ''}`}
              onClick={() => setSortBy(s)}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* ── Match list ──────────────────────────────────────────────────────── */}
      <div className="echo-match-list">
        {filteredMatches.length === 0 ? (
          <div className="echo-empty">
            {result.matches.length === 0
              ? 'No fuzzy matches found — try lowering the min score or check a different binary'
              : 'No matches pass the current filter'}
          </div>
        ) : (
          filteredMatches.map((match, i) => (
            <MatchCard
              key={`${match.pattern.id}-${match.functionAddress}-${i}`}
              match={match}
              availableImports={importNames}
              availableStrings={stringTexts}
              onNavigate={onAddressSelect}
            />
          ))
        )}
      </div>
    </div>
  );
};

export default EchoView;
