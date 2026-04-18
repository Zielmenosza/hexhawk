import React, { useMemo, useState } from 'react';
import type { FunctionMetadata } from '../App';

interface FunctionBrowserProps {
  functions: Map<number, FunctionMetadata>;
  selectedFunction: number | null;
  expandedFunctions: Set<number>;
  onFunctionSelect: (address: number) => void;
  onToggle: (address: number) => void;
  onNavigate: (address: number) => void;
  searchQuery?: string;
  onSearchChange?: (query: string) => void;
}

type SortBy = 'address' | 'size' | 'calls' | 'refs' | 'complexity';

const FunctionBrowser: React.FC<FunctionBrowserProps> = React.memo(
  ({
    functions,
    selectedFunction,
    expandedFunctions,
    onFunctionSelect,
    onToggle,
    onNavigate,
    searchQuery = '',
    onSearchChange,
  }) => {
    const [sortBy, setSortBy] = useState<SortBy>('address');
    const [showHotOnly, setShowHotOnly] = useState(false);

    const formatHex = (num: number) => `0x${num.toString(16).toUpperCase().padStart(8, '0')}`;

    const getComplexityColor = (complexity: number) => {
      if (complexity <= 2) return '#4CAF50';
      if (complexity <= 5) return '#FFC107';
      return '#F44336';
    };

    const getComplexityLabel = (complexity: number) => {
      if (complexity <= 2) return 'Simple';
      if (complexity <= 5) return 'Medium';
      return 'Complex';
    };

    // Filter and sort functions
    const filteredAndSorted = useMemo(() => {
      let items = Array.from(functions.values());

      // Filter by search query
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        items = items.filter(
          (func) =>
            formatHex(func.startAddress).toLowerCase().includes(query) ||
            func.size.toString().includes(query) ||
            func.callCount.toString().includes(query)
        );
      }

      // Filter by hot functions
      if (showHotOnly) {
        items = items.filter((func) => func.incomingCalls.size >= 3);
      }

      // Sort
      switch (sortBy) {
        case 'address':
          items.sort((a, b) => a.startAddress - b.startAddress);
          break;
        case 'size':
          items.sort((a, b) => b.size - a.size);
          break;
        case 'calls':
          items.sort((a, b) => b.callCount - a.callCount);
          break;
        case 'refs':
          items.sort((a, b) => b.incomingCalls.size - a.incomingCalls.size);
          break;
        case 'complexity':
          items.sort((a, b) => b.complexity - a.complexity);
          break;
      }

      return items;
    }, [functions, searchQuery, sortBy, showHotOnly]);

    return (
      <div className="function-browser">
        <div className="function-browser-header">
          <h3>📚 Functions ({filteredAndSorted.length})</h3>
          <div className="function-browser-controls">
            {/* Search */}
            <input
              type="text"
              placeholder="Search functions..."
              value={searchQuery}
              onChange={(e) => onSearchChange?.(e.target.value)}
              className="function-search-input"
            />

            {/* Sort selector */}
            <select value={sortBy} onChange={(e) => setSortBy(e.target.value as SortBy)} className="sort-selector">
              <option value="address">Sort: Address</option>
              <option value="size">Sort: Size</option>
              <option value="calls">Sort: Calls</option>
              <option value="refs">Sort: References</option>
              <option value="complexity">Sort: Complexity</option>
            </select>

            {/* Hot functions filter */}
            <label className="filter-checkbox">
              <input type="checkbox" checked={showHotOnly} onChange={(e) => setShowHotOnly(e.target.checked)} />
              Hot Only
            </label>
          </div>
        </div>

        {/* Function list */}
        <div className="function-list">
          {filteredAndSorted.length === 0 ? (
            <div className="function-list-empty">No functions found</div>
          ) : (
            filteredAndSorted.map((func) => {
              const isSelected = selectedFunction === func.startAddress;
              const isExpanded = expandedFunctions.has(func.startAddress);
              const isHot = func.incomingCalls.size >= 3;

              return (
                <div
                  key={func.startAddress}
                  className={`function-item ${isSelected ? 'selected' : ''} ${isHot ? 'hot' : ''}`}
                  onClick={() => onFunctionSelect(func.startAddress)}
                >
                  {/* Main function row */}
                  <div className="function-item-header">
                    <button
                      className="function-toggle"
                      onClick={(e) => {
                        e.stopPropagation();
                        onToggle(func.startAddress);
                      }}
                      title={isExpanded ? 'Collapse' : 'Expand'}
                    >
                      {isExpanded ? '▼' : '▶'}
                    </button>

                    <div className="function-address">
                      <code>{formatHex(func.startAddress)}</code>
                    </div>

                    <div className="function-metadata">
                      <span className="function-size">{func.size}B</span>
                      <span className="function-calls">📞{func.callCount}</span>
                      <span className="function-refs">🔗{func.incomingCalls.size}</span>
                      <span
                        className="function-complexity-badge"
                        style={{
                          backgroundColor: getComplexityColor(func.complexity),
                          color: '#fff',
                          padding: '2px 6px',
                          borderRadius: '3px',
                          fontSize: '0.8em',
                        }}
                        title={`Complexity: ${func.complexity}/10`}
                      >
                        {getComplexityLabel(func.complexity)}
                      </span>
                    </div>

                    <button
                      className="function-goto-btn"
                      onClick={(e) => {
                        e.stopPropagation();
                        onNavigate(func.startAddress);
                      }}
                      title="Jump to function"
                    >
                      →
                    </button>
                  </div>

                  {/* Expanded details */}
                  {isExpanded && (
                    <div className="function-details">
                      <div className="detail-row">
                        <span className="detail-label">Start:</span>
                        <span className="detail-value">{formatHex(func.startAddress)}</span>
                      </div>
                      <div className="detail-row">
                        <span className="detail-label">End:</span>
                        <span className="detail-value">{formatHex(func.endAddress)}</span>
                      </div>
                      <div className="detail-row">
                        <span className="detail-label">Size:</span>
                        <span className="detail-value">{func.size} bytes</span>
                      </div>
                      <div className="detail-row">
                        <span className="detail-label">Prologue:</span>
                        <span className="detail-value">{func.prologueType || 'Unknown'}</span>
                      </div>
                      <div className="detail-row">
                        <span className="detail-label">Calls Made:</span>
                        <span className="detail-value">{func.callCount}</span>
                      </div>
                      <div className="detail-row">
                        <span className="detail-label">Called By:</span>
                        <span className="detail-value">{func.incomingCalls.size} functions</span>
                      </div>
                      <div className="detail-row">
                        <span className="detail-label">Returns:</span>
                        <span className="detail-value">{func.returnCount}</span>
                      </div>
                      <div className="detail-row">
                        <span className="detail-label">Complexity:</span>
                        <span className="detail-value" style={{ color: getComplexityColor(func.complexity) }}>
                          {func.complexity}/10 {getComplexityLabel(func.complexity)}
                        </span>
                      </div>
                      {func.hasLoops && (
                        <div className="detail-row">
                          <span className="detail-label">🔄 Has Loops</span>
                        </div>
                      )}
                      {func.suspiciousPatterns.length > 0 && (
                        <div className="detail-row">
                          <span className="detail-label">⚠️ Patterns:</span>
                          <span className="detail-value">{func.suspiciousPatterns.join(', ')}</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>

        {/* Summary stats */}
        <div className="function-browser-footer">
          <div className="browser-stats">
            <span>Total Functions: {functions.size}</span>
            <span>
              Hot Functions ({filteredAndSorted.filter((f) => f.incomingCalls.size >= 3).length})
            </span>
            <span>
              Average Complexity:{' '}
              {(Array.from(functions.values()).reduce((sum, f) => sum + f.complexity, 0) / functions.size).toFixed(1)}
            </span>
          </div>
        </div>
      </div>
    );
  }
);

FunctionBrowser.displayName = 'FunctionBrowser';

export default FunctionBrowser;
