import React, { useState, useRef, useEffect, useMemo } from 'react';

// Helper: Format number as hex
function formatHex(num: number): string {
  return '0x' + num.toString(16).padStart(8, '0').toUpperCase();
}

// Helper: Copy to clipboard
async function copyToClipboard(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
  } catch (err) {
    console.error('Failed to copy:', err);
  }
}

// Type interpreter for selected bytes
function interpretBytes(bytes: number[], littleEndian: boolean = false): Record<string, any> {
  if (bytes.length === 0) return {};

  const view = new DataView(new Uint8Array(bytes).buffer);
  const swap = littleEndian;

  const result: Record<string, any> = {
    bytes: bytes.map(b => '0x' + b.toString(16).padStart(2, '0').toUpperCase()).join(' '),
    byteCount: bytes.length,
  };

  // u8
  if (bytes.length >= 1) {
    result.u8 = bytes[0];
  }

  // u16
  if (bytes.length >= 2) {
    const val = (bytes[0] << 8) | bytes[1];
    result.u16_be = val;
    const val_le = (bytes[1] << 8) | bytes[0];
    result.u16_le = val_le;
  }

  // u32
  if (bytes.length >= 4) {
    const val = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    result.u32_be = val;
    const val_le = (bytes[3] << 24) | (bytes[2] << 16) | (bytes[1] << 8) | bytes[0];
    result.u32_le = val_le;
  }

  // u64 (as string since JS numbers lose precision)
  if (bytes.length >= 8) {
    const hi = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    const lo = (bytes[4] << 24) | (bytes[5] << 16) | (bytes[6] << 8) | bytes[7];
    result.u64_be_str = `0x${hi.toString(16).padStart(8, '0')}${lo.toString(16).padStart(8, '0')}`;
    
    const hi_le = (bytes[7] << 24) | (bytes[6] << 16) | (bytes[5] << 8) | bytes[4];
    const lo_le = (bytes[3] << 24) | (bytes[2] << 16) | (bytes[1] << 8) | bytes[0];
    result.u64_le_str = `0x${hi_le.toString(16).padStart(8, '0')}${lo_le.toString(16).padStart(8, '0')}`;
  }

  // Float (32-bit)
  if (bytes.length >= 4) {
    const buf = new ArrayBuffer(4);
    const view = new DataView(buf);
    view.setUint8(0, bytes[0]);
    view.setUint8(1, bytes[1]);
    view.setUint8(2, bytes[2]);
    view.setUint8(3, bytes[3]);
    result.float32_be = view.getFloat32(0, false);
    result.float32_le = view.getFloat32(0, true);
  }

  // Double (64-bit)
  if (bytes.length >= 8) {
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    for (let i = 0; i < 8; i++) {
      view.setUint8(i, bytes[i]);
    }
    result.float64_be = view.getFloat64(0, false);
    result.float64_le = view.getFloat64(0, true);
  }

  return result;
}

// Search pattern matching
function findPattern(bytes: number[], pattern: string, patternType: 'hex' | 'ascii' | 'regex'): number[] {
  const matches: number[] = [];

  if (patternType === 'hex') {
    // Parse hex string (e.g., "48 8B 45 F8" or "488B45F8")
    const cleanHex = pattern.replace(/\s+/g, '');
    if (cleanHex.length % 2 !== 0) return matches;
    
    const patternBytes: number[] = [];
    for (let i = 0; i < cleanHex.length; i += 2) {
      patternBytes.push(parseInt(cleanHex.substr(i, 2), 16));
    }

    // Search for pattern
    for (let i = 0; i <= bytes.length - patternBytes.length; i++) {
      let match = true;
      for (let j = 0; j < patternBytes.length; j++) {
        if (bytes[i + j] !== patternBytes[j]) {
          match = false;
          break;
        }
      }
      if (match) matches.push(i);
    }
  } else if (patternType === 'ascii') {
    // Search for ASCII string
    const patternBytes = pattern.split('').map(c => c.charCodeAt(0));
    for (let i = 0; i <= bytes.length - patternBytes.length; i++) {
      let match = true;
      for (let j = 0; j < patternBytes.length; j++) {
        if (bytes[i + j] !== patternBytes[j]) {
          match = false;
          break;
        }
      }
      if (match) matches.push(i);
    }
  } else if (patternType === 'regex') {
    // Search for ASCII matching regex
    try {
      const regex = new RegExp(pattern);
      let ascii = bytes.map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('');
      let match;
      const re = new RegExp(regex.source, 'g');
      while ((match = re.exec(ascii)) !== null) {
        matches.push(match.index);
      }
    } catch {
      // Invalid regex
    }
  }

  return matches;
}

// Copy format helpers
function copyAsHexString(bytes: number[]): string {
  return bytes.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
}

function copyAsCArray(bytes: number[]): string {
  const hex = bytes.map(b => '0x' + b.toString(16).padStart(2, '0').toUpperCase()).join(', ');
  return `const unsigned char data[] = {${hex}};`;
}

function copyAsPythonList(bytes: number[]): string {
  return `[${bytes.join(', ')}]`;
}

function copyAsBase64(bytes: number[]): string {
  const str = String.fromCharCode(...bytes);
  return btoa(str);
}

interface HexViewerEnhancedProps {
  bytes: number[];
  title?: string;
  baseOffset: number;
  selectedIndex: number | null;
  onSelectByte: (index: number) => void;
  onJumpToDisasm?: (address: number) => void;
  highlightedRange?: { start: number; end: number };
  onRangeSelect?: (start: number, end: number) => void;
}

export function HexViewerEnhanced({
  bytes,
  title,
  baseOffset,
  selectedIndex,
  onSelectByte,
  onJumpToDisasm,
  highlightedRange,
  onRangeSelect,
}: HexViewerEnhancedProps) {
  const [searchPattern, setSearchPattern] = useState('');
  const [searchType, setSearchType] = useState<'hex' | 'ascii' | 'regex'>('hex');
  const [searchResults, setSearchResults] = useState<number[]>([]);
  const [searchResultIndex, setSearchResultIndex] = useState(0);
  const [littleEndian, setLittleEndian] = useState(false);
  const scrollContainerRef = useRef<HTMLDivElement>(null);

  // Search when pattern changes
  useEffect(() => {
    if (searchPattern.trim()) {
      const results = findPattern(bytes, searchPattern, searchType);
      setSearchResults(results);
      setSearchResultIndex(0);
      if (results.length > 0) {
        onSelectByte(results[0]);
      }
    } else {
      setSearchResults([]);
    }
  }, [searchPattern, searchType, bytes, onSelectByte]);

  // Get selected bytes
  const getSelectedBytes = (): number[] => {
    if (selectedIndex === null) return [];
    // Try to get 8 bytes for interpretation
    const endIdx = Math.min(selectedIndex + 8, bytes.length);
    return bytes.slice(selectedIndex, endIdx);
  };

  const selectedBytes = getSelectedBytes();
  const typeInfo = interpretBytes(selectedBytes, littleEndian);

  // Render rows
  const rows = [];
  for (let rowStart = 0; rowStart < bytes.length; rowStart += 16) {
    const rowBytes = bytes.slice(rowStart, rowStart + 16);
    const offset = baseOffset + rowStart;
    const rowEndOffset = offset + rowBytes.length;

    const isRowHighlighted = highlightedRange &&
      offset < highlightedRange.end &&
      rowEndOffset > highlightedRange.start;

    const hexCells = rowBytes.map((value, idx) => {
      const index = rowStart + idx;
      const cellOffset = baseOffset + index;
      const isSelected = selectedIndex === index;
      const isCellHighlighted = highlightedRange &&
        cellOffset >= highlightedRange.start &&
        cellOffset < highlightedRange.end;
      const isSearchResult = searchResults.includes(index);

      return (
        <button
          key={index}
          type="button"
          className={`hex-cell${isSelected ? ' selected' : ''}${isCellHighlighted ? ' highlighted' : ''}${isSearchResult ? ' search-result' : ''}`}
          onClick={() => onSelectByte(index)}
          title={`${formatHex(cellOffset)} = 0x${value.toString(16).padStart(2, '0').toUpperCase()}${isSearchResult ? ' (search match)' : ''}`}
        >
          {value.toString(16).padStart(2, '0').toUpperCase()}
        </button>
      );
    });

    const ascii = rowBytes
      .map((value) => (value >= 32 && value <= 126 ? String.fromCharCode(value) : '.'))
      .join('');

    rows.push(
      <div
        key={rowStart}
        className={`hex-row${isRowHighlighted ? ' highlighted' : ''}`}
        data-hex-offset={offset}
      >
        <div className="hex-offset">{offset.toString(16).padStart(8, '0').toUpperCase()}</div>
        <div className="hex-row-cells">{hexCells}</div>
        <div className="hex-ascii">{ascii}</div>
      </div>
    );
  }

  return (
    <div className="panel hex-viewer-enhanced-panel">
      <div className="hex-viewer-bar">
        <div className="hex-viewer-title">{title ?? 'Hex Viewer'}</div>
        <div className="hex-viewer-meta">
          <span>Base offset: {formatHex(baseOffset)}</span>
          <span>Size: {bytes.length} bytes</span>
          {selectedIndex !== null && (
            <span>Selected: {formatHex(baseOffset + selectedIndex)}</span>
          )}
        </div>
      </div>

      {/* Search toolbar */}
      <div className="hex-search-toolbar">
        <div className="search-input-group">
          <input
            type="text"
            placeholder="Search pattern..."
            value={searchPattern}
            onChange={(e) => setSearchPattern(e.target.value)}
            className="search-input"
          />
          <select
            value={searchType}
            onChange={(e) => setSearchType(e.target.value as any)}
            className="search-type-select"
          >
            <option value="hex">Hex</option>
            <option value="ascii">ASCII</option>
            <option value="regex">Regex</option>
          </select>
          {searchResults.length > 0 && (
            <div className="search-results-info">
              Match {searchResultIndex + 1} of {searchResults.length}
            </div>
          )}
        </div>
        {searchResults.length > 0 && (
          <div className="search-nav-buttons">
            <button
              onClick={() => {
                const prevIndex = (searchResultIndex - 1 + searchResults.length) % searchResults.length;
                setSearchResultIndex(prevIndex);
                onSelectByte(searchResults[prevIndex]);
              }}
            >
              ← Prev
            </button>
            <button
              onClick={() => {
                const nextIndex = (searchResultIndex + 1) % searchResults.length;
                setSearchResultIndex(nextIndex);
                onSelectByte(searchResults[nextIndex]);
              }}
            >
              Next →
            </button>
          </div>
        )}
      </div>

      {/* Jump to disasm button */}
      {selectedIndex !== null && onJumpToDisasm && (
        <div className="hex-jump-row">
          <button type="button" onClick={() => onJumpToDisasm(baseOffset + selectedIndex)}>
            Jump to disassembly at {formatHex(baseOffset + selectedIndex)}
          </button>
        </div>
      )}

      {/* Copy buttons */}
      {selectedIndex !== null && (
        <div className="hex-copy-toolbar">
          <button
            onClick={() => copyToClipboard(copyAsHexString([bytes[selectedIndex]]))}
            title="Copy as hex string (e.g., 48 8B)"
          >
            Copy Hex
          </button>
          <button
            onClick={() => copyToClipboard(copyAsHexString(selectedBytes))}
            title={`Copy ${selectedBytes.length} bytes as hex`}
          >
            Copy {selectedBytes.length} Bytes Hex
          </button>
          <button
            onClick={() => copyToClipboard(copyAsCArray([bytes[selectedIndex]]))}
            title="Copy as C array"
          >
            Copy C Array
          </button>
          <button
            onClick={() => copyToClipboard(copyAsPythonList([bytes[selectedIndex]]))}
            title="Copy as Python list"
          >
            Copy Python
          </button>
          <button
            onClick={() => copyToClipboard(copyAsBase64([bytes[selectedIndex]]))}
            title="Copy as Base64"
          >
            Copy Base64
          </button>
        </div>
      )}

      {/* Type interpreter */}
      {selectedIndex !== null && selectedBytes.length > 0 && (
        <div className="hex-type-interpreter">
          <div className="type-interpreter-header">
            <strong>Type Interpreter</strong>
            <label>
              <input
                type="checkbox"
                checked={littleEndian}
                onChange={(e) => setLittleEndian(e.target.checked)}
              />
              Little Endian
            </label>
          </div>
          <div className="type-interpreter-values">
            {typeInfo.byteCount && (
              <div className="type-value">
                <span className="type-label">Bytes:</span>
                <span className="type-data">{typeInfo.bytes}</span>
              </div>
            )}
            {typeInfo.u8 !== undefined && (
              <div className="type-value">
                <span className="type-label">u8:</span>
                <span className="type-data">{typeInfo.u8}</span>
              </div>
            )}
            {typeInfo.u16_be !== undefined && (
              <div className="type-value">
                <span className="type-label">u16 (BE):</span>
                <span className="type-data">{typeInfo.u16_be} / 0x{typeInfo.u16_be.toString(16).padStart(4, '0')}</span>
              </div>
            )}
            {typeInfo.u16_le !== undefined && (
              <div className="type-value">
                <span className="type-label">u16 (LE):</span>
                <span className="type-data">{typeInfo.u16_le} / 0x{typeInfo.u16_le.toString(16).padStart(4, '0')}</span>
              </div>
            )}
            {typeInfo.u32_be !== undefined && (
              <div className="type-value">
                <span className="type-label">u32 (BE):</span>
                <span className="type-data">{typeInfo.u32_be} / 0x{typeInfo.u32_be.toString(16).padStart(8, '0')}</span>
              </div>
            )}
            {typeInfo.u32_le !== undefined && (
              <div className="type-value">
                <span className="type-label">u32 (LE):</span>
                <span className="type-data">{typeInfo.u32_le} / 0x{typeInfo.u32_le.toString(16).padStart(8, '0')}</span>
              </div>
            )}
            {typeInfo.float32_be !== undefined && (
              <div className="type-value">
                <span className="type-label">f32 (BE):</span>
                <span className="type-data">{typeInfo.float32_be.toFixed(6)}</span>
              </div>
            )}
            {typeInfo.float32_le !== undefined && (
              <div className="type-value">
                <span className="type-label">f32 (LE):</span>
                <span className="type-data">{typeInfo.float32_le.toFixed(6)}</span>
              </div>
            )}
            {typeInfo.float64_be !== undefined && (
              <div className="type-value">
                <span className="type-label">f64 (BE):</span>
                <span className="type-data">{typeInfo.float64_be.toFixed(12)}</span>
              </div>
            )}
            {typeInfo.float64_le !== undefined && (
              <div className="type-value">
                <span className="type-label">f64 (LE):</span>
                <span className="type-data">{typeInfo.float64_le.toFixed(12)}</span>
              </div>
            )}
          </div>
        </div>
      )}

      <div className="hex-viewer-scroll" ref={scrollContainerRef}>
        {rows}
      </div>
    </div>
  );
}
