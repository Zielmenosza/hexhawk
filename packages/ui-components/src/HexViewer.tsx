import React from 'react';

interface HexViewerProps {
  data: {
    offset: number;
    bytes: number[];
  };
  rowSize?: number;
  highlightedRange?: { start: number; end: number };
  onRangeSelect?: (start: number, end: number) => void;
}

export function HexViewer({ data, rowSize = 16, highlightedRange, onRangeSelect }: HexViewerProps) {
  const rows = [];
  for (let i = 0; i < data.bytes.length; i += rowSize) {
    const slice = data.bytes.slice(i, i + rowSize);
    const offset = data.offset + i;
    const hex = slice.map((byte) => byte.toString(16).padStart(2, '0').toUpperCase()).join(' ');
    const ascii = slice
      .map((byte) => (byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : '.'))
      .join('');

    rows.push({ offset, hex, ascii, endOffset: offset + rowSize });
  }

  return (
    <div className="hex-viewer">
      <div className="hex-row header">
        <span>Offset</span>
        <span>Hex</span>
        <span>ASCII</span>
      </div>
      {rows.map(({ offset, hex, ascii, endOffset }) => {
        const isHighlighted = highlightedRange && offset >= highlightedRange.start && offset < highlightedRange.end;
        return (
          <div 
            className={`hex-row ${isHighlighted ? 'highlighted' : ''}`}
            key={offset}
            onClick={() => {
              if (onRangeSelect) {
                onRangeSelect(offset, Math.min(endOffset, highlightedRange?.end || endOffset));
              }
            }}
            style={{
              cursor: onRangeSelect ? 'pointer' : 'default',
            }}
          >
            <span>0x{offset.toString(16).padStart(8, '0')}</span>
            <span className="hex-bytes">{hex}</span>
            <span className="hex-ascii">{ascii}</span>
          </div>
        );
      })}
    </div>
  );
}
