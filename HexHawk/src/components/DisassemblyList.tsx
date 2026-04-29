/**
 * DisassemblyList — virtualized instruction list.
 *
 * Replaces the previous `disassembly.map(...)` render in App.tsx which created
 * one DOM node per instruction regardless of scroll position. With useVirtualList,
 * only ~20-30 rows are in the DOM at any time.
 *
 * Row heights:
 *   DISASM_ROW_HEIGHT                          — base instruction row
 *   DISASM_ROW_HEIGHT + DISASM_ANNOTATION_HEIGHT — row with inline annotation
 */
import React, { useCallback, useEffect, useMemo, useRef } from 'react';
import EnhancedInstructionRow from './EnhancedInstructionRow';
import { useVirtualList } from '../utils/useVirtualList';
import type {
  DisassembledInstruction,
  DisassemblyAnalysis,
  SuspiciousPattern,
} from '../App';

// ─── Height constants ─────────────────────────────────────────────────────────
const DISASM_ROW_HEIGHT = 44;        // px for a plain instruction row
const DISASM_ANNOTATION_HEIGHT = 28; // px added when an annotation is present

// ─── Props ────────────────────────────────────────────────────────────────────
interface DisassemblyListProps {
  disassembly: DisassembledInstruction[];
  highlightedDisasmRange: { start: number; end: number } | null;
  disassemblyAnalysis: DisassemblyAnalysis;
  selectedDisasmAddress: number | null;
  annotations: Map<number, string>;
  onSelectInstruction: (address: number) => void;
  onNavigateToFunction: (address: number) => void;
  onShowReferences: (address: number) => void;
  /** True when the backend has more instructions beyond the currently loaded chunk. */
  hasMore?: boolean;
  /** Called when the user scrolls near the end of the loaded instructions. */
  onLoadMore?: () => void;
  /** True while a load-more request is in flight. */
  isLoadingMore?: boolean;
  /** Queue an inverted-jump patch for the instruction at this address. */
  onInvertJump?: (address: number) => void;
  /** Queue a NOP-sled patch: replace `count` bytes at `address` with 0x90. */
  onNopOut?: (address: number, count: number) => void;
  /** Set of instruction addresses that have a pending patch. */
  patchedAddresses?: Set<number>;
}

// ─── Component ───────────────────────────────────────────────────────────────
const DisassemblyList: React.FC<DisassemblyListProps> = ({
  disassembly,
  highlightedDisasmRange,
  disassemblyAnalysis,
  selectedDisasmAddress,
  annotations,
  onSelectInstruction,
  onNavigateToFunction,
  onShowReferences,
  hasMore = false,
  onLoadMore,
  isLoadingMore = false,
  onInvertJump,
  onNopOut,
  patchedAddresses,
}) => {
  // Pre-build Map from address → SuspiciousPattern for O(1) row lookups
  const patternsMap = useMemo<Map<number, SuspiciousPattern>>(() => {
    const m = new Map<number, SuspiciousPattern>();
    disassemblyAnalysis.suspiciousPatterns.forEach((p) => m.set(p.address, p));
    return m;
  }, [disassemblyAnalysis.suspiciousPatterns]);

  // Item height function: rows with annotations are taller
  const itemHeight = useCallback(
    (index: number) => {
      const ins = disassembly[index];
      return ins && annotations.has(ins.address)
        ? DISASM_ROW_HEIGHT + DISASM_ANNOTATION_HEIGHT
        : DISASM_ROW_HEIGHT;
    },
    [disassembly, annotations]
  );

  const { virtualItems, totalHeight, containerRef, scrollToIndex } = useVirtualList({
    count: disassembly.length,
    itemHeight,
    overscan: 10,
  });

  // Auto-scroll to selected instruction when it changes
  useEffect(() => {
    if (selectedDisasmAddress === null || disassembly.length === 0) return;
    const idx = disassembly.findIndex((ins) => ins.address === selectedDisasmAddress);
    if (idx >= 0) scrollToIndex(idx);
  }, [selectedDisasmAddress, disassembly, scrollToIndex]);

  // Incremental loading: fire onLoadMore once when the user scrolls within
  // 20 rows of the end of the currently-loaded instructions.
  const loadTriggeredRef = useRef(false);
  useEffect(() => {
    if (!hasMore || !onLoadMore || isLoadingMore || virtualItems.length === 0) return;
    const lastVisible = virtualItems[virtualItems.length - 1];
    const nearEnd = lastVisible.index >= disassembly.length - 20;
    if (nearEnd && !loadTriggeredRef.current) {
      loadTriggeredRef.current = true;
      onLoadMore();
    } else if (!nearEnd) {
      loadTriggeredRef.current = false;
    }
  }, [virtualItems, disassembly.length, hasMore, onLoadMore, isLoadingMore]);

  return (
    <div
      ref={containerRef}
      style={{ flex: 1, minHeight: 0, overflowY: 'auto', background: '#0f0f1e' }}
    >
      <div style={{ height: totalHeight, position: 'relative' }}>
        {virtualItems.map(({ index, top, size }) => {
          const ins = disassembly[index];
          if (!ins) return null;

          const isHighlighted = !!(
            highlightedDisasmRange &&
            ins.address >= highlightedDisasmRange.start &&
            ins.address < highlightedDisasmRange.end
          );
          const refStrength = disassemblyAnalysis.referenceStrength.get(ins.address);
          const pattern = patternsMap.get(ins.address);
          const isFuncStart = disassemblyAnalysis.functions.has(ins.address);
          const inLoop = disassemblyAnalysis.loops.some(
            (l) => ins.address >= l.startAddress && ins.address <= l.endAddress
          );
          const annotation = annotations.get(ins.address);

          return (
            <div
              key={ins.address}
              style={{
                position: 'absolute',
                top,
                height: size,
                width: '100%',
                display: 'flex',
                flexDirection: 'column',
              }}
              className="disassembly-instruction"
            >
              <EnhancedInstructionRow
                address={ins.address}
                mnemonic={ins.mnemonic}
                operands={ins.operands}
                refStrength={refStrength}
                pattern={pattern}
                isFunctionStart={isFuncStart}
                isInLoop={inLoop}
                selected={selectedDisasmAddress === ins.address}
                highlighted={isHighlighted}
                isPatched={patchedAddresses?.has(ins.address) ?? false}
                onSelect={() => onSelectInstruction(ins.address)}
                onNavigateToFunction={() => {
                  if (isFuncStart) onNavigateToFunction(ins.address);
                }}
                onShowReferences={() => onShowReferences(ins.address)}
                onInvertJump={onInvertJump ? () => onInvertJump(ins.address) : undefined}
                onNopOut={onNopOut ? (count: number) => onNopOut(ins.address, count) : undefined}
              />
              {annotation && (
                <div
                  style={{
                    marginLeft: '108px',
                    marginTop: '-2px',
                    marginBottom: '2px',
                    fontSize: '0.7rem',
                    color: '#ffd54f',
                    background: 'rgba(255,213,79,0.08)',
                    border: '1px solid rgba(255,213,79,0.3)',
                    borderRadius: '0.25rem',
                    padding: '0.15rem 0.5rem',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.3rem',
                  }}
                >
                  <span>📝</span>
                  <span>{annotation}</span>
                </div>
              )}
            </div>
          );
        })}
        {isLoadingMore && (
          <div
            style={{
              position: 'absolute',
              bottom: 0,
              left: 0,
              right: 0,
              height: DISASM_ROW_HEIGHT,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#888',
              fontSize: '0.75rem',
            }}
          >
            Loading…
          </div>
        )}
      </div>
    </div>
  );
};

export default DisassemblyList;

