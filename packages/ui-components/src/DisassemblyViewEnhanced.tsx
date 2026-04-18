import React, { useMemo } from 'react';

interface DisassembledInstruction {
  address: number;
  mnemonic: string;
  operands: string;
}

interface DisassemblyInstructionProps {
  instruction: DisassembledInstruction;
  isSelected: boolean;
  isHighlighted: boolean;
  hasIncomingRefs: boolean;
  hasOutgoingRefs: boolean;
  incomingRefCount: number;
  outgoingRefCount: number;
  onSelect: () => void;
  onShowReferences: () => void;
  formatHex: (n: number) => string;
  getInstructionTypeInfo?: (mnem: string) => { type: string; color: string; badge: string };
}

export function DisassemblyInstructionRow({
  instruction,
  isSelected,
  isHighlighted,
  hasIncomingRefs,
  hasOutgoingRefs,
  incomingRefCount,
  outgoingRefCount,
  onSelect,
  onShowReferences,
  formatHex,
  getInstructionTypeInfo,
}: DisassemblyInstructionProps) {
  const typeInfo = getInstructionTypeInfo?.(instruction.mnemonic) || {
    type: 'OTHER',
    color: '#9d9d9d',
    badge: '·',
  };

  return (
    <div
      className={`disassembly-interactive${isSelected ? ' selected' : ''}${isHighlighted ? ' highlighted' : ''}`}
      onClick={onSelect}
      title={`${formatHex(instruction.address)} - ${instruction.mnemonic} ${instruction.operands}`}
    >
      {/* Address */}
      <div className="disassembly-address" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <span>{formatHex(instruction.address)}</span>
        {(hasIncomingRefs || hasOutgoingRefs) && (
          <button
            type="button"
            className="ref-badge-button"
            onClick={(e) => {
              e.stopPropagation();
              onShowReferences();
            }}
            title={`${incomingRefCount} incoming, ${outgoingRefCount} outgoing references`}
            style={{
              all: 'unset',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '20px',
              height: '20px',
              borderRadius: '50%',
              backgroundColor: 'rgba(255, 182, 0, 0.25)',
              border: '1px solid rgba(255, 182, 0, 0.5)',
              color: '#ffd166',
              fontSize: '0.75rem',
              fontWeight: 'bold',
              cursor: 'pointer',
              transition: 'all 0.15s ease',
            }}
            onMouseEnter={(e) => {
              (e.currentTarget as any).style.backgroundColor = 'rgba(255, 182, 0, 0.4)';
              (e.currentTarget as any).style.borderColor = 'rgba(255, 182, 0, 0.8)';
            }}
            onMouseLeave={(e) => {
              (e.currentTarget as any).style.backgroundColor = 'rgba(255, 182, 0, 0.25)';
              (e.currentTarget as any).style.borderColor = 'rgba(255, 182, 0, 0.5)';
            }}
          >
            {incomingRefCount + outgoingRefCount}
          </button>
        )}
      </div>

      {/* Mnemonic with type badge */}
      <div className="disassembly-mnemonic" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <span style={{ color: typeInfo.color, fontSize: '1.1em' }}>{typeInfo.badge}</span>
        <span>{instruction.mnemonic}</span>
      </div>

      {/* Operands */}
      <div className="disassembly-operands">{instruction.operands}</div>

      {/* Reference indicators on right */}
      {(hasIncomingRefs || hasOutgoingRefs) && (
        <div
          style={{
            display: 'flex',
            gap: '0.3rem',
            fontSize: '0.75rem',
            color: '#ffd166',
          }}
        >
          {hasIncomingRefs && <span title="Has incoming references">⬅</span>}
          {hasOutgoingRefs && <span title="Has outgoing references">➡</span>}
        </div>
      )}
    </div>
  );
}

interface DisassemblyViewEnhancedProps {
  instructions: DisassembledInstruction[];
  selectedAddress: number | null;
  highlightedRange: { start: number; end: number } | null;
  referencesMap?: Map<number, Set<number>>;
  jumpTargetsMap?: Map<number, Set<number>>;
  onSelectInstruction: (address: number) => void;
  onShowReferences?: (address: number) => void;
  getInstructionTypeInfo?: (mnem: string) => { type: string; color: string; badge: string };
  formatHex?: (n: number) => string;
}

export function DisassemblyViewEnhanced({
  instructions,
  selectedAddress,
  highlightedRange,
  referencesMap = new Map(),
  jumpTargetsMap = new Map(),
  onSelectInstruction,
  onShowReferences,
  getInstructionTypeInfo,
  formatHex = (n) => '0x' + n.toString(16).toUpperCase().padStart(8, '0'),
}: DisassemblyViewEnhancedProps) {
  const renderRows = useMemo(() => {
    return instructions.map((instr) => {
      const hasIncomingRefs = referencesMap.has(instr.address);
      const hasOutgoingRefs = jumpTargetsMap.has(instr.address);
      const incomingRefCount = referencesMap.get(instr.address)?.size || 0;
      const outgoingRefCount = jumpTargetsMap.get(instr.address)?.size || 0;

      const isSelected = selectedAddress === instr.address;
      const isHighlighted =
        highlightedRange &&
        instr.address >= highlightedRange.start &&
        instr.address < highlightedRange.end;

      return (
        <DisassemblyInstructionRow
          key={instr.address}
          instruction={instr}
          isSelected={isSelected}
          isHighlighted={isHighlighted}
          hasIncomingRefs={hasIncomingRefs}
          hasOutgoingRefs={hasOutgoingRefs}
          incomingRefCount={incomingRefCount}
          outgoingRefCount={outgoingRefCount}
          onSelect={() => onSelectInstruction(instr.address)}
          onShowReferences={() => onShowReferences?.(instr.address)}
          formatHex={formatHex}
          getInstructionTypeInfo={getInstructionTypeInfo}
        />
      );
    });
  }, [instructions, selectedAddress, highlightedRange, referencesMap, jumpTargetsMap, onSelectInstruction, onShowReferences, getInstructionTypeInfo, formatHex]);

  return (
    <div className="disassembly-view">
      {renderRows}
    </div>
  );
}
