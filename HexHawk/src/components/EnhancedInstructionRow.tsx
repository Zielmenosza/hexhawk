import React from 'react';
import type { ReferenceStrength, SuspiciousPattern } from '../App';

interface EnhancedInstructionRowProps {
  address: number;
  mnemonic: string;
  operands: string;
  refStrength?: ReferenceStrength;
  pattern?: SuspiciousPattern;
  isFunctionStart: boolean;
  isInLoop: boolean;
  selected: boolean;
  highlighted: boolean;
  onSelect: () => void;
  onNavigateToFunction?: (address: number) => void;
  onShowReferences?: () => void;
}

const EnhancedInstructionRow: React.FC<EnhancedInstructionRowProps> = React.memo(
  ({
    address,
    mnemonic,
    operands,
    refStrength,
    pattern,
    isFunctionStart,
    isInLoop,
    selected,
    highlighted,
    onSelect,
    onNavigateToFunction,
    onShowReferences,
  }) => {
    const formatHex = (num: number) => `0x${num.toString(16).toUpperCase().padStart(8, '0')}`;

    const getInstructionType = () => {
      const m = mnemonic.toLowerCase();
      if (m.startsWith('call')) return { type: 'CALL', icon: '📞', color: '#2196F3' };
      if (m === 'jmp') return { type: 'JMP', icon: '🔀', color: '#FFC107' };
      if (m.startsWith('j')) return { type: 'JCOND', icon: '❓', color: '#9C27B0' };
      if (m.startsWith('mov') || m.startsWith('lea')) return { type: 'DATA', icon: '📦', color: '#4CAF50' };
      if (m.startsWith('ret')) return { type: 'RET', icon: '🚪', color: '#F44336' };
      if (m.startsWith('push') || m.startsWith('pop')) return { type: 'STK', icon: '📚', color: '#FF5722' };
      return { type: 'OTHER', icon: '⚙️', color: '#757575' };
    };

    const getImportanceColor = (importance: string) => {
      switch (importance) {
        case 'critical':
          return '#F44336';
        case 'high':
          return '#FFC107';
        case 'medium':
          return '#2196F3';
        case 'low':
          return '#9E9E9E';
        default:
          return '#757575';
      }
    };

    const instrType = getInstructionType();

    return (
      <div
        className={`disassembly-row-enhanced ${selected ? 'selected' : ''} ${highlighted ? 'highlighted' : ''} ${isFunctionStart ? 'function-start' : ''} ${isInLoop ? 'in-loop' : ''}`}
        onClick={onSelect}
      >
        {/* Address column */}
        <div className="instr-address-col">
          {isFunctionStart && <span className="func-start-marker">📍</span>}
          <code className="instr-address">{formatHex(address)}</code>
        </div>

        {/* Reference strength badge */}
        {refStrength && (
          <div
            className="ref-strength-badge"
            style={{
              backgroundColor: getImportanceColor(refStrength.importance),
            }}
            title={`${refStrength.importance}: ${refStrength.incomingCount} in / ${refStrength.outgoingCount} out`}
          >
            <span className="badge-icon">
              {refStrength.importance === 'critical' ? '❗' : refStrength.importance === 'high' ? '⬇️' : refStrength.importance === 'medium' ? '→' : '•'}
            </span>
            <span className="badge-count">{refStrength.incomingCount}</span>
          </div>
        )}

        {/* Instruction type badge */}
        <div className="instr-type-badge" style={{ backgroundColor: instrType.color, color: '#fff' }}>
          <span className="badge-icon">{instrType.icon}</span>
          <span className="badge-type">{instrType.type}</span>
        </div>

        {/* Mnemonic + operands */}
        <div className="instr-code-col">
          <span className="instr-mnemonic">{mnemonic.toUpperCase()}</span>
          <span className="instr-operands">{operands}</span>
        </div>

        {/* Inline pattern warning */}
        {pattern && (
          <div className={`pattern-warning pattern-${pattern.severity}`}>
            <span className="warning-icon">⚠️</span>
            <span className="warning-text">{pattern.type}</span>
          </div>
        )}

        {/* Loop annotation */}
        {isInLoop && <div className="loop-annotation">🔄 loop</div>}

        {/* Quick action buttons */}
        <div className="instr-actions">
          {onShowReferences && refStrength && (
            <button
              className="instr-action-btn instr-action-refs"
              onClick={(e) => {
                e.stopPropagation();
                onShowReferences();
              }}
              title="Show references"
            >
              🔗
            </button>
          )}

          {onNavigateToFunction && isFunctionStart && (
            <button
              className="instr-action-btn instr-action-func"
              onClick={(e) => {
                e.stopPropagation();
                onNavigateToFunction(address);
              }}
              title="Navigate to function"
            >
              📍
            </button>
          )}
        </div>
      </div>
    );
  }
);

EnhancedInstructionRow.displayName = 'EnhancedInstructionRow';

export default EnhancedInstructionRow;
