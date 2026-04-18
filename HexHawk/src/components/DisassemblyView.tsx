import React from 'react';

interface DisassemblyViewProps {
  instructions: {
    address: number;
    mnemonic: string;
    operands: string;
  }[];
  onInstructionClick?: (address: number, mnemonic: string, operands: string) => void;
  selectedAddress?: number | null;
}

export function DisassemblyView({ 
  instructions, 
  onInstructionClick,
  selectedAddress 
}: DisassemblyViewProps) {
  return (
    <div className="disassembly-view">
      {instructions.map((ins, idx) => (
        <div 
          key={idx} 
          className={`disassembly-line ${selectedAddress === ins.address ? 'selected' : ''}`}
          onClick={() => onInstructionClick?.(ins.address, ins.mnemonic, ins.operands)}
          style={{ cursor: onInstructionClick ? 'pointer' : 'default' }}
        >
          <span className="disassembly-address">0x{ins.address.toString(16).padStart(8, '0')}</span>
          <span className="disassembly-mnemonic">{ins.mnemonic}</span>
          <span className="disassembly-operands">{ins.operands}</span>
        </div>
      ))}
    </div>
  );
}
