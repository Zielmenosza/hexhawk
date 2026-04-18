import React from 'react';
import type {
  DisassemblyAnalysis,
  FunctionMetadata,
  SuspiciousPattern,
  ReferenceStrength,
  LoopInfo,
} from '../App';

interface UnifiedAnalysisPanelProps {
  analysis: DisassemblyAnalysis;
  selectedAddress: number | null;
  selectedFunction: number | null;
  disassembly: { address: number; mnemonic: string; operands: string }[];
  onNavigate?: (address: number) => void;
}

interface FunctionStats {
  funcStart: number;
  funcEnd: number;
  instrCount: number;
  callCount: number;
  refCount: number;
  patternCount: number;
  inLoop: boolean;
  complexity: number;
}

const UnifiedAnalysisPanel: React.FC<UnifiedAnalysisPanelProps> = React.memo(
  ({ analysis, selectedAddress, selectedFunction, disassembly, onNavigate }) => {
    // Calculate stats for selected function
    const getSelectedFunctionStats = (): FunctionStats | null => {
      if (!selectedFunction || !analysis.functions.has(selectedFunction)) {
        return null;
      }

      const func = analysis.functions.get(selectedFunction)!;
      const instrInFunc = disassembly.filter(
        (instr) => instr.address >= func.startAddress && instr.address < func.endAddress
      );

      const patternsInFunc = analysis.suspiciousPatterns.filter(
        (p: SuspiciousPattern) => p.address >= func.startAddress && p.address < func.endAddress
      );

      const loopsInFunc = analysis.loops.some(
        (l: LoopInfo) =>
          (l.startAddress >= func.startAddress && l.startAddress < func.endAddress) ||
          (l.endAddress >= func.startAddress && l.endAddress < func.endAddress)
      );

      return {
        funcStart: func.startAddress,
        funcEnd: func.endAddress,
        instrCount: instrInFunc.length,
        callCount: func.callCount,
        refCount: func.incomingCalls.size,
        patternCount: patternsInFunc.length,
        inLoop: loopsInFunc,
        complexity: func.complexity,
      };
    };

    // Get stats for address at instruction level
    const getAddressStats = () => {
      if (!selectedAddress) return null;

      const instr = disassembly.find((i) => i.address === selectedAddress);
      if (!instr) return null;

      const refStrength = analysis.referenceStrength.get(selectedAddress);
      const pattern = analysis.suspiciousPatterns.find((p: SuspiciousPattern) => p.address === selectedAddress);
      const inLoop = analysis.loops.some(
        (l: LoopInfo) => selectedAddress >= l.startAddress && selectedAddress <= l.endAddress
      );

      // Find containing function
      let containingFunc: FunctionMetadata | null = null;
      for (const func of analysis.functions.values()) {
        if (selectedAddress >= func.startAddress && selectedAddress < func.endAddress) {
          containingFunc = func;
          break;
        }
      }

      return {
        address: selectedAddress,
        mnemonic: instr.mnemonic,
        operands: instr.operands,
        refStrength,
        pattern,
        inLoop,
        containingFunc,
      };
    };

    const funcStats = getSelectedFunctionStats();
    const addrStats = getAddressStats();

    const formatHex = (num: number) => `0x${num.toString(16).toUpperCase().padStart(8, '0')}`;

    const getComplexityColor = (complexity: number) => {
      if (complexity <= 2) return '#4CAF50'; // Green
      if (complexity <= 5) return '#FFC107'; // Amber
      return '#F44336'; // Red
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

    return (
      <div className="unified-analysis-panel">
        <div className="analysis-panel-header">
          <h3>📊 Analysis</h3>
          {selectedFunction && (
            <div className="analysis-context">
              Function @ {formatHex(selectedFunction)}
            </div>
          )}
        </div>

        {/* Function Summary Section */}
        {funcStats && (
          <div className="analysis-section">
            <div className="analysis-section-title">📍 Function Summary</div>
            <div className="analysis-stats">
              <div className="stat-item">
                <span className="stat-label">Range:</span>
                <span className="stat-value">
                  {formatHex(funcStats.funcStart)} → {formatHex(funcStats.funcEnd)}
                </span>
              </div>

              <div className="stat-item">
                <span className="stat-label">Size:</span>
                <span className="stat-value">{funcStats.funcEnd - funcStats.funcStart} bytes</span>
              </div>

              <div className="stat-item">
                <span className="stat-label">Instructions:</span>
                <span className="stat-value">{funcStats.instrCount}</span>
              </div>

              <div className="stat-item">
                <span className="stat-label">Calls:</span>
                <span className="stat-value">{funcStats.callCount}</span>
              </div>

              <div className="stat-item">
                <span className="stat-label">References:</span>
                <span className="stat-value">{funcStats.refCount}</span>
              </div>

              <div className="stat-item">
                <span className="stat-label">Complexity:</span>
                <span
                  className="stat-value stat-complexity"
                  style={{ color: getComplexityColor(funcStats.complexity) }}
                >
                  {funcStats.complexity}/10
                </span>
              </div>

              {funcStats.inLoop && (
                <div className="stat-item stat-warning">
                  <span className="stat-label">📍 In Loop</span>
                </div>
              )}

              {funcStats.patternCount > 0 && (
                <div className="stat-item stat-warning">
                  <span className="stat-label">⚠️ Patterns:</span>
                  <span className="stat-value">{funcStats.patternCount}</span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Address-Level Details */}
        {addrStats && (
          <div className="analysis-section">
            <div className="analysis-section-title">🔍 Instruction Details</div>
            <div className="analysis-stats">
              <div className="stat-item">
                <span className="stat-label">Address:</span>
                <span className="stat-value">{formatHex(addrStats.address)}</span>
              </div>

              <div className="stat-item">
                <span className="stat-label">Instruction:</span>
                <span className="stat-value code">
                  {addrStats.mnemonic} {addrStats.operands}
                </span>
              </div>

              {addrStats.refStrength && (
                <div className="stat-item">
                  <span className="stat-label">Reference Strength:</span>
                  <span
                    className="stat-badge"
                    style={{ backgroundColor: getImportanceColor(addrStats.refStrength.importance) }}
                  >
                    {addrStats.refStrength.importance.toUpperCase()} ({addrStats.refStrength.incomingCount}
                    ↓ / {addrStats.refStrength.outgoingCount}↑)
                  </span>
                </div>
              )}

              {addrStats.inLoop && (
                <div className="stat-item stat-info">
                  <span className="stat-label">🔄 In Loop</span>
                </div>
              )}

              {addrStats.pattern && (
                <div className="stat-item stat-warning">
                  <span className="stat-label">⚠️ Pattern:</span>
                  <span className="stat-value">{addrStats.pattern.type}</span>
                </div>
              )}

              {addrStats.containingFunc && (
                <div className="stat-item">
                  <span className="stat-label">Function:</span>
                  <button
                    className="stat-link"
                    onClick={() => onNavigate?.(addrStats.containingFunc!.startAddress)}
                    title="Jump to function start"
                  >
                    {formatHex(addrStats.containingFunc.startAddress)}
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Suspicious Patterns Section */}
        {analysis.suspiciousPatterns.length > 0 && (
          <div className="analysis-section">
            <div className="analysis-section-title">⚠️ Suspicious Patterns ({analysis.suspiciousPatterns.length})</div>
            <div className="patterns-list">
              {analysis.suspiciousPatterns.slice(0, 5).map((pattern: SuspiciousPattern, idx: number) => (
                <div key={idx} className={`pattern-item pattern-${pattern.severity}`}>
                  <div className="pattern-header">
                    <span className="pattern-type">{pattern.type}</span>
                    <span className="pattern-address">{formatHex(pattern.address)}</span>
                  </div>
                  <div className="pattern-description">{pattern.description}</div>
                </div>
              ))}
              {analysis.suspiciousPatterns.length > 5 && (
                <div className="patterns-more">+{analysis.suspiciousPatterns.length - 5} more patterns</div>
              )}
            </div>
          </div>
        )}

        {/* Loops Section */}
        {analysis.loops.length > 0 && (
          <div className="analysis-section">
            <div className="analysis-section-title">🔄 Loops Detected ({analysis.loops.length})</div>
            <div className="loops-list">
              {analysis.loops.slice(0, 3).map((loop: LoopInfo, idx: number) => (
                <div key={idx} className="loop-item">
                  <div className="loop-header">
                    <span className="loop-range">
                      {formatHex(loop.startAddress)} → {formatHex(loop.endAddress)}
                    </span>
                    <span className="loop-depth">Depth: {loop.depth}</span>
                  </div>
                  <button
                    className="loop-highlight-btn"
                    onClick={() => onNavigate?.(loop.startAddress)}
                    title="Jump to loop start"
                  >
                    Jump to loop
                  </button>
                </div>
              ))}
              {analysis.loops.length > 3 && (
                <div className="loops-more">+{analysis.loops.length - 3} more loops</div>
              )}
            </div>
          </div>
        )}

        {/* Empty State */}
        {!funcStats && !addrStats && (
          <div className="analysis-empty">
            <p>Select an instruction or function to see analysis details</p>
          </div>
        )}
      </div>
    );
  }
);

UnifiedAnalysisPanel.displayName = 'UnifiedAnalysisPanel';

export default UnifiedAnalysisPanel;
