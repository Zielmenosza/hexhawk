import React, { useMemo } from 'react';
import type { DisassemblyAnalysis, FunctionMetadata, LoopInfo } from '../App';
import { categorizePattern, getThreatLevel } from '../utils/patternIntelligence';

interface SmartSuggestionsProps {
  selectedAddress: number | null;
  analysis: DisassemblyAnalysis;
  disassembly: { address: number; mnemonic: string; operands: string }[];
  referencesMap: Map<number, Set<number>>;
  jumpTargetsMap: Map<number, Set<number>>;
  onNavigate: (address: number, description: string) => void;
}

interface Suggestion {
  id: string;
  icon: string;
  label: string;
  description: string;
  targetAddress: number;
  priority: number; // 1=high, 5=low
}

const SmartSuggestions: React.FC<SmartSuggestionsProps> = React.memo(
  ({
    selectedAddress,
    analysis,
    disassembly,
    referencesMap,
    jumpTargetsMap,
    onNavigate,
  }) => {
    const suggestions = useMemo((): Suggestion[] => {
      if (!selectedAddress) return [];

      const suggestions: Suggestion[] = [];
      const instr = disassembly.find((i) => i.address === selectedAddress);
      if (!instr) return [];

      const m = instr.mnemonic.toLowerCase();

      // 1. Find containing function
      let containingFunc: FunctionMetadata | null = null;
      for (const func of analysis.functions.values()) {
        if (selectedAddress >= func.startAddress && selectedAddress < func.endAddress) {
          containingFunc = func;
          break;
        }
      }

      if (containingFunc && containingFunc.startAddress !== selectedAddress) {
        const threatIndicator =
          containingFunc.suspiciousPatterns.length > 2 ? ' ⚠️ (high risk function)' : '';
        suggestions.push({
          id: 'goto-func-start',
          icon: '📍',
          label: 'Go to function start',
          description: `Jump to function entry — shows function boundaries and structure${threatIndicator}`,
          targetAddress: containingFunc.startAddress,
          priority: 1,
        });
      }

      // 2. If this is CALL, show called function
      if (m.includes('call')) {
        const targets = jumpTargetsMap.get(selectedAddress);
        if (targets && targets.size > 0) {
          const target = Array.from(targets)[0] as number;
          const targetFunc = analysis.functions.get(target);
          if (targetFunc) {
            const threat =
              targetFunc.suspiciousPatterns.length > 0
                ? ' 🔴 (contains suspicious code)'
                : '';
            suggestions.push({
              id: 'goto-callee',
              icon: '📞',
              label: 'Follow call (likely next step)',
              description: `Jump into callee at ${formatHex(target)} — understand what this call does${threat}`,
              targetAddress: target,
              priority: 1,
            });
          }
        }
      }

      // 3. If this is JMP or JMP_COND, show target
      if (m === 'jmp' || m.startsWith('j')) {
        const targets = jumpTargetsMap.get(selectedAddress);
        if (targets && targets.size > 0) {
          const target = Array.from(targets)[0];
          suggestions.push({
            id: 'goto-jump-target',
            icon: '🔀',
            label: 'Follow jump',
            description: `Jump to target at ${formatHex(target)}`,
            targetAddress: target,
            priority: 1,
          });
        }
      }

      // 4. Show callers if this address is called
      if (containingFunc) {
        const callers = Array.from(containingFunc.incomingCalls);
        if (callers.length > 0) {
          const caller = callers[0] as number;
          suggestions.push({
            id: 'goto-caller',
            icon: '🔗',
            label: `Show ${callers.length} caller${callers.length > 1 ? 's' : ''}`,
            description: `Jump to caller at ${formatHex(caller)}`,
            targetAddress: caller,
            priority: 2,
          });
        }
      }

      // 5. Highlight loop if in loop
      const inLoop = analysis.loops.find(
        (l: LoopInfo) => selectedAddress >= l.startAddress && selectedAddress <= l.endAddress
      );
      if (inLoop) {
        suggestions.push({
          id: 'highlight-loop',
          icon: '🔄',
          label: 'Highlight loop',
          description: `Show loop boundaries (${formatHex(inLoop.startAddress)} - ${formatHex(inLoop.endAddress)})`,
          targetAddress: inLoop.startAddress,
          priority: 2,
        });
      }

      // 6. Show patterns if any detected
      const pattern = analysis.suspiciousPatterns.find((p) => p.address === selectedAddress);
      if (pattern) {
        const category = categorizePattern(pattern, analysis, disassembly);
        const threatLevel = getThreatLevel(category);
        const threatIcon =
          threatLevel === 'critical'
            ? '🔴'
            : threatLevel === 'high'
              ? '🟠'
              : threatLevel === 'medium'
                ? '🟡'
                : '🟢';
        suggestions.push({
          id: 'view-pattern',
          icon: '⚠️',
          label: `${threatIcon} Show suspicious pattern`,
          description: `${pattern.type}: ${pattern.description} — Threat: ${threatLevel}`,
          targetAddress: selectedAddress,
          priority: 2,
        });
      }

      // 7. Show references to this address
      const refs = referencesMap.get(selectedAddress);
      if (refs && refs.size > 0) {
        const firstRef = Array.from(refs)[0];
        suggestions.push({
          id: 'show-refs',
          icon: '🔍',
          label: `Show ${refs.size} reference${refs.size > 1 ? 's' : ''}`,
          description: `${refs.size} location${refs.size > 1 ? 's' : ''} reference this address`,
          targetAddress: firstRef,
          priority: 3,
        });
      }

      // 8. Show next instruction
      const nextInstrIdx = disassembly.findIndex((i) => i.address === selectedAddress);
      if (nextInstrIdx >= 0 && nextInstrIdx < disassembly.length - 1) {
        const nextInstr = disassembly[nextInstrIdx + 1];
        suggestions.push({
          id: 'next-instr',
          icon: '⬇️',
          label: 'Next instruction',
          description: `Jump to next instruction at ${formatHex(nextInstr.address)}`,
          targetAddress: nextInstr.address,
          priority: 4,
        });
      }

      // 9. Show previous instruction
      if (nextInstrIdx > 0) {
        const prevInstr = disassembly[nextInstrIdx - 1];
        suggestions.push({
          id: 'prev-instr',
          icon: '⬆️',
          label: 'Previous instruction',
          description: `Jump to previous instruction at ${formatHex(prevInstr.address)}`,
          targetAddress: prevInstr.address,
          priority: 5,
        });
      }

      // Sort by priority
      return suggestions.sort((a, b) => a.priority - b.priority).slice(0, 6);
    }, [selectedAddress, analysis, disassembly, referencesMap, jumpTargetsMap]);

    const formatHex = (num: number) => `0x${num.toString(16).toUpperCase().padStart(8, '0')}`;

    if (suggestions.length === 0) {
      return null;
    }

    return (
      <div className="smart-suggestions">
        <div className="suggestions-header">💡 Smart Suggestions</div>
        <div className="suggestions-list">
          {suggestions.map((suggestion) => (
            <button
              key={suggestion.id}
              className="suggestion-btn"
              onClick={() => onNavigate(suggestion.targetAddress, suggestion.label)}
              title={suggestion.description}
            >
              <span className="suggestion-icon">{suggestion.icon}</span>
              <span className="suggestion-label">{suggestion.label}</span>
            </button>
          ))}
        </div>
      </div>
    );
  }
);

SmartSuggestions.displayName = 'SmartSuggestions';

export default SmartSuggestions;
