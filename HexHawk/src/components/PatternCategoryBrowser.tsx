import React, { useMemo, useState } from 'react';
import type { DisassemblyAnalysis } from '../App';
import {
  categorizePattern,
  getThreatLevel,
  PatternCategory,
  ThreatLevel,
} from '../utils/patternIntelligence';

interface PatternCategoryBrowserProps {
  analysis: DisassemblyAnalysis | null;
  disassembly: Array<{ mnemonic: string; operands: string }>;
  onNavigate: (address: number) => void;
}

interface CategoryGroup {
  category: PatternCategory;
  threatLevel: ThreatLevel;
  icon: string;
  label: string;
  patterns: Array<{ address: number; pattern: string }>;
}

const PatternCategoryBrowser = React.memo(
  function PatternCategoryBrowser({
    analysis,
    disassembly,
    onNavigate,
  }: PatternCategoryBrowserProps) {
    const [expandedCategory, setExpandedCategory] = useState<PatternCategory | null>(
      'anti-analysis'
    );

    const categoryGroups = useMemo<CategoryGroup[]>(() => {
      if (!analysis) return [];

      const groups: Record<PatternCategory, CategoryGroup> = {
        'anti-analysis': {
          category: 'anti-analysis',
          threatLevel: 'critical',
          icon: '🔴',
          label: 'Anti-Analysis',
          patterns: [],
        },
        'control-flow-anomaly': {
          category: 'control-flow-anomaly',
          threatLevel: 'high',
          icon: '🟠',
          label: 'Control Flow Anomaly',
          patterns: [],
        },
        'stack-manipulation': {
          category: 'stack-manipulation',
          threatLevel: 'medium',
          icon: '🟡',
          label: 'Stack Manipulation',
          patterns: [],
        },
        'reference-chain': {
          category: 'reference-chain',
          threatLevel: 'medium',
          icon: '🟡',
          label: 'Reference Chain',
          patterns: [],
        },
        'data-obfuscation': {
          category: 'data-obfuscation',
          threatLevel: 'low',
          icon: '🟢',
          label: 'Data Obfuscation',
          patterns: [],
        },
        'performance-critical': {
          category: 'performance-critical',
          threatLevel: 'low',
          icon: '🟢',
          label: 'Performance Optimized',
          patterns: [],
        },
      };

      // Categorize all patterns
      analysis.suspiciousPatterns.forEach((pattern) => {
        const category = categorizePattern(pattern, analysis, disassembly);
        const instr = disassembly[pattern.address] || { mnemonic: 'unknown', operands: '' };
        groups[category].patterns.push({
          address: pattern.address,
          pattern: `${instr.mnemonic} ${instr.operands}`.trim(),
        });
      });

      // Return non-empty groups in threat order
      return Object.values(groups).filter((g) => g.patterns.length > 0);
    }, [analysis, disassembly]);

    if (!analysis || categoryGroups.length === 0) {
      return (
        <div className="pattern-category-browser">
          <div className="pcb-empty">
            <div className="pcb-empty-icon">📊</div>
            <div className="pcb-empty-text">No patterns detected</div>
          </div>
        </div>
      );
    }

    return (
      <div className="pattern-category-browser">
        <div className="pcb-header">Pattern Categories</div>

        <div className="pcb-groups">
          {categoryGroups.map((group) => (
            <div key={group.category} className={`pcb-group pcb-group-${group.threatLevel}`}>
              <button
                className="pcb-group-header"
                onClick={() =>
                  setExpandedCategory(
                    expandedCategory === group.category ? null : group.category
                  )
                }
              >
                <span className="pcb-icon">{group.icon}</span>
                <span className="pcb-label">{group.label}</span>
                <span className="pcb-count">({group.patterns.length})</span>
                <span className={`pcb-toggle ${expandedCategory === group.category ? 'open' : ''}`}>
                  ▼
                </span>
              </button>

              {expandedCategory === group.category && (
                <div className="pcb-patterns">
                  {group.patterns.slice(0, 8).map((p) => (
                    <button
                      key={p.address}
                      className="pcb-pattern-item"
                      onClick={() => onNavigate(p.address)}
                      title={p.pattern}
                    >
                      <span className="pcb-addr">0x{p.address.toString(16).toUpperCase()}</span>
                      <span className="pcb-instr">{p.pattern}</span>
                    </button>
                  ))}
                  {group.patterns.length > 8 && (
                    <div className="pcb-more">
                      +{group.patterns.length - 8} more pattern
                      {group.patterns.length > 9 ? 's' : ''}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>

        <div className="pcb-footer">
          <div className="pcb-total">Total: {analysis.suspiciousPatterns.length} patterns</div>
        </div>
      </div>
    );
  }
);

export default PatternCategoryBrowser;
