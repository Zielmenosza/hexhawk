import React from 'react';
import type { WorkflowState } from './WorkflowNav';
import type { NavView } from './WorkflowNav';
import { tierAtLeast } from '../utils/tierConfig';
import type { Tier } from '../utils/tierConfig';

interface Action {
  label: string;
  detail: string;
  icon?: string;
  primary?: boolean;
  minTier?: Tier;
  onClick: () => void;
  disabled?: boolean;
}

interface ActionBarProps {
  workflowState: WorkflowState;
  tier: Tier;
  hasDisassembly: boolean;
  hasCfg: boolean;
  hasVerdict: boolean;
  disassemblyLoading?: boolean;
  onInspect: () => void;
  onDisassemble: () => void;
  onBuildCfg: () => void;
  onScanStrings: () => void;
  onRunAnalysis: () => void;
  onNavigate: (view: NavView) => void;
  onExport: () => void;
  onJumpTo: () => void;
}

export default function ActionBar({
  workflowState,
  tier,
  hasDisassembly,
  hasCfg,
  hasVerdict,
  disassemblyLoading,
  onInspect,
  onDisassemble,
  onBuildCfg,
  onScanStrings,
  onRunAnalysis,
  onNavigate,
  onExport,
  onJumpTo,
}: ActionBarProps) {
  const actionTestId = (label: string): string => {
    const normalized = label.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    return `action-${normalized}`;
  };

  let actions: Action[] = [];

  if (workflowState === 'noFile') {
    // No actions — nav shows Load CTA
    return null;
  }

  if (workflowState === 'fileLoaded') {
    actions = [
      { label: 'Inspect File', detail: 'Read safe file facts first: type, hashes, sections, imports, exports, and size.', icon: '🔎', primary: true, onClick: onInspect },
    ];
  } else if (workflowState === 'inspected') {
    actions = [
      { label: 'Disassemble', detail: 'Turn code bytes into instructions so you can follow calls, jumps, and references.', icon: '⊞', primary: !hasDisassembly, onClick: onDisassemble, disabled: disassemblyLoading },
      { label: 'Build CFG', detail: 'Draw the branch map: basic blocks, exits, loops, and decision points.', icon: '⬡', primary: !hasCfg, onClick: onBuildCfg },
      { label: 'Scan Strings', detail: 'Extract readable text such as URLs, paths, registry keys, APIs, and domains.', icon: '𝕊', onClick: onScanStrings },
      { label: 'Run Analysis', detail: 'Run the usual first-pass sequence and open the verdict when evidence is ready.', icon: '⚡', primary: !hasVerdict, onClick: onRunAnalysis },
    ];
  } else if (workflowState === 'analyzed') {
    actions = [
      { label: 'Verdict', detail: 'Open the GYRE classification, confidence, evidence, and uncertainty summary.', icon: '⚖', primary: true, onClick: () => onNavigate('verdict') },
      { label: 'Patch', detail: 'Review queued binary edits. Use cautiously and keep original files safe.', icon: '🩹', minTier: 'pro', onClick: () => onNavigate('patch') },
      { label: 'Debug', detail: 'Open runtime trace/debug evidence when available. Supports analysis; does not own the verdict.', icon: '⚙', minTier: 'pro', onClick: () => onNavigate('debugger') },
      { label: 'Export', detail: 'Save the current evidence snapshot as a reviewable analysis file.', icon: '↓', onClick: onExport },
      { label: 'Jump to…', detail: 'Go directly to an address or offset in the current file.', icon: '↗', onClick: onJumpTo },
    ];
  }

  return (
    <div className="wf-actionbar">
      {actions.map((action) => {
        const locked = action.minTier ? !tierAtLeast(tier, action.minTier) : false;
        const isDisabled = locked || action.disabled;
        return (
          <button
            key={action.label}
            type="button"
            data-testid={actionTestId(action.label)}
            className={[
              'wf-action-btn',
              action.primary ? 'wf-action-btn--primary' : '',
              isDisabled ? 'wf-action-btn--locked' : '',
            ].filter(Boolean).join(' ')}
            onClick={action.onClick}
            disabled={isDisabled}
            title={locked ? `${action.detail} Requires ${action.minTier?.toUpperCase()}.` : action.disabled ? `${action.detail} Working...` : action.detail}
          >
            {action.icon && <span className="wf-action-btn-icon">{action.icon}</span>}
            <span className="wf-action-btn-copy">
              <span className="wf-action-btn-label">{action.label}</span>
              <span className="wf-action-btn-detail">{action.detail}</span>
            </span>
            {isDisabled && !action.disabled && <span className="wf-action-btn-lock">🔒</span>}
          </button>
        );
      })}
    </div>
  );
}
