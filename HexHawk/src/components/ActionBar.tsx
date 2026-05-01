import React from 'react';
import type { WorkflowState } from './WorkflowNav';
import type { NavView } from './WorkflowNav';
import { tierAtLeast } from '../utils/tierConfig';
import type { Tier } from '../utils/tierConfig';

interface Action {
  label: string;
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
      { label: 'Inspect File', icon: '🔎', primary: true, onClick: onInspect },
    ];
  } else if (workflowState === 'inspected') {
    actions = [
      { label: 'Disassemble', icon: '⊞', primary: !hasDisassembly, onClick: onDisassemble, disabled: disassemblyLoading },
      { label: 'Build CFG',   icon: '⬡', primary: !hasCfg,         onClick: onBuildCfg },
      { label: 'Scan Strings', icon: '𝕊',                           onClick: onScanStrings },
      { label: 'Run Analysis', icon: '⚡', primary: !hasVerdict,    onClick: onRunAnalysis },
    ];
  } else if (workflowState === 'analyzed') {
    actions = [
      { label: 'Verdict',    icon: '⚖',  primary: true,  onClick: () => onNavigate('verdict') },
      { label: 'Patch',      icon: '🩹', minTier: 'pro', onClick: () => onNavigate('patch') },
      { label: 'Debug',      icon: '⚙',  minTier: 'pro', onClick: () => onNavigate('debugger') },
      { label: 'Export',     icon: '↓',                  onClick: onExport },
      { label: 'Jump to…',   icon: '↗',                  onClick: onJumpTo },
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
            title={locked ? `Requires ${action.minTier?.toUpperCase()}` : action.disabled ? `${action.label}...` : action.label}
          >
            {action.icon && <span className="wf-action-btn-icon">{action.icon}</span>}
            {action.label}
            {isDisabled && !action.disabled && <span className="wf-action-btn-lock">🔒</span>}
          </button>
        );
      })}
    </div>
  );
}
