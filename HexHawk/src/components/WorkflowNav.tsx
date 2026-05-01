import React from 'react';
import { tierAtLeast } from '../utils/tierConfig';
import type { Tier } from '../utils/tierConfig';

export type NavView =
  | 'load'
  | 'metadata'
  | 'inspect'
  | 'hex'
  | 'strings'
  | 'disassembly'
  | 'cfg'
  | 'decompile'
  | 'talon'
  | 'verdict'
  | 'signals'
  | 'report'
  | 'history'
  | 'nest'
  | 'activity'
  | 'patch'
  | 'constraint'
  | 'sandbox'
  | 'debugger'
  | 'diff'
  | 'repl'
  | 'agent'
  | 'plugins'
  | 'help'
  | 'about';

export type WorkflowState = 'noFile' | 'fileLoaded' | 'inspected' | 'analyzed';

interface NavItem {
  id: NavView;
  label: string;
  icon: string;
  minTier: Tier;
  requiresState: WorkflowState;
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    label: 'File',
    items: [
      { id: 'load',     label: 'Load Binary', icon: '📂', minTier: 'free',       requiresState: 'noFile' },
      { id: 'metadata', label: 'Metadata',    icon: '🗂', minTier: 'free',       requiresState: 'fileLoaded' },
    ],
  },
  {
    label: 'Analysis',
    items: [
      { id: 'inspect',     label: 'Inspect',     icon: '🔎', minTier: 'free', requiresState: 'fileLoaded' },
      { id: 'hex',         label: 'Hex Viewer',  icon: '⬡',  minTier: 'free', requiresState: 'fileLoaded' },
      { id: 'strings',     label: 'Strings',     icon: '𝕊',  minTier: 'free', requiresState: 'fileLoaded' },
      { id: 'disassembly', label: 'Disassembly', icon: '⊞',  minTier: 'free', requiresState: 'fileLoaded' },
      { id: 'cfg',         label: 'CFG',         icon: '⬡',  minTier: 'free', requiresState: 'fileLoaded' },
      { id: 'decompile',   label: 'Decompile',   icon: '⟨/⟩', minTier: 'free', requiresState: 'inspected' },
      { id: 'talon',       label: 'TALON',       icon: '🧠', minTier: 'pro',  requiresState: 'inspected' },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { id: 'verdict',  label: 'Verdict',          icon: '⚖',  minTier: 'free',         requiresState: 'fileLoaded' },
      { id: 'signals',  label: 'Signals',          icon: '📡',  minTier: 'free',         requiresState: 'fileLoaded' },
      { id: 'report',   label: 'Report',           icon: '📊',  minTier: 'free',         requiresState: 'fileLoaded' },
      { id: 'history',  label: 'Snapshot History', icon: '🕐',  minTier: 'free',         requiresState: 'noFile' },
      { id: 'nest',     label: 'NEST',             icon: '⟳',  minTier: 'enterprise',   requiresState: 'fileLoaded' },
      { id: 'activity', label: 'Activity',         icon: '📋',  minTier: 'pro',          requiresState: 'fileLoaded' },
    ],
  },
  {
    label: 'Actions',
    items: [
      { id: 'patch',      label: 'Patch',      icon: '🩹', minTier: 'pro', requiresState: 'inspected' },
      { id: 'constraint', label: 'Constraint', icon: '⊗',  minTier: 'pro', requiresState: 'inspected' },
      { id: 'sandbox',    label: 'Sandbox',    icon: '⬡',  minTier: 'pro', requiresState: 'fileLoaded' },
      { id: 'debugger',   label: 'Debugger',   icon: '⚙',  minTier: 'pro', requiresState: 'fileLoaded' },
      { id: 'diff',       label: 'Binary Diff', icon: '⊕',  minTier: 'pro', requiresState: 'fileLoaded' },      { id: 'repl',       label: 'REPL',        icon: '>_',  minTier: 'pro', requiresState: 'fileLoaded' },
      { id: 'agent',      label: 'Agent Gate',  icon: '⬢',  minTier: 'pro', requiresState: 'fileLoaded' },
    ],
  },
  {
    label: 'Plugins',
    items: [
      { id: 'plugins', label: 'Plugin Manager', icon: '🪶', minTier: 'free', requiresState: 'fileLoaded' },
    ],
  },
  {
    label: 'Help',
    items: [
      { id: 'help',  label: 'Help',  icon: '?', minTier: 'free', requiresState: 'noFile' },
      { id: 'about', label: 'About', icon: 'ℹ', minTier: 'free', requiresState: 'noFile' },
    ],
  },
];

// State ordering for "available" check
const STATE_ORDER: Record<WorkflowState, number> = {
  noFile: 0,
  fileLoaded: 1,
  inspected: 2,
  analyzed: 3,
};

interface WorkflowNavProps {
  activeView: NavView;
  workflowState: WorkflowState;
  tier: Tier;
  fileName: string;
  onSelect: (view: NavView) => void;
  onLoadFile: () => void;
}

export default function WorkflowNav({
  activeView,
  workflowState,
  tier,
  fileName,
  onSelect,
  onLoadFile,
}: WorkflowNavProps) {
  const currentStateOrder = STATE_ORDER[workflowState];

  return (
    <nav className="wf-nav">
      {/* File indicator */}
      <div className="wf-nav-file-badge" title={fileName || 'No file loaded'}>
        <span className="wf-nav-file-icon">{workflowState === 'noFile' ? '📭' : '📄'}</span>
        <span className="wf-nav-file-name">
          {workflowState === 'noFile' ? 'No file loaded' : (fileName || 'Unknown')}
        </span>
        <button
          type="button"
          className="wf-nav-load-btn"
          onClick={onLoadFile}
          title="Browse for a file"
          data-testid="nav-open-file"
        >
          {workflowState === 'noFile' ? 'Open' : '⇄'}
        </button>
      </div>

      {NAV_GROUPS.map((group) => (
        <div key={group.label} className="wf-nav-group">
          <div className="wf-nav-group-label">{group.label}</div>
          {group.items.map((item) => {
            const tierOk = tierAtLeast(tier, item.minTier);
            const stateOk = currentStateOrder >= STATE_ORDER[item.requiresState];
            const isActive = activeView === item.id;
            const isDisabled = !stateOk;
            const isLocked = !tierOk;

            return (
              <button
                key={item.id}
                type="button"
                data-testid={`nav-${item.id}`}
                className={[
                  'wf-nav-item',
                  isActive ? 'wf-nav-item--active' : '',
                  isDisabled ? 'wf-nav-item--disabled' : '',
                  isLocked ? 'wf-nav-item--locked' : '',
                ].filter(Boolean).join(' ')}
                onClick={() => {
                  if (!isDisabled && !isLocked) onSelect(item.id);
                  else if (isLocked) onSelect(item.id); // still navigate, TierGate handles it
                }}
                title={
                  isLocked
                    ? `Requires ${item.minTier.toUpperCase()} — click to upgrade`
                    : isDisabled
                    ? `Available after: ${item.requiresState}`
                    : item.label
                }
              >
                <span className="wf-nav-item-icon">{item.icon}</span>
                <span className="wf-nav-item-label">{item.label}</span>
                {isLocked && <span className="wf-nav-item-lock">🔒</span>}
                {!isLocked && isDisabled && <span className="wf-nav-item-lock" style={{ opacity: 0.4 }}>○</span>}
              </button>
            );
          })}
        </div>
      ))}
    </nav>
  );
}
