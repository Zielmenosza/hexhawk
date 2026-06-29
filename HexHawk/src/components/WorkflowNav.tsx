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
  | 'function-notebook'
  | 'decompile'
  | 'talon'
  | 'ai-observations'
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
  | 'strike-api'
  | 'help'
  | 'about';

export type WorkflowState = 'noFile' | 'fileLoaded' | 'inspected' | 'analyzed';

interface NavItem {
  id: NavView;
  label: string;
  plainLabel?: string;
  description: string;
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
      { id: 'load', plainLabel: 'Open a file', label: 'Load Binary', icon: '📂', minTier: 'free', requiresState: 'noFile', description: 'Choose the file you want HexHawk to inspect. The file stays on this computer unless you use an explicit online feature.' },
      { id: 'metadata', plainLabel: 'File summary', label: 'Metadata', icon: '🗂', minTier: 'free', requiresState: 'fileLoaded', description: 'Shows basic identity: file type, architecture, size, hashes, imports, exports, and sections.' },
    ],
  },
  {
    label: 'Analysis',
    items: [
      { id: 'inspect', plainLabel: 'Inspect file', label: 'Inspect', icon: '🔎', minTier: 'free', requiresState: 'fileLoaded', description: 'First safe step. Reads file facts and hashes so later evidence has a clear source.' },
      { id: 'hex', plainLabel: 'Raw bytes', label: 'Hex Viewer', icon: '⬡', minTier: 'free', requiresState: 'fileLoaded', description: 'Shows the file as bytes. Use this to verify exact offsets and copy byte ranges.' },
      { id: 'strings', plainLabel: 'Readable text', label: 'Strings', icon: '𝕊', minTier: 'free', requiresState: 'fileLoaded', description: 'Finds readable text such as URLs, file paths, registry keys, APIs, domains, and clues.' },
      { id: 'disassembly', plainLabel: 'Code map', label: 'Disassembly', icon: '⊞', minTier: 'free', requiresState: 'fileLoaded', description: 'Turns machine code into instructions and cross-references so you can follow what code may do.' },
      { id: 'cfg', plainLabel: 'Branch map', label: 'CFG', icon: '⬡', minTier: 'free', requiresState: 'fileLoaded', description: 'Draws blocks and branches so loops, exits, and decision points are easier to see.' },
      { id: 'function-notebook', plainLabel: 'Function details', label: 'Function Notebook', icon: 'ƒ', minTier: 'free', requiresState: 'fileLoaded', description: 'Imports, calls, pseudocode, and evidence for the selected function.' },
      { id: 'decompile', plainLabel: 'Pseudocode', label: 'Decompile', icon: '⟨/⟩', minTier: 'free', requiresState: 'inspected', description: 'Shows a best-effort readable summary of code. Treat it as guidance, not recovered source.' },
      { id: 'talon', plainLabel: 'Code reasoning', label: 'TALON', icon: '🧠', minTier: 'pro', requiresState: 'inspected', description: 'Adds structured code reasoning and summaries for inspected instructions and functions.' },
      { id: 'ai-observations', plainLabel: 'AI observations', label: 'AI Observations', icon: '✦', minTier: 'free', requiresState: 'fileLoaded', description: 'Suggestions from AETHERFRAME — not verdicts.' },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { id: 'verdict', plainLabel: 'Verdict', label: 'Verdict', icon: '⚖', minTier: 'free', requiresState: 'fileLoaded', description: 'GYRE classification and confidence. This is the main answer, with evidence and uncertainty shown.' },
      { id: 'signals', plainLabel: 'Why it was flagged', label: 'Signals', icon: '📡', minTier: 'free', requiresState: 'fileLoaded', description: 'Shows patterns that influenced analysis: imports, strings, code behavior, and confidence strength.' },
      { id: 'report', plainLabel: 'Exportable report', label: 'Report', icon: '📊', minTier: 'free', requiresState: 'fileLoaded', description: 'Packages the evidence and verdict into a reviewable report for handoff or records.' },
      { id: 'history', plainLabel: 'Previous snapshots', label: 'Snapshot History', icon: '🕐', minTier: 'free', requiresState: 'noFile', description: 'Shows saved analysis snapshots so you can compare previous work.' },
      { id: 'nest', plainLabel: 'Evidence review loop', label: 'NEST', icon: '⟳', minTier: 'enterprise', requiresState: 'fileLoaded', description: 'Runs repeat evidence passes to organize and converge findings. It does not replace GYRE verdict authority.' },
      { id: 'activity', plainLabel: 'Activity log', label: 'Activity', icon: '📋', minTier: 'pro', requiresState: 'fileLoaded', description: 'Lists what HexHawk did, warnings it hit, and actions you triggered during this session.' },
    ],
  },
  {
    label: 'Actions',
    items: [
      { id: 'patch', plainLabel: 'Patch planning', label: 'Patch', icon: '🩹', minTier: 'pro', requiresState: 'inspected', description: 'Queues reversible binary edits such as NOPs or branch changes. Review before applying.' },
      { id: 'constraint', plainLabel: 'Input/logic solver', label: 'Constraint', icon: '⊗', minTier: 'pro', requiresState: 'inspected', description: 'Looks for comparisons and data-flow constraints that may explain required inputs or checks.' },
      { id: 'sandbox', plainLabel: 'Scripted checks', label: 'Sandbox', icon: '⬡', minTier: 'pro', requiresState: 'fileLoaded', description: 'Runs controlled helper checks/scripts where available. It is not a malware detonation claim.' },
      { id: 'debugger', plainLabel: 'Runtime trace review', label: 'Debugger', icon: '⚙', minTier: 'pro', requiresState: 'fileLoaded', description: 'Reviews debugger/trace evidence when available. Runtime evidence supports analysis; it is not the verdict source.' },
      { id: 'diff', plainLabel: 'Compare files', label: 'Binary Diff', icon: '⊕', minTier: 'pro', requiresState: 'fileLoaded', description: 'Compares two files to find changed bytes, strings, functions, blocks, and verdict differences.' },
      { id: 'repl', plainLabel: 'Interactive commands', label: 'REPL', icon: '>_', minTier: 'pro', requiresState: 'fileLoaded', description: 'Interactive command area for advanced inspection helpers tied to the current file.' },
      { id: 'agent', plainLabel: 'Approve AI suggestions', label: 'Agent Gate', icon: '⬢', minTier: 'pro', requiresState: 'fileLoaded', description: 'Review AI suggestions here. Approving adds analyst notes only; it does not affect GYRE verdicts or analysis signals.' },
    ],
  },
  {
    label: 'Plugins',
    items: [
      { id: 'plugins', plainLabel: 'Extra tools', label: 'Plugin Manager', icon: '🪶', minTier: 'free', requiresState: 'fileLoaded', description: 'Runs built-in or approved plugin tools against the current file and shows their summaries.' },
    ],
  },
  {
    label: 'Help',
    items: [
      { id: 'help', label: 'Help', icon: '?', minTier: 'free', requiresState: 'noFile', description: 'Plain-language instructions, shortcuts, workflow guidance, and troubleshooting.' },
      { id: 'strike-api', label: 'STRIKE API', icon: '⌘', minTier: 'free', requiresState: 'noFile', description: 'Searchable reference for advisory STRIKE scripting/query helpers.' },
      { id: 'about', label: 'About', icon: 'ℹ', minTier: 'free', requiresState: 'noFile', description: 'What HexHawk is, what it does locally, and how its trust model works.' },
    ],
  },
]

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
  agentQueueCount?: number;
}

export default function WorkflowNav({
  activeView,
  workflowState,
  tier,
  fileName,
  onSelect,
  onLoadFile,
  agentQueueCount = 0,
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
                    ? `${item.description} Requires ${item.minTier.toUpperCase()} — click to upgrade.`
                    : isDisabled
                    ? `${item.description} Available after: ${item.requiresState}.`
                    : item.description
                }
              >
                <span className="wf-nav-item-icon">{item.icon}</span>
                <span className="wf-nav-item-copy">
                  <span className="wf-nav-item-label">{item.plainLabel ?? item.label}</span>
                  <span className="wf-nav-item-desc">{item.description}</span>
                </span>
                {isLocked && <span className="wf-nav-item-lock">🔒</span>}
                {!isLocked && isDisabled && <span className="wf-nav-item-lock" style={{ opacity: 0.4 }}>○</span>}
                {item.id === 'agent' && agentQueueCount > 0 && <span className="wf-nav-item-badge" aria-label={`${agentQueueCount} pending agent suggestions`}>{agentQueueCount}</span>}
              </button>
            );
          })}
        </div>
      ))}
    </nav>
  );
}
