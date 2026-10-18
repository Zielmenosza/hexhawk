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

// Native first-release scope is independent of entitlements. The browser demo
// retains legacy views, but no license tier enables an excluded native workflow.
const FIRST_RELEASE_VIEWS = new Set<NavView>([
  'load', 'metadata', 'inspect', 'hex', 'strings', 'disassembly', 'cfg',
  'verdict', 'signals', 'report', 'nest', 'activity', 'help', 'about',
]);
export function isFirstReleaseViewAllowed(view: NavView): boolean {
  return FIRST_RELEASE_VIEWS.has(view);
}

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
      { id: 'load', plainLabel: 'Open a file', label: 'Load Binary', icon: '📂', minTier: 'free', requiresState: 'noFile', description: 'Select the file you want to examine. HexHawk keeps it on this computer unless you deliberately use an online feature.' },
      { id: 'metadata', plainLabel: 'File summary', label: 'Metadata', icon: '🗂', minTier: 'free', requiresState: 'fileLoaded', description: 'See what kind of file this is, what system it was built for, its size and fingerprints, and the parts it contains.' },
    ],
  },
  {
    label: 'Understand the file',
    items: [
      { id: 'inspect', plainLabel: 'Start inspection', label: 'Inspect', icon: '🔎', minTier: 'free', requiresState: 'fileLoaded', description: 'Run this first. HexHawk records the file type, size, fingerprints, sections, imports, and exports for the other tools to use.' },
      { id: 'hex', plainLabel: 'View exact file bytes', label: 'Hex Viewer', icon: '⬡', minTier: 'free', requiresState: 'fileLoaded', description: 'See the file exactly as stored on disk, one byte at a time. Useful when you need to check or copy a precise location.' },
      { id: 'strings', plainLabel: 'Find readable text', label: 'Strings', icon: 'S', minTier: 'free', requiresState: 'fileLoaded', description: 'Find words hidden inside the file, including URLs, file paths, Windows Registry entries, program names, and other clues.' },
      { id: 'disassembly', plainLabel: 'Read program instructions', label: 'Disassembly', icon: '⊞', minTier: 'free', requiresState: 'fileLoaded', description: 'Translate the program into processor instructions and show where the code calls or jumps to other locations.' },
      { id: 'cfg', plainLabel: 'See possible code paths', label: 'CFG', icon: '⬡', minTier: 'free', requiresState: 'fileLoaded', description: 'Draw a map of the routes a function can take, making decisions, loops, and exits easier to follow.' },
      { id: 'function-notebook', plainLabel: 'Examine one function', label: 'Function Notebook', icon: 'ƒ', minTier: 'free', requiresState: 'fileLoaded', description: 'Collect everything known about the selected function in one place: what calls it, what it calls, readable code, and supporting evidence.' },
      { id: 'decompile', plainLabel: 'Read code-like text', label: 'Decompile', icon: '⟨/⟩', minTier: 'free', requiresState: 'inspected', description: 'Turn machine instructions into code-like text that is easier to read. It is an estimate, not the program’s original source code.' },
      { id: 'talon', plainLabel: 'Explain selected code', label: 'TALON', icon: '🧠', minTier: 'pro', requiresState: 'inspected', description: 'Explain what the selected instructions or function appear to do and show the evidence behind that explanation.' },
      { id: 'ai-observations', plainLabel: 'Review AI suggestions', label: 'AI Observations', icon: '✦', minTier: 'free', requiresState: 'fileLoaded', description: 'See possible explanations and next steps suggested by AI. These are suggestions for you to check, not HexHawk’s final assessment.' },
    ],
  },
  {
    label: 'Results and records',
    items: [
      { id: 'verdict', plainLabel: 'Overall assessment', label: 'Verdict', icon: '⚖', minTier: 'free', requiresState: 'fileLoaded', description: 'See HexHawk’s main assessment of the file, how certain it is, the evidence it used, and what remains unknown.' },
      { id: 'signals', plainLabel: 'Reasons behind the result', label: 'Signals', icon: '📡', minTier: 'free', requiresState: 'fileLoaded', description: 'See the imports, text, and code patterns that influenced the assessment, including how strong each reason is.' },
      { id: 'report', plainLabel: 'Create a report', label: 'Report', icon: '📊', minTier: 'free', requiresState: 'fileLoaded', description: 'Put the assessment and its supporting evidence into a document you can save, review, or give to someone else.' },
      { id: 'history', plainLabel: 'Open earlier results', label: 'Snapshot History', icon: '🕐', minTier: 'free', requiresState: 'noFile', description: 'Reopen saved results from earlier inspections and compare how the evidence or assessment changed.' },
      { id: 'nest', plainLabel: 'Repeat and organize checks', label: 'NEST', icon: '⟳', minTier: 'enterprise', requiresState: 'fileLoaded', description: 'Repeat evidence checks and organize the findings so gaps and disagreements are easier to spot. This does not decide the final assessment.' },
      { id: 'activity', plainLabel: 'See what happened', label: 'Activity', icon: '📋', minTier: 'pro', requiresState: 'fileLoaded', description: 'Review the tools you ran, the buttons you used, and any warnings or errors from this session.' },
    ],
  },
  {
    label: 'Advanced tools',
    items: [
      { id: 'patch', plainLabel: 'Plan changes to the file', label: 'Patch', icon: '🩹', minTier: 'pro', requiresState: 'inspected', description: 'Prepare exact byte or code changes and review them before anything is applied. Keep an untouched copy of the original file.' },
      { id: 'constraint', plainLabel: 'Work out required inputs', label: 'Constraint', icon: '⊗', minTier: 'pro', requiresState: 'inspected', description: 'Work backward from comparisons and checks to suggest which input values could make the program follow a chosen path.' },
      { id: 'sandbox', plainLabel: 'Run inspection scripts', label: 'Sandbox', icon: '⬡', minTier: 'pro', requiresState: 'fileLoaded', description: 'Run available helper scripts that inspect the file in a controlled way. This is not a safe environment for running suspected malware.' },
      { id: 'debugger', plainLabel: 'Live Debugger', label: 'Debugger', icon: '⚙', minTier: 'pro', requiresState: 'fileLoaded', description: 'Launch the file under HexHawk so you can pause it, step through instructions, and inspect memory, registers, calls, and breakpoints. This executes the file—only use software you trust.' },
      { id: 'diff', plainLabel: 'Compare two files', label: 'Binary Diff', icon: '⊕', minTier: 'pro', requiresState: 'fileLoaded', description: 'Choose another file and see exactly what changed, including bytes, text, functions, code blocks, and the resulting assessment.' },
      { id: 'repl', plainLabel: 'Run advanced commands', label: 'REPL', icon: '>_', minTier: 'pro', requiresState: 'fileLoaded', description: 'Type inspection commands and see their results immediately. Intended for experienced users who need tools beyond the buttons.' },
      { id: 'agent', plainLabel: 'Review AI-proposed notes', label: 'Agent Gate', icon: '⬢', minTier: 'pro', requiresState: 'fileLoaded', description: 'Accept or reject notes suggested by AI. Accepted notes are added to your workspace but cannot change HexHawk’s assessment or its evidence signals.' },
    ],
  },
  {
    label: 'Add-ons',
    items: [
      { id: 'plugins', plainLabel: 'Run add-on tools', label: 'Plugin Manager', icon: '🪶', minTier: 'free', requiresState: 'fileLoaded', description: 'Choose a built-in or approved add-on, run it on the current file, and review the results it returns.' },
    ],
  },
  {
    label: 'Help',
    items: [
      { id: 'help', label: 'Learn how to use HexHawk', icon: '?', minTier: 'free', requiresState: 'noFile', description: 'Open step-by-step instructions, keyboard shortcuts, suggested workflows, and fixes for common problems.' },
      { id: 'strike-api', plainLabel: 'Automate runtime queries', label: 'STRIKE API', icon: '⌘', minTier: 'free', requiresState: 'noFile', description: 'Look up commands programmers can use to ask HexHawk for runtime observations from scripts or other tools.' },
      { id: 'about', label: 'About HexHawk', icon: 'ℹ', minTier: 'free', requiresState: 'noFile', description: 'Learn what HexHawk does, which work stays on your computer, and which results require your own judgment.' },
    ],
  },
]

export interface WorkflowViewPresentation {
  title: string;
  technicalLabel: string;
  description: string;
  icon: string;
}

const NAV_ITEMS_BY_VIEW = new Map<NavView, NavItem>(
  NAV_GROUPS.flatMap((group) => group.items).map((item) => [item.id, item]),
);

export function getWorkflowViewPresentation(view: NavView): WorkflowViewPresentation {
  const item = NAV_ITEMS_BY_VIEW.get(view);
  if (!item) {
    throw new Error(`Missing workflow navigation presentation for view: ${view}`);
  }

  return {
    title: item.plainLabel ?? item.label,
    technicalLabel: item.label,
    description: item.description,
    icon: item.icon,
  };
}

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
  boundedRelease?: boolean;
}

export default function WorkflowNav({
  activeView,
  workflowState,
  tier,
  fileName,
  onSelect,
  onLoadFile,
  agentQueueCount = 0,
  boundedRelease = false,
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
            const scopeExcluded = boundedRelease && !isFirstReleaseViewAllowed(item.id);
            const stateOk = currentStateOrder >= STATE_ORDER[item.requiresState];
            const isActive = activeView === item.id;
            const isDisabled = !stateOk || scopeExcluded;
            const isLocked = !tierOk;

            return (
              <button
                key={item.id}
                type="button"
                disabled={scopeExcluded}
                data-testid={`nav-${item.id}`}
                className={[
                  'wf-nav-item',
                  isActive ? 'wf-nav-item--active' : '',
                  isDisabled ? 'wf-nav-item--disabled' : '',
                  isLocked ? 'wf-nav-item--locked' : '',
                ].filter(Boolean).join(' ')}
                onClick={() => {
                  if (scopeExcluded) return;
                  if (!isDisabled && !isLocked) onSelect(item.id);
                  else if (isLocked) onSelect(item.id); // still navigate, TierGate handles it
                }}
                title={
                  scopeExcluded
                    ? 'Excluded from the bounded Windows first release.'
                    : isLocked
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
