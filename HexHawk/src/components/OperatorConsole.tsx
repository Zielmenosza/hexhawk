import React, { useState, useCallback, useRef, useEffect } from 'react';
import {
  generateWorkflow,
  updateStepStatus,
  suggestIntentFromContext,
  classifyIntent,
  type ConsoleWorkflow,
  type ConsoleStep,
  type StepStatus,
  type ExecutionMode,
  type BinaryContext,
  type ConsoleTab,
} from '../utils/operatorConsole';

// ─────────────────────────────────────────────────────────────────────────────
// Props
// ─────────────────────────────────────────────────────────────────────────────

interface OperatorConsoleProps {
  /** Callback to switch the main app tab */
  onNavigateTab: (tab: ConsoleTab) => void;
  /** Binary context from the currently loaded file */
  context: BinaryContext;
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-components
// ─────────────────────────────────────────────────────────────────────────────

const PRIORITY_COLORS: Record<string, string> = {
  critical: '#ff4444',
  high:     '#ff9900',
  medium:   '#00d4ff',
  low:      '#7ec8a4',
};

const STATUS_ICONS: Record<StepStatus, string> = {
  pending: '○',
  active:  '◉',
  done:    '✓',
  skipped: '⊘',
};

interface StepCardProps {
  step: ConsoleStep;
  mode: ExecutionMode;
  isActive: boolean;
  onActivate: () => void;
  onNavigate: (tab: ConsoleTab) => void;
  onMarkDone: () => void;
  onMarkSkipped: () => void;
}

function StepCard({ step, mode, isActive, onActivate, onNavigate, onMarkDone, onMarkSkipped }: StepCardProps) {
  const isDone = step.status === 'done';
  const isSkipped = step.status === 'skipped';
  const isFinished = isDone || isSkipped;

  function handleNavigate() {
    if (step.tab && mode !== 'guide-only') {
      onNavigate(step.tab);
    }
    onActivate();
  }

  return (
    <div
      className={`oc-step${isActive ? ' oc-step--active' : ''}${isFinished ? ' oc-step--finished' : ''}`}
      data-priority={step.priority}
    >
      <div className="oc-step-header">
        <span className="oc-step-num">{STATUS_ICONS[step.status]}</span>
        <span className="oc-step-label">Step {step.stepNumber}</span>
        <span
          className="oc-step-priority"
          style={{ color: PRIORITY_COLORS[step.priority] ?? '#888' }}
        >
          {step.priority}
        </span>
        <span className="oc-step-tool">{step.tool}</span>
      </div>

      <div className="oc-step-action">{step.action}</div>
      <div className="oc-step-explanation">{step.explanation}</div>

      {step.contextHint && (
        <div className="oc-step-context-hint">
          <span className="oc-hint-icon">◈</span> {step.contextHint}
        </div>
      )}

      {!isFinished && (
        <div className="oc-step-actions">
          {step.tab && mode !== 'guide-only' && (
            <button className="oc-btn oc-btn-primary" onClick={handleNavigate}>
              → Open {step.tool}
            </button>
          )}
          {mode === 'guide-only' && (
            <button className="oc-btn oc-btn-ghost" onClick={onActivate}>
              Mark active
            </button>
          )}
          {isActive && (
            <>
              <button className="oc-btn oc-btn-success" onClick={onMarkDone}>✓ Done</button>
              <button className="oc-btn oc-btn-muted" onClick={onMarkSkipped}>⊘ Skip</button>
            </>
          )}
        </div>
      )}

      {isDone && <div className="oc-step-done-badge">Completed</div>}
      {isSkipped && <div className="oc-step-skipped-badge">Skipped</div>}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Intent chip strip
// ─────────────────────────────────────────────────────────────────────────────

const QUICK_INTENTS: Array<{ label: string; prompt: string }> = [
  { label: 'Injection',    prompt: 'analyze process injection' },
  { label: 'Networking',   prompt: 'analyze network C2 activity' },
  { label: 'Persistence',  prompt: 'analyze persistence mechanisms' },
  { label: 'Unpacking',    prompt: 'unpack and find OEP' },
  { label: 'Evasion',      prompt: 'detect anti-analysis techniques' },
  { label: 'Credentials',  prompt: 'credential theft lsass dump' },
  { label: 'Ransomware',   prompt: 'ransomware file encryption' },
  { label: 'General',      prompt: '' },
];

// ─────────────────────────────────────────────────────────────────────────────
// Main component
// ─────────────────────────────────────────────────────────────────────────────

export default function OperatorConsole({ onNavigateTab, context }: OperatorConsoleProps) {
  const [prompt, setPrompt] = useState('');
  const [workflow, setWorkflow] = useState<ConsoleWorkflow | null>(null);
  const [mode, setMode] = useState<ExecutionMode>('guided-navigation');
  const [activeStepId, setActiveStepId] = useState<string | null>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Show context-based suggestion when a binary is loaded
  const suggestedIntent = context.binaryPath
    ? suggestIntentFromContext(context)
    : null;

  // Auto-classify as user types (preview only)
  const previewIntent = prompt.trim().length > 0 ? classifyIntent(prompt) : null;

  const handleGenerate = useCallback((overridePrompt?: string) => {
    const p = overridePrompt ?? prompt;
    const wf = generateWorkflow(p, context);
    setWorkflow(wf);
    setActiveStepId(wf.steps[0]?.id ?? null);
  }, [prompt, context]);

  const handleQuickIntent = useCallback((p: string) => {
    setPrompt(p);
    const wf = generateWorkflow(p, context);
    setWorkflow(wf);
    setActiveStepId(wf.steps[0]?.id ?? null);
  }, [context]);

  const handleStepStatus = useCallback((id: string, status: StepStatus) => {
    setWorkflow(prev => {
      if (!prev) return prev;
      const updated = updateStepStatus(prev.steps, id, status);
      // Auto-advance active step on done/skip
      if (status === 'done' || status === 'skipped') {
        const idx = updated.findIndex(s => s.id === id);
        const next = updated.slice(idx + 1).find(s => s.status === 'pending');
        setActiveStepId(next?.id ?? null);
      }
      return { ...prev, steps: updated };
    });
  }, []);

  const handleNavigate = useCallback((tab: ConsoleTab) => {
    onNavigateTab(tab);
  }, [onNavigateTab]);

  const completedCount = workflow?.steps.filter(s => s.status === 'done').length ?? 0;
  const totalCount = workflow?.steps.length ?? 0;
  const progressPct = totalCount > 0 ? Math.round((completedCount / totalCount) * 100) : 0;

  // Focus input on mount
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  function handleKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleGenerate();
    }
  }

  const noFile = !context.binaryPath;

  return (
    <div className="oc-root">
      {/* ── Header ── */}
      <div className="oc-header">
        <div className="oc-header-title">
          <span className="oc-logo">⬡</span>
          <span>Operator Console</span>
        </div>
        <div className="oc-header-sub">Describe your objective — HexHawk will tell you what to do next</div>
      </div>

      {/* ── Input ── */}
      <div className="oc-input-section">
        {noFile && (
          <div className="oc-no-file-banner">
            No binary loaded. Load a file first for context-aware guidance.
          </div>
        )}

        <div className="oc-input-row">
          <textarea
            ref={inputRef}
            className="oc-input"
            placeholder="e.g. analyze process injection, detect C2 beacons, find ransom note artifacts…"
            value={prompt}
            onChange={e => setPrompt(e.target.value)}
            onKeyDown={handleKeyDown}
            rows={2}
            spellCheck={false}
          />
          <button
            className="oc-generate-btn"
            onClick={() => handleGenerate()}
            disabled={noFile && prompt.trim().length === 0}
            title="Generate workflow (Enter)"
          >
            Generate
          </button>
        </div>

        {/* Preview / suggestion row */}
        <div className="oc-meta-row">
          {previewIntent && (
            <span className="oc-intent-preview">
              Detected: <strong>{previewIntent}</strong>
            </span>
          )}
          {!previewIntent && suggestedIntent && (
            <span className="oc-context-suggestion">
              Binary context suggests: <strong>{suggestedIntent}</strong>
              <button
                className="oc-btn oc-btn-ghost oc-use-suggestion"
                onClick={() => handleQuickIntent(suggestedIntent)}
              >
                Use
              </button>
            </span>
          )}
          <span className="oc-hint">Press Enter to generate</span>
        </div>

        {/* Quick-intent chips */}
        <div className="oc-chips">
          {QUICK_INTENTS.map(qi => (
            <button
              key={qi.label}
              className="oc-chip"
              onClick={() => handleQuickIntent(qi.prompt)}
            >
              {qi.label}
            </button>
          ))}
        </div>
      </div>

      {/* ── Workflow ── */}
      {workflow && (
        <div className="oc-workflow">
          {/* Workflow header */}
          <div className="oc-wf-header">
            <div className="oc-wf-title-row">
              <div>
                <div className="oc-wf-title">{workflow.title}</div>
                <div className="oc-wf-desc">{workflow.description}</div>
              </div>
              <div className="oc-wf-meta">
                <span className="oc-intent-badge">{workflow.intentLabel}</span>
                {workflow.contextApplied && (
                  <span className="oc-context-badge">context-aware</span>
                )}
              </div>
            </div>

            {/* Progress bar */}
            <div className="oc-progress-row">
              <div className="oc-progress-bar">
                <div
                  className="oc-progress-fill"
                  style={{ width: `${progressPct}%` }}
                />
              </div>
              <span className="oc-progress-label">
                {completedCount}/{totalCount} steps
              </span>
            </div>

            {/* Mode selector */}
            <div className="oc-mode-row">
              <span className="oc-mode-label">Mode:</span>
              {(['guide-only', 'guided-navigation', 'auto-run'] as ExecutionMode[]).map(m => (
                <button
                  key={m}
                  className={`oc-mode-btn${mode === m ? ' oc-mode-btn--active' : ''}`}
                  onClick={() => setMode(m)}
                  title={
                    m === 'guide-only'          ? 'Show steps without navigating' :
                    m === 'guided-navigation'   ? 'Click step → switch to that tab' :
                                                  'Auto-run safe read-only operations'
                  }
                >
                  {m === 'guide-only'        ? 'Guide only' :
                   m === 'guided-navigation' ? 'Navigate'   :
                                               'Auto-run'}
                </button>
              ))}
            </div>
          </div>

          {/* Step list */}
          <div className="oc-steps">
            {workflow.steps.map(step => (
              <StepCard
                key={step.id}
                step={step}
                mode={mode}
                isActive={activeStepId === step.id}
                onActivate={() => setActiveStepId(step.id)}
                onNavigate={handleNavigate}
                onMarkDone={() => handleStepStatus(step.id, 'done')}
                onMarkSkipped={() => handleStepStatus(step.id, 'skipped')}
              />
            ))}
          </div>

          {completedCount === totalCount && totalCount > 0 && (
            <div className="oc-complete-banner">
              ✓ All steps complete — check the Report tab for a full summary.
              <button
                className="oc-btn oc-btn-primary"
                style={{ marginLeft: '12px' }}
                onClick={() => onNavigateTab('report')}
              >
                Open Report
              </button>
            </div>
          )}

          <div className="oc-reset-row">
            <button
              className="oc-btn oc-btn-muted"
              onClick={() => { setWorkflow(null); setActiveStepId(null); }}
            >
              ← New objective
            </button>
          </div>
        </div>
      )}

      {/* ── Empty state ── */}
      {!workflow && (
        <div className="oc-empty">
          <div className="oc-empty-icon">⬡</div>
          <div className="oc-empty-title">Ready</div>
          <div className="oc-empty-body">
            Type your objective above or select a quick-intent chip.<br />
            HexHawk will generate a guided step-by-step workflow.
          </div>
          {suggestedIntent && (
            <div className="oc-empty-suggestion">
              Based on the loaded binary, try the <strong>{suggestedIntent}</strong> workflow.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
