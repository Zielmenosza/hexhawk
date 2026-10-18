import React from 'react';
import type { AnalystPrompt } from '../utils/analystPrompts';

interface AnalystPromptCardProps {
  prompt: AnalystPrompt | null;
  onDismiss: (trigger: AnalystPrompt['trigger']) => void;
  onNavigate?: (targetView: string) => void;
}

export function AnalystPromptCard({ prompt, onDismiss, onNavigate }: AnalystPromptCardProps) {
  if (!prompt) return null;

  return (
    <aside className="analyst-prompt-card" aria-labelledby="analyst-prompt-heading" data-testid="analyst-prompt-card">
      <details className="analyst-prompt-details">
        <summary>
          <span className="analyst-prompt-kicker">Next review question</span>
          <strong id="analyst-prompt-heading">{prompt.question}</strong>
          <span className="analyst-prompt-expand" aria-hidden="true">Why?</span>
        </summary>
        <div className="analyst-prompt-copy">
          <p><strong>Why it matters:</strong> {prompt.whyItMatters}</p>
          <p><strong>Suggested action:</strong> {prompt.suggestedAction}</p>
        </div>
      </details>
      <div className="analyst-prompt-actions">
        {onNavigate && (
          <button type="button" onClick={() => onNavigate(prompt.targetView)}>
            Go to suggested view
          </button>
        )}
        <button type="button" onClick={() => onDismiss(prompt.trigger)} aria-label={`Dismiss analyst prompt: ${prompt.question}`}>
          Dismiss
        </button>
      </div>
    </aside>
  );
}

export default AnalystPromptCard;
