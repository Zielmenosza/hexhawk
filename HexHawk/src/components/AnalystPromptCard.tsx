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
      <div>
        <div className="analyst-prompt-kicker">Question to ask next</div>
        <h3 id="analyst-prompt-heading">{prompt.question}</h3>
        <p><strong>Why it matters:</strong> {prompt.whyItMatters}</p>
        <p><strong>Suggested action:</strong> {prompt.suggestedAction}</p>
      </div>
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
