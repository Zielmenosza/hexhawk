import { describe, expect, it } from 'vitest';
import {
  ANALYST_PROMPTS,
  assertPromptHasNoForbiddenVerdictLanguage,
  getAnalystPrompt,
  selectAnalystPromptTrigger,
} from '../analystPrompts';

describe('analystPrompts', () => {
  it('selects after-inspect when inspection has completed', () => {
    expect(selectAnalystPromptTrigger({ workflowState: 'inspected', activeView: 'metadata', hasDisassembly: false })).toBe('after-inspect');
  });

  it('selects after-disassemble when code is available', () => {
    expect(selectAnalystPromptTrigger({ workflowState: 'analyzed', activeView: 'disassembly', hasDisassembly: true })).toBe('after-disassemble');
  });

  it('selects function-selected prompt in Function details', () => {
    expect(selectAnalystPromptTrigger({ workflowState: 'analyzed', activeView: 'function-notebook', hasDisassembly: true })).toBe('after-function-selected');
  });

  it('prioritizes shellcode staging investigation over generic prompts', () => {
    expect(selectAnalystPromptTrigger({ workflowState: 'analyzed', activeView: 'ai-observations', hasDisassembly: true, hasShellcodePattern: true })).toBe('after-suspicious-pattern');
  });

  it('selects dynamic resolution prompt when available', () => {
    expect(selectAnalystPromptTrigger({ workflowState: 'analyzed', activeView: 'ai-observations', hasDisassembly: true, hasDynamicResolution: true })).toBe('after-dynamic-resolution');
  });

  it('dismissal rotates to the next available prompt', () => {
    expect(selectAnalystPromptTrigger({
      workflowState: 'analyzed',
      activeView: 'function-notebook',
      hasDisassembly: true,
      hasNoCallers: true,
      dismissedTriggers: ['no-callers-found'],
    })).toBe('after-function-selected');
  });

  it('prompts do not contain forbidden verdict language', () => {
    for (const prompt of ANALYST_PROMPTS) {
      expect(assertPromptHasNoForbiddenVerdictLanguage(prompt)).toBe(true);
    }
  });

  it('suggested actions point at UI targets', () => {
    expect(getAnalystPrompt('after-dynamic-resolution')).toMatchObject({
      targetView: 'strings',
      dismissible: true,
    });
  });
});
