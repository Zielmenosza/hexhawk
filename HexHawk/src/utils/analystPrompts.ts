export type AnalystPromptTrigger =
  | 'after-inspect'
  | 'after-disassemble'
  | 'after-function-selected'
  | 'after-suspicious-pattern'
  | 'after-dynamic-resolution'
  | 'no-callers-found';

export interface AnalystPrompt {
  trigger: AnalystPromptTrigger;
  question: string;
  whyItMatters: string;
  suggestedAction: string;
  targetView: string;
  dismissible: true;
}

export const ANALYST_PROMPTS: AnalystPrompt[] = [
  {
    trigger: 'after-inspect',
    question: 'What imports does this binary use?',
    whyItMatters: 'The imported functions reveal what system capabilities this binary accesses — file system, network, memory, registry.',
    suggestedAction: "Click 'Analyze code' to see the disassembly and import calls.",
    targetView: 'disassembly',
    dismissible: true,
  },
  {
    trigger: 'after-disassemble',
    question: 'Which function calls VirtualAlloc or LoadLibrary?',
    whyItMatters: 'Functions that allocate executable memory or load libraries at runtime are common starting points for deeper analysis.',
    suggestedAction: 'Open Code map and sort functions by import call count.',
    targetView: 'xrefs',
    dismissible: true,
  },
  {
    trigger: 'after-function-selected',
    question: 'Who calls this function, and with what arguments?',
    whyItMatters: 'Callers reveal the context in which this function is used, which often explains its purpose better than the function itself.',
    suggestedAction: 'Check the Callers section in Function details.',
    targetView: 'function-notebook',
    dismissible: true,
  },
  {
    trigger: 'after-suspicious-pattern',
    question: 'Where does execution go after the memory is allocated?',
    whyItMatters: 'The call target after VirtualAlloc + PAGE_EXECUTE_READWRITE is where shellcode execution typically begins.',
    suggestedAction: 'Check the Callees section for the call after the allocation.',
    targetView: 'function-notebook',
    dismissible: true,
  },
  {
    trigger: 'after-dynamic-resolution',
    question: 'What string arguments are passed to GetProcAddress?',
    whyItMatters: 'The function names passed to GetProcAddress reveal the hidden imports this binary uses at runtime.',
    suggestedAction: 'Search the Strings panel for common API names.',
    targetView: 'strings',
    dismissible: true,
  },
  {
    trigger: 'no-callers-found',
    question: 'Is this function an entry point or called indirectly?',
    whyItMatters: 'Functions with no static callers may be entry points, callback functions, or called through a function pointer.',
    suggestedAction: 'Check if the address appears in any data references.',
    targetView: 'xrefs',
    dismissible: true,
  },
];

export function getAnalystPrompt(trigger: AnalystPromptTrigger): AnalystPrompt {
  return ANALYST_PROMPTS.find(prompt => prompt.trigger === trigger) ?? ANALYST_PROMPTS[0];
}

export function selectAnalystPromptTrigger(context: {
  workflowState: 'noFile' | 'fileLoaded' | 'inspected' | 'analyzed';
  activeView: string;
  hasDisassembly: boolean;
  hasFunctionSelected?: boolean;
  hasShellcodePattern?: boolean;
  hasDynamicResolution?: boolean;
  hasNoCallers?: boolean;
  dismissedTriggers?: AnalystPromptTrigger[];
}): AnalystPromptTrigger | null {
  const candidates: AnalystPromptTrigger[] = [];

  if (context.hasShellcodePattern) candidates.push('after-suspicious-pattern');
  if (context.hasDynamicResolution) candidates.push('after-dynamic-resolution');
  if (context.hasNoCallers) candidates.push('no-callers-found');
  if (context.hasFunctionSelected || context.activeView === 'function-notebook') candidates.push('after-function-selected');
  if (context.hasDisassembly || context.activeView === 'disassembly') candidates.push('after-disassemble');
  if (context.workflowState === 'inspected' || context.workflowState === 'analyzed') candidates.push('after-inspect');

  const dismissed = new Set(context.dismissedTriggers ?? []);
  return candidates.find(trigger => !dismissed.has(trigger)) ?? null;
}

export function assertPromptHasNoForbiddenVerdictLanguage(prompt: AnalystPrompt): boolean {
  const text = `${prompt.question} ${prompt.whyItMatters} ${prompt.suggestedAction}`.toLowerCase();
  return !text.includes('classified as') && !text.includes('verdict:') && !text.includes('confirmed malware');
}
