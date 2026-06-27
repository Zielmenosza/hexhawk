import type { AiObservation } from '../types/aiObservation';
import type { FunctionIntelligence } from './functionIntelligence';

export interface AetherframeMatch {
  matched: true;
  evidenceBasis: string;
  placeholders: Record<string, string>;
}

export interface AetherframePattern {
  id: string;
  kind: AiObservation['kind'];
  title: string;
  bodyTemplate: string;
  matchFn: (fi: FunctionIntelligence) => AetherframeMatch | null;
  confidence: AiObservation['analysisConfidence'];
}

const VERDICT_LANGUAGE_RE = /\b(classification|classified as|verdict:)\b/i;

function hasImport(fi: FunctionIntelligence, names: string[]): FunctionIntelligence['importCalls'][number] | undefined {
  const wanted = new Set(names.map(name => name.toLowerCase()));
  return fi.importCalls.find(call => wanted.has(call.importName.toLowerCase()));
}

function hasAnyConstant(call: FunctionIntelligence['importCalls'][number] | undefined, names: string[]): boolean {
  if (!call) return false;
  const wanted = new Set(names.map(name => name.toLowerCase()));
  return call.constantAnnotations.some(annotation => wanted.has(annotation.toLowerCase()));
}

function constants(call: FunctionIntelligence['importCalls'][number] | undefined, fallback = 'observed flags'): string {
  if (!call || call.constantAnnotations.length === 0) return fallback;
  return call.constantAnnotations.join(', ');
}

function renderTemplate(template: string, placeholders: Record<string, string>): string {
  return template.replace(/\{([A-Z0-9_]+)\}/g, (_match, key: string) => placeholders[key] ?? 'unknown');
}

function makeObservation(pattern: AetherframePattern, match: AetherframeMatch, fi: FunctionIntelligence): AiObservation | null {
  const body = renderTemplate(pattern.bodyTemplate, match.placeholders);
  const combined = `${pattern.title} ${body} ${match.evidenceBasis}`;
  if (VERDICT_LANGUAGE_RE.test(combined)) return null;

  return {
    id: `aetherframe-${pattern.id.toLowerCase()}-${fi.id}`,
    kind: pattern.kind,
    title: pattern.title,
    body,
    evidenceBasis: match.evidenceBasis,
    source: 'aetherframe-static',
    analysisConfidence: pattern.confidence,
    functionId: fi.id,
    address: fi.address,
    accepted: false,
    dismissed: false,
    generatedAt: new Date().toISOString(),
    gyre_is_sole_verdict_authority: true,
    advisory_only: true,
  };
}

export const AETHERFRAME_PATTERNS: readonly AetherframePattern[] = [
  {
    id: 'SHELLCODE_STAGING',
    kind: 'suspicious-pattern',
    title: 'Executable memory allocation pattern',
    bodyTemplate: 'This function allocates executable memory using {ALLOC_FUNC} with {PROTECT_CONSTANT}. Memory allocated this way can be used to stage and execute arbitrary code. This is a common pattern in shellcode loaders and packers.',
    confidence: 'medium',
    matchFn: (fi) => {
      const alloc = hasImport(fi, ['VirtualAlloc', 'VirtualAllocEx']);
      if (!alloc || !hasAnyConstant(alloc, ['PAGE_EXECUTE_READWRITE'])) return null;
      if (fi.callees.length === 0) return null;
      return {
        matched: true,
        evidenceBasis: `${alloc.importName} call with ${constants(alloc)} and ${fi.callees.length} callee edge(s)`,
        placeholders: { ALLOC_FUNC: alloc.importName, PROTECT_CONSTANT: 'PAGE_EXECUTE_READWRITE' },
      };
    },
  },
  {
    id: 'FILE_READ_OPEN',
    kind: 'likely-purpose',
    title: 'File read operation',
    bodyTemplate: 'This function opens a file for reading using {OPEN_FUNC}. The access flags ({ACCESS_FLAGS}) suggest the file is opened for input only.',
    confidence: 'high',
    matchFn: (fi) => {
      const open = hasImport(fi, ['CreateFileW', 'CreateFileA']);
      if (!open || !(hasAnyConstant(open, ['GENERIC_READ']) || hasAnyConstant(open, ['OPEN_EXISTING']))) return null;
      return {
        matched: true,
        evidenceBasis: `${open.importName} call with ${constants(open)}`,
        placeholders: { OPEN_FUNC: open.importName, ACCESS_FLAGS: constants(open) },
      };
    },
  },
  {
    id: 'FILE_WRITE_CREATE',
    kind: 'likely-purpose',
    title: 'File write or creation operation',
    bodyTemplate: 'This function opens or creates a file for writing using {OPEN_FUNC}. The disposition flags ({DISP_FLAGS}) suggest the file may be created or overwritten.',
    confidence: 'high',
    matchFn: (fi) => {
      const open = hasImport(fi, ['CreateFileW', 'CreateFileA']);
      if (!open || !(hasAnyConstant(open, ['GENERIC_WRITE']) || hasAnyConstant(open, ['CREATE_ALWAYS']))) return null;
      return {
        matched: true,
        evidenceBasis: `${open.importName} call with ${constants(open)}`,
        placeholders: { OPEN_FUNC: open.importName, DISP_FLAGS: constants(open) },
      };
    },
  },
  {
    id: 'LIBRARY_LOAD',
    kind: 'technique-hint',
    title: 'Dynamic library loading',
    bodyTemplate: 'This function loads a library at runtime using {LOAD_FUNC}. Combined with GetProcAddress, dynamic loading is commonly used to resolve imports without them appearing in the static import table.',
    confidence: 'high',
    matchFn: (fi) => {
      const load = hasImport(fi, ['LoadLibraryA', 'LoadLibraryW']);
      if (!load) return null;
      return {
        matched: true,
        evidenceBasis: `${load.importName} import call observed`,
        placeholders: { LOAD_FUNC: load.importName },
      };
    },
  },
  {
    id: 'DYNAMIC_RESOLUTION',
    kind: 'technique-hint',
    title: 'Dynamic API resolution',
    bodyTemplate: 'This function dynamically resolves API addresses using {LOAD_FUNC} and GetProcAddress. This technique hides the real imports from static analysis and is frequently used by malware and packers to evade detection.',
    confidence: 'high',
    matchFn: (fi) => {
      const load = hasImport(fi, ['LoadLibraryA', 'LoadLibraryW']);
      const getProc = hasImport(fi, ['GetProcAddress']);
      if (!load || !getProc) return null;
      return {
        matched: true,
        evidenceBasis: `${load.importName} and ${getProc.importName} import calls observed`,
        placeholders: { LOAD_FUNC: load.importName },
      };
    },
  },
  {
    id: 'PROCESS_MEMORY_WRITE',
    kind: 'suspicious-pattern',
    title: 'Cross-process memory write',
    bodyTemplate: "This function writes to another process's memory using {WRITE_FUNC}. This is a core operation in process injection techniques.",
    confidence: 'high',
    matchFn: (fi) => {
      const write = hasImport(fi, ['NtWriteVirtualMemory', 'WriteProcessMemory']);
      if (!write) return null;
      return {
        matched: true,
        evidenceBasis: `${write.importName} import call observed`,
        placeholders: { WRITE_FUNC: write.importName },
      };
    },
  },
  {
    id: 'SMALL_FUNCTION_NO_IMPORTS',
    kind: 'coverage-gap',
    title: 'Small leaf function',
    bodyTemplate: 'This is a small function ({INSTR_COUNT} instructions) with no API calls or callees. It may be a utility, wrapper, or library stub.',
    confidence: 'low',
    matchFn: (fi) => {
      if (fi.instructionCount >= 10 || fi.importCalls.length !== 0 || fi.callees.length !== 0) return null;
      return {
        matched: true,
        evidenceBasis: `${fi.instructionCount} instructions, no import calls, no callees`,
        placeholders: { INSTR_COUNT: String(fi.instructionCount) },
      };
    },
  },
  {
    id: 'DEEP_CALL_GRAPH',
    kind: 'analyst-suggestion',
    title: 'High fan-out function',
    bodyTemplate: 'This function calls {CALLEE_COUNT} other functions, suggesting it may be a dispatcher, orchestrator, or initialisation routine.',
    confidence: 'medium',
    matchFn: (fi) => {
      if (fi.callees.length <= 8) return null;
      return {
        matched: true,
        evidenceBasis: `${fi.callees.length} callee edges recovered`,
        placeholders: { CALLEE_COUNT: String(fi.callees.length) },
      };
    },
  },
  {
    id: 'NO_CALLERS',
    kind: 'coverage-gap',
    title: 'Unreferenced function',
    bodyTemplate: 'No callers were found for this function. It may be an entry point, called indirectly, dead code, or a function whose callers were not recovered.',
    confidence: 'low',
    matchFn: (fi) => {
      if (fi.callers.length !== 0 || fi.nameSource === 'import-table') return null;
      return {
        matched: true,
        evidenceBasis: 'caller list is empty and function is not an import-table stub',
        placeholders: {},
      };
    },
  },
  {
    id: 'LIBRARY_SIGNATURE_MATCHED',
    kind: 'decompiler-note',
    title: 'Known library function',
    bodyTemplate: 'This function was identified as {FUNC_NAME} from {LIBRARY_NAME} by pattern matching. The name is advisory — pattern matching is not cryptographically verified.',
    confidence: 'medium',
    matchFn: (fi) => {
      if (fi.nameSource !== 'library-signature') return null;
      return {
        matched: true,
        evidenceBasis: `nameSource is library-signature for ${fi.name}`,
        placeholders: { FUNC_NAME: fi.name, LIBRARY_NAME: 'the built-in library signature set' },
      };
    },
  },
] as const;

export function runAetherframePatterns(fi: FunctionIntelligence): AiObservation[] {
  const observations: AiObservation[] = [];
  for (const pattern of AETHERFRAME_PATTERNS) {
    const match = pattern.matchFn(fi);
    if (!match?.matched) continue;
    const observation = makeObservation(pattern, match, fi);
    if (observation) observations.push(observation);
  }
  return observations;
}
