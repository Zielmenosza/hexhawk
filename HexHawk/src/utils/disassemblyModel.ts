// Typed disassembly/program model foundation for HexHawk analysis-depth work.
//
// These types are intentionally advisory/evidence-oriented. They do not carry
// malware classification, threat scoring, or GYRE verdict authority.

export type ConfidenceLevel = 'high' | 'medium' | 'low' | 'unknown';

export type InstructionSource = 'backend' | 'synthetic-test' | 'imported-trace' | 'unknown';

export type ProgramArchitecture = 'x86' | 'x86-64' | 'arm' | 'arm64' | 'mips' | 'powerpc' | 'unknown';

export type BackendImport = {
  name?: string | null;
  dll: string;
  thunk_va: number;
  ordinal?: number | null;
};

export type Instruction = {
  address: number;
  mnemonic: string;
  operands: string;
  /** Optional byte length when known. Synthetic and legacy UI rows may omit it. */
  byteLength?: number;
  bytes?: number[];
  symbol?: string;
  source?: InstructionSource;
};

export type XRefKind =
  | 'call'
  | 'jump'
  | 'conditional-jump'
  | 'fallthrough'
  | 'data'
  | 'string'
  | 'import'
  | 'unknown';

export type XRef = {
  kind: XRefKind;
  from: number;
  to: number;
  confidence: ConfidenceLevel;
  evidence: string;
};

export type BasicBlock = {
  id: string;
  startAddress: number;
  endAddress: number;
  instructions: Instruction[];
  predecessors: number[];
  successors: number[];
  confidence: ConfidenceLevel;
  warnings: AnalysisWarning[];
};

export type FunctionStartReason =
  | 'entrypoint'
  | 'symbol'
  | 'export'
  | 'known-call-target'
  | 'call-target'
  | 'prologue'
  | 'prologue-pattern'
  | 'jump-table-target'
  | 'alignment-gap'
  | 'linear-sweep';

export type FunctionStartSource =
  | 'call-target'
  | 'prologue-pattern'
  | 'jump-table-target'
  | 'alignment-gap'
  | 'symbol'
  | 'export'
  | 'entrypoint'
  | 'linear-sweep';

export type FunctionEndReason =
  | 'return'
  | 'tail-jump'
  | 'before-next-function'
  | 'end-of-input'
  | 'unknown';

export type CallingConventionName =
  | 'windows-x64'
  | 'sysv-x64'
  | 'stdcall'
  | 'cdecl'
  | 'fastcall'
  | 'arm64-unknown'
  | 'unknown';

export type CallingConventionInfo = {
  name: CallingConventionName;
  confidence: 'high' | 'medium' | 'low';
  source:
    | 'import-prototype'
    | 'windows-x64-shadow-space'
    | 'sysv-register-use'
    | 'stack-cleanup'
    | 'arm64-limited'
    | 'default-unknown';
  evidence: string[];
};

export type FunctionModel = {
  id: string;
  name: string;
  startAddress: number;
  endAddress: number;
  instructions: Instruction[];
  basicBlocks: BasicBlock[];
  startReasons: FunctionStartReason[];
  startSource: FunctionStartSource;
  endReason: FunctionEndReason;
  confidence: ConfidenceLevel;
  /** Advisory name provenance; never a GYRE verdict input. */
  nameSource?: 'symbol' | 'import-table' | 'library-signature' | 'heuristic' | 'generated';
  /** Advisory ABI/calling-convention metadata; never a GYRE verdict input. */
  callingConvention?: CallingConventionInfo;
  warnings: AnalysisWarning[];
};

export type ImportCall = {
  callAddress: number;
  targetAddress?: number;
  importName?: string;
  moduleName?: string;
  confidence: ConfidenceLevel;
  evidence: string;
};

export type DataReference = {
  from: number;
  to: number;
  access: 'read' | 'write' | 'read-write' | 'unknown';
  confidence: ConfidenceLevel;
  evidence: string;
};

export type StringReference = {
  from: number;
  to: number;
  value?: string;
  confidence: ConfidenceLevel;
  evidence: string;
};

export type JumpTableCandidate = {
  address: number;
  dispatchAddress: number;
  tableAddress?: number;
  targets: number[];
  confidence: ConfidenceLevel;
  evidence: string;
  warnings: AnalysisWarning[];
};

export type FunctionCallGraph = {
  nodes: Array<{
    address: number;
    name: string;
    confidence: ConfidenceLevel;
  }>;
  edges: Array<{
    from: number;
    to: number;
    callsite: number;
    confidence: ConfidenceLevel;
  }>;
};

export type AnalysisWarningKind =
  | 'uncertain-function-start'
  | 'uncertain-function-end'
  | 'indirect-call'
  | 'indirect-jump'
  | 'unresolved-target'
  | 'empty-input'
  | 'non-contiguous-block'
  | 'fallthrough-estimated'
  | 'overlapping-candidate'
  | 'architecture-limit'
  | 'library-signature-match';

export type AnalysisWarning = {
  kind: AnalysisWarningKind;
  address?: number;
  message: string;
  severity: 'info' | 'warning';
};

export type ProgramAnalysis = {
  schema: 'hexhawk.disassembly_program.v1';
  advisoryOnly: true;
  authority: 'analysis_evidence_not_gyre_verdict';
  arch: ProgramArchitecture;
  instructions: Instruction[];
  functions: FunctionModel[];
  basicBlocks: BasicBlock[];
  xrefs: XRef[];
  importCalls: ImportCall[];
  dataReferences: DataReference[];
  stringReferences: StringReference[];
  jumpTableCandidates: JumpTableCandidate[];
  callGraph: FunctionCallGraph;
  warnings: AnalysisWarning[];
};
