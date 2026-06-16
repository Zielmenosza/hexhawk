import type { ConfidenceLevel } from './disassemblyModel';

export type DecompilerConfidence = ConfidenceLevel;

export type DecompilerFallbackMode =
  | 'structured'
  | 'partially-structured'
  | 'block-level-fallback'
  | 'instruction-fallback';

export type DecompilerIrValue =
  | { kind: 'register'; name: string }
  | { kind: 'constant'; value: number; raw: string }
  | { kind: 'memory'; text: string; base?: string; offset?: number }
  | { kind: 'stack-variable-candidate'; base: string; offset: number; name: string }
  | { kind: 'register-variable-candidate'; register: string; name: string }
  | { kind: 'expression'; text: string };

export type DecompilerIrNode =
  | { kind: 'assignment'; address: number; destination: DecompilerIrValue; source: DecompilerIrValue; confidence: DecompilerConfidence }
  | { kind: 'load'; address: number; destination: DecompilerIrValue; source: DecompilerIrValue; confidence: DecompilerConfidence }
  | { kind: 'store'; address: number; destination: DecompilerIrValue; source: DecompilerIrValue; confidence: DecompilerConfidence }
  | { kind: 'arithmetic'; address: number; operator: string; destination: DecompilerIrValue; left: DecompilerIrValue; right: DecompilerIrValue; confidence: DecompilerConfidence }
  | { kind: 'compare'; address: number; left: DecompilerIrValue; right: DecompilerIrValue; operator?: string; confidence: DecompilerConfidence }
  | { kind: 'conditional-branch'; address: number; condition: string; target: number | null; fallthrough?: number; confidence: DecompilerConfidence }
  | { kind: 'call'; address: number; target: number | null; name?: string; args: DecompilerIrValue[]; confidence: DecompilerConfidence; unresolved: boolean }
  | { kind: 'return'; address: number; value?: DecompilerIrValue; confidence: DecompilerConfidence }
  | { kind: 'stack-variable-candidate'; address: number; variable: DecompilerIrValue; confidence: DecompilerConfidence }
  | { kind: 'register-variable-candidate'; address: number; variable: DecompilerIrValue; confidence: DecompilerConfidence }
  | { kind: 'side-effect-note'; address: number; text: string; confidence: DecompilerConfidence }
  | { kind: 'unknown'; address: number; raw: string; warning: string; confidence: 'unknown' };

export type DecompilerMaturitySummary = {
  schema: 'hexhawk.decompiler_maturity.explicit_ir.v1';
  advisoryOnly: true;
  authority: 'talon_decompiler_advisory_not_gyre_verdict';
  liftedInstructionCount: number;
  unknownInstructionCount: number;
  recoveredCallsCount: number;
  recoveredArgsCount: number;
  recoveredVariablesCount: number;
  unresolvedIndirectJumps: number;
  unresolvedCalls: number;
  structuredBlockPercentage: number;
  fallbackMode: DecompilerFallbackMode;
  confidence: DecompilerConfidence;
  warnings: string[];
  proofLimits: string[];
};
