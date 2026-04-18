/**
 * nestBackend — abstraction over the Tauri backend commands used by NEST.
 *
 * Implementations:
 *   TauriNestBackend          — invokes Tauri commands (browser / UI context)
 *   ChildProcessNestBackend   — spawns nest_cli binary (Node.js / CLI context)
 *
 * Usage: create an implementation and pass it to NestSessionRunner.
 */

import type { DisassembledInstruction, FileMetadata } from '../App';
import type { CfgGraph } from './cfgSignalExtractor';

// ── Shared result types ────────────────────────────────────────────────────────

export interface DisassemblyResult {
  arch:         string;
  is_fallback:  boolean;
  instructions: DisassembledInstruction[];
}

// ── Interface ─────────────────────────────────────────────────────────────────

export interface NestBackend {
  /** Disassemble a byte range from the binary file. */
  disassembleRange(
    path:   string,
    offset: number,
    length: number,
  ): Promise<DisassemblyResult>;

  /** Build a control-flow graph for a byte range. */
  buildCfg(
    path:   string,
    offset: number,
    length: number,
  ): Promise<CfgGraph>;

  /** Read file metadata: PE headers, imports, sections, hashes. */
  inspectMetadata(path: string): Promise<FileMetadata>;
}
