/**
 * engines/tauriBackend.ts
 *
 * Wraps all Tauri `invoke()` calls so they can be imported and called from
 * anywhere — including outside the React component tree.
 *
 * This is the ONLY file in the project that imports from '@tauri-apps/api/core'.
 * Engine code, CLI shims, and tests should import this file instead.
 */

import { invoke } from '@tauri-apps/api/core';
import type { FileMetadata, DisassembledInstruction } from '../App';
import type { CfgGraph } from '../utils/cfgSignalExtractor';
import type { NestBackend, DisassemblyResult } from '../utils/nestBackend';

// ── Extended interface (superset of NestBackend) ───────────────────────────────

export interface TauriBackend extends NestBackend {
  runPlugins(path: string): Promise<unknown>;
}

// ── Tauri backend implementation ───────────────────────────────────────────────

export const tauriBackend: TauriBackend = {
  /** Disassemble a byte range of a binary file. */
  async disassembleRange(
    path:   string,
    offset: number,
    length: number,
  ): Promise<DisassemblyResult> {
    return invoke('disassemble_file_range', { path, offset, length });
  },

  /** Build a control-flow graph for a byte range of a binary file. */
  async buildCfg(
    path:   string,
    offset: number,
    length: number,
  ): Promise<CfgGraph> {
    return invoke('build_cfg', { path, offset, length });
  },

  /** Fetch file metadata (SHA256, sections, imports, strings, entry point, …). */
  async inspectMetadata(path: string): Promise<FileMetadata> {
    return invoke('inspect_file_metadata', { path });
  },

  /** Run all loaded plugins on a file. */
  async runPlugins(path: string): Promise<unknown> {
    return invoke('run_plugins_on_file', { path });
  },
};
