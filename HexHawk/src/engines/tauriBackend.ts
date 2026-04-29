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
import { sanitizeBridgePath, sanitizeRange } from '../utils/tauriGuards';

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
    const safePath = sanitizeBridgePath(path);
    const safeRange = sanitizeRange(offset, length);
    return invoke('disassemble_file_range', { path: safePath, offset: safeRange.offset, length: safeRange.length });
  },

  /** Build a control-flow graph for a byte range of a binary file. */
  async buildCfg(
    path:   string,
    offset: number,
    length: number,
  ): Promise<CfgGraph> {
    const safePath = sanitizeBridgePath(path);
    const safeRange = sanitizeRange(offset, length);
    return invoke('build_cfg', { path: safePath, offset: safeRange.offset, length: safeRange.length });
  },

  /** Fetch file metadata (SHA256, sections, imports, strings, entry point, …). */
  async inspectMetadata(path: string): Promise<FileMetadata> {
    const safePath = sanitizeBridgePath(path);
    return invoke('inspect_file_metadata', { path: safePath });
  },

  /** Run all loaded plugins on a file. */
  async runPlugins(path: string): Promise<unknown> {
    const safePath = sanitizeBridgePath(path);
    return invoke('run_plugins_on_file', { path: safePath });
  },

  /** Extract printable strings from a file. */
  async extractStrings(path: string): Promise<string[]> {
    const safePath = sanitizeBridgePath(path);
    const r = await invoke<{ ascii: string[]; unicode: string[]; urls: string[]; paths: string[]; api_names: string[] }>('extract_strings', { path: safePath });
    return Array.from(new Set([...r.ascii, ...r.unicode, ...r.urls, ...r.paths, ...r.api_names]));
  },

  /** Lightweight format detection from magic bytes. */
  async identifyFormat(path: string): Promise<{ format: string; magic_hex: string; file_size: number; entropy_header_4kb: number }> {
    const safePath = sanitizeBridgePath(path);
    return invoke('identify_format', { path: safePath });
  },
};
