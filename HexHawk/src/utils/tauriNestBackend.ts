/**
 * tauriNestBackend — NestBackend implementation for the Tauri UI context.
 *
 * Routes every call through @tauri-apps/api/core invoke(), which is only
 * available when running inside the Tauri WebView.
 *
 * Import `tauriBackend` (the singleton) rather than instantiating the class.
 */

import { invoke } from '@tauri-apps/api/core';
import type { NestBackend, DisassemblyResult } from './nestBackend';
import type { FileMetadata } from '../App';
import type { CfgGraph } from './cfgSignalExtractor';
import { sanitizeBridgePath, sanitizeRange } from './tauriGuards';

export class TauriNestBackend implements NestBackend {
  disassembleRange(path: string, offset: number, length: number): Promise<DisassemblyResult> {
    const safePath = sanitizeBridgePath(path);
    const safeRange = sanitizeRange(offset, length);
    return invoke<DisassemblyResult>('disassemble_file_range', { path: safePath, offset: safeRange.offset, length: safeRange.length });
  }

  buildCfg(path: string, offset: number, length: number): Promise<CfgGraph> {
    const safePath = sanitizeBridgePath(path);
    const safeRange = sanitizeRange(offset, length);
    return invoke<CfgGraph>('build_cfg', { path: safePath, offset: safeRange.offset, length: safeRange.length });
  }

  inspectMetadata(path: string): Promise<FileMetadata> {
    const safePath = sanitizeBridgePath(path);
    return invoke<FileMetadata>('inspect_file_metadata', { path: safePath });
  }

  async extractStrings(path: string): Promise<string[]> {
    const safePath = sanitizeBridgePath(path);
    const r = await invoke<{ ascii: string[]; unicode: string[]; urls: string[]; paths: string[]; api_names: string[] }>('extract_strings', { path: safePath });
    return Array.from(new Set([...r.ascii, ...r.unicode, ...r.urls, ...r.paths, ...r.api_names]));
  }

  identifyFormat(path: string): Promise<{ format: string; magic_hex: string; file_size: number; entropy_header_4kb: number }> {
    const safePath = sanitizeBridgePath(path);
    return invoke('identify_format', { path: safePath });
  }
}

/** Singleton — import this in NestView.tsx and other UI code. */
export const tauriBackend = new TauriNestBackend();
