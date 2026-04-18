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

export class TauriNestBackend implements NestBackend {
  disassembleRange(path: string, offset: number, length: number): Promise<DisassemblyResult> {
    return invoke<DisassemblyResult>('disassemble_file_range', { path, offset, length });
  }

  buildCfg(path: string, offset: number, length: number): Promise<CfgGraph> {
    return invoke<CfgGraph>('build_cfg', { path, offset, length });
  }

  inspectMetadata(path: string): Promise<FileMetadata> {
    return invoke<FileMetadata>('inspect_file_metadata', { path });
  }
}

/** Singleton — import this in NestView.tsx and other UI code. */
export const tauriBackend = new TauriNestBackend();
