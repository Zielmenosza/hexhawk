import { describe, expect, it, beforeEach } from 'vitest';
import {
  DECOMPILER_OUTPUT_MODE_STORAGE_KEY,
  loadDecompilerOutputMode,
  persistDecompilerOutputMode,
} from '../DecompilerView';

describe('DecompilerView output-mode preference', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('defaults to compact mode', () => {
    expect(loadDecompilerOutputMode()).toBe('compact');
  });

  it('persists annotated mode across a simulated reload', () => {
    persistDecompilerOutputMode('annotated');
    expect(localStorage.getItem(DECOMPILER_OUTPUT_MODE_STORAGE_KEY)).toBe('annotated');
    expect(loadDecompilerOutputMode()).toBe('annotated');
  });
});
