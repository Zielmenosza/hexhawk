import { describe, expect, it } from 'vitest';
import { formatVarDictionaryKey } from '../DecompilerView';

describe('formatVarDictionaryKey', () => {
  it('formats frame-relative memory keys with an explicit sign', () => {
    expect(formatVarDictionaryKey('mem:rbp:-8')).toBe('← [rbp - 8]');
    expect(formatVarDictionaryKey('mem:rbp:16')).toBe('← [rbp + 16]');
    expect(formatVarDictionaryKey('mem:rbp:0')).toBe('← [rbp]');
  });

  it('formats register keys without altering the register name', () => {
    expect(formatVarDictionaryKey('reg:rdi')).toBe('← rdi');
  });
});
