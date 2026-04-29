import { describe, expect, it } from 'vitest';
import {
  capArraySize,
  clampInt,
  sanitizeAddress,
  sanitizeBridgePath,
  sanitizeHexOrDecAddress,
  sanitizePluginFilename,
  sanitizePluginName,
  sanitizeRange,
} from '../tauriGuards';

describe('tauriGuards', () => {
  it('sanitizes valid bridge path', () => {
    expect(sanitizeBridgePath(' C:/tmp/file.bin ')).toBe('C:/tmp/file.bin');
  });

  it('rejects path with control characters', () => {
    expect(() => sanitizeBridgePath('abc\npath')).toThrow(/unsafe control/i);
  });

  it('rejects empty bridge path', () => {
    expect(() => sanitizeBridgePath('   ')).toThrow(/empty/i);
  });

  it('accepts valid plugin filename', () => {
    expect(sanitizePluginFilename('my_plugin.dll')).toBe('my_plugin.dll');
  });

  it('rejects plugin filename traversal style payload', () => {
    expect(() => sanitizePluginFilename('../evil.dll')).toThrow(/unsupported/i);
  });

  it('rejects plugin filename with null byte', () => {
    expect(() => sanitizePluginFilename('evil\u0000.dll')).toThrow(/unsupported/i);
  });

  it('accepts plugin display name charset', () => {
    expect(sanitizePluginName('My Plugin-1.2')).toBe('My Plugin-1.2');
  });

  it('rejects plugin display name with disallowed symbols', () => {
    expect(() => sanitizePluginName('bad<script>name')).toThrow(/invalid|unsupported/i);
  });

  it('parses decimal and hex addresses', () => {
    expect(sanitizeHexOrDecAddress('1234')).toBe(1234);
    expect(sanitizeHexOrDecAddress('0x10')).toBe(16);
  });

  it('rejects malformed address input', () => {
    expect(() => sanitizeHexOrDecAddress('0xZZ')).toThrow(/hex/i);
  });

  it('clamps integer ranges with clear error on overflow', () => {
    expect(() => clampInt(999, 1, 100, 'value')).toThrow(/expected 1-100/i);
  });

  it('sanitizes range bounds', () => {
    expect(sanitizeRange(10, 20)).toEqual({ offset: 10, length: 20 });
  });

  it('rejects negative address', () => {
    expect(() => sanitizeAddress(-1)).toThrow(/out of range/i);
  });

  it('caps array sizes for UI safety', () => {
    const arr = Array.from({ length: 10 }, (_, i) => i);
    expect(capArraySize(arr, 3)).toEqual([0, 1, 2]);
  });
});
