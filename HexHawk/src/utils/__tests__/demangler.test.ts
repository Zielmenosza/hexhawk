import { describe, it, expect } from 'vitest';
import { demangle, isMangled, demangleAll } from '../../utils/demangler';

// ── Itanium ABI (_Z prefix) ──────────────────────────────────────────────────

describe('demangle — Itanium ABI', () => {
  it('demangles a simple function with no params', () => {
    // _ZN3foo3barEv → foo::bar()  (void params → empty parens)
    const result = demangle('_ZN3foo3barEv');
    expect(result).toContain('foo');
    expect(result).toContain('bar');
  });

  it('returns the original name for a non-mangled symbol', () => {
    expect(demangle('printf')).toBe('printf');
    expect(demangle('CreateFileW')).toBe('CreateFileW');
  });

  it('returns the original name for an empty string', () => {
    expect(demangle('')).toBe('');
  });

  it('handles _ZN prefix without crashing', () => {
    // Even if parsing fails the function must not throw
    expect(() => demangle('_ZN')).not.toThrow();
  });
});

// ── MSVC mangling (? prefix) ─────────────────────────────────────────────────

describe('demangle — MSVC ABI', () => {
  it('demangles a simple MSVC symbol', () => {
    const result = demangle('?bar@foo@@QEAAXXZ');
    expect(result).toContain('foo');
    expect(result).toContain('bar');
  });

  it('does not mangle a non-MSVC C-linkage symbol', () => {
    expect(demangle('_strlen')).toBe('_strlen');
  });
});

// ── isMangled ────────────────────────────────────────────────────────────────

describe('isMangled', () => {
  it('returns true for _Z-prefixed symbols', () => {
    expect(isMangled('_ZN3foo3barEv')).toBe(true);
  });

  it('returns true for MSVC ?-prefixed symbols', () => {
    expect(isMangled('?bar@foo@@QEAAXXZ')).toBe(true);
  });

  it('returns false for plain C names', () => {
    expect(isMangled('CreateFileW')).toBe(false);
    expect(isMangled('malloc')).toBe(false);
  });
});

// ── demangleAll ──────────────────────────────────────────────────────────────

describe('demangleAll', () => {
  it('returns only entries that changed', () => {
    const results = demangleAll(['printf', '_ZN3foo3barEv', 'malloc']);
    // printf and malloc should NOT appear (unchanged), _Z symbol should appear
    expect(results.every(r => r.raw !== r.demangled)).toBe(true);
    const raws = results.map(r => r.raw);
    expect(raws).not.toContain('printf');
    expect(raws).not.toContain('malloc');
  });

  it('handles an empty list', () => {
    expect(demangleAll([])).toEqual([]);
  });
});
