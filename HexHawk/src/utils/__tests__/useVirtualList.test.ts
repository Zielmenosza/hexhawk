/**
 * @vitest-environment jsdom
 */
import { describe, it, expect } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useVirtualList } from '../../utils/useVirtualList';

describe('useVirtualList — fixed height', () => {
  const ITEM_HEIGHT = 28;

  it('renders a subset of items for a large list (fixed height)', () => {
    const { result } = renderHook(() =>
      useVirtualList({ count: 1000, itemHeight: ITEM_HEIGHT, overscan: 0 }),
    );
    // With 600px container (stubbed by ResizeObserver) and 28px rows:
    // visible ≈ 21 rows. Virtual items should be << 1000.
    expect(result.current.virtualItems.length).toBeLessThan(100);
    expect(result.current.virtualItems.length).toBeGreaterThan(0);
  });

  it('totalHeight equals count * itemHeight', () => {
    const { result } = renderHook(() =>
      useVirtualList({ count: 100, itemHeight: ITEM_HEIGHT }),
    );
    expect(result.current.totalHeight).toBe(100 * ITEM_HEIGHT);
  });

  it('virtualItems have correct top and size fields', () => {
    const { result } = renderHook(() =>
      useVirtualList({ count: 50, itemHeight: ITEM_HEIGHT, overscan: 0 }),
    );
    for (const item of result.current.virtualItems) {
      expect(item.top).toBe(item.index * ITEM_HEIGHT);
      expect(item.size).toBe(ITEM_HEIGHT);
    }
  });

  it('returns empty virtualItems for count=0', () => {
    const { result } = renderHook(() =>
      useVirtualList({ count: 0, itemHeight: ITEM_HEIGHT }),
    );
    expect(result.current.virtualItems).toHaveLength(0);
    expect(result.current.totalHeight).toBe(0);
  });

  it('all rendered indices are in range [0, count)', () => {
    const count = 20;
    const { result } = renderHook(() =>
      useVirtualList({ count, itemHeight: ITEM_HEIGHT }),
    );
    for (const item of result.current.virtualItems) {
      expect(item.index).toBeGreaterThanOrEqual(0);
      expect(item.index).toBeLessThan(count);
    }
  });
});

describe('useVirtualList — variable height', () => {
  const itemHeight = (i: number) => (i % 2 === 0 ? 44 : 72); // alternating heights

  it('renders a subset of items for variable height list', () => {
    const { result } = renderHook(() =>
      useVirtualList({ count: 500, itemHeight, overscan: 0 }),
    );
    expect(result.current.virtualItems.length).toBeLessThan(500);
    expect(result.current.virtualItems.length).toBeGreaterThan(0);
  });

  it('totalHeight equals sum of all item heights', () => {
    const count = 10;
    const { result } = renderHook(() =>
      useVirtualList({ count, itemHeight }),
    );
    const expected = Array.from({ length: count }, (_, i) => itemHeight(i)).reduce((a, b) => a + b, 0);
    expect(result.current.totalHeight).toBe(expected);
  });

  it('each virtualItem size matches its itemHeight(index)', () => {
    const { result } = renderHook(() =>
      useVirtualList({ count: 20, itemHeight, overscan: 0 }),
    );
    for (const item of result.current.virtualItems) {
      expect(item.size).toBe(itemHeight(item.index));
    }
  });
});

describe('useVirtualList — scrollToIndex', () => {
  it('exposes a scrollToIndex function', () => {
    const { result } = renderHook(() =>
      useVirtualList({ count: 100, itemHeight: 28 }),
    );
    expect(typeof result.current.scrollToIndex).toBe('function');
  });

  it('does not throw when called with valid index', () => {
    const { result } = renderHook(() =>
      useVirtualList({ count: 100, itemHeight: 28 }),
    );
    expect(() => {
      act(() => result.current.scrollToIndex(50));
    }).not.toThrow();
  });
});
