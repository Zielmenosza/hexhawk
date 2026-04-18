/**
 * useVirtualList — minimal row-based virtualization hook.
 *
 * Renders only the rows visible in the scroll viewport plus `overscan` rows
 * above and below. Uses ResizeObserver to track container height automatically
 * — no explicit height prop or AutoSizer wrapper needed.
 *
 * Usage:
 *   const { virtualItems, totalHeight, containerRef, scrollToIndex } =
 *     useVirtualList({ count: 1000, itemHeight: 28, overscan: 5 });
 *
 *   <div ref={containerRef} style={{ overflowY: 'auto', ...yourHeight }}>
 *     <div style={{ height: totalHeight, position: 'relative' }}>
 *       {virtualItems.map(({ index, top, size }) => (
 *         <div key={index} style={{ position: 'absolute', top, height: size, width: '100%' }}>
 *           <YourRow index={index} />
 *         </div>
 *       ))}
 *     </div>
 *   </div>
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

export interface VirtualItem {
  index: number;
  /** Top offset in pixels from the top of the scrollable content area. */
  top: number;
  /** Height of this item in pixels. */
  size: number;
}

export interface UseVirtualListResult {
  /** Items that should be rendered (visible + overscan). */
  virtualItems: VirtualItem[];
  /** Total height of all items — set as the inner container height to create a scrollbar. */
  totalHeight: number;
  /** Attach this ref to the scrollable outer container div. */
  containerRef: React.RefObject<HTMLDivElement>;
  /** Scrolls the container so the item at `index` is visible. */
  scrollToIndex: (index: number, align?: 'auto' | 'start' | 'center' | 'end') => void;
}

export interface UseVirtualListOptions {
  /** Total number of items in the list. */
  count: number;
  /**
   * Height of each item in pixels.
   * Pass a number for fixed-height lists (fastest path).
   * Pass a function `(index) => number` for variable-height lists.
   */
  itemHeight: number | ((index: number) => number);
  /** Number of extra items to render above and below the visible area. Default: 5. */
  overscan?: number;
}

export function useVirtualList({
  count,
  itemHeight,
  overscan = 5,
}: UseVirtualListOptions): UseVirtualListResult {
  const [containerHeight, setContainerHeight] = useState(400);
  const [scrollTop, setScrollTop] = useState(0);
  const containerRef = useRef<HTMLDivElement>(null);

  // Track container height changes with ResizeObserver
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    // Capture initial size
    setContainerHeight(el.clientHeight);
    const ro = new ResizeObserver(([entry]) => {
      setContainerHeight(entry.contentRect.height);
    });
    ro.observe(el);

    // Track scroll
    const onScroll = () => setScrollTop(el.scrollTop);
    el.addEventListener('scroll', onScroll, { passive: true });

    return () => {
      ro.disconnect();
      el.removeEventListener('scroll', onScroll);
    };
  }, []);

  // Precompute cumulative offsets for variable-height lists
  const offsets = useMemo<Float64Array | null>(() => {
    if (typeof itemHeight === 'number') return null;
    const arr = new Float64Array(count + 1);
    for (let i = 0; i < count; i++) {
      arr[i + 1] = arr[i] + itemHeight(i);
    }
    return arr;
  }, [count, itemHeight]);

  const totalHeight =
    typeof itemHeight === 'number'
      ? count * itemHeight
      : offsets != null
      ? offsets[count]
      : 0;

  // Resolve top offset for item i
  const getItemTop = useCallback(
    (i: number): number => {
      if (typeof itemHeight === 'number') return i * itemHeight;
      return offsets != null ? offsets[i] : 0;
    },
    [itemHeight, offsets]
  );

  // Resolve height for item i
  const getItemSize = useCallback(
    (i: number): number => {
      if (typeof itemHeight === 'number') return itemHeight;
      return (offsets != null ? offsets[i + 1] - offsets[i] : 0);
    },
    [itemHeight, offsets]
  );

  // Binary search: find first item whose bottom edge is below `y`
  const lowerBound = useCallback(
    (y: number): number => {
      if (typeof itemHeight === 'number') {
        return Math.max(0, Math.floor(y / itemHeight));
      }
      if (offsets == null) return 0;
      let lo = 0;
      let hi = count;
      while (lo < hi) {
        const mid = (lo + hi) >> 1;
        if (offsets[mid + 1] <= y) lo = mid + 1;
        else hi = mid;
      }
      return lo;
    },
    [itemHeight, offsets, count]
  );

  // Compute visible range
  const startIndex = Math.max(0, lowerBound(scrollTop) - overscan);
  const endIndex = Math.min(
    count - 1,
    lowerBound(scrollTop + containerHeight) + overscan
  );

  const virtualItems: VirtualItem[] = [];
  for (let i = startIndex; i <= endIndex; i++) {
    virtualItems.push({ index: i, top: getItemTop(i), size: getItemSize(i) });
  }

  const scrollToIndex = useCallback(
    (index: number, align: 'auto' | 'start' | 'center' | 'end' = 'auto') => {
      const el = containerRef.current;
      if (!el) return;
      const itemTop = getItemTop(index);
      const itemSize = getItemSize(index);
      const current = el.scrollTop;

      let next = current;
      if (align === 'start') {
        next = itemTop;
      } else if (align === 'end') {
        next = itemTop + itemSize - el.clientHeight;
      } else if (align === 'center') {
        next = itemTop - el.clientHeight / 2 + itemSize / 2;
      } else {
        // 'auto' — only scroll if item is not already visible
        if (itemTop < current) {
          next = itemTop;
        } else if (itemTop + itemSize > current + el.clientHeight) {
          next = itemTop + itemSize - el.clientHeight;
        }
      }
      el.scrollTop = Math.max(0, next);
    },
    [getItemTop, getItemSize]
  );

  return { virtualItems, totalHeight, containerRef, scrollToIndex };
}
