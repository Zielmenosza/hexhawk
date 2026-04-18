import '@testing-library/jest-dom';
import { vi } from 'vitest';

// ResizeObserver is not available in jsdom — provide a minimal stub
if (typeof window !== 'undefined' && typeof ResizeObserver === 'undefined') {
  global.ResizeObserver = class ResizeObserver {
    constructor(private cb: ResizeObserverCallback) {}
    observe(_target: Element) {
      // Immediately fire with a synthetic entry so hooks see a height
      this.cb(
        [{ contentRect: { height: 600, width: 800 } } as ResizeObserverEntry],
        this,
      );
    }
    unobserve() {}
    disconnect() {}
  };
}

// scrollTo is not fully implemented in jsdom
if (typeof window !== 'undefined' && !window.scrollTo) {
  window.scrollTo = vi.fn() as unknown as typeof window.scrollTo;
}
