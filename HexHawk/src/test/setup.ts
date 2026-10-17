import '@testing-library/jest-dom';
import { vi } from 'vitest';

// React Flow reads the current viewport zoom from DOMMatrixReadOnly. Happy DOM
// exposes the name without a constructable implementation, so provide the
// identity-matrix subset used by the graph renderer.
if (typeof window !== 'undefined' && typeof window.DOMMatrixReadOnly !== 'function') {
  Object.defineProperty(window, 'DOMMatrixReadOnly', {
    configurable: true,
    value: class DOMMatrixReadOnly {
      readonly m22 = 1;
      constructor(_transform?: string) {}
    },
  });
}

// ResizeObserver is not available in jsdom — provide a minimal stub
if (typeof window !== 'undefined' && typeof ResizeObserver === 'undefined') {
  global.ResizeObserver = class ResizeObserver {
    constructor(private cb: ResizeObserverCallback) {}
    observe(target: Element) {
      // Immediately fire with a synthetic entry so hooks see a height
      this.cb(
        [{
          target,
          contentRect: { height: 600, width: 800 },
          borderBoxSize: [],
          contentBoxSize: [],
          devicePixelContentBoxSize: [],
        } as unknown as ResizeObserverEntry],
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
