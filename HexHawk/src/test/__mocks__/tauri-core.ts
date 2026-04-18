import { vi } from 'vitest';

/** Stub for @tauri-apps/api/core `invoke`. Tests configure return values via mockResolvedValue. */
export const invoke = vi.fn();
