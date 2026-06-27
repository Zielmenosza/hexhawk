import { describe, expect, it, vi } from 'vitest';
import { FIRST_RUN_LOADED_FILE_KEY, hasLoadedFileBefore, markLoadedFile, shouldShowFirstRunPanel } from '../firstRunState';

describe('first-run state', () => {
  it('renders first-run panel when hasLoadedFile is false or absent', () => {
    expect(shouldShowFirstRunPanel(false)).toBe(true);
    expect(hasLoadedFileBefore({ getItem: () => null })).toBe(false);
  });

  it('sets hasLoadedFile true after file load', () => {
    const setItem = vi.fn();
    markLoadedFile({ setItem });

    expect(setItem).toHaveBeenCalledWith(FIRST_RUN_LOADED_FILE_KEY, 'true');
  });

  it('does not render first-run panel when hasLoadedFile is true', () => {
    expect(shouldShowFirstRunPanel(true)).toBe(false);
    expect(hasLoadedFileBefore({ getItem: () => 'true' })).toBe(true);
  });
});
