/**
 * @vitest-environment jsdom
 */
import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import CorpusBenchmarkPanel from '../CorpusBenchmarkPanel';

vi.mock('../../utils/corpusManager', () => ({
  addToCorpus: vi.fn(),
  removeFromCorpus: vi.fn(),
  getCorpusStats: vi.fn(() => ({
    totalEntries: 1,
    byGroundTruth: { clean: 1, malicious: 0, challenge: 0, unknown: 0 },
    withNestResults: 0,
    avgConfidence: null,
  })),
  queryCorpus: vi.fn(() => []),
  exportCorpus: vi.fn(() => '{"entries": []}'),
  importCorpus: vi.fn(() => 1),
  clearCorpus: vi.fn(),
}));

vi.mock('../../utils/benchmarkHarness', () => ({
  loadBenchmarkHistory: vi.fn(() => []),
  deleteBenchmarkRun: vi.fn(),
}));

describe('CorpusBenchmarkPanel timer cleanup', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('clears add-entry success timer on unmount', () => {
    const { unmount } = render(
      <CorpusBenchmarkPanel binaryPath="C:\\sample.exe" onClose={() => {}} />,
    );

    fireEvent.click(screen.getByRole('button', { name: /\+ add current binary/i }));
    fireEvent.click(screen.getByRole('button', { name: /\+ add to corpus/i }));

    expect(vi.getTimerCount()).toBe(1);

    unmount();

    expect(vi.getTimerCount()).toBe(0);
  });

  it('clears import success timer on unmount', () => {
    const realCreateElement = document.createElement.bind(document);

    const input = realCreateElement('input') as HTMLInputElement;
    Object.defineProperty(input, 'files', {
      value: [new File(['{}'], 'corpus.json', { type: 'application/json' })],
      configurable: true,
    });

    vi.spyOn(document, 'createElement').mockImplementation((tagName: string) => {
      if (tagName.toLowerCase() === 'input') {
        input.click = () => {
          input.onchange?.({ target: input } as unknown as Event);
        };
        return input;
      }
      return realCreateElement(tagName);
    });

    class MockFileReader {
      result: string | ArrayBuffer | null = '{"entries": []}';
      onload: ((this: FileReader, ev: ProgressEvent<FileReader>) => unknown) | null = null;
      readAsText(_file: Blob) {
        if (this.onload) {
          this.onload.call(this as unknown as FileReader, new ProgressEvent('load'));
        }
      }
    }

    vi.stubGlobal('FileReader', MockFileReader as unknown as typeof FileReader);

    const { unmount } = render(
      <CorpusBenchmarkPanel binaryPath="C:\\sample.exe" onClose={() => {}} />,
    );

    fireEvent.click(screen.getByRole('button', { name: /import json/i }));

    expect(screen.getByText(/imported 1 entries\./i)).toBeInTheDocument();
    expect(vi.getTimerCount()).toBe(1);

    unmount();

    expect(vi.getTimerCount()).toBe(0);
  });
});
