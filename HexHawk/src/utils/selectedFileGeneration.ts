/** Renderer custody only: no verdict/classification authority or native cancellation. */
export type SelectedFileLane = 'hex' | 'strings' | 'disassembly' | 'cfg';
export type SelectedFileOperation = Readonly<{ path: string; generation: number; lane?: SelectedFileLane; sequence?: number }>;

export class SelectedFileGeneration {
  private path: string;
  private generation = 0;
  private sequences: Record<SelectedFileLane, number> = { hex: 0, strings: 0, disassembly: 0, cfg: 0 };

  constructor(path: string) { this.path = path; }

  /** Synchronous invalidation, including selecting/re-inspecting the same path. */
  select(path: string): SelectedFileOperation {
    this.path = path;
    this.generation += 1;
    return this.capture(path)!;
  }

  /** Reject an old render's callback before it can start another file-bound invoke. */
  capture(expectedPath: string, lane?: SelectedFileLane): SelectedFileOperation | null {
    if (expectedPath !== this.path) return null;
    const sequence = lane ? ++this.sequences[lane] : undefined;
    return Object.freeze({ path: this.path, generation: this.generation, lane, sequence });
  }

  isCurrent(operation: SelectedFileOperation | null): operation is SelectedFileOperation {
    return operation !== null && operation.path === this.path && operation.generation === this.generation
      && (!operation.lane || operation.sequence === this.sequences[operation.lane]);
  }

  invalidate(): void { this.generation += 1; }
}
