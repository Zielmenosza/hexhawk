import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
const source = readFileSync(new URL('../../App.tsx', import.meta.url), 'utf8');
function body(start: string, end: string) { return source.slice(source.indexOf(start), source.indexOf(end, source.indexOf(start))); }
describe('App selection custody wiring contract (source, not runtime integration)', () => {
  it('has one selected-identity setter and an isolated draft input', () => {
    expect(source.match(/setBinaryPath\(/g)).toHaveLength(1);
    expect(source).toContain('onChange={(event) => setDraftBinaryPath(event.target.value)}');
    expect(source).toContain('const candidate = draftBinaryPath.trim();');
    expect(body('onLoadTrainingBinary=', '/>')).toContain('prepareForBinarySelection(path)');
  });
  it('resets legacy pattern analysis and all loading owners at the central selection boundary', () => {
    const reset = body('function prepareForBinarySelection', 'useEffect(() => {');
    expect(reset).toContain('selectionGeneration.current.select(nextBinaryPath)');
    expect(reset).toContain('resetFileBoundState()');
    const stateReset = body('function resetFileBoundState', 'function prepareForBinarySelection');
    expect(stateReset).toContain('setDisassemblyAnalysis(');
    expect(stateReset).toContain('setDisasmIsLoading(false)');
    expect(stateReset).toContain('setHexIsLoadingMore(false)');
  });
  it.each(['hexLoadMore', 'previewHex', 'previewHexAt', 'scanStrings', 'disassembleFile', 'loadMoreDisassembly', 'buildCfg', 'analyzePlugins'])
  ('guards native publication and errors in %s', name => {
    const start = name === 'hexLoadMore' ? 'const hexLoadMore = async' : `async function ${name}(`;
    const region = body(start, name === 'hexLoadMore' ? '// NEW: Navigate to bookmark' : '\n  // ======== UNIFIED NAVIGATION');
    const nextFunction = region.indexOf('\n  async function ', start.length);
    const fn = nextFunction < 0 ? region : region.slice(0, nextFunction);
    const lanes: Record<string, string> = { hexLoadMore: 'hex', previewHex: 'hex', previewHexAt: 'hex',
      scanStrings: 'strings', disassembleFile: 'disassembly', loadMoreDisassembly: 'disassembly', buildCfg: 'cfg' };
    // Require the exact per-stream owner, not just any generation capture.
    expect(fn).toContain(lanes[name] ? `captureFileOperation('${lanes[name]}')` : 'captureFileOperation()');
    expect(fn).toMatch(/\);\s*if \(!isCurrentFileOperation\(request\)\)/);
    expect(fn).toMatch(/catch \((?:error|err)\) \{\s*if \(!isCurrentFileOperation\(request\)\)/);
    if (fn.includes('finally')) expect(fn).toMatch(/finally \{\s*if \(isCurrentFileOperation\(request\)\)/);
  });
  it('uses fresh metadata-only corpus input rather than reset-but-still-captured React state', () => {
    const corpus = body('const freshVerdict =', '// Group signal weights');
    expect(corpus).toMatch(/strings:\s*\[\]/);
    expect(corpus).toMatch(/patterns:\s*\[\]/);
  });
});
