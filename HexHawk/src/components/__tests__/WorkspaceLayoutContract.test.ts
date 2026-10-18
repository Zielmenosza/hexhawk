import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

const stylesheet = readFileSync(new URL('../../styles.css', import.meta.url), 'utf8');

function cssRule(selector: string): string {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = stylesheet.match(new RegExp(`${escaped}\\s*\\{([^}]*)\\}`, 'm'));
  expect(match, `missing CSS contract rule for ${selector}`).not.toBeNull();
  return match?.[1] ?? '';
}

describe('universal workspace layout contract', () => {
  it('keeps the main workspace as the primary vertical scroll owner', () => {
    const rule = cssRule('.wf-panel--workspace');
    expect(rule).toMatch(/overflow-y:\s*auto/);
    expect(rule).not.toMatch(/overflow:\s*hidden/);
    expect(stylesheet).not.toContain('.wf-panel--cfg');
  });

  it('lets generic workspace and debugger roots grow in natural document flow', () => {
    const shell = cssRule('.workspace-view-shell');
    const flowRoot = cssRule('.workspace-flow-root');
    const debuggerRoot = cssRule('.stk-root');
    expect(shell).toMatch(/overflow:\s*visible/);
    expect(shell).not.toMatch(/overflow:\s*hidden/);
    expect(flowRoot).toMatch(/overflow:\s*visible/);
    expect(flowRoot).not.toMatch(/overflow:\s*hidden/);
    expect(debuggerRoot).toMatch(/height:\s*auto/);
    expect(debuggerRoot).toMatch(/overflow:\s*visible/);
    expect(debuggerRoot).not.toMatch(/height:\s*100%/);
  });

  it('does not clip the Guided Value Finder card', () => {
    const finder = cssRule('.vf-root');
    expect(finder).toMatch(/box-sizing:\s*border-box/);
    expect(finder).toMatch(/overflow:\s*visible/);
  });
});
