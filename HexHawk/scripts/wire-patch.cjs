const fs = require('fs');
let c = fs.readFileSync('src/App.tsx', 'utf8');

// ── 1. Add queueFromSuggestion after clearAllPatches ─────────────────────
const clearAllPatchesLine = '  const clearAllPatches = () => setPatches([]);';
const insertAfterLine = clearAllPatchesLine + '\n';
const newHandler = `\n  /** Queue an explainable patch from a Patch Intelligence suggestion. */\n  const queueFromSuggestion = async (s: PatchSuggestion) => {\n    if (s.kind === 'invert-jump') {\n      await queueInvertJump(s.address);\n      // Attach explainability to the patch that was just added\n      setPatches(prev => {\n        const last = prev[prev.length - 1];\n        if (!last || last.address !== s.address) return prev;\n        return [\n          ...prev.slice(0, -1),\n          { ...last, reason: s.reason, impact: s.impact, verifyBefore: s.verifyBefore, risk: s.risk, signalIds: s.signalLinks.map(l => l.signalId) },\n        ];\n      });\n    } else if (s.kind === 'nop-call') {\n      await queueNopSled(s.address, 5); // call is 5 bytes (E8 xx xx xx xx)\n      setPatches(prev => {\n        const last = prev[prev.length - 1];\n        if (!last || last.address !== s.address) return prev;\n        return [\n          ...prev.slice(0, -1),\n          { ...last, reason: s.reason, impact: s.impact, verifyBefore: s.verifyBefore, risk: s.risk, signalIds: s.signalLinks.map(l => l.signalId) },\n        ];\n      });\n    }\n  };\n`;

if (c.includes(clearAllPatchesLine)) {
  c = c.replace(insertAfterLine, insertAfterLine + newHandler);
  console.log('✓ Added queueFromSuggestion');
} else {
  console.log('✗ Could not find clearAllPatches line');
}

// ── 2. Update PatchPanel JSX to pass suggestions and onQueueSuggestion ───
const oldPanel = `                <PatchPanel
                  patches={patches as PanelPatch[]}
                  binaryPath={binaryPath}
                  onRemovePatch={removePatch}
                  onTogglePatch={togglePatch}
                  onClearAll={clearAllPatches}
                />`;
const newPanel = `                <PatchPanel
                  patches={patches as PanelPatch[]}
                  binaryPath={binaryPath}
                  onRemovePatch={removePatch}
                  onTogglePatch={togglePatch}
                  onClearAll={clearAllPatches}
                  suggestions={patchSuggestions as any}
                  onQueueSuggestion={(s) => void queueFromSuggestion(s as any)}
                />`;

if (c.includes(oldPanel)) {
  c = c.replace(oldPanel, newPanel);
  console.log('✓ Updated PatchPanel JSX');
} else {
  console.log('✗ Could not find PatchPanel JSX');
}

fs.writeFileSync('src/App.tsx', c, 'utf8');
console.log('done');
