const fs = require('fs');
let c = fs.readFileSync('src/App.tsx', 'utf8');

const oldPanel = '                    <PatchPanel\r\n                      patches={patches as PanelPatch[]}\r\n                      binaryPath={binaryPath}\r\n                      onRemovePatch={removePatch}\r\n                      onTogglePatch={togglePatch}\r\n                      onClearAll={clearAllPatches}\r\n                    />';
const newPanel = '                    <PatchPanel\r\n                      patches={patches as PanelPatch[]}\r\n                      binaryPath={binaryPath}\r\n                      onRemovePatch={removePatch}\r\n                      onTogglePatch={togglePatch}\r\n                      onClearAll={clearAllPatches}\r\n                      suggestions={patchSuggestions as any}\r\n                      onQueueSuggestion={(s) => void queueFromSuggestion(s as any)}\r\n                    />';

if (c.includes(oldPanel)) {
  c = c.replace(oldPanel, newPanel);
  console.log('✓ Updated PatchPanel JSX');
} else {
  console.log('✗ Still not found');
}

fs.writeFileSync('src/App.tsx', c, 'utf8');
console.log('done');
