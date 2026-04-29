const fs = require('fs');
let c = fs.readFileSync('src/App.tsx', 'utf8');

// Find and replace patch type block
const start = c.indexOf('type Patch = {');
const end = c.indexOf('\n};', start) + 3;

console.log('Replacing block from', start, 'to', end);
console.log('Old block:', JSON.stringify(c.substring(start, end)));

const newBlock = [
  'type Patch = {',
  '  id: string;',
  '  address: number;',
  '  label: string;',
  '  originalBytes: number[];',
  '  patchedBytes: number[];',
  '  enabled: boolean;',
  '  timestamp: number;',
  '  // Explainability (optional — absent on manual patches)',
  "  reason?: string;",
  "  impact?: string;",
  "  verifyBefore?: string;",
  "  risk?: 'low' | 'medium' | 'high';",
  "  signalIds?: string[];",
  '};',
].join('\n');

c = c.substring(0, start) + newBlock + c.substring(end);
fs.writeFileSync('src/App.tsx', c, 'utf8');
console.log('done');
