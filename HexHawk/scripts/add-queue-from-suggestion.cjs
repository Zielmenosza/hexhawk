const fs = require('fs');
let c = fs.readFileSync('src/App.tsx', 'utf8');

// Find clearAllPatches and insert queueFromSuggestion after it
const clearLine = 'const clearAllPatches = () => setPatches([]);';
const idx = c.indexOf(clearLine);
if (idx < 0) {
  console.log('NOT FOUND: clearAllPatches');
  process.exit(1);
}

const insertAt = idx + clearLine.length;
const handler = '\r\n\r\n  /** Queue an explainable patch from a Patch Intelligence suggestion. */\r\n' +
  '  const queueFromSuggestion = async (s: import(\'./utils/patchEngine\').PatchSuggestion) => {\r\n' +
  '    if (s.kind === \'invert-jump\') {\r\n' +
  '      await queueInvertJump(s.address);\r\n' +
  '      setPatches(prev => {\r\n' +
  '        const last = prev[prev.length - 1];\r\n' +
  '        if (!last || last.address !== s.address) return prev;\r\n' +
  '        return [\r\n' +
  '          ...prev.slice(0, -1),\r\n' +
  '          { ...last, reason: s.reason, impact: s.impact, verifyBefore: s.verifyBefore, risk: s.risk, signalIds: s.signalLinks.map(l => l.signalId) },\r\n' +
  '        ];\r\n' +
  '      });\r\n' +
  '    } else if (s.kind === \'nop-call\') {\r\n' +
  '      await queueNopSled(s.address, 5);\r\n' +
  '      setPatches(prev => {\r\n' +
  '        const last = prev[prev.length - 1];\r\n' +
  '        if (!last || last.address !== s.address) return prev;\r\n' +
  '        return [\r\n' +
  '          ...prev.slice(0, -1),\r\n' +
  '          { ...last, reason: s.reason, impact: s.impact, verifyBefore: s.verifyBefore, risk: s.risk, signalIds: s.signalLinks.map(l => l.signalId) },\r\n' +
  '        ];\r\n' +
  '      });\r\n' +
  '    }\r\n' +
  '  };';

c = c.substring(0, insertAt) + handler + c.substring(insertAt);
fs.writeFileSync('src/App.tsx', c, 'utf8');
console.log('done - inserted at char', insertAt);
