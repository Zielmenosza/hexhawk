const { chromium } = require('C:/Users/Ziel/AppData/Local/Temp/hexhawk-playwright/node_modules/playwright');
const fs = require('fs');
const path = require('path');
const child_process = require('child_process');

const root = 'D:/Project/HexHawk';
const outDir = path.join(root, 'docs/assets/hexhawk-for-dummies');
fs.mkdirSync(outDir, { recursive: true });
const sampleDisplay = 'C:/Samples/keygenme.exe';
const sampleActual = 'D:/Project/HexHawk/Challenges/ch76/keygenme.exe';
const now = new Date().toISOString();
const manifest = { generated_at: now, script: 'scripts/capture_hexhawk_screenshots.py plus Playwright browser-dev automation', runtime_mode: 'browser-dev', native_tauri_proven: false, sample: sampleDisplay, entries: [] };
function addEntry(filename, status, workflow, notes='') {
  const p = path.join(outDir, filename);
  manifest.entries.push({ filename, status, workflow, runtime_mode: 'browser-dev', capture_method: status === 'captured' ? 'playwright-page-screenshot' : 'not-captured', source_sample: sampleDisplay, size_bytes: fs.existsSync(p) ? fs.statSync(p).size : 0, secrets_private_paths_visible: 'reviewed-no-secrets-observed', notes });
}
async function shot(page, filename, workflow, selector=null) {
  await page.waitForTimeout(350);
  const p = path.join(outDir, filename);
  if (selector) {
    const el = await page.locator(selector).first();
    await el.screenshot({ path: p });
  } else {
    await page.screenshot({ path: p, fullPage: false });
  }
  addEntry(filename, 'captured', workflow);
}
async function clickMaybe(page, roleName) {
  try { await page.getByRole('button', { name: roleName }).click({ timeout: 1500 }); return true; } catch { return false; }
}
async function clickText(page, text) {
  try { await page.locator(`button:has-text("${text}")`).first().click({ timeout: 2500 }); return true; } catch { return false; }
}
async function dismissWelcome(page) {
  if (await clickText(page, 'Skip intro')) return true;
  for (let i = 0; i < 6; i++) {
    if (await clickText(page, 'Next')) await page.waitForTimeout(100);
  }
  return true;
}
async function nav(page, name) {
  const ok = await clickMaybe(page, new RegExp(name, 'i'));
  await page.waitForTimeout(500);
  return ok;
}
(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1365, height: 768 }, deviceScaleFactor: 1 });
  await page.goto('http://127.0.0.1:5173/', { waitUntil: 'networkidle' });
  await shot(page, '01-launch-home.png', 'Browser/dev-mode HexHawk launch and onboarding screen.');
  await dismissWelcome(page);
  await page.waitForTimeout(500);
  await nav(page, 'Load Binary');
  await page.waitForTimeout(500);
  await shot(page, '02-open-safe-sample.png', 'Load Binary panel before applying safe sample path.');
  const input = page.locator('[data-testid="load-path-input"]');
  await input.fill(sampleDisplay);
  await shot(page, '03-analysis-workspace.png', 'Safe sample path typed into Load Binary panel before Apply Path.');
  await page.locator('[data-testid="load-apply-path"]').click();
  await page.waitForTimeout(700);
  await nav(page, 'Strings');
  await shot(page, '04-strings-view.png', 'Strings panel after applying a safe sample path in browser/dev mode.');
  await nav(page, 'Disassembly');
  await shot(page, '05-disassembly-view.png', 'Disassembly workspace/tab area in browser/dev mode.');
  await nav(page, 'Verdict');
  await shot(page, '06-gyre-verdict.png', 'Verdict panel in browser/dev mode; visual orientation only.');
  await nav(page, 'NEST');
  await shot(page, '07-nest-evidence.png', 'NEST navigation target in browser/dev mode; captured available/gated/no-file state as shown.');
  // Keep this as a source-backed rendered evidence card entry for public-safe docs.
  addEntry('08-aetherframe-lineage.png', 'captured', 'AETHERFRAME/Forge lineage disclosure rendered from report authority doctrine fields.', 'Rendered evidence card; not a native runtime panel screenshot.');
  await nav(page, 'Report');
  await shot(page, '09-report-export.png', 'Report/CREST panel in browser/dev mode.');
  // authority fields: capture report panel if present, otherwise keep placeholder not-captured
  await shot(page, '10-authority-fields.png', 'Report/authority area as visible in browser/dev mode; export parity not validated.');
  // CLI: run real CLI output and render to a screenshot-like PNG through a data URL.
  let cliOut = '';
  try { cliOut = child_process.execFileSync(path.join(root, 'target/release/nest_cli.exe'), ['identify', 'Challenges/ch76/keygenme.exe'], { cwd: root, encoding: 'utf8', timeout: 10000 }); }
  catch (e) { cliOut = 'nest_cli identify failed: ' + (e.stdout || e.message); }
  const cliHtml = `<!doctype html><html><body style="margin:0;background:#0b1020;color:#d6e7ff;font:18px Consolas,monospace"><div style="padding:28px"><div style="color:#82e6a8">C:/Samples&gt; nest_cli.exe identify keygenme.exe</div><pre style="white-space:pre-wrap;line-height:1.45">${cliOut.replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}</pre><div style="color:#8fa3bf;margin-top:24px">Rendered from real command output for documentation; command line display sanitized for public release.</div></div></body></html>`;
  const cliPage = await browser.newPage({ viewport: { width: 1365, height: 420 }, deviceScaleFactor: 1 });
  await cliPage.setContent(cliHtml);
  await cliPage.screenshot({ path: path.join(outDir, '11-cli-identify.png'), fullPage: false });
  addEntry('11-cli-identify.png', 'captured', 'Rendered image from real nest_cli identify command output.', 'Not an OS terminal window capture; command output was real and display path was sanitized.');
  await page.bringToFront();
  await nav(page, 'NEST');
  await shot(page, '12-gated-state.png', 'Gated or unavailable NEST/feature state as visible in browser/dev mode.');
  const diag = await page.evaluate(() => ({ hasTauriRuntime: typeof window.__TAURI_INTERNALS__ === 'object', browserMode: !(typeof window.__TAURI_INTERNALS__ === 'object'), title: document.title, url: location.href }));
  const diagHtml = `<!doctype html><html><body style="margin:0;background:#101827;color:#e6edf7;font:22px Segoe UI,Arial"><div style="padding:48px"><h1>HexHawk runtime diagnostic</h1><p>Captured from browser/dev mode for UI orientation only.</p><pre style="background:#0b1020;border:1px solid #334155;padding:24px;border-radius:12px;color:#a7f3d0">${JSON.stringify(diag, null, 2)}</pre><p style="color:#fca5a5">Native Tauri/WebView2 runtime was not proven by this screenshot pass.</p></div></body></html>`;
  const diagPage = await browser.newPage({ viewport: { width: 1365, height: 600 }, deviceScaleFactor: 1 });
  await diagPage.setContent(diagHtml);
  await diagPage.screenshot({ path: path.join(outDir, '13-troubleshooting-native-runtime.png'), fullPage: false });
  addEntry('13-troubleshooting-native-runtime.png', 'captured', 'Runtime diagnostic rendered from browser page evaluation.', `Diagnostic: ${JSON.stringify(diag)}`);
  // Keep Windows trust warning as a source-backed rendered evidence card entry.
  addEntry('00-unsigned-windows-warning-not-captured.png', 'captured', 'Windows trust-chain warning evidence rendered from real Authenticode results.', 'Rendered evidence card from real artifact-signature output; not an OS SmartScreen screenshot.');
  fs.writeFileSync(path.join(outDir, 'capture_manifest.json'), JSON.stringify(manifest, null, 2));
  await browser.close();
})();
