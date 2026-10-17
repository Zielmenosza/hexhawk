import { spawn } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { join } from 'node:path';

const repo = new URL('..', import.meta.url).pathname.replace(/^\/(?:([A-Za-z]:))/, '$1').replace(/\//g, process.platform === 'win32' ? '\\' : '/');
const frontend = join(repo, 'HexHawk');
const host = '127.0.0.1';
const availablePort = () => new Promise((resolve, reject) => {
  const server = createServer();
  server.once('error', reject);
  server.listen(0, host, () => {
    const address = server.address();
    server.close(error => error ? reject(error) : resolve(address.port));
  });
});
const vitePort = await availablePort();
const cdpPort = await availablePort();
const viewportWidth = Number.parseInt(process.argv[2] || '1280', 10);
const viewportHeight = Number.parseInt(process.argv[3] || '720', 10);
const baseUrl = `http://${host}:${vitePort}`;
const edgeExe = process.env.EDGE_EXE || 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const profile = join(process.env.LOCALAPPDATA || '.', 'Temp', `hexhawk-workspace-layout-${process.pid}`);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function waitFor(url, { attempts = 300, child, label, diagnostics = () => '' } = {}) {
  for (let i = 0; i < attempts; i += 1) {
    if (child?.exitCode !== null) {
      throw new Error(`${label || 'Child process'} exited with code ${child.exitCode} while waiting for ${url}\n${diagnostics()}`);
    }
    try {
      const response = await fetch(url);
      if (response.ok) return response;
    } catch {}
    await sleep(100);
  }
  throw new Error(`Timed out waiting for ${url}; ${label || 'child'} exitCode=${child?.exitCode ?? 'running'}\n${diagnostics()}`);
}

class CdpClient {
  constructor(url) {
    this.ws = new WebSocket(url);
    this.nextId = 1;
    this.pending = new Map();
  }
  async open() {
    await new Promise((resolve, reject) => {
      this.ws.addEventListener('open', resolve, { once: true });
      this.ws.addEventListener('error', reject, { once: true });
    });
    this.ws.addEventListener('message', event => {
      const message = JSON.parse(event.data);
      if (!message.id) return;
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      if (message.error) pending.reject(new Error(JSON.stringify(message.error)));
      else pending.resolve(message.result);
    });
  }
  send(method, params = {}) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }
  async evaluate(expression) {
    const result = await this.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  }
  close() { this.ws.close(); }
}

const vite = spawn(process.execPath, [join(repo, 'node_modules', 'vite', 'bin', 'vite.js'), '--host', host, '--port', String(vitePort)], {
  cwd: frontend,
  stdio: ['ignore', 'pipe', 'pipe'],
  windowsHide: true,
});
mkdirSync(profile, { recursive: true });
const edge = spawn(edgeExe, [
  '--headless=new', '--disable-gpu', '--disable-extensions', '--no-first-run',
  '--remote-allow-origins=*', `--remote-debugging-port=${cdpPort}`,
  `--user-data-dir=${profile}`, `--window-size=${viewportWidth},${viewportHeight}`, `${baseUrl}/?qa=1&qaTier=enterprise&qaView=cfg`,
], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });

let viteStderr = '';
let edgeStderr = '';
vite.stderr.on('data', chunk => { viteStderr = (viteStderr + chunk).slice(-4000); });
edge.stderr.on('data', chunk => { edgeStderr = (edgeStderr + chunk).slice(-4000); });

let client;
const failures = [];
const checks = {};

try {
  await waitFor(`${baseUrl}/`, { child: vite, label: 'Vite', diagnostics: () => viteStderr });
  await waitFor(`http://${host}:${cdpPort}/json/list`, { child: edge, label: 'Edge', diagnostics: () => edgeStderr });
  const targets = await (await fetch(`http://${host}:${cdpPort}/json/list`)).json();
  const page = targets.find(target => target.type === 'page');
  if (!page) throw new Error('No Edge page target');
  client = new CdpClient(page.webSocketDebuggerUrl);
  await client.open();
  await client.send('Runtime.enable');
  await client.send('Page.enable');
  await client.send('Emulation.setDeviceMetricsOverride', { width: viewportWidth, height: viewportHeight, deviceScaleFactor: 1, mobile: false });

  const navigate = async url => {
    await client.send('Page.navigate', { url });
    await sleep(1400);
  };
  const rectScript = selector => `(() => {
    const element = document.querySelector(${JSON.stringify(selector)});
    if (!element) return null;
    const box = element.getBoundingClientRect();
    const style = getComputedStyle(element);
    return {top:box.top,bottom:box.bottom,left:box.left,right:box.right,width:box.width,height:box.height,clientHeight:element.clientHeight,scrollHeight:element.scrollHeight,clientWidth:element.clientWidth,scrollWidth:element.scrollWidth,overflow:style.overflow,overflowY:style.overflowY};
  })()`;

  await navigate(`${baseUrl}/?qa=1&qaTier=enterprise&qaView=cfg`);
  const cfgEmpty = await client.evaluate(`(() => ({
    viewport:{width:innerWidth,height:innerHeight},
    document:{clientWidth:document.documentElement.clientWidth,scrollWidth:document.documentElement.scrollWidth},
    owner:(${rectScript('[data-testid="workspace-scroll-owner"]')}),
    root:(${rectScript('[data-testid="panel-cfg"]')}),
    button:(${rectScript('[data-testid="cfg-build-empty-state"]')})
  }))()`);
  const cfgEmptyAfterScroll = await client.evaluate(`(() => {
    const owner=document.querySelector('[data-testid="workspace-scroll-owner"]'); owner.scrollTop=owner.scrollHeight;
    const button=document.querySelector('[data-testid="cfg-build-empty-state"]'); const graph=document.querySelector('.cfg-view .react-flow');
    const buttonBox=button?.getBoundingClientRect(); const graphBox=graph?.getBoundingClientRect();
    const ownerBox=owner.getBoundingClientRect(); return {scrollTop:owner.scrollTop,button:buttonBox?{top:buttonBox.top,bottom:buttonBox.bottom}:null,graph:graphBox?{top:graphBox.top,bottom:graphBox.bottom,height:graphBox.height}:null,nodes:document.querySelectorAll('.react-flow__node').length,owner:{top:ownerBox.top,bottom:ownerBox.bottom}};
  })()`);
  checks.cfgEmpty = { cfgEmpty, cfgEmptyAfterScroll };
  if (!cfgEmpty.owner || cfgEmpty.owner.overflowY !== 'auto') failures.push('CFG does not use the primary vertical scroll owner');
  if (cfgEmpty.document.scrollWidth > cfgEmpty.document.clientWidth) failures.push('CFG creates document-level horizontal overflow');
  if (cfgEmptyAfterScroll.button && (cfgEmptyAfterScroll.button.top < cfgEmptyAfterScroll.owner.top || cfgEmptyAfterScroll.button.bottom > cfgEmptyAfterScroll.owner.bottom)) failures.push('CFG Build control is not reachable by primary scrolling');
  if (!cfgEmptyAfterScroll.button && (cfgEmptyAfterScroll.nodes < 1 || !cfgEmptyAfterScroll.graph || cfgEmptyAfterScroll.graph.height < 1)) failures.push('Initial CFG state has neither a reachable Build control nor a rendered graph');

  await navigate(`${baseUrl}/?qa=1&qaTier=enterprise&qaView=debugger`);
  const guided = await client.evaluate(`(() => {
    const owner=document.querySelector('[data-testid="workspace-scroll-owner"]');
    const root=document.createElement('div'); root.className='stk-root'; root.dataset.workspaceRoot='flow'; root.dataset.layoutHarness='guided';
    const finder=document.createElement('section'); finder.className='vf-root'; finder.dataset.workspaceSection='flow';
    finder.innerHTML='<div class="stk-pane-title">Guided Value Finder · layout harness</div><p class="pkt-subtitle">Tall future-safe form.</p>' + Array.from({length:32},(_,i)=>'<label class="vf-authorized"><input type="checkbox">Authorization row '+i+' remains reachable.</label>').join('');
    root.appendChild(finder); owner.appendChild(root);
    const before=finder.getBoundingClientRect(); const last=finder.lastElementChild.getBoundingClientRect(); const style=getComputedStyle(finder);
    owner.scrollTop=owner.scrollHeight;
    const after=finder.getBoundingClientRect(); const lastAfter=finder.lastElementChild.getBoundingClientRect(); const ownerBox=owner.getBoundingClientRect();
    return {owner:{clientHeight:owner.clientHeight,scrollHeight:owner.scrollHeight,scrollTop:owner.scrollTop,top:ownerBox.top,bottom:ownerBox.bottom},finder:{clientHeight:finder.clientHeight,scrollHeight:finder.scrollHeight,overflow:style.overflow,beforeBottom:before.bottom,afterBottom:after.bottom},last:{beforeBottom:last.bottom,afterBottom:lastAfter.bottom}};
  })()`);
  checks.guided = guided;
  if (guided.finder.overflow !== 'visible' || guided.finder.scrollHeight > guided.finder.clientHeight + 1) failures.push('Guided Value Finder clips its own flow content');
  if (!guided.owner.scrollTop || guided.last.afterBottom > guided.owner.bottom + 1 || guided.last.afterBottom < guided.owner.top) failures.push('Guided Value Finder bottom is not reachable through primary scrolling');

  const modal = await client.evaluate(`(() => {
    const backdrop=document.createElement('div'); backdrop.className='vf-process-picker-backdrop';
    backdrop.innerHTML='<div class="vf-process-picker" role="dialog" aria-modal="true"><div class="vf-process-picker-header"><strong>Choose a running process</strong><button class="stk-btn">Close</button></div><input class="stk-bp-field" aria-label="filter running processes"><div class="vf-process-list"></div></div>';
    const list=backdrop.querySelector('.vf-process-list'); list.innerHTML=Array.from({length:120},(_,i)=>'<button class="vf-process-row"><span>process-'+i+'.exe</span><span>PID '+(1000+i)+'</span></button>').join(''); document.body.appendChild(backdrop);
    const box=selector=>{const e=document.querySelector(selector),b=e.getBoundingClientRect();return{top:b.top,bottom:b.bottom,left:b.left,right:b.right,clientHeight:e.clientHeight,scrollHeight:e.scrollHeight}};
    return {viewport:{width:innerWidth,height:innerHeight},dialog:box('.vf-process-picker'),close:box('.vf-process-picker-header button'),filter:box('.vf-process-picker input'),list:box('.vf-process-list')};
  })()`);
  checks.modal = modal;
  if (modal.dialog.top < 0 || modal.dialog.bottom > modal.viewport.height || modal.close.bottom > modal.viewport.height || modal.filter.bottom > modal.viewport.height) failures.push('Process modal fixed controls leave the viewport');
  if (modal.list.scrollHeight <= modal.list.clientHeight) failures.push('Process modal long list is not locally scrollable');

  await client.evaluate(`document.querySelector('.vf-process-picker-backdrop')?.remove(); document.querySelector('[data-layout-harness="guided"]')?.remove(); document.querySelector('[data-testid="nav-load"]')?.click()`);
  await sleep(100);
  await client.evaluate(`(() => {const input=document.querySelector('[data-testid="load-path-input"]'); const setter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set; setter.call(input,'D:/Samples/workspace-layout.exe'); input.dispatchEvent(new Event('input',{bubbles:true})); input.dispatchEvent(new Event('change',{bubbles:true})); document.querySelector('[data-testid="load-apply-path"]')?.click();})()`);
  await sleep(250);
  await client.evaluate(`document.querySelector('[data-testid="nav-inspect"]')?.click()`); await sleep(500);
  await client.evaluate(`document.querySelector('[data-testid="nav-disassembly"]')?.click()`); await sleep(250);
  await client.evaluate(`document.querySelector('[data-testid="workspace-tab-cfg"]')?.click()`); await sleep(900);
  const populated = await client.evaluate(`(() => {const owner=document.querySelector('[data-testid="workspace-scroll-owner"]'); owner.scrollTop=owner.scrollHeight; const graph=document.querySelector('.cfg-view .react-flow')?.getBoundingClientRect(); const ownerBox=owner.getBoundingClientRect(); return {nodes:document.querySelectorAll('.react-flow__node').length,owner:{top:ownerBox.top,bottom:ownerBox.bottom,scrollTop:owner.scrollTop},graph:graph?{top:graph.top,bottom:graph.bottom,height:graph.height}:null};})()`);
  checks.cfgPopulated = populated;
  if (populated.nodes < 1 || !populated.graph || populated.graph.height < 1 || populated.graph.top < populated.owner.top - 1 || populated.graph.bottom > populated.owner.bottom + 1) failures.push('Populated CFG is not reachable inside the primary scroll owner');

  console.log(JSON.stringify({ viewport: `${viewportWidth}x${viewportHeight}`, checks, failures }, null, 2));
  if (failures.length) process.exitCode = 1;
} finally {
  if (client) {
    try { await client.send('Browser.close'); } catch {}
    client.close();
  }
  await sleep(300);
  if (edge.exitCode === null) edge.kill();
  if (vite.exitCode === null) vite.kill();
  await sleep(300);
  try { rmSync(profile, { recursive: true, force: true }); } catch {}
}
