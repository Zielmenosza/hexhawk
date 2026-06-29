"""Installed native HexHawk AI workflow CDP probe.

This is QA/probe-support tooling, not production app code. It connects to an
already-launched installed Tauri/WebView2 HexHawk instance through CDP, drives
the AI Observations / Agent Gate / Function Notebook workflow, and writes local
evidence under OUTDIR. The assertions preserve GYRE authority boundaries: AI and
AETHERFRAME output must remain advisory and must not mutate verdict fields.

Local-development defaults can be overridden with INSTALL_DIR, CDP_PORT, and
OUTDIR.
"""

import base64
import hashlib
import json
import os
import pathlib
import socket
import struct
import time
import urllib.request
from datetime import datetime, timezone

CDP_PORT = int(os.environ.get('CDP_PORT', '9500'))
INSTALL_DIR = pathlib.Path(os.environ.get('INSTALL_DIR', r'D:\Project\HexHawk-ai-probe-install'))
TEST_BINARY = INSTALL_DIR / 'nest_cli.exe'
OUTDIR = pathlib.Path(os.environ.get('OUTDIR', r'D:\Project\HexHawk-ai-probe-results'))
OUTDIR.mkdir(parents=True, exist_ok=True)

EXPECTED_TESTIDS = set('''activity-event-code
activity-item
activity-list
agent-gate-panel
ai-insight-empty
ai-insight-panel
analyst-prompt-card
authority-banner
autoheal-banner
cfg-build-empty-state
decompiler-maturity-telemetry
disassembly-scrollport
disassembly-subtabbar
feature-guide-card
first-run-browse
first-run-panel
function-notebook
hexhawk-context-menu
load-apply-path
load-browse
load-path-input
nav-open-file
panel-about
panel-activity
panel-agent
panel-ai-observations
panel-cfg
panel-decompile
panel-disassembly
panel-fidelity-badge
panel-function-notebook
panel-help
panel-history
panel-inspect
panel-load
panel-metadata
panel-nest
panel-plugins
panel-repl
panel-report
panel-strike-api
panel-strings
panel-talon
plugins-run
qa-source-matrix
report-aetherframe-policy
status-export
status-jump
status-qa-sources
status-shortcuts
strike-api-search
strike-import-trace
strike-imported-trace-events
strike-imported-trace-summary
strike-trace-file-input
strike-trace-warning-list
strings-scan
workspace-tabbar
xref-panel'''.split())

class CDP:
    def __init__(self, url):
        assert url.startswith('ws://')
        rest = url[len('ws://'):]
        hostport, path = rest.split('/', 1)
        if ':' in hostport:
            host, port = hostport.split(':', 1)
            port = int(port)
        else:
            host, port = hostport, 80
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.settimeout(30)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f'GET /{path} HTTP/1.1\r\n'
            f'Host: {hostport}\r\n'
            'Upgrade: websocket\r\n'
            'Connection: Upgrade\r\n'
            f'Sec-WebSocket-Key: {key}\r\n'
            'Sec-WebSocket-Version: 13\r\n\r\n'
        )
        self.sock.sendall(req.encode())
        resp = b''
        while b'\r\n\r\n' not in resp:
            resp += self.sock.recv(4096)
        if b' 101 ' not in resp.split(b'\r\n', 1)[0]:
            raise RuntimeError(f'WebSocket handshake failed: {resp[:200]!r}')
        self.next_id = 1
        self.events = []

    def _send_frame(self, text):
        payload = text.encode('utf-8')
        first = 0x81
        mask_bit = 0x80
        n = len(payload)
        if n < 126:
            header = bytes([first, mask_bit | n])
        elif n < (1 << 16):
            header = bytes([first, mask_bit | 126]) + struct.pack('!H', n)
        else:
            header = bytes([first, mask_bit | 127]) + struct.pack('!Q', n)
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(header + mask + masked)

    def _recv_exact(self, n):
        chunks = []
        got = 0
        while got < n:
            chunk = self.sock.recv(n - got)
            if not chunk:
                raise RuntimeError('socket closed')
            chunks.append(chunk)
            got += len(chunk)
        return b''.join(chunks)

    def _recv_frame(self):
        b1, b2 = self._recv_exact(2)
        opcode = b1 & 0x0f
        masked = bool(b2 & 0x80)
        length = b2 & 0x7f
        if length == 126:
            length = struct.unpack('!H', self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack('!Q', self._recv_exact(8))[0]
        mask = self._recv_exact(4) if masked else b''
        payload = self._recv_exact(length) if length else b''
        if masked:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        if opcode == 8:
            raise RuntimeError('websocket closed')
        if opcode == 9:
            self._send_pong(payload)
            return self._recv_frame()
        if opcode != 1:
            return self._recv_frame()
        return json.loads(payload.decode('utf-8'))

    def _send_pong(self, payload):
        first = 0x8A
        n = len(payload)
        mask_bit = 0x80
        header = bytes([first, mask_bit | n])
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(header + mask + masked)

    def call(self, method, params=None, timeout=30):
        msg_id = self.next_id
        self.next_id += 1
        self._send_frame(json.dumps({'id': msg_id, 'method': method, 'params': params or {}}))
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = self._recv_frame()
            if msg.get('id') == msg_id:
                if 'error' in msg:
                    raise RuntimeError(f'CDP {method} error: {msg["error"]}')
                return msg.get('result', {})
            self.events.append(msg)
        raise TimeoutError(method)

    def eval(self, expr, timeout=30):
        res = self.call('Runtime.evaluate', {
            'expression': expr,
            'awaitPromise': True,
            'returnByValue': True,
            'userGesture': True,
        }, timeout=timeout)
        if 'exceptionDetails' in res:
            raise RuntimeError(json.dumps(res['exceptionDetails'], ensure_ascii=False))
        return res.get('result', {}).get('value')


def page_ws_url():
    pages = json.loads(urllib.request.urlopen(f'http://127.0.0.1:{CDP_PORT}/json/list', timeout=3).read())
    page = next((p for p in pages if p.get('type') == 'page'), pages[0])
    return page['webSocketDebuggerUrl'], pages


def js_string(s):
    return json.dumps(str(s))


def wait_eval(cdp, condition_expr, timeout=30, interval=0.5, description='condition'):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            val = cdp.eval(condition_expr, timeout=5)
            last = val
            if val:
                return val
        except Exception as e:
            last = repr(e)
        time.sleep(interval)
    raise TimeoutError(f'timeout waiting for {description}; last={last!r}')


def click(cdp, selector=None, text=None, contains=False):
    if selector:
        expr = f"""(() => {{
          const el = document.querySelector({js_string(selector)});
          if (!el) return {{ok:false, reason:'missing selector', selector:{js_string(selector)}}};
          el.scrollIntoView({{block:'center', inline:'center'}});
          el.click();
          return {{ok:true, text:el.textContent, selector:{js_string(selector)}}};
        }})()"""
    else:
        pred = 'includes' if contains else 'trim_eq'
        expr = f"""(() => {{
          const needle = {js_string(text)};
          const els = Array.from(document.querySelectorAll('button, [role="button"], a'));
          const el = els.find(e => {('e.textContent.includes(needle)' if contains else 'e.textContent.trim() === needle')});
          if (!el) return {{ok:false, reason:'missing text', text:needle, buttons:els.map(e=>e.textContent.trim()).filter(Boolean).slice(0,50)}};
          el.scrollIntoView({{block:'center', inline:'center'}});
          el.click();
          return {{ok:true, text:el.textContent}};
        }})()"""
    out = cdp.eval(expr)
    if not out or not out.get('ok'):
        raise RuntimeError(f'click failed: {out}')
    return out


def screenshot(cdp, name):
    path = OUTDIR / name
    data = cdp.call('Page.captureScreenshot', {'format': 'png', 'captureBeyondViewport': False}, timeout=20).get('data')
    path.write_bytes(base64.b64decode(data))
    return str(path)


def all_console_text(cdp):
    texts = []
    for ev in cdp.events:
        m = ev.get('method')
        p = ev.get('params', {})
        if m == 'Runtime.consoleAPICalled':
            vals = []
            for a in p.get('args', []):
                vals.append(str(a.get('value', a.get('description', ''))))
            texts.append(' '.join(vals))
        elif m == 'Runtime.exceptionThrown':
            texts.append(json.dumps(p.get('exceptionDetails', {}), ensure_ascii=False))
        elif m == 'Log.entryAdded':
            texts.append(str(p.get('entry', {})))
    return '\n'.join(texts)


def main():
    result = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'cdp_port': CDP_PORT,
        'install_dir': str(INSTALL_DIR),
        'test_binary': str(TEST_BINARY),
        'steps': [],
        'discrepancies': {},
    }
    def step(name, ok, detail=None):
        result['steps'].append({'name': name, 'ok': bool(ok), 'detail': detail or {}})
        print(('PASS ' if ok else 'FAIL ') + name, json.dumps(detail or {}, ensure_ascii=False)[:1000])

    ws, pages = page_ws_url()
    result['cdp_pages'] = pages
    cdp = CDP(ws)
    cdp.call('Runtime.enable')
    cdp.call('Page.enable')
    try:
        cdp.call('Log.enable')
    except Exception:
        pass

    # Step 1
    s1 = cdp.eval("(() => ({title: document.title, tauri: typeof window.__TAURI_INTERNALS__, url: location.href}))()")
    step('Step 1 Tauri runtime', s1.get('title') and 'HexHawk' in s1.get('title','') and s1.get('tauri') != 'undefined', s1)

    # Step 2: dismiss WelcomeScreen overlay if present, then handle first-run panel by typed path.
    welcome = cdp.eval("(() => ({overlay: !!document.querySelector('.welcome-overlay'), text: document.querySelector('.welcome-overlay')?.textContent?.slice(0,200) || ''}))()")
    if welcome.get('overlay'):
        cdp.eval("(() => { const btn = Array.from(document.querySelectorAll('button')).find(b => b.textContent.trim() === 'Skip intro'); if (btn) btn.click(); return !!btn; })()")
        time.sleep(0.5)
    try:
        click(cdp, '[data-testid="nav-load"]')
    except Exception as e:
        result['nav_load_error'] = repr(e)
    time.sleep(0.5)
    first = cdp.eval("(() => ({welcomeOverlayAfter: !!document.querySelector('.welcome-overlay'), present: !!document.querySelector('[data-testid=first-run-panel]'), browse: !!document.querySelector('[data-testid=first-run-browse]')}))()").copy()
    first['welcomeOverlayBefore'] = welcome
    step('Step 2 first-run handled by typed path', not first.get('welcomeOverlayAfter'), first)

    # Step 3 live data-testid enumeration.
    live_ids = cdp.eval("Array.from(new Set(Array.from(document.querySelectorAll('[data-testid]')).map(e=>e.getAttribute('data-testid')))).sort()")
    missing_from_live = sorted(EXPECTED_TESTIDS - set(live_ids))
    extra_live = sorted(set(live_ids) - EXPECTED_TESTIDS)
    result['live_testids'] = live_ids
    result['discrepancies'] = {'expected_not_live_initial': missing_from_live, 'live_not_phase0_static': extra_live}
    step('Step 3 live data-testid enumeration', True, {'live_count': len(live_ids), 'expected_not_live_initial_count': len(missing_from_live), 'live_not_phase0_static': extra_live[:20]})

    # Step 4 set path.
    test_path = str(TEST_BINARY)
    if not TEST_BINARY.exists():
        step('Step 4 set file path', False, {'error': 'test binary missing'})
        raise SystemExit(2)
    click(cdp, '[data-testid="nav-load"]')
    wait_eval(cdp, "!!document.querySelector('[data-testid=load-path-input]')", 10, description='load path input')
    set_res = cdp.eval(f"""(() => {{
      const input = document.querySelector('[data-testid=load-path-input]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
      setter.call(input, {js_string(test_path)});
      input.dispatchEvent(new Event('input', {{ bubbles: true }}));
      input.dispatchEvent(new Event('change', {{ bubbles: true }}));
      return {{value: input.value}};
    }})()""")
    click(cdp, '[data-testid="load-apply-path"]')
    wait_eval(cdp, "!!document.querySelector('[data-testid=action-inspect-file]') && !document.querySelector('[data-testid=action-inspect-file]').disabled", 10, description='inspect action')
    step('Step 4 set file path', True, set_res)

    # Step 5 inspect.
    before_events = len(cdp.events)
    click(cdp, '[data-testid="action-inspect-file"]')
    try:
        inspect_state = wait_eval(cdp, "(() => { const body=document.body.textContent; return !!document.querySelector('[data-testid=panel-inspect]') || body.includes('Failed to inspect file') || body.includes('T.split is not a function') || body.includes('TypeError'); })()", 30, description='inspect finish')
    except Exception as e:
        console = all_console_text(cdp)
        step('Step 5 Inspect', False, {'error': repr(e), 'console': console[-2000:]})
        raise
    body = cdp.eval("document.body.textContent.slice(0, 20000)")
    console = all_console_text(cdp)
    inspect_failed = ('Failed to inspect file' in body) or ('T.split is not a function' in body) or ('TypeError' in body) or ('T.split is not a function' in console) or ('TypeError' in console)
    if inspect_failed:
        step('Step 5 Inspect', False, {'status': 'INSPECT_FAILED', 'body_error_excerpt': body[-2000:], 'console_excerpt': console[-2000:]})
        result['phase4a_required'] = True
        (OUTDIR / 'probe-result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        return 1
    file_facts = cdp.eval("(() => { const p=document.querySelector('[data-testid=panel-inspect]'); return p ? p.textContent.slice(0,1000) : null; })()")
    step('Step 5 Inspect', True, {'panel_inspect': bool(file_facts), 'excerpt': file_facts})

    # Step 6 disassemble.
    wait_eval(cdp, "!!document.querySelector('[data-testid=action-disassemble]')", 15, description='disassemble action')
    click(cdp, '[data-testid="action-disassemble"]')
    wait_eval(cdp, "document.querySelectorAll('.disassembly-instruction').length > 0 || document.querySelectorAll('[data-testid=disassembly-scrollport] .disassembly-instruction').length > 0", 45, description='disassembly rows')
    disasm_count = cdp.eval("document.querySelectorAll('.disassembly-instruction').length")
    step('Step 6 Disassembly', disasm_count > 0, {'visible_instruction_rows': disasm_count})

    # Step 7 AI observations.
    click(cdp, '[data-testid="nav-ai-observations"]')
    wait_eval(cdp, "!!document.querySelector('[data-testid=ai-insight-panel]')", 15, description='AI insight panel')
    ai = cdp.eval("(() => { const cards=Array.from(document.querySelectorAll('.ai-observation-card')); const empty=!!document.querySelector('[data-testid=ai-insight-empty]'); return {cards:cards.length, empty, firstTitle: cards[0]?.querySelector('h3')?.textContent || null, text: document.querySelector('[data-testid=ai-insight-panel]')?.textContent.slice(0,3000)}; })()")
    cdp.eval("""(() => {
      const el = document.querySelector('.ai-observation-card') || document.querySelector('[data-testid=ai-insight-empty]') || document.querySelector('[data-testid=ai-insight-panel]');
      if (!el) return false;
      let p = el.parentElement;
      while (p) {
        if (p.scrollHeight > p.clientHeight) p.scrollTop = Math.max(0, el.offsetTop - p.offsetTop - 40);
        p = p.parentElement;
      }
      el.scrollIntoView({block:'start', inline:'nearest'});
      window.scrollBy(0, -80);
      return true;
    })()""")
    time.sleep(0.5)
    ai_shot = screenshot(cdp, 'ai-insight-panel.png')
    result['ai_screenshot'] = ai_shot
    step('Step 7 AI Observations', bool(ai and (ai.get('cards',0) > 0 or ai.get('empty'))), ai)

    # Step 8 Code map / function selection.
    click(cdp, '[data-testid="nav-disassembly"]')
    wait_eval(cdp, "document.querySelectorAll('.disassembly-instruction').length > 0", 20, description='code map rows')
    first_click = cdp.eval("(() => { const row=document.querySelector('.disassembly-instruction'); if (!row) return {ok:false}; row.scrollIntoView({block:'center'}); row.click(); return {ok:true, text: row.textContent.slice(0,300)}; })()")
    click(cdp, '[data-testid="nav-function-notebook"]')
    wait_eval(cdp, "!!document.querySelector('[data-testid=function-notebook]')", 20, description='function notebook')
    step('Step 8 Select function / open notebook', bool(first_click.get('ok')), first_click)

    # Step 9 summary.
    summary = cdp.eval("(() => { const panel=document.querySelector('[data-testid=function-notebook]'); const text=panel?.textContent || ''; const headings=Array.from(panel?.querySelectorAll('h3,h4,p,strong,li')||[]).map(e=>e.textContent.trim()).filter(Boolean); const one = Array.from(panel?.querySelectorAll('.function-summary-card strong')||[])[0]?.textContent || null; return {hasWhat:text.includes('What this function does'), hasAdvisory:/advisory,? not a verdict|Advisory only/i.test(text), hasKeyOps:text.includes('Key operations'), oneLiner: one, text:text.slice(0,3000), headings: headings.slice(0,30)}; })()")
    cdp.eval("""(() => {
      for (const sel of ['[data-testid=analyst-prompt-card]', '.feature-guide-card']) {
        const node = document.querySelector(sel);
        if (node) node.style.display = 'none';
      }
      const shell = document.querySelector('[data-testid=panel-function-notebook]');
      if (shell) shell.scrollTop = 0;
      const el = document.querySelector('.function-summary-card') || document.querySelector('[data-testid=function-notebook]');
      if (!el) return false;
      let p = el.parentElement;
      while (p) {
        if (p.scrollHeight > p.clientHeight) p.scrollTop = Math.max(0, el.offsetTop - p.offsetTop - 10);
        p = p.parentElement;
      }
      el.scrollIntoView({block:'center', inline:'nearest'});
      return true;
    })()""")
    time.sleep(0.5)
    fn_shot = screenshot(cdp, 'function-notebook-summary.png')
    result['function_notebook_screenshot'] = fn_shot
    step('Step 9 Function summary', summary.get('hasWhat') and summary.get('hasAdvisory'), summary)

    # Step 10 Agent Gate.
    click(cdp, '[data-testid="nav-agent"]')
    wait_eval(cdp, "!!document.querySelector('[data-testid=agent-gate-panel]') || !!document.querySelector('[data-testid=panel-agent]')", 20, description='agent gate panel')
    gate = cdp.eval("(() => { const panel=document.querySelector('[data-testid=agent-gate-panel]') || document.querySelector('[data-testid=panel-agent]'); const text=panel?.textContent || ''; const items=Array.from(panel?.querySelectorAll('.agent-proposal-card,.agent-signal-item') || []); const proposalCount = items.filter(x=>x.classList.contains('agent-proposal-card')).length; return {rendered:!!panel, proposalCount, firstProposalTitle: items[0]?.querySelector('h4')?.textContent || null, boundaryVisible:/Does not affect GYRE verdict|does not affect GYRE verdict|does not change the GYRE verdict/i.test(text), emptyState:text.includes('No pending AI suggestions.'), text:text.slice(0,3000)}; })()")
    step('Step 10 Agent Gate', gate.get('rendered') and (gate.get('proposalCount', 0) > 0 or gate.get('emptyState')), gate)

    # Step 11 export JSON from Function Notebook, intercept blob URL.
    click(cdp, '[data-testid="nav-function-notebook"]')
    wait_eval(cdp, "!!document.querySelector('[data-testid=function-notebook]')", 15, description='function notebook before export')
    cdp.eval("""(() => {
      window.__hexhawkCapturedDownloads = [];
      if (!window.__hexhawkOldCreateObjectURL) {
        window.__hexhawkOldCreateObjectURL = URL.createObjectURL.bind(URL);
      }
      URL.createObjectURL = function(blob) {
        const id = window.__hexhawkOldCreateObjectURL(blob);
        blob.text().then(text => window.__hexhawkCapturedDownloads.push({type: blob.type, text}));
        return id;
      };
      return true;
    })()""")
    click(cdp, text='Export JSON')
    wait_eval(cdp, "window.__hexhawkCapturedDownloads && window.__hexhawkCapturedDownloads.length > 0", 15, description='captured export')
    dl = cdp.eval("window.__hexhawkCapturedDownloads[window.__hexhawkCapturedDownloads.length-1]")
    export_text = dl.get('text')
    (OUTDIR / 'function-notebook-export.json').write_text(export_text, encoding='utf-8')
    step('Step 11 Export JSON downloaded', bool(export_text), {'type': dl.get('type'), 'chars': len(export_text or '')})

    # Step 12 JSON assertions.
    exported = json.loads(export_text)
    export_str = json.dumps(exported)
    assertions = {
        'export_schema': exported.get('export_schema') == 'hexhawk.function_intelligence.v1',
        'gyre_is_sole_verdict_authority': exported.get('gyre_is_sole_verdict_authority') is True,
        'advisory_analysis_only': exported.get('advisory_analysis_only') is True,
        'ai_contributions_present': isinstance(exported.get('ai_contributions'), dict),
        'ai_did_not_affect_verdict': exported.get('ai_contributions', {}).get('ai_did_not_affect_verdict') is True,
        'no_top_level_classification': 'classification' not in exported,
        'no_threatScore_any_depth': 'threatScore' not in export_str,
    }
    step('Step 12 JSON assertions', all(assertions.values()), assertions)

    result['console_excerpt_tail'] = all_console_text(cdp)[-4000:]
    all_ok = all(s['ok'] for s in result['steps'])
    result['all_ok'] = all_ok
    (OUTDIR / 'probe-result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    return 0 if all_ok else 1

if __name__ == '__main__':
    raise SystemExit(main())
