import asyncio
import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path

import websockets

DEFAULT_OUT = Path('D:/Project/HexHawk/gui-evidence/release_hardening_native_gui_probe_latest.json')
DEFAULT_SAMPLE = 'D:/Project/HexHawk/Challenges/Gujian3.exe'


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Run packaged native GUI parity probe against an active WebView2 CDP target.')
    parser.add_argument('--output', default=str(DEFAULT_OUT), help='Path to write the probe JSON evidence file.')
    parser.add_argument('--sample', default=DEFAULT_SAMPLE, help='Sample path to inject into the Load Binary input.')
    parser.add_argument('--port', type=int, default=9223, help='Remote debugging port for WebView2 CDP.')
    return parser.parse_args()


def get_ws(port: int):
    pages = json.loads(urllib.request.urlopen(f'http://127.0.0.1:{port}/json/list', timeout=3).read().decode())
    for page in pages:
        if page.get('type') == 'page':
            return page['webSocketDebuggerUrl']
    raise RuntimeError('no page target')


async def main(args: argparse.Namespace):
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    ws = get_ws(args.port)
    results = {
        'gate': 'packaged_native_gui_export_parity_probe',
        'time': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'sample_path': args.sample,
        'remote_debug_port': args.port,
        'checks': [],
        'downloads': [],
    }
    async with websockets.connect(ws, max_size=50_000_000) as sock:
        cid = 0

        async def call(method, params=None):
            nonlocal cid
            cid += 1
            msg_id = cid
            await sock.send(json.dumps({'id': msg_id, 'method': method, 'params': params or {}}))
            while True:
                msg = json.loads(await sock.recv())
                if msg.get('id') == msg_id:
                    return msg

        async def evalv(expr, awaitp=True):
            resp = await call('Runtime.evaluate', {
                'expression': expr,
                'returnByValue': True,
                'awaitPromise': awaitp,
            })
            result = resp.get('result', {}).get('result', {})
            if 'value' in result:
                return result['value']
            if 'description' in result:
                return result['description']
            return resp

        async def wait_for(name, expr, timeout=30):
            start = time.time()
            last = None
            while time.time() - start < timeout:
                try:
                    last = await evalv(expr)
                except Exception as exc:
                    last = str(exc)
                if last:
                    results['checks'].append({'name': name, 'ok': True, 'detail': last})
                    return last
                await asyncio.sleep(0.5)
            results['checks'].append({'name': name, 'ok': False, 'detail': last})
            return None

        async def click(testid):
            expr = """
            (() => {
              const e = document.querySelector('[data-testid="%s"]');
              if (!e) return 'missing';
              if (e.disabled) return 'disabled';
              e.click();
              return 'clicked';
            })()
            """ % testid
            value = await evalv(expr)
            results['checks'].append({'name': 'click ' + testid, 'ok': value == 'clicked', 'detail': value})
            return value

        await evalv("""
        (() => {
          window.__hexhawkCapturedDownloads = [];
          const oldCreate = URL.createObjectURL.bind(URL);
          URL.createObjectURL = function(blob) {
            const id = oldCreate(blob);
            blob.text().then(text => window.__hexhawkCapturedDownloads.push({
              url: id,
              type: blob.type,
              size: blob.size,
              text: text.slice(0, 200000)
            }));
            return id;
          };
        })()
        """)

        runtime = await evalv("({hasTauriRuntime: !!window.__TAURI_INTERNALS__, browserMode: !window.__TAURI_INTERNALS__, tauriInternalsType: typeof window.__TAURI_INTERNALS__, url: location.href, title: document.title})")
        results['runtime'] = runtime
        for key, expected in [('hasTauriRuntime', True), ('browserMode', False), ('tauriInternalsType', 'object')]:
            results['checks'].append({'name': key, 'ok': runtime.get(key) == expected, 'detail': runtime.get(key)})

        await click('nav-load')
        await evalv(f"""
                (() => {{
                    const input = document.querySelector('[data-testid="load-path-input"]');
                    if (!input) return false;
                    input.value = {json.dumps(args.sample)};
                    input.dispatchEvent(new Event('input', {{ bubbles: true }}));
                    return true;
                }})()
                """)
        await click('load-apply-path')
        await asyncio.sleep(0.5)

        if await evalv("!!document.querySelector('[data-testid=\"action-inspect-file\"]')"):
            await click('action-inspect-file')
        await wait_for('metadata_present', "!!document.body.innerText.match(/SHA-256|Sections|Imports|Data Source: REAL BACKEND/)", 45)

        if await evalv("!!document.querySelector('[data-testid=\"action-run-analysis\"]')"):
            await click('action-run-analysis')
            await wait_for('verdict_or_disasm_present', "!!document.body.innerText.match(/Verdict|Threat Score|Disassembly|SUSPICIOUS|MALICIOUS|CLEAN|RAT/i)", 90)
        else:
            for testid in ['action-scan-strings', 'action-disassemble', 'action-build-cfg']:
                if await evalv("!!document.querySelector('[data-testid=\"%s\"]')" % testid):
                    await click(testid)
                    await asyncio.sleep(2)

        await click('nav-nest')
        await asyncio.sleep(1)
        nest_buttons = await evalv("Array.from(document.querySelectorAll('button,[data-testid]')).map(e=>({testid:e.getAttribute('data-testid'), text:(e.innerText||'').slice(0,100), disabled:e.disabled, state:e.getAttribute('data-nest-state')})).filter(x=>/nest|start|run|session|begin/i.test((x.testid||'')+' '+(x.text||''))).slice(0,50)")
        results['nest_buttons'] = nest_buttons
        start_testid = None
        for button in nest_buttons:
            testid = button.get('testid')
            if testid and not button.get('disabled') and ('start' in testid or 'nest' in testid):
                start_testid = testid
                break
        if start_testid:
            await click(start_testid)
            await wait_for('native_nest_completion_visible', "!!document.body.innerText.match(/final|complete|convergence|iteration|GYRE/i)", 60)
        else:
            results['checks'].append({'name': 'native_nest_start_click_ok', 'ok': False, 'detail': 'No enabled stable NEST start/session selector found'})

        await click('nav-report')
        await asyncio.sleep(1)
        report_buttons = await evalv("Array.from(document.querySelectorAll('button')).map((e,i)=>({i,text:e.innerText,disabled:e.disabled})).filter(x=>/JSON|Markdown|Export|Download|↓/.test(x.text)).slice(0,20)")
        results['report_buttons'] = report_buttons
        clicked = await evalv("(() => { const b=Array.from(document.querySelectorAll('button')).find(e=>/JSON/.test(e.innerText)); if(!b) return 'missing'; if(b.disabled) return 'disabled'; b.click(); return 'clicked'; })()")
        results['checks'].append({'name': 'report_json_export_click', 'ok': clicked == 'clicked', 'detail': clicked})
        await asyncio.sleep(2)
        downloads = await evalv("window.__hexhawkCapturedDownloads || []")
        results['downloads'] = downloads
        if downloads:
            text = downloads[-1].get('text', '')
            for marker in ['source_engine', 'gyre_is_sole_verdict_source', 'final_verdict_snapshot', 'nestEvidenceBundle', 'nest_evidence']:
                results['checks'].append({'name': 'export_contains_' + marker, 'ok': marker in text, 'detail': 'present' if marker in text else 'missing'})
            try:
                data = json.loads(text)
                results['export_top_keys'] = list(data.keys())
                results['export_verdict_classification'] = data.get('verdict', {}).get('classification')
            except Exception as exc:
                results['export_parse_error'] = str(exc)
        else:
            results['checks'].append({'name': 'export_captured', 'ok': False, 'detail': 'No Blob download captured'})

    out.write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(str(out))
    print(json.dumps({'runtime': results.get('runtime'), 'checks': results['checks']}, indent=2)[:12000])
    bad = [c for c in results['checks'] if c['name'].startswith('export_contains_') and not c['ok']]
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    parsed_args = parse_args()
    asyncio.run(main(parsed_args))
