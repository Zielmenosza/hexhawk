import asyncio
import argparse
import json
import sys
import time
import urllib.request
import hashlib
from pathlib import Path

import websockets

DEFAULT_OUT = Path('D:/Project/HexHawk/gui-evidence/release_hardening_native_gui_probe_latest.json')
DEFAULT_SAMPLE = 'D:/Project/HexHawk/Challenges/Gujian3.exe'


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Run packaged native GUI parity probe against an active WebView2 CDP target.')
    parser.add_argument('--output', default=str(DEFAULT_OUT), help='Path to write the probe JSON evidence file.')
    parser.add_argument('--sample', default=DEFAULT_SAMPLE, help='Sample path to inject into the Load Binary input.')
    parser.add_argument('--port', type=int, default=9223, help='Remote debugging port for WebView2 CDP.')
    parser.add_argument('--artifact', help='Exact packaged artifact path being probed, such as the MSI extracted by the wrapper.')
    return parser.parse_args()


def artifact_record(path_text: str | None):
    if not path_text:
        return None
    path = Path(path_text)
    record = {
        'path': str(path),
        'exists': path.exists(),
    }
    if path.exists():
        data = path.read_bytes()
        record.update({
            'size': path.stat().st_size,
            'sha256': hashlib.sha256(data).hexdigest(),
            'mtime': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(path.stat().st_mtime)),
        })
    return record


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
        'artifact': artifact_record(args.artifact),
        'assertions': {
            'aetherframe_report_packaging_required': True,
            'typed_nest_evidence_bundle_must_not_be_fabricated_by_report_export': True,
        },
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

        async def export_json(label):
            before_count = await evalv("(window.__hexhawkCapturedDownloads || []).length")
            clicked = await evalv("(() => { const b=Array.from(document.querySelectorAll('button')).find(e=>/JSON/.test(e.innerText)); if(!b) return 'missing'; if(b.disabled) return 'disabled'; b.click(); return 'clicked'; })()")
            results['checks'].append({'name': f'{label}_report_json_export_click', 'ok': clicked == 'clicked', 'detail': clicked})
            await asyncio.sleep(2)
            downloads_now = await evalv("window.__hexhawkCapturedDownloads || []")
            results['downloads'] = downloads_now
            if len(downloads_now) <= before_count:
                results['checks'].append({'name': f'{label}_export_captured', 'ok': False, 'detail': {'before': before_count, 'after': len(downloads_now)}})
                return None
            download = downloads_now[-1]
            text = download.get('text', '')
            results['checks'].append({'name': f'{label}_export_captured', 'ok': True, 'detail': {'type': download.get('type'), 'size': download.get('size')}})
            try:
                data = json.loads(text)
            except Exception as exc:
                results['checks'].append({'name': f'{label}_export_json_parse_ok', 'ok': False, 'detail': str(exc)})
                return None
            results['checks'].append({'name': f'{label}_export_json_parse_ok', 'ok': True, 'detail': list(data.keys())})
            results[f'{label}_export_top_keys'] = list(data.keys())
            results[f'{label}_export_verdict_classification'] = data.get('verdict', {}).get('classification')
            return data

        def add_semantic_export_checks(label, data, expected_enabled, expected_pass_id, expected_scope):
            if data is None:
                return
            snapshot = data.get('final_verdict_snapshot') or {}
            packaging = data.get('aetherframe_report_packaging') or {}
            nest_camel = data.get('nestEvidenceBundle', 'missing')
            nest_snake = data.get('nest_evidence_bundle', 'missing')
            status = data.get('nest_evidence_bundle_status', '')
            protected = packaging.get('protected_verdict_fields') or {}
            checks = [
                (f'{label}_source_engine_is_gyre', snapshot.get('source_engine') == 'gyre', snapshot.get('source_engine')),
                (f'{label}_gyre_sole_verdict_source', snapshot.get('gyre_is_sole_verdict_source') is True, snapshot.get('gyre_is_sole_verdict_source')),
                (f'{label}_export_contains_aetherframe_report_packaging', isinstance(packaging, dict) and bool(packaging), packaging),
                (f'{label}_aetherframe_enabled_expected', packaging.get('enabled') is expected_enabled, packaging.get('enabled')),
                (f'{label}_aetherframe_pass_id_expected', packaging.get('pass_id') == expected_pass_id, packaging.get('pass_id')),
                (f'{label}_aetherframe_mutation_scope_expected', packaging.get('mutation_scope') == expected_scope, packaging.get('mutation_scope')),
                (f'{label}_aetherframe_policy_reason_present', isinstance(packaging.get('policy_reason'), str) and bool(packaging.get('policy_reason')), packaging.get('policy_reason')),
                (f'{label}_aetherframe_protected_source_engine_gyre', protected.get('source_engine') == 'gyre', protected.get('source_engine')),
                (f'{label}_aetherframe_protected_gyre_sole_source', protected.get('gyre_is_sole_verdict_source') is True, protected.get('gyre_is_sole_verdict_source')),
                (f'{label}_aetherframe_blocks_nest_evidence_selection', 'nestEvidenceSelection' in (packaging.get('blocked_mutations') or []), packaging.get('blocked_mutations')),
                (f'{label}_aetherframe_proof_limits_present', len(packaging.get('proof_limits') or []) > 0, packaging.get('proof_limits')),
                (f'{label}_report_export_does_not_fabricate_camel_nest_bundle', nest_camel is None, nest_camel),
                (f'{label}_report_export_does_not_fabricate_snake_nest_bundle', nest_snake is None, nest_snake),
                (f'{label}_nest_bundle_status_points_to_real_nest_export', 'use NEST evidence export' in status, status),
            ]
            for name, ok, detail in checks:
                results['checks'].append({'name': name, 'ok': ok, 'detail': detail})

        enabled_export = await export_json('enabled_policy')
        add_semantic_export_checks(
            'enabled_policy',
            enabled_export,
            expected_enabled=True,
            expected_pass_id='hexhawk-report-authority-lineage-package',
            expected_scope='package',
        )

        toggle_result = await evalv("""
        (() => {
          const section = document.querySelector('[data-testid="report-aetherframe-policy"]');
          const input = section ? section.querySelector('input[type="checkbox"]') : null;
          if (!section) return 'section-missing';
          if (!input) return 'toggle-missing';
          if (input.checked) input.click();
          return input.checked ? 'still-enabled' : 'disabled';
        })()
        """)
        results['checks'].append({'name': 'disable_aetherframe_report_policy_toggle', 'ok': toggle_result == 'disabled', 'detail': toggle_result})
        disabled_export = await export_json('disabled_policy')
        add_semantic_export_checks(
            'disabled_policy',
            disabled_export,
            expected_enabled=False,
            expected_pass_id='aetherframe-disabled',
            expected_scope='none',
        )

    bad = [c for c in results['checks'] if not c.get('ok')]
    results['all_checks_ok'] = not bad
    out.write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(str(out))
    print(json.dumps({'runtime': results.get('runtime'), 'checks': results['checks']}, indent=2)[:12000])
    if bad:
        print(json.dumps({'failed_checks': bad}, indent=2)[:12000])
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    parsed_args = parse_args()
    asyncio.run(main(parsed_args))
