#!/usr/bin/env python3
"""Native WebView2/CDP proof for STRIKE HexHawk JSON trace import.

This probe assumes HexHawk is already running as a Tauri/WebView2 app with
WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS exposing a remote debugging port. It does
not start, attach to, step, continue, or execute the target binary. It only loads
an existing binary path into HexHawk's static-analysis workflow, runs static
Inspect/Disassemble actions, imports saved JSON trace fixtures, and records UI
observations.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import subprocess
import time
import traceback
import urllib.request
from pathlib import Path
from typing import Any

import websockets

ROOT = Path('D:/Project/HexHawk')
DEFAULT_SAMPLE = ROOT / 'Challenges/ch76/keygenme.exe'
DEFAULT_VALID_TRACE = ROOT / 'HexHawk/src/fixtures/traces/hexhawk-trace-valid.json'
DEFAULT_MALFORMED_TRACE = ROOT / 'HexHawk/src/fixtures/traces/hexhawk-trace-malformed.json'


def now_stamp() -> str:
    return time.strftime('%Y-%m-%d_%H%M%S', time.localtime())


def iso_now() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Probe STRIKE imported trace workflow in native Tauri/WebView2 runtime.')
    parser.add_argument('--port', type=int, default=9223, help='WebView2 remote debugging port.')
    parser.add_argument('--output', default=str(ROOT / f'gui-evidence/strike_trace_import_native_probe_{now_stamp()}.json'))
    parser.add_argument('--sample', default=str(DEFAULT_SAMPLE), help='Binary path for static inspect/disassembly only; not executed.')
    parser.add_argument('--valid-trace', default=str(DEFAULT_VALID_TRACE))
    parser.add_argument('--malformed-trace', default=str(DEFAULT_MALFORMED_TRACE))
    parser.add_argument('--screenshot-dir', default=str(ROOT / 'gui-evidence/screenshots'))
    parser.add_argument('--artifact', help='Exact packaged artifact path under proof, such as the MSI extracted by a launcher wrapper.')
    return parser.parse_args()


def git_summary() -> dict[str, Any]:
    def run(cmd: str) -> str:
        try:
            return subprocess.check_output(cmd, cwd=ROOT, shell=True, text=True, stderr=subprocess.STDOUT, timeout=20).strip()
        except Exception as exc:
            return f'ERROR: {exc}'
    return {
        'branch': run('git rev-parse --abbrev-ref HEAD'),
        'commit': run('git rev-parse HEAD'),
        'statusShort': run('git status --short'),
    }


def authenticode_status(path: Path) -> dict[str, Any]:
    ps = (
        "$sig = Get-AuthenticodeSignature -LiteralPath "
        + json.dumps(str(path))
        + "; [PSCustomObject]@{Status=[string]$sig.Status; StatusMessage=$sig.StatusMessage; "
          "SignerCertificateSubject=if($sig.SignerCertificate){$sig.SignerCertificate.Subject}else{$null}; "
          "TimeStamperCertificateSubject=if($sig.TimeStamperCertificate){$sig.TimeStamperCertificate.Subject}else{$null}} | ConvertTo-Json -Compress"
    )
    try:
        output = subprocess.check_output(
            ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps],
            cwd=ROOT,
            text=True,
            stderr=subprocess.STDOUT,
            timeout=30,
        ).strip()
        return json.loads(output)
    except Exception as exc:
        return {'status': 'Unknown', 'error': str(exc)}


def artifact_record(path_text: str | None) -> dict[str, Any] | None:
    if not path_text:
        return None
    path = Path(path_text)
    record: dict[str, Any] = {
        'path': str(path),
        'exists': path.exists(),
    }
    if path.exists():
        data = path.read_bytes()
        record.update({
            'size': path.stat().st_size,
            'mtimeUtc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(path.stat().st_mtime)),
            'sha256': hashlib.sha256(data).hexdigest(),
        })
    record['authenticode'] = authenticode_status(path) if path.exists() else {'status': 'Missing'}
    return record


def get_ws(port: int) -> tuple[str, list[dict[str, Any]]]:
    pages = json.loads(urllib.request.urlopen(f'http://127.0.0.1:{port}/json/list', timeout=5).read().decode())
    for page in pages:
        if page.get('type') == 'page':
            return page['webSocketDebuggerUrl'], pages
    raise RuntimeError(f'No page target found on CDP port {port}')


class Cdp:
    def __init__(self, sock):
        self.sock = sock
        self.cid = 0

    async def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.cid += 1
        msg_id = self.cid
        await self.sock.send(json.dumps({'id': msg_id, 'method': method, 'params': params or {}}))
        while True:
            msg = json.loads(await self.sock.recv())
            if msg.get('id') == msg_id:
                if 'error' in msg:
                    raise RuntimeError(f'CDP {method} failed: {msg["error"]}')
                return msg

    async def eval(self, expr: str, await_promise: bool = True) -> Any:
        resp = await self.call('Runtime.evaluate', {
            'expression': expr,
            'returnByValue': True,
            'awaitPromise': await_promise,
        })
        result = resp.get('result', {}).get('result', {})
        if 'value' in result:
            return result['value']
        if 'description' in result:
            return result['description']
        return result

    async def screenshot(self, path: Path) -> str:
        resp = await self.call('Page.captureScreenshot', {'format': 'png', 'captureBeyondViewport': True})
        data = resp.get('result', {}).get('data', '')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(base64.b64decode(data))
        return str(path)

    async def click_testid(self, testid: str) -> str:
        return await self.eval(f"""
        (() => {{
          const e = document.querySelector('[data-testid={json.dumps(testid)[1:-1]}]');
          if (!e) return 'missing';
          if (e.disabled) return 'disabled';
          e.click();
          return 'clicked';
        }})()
        """)

    async def wait_for(self, expr: str, timeout: float = 30, interval: float = 0.5) -> tuple[bool, Any]:
        start = time.time()
        last: Any = None
        while time.time() - start < timeout:
            try:
                last = await self.eval(expr)
                if last:
                    return True, last
            except Exception as exc:
                last = str(exc)
            await asyncio.sleep(interval)
        return False, last

    async def set_input_files(self, selector: str, files: list[str]) -> str:
        doc = await self.call('DOM.getDocument', {'depth': -1, 'pierce': True})
        root_id = doc['result']['root']['nodeId']
        node = await self.call('DOM.querySelector', {'nodeId': root_id, 'selector': selector})
        node_id = node['result'].get('nodeId')
        if not node_id:
            return 'missing'
        await self.call('DOM.setFileInputFiles', {'nodeId': node_id, 'files': files})
        # WebView2 usually fires change, but dispatch explicitly for React if needed.
        await self.eval(f"""
        (() => {{
          const input = document.querySelector({json.dumps(selector)});
          if (!input) return false;
          input.dispatchEvent(new Event('change', {{ bubbles: true }}));
          return true;
        }})()
        """)
        return 'set'


async def run_probe(args: argparse.Namespace) -> dict[str, Any]:
    out = Path(args.output)
    screenshot_dir = Path(args.screenshot_dir)
    valid_trace = Path(args.valid_trace)
    malformed_trace = Path(args.malformed_trace)
    sample = Path(args.sample)
    evidence: dict[str, Any] = {
        'generatedAt': iso_now(),
        'gate': 'strike_trace_import_native_gui_probe',
        'remoteDebugPort': args.port,
        'git': git_summary(),
        'artifact': artifact_record(args.artifact),
        'traceFixturePaths': {
            'valid': str(valid_trace),
            'validExists': valid_trace.exists(),
            'malformed': str(malformed_trace),
            'malformedExists': malformed_trace.exists(),
            'sampleBinary': str(sample),
            'sampleBinaryExists': sample.exists(),
        },
        'commandsProhibitedByScope': ['start_debug_session', 'debug_attach', 'debug_step', 'debug_continue'],
        'uiObservations': [],
        'screenshots': [],
        'checks': [],
        'validTraceImportResult': {},
        'malformedTraceImportResult': {},
        'navigationResult': {},
        'remainingUnprovenItems': [],
    }

    ws, pages = get_ws(args.port)
    evidence['cdpTargets'] = [{k: p.get(k) for k in ['id', 'type', 'url', 'title']} for p in pages]

    async with websockets.connect(ws, max_size=50_000_000) as sock:
        cdp = Cdp(sock)
        await cdp.call('Runtime.enable')
        await cdp.call('Page.enable')

        runtime = await cdp.eval("({hasTauriRuntime: !!window.__TAURI_INTERNALS__, browserMode: !window.__TAURI_INTERNALS__, tauriInternalsType: typeof window.__TAURI_INTERNALS__, url: location.href, title: document.title})")
        evidence['runtimeProof'] = runtime
        for key, expected in [('hasTauriRuntime', True), ('browserMode', False), ('tauriInternalsType', 'object')]:
            evidence['checks'].append({'name': key, 'ok': runtime.get(key) == expected, 'detail': runtime.get(key)})

        evidence['screenshots'].append(await cdp.screenshot(screenshot_dir / f'strike_trace_probe_start_{now_stamp()}.png'))

        # Ensure the dev/native proof session is allowed to reach the PRO-gated STRIKE/Debugger panel.
        # This is a UI access-tier setting only; it does not affect verdict authority or run the debugger.
        await cdp.eval("""
        (() => {
          localStorage.setItem('hexhawk.tier', 'enterprise');
          localStorage.setItem('hexhawk.activeView', 'load');
          localStorage.setItem('hexhawk.welcomeSeen', 'true');
          location.reload();
          return true;
        })()
        """)
        await asyncio.sleep(2)
        ok, detail = await cdp.wait_for("document.readyState === 'complete' && !!document.querySelector('[data-testid=\"nav-load\"]')", timeout=30)
        evidence['checks'].append({'name': 'dev_probe_enterprise_tier_seeded_for_strike_access', 'ok': ok, 'detail': detail})

        # Static-analysis setup only: apply path, inspect metadata, and disassemble.
        await cdp.click_testid('nav-load')
        await asyncio.sleep(0.5)
        set_path = await cdp.eval(f"""
        (() => {{
          const input = document.querySelector('[data-testid="load-path-input"]');
          if (!input) return 'missing';
          const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
          setter.call(input, {json.dumps(str(sample))});
          input.dispatchEvent(new Event('input', {{ bubbles: true }}));
          return input.value;
        }})()
        """)
        evidence['checks'].append({'name': 'sample_path_typed', 'ok': str(sample) in str(set_path), 'detail': set_path})
        apply_result = await cdp.click_testid('load-apply-path')
        evidence['checks'].append({'name': 'apply_binary_path_clicked', 'ok': apply_result == 'clicked', 'detail': apply_result})
        await asyncio.sleep(0.5)

        await cdp.click_testid('nav-inspect')
        inspect_click = await cdp.click_testid('action-inspect-file')
        evidence['checks'].append({'name': 'inspect_file_clicked', 'ok': inspect_click == 'clicked', 'detail': inspect_click})
        ok, detail = await cdp.wait_for("!!document.body.innerText.match(/SHA-256|File Summary|Sections|Imports/i)", timeout=45)
        evidence['checks'].append({'name': 'metadata_visible_after_static_inspect', 'ok': ok, 'detail': detail})

        disasm_click = await cdp.click_testid('action-disassemble')
        evidence['checks'].append({'name': 'disassemble_clicked_static_only', 'ok': disasm_click == 'clicked', 'detail': disasm_click})
        ok, detail = await cdp.wait_for("!!document.body.innerText.match(/0x6[0-9A-Fa-f]{2}|\\b6[0-9A-Fa-f]{2}\\b|Disassembly|Instructions/i)", timeout=60)
        evidence['checks'].append({'name': 'disassembly_visible_for_correlation', 'ok': ok, 'detail': detail})
        disasm_observation = await cdp.eval("document.body.innerText.match(/0x6[0-9A-Fa-f]{2}|\\b6[0-9A-Fa-f]{2}\\b/)?.[0] || null")
        evidence['uiObservations'].append({'name': 'firstDisassemblyAddressLike', 'value': disasm_observation})

        await cdp.click_testid('nav-debugger')
        ok, detail = await cdp.wait_for("!!document.querySelector('[data-testid=\"strike-import-trace\"]') && !!document.querySelector('[data-testid=\"strike-trace-file-input\"]')", timeout=20)
        evidence['checks'].append({'name': 'strike_import_controls_visible', 'ok': ok, 'detail': detail})
        evidence['screenshots'].append(await cdp.screenshot(screenshot_dir / f'strike_trace_probe_before_import_{now_stamp()}.png'))

        set_files = await cdp.set_input_files('[data-testid="strike-trace-file-input"]', [str(valid_trace)])
        evidence['checks'].append({'name': 'valid_trace_file_selected', 'ok': set_files == 'set', 'detail': set_files})
        ok, detail = await cdp.wait_for("!!document.querySelector('[data-testid=\"strike-imported-trace-summary\"]') && /events\s*7|functions covered|unresolved addresses|API imports/i.test(document.body.innerText)", timeout=20)
        body_after_valid = await cdp.eval("document.body.innerText")
        evidence['checks'].append({'name': 'valid_trace_summary_rendered', 'ok': ok, 'detail': detail})
        evidence['validTraceImportResult'] = {
            'summaryRendered': ok,
            'eventCountTextPresent': 'events' in body_after_valid and '7' in body_after_valid,
            'functionCoverageTextPresent': 'functions covered' in body_after_valid,
            'unresolvedTextPresent': 'unresolved addresses' in body_after_valid,
            'apiSummaryTextPresent': 'API imports' in body_after_valid,
            'bodyExcerpt': body_after_valid[:4000],
        }
        evidence['screenshots'].append(await cdp.screenshot(screenshot_dir / f'strike_trace_probe_valid_import_{now_stamp()}.png'))

        nav_click = await cdp.eval("""
        (() => {
          const root = document.querySelector('[data-testid="strike-imported-trace-events"]');
          if (!root) return 'missing-root';
          const button = Array.from(root.querySelectorAll('button')).find(b => !b.disabled);
          if (!button) return 'missing-enabled-event';
          const before = localStorage.getItem('hexhawk.activeView');
          button.click();
          return {clicked: true, text: button.innerText, before};
        })()
        """)
        await asyncio.sleep(1)
        nav_state = await cdp.eval("({activeView: localStorage.getItem('hexhawk.activeView'), bodyHasAddress: /0x6[0-9A-Fa-f]{2}|\\b6[0-9A-Fa-f]{2}\\b/i.test(document.body.innerText), selected: document.body.innerText.match(/0x6[0-9A-Fa-f]{2}|\\b6[0-9A-Fa-f]{2}\\b/)?.[0] || null})")
        evidence['navigationResult'] = {'click': nav_click, 'after': nav_state}
        evidence['checks'].append({'name': 'trace_event_click_navigated_to_disassembly', 'ok': nav_state.get('activeView') == 'disassembly' and bool(nav_state.get('bodyHasAddress')), 'detail': evidence['navigationResult']})
        evidence['screenshots'].append(await cdp.screenshot(screenshot_dir / f'strike_trace_probe_after_event_click_{now_stamp()}.png'))

        await cdp.click_testid('nav-debugger')
        ok, _ = await cdp.wait_for("!!document.querySelector('[data-testid=\"strike-trace-file-input\"]')", timeout=15)
        set_bad = await cdp.set_input_files('[data-testid="strike-trace-file-input"]', [str(malformed_trace)]) if ok else 'missing-input'
        evidence['checks'].append({'name': 'malformed_trace_file_selected', 'ok': set_bad == 'set', 'detail': set_bad})
        ok, detail = await cdp.wait_for("/Trace import failed|Malformed trace JSON/i.test(document.body.innerText)", timeout=20)
        bad_body = await cdp.eval("document.body.innerText")
        evidence['checks'].append({'name': 'malformed_trace_error_rendered', 'ok': ok, 'detail': detail})
        evidence['malformedTraceImportResult'] = {
            'errorRendered': ok,
            'bodyExcerpt': bad_body[:3000],
        }
        evidence['screenshots'].append(await cdp.screenshot(screenshot_dir / f'strike_trace_probe_malformed_import_{now_stamp()}.png'))

    evidence['pass'] = all(check.get('ok') for check in evidence['checks'] if check['name'] in {
        'hasTauriRuntime',
        'browserMode',
        'tauriInternalsType',
        'strike_import_controls_visible',
        'valid_trace_file_selected',
        'valid_trace_summary_rendered',
        'trace_event_click_navigated_to_disassembly',
        'malformed_trace_error_rendered',
    })
    if not evidence['pass']:
        evidence['remainingUnprovenItems'].append('One or more native STRIKE trace-import proof checks failed; inspect checks[] for the blocker.')
    return evidence


async def main() -> None:
    args = parse_args()
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    evidence: dict[str, Any]
    try:
        evidence = await run_probe(args)
    except Exception as exc:
        evidence = {
            'generatedAt': iso_now(),
            'gate': 'strike_trace_import_native_gui_probe',
            'pass': False,
            'blocked': True,
            'remoteDebugPort': args.port,
            'git': git_summary(),
            'artifact': artifact_record(args.artifact),
            'traceFixturePaths': {
                'valid': args.valid_trace,
                'malformed': args.malformed_trace,
                'sampleBinary': args.sample,
            },
            'blocker': str(exc),
            'traceback': traceback.format_exc(),
            'remainingUnprovenItems': ['Native WebView2/CDP proof did not complete. Do not claim native STRIKE trace import proof passed.'],
        }
    out.write_text(json.dumps(evidence, indent=2), encoding='utf-8')
    print(str(out))
    if not evidence.get('pass'):
        raise SystemExit(1)


if __name__ == '__main__':
    asyncio.run(main())
