import json
import re
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

class WindowsPackagingContract(unittest.TestCase):
    def test_ci_runtime_meets_locked_javascript_dependencies(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        versions = re.findall(r"node-version: '([^']+)'", workflow)
        self.assertTrue(versions)
        self.assertTrue(all(version == '24' for version in versions))

    def test_ci_rust_actions_are_immutable_and_permissions_are_read_only(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        refs = re.findall(r'uses: dtolnay/rust-toolchain@([^\s]+)', workflow)
        self.assertTrue(refs)
        self.assertTrue(all(re.fullmatch(r'[a-f0-9]{40}', ref) for ref in refs))
        self.assertIn('\npermissions:\n  contents: read\n', workflow)

    def test_ci_prefetches_locked_sources_before_offline_bundle_metadata(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        windows = workflow.split('  build-windows:', 1)[1].split('  build-macos:', 1)[0]
        fetch = 'run: cargo fetch --locked'
        self.assertIn(fetch, windows)
        self.assertLess(windows.index(fetch), windows.index('run: yarn tauri:build'))
        loader = (ROOT / 'scripts/release/stage-webview2-loader.mjs').read_text()
        self.assertIn("'--locked', '--offline'", loader)

    def test_required_loader_is_not_optional(self):
        hook = (ROOT / 'src-tauri/nsis/hexhawk-runtime-payload.nsh').read_text()
        loader_lines = [line for line in hook.splitlines() if line.lstrip().startswith('File ') and 'WebView2Loader.dll' in line]
        self.assertEqual(len(loader_lines), 1)
        self.assertNotIn('/nonfatal', loader_lines[0])

    def test_loader_is_staged_by_the_official_bundle_pipeline(self):
        config = json.loads((ROOT / 'src-tauri/tauri.conf.json').read_text())
        self.assertEqual(config['build'].get('beforeBundleCommand'), 'node scripts/release/stage-webview2-loader.mjs')
        self.assertTrue((ROOT / 'scripts/release/stage-webview2-loader.mjs').is_file())

    def test_uninstall_hook_does_not_silently_destroy_evidence(self):
        hook = (ROOT / 'src-tauri/nsis/hexhawk-runtime-payload.nsh').read_text()
        destructive = [line.strip() for line in hook.splitlines() if line.strip().startswith('RMDir /r')]
        self.assertEqual(destructive, [], 'Custom hooks must not recursively purge retained evidence or unknown install-root files')

    def test_updater_is_disabled_and_mit_license_is_packaged(self):
        config = json.loads((ROOT / 'src-tauri/tauri.conf.json').read_text())
        self.assertFalse(config['bundle']['createUpdaterArtifacts'])
        self.assertNotIn('updater', config.get('plugins', {}))
        self.assertEqual(config['bundle'].get('licenseFile'), '../LICENSE')
        self.assertEqual((ROOT / 'LICENSE').read_text().splitlines()[0], 'MIT License')

if __name__ == '__main__':
    unittest.main()
