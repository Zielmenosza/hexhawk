import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

class WindowsPackagingContract(unittest.TestCase):
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
