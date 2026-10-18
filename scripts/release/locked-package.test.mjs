import { test } from 'node:test';
import assert from 'node:assert/strict';
import { lockedPackageChecksum } from './locked-package.mjs';

const checksum = 'a'.repeat(64);
const entry = `[[package]]\nname = "webview2-com-sys"\nversion = "0.38.2"\nchecksum = "${checksum}"\n`;

test('extracts the exact locked package checksum from LF Cargo.lock', () => {
  assert.equal(lockedPackageChecksum(entry, 'webview2-com-sys', '0.38.2'), checksum);
});

test('extracts the identical checksum after a Windows CRLF checkout', () => {
  assert.equal(lockedPackageChecksum(entry.replaceAll('\n', '\r\n'), 'webview2-com-sys', '0.38.2'), checksum);
});

test('rejects duplicate or missing package identities', () => {
  assert.throws(() => lockedPackageChecksum(entry + entry, 'webview2-com-sys', '0.38.2'), /Ambiguous/);
  assert.throws(() => lockedPackageChecksum(entry, 'other-package', '0.38.2'), /Ambiguous/);
});

test('rejects missing or malformed checksum without weakening identity checks', () => {
  assert.throws(() => lockedPackageChecksum(entry.replace(checksum, 'invalid'), 'webview2-com-sys', '0.38.2'), /checksum/);
  assert.throws(() => lockedPackageChecksum(entry.replace(/^checksum.*\n/m, ''), 'webview2-com-sys', '0.38.2'), /checksum/);
});
