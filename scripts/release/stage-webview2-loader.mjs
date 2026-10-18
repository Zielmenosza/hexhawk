// Windows x64 packaging only: stage the loader from the exact locked crate.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { readBoundedFileSync } from './bounded-file.mjs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

if (process.platform !== 'win32' || process.arch !== 'x64') throw new Error('This release is qualified only for Windows x64.');
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const metadata = JSON.parse(execFileSync('cargo', ['metadata', '--locked', '--offline', '--format-version', '1'], { cwd: root, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 }));
const packages = metadata.packages.filter(p => p.name === 'webview2-com-sys');
if (packages.length !== 1) throw new Error(`Expected exactly one locked webview2-com-sys package, found ${packages.length}.`);
const pkg = packages[0];
const packageRoot = dirname(pkg.manifest_path);
const relative = 'x64/WebView2Loader.dll';
const source = join(packageRoot, relative);
const bytes = readBoundedFileSync(source, 4 * 1024 * 1024);
const sha256 = createHash('sha256').update(bytes).digest('hex');
// Modern Cargo caches need not retain per-file checksum metadata. Verify the
// registry archive against Cargo.lock, then compare the exact archive member.
const lockEntries = readFileSync(join(root, 'Cargo.lock'), 'utf8').split('[[package]]')
  .filter(block => block.includes(`\nname = "${pkg.name}"\n`) && block.includes(`\nversion = "${pkg.version}"\n`));
if (lockEntries.length !== 1) throw new Error('Ambiguous locked WebView2 package.');
const packageChecksum = lockEntries[0].match(/\nchecksum = "([a-f0-9]{64})"/u)?.[1];
if (!packageChecksum) throw new Error('Locked registry archive checksum is missing.');
const archivePath = resolve(packageRoot, '../../../cache', basename(dirname(packageRoot)), `${pkg.name}-${pkg.version}.crate`);
const archive = readBoundedFileSync(archivePath, 16 * 1024 * 1024);
if (archive.length > 16 * 1024 * 1024 || createHash('sha256').update(archive).digest('hex') !== packageChecksum) throw new Error('Registry archive does not match Cargo.lock.');
const tar = gunzipSync(archive, { maxOutputLength: 64 * 1024 * 1024 });
const expectedMember = `${pkg.name}-${pkg.version}/${relative}`;
const members = [];
for (let offset = 0; offset + 512 <= tar.length;) {
  const header = tar.subarray(offset, offset + 512);
  if (header.every(byte => byte === 0)) break;
  const text = (start, end) => header.subarray(start, end).toString('utf8').split('\0')[0];
  const name = [text(345, 500), text(0, 100)].filter(Boolean).join('/');
  const sizeText = text(124, 136).trim();
  if (!/^[0-7]+$/u.test(sizeText)) throw new Error('Unsupported archive entry length.');
  const size = Number.parseInt(sizeText, 8);
  const start = offset + 512;
  if (start + size > tar.length) throw new Error('Truncated registry archive entry.');
  if (name === expectedMember && (header[156] === 0 || header[156] === 48)) members.push(tar.subarray(start, start + size));
  offset = start + Math.ceil(size / 512) * 512;
}
if (members.length !== 1 || createHash('sha256').update(members[0]).digest('hex') !== sha256) throw new Error('Loader differs from the exact locked archive member.');
const pe = bytes.length >= 64 ? bytes.readUInt32LE(0x3c) : bytes.length;
if (bytes.subarray(0, 2).toString() !== 'MZ' || pe + 26 > bytes.length
  || bytes.subarray(pe, pe + 4).toString() !== 'PE\0\0'
  || bytes.readUInt16LE(pe + 4) !== 0x8664
  || !(bytes.readUInt16LE(pe + 22) & 0x2000)
  || bytes.readUInt16LE(pe + 24) !== 0x20b) throw new Error('Expected an AMD64 PE32+ DLL loader.');
const destination = join(metadata.target_directory, 'release', 'WebView2Loader.dll');
mkdirSync(dirname(destination), { recursive: true });
let existing;
try {
  existing = readBoundedFileSync(destination, 4 * 1024 * 1024);
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
  // Publish exactly the bytes validated above; never reopen the source path.
  // Refuse a concurrently created destination rather than overwriting it.
  writeFileSync(destination, bytes, { flag: 'wx' });
}
if (existing && createHash('sha256').update(existing).digest('hex') !== sha256) {
  throw new Error('A different release loader already exists; preserve it before rebuilding.');
}
if (createHash('sha256').update(readBoundedFileSync(destination, 4 * 1024 * 1024)).digest('hex') !== sha256) throw new Error('Staged loader readback failed.');
const receipt = { schema: 'hexhawk.loader-custody.v1', package: pkg.name, version: pkg.version, registry_package_sha256: packageChecksum, archivePath, source, destination, sha256, bytes: bytes.length, architecture: 'AMD64', checksum_verified: true };
writeFileSync(join(dirname(destination), 'WebView2Loader.custody.json'), JSON.stringify(receipt, null, 2));
console.log(JSON.stringify(receipt));
