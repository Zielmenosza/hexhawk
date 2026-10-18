import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { readBoundedFileSync, writeFileAtomicSync } from './bounded-file.mjs';

function fixture(run) {
  const root = fs.mkdtempSync(join(process.env.TMPDIR || tmpdir(), 'hexhawk-bounded-'));
  try { run(root); } finally { mock.restoreAll(); fs.rmSync(root, { recursive: true, force: true }); }
}

test('reads empty/exact-limit files and rejects one byte over budget', () => fixture(root => {
  const file = join(root, 'input');
  fs.writeFileSync(file, '');
  assert.equal(readBoundedFileSync(file, 0).length, 0);
  fs.writeFileSync(file, 'abcd');
  assert.equal(readBoundedFileSync(file, 4).toString(), 'abcd');
  assert.throws(() => readBoundedFileSync(file, 3), /budget/);
  assert.throws(() => readBoundedFileSync(file, -1), /budget/);
}));

test('reads the opened file, not a replacement path after descriptor validation', () => fixture(root => {
  const file = join(root, 'input');
  fs.writeFileSync(file, 'original');
  const fstat = fs.fstatSync;
  const hook = mock.method(fs, 'fstatSync', fd => {
    const stat = fstat(fd);
    fs.renameSync(file, file + '.old');
    fs.writeFileSync(file, 'replaced');
    return stat;
  });
  assert.equal(readBoundedFileSync(file, 8).toString(), 'original');
  hook.mock.restore();
  assert.equal(fs.readFileSync(file, 'utf8'), 'replaced');
}));

test('rejects growth after validation and closes its descriptor on rejection', () => fixture(root => {
  const file = join(root, 'input');
  fs.writeFileSync(file, 'abcd');
  const fstat = fs.fstatSync;
  let descriptor;
  const hook = mock.method(fs, 'fstatSync', fd => {
    descriptor = fd;
    const stat = fstat(fd);
    fs.appendFileSync(file, 'e');
    return stat;
  });
  assert.throws(() => readBoundedFileSync(file, 4), /budget/);
  hook.mock.restore();
  assert.throws(() => fs.readSync(descriptor, Buffer.alloc(1), 0, 1, 0), { code: 'EBADF' });
}));

test('rejects non-regular files', () => fixture(root => {
  assert.throws(() => readBoundedFileSync(root, 8));
}));

test('atomically replaces output without modifying an existing linked file', () => fixture(root => {
  const victim = join(root, 'retained');
  const output = join(root, 'corpus.json');
  fs.writeFileSync(victim, 'retained');
  fs.linkSync(victim, output);
  writeFileAtomicSync(output, '{"entries":[]}');
  assert.equal(fs.readFileSync(output, 'utf8'), '{"entries":[]}');
  assert.equal(fs.readFileSync(victim, 'utf8'), 'retained');
  assert.deepEqual(fs.readdirSync(root).sort(), ['corpus.json', 'retained']);
}));

test('creates missing output directories and leaves no temporary files', () => fixture(root => {
  const output = join(root, 'nested', 'corpus.json');
  writeFileAtomicSync(output, '{}');
  assert.equal(fs.readFileSync(output, 'utf8'), '{}');
  assert.deepEqual(fs.readdirSync(join(root, 'nested')), ['corpus.json']);
}));

test('failed publication preserves the prior output and cleans its owned temporary file', () => fixture(root => {
  const output = join(root, 'corpus.json');
  fs.writeFileSync(output, 'retained');
  mock.method(fs, 'renameSync', () => { throw new Error('controlled publish refusal'); });
  assert.throws(() => writeFileAtomicSync(output, 'replacement'), /publish refusal/);
  assert.equal(fs.readFileSync(output, 'utf8'), 'retained');
  assert.deepEqual(fs.readdirSync(root), ['corpus.json']);
}));
