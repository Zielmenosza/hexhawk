import fs from 'node:fs';
import { randomUUID } from 'node:crypto';
import { basename, dirname, join } from 'node:path';

// Validate and read one opened regular file. A renamed/replaced pathname is not
// reopened, and max+1 bounds growth after fstat rather than trusting its size.
export function readBoundedFileSync(path, maxBytes) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || maxBytes > 64 * 1024 * 1024) {
    throw new RangeError('Invalid read budget.');
  }
  const fd = fs.openSync(path, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK || 0));
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) throw new Error('Expected a regular file.');
    if (stat.size > maxBytes) throw new Error('File exceeds read budget.');
    const bytes = Buffer.alloc(maxBytes + 1);
    let used = 0;
    while (used < bytes.length) {
      const count = fs.readSync(fd, bytes, used, bytes.length - used, null);
      if (count === 0) break;
      used += count;
    }
    if (used > maxBytes) throw new Error('File exceeds read budget.');
    return bytes.subarray(0, used);
  } finally {
    fs.closeSync(fd);
  }
}

// Publish via an owned exclusive sibling, not by opening the checked destination
// for overwrite. Rename replaces an output link rather than following it.
export function writeFileAtomicSync(path, data) {
  const parent = dirname(path);
  fs.mkdirSync(parent, { recursive: true });
  const temporary = join(parent, `.${basename(path)}.${randomUUID()}.tmp`);
  const fd = fs.openSync(temporary, 'wx', 0o600);
  let closed = false;
  let published = false;
  try {
    fs.writeFileSync(fd, data);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    closed = true;
    fs.renameSync(temporary, path);
    published = true;
  } finally {
    if (!closed) fs.closeSync(fd);
    if (!published) fs.unlinkSync(temporary);
  }
}
