export const MAX_BRIDGE_PATH_LEN = 4096;
export const MAX_BRIDGE_LIST_ITEMS = 50000;

function assertFiniteInt(value: number, field: string): number {
  if (!Number.isFinite(value) || !Number.isInteger(value)) {
    throw new Error(`Invalid ${field}: expected an integer.`);
  }
  return value;
}

export function clampInt(value: number, min: number, max: number, field: string): number {
  const parsed = assertFiniteInt(value, field);
  if (parsed < min || parsed > max) {
    throw new Error(`Invalid ${field}: expected ${min}-${max}.`);
  }
  return parsed;
}

export function sanitizeBridgePath(raw: string, field = 'path'): string {
  if (typeof raw !== 'string') {
    throw new Error(`Invalid ${field}: expected a string path.`);
  }
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error(`Invalid ${field}: path is empty.`);
  }
  if (trimmed.length > MAX_BRIDGE_PATH_LEN) {
    throw new Error(`Invalid ${field}: path is too long.`);
  }
  // Prevent control-character and null-byte injection in bridged command arguments.
  if (/[\x00-\x1F]/.test(trimmed)) {
    throw new Error(`Invalid ${field}: contains unsafe control characters.`);
  }
  return trimmed;
}

export function sanitizePluginName(raw: string, field = 'plugin name'): string {
  if (typeof raw !== 'string') {
    throw new Error(`Invalid ${field}: expected a string.`);
  }
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error(`Invalid ${field}: value is empty.`);
  }
  if (trimmed.length > 128) {
    throw new Error(`Invalid ${field}: value is too long.`);
  }
  if (!/^[A-Za-z0-9._\- ]+$/.test(trimmed)) {
    throw new Error(`Invalid ${field}: contains unsupported characters.`);
  }
  return trimmed;
}

export function sanitizePluginFilename(raw: string, field = 'plugin filename'): string {
  if (typeof raw !== 'string') {
    throw new Error(`Invalid ${field}: expected a string.`);
  }
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error(`Invalid ${field}: value is empty.`);
  }
  if (trimmed.length > 255) {
    throw new Error(`Invalid ${field}: value is too long.`);
  }
  if (!/^[A-Za-z0-9._\-]+$/.test(trimmed)) {
    throw new Error(`Invalid ${field}: contains unsupported characters.`);
  }
  return trimmed;
}

export function sanitizeAddress(raw: number, field = 'address'): number {
  const addr = assertFiniteInt(raw, field);
  if (addr < 0 || addr > Number.MAX_SAFE_INTEGER) {
    throw new Error(`Invalid ${field}: out of range.`);
  }
  return addr;
}

export function sanitizeHexOrDecAddress(raw: string, field = 'address'): number {
  const input = raw.trim();
  if (!input) {
    throw new Error(`Invalid ${field}: value is empty.`);
  }
  const isHex = /^0x[0-9a-fA-F]+$/.test(input);
  const isDec = /^[0-9]+$/.test(input);
  if (!isHex && !isDec) {
    throw new Error(`Invalid ${field}: use decimal or 0x-prefixed hex.`);
  }
  const parsed = isHex ? Number.parseInt(input, 16) : Number.parseInt(input, 10);
  return sanitizeAddress(parsed, field);
}

export function sanitizeRange(offset: number, length: number): { offset: number; length: number } {
  const safeOffset = clampInt(offset, 0, Number.MAX_SAFE_INTEGER, 'offset');
  const safeLength = clampInt(length, 1, 1024 * 1024 * 1024, 'length');
  return { offset: safeOffset, length: safeLength };
}

export function capArraySize<T>(items: T[], maxItems = MAX_BRIDGE_LIST_ITEMS): T[] {
  if (items.length <= maxItems) return items;
  return items.slice(0, maxItems);
}
