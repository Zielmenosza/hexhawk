export type LegacyRecordFormat = 'intel-hex' | 'motorola-srec' | 'unknown';

const LEGACY_RECORD_EXTENSIONS = /\.(hex|ihex|ihx|s19|s28|s37|srec)$/i;

export function isLegacyRecordCandidateFileName(fileName: string): boolean {
  return LEGACY_RECORD_EXTENSIONS.test(fileName);
}

export interface LegacyRecordRange {
  start: number;
  endInclusive: number;
  byteLength: number;
}

export interface LegacyRecordString {
  address: number;
  value: string;
}

export interface LegacyRecordMetadata {
  schema: 'hexhawk.legacy_record_metadata.v1';
  format: LegacyRecordFormat;
  recordCount: number;
  dataRecordCount: number;
  byteCount: number;
  ranges: LegacyRecordRange[];
  entryAddress?: number;
  strings: LegacyRecordString[];
  errors: string[];
  warnings: string[];
  authorityBoundary: string;
  noExecution: true;
}

const AUTHORITY_BOUNDARY = 'Metadata-first legacy record adapter: validates records and maps bytes only. It does not execute content, recover source, decompile, or assign GYRE verdict authority.';

interface ParsedByte {
  address: number;
  value: number;
}

function parseHexByte(value: string, context: string, errors: string[]): number | undefined {
  if (!/^[0-9a-fA-F]{2}$/.test(value)) {
    errors.push(`${context}: invalid hex byte '${value}'`);
    return undefined;
  }
  return Number.parseInt(value, 16);
}

function parseHexBytes(value: string, context: string, errors: string[]): number[] | undefined {
  if (value.length % 2 !== 0) {
    errors.push(`${context}: odd-length hex payload`);
    return undefined;
  }
  const bytes: number[] = [];
  for (let i = 0; i < value.length; i += 2) {
    const byte = parseHexByte(value.slice(i, i + 2), context, errors);
    if (byte === undefined) return undefined;
    bytes.push(byte);
  }
  return bytes;
}

function checksumIntel(bytesWithoutChecksum: number[], checksum: number): boolean {
  const sum = [...bytesWithoutChecksum, checksum].reduce((acc, byte) => (acc + byte) & 0xff, 0);
  return sum === 0;
}

function checksumSRecord(bytesIncludingChecksum: number[]): boolean {
  const sum = bytesIncludingChecksum.reduce((acc, byte) => (acc + byte) & 0xff, 0);
  return sum === 0xff;
}

function compactRanges(bytes: ParsedByte[], warnings: string[]): LegacyRecordRange[] {
  const sorted = [...bytes].sort((a, b) => a.address - b.address || a.value - b.value);
  const seen = new Set<number>();
  const unique: ParsedByte[] = [];

  for (const byte of sorted) {
    if (seen.has(byte.address)) {
      warnings.push(`overlapping data at 0x${byte.address.toString(16)}`);
      continue;
    }
    seen.add(byte.address);
    unique.push(byte);
  }

  const ranges: LegacyRecordRange[] = [];
  for (const byte of unique) {
    const last = ranges[ranges.length - 1];
    if (last && byte.address === last.endInclusive + 1) {
      last.endInclusive = byte.address;
      last.byteLength += 1;
    } else {
      ranges.push({ start: byte.address, endInclusive: byte.address, byteLength: 1 });
    }
  }
  return ranges;
}

function extractStrings(bytes: ParsedByte[], minimumLength = 4): LegacyRecordString[] {
  const sorted = [...bytes].sort((a, b) => a.address - b.address);
  const strings: LegacyRecordString[] = [];
  let currentAddress: number | undefined;
  let current = '';
  let previousAddress: number | undefined;

  const flush = () => {
    if (currentAddress !== undefined && current.length >= minimumLength) {
      strings.push({ address: currentAddress, value: current });
    }
    currentAddress = undefined;
    current = '';
    previousAddress = undefined;
  };

  for (const byte of sorted) {
    const printable = byte.value >= 0x20 && byte.value <= 0x7e;
    const contiguous = previousAddress === undefined || byte.address === previousAddress + 1;
    if (!printable || !contiguous) {
      flush();
      if (!printable) continue;
    }
    if (currentAddress === undefined) currentAddress = byte.address;
    current += String.fromCharCode(byte.value);
    previousAddress = byte.address;
  }
  flush();
  return strings;
}

function emptyMetadata(format: LegacyRecordFormat, errors: string[] = [], warnings: string[] = []): LegacyRecordMetadata {
  return {
    schema: 'hexhawk.legacy_record_metadata.v1',
    format,
    recordCount: 0,
    dataRecordCount: 0,
    byteCount: 0,
    ranges: [],
    strings: [],
    errors,
    warnings,
    authorityBoundary: AUTHORITY_BOUNDARY,
    noExecution: true,
  };
}

export function detectLegacyRecordFormat(text: string): LegacyRecordFormat {
  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (lines.length === 0) return 'unknown';
  const intel = lines.filter((line) => line.startsWith(':')).length;
  const srec = lines.filter((line) => /^S[0-9]/i.test(line)).length;
  if (intel > 0 && intel >= srec) return 'intel-hex';
  if (srec > 0) return 'motorola-srec';
  return 'unknown';
}

export function parseIntelHexMetadata(text: string): LegacyRecordMetadata {
  const errors: string[] = [];
  const warnings: string[] = [];
  const bytes: ParsedByte[] = [];
  let recordCount = 0;
  let dataRecordCount = 0;
  let upperLinearAddress = 0;
  let upperSegmentAddress = 0;
  let entryAddress: number | undefined;

  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  for (const [index, line] of lines.entries()) {
    const context = `line ${index + 1}`;
    if (!line.startsWith(':')) {
      errors.push(`${context}: Intel HEX record must start with ':'`);
      continue;
    }
    const payload = line.slice(1);
    const raw = parseHexBytes(payload, context, errors);
    if (!raw) continue;
    if (raw.length < 5) {
      errors.push(`${context}: record too short`);
      continue;
    }
    const [count, addressHigh, addressLow, type, ...rest] = raw;
    const data = rest.slice(0, -1);
    const checksum = rest[rest.length - 1];
    if (data.length !== count) {
      errors.push(`${context}: byte count ${count} does not match data length ${data.length}`);
      continue;
    }
    if (!checksumIntel(raw.slice(0, -1), checksum)) {
      errors.push(`${context}: checksum mismatch`);
      continue;
    }

    recordCount += 1;
    const offset = (addressHigh << 8) | addressLow;
    if (type === 0x00) {
      dataRecordCount += 1;
      const base = upperLinearAddress + upperSegmentAddress;
      for (const [byteIndex, value] of data.entries()) {
        bytes.push({ address: base + offset + byteIndex, value });
      }
    } else if (type === 0x01) {
      if (count !== 0) errors.push(`${context}: EOF record should not contain data`);
    } else if (type === 0x02) {
      if (count !== 2) errors.push(`${context}: extended segment address record must contain 2 bytes`);
      upperSegmentAddress = (((data[0] ?? 0) << 8) | (data[1] ?? 0)) << 4;
      upperLinearAddress = 0;
    } else if (type === 0x04) {
      if (count !== 2) errors.push(`${context}: extended linear address record must contain 2 bytes`);
      upperLinearAddress = (((data[0] ?? 0) << 8) | (data[1] ?? 0)) << 16;
      upperSegmentAddress = 0;
    } else if (type === 0x03 || type === 0x05) {
      if (count === 4) {
        entryAddress = data.reduce((acc, value) => (acc << 8) | value, 0) >>> 0;
      } else {
        errors.push(`${context}: start address record must contain 4 bytes`);
      }
    } else {
      warnings.push(`${context}: unsupported Intel HEX record type 0x${type.toString(16).padStart(2, '0')}`);
    }
  }

  return {
    ...emptyMetadata('intel-hex', errors, warnings),
    recordCount,
    dataRecordCount,
    byteCount: bytes.length,
    ranges: compactRanges(bytes, warnings),
    entryAddress,
    strings: extractStrings(bytes),
  };
}

const S_RECORD_ADDRESS_LENGTH: Record<string, number> = {
  S0: 2,
  S1: 2,
  S2: 3,
  S3: 4,
  S5: 2,
  S6: 3,
  S7: 4,
  S8: 3,
  S9: 2,
};

export function parseMotorolaSRecordMetadata(text: string): LegacyRecordMetadata {
  const errors: string[] = [];
  const warnings: string[] = [];
  const bytes: ParsedByte[] = [];
  let recordCount = 0;
  let dataRecordCount = 0;
  let entryAddress: number | undefined;

  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  for (const [index, line] of lines.entries()) {
    const context = `line ${index + 1}`;
    const type = line.slice(0, 2).toUpperCase();
    if (!/^S[0-9]$/.test(type)) {
      errors.push(`${context}: Motorola S-record must start with S0-S9`);
      continue;
    }
    const addressLength = S_RECORD_ADDRESS_LENGTH[type];
    if (!addressLength) {
      warnings.push(`${context}: unsupported S-record type ${type}`);
      continue;
    }
    const raw = parseHexBytes(line.slice(2), context, errors);
    if (!raw) continue;
    if (raw.length < 1 + addressLength + 1) {
      errors.push(`${context}: record too short`);
      continue;
    }
    const count = raw[0];
    const bytesAfterCount = raw.slice(1);
    if (count !== bytesAfterCount.length) {
      errors.push(`${context}: byte count ${count} does not match payload length ${bytesAfterCount.length}`);
      continue;
    }
    if (!checksumSRecord(raw)) {
      errors.push(`${context}: checksum mismatch`);
      continue;
    }

    recordCount += 1;
    const addressBytes = bytesAfterCount.slice(0, addressLength);
    const data = bytesAfterCount.slice(addressLength, -1);
    const address = addressBytes.reduce((acc, value) => (acc << 8) | value, 0) >>> 0;

    if (type === 'S1' || type === 'S2' || type === 'S3') {
      dataRecordCount += 1;
      for (const [byteIndex, value] of data.entries()) {
        bytes.push({ address: address + byteIndex, value });
      }
    } else if (type === 'S7' || type === 'S8' || type === 'S9') {
      entryAddress = address;
    }
  }

  return {
    ...emptyMetadata('motorola-srec', errors, warnings),
    recordCount,
    dataRecordCount,
    byteCount: bytes.length,
    ranges: compactRanges(bytes, warnings),
    entryAddress,
    strings: extractStrings(bytes),
  };
}

export function parseLegacyRecordMetadata(text: string): LegacyRecordMetadata {
  const format = detectLegacyRecordFormat(text);
  if (format === 'intel-hex') return parseIntelHexMetadata(text);
  if (format === 'motorola-srec') return parseMotorolaSRecordMetadata(text);
  return emptyMetadata('unknown', ['unknown legacy record format']);
}

export function parseLegacyRecordMetadataFromBytes(bytes: number[]): LegacyRecordMetadata {
  const bounded = bytes.slice(0, 1024 * 1024);
  const text = bounded.map((byte) => String.fromCharCode(byte & 0xff)).join('');
  return parseLegacyRecordMetadata(text);
}
