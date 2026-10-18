import { describe, expect, it } from 'vitest';
import {
  detectLegacyRecordFormat,
  isLegacyRecordCandidateFileName,
  parseIntelHexMetadata,
  parseLegacyRecordMetadata,
  parseLegacyRecordMetadataFromBytes,
  parseMotorolaSRecordMetadata,
} from '../legacyRecordMetadata';

describe('legacyRecordMetadata', () => {
  it('detects legacy record candidate filenames for file-inspection routing', () => {
    expect(isLegacyRecordCandidateFileName('firmware.hex')).toBe(true);
    expect(isLegacyRecordCandidateFileName('boot.IHEX')).toBe(true);
    expect(isLegacyRecordCandidateFileName('motorola.s19')).toBe(true);
    expect(isLegacyRecordCandidateFileName('image.srec')).toBe(true);
    expect(isLegacyRecordCandidateFileName('archive.7z')).toBe(false);
    expect(isLegacyRecordCandidateFileName('firmware.rom')).toBe(false);
  });

  it('detects Intel HEX and validates checksum/address ranges without executing content', () => {
    const text = [
      ':020000040000FA',
      ':0501000048454C4C4F86',
      ':00000001FF',
    ].join('\n');

    const metadata = parseIntelHexMetadata(text);

    expect(detectLegacyRecordFormat(text)).toBe('intel-hex');
    expect(metadata.schema).toBe('hexhawk.legacy_record_metadata.v1');
    expect(metadata.format).toBe('intel-hex');
    expect(metadata.recordCount).toBe(3);
    expect(metadata.dataRecordCount).toBe(1);
    expect(metadata.byteCount).toBe(5);
    expect(metadata.ranges).toEqual([{ start: 0x100, endInclusive: 0x104, byteLength: 5 }]);
    expect(metadata.strings).toEqual([{ address: 0x100, value: 'HELLO' }]);
    expect(metadata.errors).toEqual([]);
    expect(metadata.noExecution).toBe(true);
    expect(metadata.authorityBoundary).toContain('does not execute content');
    expect(metadata.authorityBoundary).toContain('does not');
  });

  it('rejects Intel HEX checksum mismatches and does not promote malformed data', () => {
    const metadata = parseLegacyRecordMetadata(':0501000048454C4C4F00\n:00000001FF');

    expect(metadata.format).toBe('intel-hex');
    expect(metadata.recordCount).toBe(1);
    expect(metadata.dataRecordCount).toBe(0);
    expect(metadata.byteCount).toBe(0);
    expect(metadata.errors).toEqual(expect.arrayContaining(['line 1: checksum mismatch']));
  });

  it('detects Motorola S-record data, entrypoint, ranges, strings, and checksums', () => {
    const text = ['S1081000574F524C445F', 'S9031000EC'].join('\n');

    const metadata = parseMotorolaSRecordMetadata(text);

    expect(detectLegacyRecordFormat(text)).toBe('motorola-srec');
    expect(metadata.format).toBe('motorola-srec');
    expect(metadata.recordCount).toBe(2);
    expect(metadata.dataRecordCount).toBe(1);
    expect(metadata.byteCount).toBe(5);
    expect(metadata.entryAddress).toBe(0x1000);
    expect(metadata.ranges).toEqual([{ start: 0x1000, endInclusive: 0x1004, byteLength: 5 }]);
    expect(metadata.strings).toEqual([{ address: 0x1000, value: 'WORLD' }]);
    expect(metadata.errors).toEqual([]);
    expect(metadata.noExecution).toBe(true);
  });

  it('reports overlapping address data as warning instead of hiding custody ambiguity', () => {
    const text = [
      ':0301000041424336',
      ':0301020058595AEF',
      ':00000001FF',
    ].join('\n');

    const metadata = parseIntelHexMetadata(text);

    expect(metadata.byteCount).toBe(6);
    expect(metadata.ranges).toEqual([{ start: 0x100, endInclusive: 0x104, byteLength: 5 }]);
    expect(metadata.warnings.some((warning) => warning.includes('overlapping data at 0x102'))).toBe(true);
  });

  it('returns unknown metadata for unsupported record text', () => {
    const metadata = parseLegacyRecordMetadata('not a legacy record');

    expect(metadata.format).toBe('unknown');
    expect(metadata.errors).toEqual(['unknown legacy record format']);
    expect(metadata.byteCount).toBe(0);
  });

  it('parses legacy record metadata from a bounded byte window for UI file inspection', () => {
    const text = [
      ':020000040000FA',
      ':0501000048454C4C4F86',
      ':00000001FF',
      'ignored trailer after EOF',
    ].join('\n');
    const bytes = Array.from(text, (char) => char.charCodeAt(0));

    const metadata = parseLegacyRecordMetadataFromBytes(bytes);

    expect(metadata.format).toBe('intel-hex');
    expect(metadata.byteCount).toBe(5);
    expect(metadata.ranges).toEqual([{ start: 0x100, endInclusive: 0x104, byteLength: 5 }]);
    expect(metadata.noExecution).toBe(true);
  });
});
