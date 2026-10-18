import { describe, expect, it } from 'vitest';
import { analyzeHarText } from '../harPacketIntelligence';

const har = {
  log: {
    version: '1.2',
    creator: { name: 'test', version: '1' },
    entries: [
      {
        startedDateTime: '2026-08-12T10:00:00.000Z',
        time: 120,
        request: {
          method: 'GET',
          url: 'https://api.example.test/v1/profile?user=7&token=secret',
          headers: [
            { name: 'Authorization', value: 'Bearer secret' },
            { name: 'Accept', value: 'application/json' },
          ],
          queryString: [
            { name: 'user', value: '7' },
            { name: 'token', value: 'secret' },
          ],
          cookies: [{ name: 'session', value: 'secret' }],
          headersSize: 40,
          bodySize: 0,
        },
        response: {
          status: 200,
          statusText: 'OK',
          headers: [{ name: 'Set-Cookie', value: 'session=secret' }],
          cookies: [],
          content: { size: 80, mimeType: 'application/json', text: '{"name":"Ziel","token":"secret"}' },
          redirectURL: '',
          headersSize: 30,
          bodySize: 80,
        },
        cache: {},
        timings: { send: 2, wait: 100, receive: 18 },
      },
      {
        startedDateTime: '2026-08-12T10:00:01.000Z',
        time: 900,
        request: {
          method: 'POST',
          url: 'https://api.example.test/v1/action',
          headers: [{ name: 'Content-Type', value: 'application/json' }],
          queryString: [], cookies: [], headersSize: 20, bodySize: 25,
          postData: { mimeType: 'application/json', text: '{"action":"jump"}' },
        },
        response: {
          status: 429, statusText: 'Too Many Requests', headers: [], cookies: [],
          content: { size: 12, mimeType: 'application/json' }, redirectURL: '', headersSize: 20, bodySize: 12,
        },
        cache: {}, timings: { send: 2, wait: 880, receive: 18 },
      },
    ],
  },
};

describe('HAR packet intelligence', () => {
  it('summarises traffic while redacting secrets and payload bodies', () => {
    const report = analyzeHarText(JSON.stringify(har));
    expect(report.totalRequests).toBe(2);
    expect(report.hosts).toEqual([{ host: 'api.example.test', count: 2 }]);
    expect(report.slowRequests[0].durationMs).toBe(900);
    expect(report.statusGroups).toMatchObject({ success: 1, clientError: 1 });
    expect(report.entries[0].url).toBe('https://api.example.test/v1/profile?user=%5BREDACTED%5D&token=%5BREDACTED%5D');
    expect(JSON.stringify(report)).not.toContain('Bearer secret');
    expect(JSON.stringify(report)).not.toContain('requestHeaders');
    expect(JSON.stringify(report)).not.toContain('responseHeaders');
    expect(JSON.stringify(report)).not.toContain('session=secret');
    expect(JSON.stringify(report)).not.toContain('Ziel');
  });

  it('rejects malformed and oversized inputs', () => {
    expect(() => analyzeHarText('{')).toThrow(/valid HAR JSON/i);
    expect(() => analyzeHarText(JSON.stringify({ log: { entries: 'nope' } }))).toThrow(/entries/i);
    expect(() => analyzeHarText('x'.repeat(25 * 1024 * 1024 + 1))).toThrow(/too large/i);
  });
});
