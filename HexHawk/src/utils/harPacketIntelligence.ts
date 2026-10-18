const MAX_HAR_BYTES = 25 * 1024 * 1024;
export interface PacketEntrySummary {
  startedDateTime: string;
  method: string;
  url: string;
  host: string;
  status: number;
  durationMs: number;
  requestBytes: number;
  responseBytes: number;
  mimeType: string;
  hasRequestBody: boolean;
  hasResponseBody: boolean;
}

export interface PacketIntelligenceReport {
  source: 'har';
  authority: 'advisory';
  totalRequests: number;
  hosts: Array<{ host: string; count: number }>;
  statusGroups: { informational: number; success: number; redirect: number; clientError: number; serverError: number; other: number };
  slowRequests: PacketEntrySummary[];
  entries: PacketEntrySummary[];
  notices: string[];
}

type UnknownRecord = Record<string, unknown>;
const record = (value: unknown): UnknownRecord => value && typeof value === 'object' ? value as UnknownRecord : {};
const number = (value: unknown): number => typeof value === 'number' && Number.isFinite(value) ? value : 0;
const string = (value: unknown): string => typeof value === 'string' ? value : '';

function safeUrl(raw: string): { url: string; host: string } {
  try {
    const url = new URL(raw);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return { url: `[${url.protocol.replace(':', '')} URL omitted]`, host: url.hostname || 'non-http' };
    }
    for (const key of [...url.searchParams.keys()]) {
      url.searchParams.set(key, '[REDACTED]');
    }
    url.pathname = url.pathname
      .split('/')
      .map(segment => {
        if (!segment) return segment;
        const decoded = decodeURIComponent(segment);
        return /@|\d{4,}|[0-9a-f]{8,}|[_-][0-9a-z]{12,}/i.test(decoded) ? '[REDACTED]' : segment;
      })
      .join('/');
    url.username = '';
    url.password = '';
    url.hash = '';
    return { url: url.toString(), host: url.hostname };
  } catch {
    return { url: '[invalid URL]', host: 'invalid' };
  }
}

function statusGroup(status: number): keyof PacketIntelligenceReport['statusGroups'] {
  if (status >= 100 && status < 200) return 'informational';
  if (status >= 200 && status < 300) return 'success';
  if (status >= 300 && status < 400) return 'redirect';
  if (status >= 400 && status < 500) return 'clientError';
  if (status >= 500 && status < 600) return 'serverError';
  return 'other';
}

export function analyzeHarText(text: string): PacketIntelligenceReport {
  if (new TextEncoder().encode(text).byteLength > MAX_HAR_BYTES) throw new Error('HAR file is too large (25 MiB maximum).');
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { throw new Error('Select valid HAR JSON.'); }
  const entriesValue = record(record(parsed).log).entries;
  if (!Array.isArray(entriesValue)) throw new Error('HAR log.entries must be an array.');
  if (entriesValue.length > 100_000) throw new Error('HAR contains too many entries.');

  const entries = entriesValue.map(item => {
    const entry = record(item);
    const request = record(entry.request);
    const response = record(entry.response);
    const content = record(response.content);
    const postData = record(request.postData);
    const { url, host } = safeUrl(string(request.url));
    return {
      startedDateTime: string(entry.startedDateTime),
      method: string(request.method).slice(0, 32),
      url,
      host,
      status: number(response.status),
      durationMs: Math.max(0, number(entry.time)),
      requestBytes: Math.max(0, number(request.headersSize)) + Math.max(0, number(request.bodySize)),
      responseBytes: Math.max(0, number(response.headersSize)) + Math.max(0, number(response.bodySize) || number(content.size)),
      mimeType: string(content.mimeType).slice(0, 256),
      hasRequestBody: typeof postData.text === 'string' || number(request.bodySize) > 0,
      hasResponseBody: typeof content.text === 'string' || number(content.size) > 0,
    } satisfies PacketEntrySummary;
  });

  const hostCounts = new Map<string, number>();
  const statusGroups: PacketIntelligenceReport['statusGroups'] = {
    informational: 0, success: 0, redirect: 0, clientError: 0, serverError: 0, other: 0,
  };
  for (const entry of entries) {
    hostCounts.set(entry.host, (hostCounts.get(entry.host) ?? 0) + 1);
    statusGroups[statusGroup(entry.status)] += 1;
  }

  return {
    source: 'har',
    authority: 'advisory',
    totalRequests: entries.length,
    hosts: [...hostCounts.entries()].map(([host, count]) => ({ host, count })).sort((a, b) => b.count - a.count || a.host.localeCompare(b.host)),
    statusGroups,
    slowRequests: [...entries].sort((a, b) => b.durationMs - a.durationMs).slice(0, 10),
    entries,
    notices: [
      'Imported metadata is advisory and cannot change GYRE verdicts.',
      'Request and response headers and bodies, cookies, credentials, and all query values are not retained.',
      'Replay and mutation require a separate authorized-target declaration and explicit confirmation.',
    ],
  };
}
