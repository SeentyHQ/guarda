import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { FetchLike } from '../../src/adapters.js';
import { formatFeedStatus, readFeedStatus, type FeedStatusFile } from '../../src/client/feed-status.js';

const status: FeedStatusFile = {
  schema_version: '1', feed_version: 3, generated_at: '2026-10-24T10:00:00Z', expires_at: '2026-10-31T10:00:00Z', published_at: '2026-10-24T10:00:05Z', manifest_sha256: 'ab'.repeat(32),
  sources: { guarda: { snapshot: '2026-10-24T10:00:00Z', licence: 'CC-BY-SA-4.0' }, 'openssf-mal': { snapshot: '2026-10-24T03:00:00Z', commit: 'abc', licence: 'CC-BY-4.0' } },
  counts: { curated_advisories: 31, mal_records: 233888, left_out: 1, by_ecosystem: { PyPI: 9, npm: 20 }, by_kind: { poisoned_release: 20 }, by_severity: { critical: 12 } },
  latest_curated_published_at: '2026-10-23T00:00:00Z', left_out: ['GUARDA-2026-0009'],
};
const fakeFetch = (body: string | null, ok = true): FetchLike & { calls: string[] } => {
  const calls: string[] = [];
  const f = (async (url: string) => { calls.push(url); const bytes = Buffer.from(body ?? ''); return { status: ok ? 200 : 404, headers: { get: () => null }, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) }; }) as unknown as FetchLike & { calls: string[] };
  f.calls = calls; return f;
};

describe('readFeedStatus', () => {
  it('fetches <url>/status.json with the user agent and parses it', async () => {
    const fetch = fakeFetch(JSON.stringify(status));
    const s = await readFeedStatus({ source: 'https://feed.example/guarda/v1/', fetch, userAgent: 'guarda/0.1.6' });
    expect(fetch.calls).toEqual(['https://feed.example/guarda/v1/status.json']);
    expect(s).toMatchObject({ feed_version: 3, counts: { curated_advisories: 31 } });
  });
  it('reads status.json from a feed directory', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'guarda-status-')); writeFileSync(join(dir, 'status.json'), JSON.stringify(status));
    expect(await readFeedStatus({ source: dir })).toMatchObject({ feed_version: 3 });
  });
  it('never throws: missing file, 404, malformed JSON and a wrong shape all give null', async () => {
    expect(await readFeedStatus({ source: mkdtempSync(join(tmpdir(), 'guarda-nostatus-')) })).toBeNull();
    expect(await readFeedStatus({ source: 'https://feed.example/v1', fetch: fakeFetch(null, false) })).toBeNull();
    expect(await readFeedStatus({ source: 'https://feed.example/v1', fetch: fakeFetch('{not json') })).toBeNull();
    expect(await readFeedStatus({ source: 'https://feed.example/v1', fetch: fakeFetch('{"hello":"world"}') })).toBeNull();
    const throwing = (async () => { throw new Error('ECONNRESET'); }) as unknown as FetchLike;
    expect(await readFeedStatus({ source: 'https://feed.example/v1', fetch: throwing })).toBeNull();
  });
});

describe('formatFeedStatus', () => {
  it('prints counts per ecosystem, the latest curated date and what was left out', () => {
    expect(formatFeedStatus(status)).toEqual([
      '  published 2026-10-24T10:00:05Z; curated advisories: 31 (PyPI 9, npm 20); malicious-package records: 233888',
      '  latest curated advisory: 2026-10-23T00:00:00Z',
      '  left out of this publication: GUARDA-2026-0009',
    ]);
    expect(formatFeedStatus({ ...status, latest_curated_published_at: null, counts: { ...status.counts, left_out: 0, by_ecosystem: {} }, left_out: [] })).toEqual(['  published 2026-10-24T10:00:05Z; curated advisories: 31; malicious-package records: 233888']);
  });
});
