import { mkdtempSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { FetchLike } from '../../src/adapters.js';
import { loadFeed, FeedError } from '../../src/client/feed-client.js';
import { buildFeed } from '../../src/feed/build.js';
import { generateKeyPair } from '../../src/feed/sign.js';

const k = generateKeyPair();
function makeFeed(version: number, now = new Date('2026-10-09T14:00:00Z')) {
  return buildFeed({ advisories: [{ title: 't', severity: 'high', packages: [{ ecosystem: 'npm', package_name: 'keyv', affected_versions: '5.7.2' }] }], mal: [{ id: 'MAL-1', modified: 'x', summary: 's', affected: [{ package: { ecosystem: 'npm', name: 'evil' }, versions: ['1.0.0'] }] }], feedVersion: version, now, privateKeyPem: k.privateKeyPem });
}
function writeDir(dir: string, f: ReturnType<typeof makeFeed>) {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'manifest.json'), f.manifestBytes); writeFileSync(join(dir, 'manifest.json.sig'), f.signature);
  for (const [name, bytes] of f.files) writeFileSync(join(dir, name), bytes);
}
function server(f: ReturnType<typeof makeFeed>, log: string[], opts: { etag?: string; fail?: boolean } = {}): FetchLike {
  return async (url, init) => {
    log.push(url + (init?.headers?.['If-None-Match'] ? ' inm' : ''));
    if (opts.fail) throw new Error('ECONNRESET');
    const name = url.split('/').pop()!;
    if (name === 'manifest.json' && opts.etag && init?.headers?.['If-None-Match'] === opts.etag) return { status: 304, headers: { get: () => null }, arrayBuffer: async () => new ArrayBuffer(0) };
    const body = name === 'manifest.json' ? f.manifestBytes : name === 'manifest.json.sig' ? Buffer.from(f.signature) : f.files.get(name);
    if (!body) return { status: 404, headers: { get: () => null }, arrayBuffer: async () => new ArrayBuffer(0) };
    return { status: 200, headers: { get: (h: string) => (h.toLowerCase() === 'etag' && name === 'manifest.json' ? opts.etag ?? null : null) }, arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer };
  };
}
const tmp = () => mkdtempSync(join(tmpdir(), 'guarda-'));
const sleep = async () => {};

describe('loadFeed', () => {
  it('loads from a directory and verifies', async () => {
    const dir = tmp(); writeDir(join(dir, 'feed'), makeFeed(1));
    const r = await loadFeed({ source: join(dir, 'feed'), cacheDir: join(dir, 'cache'), publicKeys: [k.publicKeyPem], now: () => new Date('2026-10-10T00:00:00Z') });
    expect(r.status).toMatchObject({ version: 1, origin: 'directory', stale: false });
    expect(r.feed.advisories.map((a) => a.advisory.id)).toEqual(['GUARDA-2026-0001', 'MAL-1']);
    expect(r.keyId).toBe(k.keyId);
  });
  it('fetches over the network with ETag, caches, then serves 304 from cache and goes offline', async () => {
    const dir = tmp(); const f = makeFeed(2); const log: string[] = [];
    const opts = { source: 'https://feed.example/v1', cacheDir: join(dir, 'cache'), publicKeys: [k.publicKeyPem], sleep, now: () => new Date('2026-10-10T00:00:00Z') };
    const r1 = await loadFeed({ ...opts, fetch: server(f, log, { etag: '"abc"' }) });
    expect(r1.status.origin).toBe('network');
    expect(log.filter((l) => l.endsWith('manifest.json'))).toHaveLength(1);
    expect(log.some((l) => l.includes('openssf-mal-npm'))).toBe(true);
    const log2: string[] = [];
    const r2 = await loadFeed({ ...opts, fetch: server(f, log2, { etag: '"abc"' }) });
    expect(r2.status.origin).toBe('cache');
    expect(log2).toEqual(['https://feed.example/v1/manifest.json inm']);
    const r3 = await loadFeed({ ...opts, offline: true, fetch: async () => { throw new Error('must not fetch'); } });
    expect(r3.status.origin).toBe('cache');
    expect(JSON.parse(readFileSync(join(dir, 'cache', 'state.json'), 'utf8'))).toEqual({ lastAcceptedVersion: 2 });
  });
  it('refuses rollback, falls back to cache on network failure, and fails offline without cache', async () => {
    const dir = tmp(); const log: string[] = [];
    const opts = { source: 'https://feed.example/v1', cacheDir: join(dir, 'cache'), publicKeys: [k.publicKeyPem], sleep, now: () => new Date('2026-10-10T00:00:00Z') };
    await loadFeed({ ...opts, fetch: server(makeFeed(5), log) });
    await expect(loadFeed({ ...opts, fetch: server(makeFeed(4), log) })).rejects.toMatchObject({ code: 'rollback' });
    const warnings: string[] = [];
    const r = await loadFeed({ ...opts, fetch: server(makeFeed(6), log, { fail: true }), retries: 1, warn: (m) => warnings.push(m) });
    expect(r.status).toMatchObject({ version: 5, origin: 'cache' });
    expect(warnings[0]).toContain('using cached copy');
    await expect(loadFeed({ ...opts, cacheDir: join(dir, 'empty'), offline: true })).rejects.toMatchObject({ code: 'offline-no-cache' });
  });
  it('rejects a tampered cache and marks an expired feed stale', async () => {
    const dir = tmp(); const log: string[] = [];
    const opts = { source: 'https://feed.example/v1', cacheDir: join(dir, 'cache'), publicKeys: [k.publicKeyPem], sleep };
    await loadFeed({ ...opts, fetch: server(makeFeed(1), log), now: () => new Date('2026-10-10T00:00:00Z') });
    const r = await loadFeed({ ...opts, offline: true, now: () => new Date('2026-11-01T00:00:00Z') });
    expect(r.status.stale).toBe(true);
    writeFileSync(join(dir, 'cache', 'manifest.json'), JSON.stringify({ ...JSON.parse(readFileSync(join(dir, 'cache', 'manifest.json'), 'utf8')), feed_version: 99 }));
    await expect(loadFeed({ ...opts, offline: true, now: () => new Date('2026-10-10T00:00:00Z') })).rejects.toBeInstanceOf(FeedError);
  });
});
