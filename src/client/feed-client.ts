import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { FetchLike } from '../adapters.js';
import { verifyManifest, verifyShard } from '../feed/verify.js';
import type { Advisory, Feed, FeedStatus, Manifest, SourceId } from '../types.js';

export type FeedErrorCode = 'offline-no-cache' | 'verification-failed' | 'rollback' | 'network' | 'invalid';
export class FeedError extends Error { constructor(public code: FeedErrorCode, message: string) { super(message); } }
export interface LoadFeedOptions { source: string; cacheDir: string; publicKeys: string[]; offline?: boolean; now?: () => Date; fetch?: FetchLike; userAgent?: string; ecosystems?: string[]; retries?: number; sleep?: (ms: number) => Promise<void>; warn?: (msg: string) => void }
export interface LoadedFeed { feed: Feed; status: FeedStatus; keyId: string }

const isUrl = (s: string) => /^https?:\/\//.test(s);

async function writeAtomic(path: string, data: Uint8Array | string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`; await writeFile(tmp, data); await rename(tmp, path);
}
async function readOrNull(path: string): Promise<Buffer | null> { try { return await readFile(path); } catch { return null; } }

export async function loadFeed(opts: LoadFeedOptions): Promise<LoadedFeed> {
  const now = opts.now ?? (() => new Date()); const warn = opts.warn ?? (() => {}); const sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  const fetchFn = opts.fetch ?? (globalThis.fetch as unknown as FetchLike);
  const retries = opts.retries ?? 3; const cache = opts.cacheDir; const shardsDir = join(cache, 'shards');
  const headers: Record<string, string> = { 'User-Agent': opts.userAgent ?? 'guarda' };
  const get = async (name: string, extra: Record<string, string> = {}): Promise<{ status: number; body: Buffer; etag: string | null }> => {
    let lastErr: unknown;
    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const res = await fetchFn(`${opts.source.replace(/\/$/, '')}/${name}`, { headers: { ...headers, ...extra } });
        if (res.status >= 500) throw new Error(`HTTP ${res.status}`);
        return { status: res.status, body: Buffer.from(await res.arrayBuffer()), etag: res.headers.get('etag') };
      } catch (err) { lastErr = err; if (attempt < retries) await sleep(500 * 2 ** attempt); }
    }
    throw new FeedError('network', `feed download failed: ${(lastErr as Error).message}`);
  };
  let state = { lastAcceptedVersion: 0 };
  try { state = JSON.parse((await readOrNull(join(cache, 'state.json')))?.toString() ?? '{"lastAcceptedVersion":0}') as typeof state; } catch { await rm(join(cache, 'state.json'), { force: true }); }
  const readShard = async (name: string, sha256: string, fetchIfMissing: boolean): Promise<Advisory[]> => {
    const path = isUrl(opts.source) ? join(shardsDir, name) : join(opts.source, name);
    let bytes = await readOrNull(path);
    if (bytes) { const v = verifyShard(bytes, sha256); if (v.ok) return v.advisories; if (isUrl(opts.source)) await rm(path, { force: true }); else throw new FeedError('verification-failed', `shard ${name}: ${v.reason}`); bytes = null; }
    if (!fetchIfMissing) throw new FeedError('offline-no-cache', `shard ${name} is not cached`);
    const r = await get(name); if (r.status !== 200) throw new FeedError('network', `shard ${name}: HTTP ${r.status}`);
    const v = verifyShard(r.body, sha256); if (!v.ok) throw new FeedError('verification-failed', `shard ${name}: ${v.reason}`);
    await writeAtomic(join(shardsDir, name), r.body); return v.advisories;
  };
  const finish = async (manifest: Manifest, keyId: string, origin: FeedStatus['origin'], canFetch: boolean): Promise<LoadedFeed> => {
    const wanted = new Set((opts.ecosystems ?? []).map((e) => e.toLowerCase()));
    const advisories: Feed['advisories'] = [];
    for (const s of manifest.shards) {
      if (s.source !== 'guarda' && wanted.size > 0 && !wanted.has(s.ecosystem.toLowerCase())) continue;
      for (const advisory of await readShard(s.url, s.sha256, canFetch)) advisories.push({ source: s.source as SourceId, advisory });
    }
    const stale = now().getTime() > Date.parse(manifest.expires_at);
    return { feed: { manifest, advisories }, keyId, status: { version: manifest.feed_version, generatedAt: manifest.generated_at, expiresAt: manifest.expires_at, stale, sources: manifest.sources, origin } };
  };

  // Local directory source: read and verify in place, no cache involved.
  if (!isUrl(opts.source)) {
    const bytes = await readOrNull(join(opts.source, 'manifest.json')); const sig = await readOrNull(join(opts.source, 'manifest.json.sig'));
    if (!bytes || !sig) throw new FeedError('invalid', `no manifest.json and manifest.json.sig in ${opts.source}`);
    const v = verifyManifest(bytes, sig.toString(), opts.publicKeys); if (!v.ok) throw new FeedError('verification-failed', v.reason);
    return finish(v.manifest, v.keyId, 'directory', false);
  }

  const cachedBytes = await readOrNull(join(cache, 'manifest.json')); const cachedSig = await readOrNull(join(cache, 'manifest.json.sig'));
  let cached: { manifest: Manifest; keyId: string } | null = null;
  if (cachedBytes && cachedSig) {
    const v = verifyManifest(cachedBytes, cachedSig.toString(), opts.publicKeys);
    if (v.ok) cached = { manifest: v.manifest, keyId: v.keyId };
    else {
      // A cache that fails verification is discarded; offline that is fatal, online the feed is fetched again.
      await rm(join(cache, 'manifest.json'), { force: true }); await rm(join(cache, 'manifest.json.sig'), { force: true }); await rm(join(cache, 'manifest.etag'), { force: true });
      if (opts.offline) throw new FeedError('verification-failed', `cached manifest rejected: ${v.reason}`);
      warn(`feed: cached manifest rejected (${v.reason}); fetching again`);
    }
  }
  if (opts.offline) {
    if (!cached) throw new FeedError('offline-no-cache', 'no cached feed; run once online or pass --feed <dir>');
    return finish(cached.manifest, cached.keyId, 'cache', false);
  }
  const etag = (await readOrNull(join(cache, 'manifest.etag')))?.toString();
  try {
    const res = await get('manifest.json', cached && etag ? { 'If-None-Match': etag } : {});
    if (res.status === 304 && cached) return finish(cached.manifest, cached.keyId, 'cache', true);
    if (res.status !== 200) throw new FeedError('network', `manifest: HTTP ${res.status}`);
    const sigRes = await get('manifest.json.sig'); if (sigRes.status !== 200) throw new FeedError('network', `manifest signature: HTTP ${sigRes.status}`);
    const v = verifyManifest(res.body, sigRes.body.toString(), opts.publicKeys);
    if (!v.ok) throw new FeedError('verification-failed', `downloaded manifest rejected: ${v.reason}`);
    if (v.manifest.feed_version < state.lastAcceptedVersion) throw new FeedError('rollback', `feed version ${v.manifest.feed_version} is older than the last accepted ${state.lastAcceptedVersion}`);
    await writeAtomic(join(cache, 'manifest.json'), res.body); await writeAtomic(join(cache, 'manifest.json.sig'), sigRes.body);
    if (res.etag) await writeAtomic(join(cache, 'manifest.etag'), res.etag); else await rm(join(cache, 'manifest.etag'), { force: true });
    await writeAtomic(join(cache, 'state.json'), JSON.stringify({ lastAcceptedVersion: v.manifest.feed_version }));
    return finish(v.manifest, v.keyId, 'network', true);
  } catch (err) {
    if (err instanceof FeedError && err.code !== 'network') throw err;
    if (!cached) throw err instanceof FeedError ? err : new FeedError('network', (err as Error).message);
    warn(`feed: using cached copy: ${(err as Error).message}`);
    return finish(cached.manifest, cached.keyId, 'cache', false);
  }
}
