/**
 * `status.json` is the unsigned summary the publisher writes next to the manifest: version, freshness,
 * per-source snapshot and counts. It is informational (the manifest is the truth), so reading it never
 * fails a command: any error yields null and the caller prints what it has.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { FetchLike } from '../adapters.js';

export interface FeedStatusFile {
  schema_version: string; feed_version: number; generated_at: string; expires_at: string; published_at: string;
  manifest_sha256: string; min_cli_version?: string;
  sources: Record<string, { snapshot?: string; commit?: string; licence?: string; attribution?: string } | undefined>;
  counts: { curated_advisories: number; mal_records: number; left_out: number; by_ecosystem: Record<string, number>; by_kind: Record<string, number>; by_severity: Record<string, number> };
  latest_curated_published_at: string | null;
  left_out: string[];
}

const isStatus = (v: unknown): v is FeedStatusFile => {
  const s = v as FeedStatusFile;
  return typeof s === 'object' && s !== null && typeof s.feed_version === 'number' && typeof s.counts === 'object' && s.counts !== null && typeof s.counts.curated_advisories === 'number';
};

export interface ReadFeedStatusOptions { source: string; fetch?: FetchLike; userAgent?: string; timeoutMs?: number }

/** The parsed status.json of a feed URL or directory, or null when absent, unreachable or malformed. */
export async function readFeedStatus(opts: ReadFeedStatusOptions): Promise<FeedStatusFile | null> {
  try {
    let text: string;
    if (/^https?:\/\//.test(opts.source)) {
      const fetchFn = opts.fetch ?? (globalThis.fetch as unknown as FetchLike);
      const res = await Promise.race([
        fetchFn(`${opts.source.replace(/\/$/, '')}/status.json`, { headers: { 'User-Agent': opts.userAgent ?? 'guarda' } }),
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error('timeout')), opts.timeoutMs ?? 5_000).unref()),
      ]);
      if (res.status !== 200) return null;
      text = Buffer.from(await res.arrayBuffer()).toString('utf8');
    } else {
      text = await readFile(join(opts.source, 'status.json'), 'utf8');
    }
    const parsed: unknown = JSON.parse(text);
    return isStatus(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/** The lines `guarda feed` prints under the manifest summary. */
export function formatFeedStatus(s: FeedStatusFile): string[] {
  const eco = Object.entries(s.counts.by_ecosystem).map(([k, v]) => `${k} ${v}`).join(', ');
  const lines = [
    `  published ${s.published_at}; curated advisories: ${s.counts.curated_advisories}${eco ? ` (${eco})` : ''}; malicious-package records: ${s.counts.mal_records}`,
  ];
  if (s.latest_curated_published_at) lines.push(`  latest curated advisory: ${s.latest_curated_published_at}`);
  if (s.counts.left_out > 0) lines.push(`  left out of this publication: ${s.left_out.join(', ')}`);
  return lines;
}
