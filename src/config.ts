import { homedir } from 'node:os';
import { join } from 'node:path';
import type { Severity } from './types.js';
import { DEFAULT_FEED_URL } from './client/keys.js';

export type Only = 'packages' | 'actions' | 'secrets';
export interface Settings { feedUrl: string; failOn: Severity | 'none'; only: Only[] | null; strict: boolean; maxFeedAgeDays: number; offline: boolean; cacheDir: string; noTips: boolean; doNotTrack: boolean; ignore: string[] }
const SEVERITIES = new Set(['none', 'info', 'low', 'medium', 'high', 'critical']);
const ONLY = new Set(['packages', 'actions', 'secrets']);
/** The scanned repository is untrusted: its .guarda.json may only tune the gate, never the network or the strictness. */
const PROJECT_KEYS = new Set(['failOn', 'only', 'ignore']);

/** Precedence: CLI flag > GUARDA_* env > project .guarda.json (failOn, only) > ~/.guarda/config.json > default. */
export function resolveSettings(flags: Record<string, string | boolean | undefined>, env: NodeJS.ProcessEnv, projectRaw: Partial<Settings> | null, user: Partial<Settings> | null, notice: (msg: string) => void = () => {}): Settings {
  const project: Partial<Settings> = {};
  if (projectRaw) {
    const ignored = Object.keys(projectRaw).filter((k) => !PROJECT_KEYS.has(k));
    if (ignored.length) notice(`.guarda.json: ignoring ${ignored.join(', ')} (only failOn, only and ignore are read from a repository)`);
    if (projectRaw.failOn !== undefined) project.failOn = projectRaw.failOn;
    if (projectRaw.only !== undefined) project.only = projectRaw.only;
    if (projectRaw.ignore !== undefined) {
      if (!Array.isArray(projectRaw.ignore) || projectRaw.ignore.some((g) => typeof g !== 'string')) throw new Error('.guarda.json: ignore must be an array of path globs');
      project.ignore = projectRaw.ignore.map((g) => g.replace(/^\.\//, '').replace(/\\/g, '/'));
    }
  }
  const pick = <T>(flag: unknown, envVal: string | undefined, p: T | undefined, u: T | undefined, d: T, conv: (s: string) => T = (s) => s as unknown as T): T =>
    flag !== undefined ? conv(String(flag)) : envVal !== undefined ? conv(envVal) : p !== undefined ? p : u !== undefined ? u : d;
  const failOn = pick(flags['fail-on'], env.GUARDA_FAIL_ON, project.failOn, user?.failOn, 'low' as Settings['failOn']);
  if (!SEVERITIES.has(failOn)) throw new Error(`invalid --fail-on "${failOn}" (none|info|low|medium|high|critical)`);
  const onlyRaw = pick<string | null>(flags.only, env.GUARDA_ONLY, project.only?.join(','), user?.only?.join(','), null);
  const only = onlyRaw === null ? null : (onlyRaw.split(',').map((s) => s.trim()) as Only[]);
  if (only && only.some((o) => !ONLY.has(o))) throw new Error(`invalid --only "${onlyRaw}" (packages,actions,secrets)`);
  const days = (s: string) => { const n = Number(s.replace(/d$/, '')); if (!Number.isFinite(n) || n < 0) throw new Error(`invalid --max-feed-age "${s}" (a number of days, e.g. 7 or 7d)`); return n; };
  const cacheBase = env.XDG_CACHE_HOME ? join(env.XDG_CACHE_HOME, 'guarda') : join(env.HOME ?? homedir(), '.guarda', 'cache');
  const bool = (s: string) => s === 'true' || s === '1';
  const doNotTrack = env.DO_NOT_TRACK === '1' || env.DO_NOT_TRACK === 'true';
  return {
    feedUrl: pick(flags.feed, env.GUARDA_FEED_URL, undefined, user?.feedUrl, DEFAULT_FEED_URL),
    failOn, only,
    strict: pick(flags.strict, env.GUARDA_STRICT, undefined, user?.strict, false, bool),
    maxFeedAgeDays: pick(flags['max-feed-age'], env.GUARDA_MAX_FEED_AGE, undefined, user?.maxFeedAgeDays, 7, days),
    offline: pick(flags.offline, env.GUARDA_OFFLINE, undefined, undefined, false, bool),
    cacheDir: pick(flags['cache-dir'], env.GUARDA_CACHE_DIR, undefined, user?.cacheDir, cacheBase),
    noTips: Boolean(flags['no-tips']) || doNotTrack || env.GUARDA_NO_TIPS === '1' || env.CI === 'true' || env.CI === '1',
    doNotTrack: doNotTrack || Boolean(flags['no-tips']),
    ignore: [...(user?.ignore ?? []), ...(project.ignore ?? [])],
  };
}
