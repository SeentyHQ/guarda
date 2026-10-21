import { describe, expect, it } from 'vitest';
import { memoryFs, type GitAdapter } from '../src/adapters.js';
import { scan } from '../src/scan.js';
import { globToRegExp } from '../src/ignore.js';
import type { Feed, FeedStatus } from '../src/types.js';

const feed: Feed = { manifest: { schema_version: '1.0.0', feed_version: 1, generated_at: 'x', expires_at: 'y', min_cli_version: '0.1.0', sources: {}, shards: [] }, advisories: [] };
const status: FeedStatus = { version: 1, generatedAt: 'x', expiresAt: 'y', stale: false, origin: 'directory', sources: {} };
const git: GitAdapter = { ignored: async () => new Set(), stagedFiles: async () => [], showStaged: async () => '' };

describe('globToRegExp', () => {
  it('supports **, * and exact paths', () => {
    expect(globToRegExp('test/**').test('test/a/b.ts')).toBe(true);
    expect(globToRegExp('test/**').test('tests/a.ts')).toBe(false);
    expect(globToRegExp('docs/*.md').test('docs/a.md')).toBe(true);
    expect(globToRegExp('docs/*.md').test('docs/sub/a.md')).toBe(false);
    expect(globToRegExp('src/secrets/rules.ts').test('src/secrets/rules.ts')).toBe(true);
    expect(globToRegExp('**/*.snap').test('a/b/c.snap')).toBe(true);
  });
});

describe('scan with ignore', () => {
  it('skips ignored files for secrets and reports them as excluded', async () => {
    const fs = memoryFs({ 'src/rules.ts': 'AKIAIOSFODNN7EXAMPLE', 'src/app.ts': 'AKIAIOSFODNN7EXAMPLE' });
    const r = await scan('/repo', { feed, feedStatus: status, fs, git, ignore: ['src/rules.ts'] });
    expect(r.secrets.map((s) => s.path)).toEqual(['src/app.ts']);
    expect(r.coverage.skipped).toContainEqual({ path: 'src/rules.ts', reason: 'excluded', detail: 'ignored by .guarda.json' });
    expect(r.coverage.complete).toBe(true);
  });
});

describe('scan ignore applies to lockfiles and workflows too', () => {
  it('drops ignored lockfiles from the inventory and reports them as excluded', async () => {
    const fs = memoryFs({ 'test/fixtures/package-lock.json': '{"lockfileVersion":3,"packages":{"":{},"node_modules/keyv":{"version":"5.7.2"}}}', 'test/fixtures/legacy/bun.lockb': 'x', 'package-lock.json': '{"lockfileVersion":3,"packages":{"":{},"node_modules/left-pad":{"version":"1.3.0"}}}' });
    const r = await scan('/repo', { feed: { ...feed, advisories: [{ source: 'guarda', advisory: { id: 'G', modified: 'x', summary: 's', affected: [{ package: { ecosystem: 'npm', name: 'keyv' }, versions: ['5.7.2'] }] } }] }, feedStatus: status, fs, git, ignore: ['test/**'] });
    expect(r.matches).toEqual([]);
    expect(r.coverage.complete).toBe(true);
    expect(r.coverage.skipped).toContainEqual({ path: 'test/fixtures/package-lock.json', reason: 'excluded', detail: 'ignored by .guarda.json' });
    expect(r.coverage.skipped.some((k) => k.path === 'test/fixtures/legacy/bun.lockb' && k.reason === 'unsupported-format')).toBe(false);
  });
});
