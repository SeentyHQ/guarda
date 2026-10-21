import { describe, expect, it } from 'vitest';
import { memoryFs, type GitAdapter } from '../src/adapters.js';
import { scan } from '../src/scan.js';
import type { Feed, FeedStatus } from '../src/types.js';

const feed: Feed = { manifest: { schema_version: '1.0.0', feed_version: 1, generated_at: 'x', expires_at: 'y', min_cli_version: '0.1.0', sources: {}, shards: [] }, advisories: [
  { source: 'guarda', advisory: { id: 'GUARDA-1', modified: 'x', summary: 'keyv', affected: [{ package: { ecosystem: 'npm', name: 'keyv' }, versions: ['5.7.2'] }], database_specific: { seenty: { severity: 'critical' } } } },
] };
const status: FeedStatus = { version: 1, generatedAt: 'x', expiresAt: 'y', stale: false, origin: 'directory', sources: {} };
const git: GitAdapter = { ignored: async () => new Set(['.env']), stagedFiles: async () => ['staged.ts'], showStaged: async () => 'ghp_' + 'B'.repeat(36) };

describe('scan', () => {
  it('combines inventory matching and secrets, marks gitignored files and reports completeness', async () => {
    const fs = memoryFs({
      'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/keyv': { version: '5.7.2' } } }),
      'legacy/bun.lockb': 'x',
      '.env': 'TOKEN=ghp_' + 'A'.repeat(36) + '\n',
      'src/a.ts': 'const k = "AKIAIOSFODNN7EXAMPLE";',
      'img/logo.png': 'PNG\0\0binary',
      'test/fixtures/secrets/sample.txt': 'AKIAIOSFODNN7EXAMPLE',
    });
    const r = await scan('/repo', { feed, feedStatus: status, fs, git });
    expect(r.matches.map((m) => m.advisory.id)).toEqual(['GUARDA-1']);
    expect(r.secrets.map((s) => [s.ruleId, s.path, s.gitignored, s.severity])).toEqual([
      ['github-pat', '.env', true, 'high'],
      ['aws-access-key-id', 'src/a.ts', false, 'high'],
    ]);
    expect(r.coverage.complete).toBe(false);
    expect(r.coverage.skipped.some((s) => s.path === 'legacy/bun.lockb')).toBe(true);
    expect(r.coverage.skipped).toContainEqual({ path: 'img/logo.png', reason: 'excluded', detail: 'binary file' });
    expect(r.coverage.skipped).toContainEqual({ path: 'test/fixtures/secrets/sample.txt', reason: 'excluded', detail: 'guarda secret-rule fixtures' });
    expect(r.coverage.scannedFiles).toBe(3);
    expect(r.coverage.inventory).toEqual({ packages: 1, lockfiles: 1, declared: 0, manifests: 0, actions: 0, workflows: 0, runtimes: 0, runtimeFiles: 0, images: 0, imageFiles: 0 });
  });
  it('respects only and staged', async () => {
    const fs = memoryFs({ 'src/a.ts': 'AKIAIOSFODNN7EXAMPLE' });
    const r = await scan('/repo', { feed, feedStatus: status, fs, git, only: ['secrets'], staged: true });
    expect(r.matches).toEqual([]);
    expect(r.secrets.map((s) => s.path)).toEqual(['staged.ts']);
  });
  it('without a lockfile, package.json is read: pins match, ranges are range exposures, coverage is incomplete', async () => {
    const fs = memoryFs({ 'package.json': JSON.stringify({ dependencies: { keyv: '^5.7.0', other: '1.0.0' } }) });
    const r = await scan('/repo', { feed, feedStatus: status, fs, git });
    expect(r.matches.map((m) => [m.advisory.id, m.target.kind, m.severity])).toEqual([['GUARDA-1', 'declared', 'high']]);
    expect(r.coverage.complete).toBe(false);
    expect(r.coverage.skipped).toContainEqual({ path: 'package.json', reason: 'no-lockfile', detail: 'transitive dependencies not checked; commit a lockfile' });
    expect(r.coverage.inventory).toEqual({ packages: 1, lockfiles: 0, declared: 1, manifests: 1, actions: 0, workflows: 0, runtimes: 0, runtimeFiles: 0, images: 0, imageFiles: 0 });
  });
  it('with a committed lockfile next to it, package.json pins are not duplicated and its ranges are informational', async () => {
    const fs = memoryFs({ 'package.json': JSON.stringify({ dependencies: { keyv: '^5.7.0', other: '1.0.0' } }), 'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/keyv': { version: '5.7.3' }, 'node_modules/other': { version: '1.0.0' } } }) });
    const r = await scan('/repo', { feed, feedStatus: status, fs, git });
    expect(r.matches.map((m) => [m.advisory.id, m.target.kind, m.severity])).toEqual([['GUARDA-1', 'declared', 'info']]);
    expect(r.coverage.skipped.some((k) => k.reason === 'no-lockfile')).toBe(false);
    expect(r.coverage.inventory).toMatchObject({ packages: 2, lockfiles: 1, declared: 1, manifests: 1 });
  });
  it('a gitignored lockfile does not reach CI: ranges are real exposures and coverage says so', async () => {
    const fs = memoryFs({ 'package.json': JSON.stringify({ dependencies: { keyv: '^5.7.0' } }), 'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/keyv': { version: '5.7.3' } } }) });
    const gitIgnoringLock: GitAdapter = { ...git, ignored: async () => new Set(['package-lock.json']) };
    const r = await scan('/repo', { feed, feedStatus: status, fs, git: gitIgnoringLock });
    expect(r.matches.map((m) => [m.advisory.id, m.target.kind, m.severity])).toEqual([['GUARDA-1', 'declared', 'high']]);
    expect(r.coverage.skipped).toContainEqual({ path: 'package-lock.json', reason: 'no-lockfile', detail: 'gitignored: CI resolves package.json ranges fresh' });
    expect(r.coverage.complete).toBe(false);
  });
  it('returns an empty complete report for an empty directory', async () => {
    const r = await scan('/repo', { feed, feedStatus: status, fs: memoryFs({}), git });
    expect(r.coverage.inventory).toEqual({ packages: 0, lockfiles: 0, declared: 0, manifests: 0, actions: 0, workflows: 0, runtimes: 0, runtimeFiles: 0, images: 0, imageFiles: 0 });
    expect(r).toMatchObject({ matches: [], secrets: [], coverage: { scannedFiles: 0, skipped: [], complete: true } });
  });
});

describe('scan: runtimes', () => {
  const phpFeed: Feed = { ...feed, advisories: [...feed.advisories,
    { source: 'guarda', advisory: { id: 'GUARDA-PHP', modified: 'x', summary: 'PHP2Shell', affected: [{ package: { ecosystem: 'software', name: 'php' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '8.2.34' }] }] }], database_specific: { seenty: { severity: 'critical' } } } },
  ] };
  it('an exact runtime inside the range is a hit; a major-only one is a possible hit; coverage counts runtimes', async () => {
    const fs = memoryFs({ 'Dockerfile': 'FROM php:8.2.33-fpm\n', 'legacy/Dockerfile': 'FROM php:8.2-apache\n', '.nvmrc': 'v22.1.0\n' });
    const r = await scan('/repo', { feed: phpFeed, feedStatus: status, fs, git, secrets: false });
    const hits = r.matches.filter((m) => m.target.kind === 'package' && m.target.package.ecosystem === 'software').map((m) => m.target.kind === 'package' ? `${m.target.package.name}@${m.target.package.version} ${m.target.package.lockfile} · ${m.clause}` : '');
    expect(hits).toEqual(['php@8.2.33 Dockerfile · >= 0, < 8.2.34', 'php@8.2 legacy/Dockerfile · possibly affected: the 8.2 line is in >= 0, < 8.2.34; set the exact version']);
    expect(r.coverage.inventory).toMatchObject({ runtimes: 3, runtimeFiles: 3 });
    expect(r.coverage.complete).toBe(true);
  });
  it('a runtime without a version is reported as unchecked, not matched', async () => {
    const fs = memoryFs({ 'Dockerfile': 'FROM php:latest\n' });
    const r = await scan('/repo', { feed: phpFeed, feedStatus: status, fs, git, secrets: false });
    expect(r.matches).toEqual([]);
    expect(r.coverage.skipped).toEqual(expect.arrayContaining([{ path: 'Dockerfile', reason: 'unsupported-entry', detail: 'line 1: php has no version to check (latest); pin the tag' }]));
  });
});

describe('scan: container images', () => {
  const imageFeed: Feed = { ...feed, advisories: [...feed.advisories,
    { source: 'guarda', advisory: { id: 'GUARDA-IMG', modified: 'x', summary: 'LiteLLM image compromised', affected: [{ package: { ecosystem: 'Docker', name: 'litellm/litellm' }, versions: ['1.107.0'] }], database_specific: { seenty: { severity: 'critical' } } } },
  ] };
  it('an image pulled by tag matches a Docker advisory; untagged images are reported as unchecked', async () => {
    const fs = memoryFs({ 'docker-compose.yml': 'services:\n  llm:\n    image: docker.io/litellm/litellm:1.107.0\n', 'Dockerfile': 'FROM litellm/litellm:1.107.1\nFROM php\n' });
    const r = await scan('/repo', { feed: imageFeed, feedStatus: status, fs, git, secrets: false });
    expect(r.matches.map((m) => (m.target.kind === 'package' ? `${m.target.package.ecosystem} ${m.target.package.name}@${m.target.package.version} ${m.target.package.lockfile}:${m.target.package.line}` : ''))).toEqual(['Docker litellm/litellm@1.107.0 docker-compose.yml:3']);
    expect(r.coverage.inventory).toMatchObject({ images: 3, imageFiles: 2 });
    expect(r.coverage.skipped).toEqual(expect.arrayContaining([{ path: 'Dockerfile', reason: 'unsupported-entry', detail: 'line 2: library/php has no tag or digest to check; pin it' }]));
  });
});
