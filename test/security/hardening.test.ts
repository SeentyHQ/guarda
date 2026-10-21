import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { nodeGit } from '../../src/adapters.js';
import { collectInventory } from '../../src/inventory/index.js';
import { nodeFs, memoryFs } from '../../src/adapters.js';
import { parseWorkflow } from '../../src/inventory/workflows.js';
import { parsePnpmLock } from '../../src/inventory/pnpm-lock.js';
import { parseYarnLock } from '../../src/inventory/yarn-lock.js';
import { parseNpmLock } from '../../src/inventory/npm-lock.js';
import { scanSecrets } from '../../src/secrets/engine.js';
import { RULES } from '../../src/secrets/rules.js';
import { matchPackages } from '../../src/match/packages.js';
import { formatPretty } from '../../src/report/pretty.js';
import type { Feed, Report } from '../../src/types.js';

const TOKEN = 'ghp_' + 'Z'.repeat(36);
const tmp = () => mkdtempSync(join(tmpdir(), 'guarda-hard-'));

describe('critical 1: directories that are not git repositories', () => {
  it('nodeGit.ignored resolves to an empty set outside a repository instead of crashing', async () => {
    const dir = tmp(); writeFileSync(join(dir, 'a.txt'), 'x');
    await expect(nodeGit.ignored(dir, ['a.txt'])).resolves.toEqual(new Set());
  });
  it('nodeGit hardening flags disable repository-provided hooks and fsmonitor', async () => {
    const dir = tmp(); execFileSync('git', ['init', '-q'], { cwd: dir });
    execFileSync('git', ['-C', dir, 'config', 'core.fsmonitor', 'false']);
    writeFileSync(join(dir, '.gitignore'), 'ignored.txt\n');
    await expect(nodeGit.ignored(dir, ['ignored.txt', 'kept.txt'])).resolves.toEqual(new Set(['ignored.txt']));
  });
});

describe('critical 2: parser errors never carry file content', () => {
  it('workflow, pnpm, yarn and npm parse errors report only a position', () => {
    const wf = parseWorkflow(`jobs:\n  a:\n    steps:\n      - uses: x\n      TOKEN: ${TOKEN}: bad\n`, 'w.yml');
    const pn = parsePnpmLock(`lockfileVersion: '9.0'\npackages:\n  bad: [${TOKEN}\n`, 'pnpm-lock.yaml');
    const ya = parseYarnLock(`__metadata:\n  version: 8\n"x@npm:1":\n  version: 1\n  resolution: [${TOKEN}\n`, 'yarn.lock');
    const np = parseNpmLock(`{"packages": {"a": ${TOKEN}}}`, 'package-lock.json');
    for (const r of [wf, pn, ya, np]) {
      const text = JSON.stringify(r);
      expect(text).not.toContain(TOKEN);
      expect(r.skipped[0]?.reason).toBe('parse-error');
    }
    expect(wf.skipped[0]!.detail).toMatch(/line \d+/);
  });
});

describe('critical 3: hostile inputs stay within the time budget', () => {
  const anchors = (id: string) => RULES.find((r) => r.id === id)!.anchors ?? [];
  for (const [id, filler] of [['database-url-with-password', 'postgres://a:'], ['jwt-generic', '-eyJAAAA'], ['supabase-service-role-key', '-eyJAAAA'], ['openai-api-key', '-sk-proj-AAAA'], ['anthropic-api-key', '-sk-ant-api03-AAAA'], ['aws-secret-access-key', 'aws_secret_key=']] as const) {
    it(`${id}: 100 KB of repeated "${filler}" scans in under 50 ms, 1 MB in under 500 ms`, () => {
      expect(anchors(id).length).toBeGreaterThan(0);
      const small = filler.repeat(Math.ceil(100_000 / filler.length)); const big = filler.repeat(Math.ceil(1_000_000 / filler.length));
      let t = performance.now(); scanSecrets([{ path: 'x.txt', content: small, gitignored: false }]); expect(performance.now() - t).toBeLessThan(50);
      t = performance.now(); scanSecrets([{ path: 'x.txt', content: big, gitignored: false }]); expect(performance.now() - t).toBeLessThan(500);
    });
  }
  it('thousands of findings do not make line computation quadratic', () => {
    const content = ('const a = "AKIAIOSFODNN7EXAMPLE";\n').repeat(5000);
    const t = performance.now(); const r = scanSecrets([{ path: 'x.ts', content, gitignored: false }]); expect(performance.now() - t).toBeLessThan(300);
    expect(r).toHaveLength(5000); expect(r[4999]!.line).toBe(5000);
  });
});

describe('important: fault tolerance and silent drops', () => {
  it('a null lockfile entry is reported, not thrown', () => {
    const r = parseNpmLock('{"packages":{"":{},"node_modules/a":null,"node_modules/b":{"version":"1.0.0"}}}', 'package-lock.json');
    expect(r.packages.map((p) => p.name)).toEqual(['b']);
    expect(r.skipped[0]).toMatchObject({ reason: 'unsupported-entry' });
  });
  it('collectInventory survives a parser throwing and records a parse-error', async () => {
    const fs = memoryFs({ 'yarn.lock': '__metadata:\n  version: 8\n"x":\n  version: {a: [}\n' });
    const inv = await collectInventory('/repo', fs);
    expect(inv.skipped[0]).toMatchObject({ path: 'yarn.lock', reason: 'parse-error' });
  });
  it('a pnpm lockfile with no packages is empty, not an error', () => {
    expect(parsePnpmLock("lockfileVersion: '9.0'\nimporters:\n  .: {}\n", 'pnpm-lock.yaml')).toEqual({ packages: [], skipped: [] });
  });
  it('excluded directories, symlinks and binaries are reported as excluded without making coverage incomplete', async () => {
    const dir = tmp(); mkdirSync(join(dir, 'dist')); writeFileSync(join(dir, 'dist', 'bundle.js'), 'x'); writeFileSync(join(dir, 'logo.png'), 'PNG\0');
    const inv = await collectInventory(dir, nodeFs);
    expect(inv.skipped).toContainEqual({ path: 'dist', reason: 'excluded', detail: 'build output directory' });
  });
  it('a bad range in the feed skips that advisory instead of aborting the scan', () => {
    const feed: Feed = { manifest: { schema_version: '1.0.0', feed_version: 1, generated_at: 'x', expires_at: 'y', min_cli_version: '0.1.0', sources: {}, shards: [] }, advisories: [
      { source: 'openssf-mal', advisory: { id: 'MAL-BAD', modified: 'x', summary: 's', affected: [{ package: { ecosystem: 'npm', name: 'a' }, ranges: [{ type: 'SEMVER', events: [{ introduced: 'not-a-version' }] }] }] } },
      { source: 'openssf-mal', advisory: { id: 'MAL-ALL', modified: 'x', summary: 's', affected: [{ package: { ecosystem: 'npm', name: 'b' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }] }] } },
    ] };
    const r = matchPackages([{ ecosystem: 'npm', name: 'a', version: '1.0.0', purl: '', lockfile: 'l' }, { ecosystem: 'npm', name: 'b', version: 'git+https://x/y#abc', purl: '', lockfile: 'l' }], feed);
    expect(r.matches.map((m) => m.advisory.id)).toEqual(['MAL-ALL']);
    expect(r.skipped).toContainEqual({ path: 'l', reason: 'unsupported-entry', detail: 'MAL-BAD: invalid range for a' });
  });
  it('unwraps npm: aliases in npm v1 and yarn classic', () => {
    const v1 = parseNpmLock('{"lockfileVersion":1,"dependencies":{"safe":{"version":"npm:evil-pkg@1.0.0"}}}', 'package-lock.json');
    expect(v1.packages.map((p) => `${p.name}@${p.version}`)).toEqual(['evil-pkg@1.0.0']);
    const yc = parseYarnLock('# yarn lockfile v1\n\n\n"safe@npm:evil-pkg@^1":\n  version "1.0.0"\n  resolved "https://registry.yarnpkg.com/evil-pkg/-/evil-pkg-1.0.0.tgz#a"\n', 'yarn.lock');
    expect(yc.packages.map((p) => `${p.name}@${p.version}`)).toEqual(['evil-pkg@1.0.0']);
  });
  it('strips terminal control characters from untrusted names in the human output', () => {
    const report: Report = { engineVersion: '0.1.0', matches: [], secrets: [{ ruleId: 'r', title: 'T', severity: 'high', path: 'evil\x1b[31m\x07.txt', line: 1, redacted: 'x…(10 chars)…y', gitignored: false }],
      coverage: { scannedFiles: 1, skipped: [], complete: true, inventory: { packages: 0, lockfiles: 0, declared: 0, manifests: 0, actions: 0, workflows: 0, runtimes: 0, runtimeFiles: 0, images: 0, imageFiles: 0 }, feed: { version: 1, generatedAt: 'x', expiresAt: 'y', stale: false, origin: 'directory', sources: {} } } };
    const out = formatPretty(report, { color: false });
    expect(out).not.toContain('\x1b[31m'); expect(out).not.toContain('\x07'); expect(out).toContain('evil');
  });
});

describe('git invocation', () => {
  it('disables repository hooks and fsmonitor and trusts only the scanned root as safe.directory', async () => {
    const { gitArgs } = await import('../../src/adapters.js');
    expect(gitArgs('/repo', ['check-ignore'])).toEqual(['-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-c', 'safe.directory=/repo', '-C', '/repo', 'check-ignore']);
  });
});
