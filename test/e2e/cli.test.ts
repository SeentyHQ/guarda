import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { buildFeed, type AdvisoryInput } from '../../src/feed/build.js';
import { generateKeyPair } from '../../src/feed/sign.js';

const fixtures = new URL('../fixtures/', import.meta.url).pathname;
const pkgRoot = new URL('../../', import.meta.url).pathname;
let feedDir: string; let pub: string; let cache: string; let repo: string;

function run(args: string[], env: Record<string, string> = {}) {
  const r = spawnSync(process.execPath, [join(pkgRoot, 'node_modules/tsx/dist/cli.mjs'), join(pkgRoot, 'src/bin.ts'), ...args], { cwd: pkgRoot, encoding: 'utf8', env: { ...process.env, HOME: '/nonexistent', GUARDA_CACHE_DIR: cache, GUARDA_FEED_PUBKEY: pub, CI: '', ...env } });
  return { code: r.status ?? -1, out: r.stdout, err: r.stderr };
}

beforeAll(() => {
  const k = generateKeyPair(); pub = k.publicKeyPem;
  const advisories = JSON.parse(readFileSync(join(fixtures, 'advisories.json'), 'utf8')) as AdvisoryInput[];
  const f = buildFeed({ advisories, mal: [{ id: 'MAL-2026-0001', modified: '2026-10-01T00:00:00Z', summary: 'Malicious code in evil-pkg (npm)', affected: [{ package: { ecosystem: 'npm', name: 'evil-pkg' }, versions: ['1.0.0', '1.0.1'] }] }], feedVersion: 1, now: new Date(), privateKeyPem: k.privateKeyPem });
  feedDir = mkdtempSync(join(tmpdir(), 'guarda-feed-')); cache = mkdtempSync(join(tmpdir(), 'guarda-cache-'));
  writeFileSync(join(feedDir, 'manifest.json'), f.manifestBytes); writeFileSync(join(feedDir, 'manifest.json.sig'), f.signature);
  for (const [n, b] of f.files) writeFileSync(join(feedDir, n), b);
  repo = mkdtempSync(join(tmpdir(), 'guarda-repo-')); cpSync(join(fixtures, 'repo'), repo, { recursive: true });
  execFileSync('git', ['init', '-q'], { cwd: repo });
});

describe('guarda e2e', () => {
  it('finds every planted problem and exits 1', () => {
    const r = run([repo, '--feed', feedDir, '--json']);
    expect(r.code, r.err).toBe(1);
    const report = JSON.parse(r.out);
    const ids = report.matches.map((m: { advisory: { id: string }; clause: string }) => `${m.advisory.id} ${m.clause}`).sort();
    expect(ids).toEqual(['GUARDA-2026-0001 = 5.7.2', 'GUARDA-2026-0001 >= 2.1.0, < 2.1.3', 'GUARDA-2026-0002 ref 0.28.0 exposed between 2026-03-19T00:00:00Z and 2026-03-19T12:00:00Z', 'GUARDA-2026-0002 sha deadbeefdeadbeefdeadbeefdeadbeefdeadbeef', 'MAL-2026-0001 = 1.0.1']);
    expect(report.secrets.map((s: { ruleId: string; path: string; gitignored: boolean }) => [s.ruleId, s.path, s.gitignored]).sort()).toEqual([['aws-secret-access-key', '.env', true], ['github-pat', 'src/config.ts', false]]);
    expect(report.coverage.complete).toBe(false);
    expect(report.coverage.skipped.map((s: { path: string }) => s.path)).toContain('legacy/bun.lockb');
    expect(r.out).not.toContain('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
  });
  it('honours --fail-on, --strict and --only', () => {
    expect(run([repo, '--feed', feedDir, '--fail-on', 'none']).code).toBe(0);
    expect(run([repo, '--feed', feedDir, '--strict', '--fail-on', 'none']).code).toBe(2);
    const r = run([repo, '--feed', feedDir, '--only', 'secrets', '--json']);
    expect(JSON.parse(r.out).matches).toEqual([]);
  });
  it('emits sarif', () => {
    const r = run([repo, '--feed', feedDir, '--sarif']);
    expect(JSON.parse(r.out).runs[0].results.length).toBe(7);
  });
  it('explain and feed work from the directory source', () => {
    expect(run(['explain', 'GUARDA-2026-0001', '--feed', feedDir]).out).toContain('keyv poisoned releases');
    expect(run(['feed', '--feed', feedDir, '--verify']).out).toContain('signature ok');
    // Without status.json the command prints the manifest summary only; with it, the publisher's counts.
    expect(run(['feed', '--feed', feedDir]).out).not.toContain('curated advisories:');
    writeFileSync(join(feedDir, 'status.json'), JSON.stringify({ schema_version: '1', feed_version: 1, generated_at: 'g', expires_at: 'e', published_at: '2026-10-24T10:00:05Z', manifest_sha256: 'x', sources: {}, counts: { curated_advisories: 2, mal_records: 1, left_out: 0, by_ecosystem: { npm: 2 }, by_kind: {}, by_severity: {} }, latest_curated_published_at: null, left_out: [] }));
    expect(run(['feed', '--feed', feedDir]).out).toContain('curated advisories: 2 (npm 2); malicious-package records: 1');
  });
  it('scans a directory that is not a git repository without crashing', () => {
    const plain = mkdtempSync(join(tmpdir(), 'guarda-plain-')); cpSync(join(fixtures, 'repo'), plain, { recursive: true });
    const r = run([plain, '--feed', feedDir, '--json']);
    expect(r.code, r.err).toBe(1);
    const report = JSON.parse(r.out);
    expect(report.secrets.map((s: { path: string; gitignored: boolean }) => [s.path, s.gitignored]).sort()).toEqual([['.env', false], ['src/config.ts', false]]);
  });
  it('never prints a token that sits on an unparsable workflow line', () => {
    const dir = mkdtempSync(join(tmpdir(), 'guarda-leak-')); mkdirSync(join(dir, '.github', 'workflows'), { recursive: true });
    const token = 'ghp_' + 'Q'.repeat(36);
    writeFileSync(join(dir, '.github', 'workflows', 'bad.yml'), `jobs:\n  a:\n    steps:\n      - uses: x\n      TOKEN: ${token}: bad\n`);
    for (const flags of [['--json'], ['--sarif'], []]) {
      const r = run([dir, '--feed', feedDir, ...flags]);
      expect(r.out + r.err).not.toContain(token);
      expect(r.out + r.err).toContain('ghp_');
    }
  });
  it('returns 3 on an empty directory and prints the footer only outside CI', () => {
    const empty = mkdtempSync(join(tmpdir(), 'guarda-empty-')); mkdirSync(empty, { recursive: true });
    expect(run([empty, '--feed', feedDir]).code).toBe(3);
    expect(run([repo, '--feed', feedDir]).out).toContain('Report a compromised package');
    expect(run([repo, '--feed', feedDir], { CI: 'true' }).out).not.toContain('Report a compromised package');
  });
});
