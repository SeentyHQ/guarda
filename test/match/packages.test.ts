import { describe, expect, it } from 'vitest';
import { matchPackages, severityOf } from '../../src/match/packages.js';
import type { Advisory, Feed, Package } from '../../src/types.js';

const adv = (id: string, affected: Advisory['affected'], extra: Partial<Advisory> = {}): Advisory => ({ id, modified: '2026-10-09T00:00:00Z', summary: id, affected, ...extra });
const feed = (entries: Feed['advisories']): Feed => ({ manifest: { schema_version: '1.0.0', feed_version: 1, generated_at: 'x', expires_at: 'y', min_cli_version: '0.1.0', sources: {}, shards: [] }, advisories: entries });
const p = (name: string, version: string, ecosystem: Package['ecosystem'] = 'npm'): Package => ({ ecosystem, name, version, purl: '', lockfile: 'package-lock.json' });

describe('matchPackages', () => {
  it('matches exact versions by normalized name and version, with the clause', () => {
    const f = feed([{ source: 'guarda', advisory: adv('GUARDA-1', [{ package: { ecosystem: 'npm', name: 'KeyV' }, versions: ['v5.7.2', '5.7.3'] }], { database_specific: { seenty: { severity: 'critical' } } }) }]);
    const r = matchPackages([p('keyv', '5.7.2'), p('keyv', '5.7.1')], f);
    expect(r.matches).toHaveLength(1);
    expect(r.matches[0]!.clause).toBe('= 5.7.2');
    expect(r.matches[0]!.severity).toBe('critical');
    expect(r.matches[0]!.source).toBe('guarda');
  });
  it('matches ranges through the events walker', () => {
    const f = feed([{ source: 'openssf-mal', advisory: adv('MAL-1', [{ package: { ecosystem: 'npm', name: 'cacheable' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '2.1.0' }, { fixed: '2.1.3' }] }] }]) }]);
    const r = matchPackages([p('cacheable', '2.1.2'), p('cacheable', '2.1.3')], f);
    expect(r.matches.map((m) => m.clause)).toEqual(['>= 2.1.0, < 2.1.3']);
    expect(r.matches[0]!.severity).toBe('high');
  });
  it('skips withdrawn advisories and ecosystems without a comparator, and mismatched ecosystems', () => {
    const f = feed([
      { source: 'guarda', advisory: adv('W', [{ package: { ecosystem: 'npm', name: 'a' }, versions: ['1.0.0'] }], { withdrawn: '2026-01-01T00:00:00Z' }) },
      { source: 'guarda', advisory: adv('M', [{ package: { ecosystem: 'Maven', name: 'g:a' }, versions: ['1.0.0'] }]) },
      { source: 'guarda', advisory: adv('P', [{ package: { ecosystem: 'pypi', name: 'Requests' }, versions: ['2.0.0'] }]) },
    ]);
    const r = matchPackages([p('a', '1.0.0'), p('g:a', '1.0.0', 'Maven'), p('requests', '2.0.0', 'PyPI'), p('requests', '2.0.0')], f);
    expect(r.matches.map((m) => m.advisory.id)).toEqual(['P']);
    expect(r.skipped).toEqual([{ path: 'package-lock.json', reason: 'unsupported-ecosystem', detail: 'Maven: g:a@1.0.0' }]);
  });
  it('severityOf falls back by source', () => {
    expect(severityOf(adv('x', []), 'openssf-mal')).toBe('high');
    expect(severityOf(adv('x', []), 'guarda')).toBe('medium');
  });
});

describe('software advisories', () => {
  it('a declared runtime hits a software advisory by catalog slug and range', () => {
    const f = feed([{ source: 'guarda', advisory: adv('PHP2SHELL', [{ package: { ecosystem: 'software', name: 'php' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '8.2.34' }] }] }]) }]);
    const r = matchPackages([p('PHP', '8.2.33', 'software'), p('php', '8.2.34', 'software'), p('php', '8.2.33')], f);
    expect(r.matches.map((m) => [m.advisory.id, m.clause])).toEqual([['PHP2SHELL', '>= 0, < 8.2.34']]);
    expect(r.skipped).toEqual([]);
  });
});
