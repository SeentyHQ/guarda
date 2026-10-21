import { describe, expect, it } from 'vitest';
import { matchDeclared } from '../../src/match/declared.js';
import type { DeclaredDep, Feed } from '../../src/types.js';

const feed: Feed = { manifest: { schema_version: '1.0.0', feed_version: 1, generated_at: 'x', expires_at: 'y', min_cli_version: '0.1.0', sources: {}, shards: [] }, advisories: [
  { source: 'guarda', advisory: { id: 'GUARDA-1', modified: 'x', summary: 'chalk poisoned', affected: [{ package: { ecosystem: 'npm', name: 'chalk' }, versions: ['5.6.1'] }], database_specific: { seenty: { severity: 'critical' } } } },
  { source: 'openssf-mal', advisory: { id: 'MAL-1', modified: 'x', summary: 'evil all versions', affected: [{ package: { ecosystem: 'npm', name: 'evil' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }] }] } },
  { source: 'guarda', advisory: { id: 'GUARDA-2', modified: 'x', summary: 'left-pad window', affected: [{ package: { ecosystem: 'npm', name: 'left-pad' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '1.3.0' }, { fixed: '1.3.2' }] }] }], database_specific: { seenty: { severity: 'high' } } } },
] };
const dep = (name: string, range: string, lockfile: DeclaredDep['lockfile'] = 'none'): DeclaredDep => ({ ecosystem: 'npm', name, range, manifest: 'package.json', line: 3, lockfile });

describe('matchDeclared (ranges from package.json)', () => {
  it('a range that admits a poisoned exact version is a range exposure, one severity below the advisory', () => {
    const { matches } = matchDeclared([dep('chalk', '^5.6.0')], feed);
    expect(matches).toHaveLength(1);
    expect(matches[0]!.severity).toBe('high');
    expect(matches[0]!.target).toEqual({ kind: 'declared', declared: dep('chalk', '^5.6.0'), exposure: 'range' });
    expect(matches[0]!.clause).toBe('range ^5.6.0 admits poisoned 5.6.1');
  });
  it('a range that excludes every poisoned version is clean', () => {
    expect(matchDeclared([dep('chalk', '^5.7.0'), dep('chalk', '<5.6.1')], feed).matches).toEqual([]);
  });
  it('intersects with OSV event spans, including introduced-only spans', () => {
    expect(matchDeclared([dep('evil', '^2.0.0')], feed).matches.map((m) => [m.advisory.id, m.severity, m.clause])).toEqual([['MAL-1', 'medium', 'range ^2.0.0 overlaps >=0']]);
    expect(matchDeclared([dep('left-pad', '~1.3.0')], feed).matches.map((m) => m.clause)).toEqual(['range ~1.3.0 overlaps >=1.3.0 <1.3.2']);
    expect(matchDeclared([dep('left-pad', '^1.3.2')], feed).matches).toEqual([]);
  });
  it('a committed lockfile makes the exposure informational; a gitignored one does not', () => {
    expect(matchDeclared([dep('chalk', '^5.6.0', 'committed')], feed).matches[0]!.severity).toBe('info');
    expect(matchDeclared([dep('chalk', '^5.6.0', 'ignored')], feed).matches[0]!.severity).toBe('high');
  });
  it('reports an unparsable range instead of guessing', () => {
    const { matches, skipped } = matchDeclared([dep('chalk', 'latest')], feed);
    expect(matches).toEqual([]); expect(skipped[0]).toMatchObject({ path: 'package.json', reason: 'unsupported-entry' });
  });
});
