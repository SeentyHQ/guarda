import { describe, expect, it } from 'vitest';
import { matchActions } from '../../src/match/actions.js';
import type { ActionRef, Feed } from '../../src/types.js';

const feed: Feed = { manifest: { schema_version: '1.0.0', feed_version: 1, generated_at: 'x', expires_at: 'y', min_cli_version: '0.1.0', sources: {}, shards: [] }, advisories: [{
  source: 'guarda',
  advisory: { id: 'GUARDA-2026-0001', modified: 'x', summary: 'trivy-action tags hijacked', affected: [{ package: { ecosystem: 'GitHub Actions', name: 'aquasecurity/trivy-action' }, versions: ['deadbeefdeadbeefdeadbeefdeadbeefdeadbeef'] }],
    database_specific: { seenty: { severity: 'critical', exposed_refs: ['0.28.0', 'master'], window: { from: '2026-03-19T00:00:00Z', to: '2026-03-19T12:00:00Z' } } } },
}] };
const a = (repo: string, ref: string, refKind: ActionRef['refKind']): ActionRef => ({ repo, ref, refKind, workflow: 'ci.yml', line: 1 });

describe('matchActions', () => {
  it('classifies malicious sha, exposed ref and unlisted ref', () => {
    const r = matchActions([
      a('aquasecurity/trivy-action', 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef', 'sha'),
      a('AquaSecurity/Trivy-Action', '0.28.0', 'tag'),
      a('aquasecurity/trivy-action', '0.29.0', 'tag'),
      a('actions/checkout', 'v4', 'tag'),
    ], feed);
    expect(r.map((m) => [m.target.kind === 'action' ? m.target.exposure : '', m.severity, m.clause])).toEqual([
      ['malicious-sha', 'critical', 'sha deadbeefdeadbeefdeadbeefdeadbeefdeadbeef'],
      ['exposed-ref', 'critical', 'ref 0.28.0 exposed between 2026-03-19T00:00:00Z and 2026-03-19T12:00:00Z'],
      ['repo-listed', 'info', 'ref 0.29.0 not listed'],
    ]);
  });
});
