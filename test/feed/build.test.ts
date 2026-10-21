import { describe, expect, it } from 'vitest';
import { canonicalize, sha256Hex } from '../../src/feed/canonical.js';
import { buildFeed, translateAdvisory } from '../../src/feed/build.js';
import { generateKeyPair } from '../../src/feed/sign.js';
import { verifyManifest, verifyShard } from '../../src/feed/verify.js';

const input = { title: 'keyv poisoned', summary: 'stealer', severity: 'critical' as const, source_label: 'Wiz', reference_urls: ['https://w.example'], published_at: '2026-10-09T13:10:00Z', updated_at: '2026-10-09T13:16:00Z', kind: 'poisoned_release', window: { from: 'a', to: 'b' }, remediation: 'pin 5.7.1',
  packages: [{ ecosystem: 'npm', package_name: 'keyv', affected_versions: '5.7.2, 5.7.3' }, { ecosystem: 'github actions', package_name: 'aquasecurity/trivy-action', affected_versions: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef', exposed_refs: ['0.28.0'] }] };

describe('translateAdvisory', () => {
  it('produces an OSV-shaped advisory with Seenty fields and canonical ecosystems', () => {
    const a = translateAdvisory(input, 42);
    expect(a.id).toBe('GUARDA-2026-0042');
    expect(a.affected[0]).toEqual({ package: { ecosystem: 'npm', name: 'keyv', purl: 'pkg:npm/keyv' }, versions: ['5.7.2', '5.7.3'], ranges: [] });
    expect(a.affected[1]!.package.ecosystem).toBe('GitHub Actions');
    expect(a.database_specific?.seenty).toEqual({ severity: 'critical', source_label: 'Wiz', kind: 'poisoned_release', window: { from: 'a', to: 'b' }, remediation: 'pin 5.7.1', exposed_refs: ['0.28.0'] });
    expect(a.references).toEqual([{ type: 'REPORT', url: 'https://w.example' }]);
  });
  it('throws on an unparsable token', () => {
    expect(() => translateAdvisory({ ...input, packages: [{ ecosystem: 'npm', package_name: 'x', affected_versions: '>1.2.3' }] }, 1)).toThrow(/">1.2.3"/);
  });
});

describe('buildFeed', () => {
  it('writes hashed shards and a signed manifest that verify', () => {
    const k = generateKeyPair();
    const out = buildFeed({ advisories: [input], mal: [{ id: 'MAL-1', modified: 'x', summary: 's', affected: [{ package: { ecosystem: 'npm', name: 'evil' }, versions: ['1.0.0'] }] }], malMeta: { snapshot: '2026-10-09T01:00:00Z', commit: 'abc' }, feedVersion: 7, now: new Date('2026-10-09T14:00:00Z'), privateKeyPem: k.privateKeyPem });
    expect(out.manifest.feed_version).toBe(7);
    expect(out.manifest.expires_at).toBe('2026-10-16T14:00:00.000Z');
    expect(out.manifest.shards.map((s) => s.source + ':' + s.ecosystem)).toEqual(['guarda:*', 'openssf-mal:npm']);
    for (const s of out.manifest.shards) {
      expect(s.url).toMatch(new RegExp(`^${s.source}(-npm)?\\.${s.sha256}\\.json$`));
      const bytes = out.files.get(s.url)!;
      expect(sha256Hex(bytes)).toBe(s.sha256); expect(bytes.byteLength).toBe(s.bytes);
      expect(verifyShard(bytes, s.sha256).ok).toBe(true);
    }
    expect(out.manifestBytes.toString()).toBe(canonicalize(out.manifest));
    expect(verifyManifest(out.manifestBytes, out.signature, [k.publicKeyPem]).ok).toBe(true);
    expect(out.manifest.sources['openssf-mal']?.attribution).toContain('OpenSSF');
  });
});
