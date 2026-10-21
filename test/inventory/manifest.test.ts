import { describe, expect, it } from 'vitest';
import { parseNpmManifest } from '../../src/inventory/npm-manifest.js';

const manifest = JSON.stringify({
  name: 'app', version: '1.0.0',
  dependencies: { chalk: '5.6.1', express: '^4.18.0', lodash: '~4.17.0', any: '*', fromgit: 'github:org/repo', local: 'file:../x', alias: 'npm:real@1.2.3' },
  devDependencies: { vitest: '=3.2.0' },
  optionalDependencies: { fsevents: '2.3.3' },
  peerDependencies: { react: '>=18' },
}, null, 2);

describe('parseNpmManifest (package.json without a lockfile)', () => {
  const r = parseNpmManifest(manifest, 'package.json');
  it('exact pins become packages attributed to package.json, with their line', () => {
    expect(r.packages.map((p) => `${p.name}@${p.version}:${p.lockfile}`).sort()).toEqual(['chalk@5.6.1:package.json', 'fsevents@2.3.3:package.json', 'vitest@3.2.0:package.json']);
    expect(r.packages.every((p) => p.ecosystem === 'npm' && p.direct === true && typeof p.line === 'number')).toBe(true);
  });
  it('ranges become declared dependencies; peerDependencies are not installed and are left out', () => {
    expect(r.declared.map((d) => `${d.name} ${d.range}`).sort()).toEqual(['any *', 'express ^4.18.0', 'lodash ~4.17.0']);
    expect(r.declared[0]!.manifest).toBe('package.json');
  });
  it('specs that are not versions or semver ranges are reported, never guessed', () => {
    expect(r.skipped.map((s) => s.detail)).toEqual(expect.arrayContaining([expect.stringContaining('fromgit'), expect.stringContaining('local'), expect.stringContaining('alias')]));
    expect(r.skipped.every((s) => s.reason === 'unsupported-entry' && s.path === 'package.json')).toBe(true);
  });
  it('tolerates a broken manifest with a parse error that carries no content', () => {
    const broken = parseNpmManifest('{"dependencies": {"a": "1.0.0",', 'package.json');
    expect(broken.packages).toEqual([]); expect(broken.declared).toEqual([]);
    expect(broken.skipped[0]!.reason).toBe('parse-error'); expect(broken.skipped[0]!.detail).not.toContain('1.0.0');
  });
});
