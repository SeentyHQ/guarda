import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseNpmLock } from '../../src/inventory/npm-lock.js';

const fx = (n: string) => readFileSync(new URL(`../fixtures/lockfiles/${n}`, import.meta.url), 'utf8');
const key = (p: { name: string; version: string }) => `${p.name}@${p.version}`;

describe('parseNpmLock', () => {
  it('reads v3 packages, nested duplicates, aliases and marks direct deps', () => {
    const r = parseNpmLock(fx('package-lock-v3.json'), 'package-lock.json');
    expect(r.packages.map(key).sort()).toEqual(['@scope/pkg@1.0.0', 'keyv@4.5.4', 'keyv@5.7.2', 'real-name@2.0.0']);
    const keyv = r.packages.find((p) => key(p) === 'keyv@5.7.2')!;
    expect(keyv.direct).toBe(true);
    expect(keyv.purl).toBe('pkg:npm/keyv@5.7.2');
    expect(keyv.ecosystem).toBe('npm');
    expect(keyv.lockfile).toBe('package-lock.json');
    expect(r.packages.find((p) => p.name === '@scope/pkg')!.purl).toBe('pkg:npm/%40scope/pkg@1.0.0');
    expect(r.skipped).toEqual([
      { path: 'package-lock.json', reason: 'unsupported-entry', detail: 'node_modules/linked: link' },
      { path: 'package-lock.json', reason: 'unsupported-entry', detail: 'packages/linked: workspace' },
    ]);
  });
  it('reads v1 nested dependencies', () => {
    const r = parseNpmLock(fx('package-lock-v1.json'), 'a/package-lock.json');
    expect(r.packages.map(key).sort()).toEqual(['@scope/pkg@1.0.0', 'json-buffer@3.0.1', 'keyv@5.7.2']);
  });
  it('reports a JSON file that is not a lockfile', () => {
    expect(parseNpmLock('{}', 'package-lock.json')).toEqual({ packages: [], skipped: [{ path: 'package-lock.json', reason: 'parse-error', detail: 'no "packages" or "dependencies" field' }] });
    expect(parseNpmLock('not json', 'package-lock.json').skipped[0]!.reason).toBe('parse-error');
  });
});
