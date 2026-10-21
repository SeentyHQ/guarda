import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parsePnpmLock } from '../../src/inventory/pnpm-lock.js';

const fx = (n: string) => readFileSync(new URL(`../fixtures/lockfiles/${n}`, import.meta.url), 'utf8');
const keys = (r: { packages: { name: string; version: string }[] }) => r.packages.map((p) => `${p.name}@${p.version}`).sort();

describe('parsePnpmLock', () => {
  it('reads v5 keys with slash separators and peer suffixes', () => {
    expect(keys(parsePnpmLock(fx('pnpm-lock-v5.yaml'), 'pnpm-lock.yaml'))).toEqual(['@scope/pkg@1.0.0', 'json-buffer@3.0.1', 'keyv@5.7.2']);
  });
  it('reads v6 keys with @ separators and reports link entries', () => {
    const r = parsePnpmLock(fx('pnpm-lock-v6.yaml'), 'pnpm-lock.yaml');
    expect(keys(r)).toEqual(['@scope/pkg@1.0.0', 'keyv@5.7.2']);
    expect(r.skipped).toEqual([{ path: 'pnpm-lock.yaml', reason: 'unsupported-entry', detail: '/local@link:../local: link' }]);
  });
  it('reads v9 packages and marks importer dependencies as direct', () => {
    const r = parsePnpmLock(fx('pnpm-lock-v9.yaml'), 'pnpm-lock.yaml');
    expect(keys(r)).toEqual(['@scope/pkg@1.0.0', 'json-buffer@3.0.1', 'keyv@5.7.2']);
    expect(r.packages.find((p) => p.name === 'keyv')!.direct).toBe(true);
  });
  it('treats a lockfile without packages as empty and a non-lockfile as an error', () => {
    expect(parsePnpmLock('lockfileVersion: 9.0\n', 'pnpm-lock.yaml')).toEqual({ packages: [], skipped: [] });
    expect(parsePnpmLock('', 'pnpm-lock.yaml').skipped[0]).toEqual({ path: 'pnpm-lock.yaml', reason: 'parse-error', detail: 'no "packages" field' });
  });
});
