import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseBunLock } from '../../src/inventory/bun-lock.js';

describe('parseBunLock', () => {
  it('reads JSONC with trailing commas, nested keys and reports workspaces', () => {
    const r = parseBunLock(readFileSync(new URL('../fixtures/lockfiles/bun.lock', import.meta.url), 'utf8'), 'bun.lock');
    expect(r.packages.map((p) => `${p.name}@${p.version}`).sort()).toEqual(['@scope/pkg@1.0.0', 'json-buffer@2.0.0', 'json-buffer@3.0.1', 'keyv@5.7.2']);
    expect(r.packages.find((p) => p.name === 'keyv')!.direct).toBe(true);
    expect(r.skipped).toEqual([{ path: 'bun.lock', reason: 'unsupported-entry', detail: 'lib: workspace' }]);
  });
  it('reports a file without packages', () => {
    expect(parseBunLock('{ "lockfileVersion": 1 }', 'bun.lock').skipped[0]!.detail).toBe('no "packages" field');
  });
});
