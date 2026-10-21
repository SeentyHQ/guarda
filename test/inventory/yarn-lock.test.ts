import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseYarnLock } from '../../src/inventory/yarn-lock.js';

const fx = (n: string) => readFileSync(new URL(`../fixtures/lockfiles/${n}`, import.meta.url), 'utf8');
const keys = (r: { packages: { name: string; version: string }[] }) => r.packages.map((p) => `${p.name}@${p.version}`).sort();

describe('parseYarnLock', () => {
  it('reads classic blocks with multiple descriptors', () => {
    const r = parseYarnLock(fx('yarn-classic.lock'), 'yarn.lock');
    expect(keys(r)).toEqual(['@scope/pkg@1.0.0', 'json-buffer@3.0.1', 'keyv@5.7.2']);
    expect(r.skipped).toEqual([]);
  });
  it('reads berry resolutions, unwraps patches and reports workspaces', () => {
    const r = parseYarnLock(fx('yarn-berry.lock'), 'yarn.lock');
    expect(keys(r)).toEqual(['@scope/pkg@1.0.0', 'json-buffer@3.0.1', 'keyv@5.7.2', 'left-pad@1.3.0']);
    expect(r.skipped).toEqual([{ path: 'yarn.lock', reason: 'unsupported-entry', detail: 'fixture@workspace:.: workspace' }]);
  });
  it('reports garbage', () => {
    expect(parseYarnLock('%%%', 'yarn.lock').skipped[0]!.reason).toBe('parse-error');
  });
});
