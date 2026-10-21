import { describe, expect, it } from 'vitest';
import { readMalClone } from '../../src/feed/mal.js';

describe('readMalClone', () => {
  it('keeps id, modified, withdrawn, affected versions and ranges, drops details', async () => {
    const dir = new URL('../fixtures/mal', import.meta.url).pathname;
    const recs = await readMalClone(dir, ['npm']);
    expect(recs.map((r) => r.id).sort()).toEqual(['MAL-2026-0001', 'MAL-2026-0002']);
    const a = recs.find((r) => r.id === 'MAL-2026-0001')!;
    expect(a.details).toBeUndefined();
    expect(a.affected[0]!.versions).toEqual(['1.0.0', '1.0.1']);
    expect(recs.find((r) => r.id === 'MAL-2026-0002')!.withdrawn).toBe('2026-10-03T00:00:00Z');
  });
  it('returns nothing for an ecosystem directory that does not exist', async () => {
    expect(await readMalClone(new URL('../fixtures/mal', import.meta.url).pathname, ['PyPI'])).toEqual([]);
  });
});
