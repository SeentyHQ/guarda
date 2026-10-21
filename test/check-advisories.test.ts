import { describe, expect, it } from 'vitest';
import { checkAdvisories } from '../scripts/check-advisories.js';

describe('checkAdvisories', () => {
  it('accepts the fixture advisories and reports counts', () => {
    const r = checkAdvisories(new URL('./fixtures/advisories.json', import.meta.url).pathname);
    expect(r.errors).toEqual([]);
    expect(r.summary).toMatchObject({ records: 2, packages: 3, ecosystems: { npm: 2, 'GitHub Actions': 1 } });
  });
  it('reports the record index, package and reason for every invalid token or unknown ecosystem', () => {
    const r = checkAdvisories(new URL('./fixtures/advisories-bad.json', import.meta.url).pathname);
    expect(r.errors).toEqual([
      { record: 0, title: 'bad range', package: 'npm:x', reason: 'cannot publish token ">1.2.3": operator > cannot be expressed as OSV events' },
      { record: 1, title: 'bad ecosystem', package: 'hex:y', reason: 'unknown ecosystem hex' },
      { record: 2, title: 'missing fields', package: '', reason: 'missing title, severity or packages' },
    ]);
  });
});
