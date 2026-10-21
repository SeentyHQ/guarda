import { describe, expect, it } from 'vitest';
import { RULES, RuleSchema } from '../../src/secrets/rules.js';

describe('secret rules', () => {
  it('validate against the schema and have unique ids', () => {
    for (const r of RULES) expect(() => RuleSchema.parse(r)).not.toThrow();
    expect(new Set(RULES.map((r) => r.id)).size).toBe(RULES.length);
    expect(RULES.length).toBeGreaterThanOrEqual(20);
  });
  for (const r of RULES) {
    it(`${r.id} matches its positives and not its negatives`, () => {
      for (const p of r.examples.positive) { const m = new RegExp(r.pattern.source, r.pattern.flags.replace('g', '')).exec(p); expect(m, p).not.toBeNull(); if (r.validate) expect(r.validate(m![1] ?? m![0]), p).toBe(true); }
      for (const n of r.examples.negative) { const m = new RegExp(r.pattern.source, r.pattern.flags.replace('g', '')).exec(n); expect(m === null || (r.validate !== undefined && !r.validate(m[1] ?? m[0])), n).toBe(true); }
    });
    it(`${r.id} stays under the ReDoS budget`, () => {
      const adversarial = (r.keywords[0] ?? 'x') + '='.repeat(10) + 'a'.repeat(100_000) + '!';
      const t = performance.now(); new RegExp(r.pattern.source, r.pattern.flags).test(adversarial); expect(performance.now() - t).toBeLessThan(50);
    });
  }
});
