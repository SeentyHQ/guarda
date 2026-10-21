import { describe, expect, it } from 'vitest';
import { comparatorFor } from '../../src/match/comparators.js';

describe('semver comparator (npm, crates.io, Go, Packagist)', () => {
  const c = comparatorFor('npm')!;
  it('normalizes v prefixes and keeps pre-releases', () => {
    expect(c.normalize('v1.2.3')).toBe('1.2.3');
    expect(c.normalize('1.2.3-beta.1')).toBe('1.2.3-beta.1');
    expect(c.normalize('1.2.3+build.5')).toBe('1.2.3');
    expect(c.normalize('not a version')).toBeNull();
  });
  it('orders pre-releases before the release', () => {
    expect(c.compare('1.2.3-beta.1', '1.2.3')).toBeLessThan(0);
    expect(c.compare('1.2.3', '1.2.3')).toBe(0);
    expect(c.compare('1.10.0', '1.9.0')).toBeGreaterThan(0);
  });
  it('handles Go pseudo-versions as pre-releases of the next patch', () => {
    const g = comparatorFor('Go')!;
    expect(g.compare('v0.0.0-20240101120000-abcdefabcdef', 'v0.1.0')).toBeLessThan(0);
  });
});

describe('PEP 440 comparator', () => {
  const c = comparatorFor('PyPI')!;
  it('orders dev, pre, release, post', () => {
    expect(c.compare('1.0.dev1', '1.0a1')).toBeLessThan(0);
    expect(c.compare('1.0rc1', '1.0')).toBeLessThan(0);
    expect(c.compare('1.0', '1.0.post1')).toBeLessThan(0);
    expect(c.compare('1.0', '1.0.0')).toBe(0);
  });
  it('rejects garbage', () => { expect(c.normalize('1.0.x')).toBeNull(); });
});

it('has no comparator for Maven, RubyGems, NuGet', () => {
  expect(comparatorFor('Maven')).toBeNull(); expect(comparatorFor('RubyGems')).toBeNull(); expect(comparatorFor('NuGet')).toBeNull();
});

describe('software comparator (coerced dotted numbers)', () => {
  const c = comparatorFor('software')!;
  it('coerces runtime, OS and product version strings', () => {
    expect(c.normalize('8.2.33')).toBe('8.2.33');
    expect(c.normalize('22.04')).toBe('22.4.0');
    expect(c.normalize('2019')).toBe('2019.0.0');
    expect(c.normalize('v1.107.0')).toBe('1.107.0');
    expect(c.normalize('latest')).toBeNull();
  });
  it('orders them numerically', () => {
    expect(c.compare('22.04', '22.10')).toBeLessThan(0);
    expect(c.compare('8.2.33', '8.2.34')).toBeLessThan(0);
    expect(c.compare('8.2.33', '8.10.0')).toBeLessThan(0);
    expect(c.compare('1.107.0', '1.107.0')).toBe(0);
    expect(() => c.compare('latest', '1.0')).toThrow(/not a software version/);
  });
});

describe('Docker comparator (tags are opaque: equality only)', () => {
  const c = comparatorFor('Docker')!;
  it('keeps any non-empty tag or digest and never orders them', () => {
    expect(c.normalize(' 1.107.0-slim ')).toBe('1.107.0-slim');
    expect(c.normalize('sha256:abc')).toBe('sha256:abc');
    expect(c.normalize('')).toBeNull();
    expect(c.compare('1.107.0', '1.107.0')).toBe(0);
    expect(() => c.compare('1.107.0', '1.108.0')).toThrow(/no order/);
  });
});
