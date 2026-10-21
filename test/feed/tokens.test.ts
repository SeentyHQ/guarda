import { describe, expect, it } from 'vitest';
import { tokensToAffected } from '../../src/feed/tokens.js';

describe('tokensToAffected', () => {
  it('splits exact versions and simple ranges for npm', () => {
    expect(tokensToAffected('npm', '5.7.2, 5.7.3, <2.1.3, >=1.0.0 <1.0.5, ^3.1.0')).toEqual({
      versions: ['5.7.2', '5.7.3'],
      ranges: [
        { type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.1.3' }] },
        { type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.0.5' }] },
        { type: 'SEMVER', events: [{ introduced: '3.1.0' }, { fixed: '4.0.0' }] },
      ],
    });
  });
  it('turns <= into last_affected and || into separate spans', () => {
    expect(tokensToAffected('npm', '>=1.0.0 <=1.0.5 || 2.0.0').ranges).toEqual([{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { last_affected: '1.0.5' }] }]);
    expect(tokensToAffected('npm', '>=1.0.0 <=1.0.5 || 2.0.0').versions).toEqual(['2.0.0']);
  });
  it('refuses tokens it cannot express losslessly', () => {
    expect(() => tokensToAffected('npm', '>1.2.3')).toThrow(/">1.2.3"/);
    expect(() => tokensToAffected('npm', 'banana')).toThrow(/"banana"/);
    expect(() => tokensToAffected('PyPI', '~=1.4')).toThrow(/"~=1.4"/);
  });
  it('accepts PEP 440 exact versions and GitHub Actions shas', () => {
    expect(tokensToAffected('PyPI', '1.0.post1, 2.0rc1').versions).toEqual(['1.0.post1', '2.0rc1']);
    expect(tokensToAffected('GitHub Actions', 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef').versions).toEqual(['deadbeefdeadbeefdeadbeefdeadbeefdeadbeef']);
    expect(() => tokensToAffected('GitHub Actions', 'v4')).toThrow(/"v4"/);
  });
});

describe('ecosystems without a comparator (Maven, RubyGems, NuGet)', () => {
  it('accepts exact versions as versions[] (matched by string equality) and refuses ranges', () => {
    expect(tokensToAffected('Maven', '1.0, 2.3.1-SNAPSHOT')).toEqual({ versions: ['1.0', '2.3.1-SNAPSHOT'], ranges: [] });
    expect(tokensToAffected('RubyGems', 'v3.2.0')).toEqual({ versions: ['3.2.0'], ranges: [] });
    expect(() => tokensToAffected('NuGet', '>=1.0 <2.0')).toThrow(/no comparator for NuGet/);
    expect(() => tokensToAffected('Maven', '^1.0')).toThrow(/no comparator for Maven/);
  });
});

describe('software tokens', () => {
  it('accepts exact versions and semver-style ranges', () => {
    expect(tokensToAffected('software', '<8.2.34, 8.3.0')).toEqual({ versions: ['8.3.0'], ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '8.2.34' }] }] });
    expect(tokensToAffected('software', '<22.04, 2019')).toEqual({ versions: ['2019'], ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '22.4.0' }] }] });
  });
  it('rejects words that are not versions', () => {
    expect(() => tokensToAffected('software', 'latest')).toThrow();
  });
});

describe('Docker tokens', () => {
  it('accepts tags and digests as exact versions and rejects ranges', () => {
    expect(tokensToAffected('Docker', '1.107.0, 1.107.0-slim, sha256:0123abcd')).toEqual({ versions: ['1.107.0', '1.107.0-slim', 'sha256:0123abcd'], ranges: [] });
    expect(() => tokensToAffected('Docker', '<1.108')).toThrow(/tags/);
  });
});
