import { describe, expect, it } from 'vitest';
import { resolveSettings } from '../src/config.js';

describe('project config is untrusted', () => {
  it('ignores feedUrl, strict and maxFeedAgeDays from the scanned repository and keeps failOn and only', () => {
    const notices: string[] = [];
    const s = resolveSettings({}, {}, { feedUrl: 'http://evil.example', strict: false, maxFeedAgeDays: 999, failOn: 'high', only: ['secrets'] }, null, (m) => notices.push(m));
    expect(s.feedUrl).toBe('https://feed.seenty.com/guarda/v1');
    expect(s.maxFeedAgeDays).toBe(7);
    expect(s.failOn).toBe('high'); expect(s.only).toEqual(['secrets']);
    expect(notices.join(' ')).toMatch(/feedUrl/);
  });
  it('rejects a non-numeric max feed age and separates DO_NOT_TRACK from CI', () => {
    expect(() => resolveSettings({ 'max-feed-age': 'abc' }, {}, null, null)).toThrow(/max-feed-age/);
    expect(resolveSettings({}, { CI: 'true' }, null, null)).toMatchObject({ noTips: true, doNotTrack: false });
    expect(resolveSettings({}, { DO_NOT_TRACK: '1' }, null, null)).toMatchObject({ noTips: true, doNotTrack: true });
  });
});

describe('project ignore list', () => {
  it('accepts ignore globs from the repository and normalises them', () => {
    const s = resolveSettings({}, {}, { ignore: ['src/secrets/rules.ts', 'test/**', 'docs/*.md'] }, null);
    expect(s.ignore).toEqual(['src/secrets/rules.ts', 'test/**', 'docs/*.md']);
    expect(() => resolveSettings({}, {}, { ignore: 'nope' as unknown as string[] }, null)).toThrow(/ignore/);
  });
});
