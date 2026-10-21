import { describe, expect, it } from 'vitest';
import { resolveSettings } from '../src/config.js';

describe('resolveSettings precedence', () => {
  it('flag > env > project > user > default', () => {
    const base = { feedUrl: 'u', failOn: 'high' as const, only: null, strict: false, maxFeedAgeDays: 7, offline: false, cacheDir: 'c', noTips: false };
    expect(resolveSettings({}, {}, null, null).feedUrl).toBe('https://feed.seenty.com/guarda/v1');
    expect(resolveSettings({}, {}, null, { ...base, feedUrl: 'user' }).feedUrl).toBe('user');
    expect(resolveSettings({}, {}, { feedUrl: 'proj' }, { ...base, feedUrl: 'user' }).feedUrl).toBe('user');
    expect(resolveSettings({}, {}, { failOn: 'critical' }, { ...base, failOn: 'high' }).failOn).toBe('critical');
    expect(resolveSettings({}, { GUARDA_FEED_URL: 'env' }, null, { ...base, feedUrl: 'user' }).feedUrl).toBe('env');
    expect(resolveSettings({ feed: 'flag' }, { GUARDA_FEED_URL: 'env' }, null, null).feedUrl).toBe('flag');
    expect(resolveSettings({ 'fail-on': 'none' }, {}, null, null).failOn).toBe('none');
    expect(resolveSettings({ only: 'packages,secrets' }, {}, null, null).only).toEqual(['packages', 'secrets']);
    expect(resolveSettings({}, { DO_NOT_TRACK: '1' }, null, null).noTips).toBe(true);
    expect(resolveSettings({}, { XDG_CACHE_HOME: '/x' }, null, null).cacheDir).toBe('/x/guarda');
  });
  it('rejects bad values', () => {
    expect(() => resolveSettings({ 'fail-on': 'huge' }, {}, null, null)).toThrow(/fail-on/);
    expect(() => resolveSettings({ only: 'cats' }, {}, null, null)).toThrow(/only/);
  });
});
