import { describe, expect, it } from 'vitest';
import { comparatorFor } from '../../src/match/comparators.js';
import { versionInEvents } from '../../src/match/events.js';

const npm = comparatorFor('npm')!;
describe('versionInEvents', () => {
  it('introduced 0 + fixed', () => {
    const ev = [{ introduced: '0' }, { fixed: '2.1.3' }];
    expect(versionInEvents('2.1.2', ev, npm)).toEqual({ hit: true, clause: '>= 0, < 2.1.3' });
    expect(versionInEvents('2.1.3', ev, npm).hit).toBe(false);
    expect(versionInEvents('0.0.1', ev, npm).hit).toBe(true);
  });
  it('introduced + last_affected is inclusive', () => {
    const ev = [{ introduced: '5.7.2' }, { last_affected: '5.7.3' }];
    expect(versionInEvents('5.7.3', ev, npm).hit).toBe(true);
    expect(versionInEvents('5.7.4', ev, npm).hit).toBe(false);
    expect(versionInEvents('5.7.1', ev, npm).hit).toBe(false);
  });
  it('disjoint spans in one events list', () => {
    const ev = [{ introduced: '1.0.0' }, { fixed: '1.0.5' }, { introduced: '2.0.0' }, { fixed: '2.0.2' }];
    expect(versionInEvents('1.0.4', ev, npm).hit).toBe(true);
    expect(versionInEvents('1.5.0', ev, npm).hit).toBe(false);
    expect(versionInEvents('2.0.1', ev, npm).hit).toBe(true);
  });
  it('pre-release inside a span is compared, not dropped', () => {
    expect(versionInEvents('2.0.0-rc.1', [{ introduced: '1.9.0' }, { fixed: '2.0.0' }], npm).hit).toBe(true);
  });
  it('unparseable installed version never hits a bounded span but does hit the open "every version" span', () => {
    expect(versionInEvents('garbage', [{ introduced: '0' }, { fixed: '2.0.0' }], npm).hit).toBe(false);
    expect(versionInEvents('git+https://x/y#abc', [{ introduced: '0' }], npm)).toEqual({ hit: true, clause: '>= 0' });
  });
});
