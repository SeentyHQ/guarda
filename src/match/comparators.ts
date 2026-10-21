import semver from 'semver';
import * as pep440 from '@renovatebot/pep440';
import type { Ecosystem } from '../types.js';

export interface Comparator { normalize(v: string): string | null; compare(a: string, b: string): number }

const SEMVER: Comparator = {
  normalize(v) {
    const s = semver.parse(v.trim().replace(/^[v=]/, ''), { loose: true });
    if (!s) return null;
    return s.prerelease.length ? `${s.major}.${s.minor}.${s.patch}-${s.prerelease.join('.')}` : `${s.major}.${s.minor}.${s.patch}`;
  },
  compare(a, b) {
    const x = SEMVER.normalize(a); const y = SEMVER.normalize(b);
    if (x === null || y === null) throw new Error(`not semver: ${x === null ? a : b}`);
    return semver.compare(x, y);
  },
};

const PEP440: Comparator = {
  normalize(v) { const t = v.trim(); return pep440.valid(t) ? t : null; },
  compare(a, b) {
    if (!pep440.valid(a) || !pep440.valid(b)) throw new Error(`not pep440: ${!pep440.valid(a) ? a : b}`);
    return pep440.compare(a, b);
  },
};

/**
 * Software releases are dotted numbers of any width ("8.2.33", "22.04", "2019", "1.107.0"): the leading numeric parts
 * are read, leading zeros dropped and the result padded to three. Pre-release tags and a fourth part are dropped on purpose.
 */
const SOFTWARE: Comparator = {
  normalize(v) {
    const m = /^[v=]?(\d+(?:\.\d+)*)/.exec(v.trim()); if (!m) return null;
    const parts = m[1]!.split('.').slice(0, 3).map((p) => String(Number(p)));
    while (parts.length < 3) parts.push('0');
    return parts.join('.');
  },
  compare(a, b) {
    const x = SOFTWARE.normalize(a); const y = SOFTWARE.normalize(b);
    if (x === null || y === null) throw new Error(`not a software version: ${x === null ? a : b}`);
    return semver.compare(x, y);
  },
};

/** Image tags are opaque: equal or not. Ranges are refused at the feed, so compare only ever sees equal tags. */
const DOCKER: Comparator = {
  normalize(v) { const t = v.trim(); return t ? t : null; },
  compare(a, b) { if (a.trim() === b.trim()) return 0; throw new Error(`image tags have no order: ${a} vs ${b}`); },
};

export function comparatorFor(eco: Ecosystem): Comparator | null {
  switch (eco) {
    case 'npm': case 'crates.io': case 'Go': case 'Packagist': return SEMVER;
    case 'PyPI': return PEP440;
    case 'software': return SOFTWARE;
    case 'Docker': return DOCKER;
    default: return null;
  }
}
