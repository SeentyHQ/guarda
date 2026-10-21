import semver from 'semver';
import { comparatorFor } from '../match/comparators.js';
import type { Ecosystem, OsvRange } from '../types.js';

export class TokenError extends Error { constructor(public token: string, reason: string) { super(`cannot publish token "${token}": ${reason}`); } }

const stripZero = (v: string) => (v.endsWith('-0') ? v.slice(0, -2) : v);

/** Comma-separated tokens (OR). Exact versions -> versions[]; semver ranges -> OSV events; anything lossy throws. */
export function tokensToAffected(eco: Ecosystem, affectedVersions: string): { versions: string[]; ranges: OsvRange[] } {
  const versions: string[] = []; const ranges: OsvRange[] = [];
  for (const raw of affectedVersions.split(',')) {
    const token = raw.trim(); if (!token) continue;
    if (eco === 'GitHub Actions') {
      if (/^[0-9a-f]{40}([0-9a-f]{24})?$/i.test(token)) { versions.push(token.toLowerCase()); continue; }
      throw new TokenError(token, 'GitHub Actions versions must be commit SHAs; put tags in exposed_refs');
    }
    const cmp = comparatorFor(eco);
    // Software ranges are written the way vendors write them ("<22.04"); semver needs the padded form.
    const spec = eco === 'software' ? token.replace(/\d+(?:\.\d+)*/g, (m) => cmp!.normalize(m) ?? m) : token;
    if (!cmp) {
      // No comparator (Maven, RubyGems, NuGet): exact versions travel as versions[] and match by string equality; ranges would be lossy.
      if (/[<>=^~*x|\s]/.test(token) || token.includes('..')) throw new TokenError(token, `no comparator for ${eco}`);
      versions.push(token.replace(/^[v=]/, '')); continue;
    }
    if (cmp.normalize(token) !== null && !/[<>=^~*x|\s]/.test(token)) { versions.push(token.replace(/^[v=]/, '')); continue; }
    if (eco === 'PyPI') throw new TokenError(token, 'PyPI ranges are not supported yet; list exact versions');
    if (eco === 'Docker') throw new TokenError(token, 'image tags have no order; list the exact tags or digests');
    if (!semver.validRange(spec, { includePrerelease: true })) throw new TokenError(token, 'not a version or a semver range');
    for (const set of new semver.Range(spec, { includePrerelease: true }).set) {
      let introduced = '0'; let upper: { fixed?: string; last_affected?: string } | null = null; let exact: string | null = null;
      for (const c of set) {
        if (c.value === '') continue;
        const v = c.semver.version;
        if (c.operator === '' || c.operator === '=') exact = v;
        else if (c.operator === '>=') introduced = v;
        else if (c.operator === '<') upper = { fixed: stripZero(v) };
        else if (c.operator === '<=') upper = { last_affected: v };
        else throw new TokenError(token, `operator ${c.operator} cannot be expressed as OSV events`);
      }
      if (exact !== null) { versions.push(exact); continue; }
      if (upper === null) ranges.push({ type: 'SEMVER', events: [{ introduced }] });
      else ranges.push({ type: 'SEMVER', events: [{ introduced }, upper] });
    }
  }
  return { versions, ranges };
}
