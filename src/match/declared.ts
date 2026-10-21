import semver from 'semver';
import type { DeclaredDep, Feed, Match, Severity, Skipped } from '../types.js';
import { normalizeName } from '../ecosystem.js';
import { indexFeed, severityOf } from './packages.js';

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const below = (s: Severity): Severity => ORDER[Math.min(ORDER.indexOf(s) + 1, ORDER.length - 1)]!;
const OPTS = { includePrerelease: true } as const;

/** The semver range an OSV event span covers, e.g. ">=1.3.0 <1.3.2". */
function spanRange(events: { introduced?: string; fixed?: string; last_affected?: string }[]): string[] {
  const spans: string[] = []; let intro: string | null = null;
  for (const e of events) {
    if (e.introduced !== undefined) { if (intro !== null) spans.push(intro === '0' ? '>=0.0.0-0' : `>=${intro}`); intro = e.introduced; }
    if (e.fixed !== undefined && intro !== null) { spans.push(`${intro === '0' ? '>=0.0.0-0' : '>=' + intro} <${e.fixed}`); intro = null; }
    if (e.last_affected !== undefined && intro !== null) { spans.push(`${intro === '0' ? '>=0.0.0-0' : '>=' + intro} <=${e.last_affected}`); intro = null; }
  }
  if (intro !== null) spans.push(intro === '0' ? '>=0.0.0-0' : `>=${intro}`);
  return spans;
}
const pretty = (span: string) => span.replace('>=0.0.0-0', '>=0');

/**
 * Ranges from a manifest: a range that admits a poisoned version is a "range exposure". It is what a
 * fresh install may pull, not what is installed, so the severity sits one step below the advisory;
 * with a committed lockfile the install is pinned and the exposure is informational only.
 */
export function matchDeclared(declared: DeclaredDep[], feed: Feed): { matches: Match[]; skipped: Skipped[] } {
  const idx = indexFeed(feed); const matches: Match[] = []; const skipped: Skipped[] = [];
  for (const dep of declared) {
    if (dep.ecosystem !== 'npm' || semver.validRange(dep.range, OPTS) === null) { skipped.push({ path: dep.manifest, reason: 'unsupported-entry', detail: `${dep.name}: range ${dep.range.slice(0, 40)}` }); continue; }
    const candidates = idx.get(`${dep.ecosystem}\0${normalizeName(dep.ecosystem, dep.name)}`);
    if (!candidates) continue;
    for (const c of candidates) {
      let clause: string | null = null;
      try {
        for (const v of c.affected.versions ?? []) { const clean = semver.valid(v.replace(/^[=v]/, '')); if (clean && semver.satisfies(clean, dep.range, OPTS)) { clause = `range ${dep.range} admits poisoned ${clean}`; break; } }
        if (clause === null) for (const r of c.affected.ranges ?? []) for (const span of spanRange(r.events)) if (semver.intersects(dep.range, span, OPTS)) { clause = `range ${dep.range} overlaps ${pretty(span)}`; break; }
      } catch { skipped.push({ path: dep.manifest, reason: 'unsupported-entry', detail: `${c.advisory.id}: invalid range for ${dep.name}` }); continue; }
      if (clause === null) continue;
      const base = severityOf(c.advisory, c.source);
      matches.push({ advisory: c.advisory, source: c.source, severity: dep.lockfile === 'committed' ? 'info' : below(base), clause, target: { kind: 'declared', declared: dep, exposure: 'range' } });
    }
  }
  return { matches, skipped };
}
