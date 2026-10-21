import { canonicalEcosystem, normalizeName } from '../ecosystem.js';
import type { Advisory, Feed, Match, Package, Severity, Skipped, SourceId } from '../types.js';
import { comparatorFor } from './comparators.js';
import { versionInEvents } from './events.js';

export function severityOf(advisory: Advisory, source: SourceId): Severity {
  return advisory.database_specific?.seenty?.severity ?? (source === 'openssf-mal' ? 'high' : 'medium');
}

interface Indexed { source: SourceId; advisory: Advisory; affected: Advisory['affected'][number] }

export function indexFeed(feed: Feed): Map<string, Indexed[]> {
  const idx = new Map<string, Indexed[]>();
  for (const { source, advisory } of feed.advisories) {
    if (advisory.withdrawn) continue;
    for (const affected of advisory.affected) {
      const eco = canonicalEcosystem(affected.package.ecosystem); if (!eco) continue;
      const key = `${eco}\0${normalizeName(eco, affected.package.name)}`;
      const list = idx.get(key) ?? []; list.push({ source, advisory, affected }); idx.set(key, list);
    }
  }
  return idx;
}

export function matchPackages(packages: Package[], feed: Feed): { matches: Match[]; skipped: Skipped[] } {
  const idx = indexFeed(feed); const matches: Match[] = []; const skipped: Skipped[] = [];
  for (const pkg of packages) {
    const cmp = comparatorFor(pkg.ecosystem);
    if (!cmp) { skipped.push({ path: pkg.lockfile, reason: 'unsupported-ecosystem', detail: `${pkg.ecosystem}: ${pkg.name}@${pkg.version}` }); continue; }
    const candidates = idx.get(`${pkg.ecosystem}\0${normalizeName(pkg.ecosystem, pkg.name)}`);
    if (!candidates) continue;
    const installed = cmp.normalize(pkg.version);
    let hit = false;
    for (const c of candidates) {
      let clause: string | null = null;
      try {
        for (const v of c.affected.versions ?? []) {
          const n = cmp.normalize(v);
          if ((n !== null && installed !== null && n === installed) || v === pkg.version) { clause = `= ${n ?? v}`; break; }
        }
        if (clause === null) for (const range of c.affected.ranges ?? []) {
          const r = versionInEvents(pkg.version, range.events, cmp);
          if (r.hit) { clause = r.clause; break; }
        }
      } catch {
        skipped.push({ path: pkg.lockfile, reason: 'unsupported-entry', detail: `${c.advisory.id}: invalid range for ${pkg.name}` });
        continue;
      }
      if (clause !== null) { hit = true; matches.push({ advisory: c.advisory, source: c.source, severity: severityOf(c.advisory, c.source), clause, target: { kind: 'package', package: pkg } }); }
    }
    if (installed === null && !hit) skipped.push({ path: pkg.lockfile, reason: 'unsupported-entry', detail: `${pkg.name}: unparsable version ${pkg.version.slice(0, 80)}` });
  }
  return { matches, skipped };
}
