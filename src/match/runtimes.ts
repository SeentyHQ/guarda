import type { Feed, Match, Package, RuntimeRef, Skipped } from '../types.js';
import { matchPackages } from './packages.js';

/** The last version a major-only declaration can stand for: "8.2" → "8.2.999999", "22" → "22.999999.999999". */
export const cycleEnd = (version: string): string => { const p = version.split('.').slice(0, 2); while (p.length < 3) p.push('999999'); return p.join('.'); };

/**
 * Runtimes against `software` advisories. An exact version is matched as any package. A major-only one ("8.2") is
 * probed at both ends of its line and reported as a possible hit, since the exact patch decides. Ranges and
 * versionless tags cannot be checked and are reported so the user pins them.
 */
export function matchRuntimes(runtimes: readonly RuntimeRef[], feed: Feed): { matches: Match[]; skipped: Skipped[] } {
  const matches: Match[] = []; const skipped: Skipped[] = [];
  const asPackage = (r: RuntimeRef, version: string, lockfile: string): Package => ({ ecosystem: 'software', name: r.slug, version, purl: `pkg:generic/${r.slug}@${version}`, lockfile, ...(r.line ? { line: r.line } : {}) });
  const shown = (r: RuntimeRef) => (r.raw.includes(':') ? r.raw.slice(r.raw.indexOf(':') + 1) : r.raw);
  for (const r of runtimes) {
    if (r.precision === 'exact' && r.version) { matches.push(...matchPackages([asPackage(r, r.version, r.file)], feed).matches); continue; }
    if (r.precision === 'major' && r.version) {
      const probes = [asPackage(r, r.version, 'low'), asPackage(r, cycleEnd(r.version), 'high')];
      const seen = new Set<string>();
      for (const m of matchPackages(probes, feed).matches) {
        if (m.target.kind !== 'package' || seen.has(m.advisory.id)) continue; seen.add(m.advisory.id);
        matches.push({ ...m, clause: `possibly affected: the ${r.version} line is in ${m.clause}; set the exact version`, target: { kind: 'package', package: asPackage(r, r.version, r.file) } });
      }
      continue;
    }
    const why = r.precision === 'range' ? `${r.slug} is a range (${r.raw}), not a version; pin it to check` : `${r.slug} has no version to check (${shown(r)}); pin the tag`;
    skipped.push({ path: r.file, reason: 'unsupported-entry', detail: `${r.line ? `line ${r.line}: ` : ''}${why}` });
  }
  return { matches, skipped };
}
