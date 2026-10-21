import { canonicalEcosystem, normalizeName } from '../ecosystem.js';
import type { ActionRef, Feed, Match } from '../types.js';
import { severityOf } from './packages.js';

export function matchActions(actions: ActionRef[], feed: Feed): Match[] {
  const matches: Match[] = [];
  for (const { source, advisory } of feed.advisories) {
    if (advisory.withdrawn) continue;
    for (const affected of advisory.affected) {
      if (canonicalEcosystem(affected.package.ecosystem) !== 'GitHub Actions') continue;
      const repo = normalizeName('GitHub Actions', affected.package.name);
      const shas = new Set((affected.versions ?? []).map((s) => s.toLowerCase()));
      const exposed = new Set((advisory.database_specific?.seenty?.exposed_refs ?? []).map((r) => r.toLowerCase()));
      const w = advisory.database_specific?.seenty?.window;
      for (const action of actions) {
        if (normalizeName('GitHub Actions', action.repo) !== repo) continue;
        const ref = action.ref.toLowerCase();
        if (action.refKind === 'sha' && shas.has(ref)) {
          matches.push({ advisory, source, severity: severityOf(advisory, source), clause: `sha ${action.ref}`, target: { kind: 'action', action, exposure: 'malicious-sha' } });
        } else if (exposed.has(ref)) {
          const when = w?.from && w?.to ? ` between ${w.from} and ${w.to}` : '';
          matches.push({ advisory, source, severity: severityOf(advisory, source), clause: `ref ${action.ref} exposed${when}`, target: { kind: 'action', action, exposure: 'exposed-ref' } });
        } else {
          matches.push({ advisory, source, severity: 'info', clause: `ref ${action.ref} not listed`, target: { kind: 'action', action, exposure: 'repo-listed' } });
        }
      }
    }
  }
  return matches;
}
