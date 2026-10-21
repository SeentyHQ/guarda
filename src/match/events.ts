import type { OsvEvent } from '../types.js';
import type { Comparator } from './comparators.js';

/** OSV semantics: walk events in order; introduced inclusive ("0" = start), fixed exclusive, last_affected inclusive. */
export function versionInEvents(version: string, events: OsvEvent[], cmp: Comparator): { hit: boolean; clause: string } {
  const v = cmp.normalize(version);
  if (v === null) {
    // A version we cannot compare (git, tarball, alias) still hits an open "every version" span.
    const everyVersion = events.length === 1 && events[0]!.introduced === '0';
    return everyVersion ? { hit: true, clause: '>= 0' } : { hit: false, clause: '' };
  }
  let open: string | null = null;
  for (const e of events) {
    if (e.introduced !== undefined) {
      open = e.introduced;
    } else if (e.fixed !== undefined && open !== null) {
      if (inSpan(v, open, e.fixed, false, cmp)) return { hit: true, clause: `>= ${open}, < ${e.fixed}` };
      open = null;
    } else if (e.last_affected !== undefined && open !== null) {
      if (inSpan(v, open, e.last_affected, true, cmp)) return { hit: true, clause: `>= ${open}, <= ${e.last_affected}` };
      open = null;
    }
  }
  if (open !== null && (open === '0' || cmp.compare(v, open) >= 0)) return { hit: true, clause: `>= ${open}` };
  return { hit: false, clause: '' };
}

function inSpan(v: string, from: string, to: string, inclusive: boolean, cmp: Comparator): boolean {
  const lower = from === '0' || cmp.compare(v, from) >= 0;
  const upper = inclusive ? cmp.compare(v, to) <= 0 : cmp.compare(v, to) < 0;
  return lower && upper;
}
