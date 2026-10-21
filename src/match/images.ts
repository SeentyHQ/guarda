import type { Feed, ImageRef, Match, Package, Skipped } from '../types.js';
import { matchPackages } from './packages.js';

/** Images against Docker advisories: the tag, or the digest when pinned by digest, must be listed exactly. */
export function matchImages(images: readonly ImageRef[], feed: Feed): { matches: Match[]; skipped: Skipped[] } {
  const packages: Package[] = []; const skipped: Skipped[] = [];
  for (const i of images) {
    const version = i.tag ?? i.digest;
    if (!version) { skipped.push({ path: i.file, reason: 'unsupported-entry', detail: `line ${i.line}: ${i.name} has no tag or digest to check; pin it` }); continue; }
    packages.push({ ecosystem: 'Docker', name: i.name, version, purl: `pkg:docker/${i.name}@${version}`, lockfile: i.file, line: i.line });
  }
  const r = matchPackages(packages, feed);
  return { matches: r.matches, skipped: [...skipped, ...r.skipped] };
}
