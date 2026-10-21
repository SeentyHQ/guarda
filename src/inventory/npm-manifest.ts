import semver from 'semver';
import type { DeclaredDep, Package, Skipped } from '../types.js';
import { parseErrorDetail } from './types.js';
import { purl } from './types.js';

const SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies'] as const; // peerDependencies are not installed by the manifest itself

/**
 * package.json: exact pins become packages (only used when no lockfile sits next to it), semver
 * ranges become declared dependencies (what a fresh install may resolve). Anything else (git, file,
 * npm: aliases, tags) is reported, never guessed. Line numbers come from the raw text.
 */
export function parseNpmManifest(content: string, path: string, lockfile: DeclaredDep['lockfile'] = 'none'): { packages: Package[]; declared: DeclaredDep[]; skipped: Skipped[] } {
  const packages: Package[] = []; const declared: DeclaredDep[] = []; const skipped: Skipped[] = [];
  let doc: unknown;
  try { doc = JSON.parse(content); } catch (err) { return { packages, declared, skipped: [{ path, reason: 'parse-error', detail: parseErrorDetail(err) }] }; }
  if (!doc || typeof doc !== 'object') return { packages, declared, skipped: [{ path, reason: 'parse-error', detail: 'not an object' }] };
  const lines = content.split('\n');
  const lineOf = (name: string): number | undefined => { const i = lines.findIndex((l) => l.includes(`"${name}"`)); return i === -1 ? undefined : i + 1; };
  for (const section of SECTIONS) {
    const deps = (doc as Record<string, unknown>)[section];
    if (!deps || typeof deps !== 'object') continue;
    for (const [name, spec] of Object.entries(deps as Record<string, unknown>)) {
      if (typeof spec !== 'string') { skipped.push({ path, reason: 'unsupported-entry', detail: `${name}: non-string spec` }); continue; }
      const line = lineOf(name);
      const exact = semver.valid(spec.replace(/^[=v]/, ''));
      if (exact !== null && !/[<>^~*x|\s]/.test(spec)) { packages.push({ ecosystem: 'npm', name, version: exact, purl: purl('npm', name, exact), lockfile: path, direct: true, ...(line ? { line } : {}) }); continue; }
      if (semver.validRange(spec, { includePrerelease: true }) !== null) { declared.push({ ecosystem: 'npm', name, range: spec, manifest: path, lockfile, ...(line ? { line } : {}) }); continue; }
      skipped.push({ path, reason: 'unsupported-entry', detail: `${name}: spec is not a version or a semver range (${spec.slice(0, 40)})` });
    }
  }
  return { packages, declared, skipped };
}
