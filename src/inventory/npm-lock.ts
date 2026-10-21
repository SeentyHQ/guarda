import type { Package, Skipped } from '../types.js';
import { parseErrorDetail, pkg, type ParseResult } from './types.js';

interface LockEntry { version?: string; name?: string; link?: boolean; dependencies?: Record<string, LockEntry>; devDependencies?: Record<string, unknown> }
interface Lock { lockfileVersion?: number; packages?: Record<string, LockEntry>; dependencies?: Record<string, LockEntry> }

export function parseNpmLock(content: string, lockfilePath: string): ParseResult {
  let lock: Lock;
  try { lock = JSON.parse(content) as Lock; } catch (err) { return { packages: [], skipped: [{ path: lockfilePath, reason: 'parse-error', detail: parseErrorDetail(err) }] }; }
  if (typeof lock !== 'object' || lock === null || (!lock.packages && !lock.dependencies)) {
    return { packages: [], skipped: [{ path: lockfilePath, reason: 'parse-error', detail: 'no "packages" or "dependencies" field' }] };
  }
  const packages: Package[] = []; const skipped: Skipped[] = []; const seen = new Set<string>();
  const add = (name: string, version: string, direct: boolean) => {
    const k = `${name}@${version}`; if (seen.has(k)) return; seen.add(k);
    packages.push(pkg('npm', name, version, lockfilePath, direct ? { direct: true } : {}));
  };
  if (lock.packages) {
    const root = lock.packages[''];
    const directNames = new Set(Object.keys({ ...(root?.dependencies ?? {}), ...(root?.devDependencies ?? {}) }));
    for (const [path, entry] of Object.entries(lock.packages)) {
      if (path === '') continue;
      if (!entry || typeof entry !== 'object') { skipped.push({ path: lockfilePath, reason: 'unsupported-entry', detail: `${path}: malformed entry` }); continue; }
      if (entry.link) { skipped.push({ path: lockfilePath, reason: 'unsupported-entry', detail: `${path}: link` }); continue; }
      const idx = path.lastIndexOf('node_modules/');
      if (idx === -1) { skipped.push({ path: lockfilePath, reason: 'unsupported-entry', detail: `${path}: workspace` }); continue; }
      const keyName = path.slice(idx + 'node_modules/'.length);
      const name = entry.name ?? keyName;
      if (!entry.version) { skipped.push({ path: lockfilePath, reason: 'unsupported-entry', detail: `${path}: no version` }); continue; }
      add(name, entry.version, path === `node_modules/${keyName}` && directNames.has(keyName));
    }
  } else if (lock.dependencies) {
    const walk = (deps: Record<string, LockEntry>, direct: boolean) => {
      for (const [name, entry] of Object.entries(deps)) {
        if (!entry || typeof entry !== 'object') { skipped.push({ path: lockfilePath, reason: 'unsupported-entry', detail: `${name}: malformed entry` }); continue; }
        if (entry.version) {
          // v1 aliases: "safe": { "version": "npm:evil-pkg@1.0.0" } installs evil-pkg.
          const alias = /^npm:(.+)@([^@]+)$/.exec(entry.version);
          if (alias) add(alias[1]!, alias[2]!, direct); else add(name, entry.version, direct);
        }
        if (entry.dependencies) walk(entry.dependencies, false);
      }
    };
    walk(lock.dependencies, true);
  }
  return { packages, skipped };
}
