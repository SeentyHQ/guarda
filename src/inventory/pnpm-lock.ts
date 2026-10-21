import { parse } from 'yaml';
import type { Package, Skipped } from '../types.js';
import { parseErrorDetail, pkg, type ParseResult } from './types.js';

interface Lock { lockfileVersion?: string | number; packages?: Record<string, unknown>; dependencies?: Record<string, unknown>; importers?: Record<string, { dependencies?: Record<string, unknown>; devDependencies?: Record<string, unknown> }> }

/** "/name/1.2.3_peer" (v5), "/name@1.2.3(peer)" (v6), "name@1.2.3(peer)" (v9) -> { name, version } or null for link/file entries. */
export function splitPnpmKey(key: string, major: number): { name: string; version: string } | null {
  let k = key.startsWith('/') ? key.slice(1) : key;
  const paren = k.indexOf('('); if (paren !== -1) k = k.slice(0, paren);
  if (/(^|@)(link|file|git\+?[a-z]*|workspace):/.test(k)) return null;
  if (major < 6) {
    // v5: "name/1.2.3[_peer...]" or "@scope/name/1.2.3[_peer...]"
    const slash = k.lastIndexOf('/');
    if (slash <= 0) return null;
    return { name: k.slice(0, slash), version: k.slice(slash + 1).split('_')[0]! };
  }
  const at = k.lastIndexOf('@');
  if (at <= 0) return null;
  return { name: k.slice(0, at), version: k.slice(at + 1) };
}

export function parsePnpmLock(content: string, lockfilePath: string): ParseResult {
  let lock: Lock;
  try { lock = parse(content) as Lock; } catch (err) { return { packages: [], skipped: [{ path: lockfilePath, reason: 'parse-error', detail: parseErrorDetail(err) }] }; }
  if (!lock || typeof lock !== 'object') return { packages: [], skipped: [{ path: lockfilePath, reason: 'parse-error', detail: 'no "packages" field' }] };
  if (!lock.packages) return lock.lockfileVersion !== undefined ? { packages: [], skipped: [] } : { packages: [], skipped: [{ path: lockfilePath, reason: 'parse-error', detail: 'no "packages" field' }] };
  const major = Math.floor(Number(lock.lockfileVersion ?? 9)) || 9;
  const direct = new Set<string>();
  const collect = (deps?: Record<string, unknown>) => {
    for (const [name, v] of Object.entries(deps ?? {})) {
      const version = typeof v === 'string' ? v : (v as { version?: string })?.version ?? '';
      direct.add(`${name}@${version.split('(')[0]!.split('_')[0]!}`);
    }
  };
  collect(lock.dependencies);
  for (const imp of Object.values(lock.importers ?? {})) { collect(imp.dependencies); collect(imp.devDependencies); }
  const packages: Package[] = []; const skipped: Skipped[] = []; const seen = new Set<string>();
  for (const key of Object.keys(lock.packages)) {
    const split = splitPnpmKey(key, major);
    if (!split) { skipped.push({ path: lockfilePath, reason: 'unsupported-entry', detail: `${key}: link` }); continue; }
    const id = `${split.name}@${split.version}`; if (seen.has(id)) continue; seen.add(id);
    packages.push(pkg('npm', split.name, split.version, lockfilePath, direct.has(id) ? { direct: true } : {}));
  }
  return { packages, skipped };
}
