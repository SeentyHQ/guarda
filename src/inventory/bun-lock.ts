import { parse, type ParseError } from 'jsonc-parser';
import type { Package, Skipped } from '../types.js';
import { pkg, type ParseResult } from './types.js';

interface Lock { packages?: Record<string, unknown[]>; workspaces?: Record<string, { dependencies?: Record<string, string>; devDependencies?: Record<string, string> }> }

export function parseBunLock(content: string, lockfilePath: string): ParseResult {
  const errors: ParseError[] = [];
  const lock = parse(content, errors, { allowTrailingComma: true }) as Lock | undefined;
  if (errors.length > 0 || !lock || typeof lock !== 'object') return { packages: [], skipped: [{ path: lockfilePath, reason: 'parse-error', detail: `jsonc error at offset ${errors[0]?.offset ?? 0}` }] };
  if (!lock.packages) return { packages: [], skipped: [{ path: lockfilePath, reason: 'parse-error', detail: 'no "packages" field' }] };
  const direct = new Set<string>();
  for (const ws of Object.values(lock.workspaces ?? {})) for (const n of Object.keys({ ...ws.dependencies, ...ws.devDependencies })) direct.add(n);
  const packages: Package[] = []; const skipped: Skipped[] = []; const seen = new Set<string>();
  for (const [key, arr] of Object.entries(lock.packages)) {
    const spec = typeof arr?.[0] === 'string' ? arr[0] : '';
    const at = spec.indexOf('@', 1);
    if (at === -1) { skipped.push({ path: lockfilePath, reason: 'unsupported-entry', detail: `${key}: no version` }); continue; }
    const name = spec.slice(0, at); let version = spec.slice(at + 1);
    if (version.startsWith('npm:')) version = version.slice(4);
    if (/^(workspace|link|file|git|github):/.test(version)) { skipped.push({ path: lockfilePath, reason: 'unsupported-entry', detail: `${key}: ${version.split(':')[0]}` }); continue; }
    const id = `${name}@${version}`; if (seen.has(id)) continue; seen.add(id);
    const topLevel = key === name;
    packages.push(pkg('npm', name, version, lockfilePath, topLevel && direct.has(name) ? { direct: true } : {}));
  }
  return { packages, skipped };
}
