import type { Ecosystem, Package, Skipped } from '../types.js';
export interface ParseResult { packages: Package[]; skipped: Skipped[] }
const PURL_TYPE: Record<Ecosystem, string> = { npm: 'npm', PyPI: 'pypi', Go: 'golang', 'crates.io': 'cargo', Packagist: 'composer', Maven: 'maven', RubyGems: 'gem', NuGet: 'nuget', 'GitHub Actions': 'github', software: 'generic', Docker: 'docker' };
export function purl(eco: Ecosystem, name: string, version?: string): string {
  const encoded = name.split('/').map((s) => encodeURIComponent(s)).join('/');
  return `pkg:${PURL_TYPE[eco]}/${encoded}${version ? '@' + version : ''}`;
}
export function pkg(eco: Ecosystem, name: string, version: string, lockfile: string, extra: Partial<Package> = {}): Package {
  return { ecosystem: eco, name, version, purl: purl(eco, name, version), lockfile, ...extra };
}

/** Parser errors never carry file content: only a position survives. */
export function parseErrorDetail(err: unknown): string {
  const e = err as { linePos?: { line: number; col: number }[] | { line: number; col: number }; message?: string; code?: string };
  const pos = Array.isArray(e?.linePos) ? e.linePos[0] : e?.linePos;
  if (pos && typeof pos.line === 'number') return `invalid syntax at line ${pos.line}, column ${pos.col}`;
  const m = /position (\d+)/.exec(e?.message ?? '');
  if (m) return `invalid JSON at position ${m[1]}`;
  if (e?.code) return `read error ${e.code}`;
  return 'invalid syntax';
}
