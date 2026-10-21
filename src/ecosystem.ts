import type { Ecosystem } from './types.js';

const ALIASES: Record<string, Ecosystem> = {
  npm: 'npm', pypi: 'PyPI', pip: 'PyPI', go: 'Go', golang: 'Go', cargo: 'crates.io', 'crates.io': 'crates.io', crates: 'crates.io',
  composer: 'Packagist', packagist: 'Packagist', maven: 'Maven', rubygems: 'RubyGems', gem: 'RubyGems',
  nuget: 'NuGet', 'github actions': 'GitHub Actions', 'github-actions': 'GitHub Actions', actions: 'GitHub Actions',
  software: 'software', runtime: 'software', product: 'software', os: 'software',
  docker: 'Docker', oci: 'Docker', container: 'Docker', 'docker hub': 'Docker', image: 'Docker',
};

/** An image reference without tag or digest, as Docker resolves it: `php` → `library/php`, `docker.io/x/y` → `x/y`, other registries kept. */
export function normalizeImageName(name: string): string {
  let n = name.trim().toLowerCase().replace(/^docker\.io\//, '').replace(/^index\.docker\.io\//, '');
  const registry = /^[a-z0-9.-]+\.[a-z]{2,}(:\d+)?\//.test(n) || n.startsWith('localhost/');
  if (!registry && !n.includes('/')) n = `library/${n}`;
  return n;
}

export function canonicalEcosystem(input: string): Ecosystem | null {
  return ALIASES[input.trim().toLowerCase()] ?? null;
}

export function normalizeName(eco: Ecosystem, name: string): string {
  switch (eco) {
    case 'npm': case 'Packagist': case 'RubyGems': case 'NuGet': case 'GitHub Actions': case 'software': return name.trim().toLowerCase();
    case 'Docker': return normalizeImageName(name);
    case 'PyPI': return name.trim().toLowerCase().replace(/[-_.]+/g, '-');
    case 'crates.io': return name.trim().toLowerCase().replace(/_/g, '-');
    default: return name.trim();
  }
}
