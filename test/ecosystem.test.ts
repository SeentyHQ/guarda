import { describe, expect, it } from 'vitest';
import { canonicalEcosystem, normalizeName } from '../src/ecosystem.js';

describe('canonicalEcosystem', () => {
  it('maps every spelling seen in the Seenty repo to the OSV name', () => {
    expect(canonicalEcosystem('npm')).toBe('npm');
    expect(canonicalEcosystem('pypi')).toBe('PyPI');
    expect(canonicalEcosystem('pip')).toBe('PyPI'); // GitHub Advisory Database spelling
    expect(canonicalEcosystem('PyPI')).toBe('PyPI');
    expect(canonicalEcosystem('go')).toBe('Go');
    expect(canonicalEcosystem('cargo')).toBe('crates.io');
    expect(canonicalEcosystem('crates.io')).toBe('crates.io');
    expect(canonicalEcosystem('composer')).toBe('Packagist');
    expect(canonicalEcosystem('packagist')).toBe('Packagist');
    expect(canonicalEcosystem('maven')).toBe('Maven');
    expect(canonicalEcosystem('rubygems')).toBe('RubyGems');
    expect(canonicalEcosystem('nuget')).toBe('NuGet');
    expect(canonicalEcosystem('github actions')).toBe('GitHub Actions');
    expect(canonicalEcosystem('GitHub Actions')).toBe('GitHub Actions');
  });
  it('returns null for unknown spellings', () => {
    expect(canonicalEcosystem('hex')).toBeNull();
    expect(canonicalEcosystem('')).toBeNull();
  });
});

describe('normalizeName', () => {
  it('lowercases npm names and keeps the scope', () => {
    expect(normalizeName('npm', '@Scope/Name')).toBe('@scope/name');
  });
  it('applies PEP 503 to PyPI names', () => {
    expect(normalizeName('PyPI', 'Django_Rest.Framework')).toBe('django-rest-framework');
  });
  it('lowercases GitHub Actions repos', () => {
    expect(normalizeName('GitHub Actions', 'Actions/Checkout')).toBe('actions/checkout');
  });
  it('leaves Go module paths untouched except lowercase host', () => {
    expect(normalizeName('Go', 'github.com/Foo/Bar')).toBe('github.com/Foo/Bar');
  });
});

describe('software ecosystem (runtimes, products and OS releases from the Seenty Inventory catalog)', () => {
  it('canonicalizes the spellings staff may type', () => {
    for (const s of ['software', 'Software', 'runtime', 'product', 'os']) expect(canonicalEcosystem(s)).toBe('software');
  });
  it('names are catalog slugs: trimmed and lowercased', () => {
    expect(normalizeName('software', '  PHP ')).toBe('php');
  });
});

describe('Docker ecosystem (container images by tag or digest)', () => {
  it('canonicalizes the spellings and normalizes image references to namespace/name', async () => {
    for (const s of ['docker', 'Docker', 'oci', 'container', 'docker hub']) expect(canonicalEcosystem(s)).toBe('Docker');
    expect(normalizeName('Docker', 'PHP')).toBe('library/php');
    expect(normalizeName('Docker', 'docker.io/library/php')).toBe('library/php');
    expect(normalizeName('Docker', 'docker.io/litellm/litellm')).toBe('litellm/litellm');
    expect(normalizeName('Docker', 'ghcr.io/Acme/Tool')).toBe('ghcr.io/acme/tool');
  });
});
