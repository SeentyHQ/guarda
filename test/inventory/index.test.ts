import { describe, expect, it } from 'vitest';
import { memoryFs } from '../../src/adapters.js';
import { collectInventory } from '../../src/inventory/index.js';

describe('collectInventory', () => {
  it('dispatches every source and reports bun.lockb and oversized files', async () => {
    const fs = memoryFs({
      'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/keyv': { version: '5.7.2' } } }),
      'legacy/bun.lockb': 'x',
      'big/yarn.lock': 'x'.repeat(100),
      '.github/workflows/ci.yml': 'jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n',
      'README.md': 'hi',
    });
    const inv = await collectInventory('/repo', fs, { maxFileBytes: 90 });
    expect(inv.packages.map((p) => p.name)).toEqual(['keyv']);
    expect(inv.actions.map((a) => a.repo)).toEqual(['actions/checkout']);
    expect(inv.skipped).toEqual(expect.arrayContaining([
      { path: 'legacy/bun.lockb', reason: 'unsupported-format', detail: 'binary lockfile; run "bun install --save-text-lockfile"' },
      { path: 'big/yarn.lock', reason: 'too-large', detail: '100 bytes > 90' },
    ]));
    expect(inv.scannedFiles.sort()).toEqual(['.github/workflows/ci.yml', 'package-lock.json']);
    expect(inv.files).toContain('README.md');
  });
});

describe('collectInventory: runtimes', () => {
  it('collects the runtime the repo declares from every file kind, with the file it came from', async () => {
    const fs = memoryFs({
      'Dockerfile': 'FROM php:8.2-fpm\n',
      'docker/api.Dockerfile': 'FROM node:22.1.0\n',
      '.nvmrc': 'v22.1.0\n',
      'api/package.json': JSON.stringify({ name: 'api', engines: { node: '>=22' } }),
      'web/composer.json': JSON.stringify({ require: { php: '^8.2' } }),
      '.python-version': '3.12.4\n',
      '.tool-versions': 'ruby 3.3.0\n',
    });
    const inv = await collectInventory('/repo', fs);
    expect(inv.runtimes.map((r) => `${r.slug}@${r.version ?? '?'} ${r.file}`).sort()).toEqual([
      'nodejs@22.1.0 .nvmrc', 'nodejs@22.1.0 docker/api.Dockerfile', 'nodejs@>=22 api/package.json', 'php@8.2 Dockerfile', 'php@^8.2 web/composer.json', 'python@3.12.4 .python-version', 'ruby@3.3.0 .tool-versions',
    ]);
    expect(inv.packages).toEqual([]);
    expect(inv.scannedFiles).toEqual(expect.arrayContaining(['Dockerfile', '.nvmrc', '.tool-versions']));
  });
});
