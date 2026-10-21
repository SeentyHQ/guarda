import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parsePipfileLock, parsePoetryLock, parseRequirements, parseUvLock } from '../../src/inventory/python.js';

const fx = (n: string) => readFileSync(new URL(`../fixtures/lockfiles/python/${n}`, import.meta.url), 'utf8');
const key = (p: { name: string; version: string }) => `${p.name}@${p.version}`;

describe('requirements.txt', () => {
  it('keeps exact pins with their line, drops extras and markers, skips ranges, includes, urls and paths', () => {
    const r = parseRequirements(fx('requirements.txt'), 'requirements.txt');
    expect(r.packages.map(key)).toEqual(['litellm@1.107.0', 'requests@2.32.3', 'Django@5.1.2']);
    expect(r.packages[0]).toMatchObject({ ecosystem: 'PyPI', purl: 'pkg:pypi/litellm@1.107.0', lockfile: 'requirements.txt', line: 2, direct: true });
    expect(r.packages[2]!.line).toBe(4);
    expect(r.skipped).toEqual([
      { path: 'requirements.txt', reason: 'unsupported-entry', detail: 'line 7: flask>=3.0 is a range, not a pin' },
      { path: 'requirements.txt', reason: 'unsupported-entry', detail: 'line 8: numpy~=2.1 is a range, not a pin' },
      { path: 'requirements.txt', reason: 'unsupported-entry', detail: 'line 9: ./local-package is not a registry package' },
      { path: 'requirements.txt', reason: 'unsupported-entry', detail: 'line 10: git+https://github.com/x/y.git#egg=y is not a registry package' },
    ]);
  });
});

describe('poetry.lock', () => {
  it('reads every [[package]] name and version', () => {
    const r = parsePoetryLock(fx('poetry.lock'), 'poetry.lock');
    expect(r.packages.map(key)).toEqual(['litellm@1.107.0', 'requests@2.32.3']);
    expect(r.packages[0]).toMatchObject({ ecosystem: 'PyPI', purl: 'pkg:pypi/litellm@1.107.0', lockfile: 'poetry.lock', line: 3 });
    expect(r.skipped).toEqual([]);
  });
  it('reports a lockfile without packages', () => {
    expect(parsePoetryLock('[metadata]\nlock-version = "2.0"\n', 'poetry.lock').skipped).toEqual([{ path: 'poetry.lock', reason: 'parse-error', detail: 'no [[package]] entries' }]);
  });
});

describe('uv.lock', () => {
  it('reads registry packages and leaves the editable project out', () => {
    const r = parseUvLock(fx('uv.lock'), 'uv.lock');
    expect(r.packages.map(key)).toEqual(['litellm@1.107.0', 'typing-extensions@4.12.2']);
    expect(r.skipped).toEqual([{ path: 'uv.lock', reason: 'unsupported-entry', detail: 'my-app: editable project, not a registry package' }]);
  });
});

describe('Pipfile.lock', () => {
  it('reads default and develop pins and skips path entries', () => {
    const r = parsePipfileLock(fx('Pipfile.lock'), 'Pipfile.lock');
    expect(r.packages.map(key)).toEqual(['litellm@1.107.0', 'requests@2.32.3', 'pytest@8.3.3']);
    expect(r.packages[0]!.direct).toBe(true);
    expect(r.skipped).toEqual([{ path: 'Pipfile.lock', reason: 'unsupported-entry', detail: 'local-thing: no pinned version' }]);
  });
  it('reports invalid JSON', () => {
    expect(parsePipfileLock('{', 'Pipfile.lock').skipped[0]).toMatchObject({ path: 'Pipfile.lock', reason: 'parse-error' });
  });
});
