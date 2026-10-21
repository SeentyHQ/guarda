import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseWorkflow } from '../../src/inventory/workflows.js';

describe('parseWorkflow', () => {
  it('extracts every uses: with repo, ref kind and line; strips sub-paths; skips local, docker and expressions', () => {
    const r = parseWorkflow(readFileSync(new URL('../fixtures/workflows/ci.yml', import.meta.url), 'utf8'), '.github/workflows/ci.yml');
    expect(r.actions).toEqual([
      { repo: 'actions/checkout', ref: 'v4', refKind: 'tag', workflow: '.github/workflows/ci.yml', line: 7 },
      { repo: 'actions/setup-node', ref: '1e60f620b9541d16bece96c5465dc8ee9832be0b', refKind: 'sha', workflow: '.github/workflows/ci.yml', line: 8 },
      { repo: 'aquasecurity/trivy-action', ref: '0.28.0', refKind: 'tag', workflow: '.github/workflows/ci.yml', line: 9 },
      { repo: 'actions/github-script', ref: 'v7', refKind: 'tag', workflow: '.github/workflows/ci.yml', line: 12 },
      { repo: 'owner/repo', ref: 'refs/heads/main', refKind: 'branch', workflow: '.github/workflows/ci.yml', line: 13 },
      { repo: 'org/workflows', ref: 'v2', refKind: 'tag', workflow: '.github/workflows/ci.yml', line: 17 },
    ]);
    expect(r.skipped.map((s) => s.detail)).toEqual(['./.github/actions/local: local', 'docker://alpine:3.20: docker', '${{ matrix.action }}: expression']);
  });
  it('reports invalid yaml', () => {
    expect(parseWorkflow('jobs: [', 'w.yml').skipped[0]!.reason).toBe('parse-error');
  });
});
