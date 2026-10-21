import { describe, expect, it } from 'vitest';
import { memoryFs } from '../../src/adapters.js';
import { discover } from '../../src/inventory/discover.js';

describe('discover', () => {
  it('finds lockfiles and workflows at any depth and skips vendored dirs', async () => {
    const fs = memoryFs({
      'package-lock.json': '{}',
      'apps/web/pnpm-lock.yaml': '',
      'apps/api/yarn.lock': '',
      'tools/bun.lock': '',
      'legacy/bun.lockb': 'binary',
      '.github/workflows/ci.yml': 'on: push',
      '.github/workflows/release.yaml': 'on: push',
      'node_modules/dep/package-lock.json': '{}',
      'src/index.ts': 'console.log(1)',
    });
    const r = await discover('/repo', fs);
    expect(r.sources.map((s) => `${s.kind}:${s.path}`).sort()).toEqual([
      'bun-lock:tools/bun.lock', 'bun-lockb:legacy/bun.lockb', 'npm-lock:package-lock.json', 'pnpm-lock:apps/web/pnpm-lock.yaml',
      'workflow:.github/workflows/ci.yml', 'workflow:.github/workflows/release.yaml', 'yarn-lock:apps/api/yarn.lock',
    ]);
    expect(r.files).toContain('src/index.ts');
    expect(r.files.some((f) => f.startsWith('node_modules/'))).toBe(false);
  });
  it('does not follow symlinks', async () => {
    const fs = memoryFs({ 'a/package-lock.json': '{}' }, { symlinks: ['link'] });
    const r = await discover('/repo', fs);
    expect(r.sources).toHaveLength(1);
  });
});

describe('discover: python', () => {
  it('finds the Python lockfiles at any depth, requirements variants included', async () => {
    const { memoryFs } = await import('../../src/adapters.js');
    const { discover } = await import('../../src/inventory/discover.js');
    const fs = memoryFs({ 'requirements.txt': 'a==1', 'api/poetry.lock': '', 'svc/uv.lock': '', 'old/Pipfile.lock': '{}', 'docs/requirements-docs.txt': 'x==1' });
    const found = await discover('/repo', fs);
    expect(found.sources.map((s) => `${s.kind}:${s.path}`)).toEqual(['poetry-lock:api/poetry.lock', 'requirements:docs/requirements-docs.txt', 'pipfile-lock:old/Pipfile.lock', 'requirements:requirements.txt', 'uv-lock:svc/uv.lock']);
  });
});

describe('discover: images', () => {
  it('finds compose files anywhere and manifests under deploy directories only', async () => {
    const { memoryFs } = await import('../../src/adapters.js');
    const { discover } = await import('../../src/inventory/discover.js');
    const fs = memoryFs({ 'docker-compose.yml': '', 'ops/compose.prod.yaml': '', 'k8s/api.yaml': '', 'deploy/web.yml': '', 'charts/x/templates/d.yaml': '', 'config/app.yaml': '', '.github/workflows/ci.yml': '' });
    const found = await discover('/repo', fs);
    expect(found.sources.filter((s) => s.kind === 'compose' || s.kind === 'manifest').map((s) => `${s.kind}:${s.path}`)).toEqual(['manifest:charts/x/templates/d.yaml', 'manifest:deploy/web.yml', 'compose:docker-compose.yml', 'manifest:k8s/api.yaml', 'compose:ops/compose.prod.yaml']);
  });
});
