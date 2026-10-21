import type { FsAdapter } from '../adapters.js';
import { joinPath, relJoin } from '../adapters.js';
import type { Skipped } from '../types.js';

export type SourceKind = 'npm-lock' | 'pnpm-lock' | 'yarn-lock' | 'bun-lock' | 'bun-lockb' | 'workflow' | 'npm-manifest' | 'requirements' | 'poetry-lock' | 'uv-lock' | 'pipfile-lock'
  | 'dockerfile' | 'nvmrc' | 'node-version' | 'python-version' | 'tool-versions' | 'composer-manifest' | 'compose' | 'manifest';
export interface SourceFile { path: string; kind: SourceKind }

const EXCLUDED_DIRS: Record<string, string> = {
  node_modules: 'dependency directory', vendor: 'dependency directory', '.git': 'version control directory',
  dist: 'build output directory', build: 'build output directory', '.next': 'build output directory', target: 'build output directory',
  __pycache__: 'bytecode cache', '.venv': 'virtual environment', venv: 'virtual environment',
};
const LOCKFILES: Record<string, SourceKind> = {
  'package-lock.json': 'npm-lock', 'npm-shrinkwrap.json': 'npm-lock', 'pnpm-lock.yaml': 'pnpm-lock',
  'yarn.lock': 'yarn-lock', 'bun.lock': 'bun-lock', 'bun.lockb': 'bun-lockb',
  'poetry.lock': 'poetry-lock', 'uv.lock': 'uv-lock', 'Pipfile.lock': 'pipfile-lock',
};
// requirements.txt and its variants (requirements-dev.txt, requirements/prod.txt): pins only, see python.ts.
const REQUIREMENTS = /^requirements[\w.-]*\.txt$/;
const VERSION_FILES: Record<string, SourceKind> = { '.nvmrc': 'nvmrc', '.node-version': 'node-version', '.python-version': 'python-version', '.tool-versions': 'tool-versions', 'composer.json': 'composer-manifest' };
const DOCKERFILE = /^(Dockerfile(\.[\w.-]+)?|[\w.-]+\.Dockerfile)$/i;
const COMPOSE = /^(docker-)?compose[\w.-]*\.ya?ml$/;
// Kubernetes and Helm manifests are read only where they usually live; any other yaml is left alone.
const MANIFEST_DIR = /(^|\/)(k8s|kubernetes|deploy|deployment|deployments|manifests|charts|helm)\//;

export async function discover(root: string, fs: FsAdapter): Promise<{ sources: SourceFile[]; skipped: Skipped[]; files: string[] }> {
  const sources: SourceFile[] = []; const skipped: Skipped[] = []; const files: string[] = [];
  async function walk(rel: string): Promise<void> {
    let entries;
    try { entries = await fs.readdir(joinPath(root, rel)); }
    catch (err) { skipped.push({ path: rel || '.', reason: 'parse-error', detail: `read error ${(err as NodeJS.ErrnoException).code ?? ''}`.trim() }); return; }
    for (const e of entries) {
      const p = relJoin(rel, e.name);
      if (e.isSymlink) { skipped.push({ path: p, reason: 'excluded', detail: 'symbolic link' }); continue; }
      if (e.isDirectory) { const why = EXCLUDED_DIRS[e.name]; if (why) skipped.push({ path: p, reason: 'excluded', detail: why }); else await walk(p); continue; }
      if (!e.isFile) continue;
      files.push(p);
      const kind = LOCKFILES[e.name];
      if (kind) sources.push({ path: p, kind });
      else if (REQUIREMENTS.test(e.name) || /^requirements\/[^/]+\.txt$/.test(p)) sources.push({ path: p, kind: 'requirements' });
      else if (e.name === 'package.json') sources.push({ path: p, kind: 'npm-manifest' });
      else if (VERSION_FILES[e.name]) sources.push({ path: p, kind: VERSION_FILES[e.name]! });
      else if (DOCKERFILE.test(e.name)) sources.push({ path: p, kind: 'dockerfile' });
      else if (COMPOSE.test(e.name)) sources.push({ path: p, kind: 'compose' });
      else if (/\.ya?ml$/.test(e.name) && MANIFEST_DIR.test(p)) sources.push({ path: p, kind: 'manifest' });
      else if (/^\.github\/workflows\/[^/]+\.ya?ml$/.test(p)) sources.push({ path: p, kind: 'workflow' });
    }
  }
  await walk('');
  sources.sort((a, b) => a.path.localeCompare(b.path));
  return { sources, skipped, files };
}
