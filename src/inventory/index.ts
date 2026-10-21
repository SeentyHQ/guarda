import type { FsAdapter } from '../adapters.js';
import { joinPath } from '../adapters.js';
import type { Inventory, Skipped } from '../types.js';
import { parseBunLock } from './bun-lock.js';
import { discover } from './discover.js';
import { parseNpmLock } from './npm-lock.js';
import { parseNpmManifest } from './npm-manifest.js';
import { parsePnpmLock } from './pnpm-lock.js';
import { parsePipfileLock, parsePoetryLock, parseRequirements, parseUvLock } from './python.js';
import { parseComposerRuntime, parseDockerfile, parseEngines, parseImageLines, parsePythonVersion, parseToolVersions, parseVersionFile } from './runtimes.js';
import { parseErrorDetail } from './types.js';
import { parseWorkflow } from './workflows.js';
import { parseYarnLock } from './yarn-lock.js';

export const DEFAULT_MAX_FILE_BYTES = 20 * 1024 * 1024;

export async function collectInventory(root: string, fs: FsAdapter, opts: { maxFileBytes?: number } = {}): Promise<Inventory & { files: string[] }> {
  const max = opts.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const found = await discover(root, fs);
  const inv: Inventory & { files: string[] } = { packages: [], declared: [], actions: [], runtimes: [], images: [], skipped: [...found.skipped], scannedFiles: [], files: found.files };
  const dirOf = (p: string) => p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '';
  // Directories that have an npm-family lockfile: their package.json pins are redundant (the lock has the resolved version).
  const RUNTIME_KINDS = new Set(['dockerfile', 'nvmrc', 'node-version', 'python-version', 'tool-versions', 'composer-manifest', 'compose', 'manifest']);
  const lockedDirs = new Set(found.sources.filter((s) => s.kind !== 'workflow' && s.kind !== 'npm-manifest' && !RUNTIME_KINDS.has(s.kind)).map((s) => dirOf(s.path)));
  for (const src of found.sources) {
    if (src.kind === 'bun-lockb') { inv.skipped.push({ path: src.path, reason: 'unsupported-format', detail: 'binary lockfile; run "bun install --save-text-lockfile"' }); continue; }
    const size = await fs.size(joinPath(root, src.path));
    if (size > max) { inv.skipped.push({ path: src.path, reason: 'too-large', detail: `${size} bytes > ${max}` }); continue; }
    let content: string;
    try { content = await fs.readFile(joinPath(root, src.path)); } catch (err) { inv.skipped.push({ path: src.path, reason: 'parse-error', detail: parseErrorDetail(err) }); continue; }
    let skipped: Skipped[];
    try {
    switch (src.kind) {
      case 'npm-lock': { const r = parseNpmLock(content, src.path); inv.packages.push(...r.packages); skipped = r.skipped; break; }
      case 'pnpm-lock': { const r = parsePnpmLock(content, src.path); inv.packages.push(...r.packages); skipped = r.skipped; break; }
      case 'yarn-lock': { const r = parseYarnLock(content, src.path); inv.packages.push(...r.packages); skipped = r.skipped; break; }
      case 'bun-lock': { const r = parseBunLock(content, src.path); inv.packages.push(...r.packages); skipped = r.skipped; break; }
      case 'requirements': { const r = parseRequirements(content, src.path); inv.packages.push(...r.packages); skipped = r.skipped; break; }
      case 'poetry-lock': { const r = parsePoetryLock(content, src.path); inv.packages.push(...r.packages); skipped = r.skipped; break; }
      case 'uv-lock': { const r = parseUvLock(content, src.path); inv.packages.push(...r.packages); skipped = r.skipped; break; }
      case 'pipfile-lock': { const r = parsePipfileLock(content, src.path); inv.packages.push(...r.packages); skipped = r.skipped; break; }
      case 'dockerfile': { const r = parseDockerfile(content, src.path); inv.runtimes.push(...r.runtimes); inv.images.push(...r.images); skipped = r.skipped; break; }
      case 'compose': case 'manifest': { const r = parseImageLines(content, src.path); inv.images.push(...r.images); skipped = r.skipped; break; }
      case 'nvmrc': case 'node-version': { const r = parseVersionFile(content, src.path, 'nodejs'); inv.runtimes.push(...r.runtimes); skipped = r.skipped; break; }
      case 'python-version': { const r = parsePythonVersion(content, src.path); inv.runtimes.push(...r.runtimes); skipped = r.skipped; break; }
      case 'tool-versions': { const r = parseToolVersions(content, src.path); inv.runtimes.push(...r.runtimes); skipped = r.skipped; break; }
      case 'composer-manifest': { const r = parseComposerRuntime(content, src.path); inv.runtimes.push(...r.runtimes); skipped = r.skipped; break; }
      case 'workflow': { const r = parseWorkflow(content, src.path); inv.actions.push(...r.actions); skipped = r.skipped; break; }
      case 'npm-manifest': {
        const locked = lockedDirs.has(dirOf(src.path));
        const r = parseNpmManifest(content, src.path, locked ? 'committed' : 'none');
        if (!locked) inv.packages.push(...r.packages);
        inv.declared.push(...r.declared); skipped = r.skipped;
        inv.runtimes.push(...parseEngines(content, src.path).runtimes);
        if (!locked) skipped.push({ path: src.path, reason: 'no-lockfile', detail: 'transitive dependencies not checked; commit a lockfile' });
        break;
      }
    }
    } catch (err) { skipped = [{ path: src.path, reason: 'parse-error', detail: parseErrorDetail(err) }]; }
    inv.scannedFiles.push(src.path);
    inv.skipped.push(...skipped);
  }
  return inv;
}
