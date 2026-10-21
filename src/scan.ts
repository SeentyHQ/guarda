import { joinPath, nodeFs, nodeGit, type FsAdapter, type GitAdapter } from './adapters.js';
import { collectInventory } from './inventory/index.js';
import { matchActions } from './match/actions.js';
import { matchPackages } from './match/packages.js';
import { matchDeclared } from './match/declared.js';
import { matchRuntimes } from './match/runtimes.js';
import { matchImages } from './match/images.js';
import { globToRegExp, isIgnored } from './ignore.js';
import { scanSecrets, type SecretsInput } from './secrets/engine.js';
import type { Feed, FeedStatus, Report, Skipped } from './types.js';

export const ENGINE_VERSION = '0.1.5';
export interface ScanOptions { feed: Feed; feedStatus: FeedStatus; fs?: FsAdapter; git?: GitAdapter; secrets?: boolean; only?: ('packages' | 'actions' | 'secrets')[]; staged?: boolean; maxSecretFileBytes?: number; engineVersion?: string; /** Path globs (from .guarda.json) excluded from the secrets scan. */ ignore?: string[]; /** A pre-collected inventory for the same root, to avoid walking twice. */ inventory?: Awaited<ReturnType<typeof collectInventory>> }

const OWN_FIXTURES = /(^|\/)test\/fixtures\/secrets\//;

const BINARY_EXT = /\.(png|jpe?g|gif|webp|ico|pdf|zip|gz|tgz|bz2|xz|7z|jar|war|class|exe|dll|so|dylib|wasm|woff2?|ttf|otf|eot|mp[34]|mov|avi|lockb|node|pyc|o|a)$/i;
const INCOMPLETE: Set<Skipped['reason']> = new Set(['parse-error', 'too-large', 'unsupported-format', 'no-lockfile']);
const isBinary = (content: string) => content.slice(0, 8192).includes('\0');

export async function scan(root: string, opts: ScanOptions): Promise<Report> {
  const fs = opts.fs ?? nodeFs; const git = opts.git ?? nodeGit;
  const want = new Set(opts.only ?? ['packages', 'actions', 'secrets']);
  if (opts.secrets === false) want.delete('secrets');
  const raw = opts.inventory ?? await collectInventory(root, fs);
  const ignorePatterns = (opts.ignore ?? []).map(globToRegExp);
  const isIgnoredPath = (p: string) => ignorePatterns.length > 0 && isIgnored(p, ignorePatterns);
  // .guarda.json ignore globs apply to everything: lockfiles, workflows and files for the secrets scan.
  const inv = ignorePatterns.length === 0 ? raw : {
    packages: raw.packages.filter((p) => !isIgnoredPath(p.lockfile)),
    declared: raw.declared.filter((d) => !isIgnoredPath(d.manifest)),
    actions: raw.actions.filter((a) => !isIgnoredPath(a.workflow)),
    runtimes: raw.runtimes.filter((r) => !isIgnoredPath(r.file)),
    images: raw.images.filter((i) => !isIgnoredPath(i.file)),
    skipped: raw.skipped.filter((k) => !isIgnoredPath(k.path)),
    scannedFiles: raw.scannedFiles.filter((f) => !isIgnoredPath(f)),
    files: raw.files,
  };
  const skipped: Skipped[] = [...inv.skipped];
  for (const f of raw.scannedFiles) if (isIgnoredPath(f)) skipped.push({ path: f, reason: 'excluded', detail: 'ignored by .guarda.json' });
  const pkgResult = want.has('packages') ? matchPackages(inv.packages, opts.feed) : { matches: [], skipped: [] as Skipped[] };
  skipped.push(...pkgResult.skipped);
  // A lockfile that git ignores never reaches CI: there, package.json ranges resolve fresh, so treat them as unlocked.
  let declared = inv.declared;
  if (want.has('packages') && declared.some((d) => d.lockfile === 'committed')) {
    const lockfiles = [...new Set(inv.packages.map((p) => p.lockfile).filter((f) => !f.endsWith('package.json')))];
    const answer = lockfiles.length ? await git.ignored(root, lockfiles) : new Set<string>();
    const ignoredLocks = lockfiles.filter((f) => answer.has(f)); // only the lockfiles we asked about
    const dirOf = (p: string) => p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '';
    const ignoredDirs = new Set(ignoredLocks.map(dirOf));
    for (const lock of ignoredLocks) skipped.push({ path: lock, reason: 'no-lockfile', detail: 'gitignored: CI resolves package.json ranges fresh' });
    declared = declared.map((d) => d.lockfile === 'committed' && ignoredDirs.has(dirOf(d.manifest)) ? { ...d, lockfile: 'ignored' as const } : d);
  }
  const declResult = want.has('packages') ? matchDeclared(declared, opts.feed) : { matches: [], skipped: [] as Skipped[] };
  skipped.push(...declResult.skipped);
  const runtimeResult = want.has('packages') ? matchRuntimes(inv.runtimes, opts.feed) : { matches: [], skipped: [] as Skipped[] };
  skipped.push(...runtimeResult.skipped);
  const imageResult = want.has('packages') ? matchImages(inv.images, opts.feed) : { matches: [], skipped: [] as Skipped[] };
  skipped.push(...imageResult.skipped);
  const matches = [...pkgResult.matches, ...declResult.matches, ...runtimeResult.matches, ...imageResult.matches, ...(want.has('actions') ? matchActions(inv.actions, opts.feed) : [])];
  const scanned = new Set<string>(inv.scannedFiles);
  let secrets: Report['secrets'] = [];
  if (want.has('secrets')) {
    const inputs: SecretsInput[] = [];
    const max = opts.maxSecretFileBytes ?? 1024 * 1024;
    if (opts.staged) {
      for (const path of await git.stagedFiles(root)) {
        if (BINARY_EXT.test(path)) { skipped.push({ path, reason: 'excluded', detail: 'binary file' }); continue; }
        let content: string;
        try { content = await git.showStaged(root, path); } catch { skipped.push({ path, reason: 'parse-error', detail: 'could not read the staged file' }); continue; }
        if (content.length > max) { skipped.push({ path, reason: 'too-large', detail: `${content.length} bytes > ${max}` }); continue; }
        if (isBinary(content)) { skipped.push({ path, reason: 'excluded', detail: 'binary file' }); continue; }
        inputs.push({ path, content, gitignored: false }); scanned.add(path);
      }
    } else {
      const candidates: string[] = [];
      for (const f of inv.files) {
        if (isIgnoredPath(f)) { if (!raw.scannedFiles.includes(f)) skipped.push({ path: f, reason: 'excluded', detail: 'ignored by .guarda.json' }); }
        else if (BINARY_EXT.test(f)) skipped.push({ path: f, reason: 'excluded', detail: 'binary file' });
        else if (OWN_FIXTURES.test(f)) skipped.push({ path: f, reason: 'excluded', detail: 'guarda secret-rule fixtures' });
        else candidates.push(f);
      }
      const ignored = await git.ignored(root, candidates);
      for (const path of candidates) {
        const size = await fs.size(joinPath(root, path));
        if (size > max) { skipped.push({ path, reason: 'too-large', detail: `${size} bytes > ${max}` }); continue; }
        let content: string;
        try { content = await fs.readFile(joinPath(root, path)); } catch (err) { skipped.push({ path, reason: 'parse-error', detail: `read error ${(err as NodeJS.ErrnoException).code ?? ''}`.trim() }); continue; }
        if (isBinary(content)) { skipped.push({ path, reason: 'excluded', detail: 'binary file' }); continue; }
        inputs.push({ path, content, gitignored: ignored.has(path) }); scanned.add(path);
      }
    }
    secrets = scanSecrets(inputs);
  }
  return {
    matches, secrets,
    coverage: {
      scannedFiles: scanned.size, skipped, feed: opts.feedStatus, complete: !skipped.some((s) => INCOMPLETE.has(s.reason)) && !opts.feedStatus.stale,
      inventory: {
        packages: inv.packages.length, lockfiles: new Set(inv.packages.map((p) => p.lockfile).filter((f) => !f.endsWith('package.json'))).size,
        declared: inv.declared.length, manifests: new Set(inv.declared.map((d) => d.manifest)).size,
        actions: inv.actions.length, workflows: new Set(inv.actions.map((a) => a.workflow)).size,
        runtimes: inv.runtimes.length, runtimeFiles: new Set(inv.runtimes.map((r) => r.file)).size,
        images: inv.images.length, imageFiles: new Set(inv.images.map((i) => i.file)).size,
      },
    },
    engineVersion: opts.engineVersion ?? ENGINE_VERSION,
  };
}
