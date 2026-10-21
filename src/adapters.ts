import { readFile as fsReadFile, readdir as fsReaddir, stat as fsStat } from 'node:fs/promises';
import { join, posix } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export interface DirEntry { name: string; isDirectory: boolean; isFile: boolean; isSymlink: boolean }
export interface FsAdapter { readFile(path: string): Promise<string>; readdir(path: string): Promise<DirEntry[]>; size(path: string): Promise<number> }
export interface GitAdapter {
  ignored(root: string, paths: string[]): Promise<Set<string>>;
  stagedFiles(root: string): Promise<string[]>;
  showStaged(root: string, path: string): Promise<string>;
}
export interface FetchResponse { status: number; headers: { get(name: string): string | null }; arrayBuffer(): Promise<ArrayBuffer> }
export type FetchLike = (url: string, init?: { headers?: Record<string, string> }) => Promise<FetchResponse>;

export const nodeFs: FsAdapter = {
  readFile: (p) => fsReadFile(p, 'utf8'),
  async readdir(p) {
    const entries = await fsReaddir(p, { withFileTypes: true });
    return entries.map((e) => ({ name: e.name, isDirectory: e.isDirectory(), isFile: e.isFile(), isSymlink: e.isSymbolicLink() }));
  },
  size: async (p) => (await fsStat(p)).size,
};

/**
 * Git is run with repository-provided hooks and fsmonitor disabled: the scanned repository is untrusted.
 * safe.directory names the scanned root only: a bind mount (Docker, CI) is often owned by another uid and git
 * would otherwise refuse it as "dubious ownership", silently turning every ignore check into "not ignored".
 */
export function gitArgs(root: string, args: string[]): string[] {
  return ['-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-c', `safe.directory=${root}`, '-C', root, ...args];
}

/** `git check-ignore --stdin -z`; exit 1 means nothing ignored, exit 128 (not a repository) means the same here. */
export const nodeGit: GitAdapter = {
  ignored(root, paths) {
    if (paths.length === 0) return Promise.resolve(new Set());
    return new Promise((resolve) => {
      let done = false; const finish = (out: string) => { if (!done) { done = true; resolve(new Set(out.split('\0').filter(Boolean))); } };
      const child = execFile('git', gitArgs(root, ['check-ignore', '--stdin', '-z']), { maxBuffer: 64 * 1024 * 1024 }, (_err, stdout) => finish(String(stdout ?? '')));
      child.on('error', () => finish(''));
      child.stdin?.on('error', () => {});
      child.stdin?.end(paths.join('\0') + '\0');
    });
  },
  async stagedFiles(root) {
    const { stdout } = await execFileAsync('git', gitArgs(root, ['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z']));
    return stdout.split('\0').filter(Boolean);
  },
  async showStaged(root, path) {
    const { stdout } = await execFileAsync('git', gitArgs(root, ['show', `:${path}`]), { maxBuffer: 64 * 1024 * 1024 });
    return stdout;
  },
};

/** In-memory adapter for tests. Paths are relative to any root; a leading "/repo" is ignored. */
export function memoryFs(files: Record<string, string>, opts: { symlinks?: string[] } = {}): FsAdapter {
  const norm = (p: string) => p.replace(/^\/repo\/?/, '').replace(/^\.\//, '');
  const symlinks = new Set(opts.symlinks ?? []);
  return {
    async readFile(p) { const k = norm(p); if (!(k in files)) throw new Error(`ENOENT: ${p}`); return files[k]!; },
    async readdir(p) {
      const prefix = norm(p); const base = prefix === '' ? '' : prefix.replace(/\/$/, '') + '/';
      const names = new Map<string, DirEntry>();
      for (const f of Object.keys(files)) {
        if (!f.startsWith(base)) continue;
        const rest = f.slice(base.length); const head = rest.split('/')[0]!;
        if (!head) continue;
        names.set(head, { name: head, isDirectory: rest.includes('/'), isFile: !rest.includes('/'), isSymlink: false });
      }
      for (const s of symlinks) if (s.startsWith(base) && !s.slice(base.length).includes('/')) names.set(s, { name: s, isDirectory: false, isFile: false, isSymlink: true });
      return [...names.values()];
    },
    async size(p) { return Buffer.byteLength(files[norm(p)] ?? '', 'utf8'); },
  };
}

export function joinPath(root: string, rel: string): string { return root === '' ? rel : join(root, rel); }
export const relJoin = (a: string, b: string): string => (a === '' ? b : posix.join(a, b));
