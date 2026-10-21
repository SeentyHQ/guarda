/**
 * Python lockfiles: requirements.txt (pins only), poetry.lock and uv.lock (TOML [[package]] blocks, read with a
 * line-based subset parser: name and version are always plain strings on their own line) and Pipfile.lock (JSON).
 * Names are passed as written; the matcher normalizes them by PEP 503 at match time.
 */
import type { Package, Skipped } from '../types.js';
import { parseErrorDetail, pkg, type ParseResult } from './types.js';

const NAME = '[A-Za-z0-9][A-Za-z0-9._-]*';

/** `name[extra]==1.2.3 ; marker  # comment` → a package; ranges, includes, options, URLs and paths are skipped. */
export function parseRequirements(content: string, lockfilePath: string): ParseResult {
  const packages: Package[] = []; const skipped: Skipped[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]!.replace(/\s+#.*$/, '').replace(/^#.*$/, '').trim();
    if (!raw) continue;
    const spec = raw.split(';')[0]!.trim();
    if (spec.startsWith('-') || spec.startsWith('--')) continue; // -r other.txt, --index-url, -e: options and includes
    const pin = new RegExp(`^(${NAME})(?:\\[[^\\]]*\\])?\\s*==\\s*([A-Za-z0-9][A-Za-z0-9.+!*-]*)$`).exec(spec);
    if (pin) { packages.push(pkg('PyPI', pin[1]!, pin[2]!, lockfilePath, { line: i + 1, direct: true })); continue; }
    if (new RegExp(`^(${NAME})(?:\\[[^\\]]*\\])?\\s*(>=|<=|~=|!=|>|<|===)`).test(spec)) { skipped.push({ path: lockfilePath, reason: 'unsupported-entry', detail: `line ${i + 1}: ${spec} is a range, not a pin` }); continue; }
    skipped.push({ path: lockfilePath, reason: 'unsupported-entry', detail: `line ${i + 1}: ${spec} is not a registry package` });
  }
  return { packages, skipped };
}

interface TomlPackage { name?: string; version?: string; line: number; source?: string }

/** The `[[package]]` blocks of a TOML lockfile: top-level `name`, `version` and a flattened `source` line. */
function tomlPackages(content: string): TomlPackage[] {
  const out: TomlPackage[] = []; let current: TomlPackage | null = null; let inPackage = false;
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();
    if (line === '[[package]]') { current = { line: i + 1 }; out.push(current); inPackage = true; continue; }
    if (line.startsWith('[')) { inPackage = false; continue; } // [package.dependencies], [metadata], [[package.x]] ...
    if (!inPackage || !current) continue;
    const kv = /^([A-Za-z_-]+)\s*=\s*(.*)$/.exec(line); if (!kv) continue;
    const str = /^"([^"]*)"/.exec(kv[2]!);
    if (kv[1] === 'name' && str) current.name = str[1]!;
    else if (kv[1] === 'version' && str) current.version = str[1]!;
    else if (kv[1] === 'source') current.source = kv[2]!;
  }
  return out;
}

export function parsePoetryLock(content: string, lockfilePath: string): ParseResult {
  const blocks = tomlPackages(content);
  if (!blocks.length) return { packages: [], skipped: [{ path: lockfilePath, reason: 'parse-error', detail: 'no [[package]] entries' }] };
  const packages: Package[] = []; const skipped: Skipped[] = [];
  for (const b of blocks) {
    if (!b.name || !b.version) { skipped.push({ path: lockfilePath, reason: 'unsupported-entry', detail: `line ${b.line}: package without name or version` }); continue; }
    packages.push(pkg('PyPI', b.name, b.version, lockfilePath, { line: b.line }));
  }
  return { packages, skipped };
}

export function parseUvLock(content: string, lockfilePath: string): ParseResult {
  const blocks = tomlPackages(content);
  if (!blocks.length) return { packages: [], skipped: [{ path: lockfilePath, reason: 'parse-error', detail: 'no [[package]] entries' }] };
  const packages: Package[] = []; const skipped: Skipped[] = [];
  for (const b of blocks) {
    if (!b.name || !b.version) { skipped.push({ path: lockfilePath, reason: 'unsupported-entry', detail: `line ${b.line}: package without name or version` }); continue; }
    // The project itself and path/git dependencies are not registry packages.
    if (b.source && /\b(editable|path|git|directory|virtual)\s*=/.test(b.source)) { skipped.push({ path: lockfilePath, reason: 'unsupported-entry', detail: `${b.name}: editable project, not a registry package` }); continue; }
    packages.push(pkg('PyPI', b.name, b.version, lockfilePath, { line: b.line }));
  }
  return { packages, skipped };
}

interface PipfileEntry { version?: string; path?: string; git?: string }
interface PipfileLock { default?: Record<string, PipfileEntry>; develop?: Record<string, PipfileEntry> }

export function parsePipfileLock(content: string, lockfilePath: string): ParseResult {
  let lock: PipfileLock;
  try { lock = JSON.parse(content) as PipfileLock; } catch (err) { return { packages: [], skipped: [{ path: lockfilePath, reason: 'parse-error', detail: parseErrorDetail(err) }] }; }
  if (typeof lock !== 'object' || lock === null || (!lock.default && !lock.develop)) return { packages: [], skipped: [{ path: lockfilePath, reason: 'parse-error', detail: 'no "default" or "develop" section' }] };
  const packages: Package[] = []; const skipped: Skipped[] = [];
  for (const section of [lock.default ?? {}, lock.develop ?? {}]) {
    for (const [name, entry] of Object.entries(section)) {
      const version = typeof entry?.version === 'string' ? entry.version.replace(/^==/, '').trim() : '';
      if (!version) { skipped.push({ path: lockfilePath, reason: 'unsupported-entry', detail: `${name}: no pinned version` }); continue; }
      packages.push(pkg('PyPI', name, version, lockfilePath, { direct: true }));
    }
  }
  return { packages, skipped };
}
