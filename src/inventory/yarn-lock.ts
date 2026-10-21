import { parse } from 'yaml';
import type { Package, Skipped } from '../types.js';
import { parseErrorDetail, pkg, type ParseResult } from './types.js';

/** "name@range" or "@scope/name@range" -> name */
function descriptorName(d: string): string {
  const s = d.trim().replace(/^"|"$/g, '');
  // "safe@npm:evil-pkg@^1" is an alias: the installed package is evil-pkg.
  const alias = s.indexOf('@npm:');
  if (alias > 0) { const rest = s.slice(alias + 5); const at = rest.indexOf('@', 1); return at === -1 ? rest : rest.slice(0, at); }
  const at = s.indexOf('@', 1);
  return at === -1 ? s : s.slice(0, at);
}

function parseClassic(content: string, lockfilePath: string): ParseResult {
  const packages: Package[] = []; const seen = new Set<string>();
  const blocks = content.split(/\n(?=\S)/);
  let sawBlock = false;
  for (const block of blocks) {
    const lines = block.split('\n');
    const head = lines[0] ?? '';
    if (head.startsWith('#') || head.trim() === '' || !head.trim().endsWith(':')) continue;
    const version = lines.map((l) => /^\s+version\s+"?([^"\s]+)"?\s*$/.exec(l)?.[1]).find(Boolean);
    if (!version) continue;
    sawBlock = true;
    const name = descriptorName(head.trim().slice(0, -1).split(',')[0]!);
    const id = `${name}@${version}`; if (seen.has(id)) continue; seen.add(id);
    packages.push(pkg('npm', name, version, lockfilePath));
  }
  if (!sawBlock) return { packages: [], skipped: [{ path: lockfilePath, reason: 'parse-error', detail: 'no yarn entries found' }] };
  return { packages, skipped: [] };
}

function parseBerry(content: string, lockfilePath: string): ParseResult {
  let doc: Record<string, { version?: string | number; resolution?: string }>;
  try { doc = parse(content); } catch (err) { return { packages: [], skipped: [{ path: lockfilePath, reason: 'parse-error', detail: parseErrorDetail(err) }] }; }
  if (!doc || typeof doc !== 'object') return { packages: [], skipped: [{ path: lockfilePath, reason: 'parse-error', detail: 'no entries' }] };
  const packages: Package[] = []; const skipped: Skipped[] = []; const seen = new Set<string>();
  for (const [key, entry] of Object.entries(doc)) {
    if (key === '__metadata' || !entry || typeof entry !== 'object') continue;
    const resolution = entry.resolution ?? '';
    const at = resolution.indexOf('@', 1);
    const name = at === -1 ? resolution : resolution.slice(0, at);
    const locator = at === -1 ? '' : resolution.slice(at + 1);
    const protocol = locator.split(':')[0] ?? '';
    if (protocol === 'workspace') { skipped.push({ path: lockfilePath, reason: 'unsupported-entry', detail: `${key}: workspace` }); continue; }
    if (!['npm', 'patch'].includes(protocol)) { skipped.push({ path: lockfilePath, reason: 'unsupported-entry', detail: `${key}: ${protocol || 'unknown'}` }); continue; }
    const version = String(entry.version ?? '');
    if (!version) { skipped.push({ path: lockfilePath, reason: 'unsupported-entry', detail: `${key}: no version` }); continue; }
    const id = `${name}@${version}`; if (seen.has(id)) continue; seen.add(id);
    packages.push(pkg('npm', name, version, lockfilePath));
  }
  return { packages, skipped };
}

export function parseYarnLock(content: string, lockfilePath: string): ParseResult {
  return /^__metadata:/m.test(content) ? parseBerry(content, lockfilePath) : parseClassic(content, lockfilePath);
}
