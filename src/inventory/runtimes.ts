/**
 * The runtime a repository declares about itself: the base image of its Dockerfiles, version files (.nvmrc,
 * .node-version, .python-version, .tool-versions) and the engine pins of its manifests (package.json engines.node,
 * composer.json require.php). Each becomes a RuntimeRef keyed by the Seenty Inventory catalog slug; the scan matches
 * the exact ones against `software` advisories and reports the rest as possible or unchecked.
 */
import type { ImageRef, RuntimeRef, Skipped } from '../types.js';
import { normalizeImageName } from '../ecosystem.js';
import { parseErrorDetail } from './types.js';

export interface RuntimeResult { runtimes: RuntimeRef[]; skipped: Skipped[] }
export interface ImageResult { images: ImageRef[]; skipped: Skipped[] }

/** `name[:tag][@digest]` → an ImageRef; the name normalized the way Docker resolves it. */
export function imageRef(reference: string, file: string, line: number): ImageRef {
  const at = reference.indexOf('@');
  const digest = at >= 0 ? reference.slice(at + 1) : null;
  const ref = at >= 0 ? reference.slice(0, at) : reference;
  const colon = ref.lastIndexOf(':');
  const hasTag = colon > ref.lastIndexOf('/');
  return { name: normalizeImageName(hasTag ? ref.slice(0, colon) : ref), tag: hasTag ? ref.slice(colon + 1) : null, digest, file, line, raw: reference };
}

/** Official image names and tool names → catalog slugs. Anything else is not a runtime we know. */
const IMAGE_SLUGS: Record<string, string> = {
  php: 'php', node: 'nodejs', nodejs: 'nodejs', python: 'python', ruby: 'ruby', nginx: 'nginx', httpd: 'apache-httpd',
  ubuntu: 'ubuntu', debian: 'debian', alpine: 'alpine',
};

/** Leading numeric part of a tag or version string: `8.2-fpm-alpine` → 8.2 (major), `v22.1.0-slim` → 22.1.0 (exact). */
export function numericVersion(text: string): { version: string | null; precision: RuntimeRef['precision'] } {
  const m = /^v?(\d+(?:\.\d+)*)(?![A-Za-z0-9])/.exec(text.trim());
  if (!m) return { version: null, precision: 'unknown' };
  const parts = m[1]!.split('.').length;
  return { version: m[1]!, precision: parts >= 3 ? 'exact' : 'major' };
}
/** A manifest constraint: an exact triple, or a range kept as written. */
function constraint(text: string): { version: string | null; precision: RuntimeRef['precision'] } {
  const t = text.trim();
  if (!t) return { version: null, precision: 'unknown' };
  if (/^v?\d+\.\d+\.\d+$/.test(t)) return { version: t.replace(/^v/, ''), precision: 'exact' };
  return { version: t, precision: 'range' };
}

export function parseDockerfile(content: string, path: string): RuntimeResult & ImageResult {
  const runtimes: RuntimeRef[] = []; const images: ImageRef[] = []; const skipped: Skipped[] = []; const stages = new Set<string>();
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i.exec(lines[i]!);
    if (!m) continue;
    const image = m[1]!; if (m[2]) stages.add(m[2].toLowerCase());
    if (image === 'scratch' || stages.has(image.toLowerCase())) continue;
    images.push(imageRef(image, path, i + 1));
    const [ref] = image.split('@'); // digest pinned: no tag to read
    const colon = ref!.lastIndexOf(':');
    const name = (colon > ref!.lastIndexOf('/') ? ref!.slice(0, colon) : ref!).toLowerCase();
    const tag = colon > ref!.lastIndexOf('/') ? ref!.slice(colon + 1) : '';
    const base = name.split('/').pop()!;
    const official = name === base || name === `library/${base}` || name === `docker.io/library/${base}` || name === `docker.io/${base}`;
    const slug = official ? IMAGE_SLUGS[base] : undefined;
    if (!slug) continue; // not a catalog runtime: it is still an image, listed above
    const { version, precision } = tag ? numericVersion(tag) : { version: null, precision: 'unknown' as const };
    runtimes.push({ slug, version, precision, file: path, line: i + 1, raw: tag ? `${base}:${tag}` : base });
  }
  return { runtimes, images, skipped };
}

/** compose files and Kubernetes manifests: every `image:` line, quotes stripped. */
export function parseImageLines(content: string, path: string): ImageResult {
  const images: ImageRef[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*-?\s*image:\s*["']?([^"'\s#]+)["']?\s*(#.*)?$/.exec(lines[i]!);
    if (!m || m[1]!.includes('${') || m[1]!.includes('{{')) continue; // templated references cannot be checked
    images.push(imageRef(m[1]!, path, i + 1));
  }
  return { images, skipped: [] };
}

/** .nvmrc / .node-version: one version, aliases like lts/* have none. */
export function parseVersionFile(content: string, path: string, slug: string): RuntimeResult {
  const raw = content.split(/\r?\n/).map((l) => l.trim()).find((l) => l && !l.startsWith('#')) ?? '';
  const { version, precision } = numericVersion(raw);
  return { runtimes: raw ? [{ slug, version, precision, file: path, line: 1, raw }] : [], skipped: [] };
}
export function parsePythonVersion(content: string, path: string): RuntimeResult { return parseVersionFile(content, path, 'python'); }

const TOOL_SLUGS: Record<string, string> = { nodejs: 'nodejs', node: 'nodejs', python: 'python', ruby: 'ruby', php: 'php' };
export function parseToolVersions(content: string, path: string): RuntimeResult {
  const runtimes: RuntimeRef[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*([A-Za-z0-9_-]+)\s+(\S+)/.exec(lines[i]!.replace(/#.*$/, ''));
    const slug = m ? TOOL_SLUGS[m[1]!.toLowerCase()] : undefined;
    if (!m || !slug) continue;
    runtimes.push({ slug, ...numericVersion(m[2]!), file: path, line: i + 1, raw: m[2]! });
  }
  return { runtimes, skipped: [] };
}

/** package.json engines.node. */
export function parseEngines(content: string, path: string): RuntimeResult {
  let doc: { engines?: { node?: unknown } };
  try { doc = JSON.parse(content); } catch (err) { return { runtimes: [], skipped: [{ path, reason: 'parse-error', detail: parseErrorDetail(err) }] }; }
  const node = doc?.engines?.node;
  if (typeof node !== 'string' || !node.trim()) return { runtimes: [], skipped: [] };
  return { runtimes: [{ slug: 'nodejs', ...constraint(node), file: path, raw: node.trim() }], skipped: [] };
}
/** composer.json require.php. */
export function parseComposerRuntime(content: string, path: string): RuntimeResult {
  let doc: { require?: { php?: unknown } };
  try { doc = JSON.parse(content); } catch (err) { return { runtimes: [], skipped: [{ path, reason: 'parse-error', detail: parseErrorDetail(err) }] }; }
  const php = doc?.require?.php;
  if (typeof php !== 'string' || !php.trim()) return { runtimes: [], skipped: [] };
  return { runtimes: [{ slug: 'php', ...constraint(php), file: path, raw: php.trim() }], skipped: [] };
}
