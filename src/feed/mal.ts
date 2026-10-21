import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Advisory } from '../types.js';
import { AdvisorySchema } from './schema.js';
import { canonicalEcosystem } from '../ecosystem.js';
import { comparatorFor } from '../match/comparators.js';

const ECO_DIR: Record<string, string> = { npm: 'npm', PyPI: 'pypi', Go: 'go', 'crates.io': 'crates.io', Packagist: 'packagist', RubyGems: 'rubygems', NuGet: 'nuget', Maven: 'maven' };

export async function readMalClone(dir: string, ecosystems: string[]): Promise<Advisory[]> {
  const out: Advisory[] = [];
  for (const eco of ecosystems) {
    const base = join(dir, 'osv', 'malicious', ECO_DIR[eco] ?? eco.toLowerCase());
    let entries; try { entries = await readdir(base, { withFileTypes: true, recursive: true }); } catch { continue; }
    for (const e of entries) {
      if (!e.isFile() || !/^MAL-\d{4}-\d+\.json$/.test(e.name)) continue;
      const raw = JSON.parse(await readFile(join(e.parentPath, e.name), 'utf8')) as Record<string, unknown>;
      const slim = { id: raw.id, modified: raw.modified, published: raw.published, withdrawn: raw.withdrawn, summary: raw.summary ?? '', affected: raw.affected ?? [], references: raw.references };
      const r = AdvisorySchema.safeParse(JSON.parse(JSON.stringify(slim)));
      if (!r.success) continue;
      const valid = r.data.affected.every((a) => { const eco = canonicalEcosystem(a.package.ecosystem); const cmp = eco ? comparatorFor(eco) : null; return !cmp || (a.ranges ?? []).every((rg) => rg.events.every((ev) => [ev.introduced, ev.fixed, ev.last_affected].every((v) => v === undefined || v === '0' || cmp.normalize(v) !== null))); });
      if (valid) out.push(r.data);
    }
  }
  return out;
}
