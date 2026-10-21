import { readFileSync } from 'node:fs';
import { canonicalEcosystem } from '../src/ecosystem.js';
import { translateAdvisory, type AdvisoryInput } from '../src/feed/build.js';
import { AdvisorySchema } from '../src/feed/schema.js';

export interface CheckResult { errors: { record: number; title: string; package: string; reason: string }[]; summary: { records: number; packages: number; ecosystems: Record<string, number> } }

/** Validates a draft advisories file the way build-feed would, without signing anything. */
export function checkAdvisories(path: string): CheckResult {
  const input = JSON.parse(readFileSync(path, 'utf8')) as Partial<AdvisoryInput>[];
  const errors: CheckResult['errors'] = []; const ecosystems: Record<string, number> = {}; let packages = 0;
  input.forEach((rec, i) => {
    const title = rec.title ?? '';
    if (!rec.title || !rec.severity || !Array.isArray(rec.packages) || rec.packages.length === 0) { errors.push({ record: i, title, package: '', reason: 'missing title, severity or packages' }); return; }
    for (const p of rec.packages) {
      const eco = canonicalEcosystem(p.ecosystem);
      if (!eco) { errors.push({ record: i, title, package: `${p.ecosystem}:${p.package_name}`, reason: `unknown ecosystem ${p.ecosystem}` }); continue; }
      try {
        const adv = translateAdvisory({ ...(rec as AdvisoryInput), packages: [p] }, i + 1);
        const parsed = AdvisorySchema.safeParse(JSON.parse(JSON.stringify(adv)));
        if (!parsed.success) { errors.push({ record: i, title, package: `${p.ecosystem}:${p.package_name}`, reason: `schema: ${parsed.error.issues[0]?.path.join('.')} ${parsed.error.issues[0]?.message}` }); continue; }
        packages += 1; ecosystems[eco] = (ecosystems[eco] ?? 0) + 1;
      }
      catch (err) { errors.push({ record: i, title, package: `${p.ecosystem}:${p.package_name}`, reason: (err as Error).message }); }
    }
  });
  return { errors, summary: { records: input.length, packages, ecosystems } };
}

const isDirectRun = process.argv[1] !== undefined && /check-advisories\.(js|ts)$/.test(process.argv[1]);
if (isDirectRun) {
  const file = process.argv[2];
  if (!file) { console.error('usage: check-advisories <advisories.json>'); process.exit(2); }
  const r = checkAdvisories(file);
  console.log(`${r.summary.records} records, ${r.summary.packages} package entries, ecosystems: ${Object.entries(r.summary.ecosystems).map(([k, v]) => `${k} ${v}`).join(', ') || 'none'}`);
  for (const e of r.errors) console.error(`  record ${e.record} "${e.title}" ${e.package}: ${e.reason}`);
  process.exit(r.errors.length ? 1 : 0);
}
