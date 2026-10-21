import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { buildFeed, type AdvisoryInput } from '../src/feed/build.js';
import { readMalClone } from '../src/feed/mal.js';
const { values } = parseArgs({ options: { advisories: { type: 'string' }, mal: { type: 'string' }, out: { type: 'string', default: '.feed-out' }, key: { type: 'string', default: 'keys/active.private.pem' }, version: { type: 'string' }, ecosystems: { type: 'string', default: 'npm,PyPI' } } });
if (!values.advisories || !values.version) { console.error('usage: build-feed --advisories export.json --version N [--mal <clone dir>] [--out dir] [--key pem] [--ecosystems npm,PyPI]'); process.exit(2); }
const advisories = JSON.parse(readFileSync(values.advisories, 'utf8')) as AdvisoryInput[];
const mal = values.mal ? await readMalClone(values.mal, values.ecosystems!.split(',')) : [];
const feed = buildFeed({ advisories, mal, feedVersion: Number(values.version), now: new Date(), privateKeyPem: readFileSync(values.key!, 'utf8'), ...(values.mal ? { malMeta: { snapshot: new Date().toISOString() } } : {}) });
mkdirSync(values.out!, { recursive: true });
for (const [name, bytes] of feed.files) writeFileSync(join(values.out!, name), bytes);
writeFileSync(join(values.out!, 'manifest.json'), feed.manifestBytes);
writeFileSync(join(values.out!, 'manifest.json.sig'), feed.signature);
console.log(`feed ${feed.manifest.feed_version}: ${advisories.length} guarda advisories, ${mal.length} OpenSSF records, ${feed.files.size} shards -> ${values.out}`);
