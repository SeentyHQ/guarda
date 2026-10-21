import { canonicalEcosystem } from '../ecosystem.js';
import { purl } from '../inventory/types.js';
import type { Advisory, Manifest, Severity, ShardEntry, SourceInfo } from '../types.js';
import { canonicalize, sha256Hex } from './canonical.js';
import { signBytes } from './sign.js';
import { TokenError, tokensToAffected } from './tokens.js';

export interface AdvisoryInput {
  id?: string; title: string; summary?: string | null; severity: Severity; source_label?: string | null; reference_urls?: string[];
  published_at?: string; updated_at?: string; kind?: string; window?: { from?: string; to?: string }; remediation?: string; credits?: string[];
  packages: { ecosystem: string; package_name: string; affected_versions: string; exposed_refs?: string[] }[];
}

export function translateAdvisory(input: AdvisoryInput, index: number): Advisory {
  const year = (input.published_at ?? new Date().toISOString()).slice(0, 4);
  const exposed = input.packages.flatMap((p) => p.exposed_refs ?? []);
  const affected = input.packages.map((p) => {
    const eco = canonicalEcosystem(p.ecosystem); if (!eco) throw new TokenError(p.affected_versions, `unknown ecosystem ${p.ecosystem}`);
    const { versions, ranges } = tokensToAffected(eco, p.affected_versions);
    return { package: { ecosystem: eco, name: p.package_name, purl: purl(eco, p.package_name) }, versions, ranges };
  });
  const seenty: NonNullable<NonNullable<Advisory['database_specific']>['seenty']> = { severity: input.severity };
  if (input.source_label) seenty.source_label = input.source_label;
  if (input.kind) seenty.kind = input.kind;
  if (input.window) seenty.window = input.window;
  if (input.remediation) seenty.remediation = input.remediation;
  if (exposed.length) seenty.exposed_refs = exposed;
  if (input.credits?.length) seenty.credits = input.credits;
  const advisory: Advisory = {
    id: input.id ?? `GUARDA-${year}-${String(index).padStart(4, '0')}`,
    modified: input.updated_at ?? input.published_at ?? new Date().toISOString(),
    summary: input.title, affected, database_specific: { seenty },
    references: (input.reference_urls ?? []).map((url) => ({ type: 'REPORT', url })),
  };
  if (input.published_at) advisory.published = input.published_at;
  if (input.summary) advisory.details = input.summary;
  return advisory;
}

export interface BuildInput { advisories: AdvisoryInput[]; mal: Advisory[]; malMeta?: { snapshot: string; commit?: string }; feedVersion: number; now: Date; privateKeyPem: string; expiresInDays?: number; minCliVersion?: string }

export function buildFeed(input: BuildInput): { manifest: Manifest; manifestBytes: Buffer; signature: string; files: Map<string, Buffer> } {
  const files = new Map<string, Buffer>(); const shards: ShardEntry[] = [];
  const addShard = (source: ShardEntry['source'], ecosystem: string, advisories: Advisory[]) => {
    const bytes = Buffer.from(canonicalize(advisories)); const sha256 = sha256Hex(bytes);
    const url = `${source}${ecosystem === '*' ? '' : '-' + ecosystem.toLowerCase()}.${sha256}.json`;
    files.set(url, bytes); shards.push({ source, ecosystem, url, sha256, bytes: bytes.byteLength });
  };
  addShard('guarda', '*', input.advisories.map((a, i) => translateAdvisory(a, i + 1)));
  const byEco = new Map<string, Advisory[]>();
  for (const m of input.mal) for (const eco of new Set(m.affected.map((a) => canonicalEcosystem(a.package.ecosystem) ?? a.package.ecosystem))) { const l = byEco.get(eco) ?? []; l.push(m); byEco.set(eco, l); }
  for (const [eco, list] of [...byEco.entries()].sort()) addShard('openssf-mal', eco, list);
  const nowIso = input.now.toISOString();
  const sources: Partial<Record<'guarda' | 'openssf-mal', SourceInfo>> = { guarda: { snapshot: nowIso, licence: 'CC-BY-SA-4.0' } };
  if (input.mal.length) sources['openssf-mal'] = { snapshot: input.malMeta?.snapshot ?? nowIso, licence: 'Apache-2.0', attribution: 'OpenSSF Malicious Packages (https://github.com/ossf/malicious-packages)', ...(input.malMeta?.commit ? { commit: input.malMeta.commit } : {}) };
  const manifest: Manifest = {
    schema_version: '1.0.0', feed_version: input.feedVersion, generated_at: nowIso,
    expires_at: new Date(input.now.getTime() + (input.expiresInDays ?? 7) * 86_400_000).toISOString(),
    min_cli_version: input.minCliVersion ?? '0.1.0', sources, shards,
  };
  const manifestBytes = Buffer.from(canonicalize(manifest));
  return { manifest, manifestBytes, signature: signBytes(manifestBytes, input.privateKeyPem), files };
}
