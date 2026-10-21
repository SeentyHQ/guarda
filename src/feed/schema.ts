import { z } from 'zod';
import type { Advisory, Manifest } from '../types.js';

const Severity = z.enum(['info', 'low', 'medium', 'high', 'critical']);
const Event = z.strictObject({ introduced: z.string().optional(), fixed: z.string().optional(), last_affected: z.string().optional() });
const SeentyFields = z.object({
  severity: Severity.optional(), source_label: z.string().optional(), kind: z.string().optional(),
  window: z.object({ from: z.string().optional(), to: z.string().optional() }).optional(),
  remediation: z.string().optional(), exposed_refs: z.array(z.string()).optional(), credits: z.array(z.string()).optional(),
});
export const AdvisorySchema = z.object({
  id: z.string().min(1), modified: z.string(), published: z.string().optional(), withdrawn: z.string().optional(),
  summary: z.string(), details: z.string().optional(),
  affected: z.array(z.object({
    package: z.object({ ecosystem: z.string(), name: z.string().min(1), purl: z.string().optional() }),
    versions: z.array(z.string()).optional(),
    ranges: z.array(z.object({ type: z.enum(['SEMVER', 'ECOSYSTEM']), events: z.array(Event).min(1) })).optional(),
  })),
  references: z.array(z.object({ type: z.string(), url: z.string() })).optional(),
  database_specific: z.looseObject({ seenty: SeentyFields.optional() }).optional(),
}) as unknown as z.ZodType<Advisory>;
export const ShardSchema = z.array(AdvisorySchema);
const SourceInfo = z.object({ snapshot: z.string(), licence: z.string(), attribution: z.string().optional(), commit: z.string().optional() });
export const ManifestSchema = z.object({
  schema_version: z.string(), feed_version: z.number().int().nonnegative(), generated_at: z.string(), expires_at: z.string(), min_cli_version: z.string(),
  sources: z.object({ guarda: SourceInfo.optional(), 'openssf-mal': SourceInfo.optional() }),
  shards: z.array(z.object({ source: z.enum(['guarda', 'openssf-mal']), ecosystem: z.string(), url: z.string(), sha256: z.string().length(64), bytes: z.number().int() })),
}) as unknown as z.ZodType<Manifest>;
