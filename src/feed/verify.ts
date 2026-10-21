import { createPublicKey, verify } from 'node:crypto';
import type { Advisory, Manifest } from '../types.js';
import { sha256Hex } from './canonical.js';
import { ManifestSchema, ShardSchema } from './schema.js';
import { keyIdOf } from './sign.js';

export function verifyManifest(bytes: Uint8Array, signatureB64: string, publicKeysPem: string[]): { ok: true; keyId: string; manifest: Manifest } | { ok: false; reason: string } {
  const sig = Buffer.from(signatureB64.trim(), 'base64');
  if (sig.length === 0) return { ok: false, reason: 'signature is empty' };
  const key = publicKeysPem.find((pem) => { try { return verify(null, bytes, createPublicKey(pem), sig); } catch { return false; } });
  if (!key) return { ok: false, reason: 'signature does not match any pinned key' };
  let parsed: unknown; try { parsed = JSON.parse(Buffer.from(bytes).toString('utf8')); } catch { return { ok: false, reason: 'manifest is not JSON' }; }
  const r = ManifestSchema.safeParse(parsed);
  if (!r.success) return { ok: false, reason: `manifest schema: ${r.error.issues[0]?.message ?? 'invalid'}` };
  return { ok: true, keyId: keyIdOf(key), manifest: r.data };
}

export function verifyShard(bytes: Uint8Array, expectedSha256: string): { ok: true; advisories: Advisory[] } | { ok: false; reason: string } {
  if (sha256Hex(bytes) !== expectedSha256) return { ok: false, reason: 'shard hash mismatch' };
  let parsed: unknown; try { parsed = JSON.parse(Buffer.from(bytes).toString('utf8')); } catch { return { ok: false, reason: 'shard is not JSON' }; }
  const r = ShardSchema.safeParse(parsed);
  if (!r.success) return { ok: false, reason: `shard schema: ${r.error.issues[0]?.path.join('.') ?? ''} ${r.error.issues[0]?.message ?? 'invalid'}` };
  return { ok: true, advisories: r.data };
}
