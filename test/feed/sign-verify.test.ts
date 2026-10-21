import { describe, expect, it } from 'vitest';
import { canonicalize, sha256Hex } from '../../src/feed/canonical.js';
import { generateKeyPair, signBytes } from '../../src/feed/sign.js';
import { verifyManifest, verifyShard } from '../../src/feed/verify.js';

const manifest = { schema_version: '1.0.0', feed_version: 3, generated_at: '2026-10-09T00:00:00Z', expires_at: '2026-10-16T00:00:00Z', min_cli_version: '0.1.0', sources: { guarda: { snapshot: '2026-10-09T00:00:00Z', licence: 'CC-BY-SA-4.0' } }, shards: [] };

describe('canonicalize', () => {
  it('sorts keys recursively and strips whitespace', () => {
    expect(canonicalize({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: 'x' } })).toBe('{"a":{"c":"x","d":[3,{"y":2,"z":1}]},"b":1}');
  });
});

describe('sign and verify', () => {
  const k1 = generateKeyPair(); const k2 = generateKeyPair();
  const bytes = Buffer.from(canonicalize(manifest));
  it('round-trips with any of the pinned keys and reports which one', () => {
    const sig = signBytes(bytes, k2.privateKeyPem);
    const r = verifyManifest(bytes, sig, [k1.publicKeyPem, k2.publicKeyPem]);
    expect(r.ok).toBe(true); if (r.ok) { expect(r.keyId).toBe(k2.keyId); expect(r.manifest.feed_version).toBe(3); }
  });
  it('rejects a tampered byte, a wrong key, and a manifest that fails the schema', () => {
    const sig = signBytes(bytes, k1.privateKeyPem);
    const tampered = Buffer.from(canonicalize({ ...manifest, feed_version: 4 }));
    expect(verifyManifest(tampered, sig, [k1.publicKeyPem])).toEqual({ ok: false, reason: 'signature does not match any pinned key' });
    expect(verifyManifest(bytes, sig, [k2.publicKeyPem]).ok).toBe(false);
    const bad = Buffer.from(canonicalize({ hello: 'world' }));
    expect(verifyManifest(bad, signBytes(bad, k1.privateKeyPem), [k1.publicKeyPem]).ok).toBe(false);
  });
  it('verifies a shard by hash and schema', () => {
    const shard = Buffer.from(JSON.stringify([{ id: 'GUARDA-1', modified: 'x', summary: 's', affected: [] }]));
    expect(verifyShard(shard, sha256Hex(shard)).ok).toBe(true);
    expect(verifyShard(shard, 'ff'.repeat(32))).toEqual({ ok: false, reason: 'shard hash mismatch' });
    expect(verifyShard(Buffer.from('[{"id":1}]'), sha256Hex('[{"id":1}]')).ok).toBe(false);
  });
});
