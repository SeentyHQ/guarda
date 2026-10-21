import { createHash } from 'node:crypto';
export function canonicalize(value: unknown): string {
  const sort = (v: unknown): unknown => Array.isArray(v) ? v.map(sort) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v as object).sort().map((k) => [k, sort((v as Record<string, unknown>)[k])])) : v;
  return JSON.stringify(sort(value));
}
export function sha256Hex(bytes: Uint8Array | string): string { return createHash('sha256').update(bytes).digest('hex'); }
