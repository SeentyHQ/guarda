import type { Report } from '../types.js';
const sortKeys = (v: unknown): unknown => Array.isArray(v) ? v.map(sortKeys) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v as object).sort().map((k) => [k, sortKeys((v as Record<string, unknown>)[k])])) : v;
export function formatJson(report: Report): string { return JSON.stringify(sortKeys(report), null, 2) + '\n'; }
