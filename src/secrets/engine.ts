import type { SecretFinding, Severity } from '../types.js';
import { SEVERITY_ORDER } from '../types.js';
import { shannonEntropy } from './entropy.js';
import { redact } from './redact.js';
import { RULES, type SecretRule } from './rules.js';

export interface SecretsInput { path: string; content: string; gitignored: boolean }

const ENV_FILE = /(^|\/)\.env(\..+)?$/;
const ENV_LINE = /^\s{0,16}(?:export\s{1,8})?([A-Z0-9_]{1,64})\s{0,8}=\s{0,8}["']?([^\s"'#]{20,1024})["']?\s{0,8}(?:#.{0,256})?$/;
const ENV_IGNORE_KEYS = /(URL|URI|HOST|PATH|DIR|NAME|ENV|MODE|REGION|PORT|VERSION)$/;

function downgrade(s: Severity): Severity { return SEVERITY_ORDER[Math.max(0, SEVERITY_ORDER.indexOf(s) - 1)]!; }

/** Newline offsets computed once per file; line numbers by binary search. */
function lineIndex(content: string): (index: number) => number {
  const starts = [0]; for (let i = 0; i < content.length; i++) if (content.charCodeAt(i) === 10) starts.push(i + 1);
  return (index) => { let lo = 0, hi = starts.length - 1; while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid]! <= index) lo = mid; else hi = mid - 1; } return lo + 1; };
}

function* matchesOf(rule: SecretRule, content: string, lower: string): Generator<{ value: string; index: number }> {
  const flags = rule.pattern.flags.replace('g', '').replace('y', '');
  if (rule.anchors && rule.anchors.length) {
    const sticky = new RegExp(rule.pattern.source, flags + 'y');
    const ci = flags.includes('i');
    const haystack = ci ? lower : content;
    const seen = new Set<number>();
    for (const anchor of rule.anchors) {
      const needle = ci ? anchor.toLowerCase() : anchor;
      let from = 0;
      for (;;) {
        const idx = haystack.indexOf(needle, from); if (idx === -1) break;
        from = idx + 1;
        if (seen.has(idx)) continue;
        sticky.lastIndex = idx;
        const m = sticky.exec(content);
        if (m && m.index === idx) { seen.add(idx); yield { value: m[1] ?? m[0], index: idx }; from = idx + m[0].length; continue; }
        if (rule.runClass) { rule.runClass.lastIndex = idx; const run = rule.runClass.exec(content); if (run && run.index === idx) from = idx + run[0].length; }
      }
    }
    return;
  }
  const re = new RegExp(rule.pattern.source, flags + 'g');
  for (const m of content.matchAll(re)) yield { value: m[1] ?? m[0], index: m.index ?? 0 };
}

export function scanSecrets(files: SecretsInput[], rules: SecretRule[] = RULES): SecretFinding[] {
  const out: SecretFinding[] = [];
  for (const file of files) {
    const lower = file.content.toLowerCase();
    const lineOf = lineIndex(file.content);
    const seen = new Set<string>();
    for (const rule of rules) {
      if (!rule.keywords.some((k) => lower.includes(k.toLowerCase()))) continue;
      for (const { value, index } of matchesOf(rule, file.content, lower)) {
        if (rule.validate && !rule.validate(value)) continue;
        if (rule.entropyMin !== undefined && shannonEntropy(value) < rule.entropyMin) continue;
        const line = lineOf(index);
        const key = `${rule.id}\0${line}\0${value}`; if (seen.has(key)) continue; seen.add(key);
        out.push({ ruleId: rule.id, title: rule.title, severity: file.gitignored ? downgrade(rule.severity) : rule.severity, path: file.path, line, redacted: redact(value), gitignored: file.gitignored });
      }
    }
    if (ENV_FILE.test(file.path)) {
      const taken = new Set(out.filter((f) => f.path === file.path).map((f) => f.line));
      file.content.split('\n').forEach((text, i) => {
        if (text.length > 4096) return;
        const m = ENV_LINE.exec(text); if (!m) return;
        const key = m[1]!; const value = m[2]!;
        if (ENV_IGNORE_KEYS.test(key) || /^https?:\/\//.test(value)) return;
        const entropy = shannonEntropy(value); if (entropy <= 4.0) return;
        if (taken.has(i + 1)) return;
        out.push({ ruleId: 'generic-high-entropy-env', title: 'High-entropy value in env file', severity: file.gitignored ? 'info' : 'low', path: file.path, line: i + 1, redacted: redact(value), entropy, gitignored: file.gitignored });
      });
    }
  }
  return out;
}
