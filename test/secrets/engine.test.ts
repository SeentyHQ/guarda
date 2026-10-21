import { describe, expect, it } from 'vitest';
import { scanSecrets } from '../../src/secrets/engine.js';
import { redact } from '../../src/secrets/redact.js';

describe('redact', () => {
  it('keeps 4 + 2 characters for long values and never shows a short value whole', () => {
    expect(redact('AKIAIOSFODNN7EXAMPLE')).toBe('AKIA…(20 chars)…LE');
    expect(redact('abcdefg')).toBe('ab…(7 chars)');
  });
});

describe('scanSecrets', () => {
  it('finds a token with line number and redacted value and downgrades gitignored files', () => {
    const files = [
      { path: 'src/config.ts', content: 'const x = 1;\nconst key = "AKIAIOSFODNN7EXAMPLE";\n', gitignored: false },
      { path: '.env', content: 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n', gitignored: true },
    ];
    const r = scanSecrets(files);
    expect(r).toEqual([
      { ruleId: 'aws-access-key-id', title: 'AWS access key ID', severity: 'high', path: 'src/config.ts', line: 2, redacted: 'AKIA…(20 chars)…LE', gitignored: false },
      { ruleId: 'aws-access-key-id', title: 'AWS access key ID', severity: 'medium', path: '.env', line: 1, redacted: 'AKIA…(20 chars)…LE', gitignored: true },
    ]);
  });
  it('flags high-entropy .env values and ignores low-entropy ones', () => {
    const r = scanSecrets([{ path: '.env.local', content: 'API_SECRET=Zx9Qp2Lm7Vb4Ns8Rt1Yw6Kd3Fh5Jg0Ca\nNAME=aaaaaaaaaaaaaaaaaaaaaaaa\nURL=http://localhost:3000/some/path\n', gitignored: false }]);
    expect(r.map((f) => [f.ruleId, f.line])).toEqual([['generic-high-entropy-env', 1]]);
    expect(r[0]!.entropy).toBeGreaterThan(4);
  });
  it('skips files without any rule keyword quickly and dedupes the same value on one line', () => {
    expect(scanSecrets([{ path: 'a.md', content: 'nothing here', gitignored: false }])).toEqual([]);
    expect(scanSecrets([{ path: 'a.ts', content: 'ghp_' + 'A'.repeat(36) + ' ghp_' + 'A'.repeat(36), gitignored: false }])).toHaveLength(1);
  });
});
