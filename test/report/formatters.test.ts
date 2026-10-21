import { describe, expect, it } from 'vitest';
import { formatJson } from '../../src/report/json.js';
import { formatPretty } from '../../src/report/pretty.js';
import { formatSarif } from '../../src/report/sarif.js';
import type { Report } from '../../src/types.js';

const report: Report = {
  engineVersion: '0.1.0',
  matches: [{ source: 'guarda', severity: 'critical', clause: '= 5.7.2', advisory: { id: 'GUARDA-2026-0001', modified: 'x', summary: 'keyv poisoned', affected: [], database_specific: { seenty: { remediation: 'pin 5.7.1' } } },
    target: { kind: 'package', package: { ecosystem: 'npm', name: 'keyv', version: '5.7.2', purl: 'pkg:npm/keyv@5.7.2', lockfile: 'package-lock.json' } } },
  { source: 'guarda', severity: 'critical', clause: 'ref 0.28.0 exposed between a and b', advisory: { id: 'GUARDA-2026-0002', modified: 'x', summary: 'trivy-action hijacked', affected: [] },
    target: { kind: 'action', exposure: 'exposed-ref', action: { repo: 'aquasecurity/trivy-action', ref: '0.28.0', refKind: 'tag', workflow: '.github/workflows/ci.yml', line: 9 } } }],
  secrets: [{ ruleId: 'aws-access-key-id', title: 'AWS access key ID', severity: 'high', path: 'src/config.ts', line: 2, redacted: 'AKIA…(20 chars)…LE', gitignored: false }],
  coverage: { scannedFiles: 3, skipped: [{ path: 'legacy/bun.lockb', reason: 'unsupported-format', detail: 'binary lockfile' }], complete: false, inventory: { packages: 2, lockfiles: 1, declared: 0, manifests: 0, actions: 1, workflows: 1, runtimes: 0, runtimeFiles: 0, images: 0, imageFiles: 0 },
    feed: { version: 7, generatedAt: '2026-10-09T14:00:00Z', expiresAt: '2026-10-16T14:00:00Z', stale: false, origin: 'cache', sources: { guarda: { snapshot: '2026-10-09T13:58:00Z', licence: 'CC-BY-SA-4.0' } } } },
};

describe('formatters', () => {
  it('pretty uses the Guarda layout: status pill, score bar, at-a-glance table, advisories, secrets, next moves', () => {
    const out = formatPretty(report, { color: false, footer: 'footer line' });
    expect(out).toContain('● EXPOSED');
    expect(out).toMatch(/Guarda score\s+[▰▱]{10}\s+\d+\/100\s+\([A-F]\)/);
    expect(out).toContain('supply chain');
    expect(out).toContain('ADVISORIES');
    expect(out).toContain('SECRETS');
    expect(out).toContain('NEXT MOVES');
    expect(out).toContain('GUARDA-2026-0001');
    expect(out).toContain('keyv@5.7.2');
    expect(out).toContain('package-lock.json');
    expect(out).toContain('pin 5.7.1');
    expect(out).toContain('ci.yml:9');
    expect(out).toContain('check your run logs');
    expect(out).toContain('AKIA…(20 chars)…LE');
    expect(out).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(out).toContain('1 skipped');
    expect(out).toContain('feed #7');
    expect(out).toContain('incomplete');
    expect(out).not.toMatch(/Findings|Sections|Action Items/);
    expect(out.trimEnd().endsWith('footer line')).toBe(true);
    expect(formatPretty(report, { color: false })).not.toContain('footer line');
  });
  it('scores the repository and labels a clean complete run CLEAN with 100/100', () => {
    const clean = formatPretty({ ...report, matches: [], secrets: [], coverage: { ...report.coverage, complete: true, skipped: [] } }, { color: false });
    expect(clean).toContain('● CLEAN');
    expect(clean).toContain('100/100  (A)');
    expect(clean).not.toContain('NEXT MOVES');
    const one = formatPretty({ ...report, matches: [report.matches[0]!], secrets: [], coverage: { ...report.coverage, complete: true, skipped: [] } }, { color: false });
    expect(one).toContain('75/100  (B)');
    expect(formatPretty(report, { color: false })).toContain('40/100  (D)');
  });
  it('emits 256-colour neon escapes when colour is on', () => {
    const out = formatPretty(report, { color: true });
    expect(out).toContain('\x1b[38;5;');
    expect(out).toContain('\x1b[0m');
  });
  it('json is stable and parseable', () => {
    const parsed = JSON.parse(formatJson(report)) as Report;
    expect(parsed.matches[0]!.advisory.id).toBe('GUARDA-2026-0001');
    expect(Object.keys(parsed)).toEqual(['coverage', 'engineVersion', 'matches', 'secrets']);
  });
  it('sarif has one run with rules and located results', () => {
    const sarif = JSON.parse(formatSarif(report)) as { version: string; runs: { tool: { driver: { name: string; rules: { id: string }[] } }; results: { ruleId: string; level: string; locations: { physicalLocation: { artifactLocation: { uri: string }; region?: { startLine: number } } }[] }[] }[] };
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]!.tool.driver.name).toBe('guarda');
    expect(sarif.runs[0]!.tool.driver.rules.map((r) => r.id).sort()).toEqual(['GUARDA-2026-0001', 'GUARDA-2026-0002', 'aws-access-key-id']);
    expect(sarif.runs[0]!.results.map((r) => [r.ruleId, r.level, r.locations[0]!.physicalLocation.artifactLocation.uri, r.locations[0]!.physicalLocation.region?.startLine])).toEqual([
      ['GUARDA-2026-0001', 'error', 'package-lock.json', undefined],
      ['GUARDA-2026-0002', 'error', '.github/workflows/ci.yml', 9],
      ['aws-access-key-id', 'error', 'src/config.ts', 2],
    ]);
  });
});

describe('pretty report: what was looked at', () => {
  const base = { matches: [], secrets: [], engineVersion: '0.1.2', coverage: { scannedFiles: 1, skipped: [], complete: true, feed: { version: 3, generatedAt: '2026-10-10T22:07:38.560Z', expiresAt: '2026-10-17T22:07:38.560Z', stale: false, origin: 'network' as const, sources: {}, inventory: { packages: 2, lockfiles: 1, declared: 0, manifests: 0, actions: 1, workflows: 1, runtimes: 0, runtimeFiles: 0, images: 0, imageFiles: 0 } } } };
  it('says how many packages, lockfiles, actions and workflows were checked', async () => {
    const { formatPretty } = await import('../../src/report/pretty.js');
    const out = formatPretty({ ...base, coverage: { ...base.coverage, inventory: { packages: 69, lockfiles: 1, declared: 0, manifests: 0, actions: 3, workflows: 2, runtimes: 0, runtimeFiles: 0, images: 0, imageFiles: 0 } } }, { color: false });
    expect(out).toMatch(/supply chain\s+clean\s+69 packages · 1 lockfile/);
    expect(out).toMatch(/workflows\s+clean\s+3 uses · 2 workflows/);
  });
  it('says plainly when there was nothing to check', async () => {
    const { formatPretty } = await import('../../src/report/pretty.js');
    const out = formatPretty({ ...base, coverage: { ...base.coverage, inventory: { packages: 0, lockfiles: 0, declared: 0, manifests: 0, actions: 0, workflows: 0, runtimes: 0, runtimeFiles: 0, images: 0, imageFiles: 0 } } }, { color: false });
    expect(out).toMatch(/supply chain\s+no lockfile\s+/);
    expect(out).toMatch(/workflows\s+none found\s+/);
  });
});

describe('pretty report: package.json without a lockfile', () => {
  it('shows the declared dependencies, the range exposure and asks for a lockfile', async () => {
    const { formatPretty } = await import('../../src/report/pretty.js');
    const report: import('../../src/types.js').Report = {
      engineVersion: '0.1.3', secrets: [],
      matches: [{ advisory: { id: 'GUARDA-2026-0030', modified: 'x', summary: 'chalk poisoned', affected: [] }, source: 'guarda' as const, severity: 'high' as const, clause: 'range ^5.6.0 admits poisoned 5.6.1',
        target: { kind: 'declared' as const, exposure: 'range' as const, declared: { ecosystem: 'npm' as const, name: 'chalk', range: '^5.6.0', manifest: 'package.json', line: 7, lockfile: 'none' as const } } }],
      coverage: { scannedFiles: 1, complete: false, skipped: [{ path: 'package.json', reason: 'no-lockfile' as const, detail: 'transitive dependencies not checked; commit a lockfile' }],
        inventory: { packages: 0, lockfiles: 0, declared: 5, manifests: 1, actions: 0, workflows: 0, runtimes: 0, runtimeFiles: 0, images: 0, imageFiles: 0 },
        feed: { version: 3, generatedAt: '2026-10-10T22:07:38.560Z', expiresAt: '2026-10-17T22:07:38.560Z', stale: false, origin: 'network' as const, sources: {} } },
    };
    const out = formatPretty(report, { color: false });
    expect(out).toMatch(/supply chain\s+1 exposed\s+5 declared in package.json · no lockfile/);
    expect(out).toContain('chalk ^5.6.0');
    expect(out).toContain('package.json:7');
    expect(out).toContain('range ^5.6.0 admits poisoned 5.6.1');
    expect(out).toMatch(/Commit a lockfile/);
  });
});

describe('pretty report: counts are per package, not per advisory', () => {
  it('one pinned package and one range each matched by two advisories count once', async () => {
    const { formatPretty } = await import('../../src/report/pretty.js');
    const adv = (id: string) => ({ id, modified: 'x', summary: id, affected: [] });
    const pkg = { ecosystem: 'npm' as const, name: '@ctrl/tinycolor', version: '4.1.1', purl: 'pkg:npm/%40ctrl/tinycolor@4.1.1', lockfile: 'package.json', line: 13 };
    const dep = { ecosystem: 'npm' as const, name: 'chalk', range: '^5.6.0', manifest: 'package.json', line: 12, lockfile: 'none' as const };
    const report: import('../../src/types.js').Report = {
      engineVersion: '0.1.4', secrets: [],
      matches: [
        { advisory: adv('GUARDA-2026-0002'), source: 'guarda', severity: 'critical', clause: '= 4.1.1', target: { kind: 'package', package: pkg } },
        { advisory: adv('MAL-2025-47141'), source: 'openssf-mal', severity: 'high', clause: '= 4.1.1', target: { kind: 'package', package: pkg } },
        { advisory: adv('GUARDA-2026-0030'), source: 'guarda', severity: 'high', clause: 'range ^5.6.0 admits poisoned 5.6.1', target: { kind: 'declared', exposure: 'range', declared: dep } },
        { advisory: adv('MAL-2025-46969'), source: 'openssf-mal', severity: 'medium', clause: 'range ^5.6.0 admits poisoned 5.6.1', target: { kind: 'declared', exposure: 'range', declared: dep } },
      ],
      coverage: { scannedFiles: 1, complete: false, skipped: [{ path: 'package.json', reason: 'no-lockfile', detail: 'x' }], inventory: { packages: 1, lockfiles: 0, declared: 3, manifests: 1, actions: 0, workflows: 0, runtimes: 0, runtimeFiles: 0, images: 0, imageFiles: 0 },
        feed: { version: 3, generatedAt: '2026-10-10T22:07:38.560Z', expiresAt: '2026-10-17T22:07:38.560Z', stale: false, origin: 'network', sources: {} } },
    };
    const out = formatPretty(report, { color: false });
    expect(out).toMatch(/supply chain\s+1 hit\s/);
    expect(out).toContain('Replace the 1 poisoned version and');
    expect(out).toContain('Pin the 1 range that admits');
  });
});

describe('pretty report: lockfile that git ignores', () => {
  it('says the lockfile is gitignored instead of "no lockfile"', async () => {
    const { formatPretty } = await import('../../src/report/pretty.js');
    const report: import('../../src/types.js').Report = {
      engineVersion: '0.1.5', secrets: [], matches: [],
      coverage: { scannedFiles: 2, complete: false, skipped: [{ path: 'package-lock.json', reason: 'no-lockfile', detail: 'gitignored: CI resolves package.json ranges fresh' }],
        inventory: { packages: 71, lockfiles: 1, declared: 3, manifests: 1, actions: 0, workflows: 0, runtimes: 0, runtimeFiles: 0, images: 0, imageFiles: 0 },
        feed: { version: 3, generatedAt: '2026-10-10T22:07:38.560Z', expiresAt: '2026-10-17T22:07:38.560Z', stale: false, origin: 'network', sources: {} } },
    };
    const out = formatPretty(report, { color: false });
    expect(out).toMatch(/supply chain\s+clean\s+71 packages · 1 lockfile · 3 declared in package.json · lockfile gitignored/);
    expect(out).toContain('Commit the lockfile');
  });
});
