import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { main, type Io } from '../src/bin.js';

const io = (): Io & { out: string[]; err: string[] } => { const out: string[] = []; const err: string[] = []; return { out, err, stdout: (s) => out.push(s), stderr: (s) => err.push(s), env: { HOME: '/nonexistent' }, cwd: mkdtempSync(join(tmpdir(), 'guarda-bin-')), isTTY: false }; };

describe('main', () => {
  it('prints help and version', async () => {
    const a = io(); expect(await main(['--help'], a)).toBe(0); expect(a.out.join('')).toContain('Usage: guarda');
    const b = io(); expect(await main(['--version'], b)).toBe(0); expect(b.out.join('')).toMatch(/^\d+\.\d+\.\d+/);
  });
  it('rejects unknown flags with exit 2', async () => {
    const a = io(); expect(await main(['--bogus'], a)).toBe(2); expect(a.err.join('')).toContain("unknown option '--bogus'");
  });
  it('report prints a pre-filled issue url without network', async () => {
    const a = io(); expect(await main(['report', 'npm:keyv@5.7.2'], a)).toBe(0);
    expect(a.out.join('')).toContain('issues/new?template=report-compromised-package.yml');
  });
  it('fails with exit 2 offline without a cache', async () => {
    const a = io(); a.env.GUARDA_CACHE_DIR = '/nonexistent/cache';
    expect(await main(['.', '--offline'], a)).toBe(2); expect(a.err.join('')).toContain('offline-no-cache');
  });
});
