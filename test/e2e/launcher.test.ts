import { spawnSync } from 'node:child_process';
import { mkdtempSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const pkgRoot = new URL('../../', import.meta.url).pathname;
const bin = join(pkgRoot, 'dist/bin.js');

describe('launcher (built dist/bin.js)', () => {
  it('runs when invoked directly', () => {
    const r = spawnSync(process.execPath, [bin, '--version'], { encoding: 'utf8' });
    expect(r.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });
  it('runs when invoked through a .bin symlink named guarda, as npm installs it', () => {
    const dir = mkdtempSync(join(tmpdir(), 'guarda-bin-'));
    const link = join(dir, 'guarda');
    symlinkSync(bin, link);
    const r = spawnSync(process.execPath, [link, '--version'], { encoding: 'utf8' });
    expect(r.status).toBe(0);
    expect(r.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });
});
