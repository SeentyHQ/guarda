#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve, join } from 'node:path';
import { homedir } from 'node:os';
import { Command, CommanderError } from 'commander';
import { PINNED_PUBLIC_KEYS } from './client/keys.js';
import { FeedError, loadFeed, type LoadedFeed } from './client/feed-client.js';
import { formatFeedStatus, readFeedStatus } from './client/feed-status.js';
import { resolveSettings, type Settings } from './config.js';
import { collectInventory } from './inventory/index.js';
import { formatJson } from './report/json.js';
import { formatPretty } from './report/pretty.js';
import { formatSarif } from './report/sarif.js';
import { ENGINE_VERSION, scan } from './scan.js';
import { nodeFs } from './adapters.js';
import { SEVERITY_ORDER, type Report, type Severity } from './types.js';
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export interface Io { stdout: (s: string) => void; stderr: (s: string) => void; env: NodeJS.ProcessEnv; cwd: string; isTTY: boolean }
const FOOTER = 'Guarda checks lockfiles and workflows against curated supply-chain advisories. Report a compromised package: guarda report <pkg@ver>';

async function readJson(path: string): Promise<Partial<Settings> | null> { try { return JSON.parse(await readFile(path, 'utf8')) as Partial<Settings>; } catch { return null; } }
const publicKeys = (env: NodeJS.ProcessEnv) => (env.GUARDA_FEED_PUBKEY ? [env.GUARDA_FEED_PUBKEY.replace(/\\n/g, '\n'), ...PINNED_PUBLIC_KEYS] : PINNED_PUBLIC_KEYS);
function atOrAbove(a: Severity, b: Severity | 'none'): boolean { return b !== 'none' && SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b); }

interface CommonOpts { feed?: string; offline?: boolean; cacheDir?: string; tips: boolean }
interface ScanOpts extends CommonOpts { json?: boolean; sarif?: boolean; failOn?: string; strict?: boolean; maxFeedAge?: string; only?: string; staged?: boolean; color: boolean }

/** commander option names -> the flag names resolveSettings understands. */
function flagsOf(o: ScanOpts | CommonOpts): Record<string, string | boolean | undefined> {
  const s = o as ScanOpts;
  return { feed: s.feed, offline: s.offline, 'cache-dir': s.cacheDir, 'no-tips': s.tips === false ? true : undefined, 'fail-on': s.failOn, strict: s.strict, 'max-feed-age': s.maxFeedAge, only: s.only };
}

async function settingsFor(root: string, opts: CommonOpts, io: Io, machine = false): Promise<Settings> {
  const notice = (m: string) => { if (!machine) io.stderr(`notice: ${m}\n`); };
  return resolveSettings(flagsOf(opts), io.env, await readJson(join(root, '.guarda.json')), await readJson(join(io.env.HOME ?? homedir(), '.guarda', 'config.json')), notice);
}

/** One cache per feed location, so a dev feed never pins the rollback state of the production one. */
const cacheFor = (settings: Settings) => join(settings.cacheDir, createHash('sha256').update(settings.feedUrl).digest('hex').slice(0, 12));

async function feedFor(settings: Settings, io: Io, opts: { ecosystems?: string[]; forceUpdate?: boolean; machine: boolean }): Promise<LoadedFeed> {
  const warn = (m: string) => { if (!opts.machine) io.stderr(`warning: ${m}\n`); };
  return loadFeed({ source: settings.feedUrl, cacheDir: cacheFor(settings), publicKeys: publicKeys(io.env), offline: settings.offline && !opts.forceUpdate,
    userAgent: settings.doNotTrack ? 'guarda' : `guarda/${ENGINE_VERSION}${io.env.CI ? ' ci' : ''}`, ...(opts.ecosystems ? { ecosystems: opts.ecosystems } : {}), warn });
}

function feedFailure(err: unknown, io: Io): number { const e = err as FeedError; io.stderr(`feed error${e.code ? ` (${e.code})` : ''}: ${e.message}\n`); return 2; }

async function runScan(path: string | undefined, opts: ScanOpts, io: Io): Promise<number> {
  const root = resolve(io.cwd, path ?? '.');
  const machine = Boolean(opts.json || opts.sarif);
  let settings: Settings; try { settings = await settingsFor(root, opts, io, machine); } catch (err) { io.stderr(`${(err as Error).message}\n`); return 2; }
  let inventory: Awaited<ReturnType<typeof collectInventory>>;
  try { inventory = await collectInventory(root, nodeFs); } catch (err) { io.stderr(`inventory error: ${(err as Error).message}\n`); return 2; }
  let loaded: LoadedFeed;
  try { loaded = await feedFor(settings, io, { ecosystems: [...new Set([...inventory.packages.map((p) => p.ecosystem), ...(inventory.runtimes.length ? ['software'] : []), ...(inventory.images.length ? ['Docker'] : [])])], machine }); }
  catch (err) { return feedFailure(err, io); }
  let report: Report;
  try { report = await scan(root, { feed: loaded.feed, feedStatus: loaded.status, inventory, ignore: settings.ignore, ...(settings.only ? { only: settings.only } : {}), ...(opts.staged ? { staged: true } : {}) }); }
  catch (err) { io.stderr(`scan error: ${(err as Error).message}\n`); return 2; }
  if (opts.json) io.stdout(formatJson(report));
  else if (opts.sarif) io.stdout(formatSarif(report));
  else io.stdout(formatPretty(report, { color: io.isTTY && opts.color && !io.env.NO_COLOR, ...(settings.noTips ? {} : { footer: FOOTER }) }));
  if (report.coverage.scannedFiles === 0 && report.coverage.skipped.length === 0) return 3;
  const ageDays = (Date.now() - Date.parse(loaded.status.generatedAt)) / 86_400_000;
  if (settings.strict && (!report.coverage.complete || loaded.status.stale || ageDays > settings.maxFeedAgeDays)) {
    io.stderr(`strict: ${!report.coverage.complete ? 'coverage incomplete' : 'feed stale or older than the allowed age'}\n`);
    return 2;
  }
  const findings = [...report.matches.map((m) => m.severity), ...report.secrets.map((s) => s.severity)];
  return findings.some((s) => atOrAbove(s, settings.failOn)) ? 1 : 0;
}

async function runFeed(opts: CommonOpts & { update?: boolean; verify?: boolean }, io: Io): Promise<number> {
  let settings: Settings; try { settings = await settingsFor(io.cwd, opts, io); } catch (err) { io.stderr(`${(err as Error).message}\n`); return 2; }
  let loaded: LoadedFeed; try { loaded = await feedFor(settings, io, { forceUpdate: Boolean(opts.update), machine: false }); } catch (err) { return feedFailure(err, io); }
  const s = loaded.status;
  if (opts.verify) io.stdout(`signature ok, key ${loaded.keyId}\n`);
  io.stdout(`feed version ${s.version}, generated ${s.generatedAt}, expires ${s.expiresAt}${s.stale ? ' (STALE)' : ''}, origin ${s.origin}\n`);
  for (const [k, v] of Object.entries(s.sources)) io.stdout(`  ${k}: snapshot ${v?.snapshot}, licence ${v?.licence}${v?.attribution ? `, ${v.attribution}` : ''}\n`);
  io.stdout(`  advisories: ${loaded.feed.advisories.length}\n`);
  // The publisher's own summary (status.json) is informational and optional: offline runs and feeds without it print nothing more.
  if (!settings.offline || opts.update) {
    const status = await readFeedStatus({ source: settings.feedUrl, userAgent: settings.doNotTrack ? 'guarda' : `guarda/${ENGINE_VERSION}` });
    if (status) for (const line of formatFeedStatus(status)) io.stdout(`${line}\n`);
  }
  return 0;
}

async function runExplain(id: string, opts: CommonOpts, io: Io): Promise<number> {
  let settings: Settings; try { settings = await settingsFor(io.cwd, opts, io); } catch (err) { io.stderr(`${(err as Error).message}\n`); return 2; }
  let loaded: LoadedFeed; try { loaded = await feedFor(settings, io, { machine: false }); } catch (err) { return feedFailure(err, io); }
  const hit = loaded.feed.advisories.find((a) => a.advisory.id === id);
  if (!hit) { io.stderr(`advisory ${id} is not in the feed (${loaded.status.origin}, version ${loaded.status.version})\n`); return 2; }
  io.stdout(JSON.stringify(hit.advisory, null, 2) + '\n'); return 0;
}

function runReport(spec: string, io: Io): number {
  const url = `https://github.com/seentyhq/guarda/issues/new?template=report-compromised-package.yml&title=${encodeURIComponent(`Compromised package: ${spec}`)}&package=${encodeURIComponent(spec)}`;
  io.stdout(`${url}\n`); return 0;
}

export async function main(argv: string[], io: Io): Promise<number> {
  let exit = 0;
  const program = new Command('guarda')
    .description('Checks lockfiles and CI workflows against curated supply-chain advisories and finds secrets. Nothing about your project leaves your machine; see NETWORK.md.')
    .version(ENGINE_VERSION, '-v, --version')
    .exitOverride()
    .configureOutput({ writeOut: io.stdout, writeErr: io.stderr })
    .addHelpText('after', '\nExit codes: 0 nothing found and complete; 1 findings at or above --fail-on; 2 error, or incomplete/stale with --strict; 3 nothing to scan.');
  const common = (c: Command) => c
    .option('--feed <url|dir>', 'feed location (also GUARDA_FEED_URL)')
    .option('--offline', 'use the cached feed only, no network')
    .option('--cache-dir <dir>', 'cache directory (default ~/.guarda/cache)')
    .option('--no-tips', 'suppress the footer line (also DO_NOT_TRACK=1)');
  common(program.command('scan [path]', { isDefault: true }).description('scan a directory (default .)'))
    .option('--json', 'JSON report').option('--sarif', 'SARIF 2.1.0 report')
    .option('--fail-on <level>', 'exit 1 at or above: none|info|low|medium|high|critical (default low)')
    .option('--strict', 'exit 2 on incomplete coverage or a stale feed')
    .option('--max-feed-age <days>', 'with --strict: fail when the feed is older (default 7)')
    .option('--only <list>', 'packages,actions,secrets')
    .option('--staged', 'scan secrets in the git index instead of the working tree')
    .option('--no-color', 'disable colour')
    .action(async (path: string | undefined, opts: ScanOpts) => { exit = await runScan(path, opts, io); });
  common(program.command('feed').description('show the cached feed'))
    .option('--update', 'fetch now even with --offline in config').option('--verify', 'print the signing key id')
    .action(async (opts: CommonOpts & { update?: boolean; verify?: boolean }) => { exit = await runFeed(opts, io); });
  common(program.command('explain <id>').description('print one advisory from the cached feed'))
    .action(async (id: string, opts: CommonOpts) => { exit = await runExplain(id, opts, io); });
  program.command('report <package@version>').description('print the URL of a pre-filled issue to report a compromised package')
    .action((spec: string) => { exit = runReport(spec, io); });
  try { await program.parseAsync(argv, { from: 'user' }); }
  catch (err) {
    if (err instanceof CommanderError) return err.exitCode === 0 ? 0 : 2;   // help/version exit 0; usage errors exit 2
    throw err;
  }
  return exit;
}

// Direct run: node dist/bin.js, tsx src/bin.ts, or the .bin/guarda symlink npm creates (argv[1] is the
// symlink, so compare real paths; a bare suffix check made the published 0.1.0 exit silently under npx).
const isDirectRun = (() => {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try { return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url)); } catch { return /[\\/]bin\.(js|ts)$/.test(entry); }
})();
if (isDirectRun) {
  main(process.argv.slice(2), { stdout: (s) => process.stdout.write(s), stderr: (s) => process.stderr.write(s), env: process.env, cwd: process.cwd(), isTTY: Boolean(process.stdout.isTTY) })
    .then((code) => { process.exitCode = code; });
}
