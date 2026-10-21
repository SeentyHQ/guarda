import type { Match, Report, Severity } from '../types.js';

/** Neon palette (256 colours). `color: false` strips every escape. */
const P = { cyan: 51, red: 203, green: 118, yellow: 226, orange: 208, teal: 44, grey: 245, dim: 240, white: 255 } as const;
type Tone = keyof typeof P;
const sevTone: Record<Severity, Tone> = { critical: 'red', high: 'orange', medium: 'yellow', low: 'teal', info: 'grey' };
const sevLabel: Record<Severity, string> = { critical: 'CRIT', high: 'HIGH', medium: 'MED ', low: 'LOW ', info: 'INFO' };
const WEIGHT: Record<Severity, number> = { critical: 25, high: 10, medium: 4, low: 1, info: 1 };
/** Untrusted strings (paths, names, refs, advisory text) never carry terminal control characters into the output. */
const sz = (s: string) => s.replace(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/g, '');

export function guardaScore(severities: Severity[], complete: boolean): { score: number; grade: string } {
  const score = Math.max(0, 100 - severities.reduce((acc, s) => acc + WEIGHT[s], 0));
  let grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  if (!complete && grade === 'A') grade = 'B';
  return { score, grade };
}

export function formatPretty(report: Report, opts: { color: boolean; footer?: string }): string {
  const c = (tone: Tone, s: string, bold = false) => (opts.color ? `${bold ? '\x1b[1m' : ''}\x1b[38;5;${P[tone]}m${s}\x1b[0m` : s);
  const bar = (tone: Tone) => c(tone, '┃');
  const L: string[] = [];
  const cov = report.coverage;
  const sevs = [...report.matches.map((m) => m.severity), ...report.secrets.map((s) => s.severity)];
  const n = (s: Severity) => sevs.filter((x) => x === s).length;
  const { score, grade } = guardaScore(sevs, cov.complete);
  const exposed = n('critical') + n('high') > 0;
  const status = exposed ? c('red', '● EXPOSED', true) : sevs.length || !cov.complete ? c('yellow', '● ATTENTION', true) : c('green', '● CLEAN', true);
  const filled = Math.round(score / 10);
  const barTone: Tone = score >= 75 ? 'green' : score >= 40 ? 'yellow' : 'red';
  const meter = c(barTone, '▰'.repeat(filled)) + c('dim', '▱'.repeat(10 - filled));
  const generated = cov.feed.generatedAt.replace('T', ' ').replace(/:\d\d(\.\d+)?Z$/, ' UTC');
  // Counts are per package, range or action, not per advisory: one poisoned version often matches our curation and the OpenSSF record.
  const pkgHits = new Set(report.matches.flatMap((m) => m.target.kind === 'package' ? [`${m.target.package.lockfile}\0${m.target.package.name}@${m.target.package.version}`] : [])).size;
  const actHits = new Set(report.matches.flatMap((m) => m.target.kind === 'action' ? [`${m.target.action.workflow}:${m.target.action.line}`] : [])).size;
  const inv = cov.inventory;
  const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? '' : 's'}`;

  L.push(`${c('cyan', '◆ guarda', true)} ${c('grey', report.engineVersion)}${' '.repeat(Math.max(2, 50 - report.engineVersion.length))}${c('grey', `feed #${cov.feed.version} · ${generated}${cov.feed.stale ? ' · STALE' : ''}`)}`);
  L.push('');
  L.push(`  ${status}   ${c('white', 'Guarda score')}  ${meter}  ${c(barTone, `${score}/100`, true)}  ${c('grey', `(${grade})`)}`);
  L.push('');
  const row = (k: string, v: string, tone: Tone, extra: string) => `  ${c('white', k.padEnd(14))} ${c(tone, v.padEnd(12))} ${c('grey', extra)}`;
  const rangeHits = new Set(report.matches.flatMap((m) => m.target.kind === 'declared' && m.severity !== 'info' ? [`${m.target.declared.manifest}\0${m.target.declared.name} ${m.target.declared.range}`] : [])).size;
  const noLockSkips = cov.skipped.filter((k) => k.reason === 'no-lockfile');
  const noLock = noLockSkips.length > 0;
  const lockIgnored = noLockSkips.some((k) => !k.path.endsWith('package.json'));
  const sc: [string, Tone] = pkgHits ? [`${pkgHits} hit${pkgHits === 1 ? '' : 's'}`, 'red' as Tone] : rangeHits ? [`${rangeHits} exposed`, 'orange' as Tone] : inv.lockfiles || inv.declared ? ['clean', noLock ? 'yellow' as Tone : 'green' as Tone] : ['no lockfile', 'yellow' as Tone];
  const scDetail = [inv.lockfiles ? `${plural(inv.packages, 'package')} · ${plural(inv.lockfiles, 'lockfile')}` : '', inv.declared ? `${inv.declared} declared in ${inv.manifests === 1 ? 'package.json' : plural(inv.manifests, 'manifest')}` : '', noLock ? (lockIgnored ? 'lockfile gitignored' : 'no lockfile') : ''].filter(Boolean).join(' · ') || 'nothing to check';
  L.push(row('supply chain', sc[0], sc[1], scDetail));
  L.push(row('workflows', actHits ? `${actHits} hit${actHits === 1 ? '' : 's'}` : inv.workflows ? 'clean' : 'none found', actHits ? 'red' : inv.workflows ? 'green' : 'grey', inv.workflows ? `${plural(inv.actions, 'use')} · ${plural(inv.workflows, 'workflow')}` : ''));
  const rtHits = new Set(report.matches.flatMap((m) => m.target.kind === 'package' && m.target.package.ecosystem === 'software' ? [`${m.target.package.lockfile}\0${m.target.package.name}`] : [])).size;
  const imgHits = new Set(report.matches.flatMap((m) => m.target.kind === 'package' && m.target.package.ecosystem === 'Docker' ? [`${m.target.package.lockfile}\0${m.target.package.name}`] : [])).size;
  if (inv.images) L.push(row('images', imgHits ? `${imgHits} hit${imgHits === 1 ? '' : 's'}` : 'clean', imgHits ? 'red' : 'green', `${plural(inv.images, 'image')} · ${plural(inv.imageFiles, 'file')}`));
  if (inv.runtimes) L.push(row('runtimes', rtHits ? `${rtHits} hit${rtHits === 1 ? '' : 's'}` : 'clean', rtHits ? 'red' : 'green', `${plural(inv.runtimes, 'runtime')} · ${plural(inv.runtimeFiles, 'file')}`));
  L.push(row('secrets', report.secrets.length ? `${report.secrets.length} found` : 'none', report.secrets.length ? 'orange' : 'green', `files ${cov.scannedFiles}`));
  const blocking = cov.skipped.filter((k) => k.reason === 'parse-error' || k.reason === 'too-large' || k.reason === 'unsupported-format');
  const unsupported = cov.skipped.filter((k) => k.reason === 'unsupported-entry' || k.reason === 'unsupported-ecosystem').length;
  const excluded = cov.skipped.filter((k) => k.reason === 'excluded').length;
  const parts = [
    blocking.length ? `${blocking.length} skipped: ${blocking.slice(0, 3).map((k) => sz(k.path)).join(', ')}${blocking.length > 3 ? ', …' : ''}` : '',
    unsupported ? `${unsupported} unsupported entr${unsupported === 1 ? 'y' : 'ies'}` : '',
    excluded ? `${excluded} excluded` : '',
  ].filter(Boolean);
  L.push(row('coverage', cov.complete ? 'complete' : 'incomplete', cov.complete ? 'green' : 'yellow', parts.join('; ')));
  L.push('');

  if (report.matches.length) {
    L.push(`${bar('cyan')} ${c('cyan', 'ADVISORIES', true)}`); L.push(bar('cyan'));
    for (const m of report.matches) for (const line of matchLines(m, c)) L.push(line === '' ? bar('cyan') : `${bar('cyan')}  ${line}`);
    L.push('');
  }
  if (report.secrets.length) {
    L.push(`${bar('cyan')} ${c('cyan', 'SECRETS', true)}`); L.push(bar('cyan'));
    const w = Math.max(...report.secrets.map((s) => s.title.length));
    for (const s of report.secrets) L.push(`${bar('cyan')}  ${c(sevTone[s.severity], sevLabel[s.severity], true)}  ${sz(s.title).padEnd(w)}   ${c('white', `${sz(s.path)}:${s.line}`)}   ${c('grey', sz(s.redacted))}${s.gitignored ? c('dim', '   gitignored') : ''}`);
    L.push('');
  }
  const moves: string[] = [];
  if (pkgHits) moves.push(`Replace the ${pkgHits} poisoned version${pkgHits === 1 ? '' : 's'} and rotate anything the build could read`);
  if (report.matches.some((m) => m.target.kind === 'action')) moves.push('Pin workflow actions to commit SHAs and check your run logs for the incident windows');
  if (report.secrets.length) moves.push(`Rotate the ${report.secrets.length} exposed secret${report.secrets.length === 1 ? '' : 's'} and keep them out of the repository`);
  if (noLock) moves.push(lockIgnored ? 'Commit the lockfile (remove it from .gitignore) so CI installs what you tested' : 'Commit a lockfile so transitive dependencies are checked and CI installs what you tested');
  if (rangeHits) moves.push(`Pin the ${rangeHits} range${rangeHits === 1 ? '' : 's'} that admit${rangeHits === 1 ? 's' : ''} poisoned versions, or commit a lockfile`);
  if (!cov.complete && !noLock) moves.push('Fix the skipped entries above so the next run covers everything');
  if (moves.length) {
    L.push(`${bar('cyan')} ${c('cyan', 'NEXT MOVES', true)}`);
    moves.forEach((m, i) => L.push(`${bar('cyan')}  ${c('cyan', String(i + 1), true)}  ${m}`));
    L.push('');
  }
  if (cov.feed.stale) L.push(`  ${c('yellow', 'feed is past its expiry; run guarda feed --update')}`);
  if (!cov.complete) L.push(`  ${c('yellow', 'coverage incomplete: a clean result does not cover the skipped entries')}`);
  if (opts.footer) L.push(`  ${c('dim', opts.footer)}`);
  return L.join('\n').replace(/\n+$/, '') + '\n';
}

function matchLines(m: Match, c: (tone: Tone, s: string, bold?: boolean) => string): string[] {
  const out: string[] = [];
  const sev = c(sevTone[m.severity], sevLabel[m.severity], true);
  const src = m.source === 'guarda' ? '' : c('dim', ` [${m.source}]`);
  if (m.target.kind === 'package') {
    const p = m.target.package;
    out.push(`${sev}  ${c('white', sz(m.advisory.id), true)}${src}  ${sz(p.name)}@${sz(p.version)}${' '.repeat(Math.max(2, 24 - p.name.length - p.version.length))}${c('grey', `${sz(p.lockfile)}${p.line ? ':' + p.line : ''}`)}`);
    out.push(`      ${c('grey', sz(`${m.advisory.summary} · ${m.clause}`))}`);
  } else if (m.target.kind === 'declared') {
    const d = m.target.declared;
    out.push(`${sev}  ${c('white', sz(m.advisory.id), true)}${src}  ${sz(d.name)} ${sz(d.range)}${' '.repeat(Math.max(2, 24 - d.name.length - d.range.length))}${c('grey', `${sz(d.manifest)}${d.line ? ':' + d.line : ''}`)}`);
    out.push(`      ${c('grey', sz(`${m.advisory.summary} · ${m.clause}`))}`);
  } else {
    const a = m.target.action;
    const ref = a.refKind === 'sha' ? a.ref.slice(0, 12) + '…' : a.ref;
    out.push(`${sev}  ${c('white', sz(m.advisory.id), true)}${src}  ${sz(a.repo)}@${sz(ref)}   ${c('grey', `${sz(a.workflow)}:${a.line}`)}`);
    const detail = m.target.exposure === 'malicious-sha' ? 'pinned to a known malicious commit'
      : m.target.exposure === 'exposed-ref' ? `${m.clause}; check your run logs for that window`
      : 'repository is in an advisory; this ref is not listed';
    out.push(`      ${c('grey', sz(`${m.advisory.summary} · ${detail}`))}`);
  }
  const rem = m.advisory.database_specific?.seenty?.remediation;
  if (rem) out.push(`      ${c('green', '→')} ${sz(rem)}`);
  const ref = m.advisory.references?.[0]?.url; if (ref) out.push(`      ${c('dim', sz(ref))}`);
  out.push('');
  return out;
}
