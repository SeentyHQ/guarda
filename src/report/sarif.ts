import type { Report, Severity } from '../types.js';
const level = (s: Severity) => (s === 'critical' || s === 'high' ? 'error' : s === 'medium' ? 'warning' : 'note');
export function formatSarif(report: Report): string {
  const rules = new Map<string, { id: string; name: string; shortDescription: { text: string }; helpUri?: string }>();
  const results: unknown[] = [];
  for (const m of report.matches) {
    const r: { id: string; name: string; shortDescription: { text: string }; helpUri?: string } = { id: m.advisory.id, name: m.advisory.id, shortDescription: { text: m.advisory.summary } };
    const url = m.advisory.references?.[0]?.url; if (url) r.helpUri = url;
    rules.set(m.advisory.id, r);
    const loc = m.target.kind === 'package'
      ? { physicalLocation: { artifactLocation: { uri: m.target.package.lockfile }, ...(m.target.package.line ? { region: { startLine: m.target.package.line } } : {}) } }
      : m.target.kind === 'declared'
        ? { physicalLocation: { artifactLocation: { uri: m.target.declared.manifest }, ...(m.target.declared.line ? { region: { startLine: m.target.declared.line } } : {}) } }
        : { physicalLocation: { artifactLocation: { uri: m.target.action.workflow }, region: { startLine: m.target.action.line } } };
    const text = m.target.kind === 'package' ? `${m.target.package.name}@${m.target.package.version} matches ${m.advisory.id} (${m.clause})`
      : m.target.kind === 'declared' ? `${m.target.declared.name} ${m.target.declared.range} may resolve to a version in ${m.advisory.id} (${m.clause})`
      : `uses ${m.target.action.repo}@${m.target.action.ref}: ${m.clause}`;
    results.push({ ruleId: m.advisory.id, level: level(m.severity), message: { text }, locations: [loc] });
  }
  for (const s of report.secrets) {
    rules.set(s.ruleId, { id: s.ruleId, name: s.ruleId, shortDescription: { text: s.title } });
    results.push({ ruleId: s.ruleId, level: level(s.severity), message: { text: `${s.title}: ${s.redacted}` }, locations: [{ physicalLocation: { artifactLocation: { uri: s.path }, region: { startLine: s.line } } }] });
  }
  const sarif = { $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0', runs: [{ tool: { driver: { name: 'guarda', version: report.engineVersion, informationUri: 'https://github.com/seentyhq/guarda', rules: [...rules.values()] } }, results }] };
  return JSON.stringify(sarif, null, 2) + '\n';
}
