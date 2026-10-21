/** `software` is not a package registry: a runtime, product, framework or OS release named by its Seenty Inventory catalog slug (php, node.js, ubuntu, litellm). */
/** `Docker` is a container image by tag or digest (`litellm/litellm`, `library/php`); tags are opaque, so advisories list exact tags. */
export type Ecosystem = 'npm' | 'PyPI' | 'Go' | 'crates.io' | 'Packagist' | 'Maven' | 'RubyGems' | 'NuGet' | 'GitHub Actions' | 'software' | 'Docker';
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export const SEVERITY_ORDER: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
export type SourceId = 'guarda' | 'openssf-mal';

export interface Package { ecosystem: Ecosystem; name: string; version: string; purl: string; lockfile: string; line?: number; direct?: boolean }
export interface ActionRef { repo: string; ref: string; refKind: 'tag' | 'branch' | 'sha'; workflow: string; line: number }
export type SkipReason = 'unsupported-format' | 'parse-error' | 'too-large' | 'unsupported-entry' | 'unsupported-ecosystem' | 'excluded' | 'no-lockfile';
export interface Skipped { path: string; reason: SkipReason; detail?: string }
/** A dependency declared as a range in a manifest (package.json): what a fresh install may resolve, not what is installed. */
export interface DeclaredDep { ecosystem: Ecosystem; name: string; range: string; manifest: string; line?: number; lockfile: 'committed' | 'ignored' | 'none' }
/** The runtime a repository declares (base image, version file, engine pin), keyed by the Seenty Inventory catalog slug. */
export interface RuntimeRef { slug: string; version: string | null; precision: 'exact' | 'major' | 'range' | 'unknown'; file: string; line?: number; raw: string }
/** A container image the repository pulls: base image of a Dockerfile, `image:` of a compose file or manifest. */
export interface ImageRef { name: string; tag: string | null; digest: string | null; file: string; line: number; raw: string }
export interface Inventory { packages: Package[]; declared: DeclaredDep[]; actions: ActionRef[]; runtimes: RuntimeRef[]; images: ImageRef[]; skipped: Skipped[]; scannedFiles: string[] }

export interface OsvEvent { introduced?: string; fixed?: string; last_affected?: string }
export interface OsvRange { type: 'SEMVER' | 'ECOSYSTEM'; events: OsvEvent[] }
export interface Affected { package: { ecosystem: string; name: string; purl?: string }; versions?: string[]; ranges?: OsvRange[] }
export interface SeentyFields {
  severity?: Severity; source_label?: string; kind?: string;
  window?: { from?: string; to?: string }; remediation?: string; exposed_refs?: string[]; credits?: string[];
}
export interface Advisory {
  id: string; modified: string; published?: string; withdrawn?: string; summary: string; details?: string;
  affected: Affected[]; references?: { type: string; url: string }[];
  database_specific?: { seenty?: SeentyFields; [k: string]: unknown };
}
export interface ShardEntry { source: SourceId; ecosystem: string; url: string; sha256: string; bytes: number }
export interface SourceInfo { snapshot: string; licence: string; attribution?: string; commit?: string }
export interface Manifest {
  schema_version: string; feed_version: number; generated_at: string; expires_at: string; min_cli_version: string;
  sources: Partial<Record<SourceId, SourceInfo>>; shards: ShardEntry[];
}
export interface Feed { manifest: Manifest; advisories: { source: SourceId; advisory: Advisory }[] }

export type Exposure = 'malicious-sha' | 'exposed-ref' | 'repo-listed';
export interface Match {
  advisory: Advisory; source: SourceId; severity: Severity; clause: string;
  target: { kind: 'package'; package: Package } | { kind: 'action'; action: ActionRef; exposure: Exposure } | { kind: 'declared'; declared: DeclaredDep; exposure: 'range' };
}
export interface SecretFinding { ruleId: string; title: string; severity: Severity; path: string; line: number; redacted: string; entropy?: number; gitignored: boolean }
export interface FeedStatus { version: number; generatedAt: string; expiresAt: string; stale: boolean; sources: Partial<Record<SourceId, SourceInfo>>; origin: 'network' | 'cache' | 'directory' }
/** What the run looked at, so a clean result says what it covered. */
export interface InventoryCounts { packages: number; lockfiles: number; declared: number; manifests: number; actions: number; workflows: number; runtimes: number; runtimeFiles: number; images: number; imageFiles: number }
export interface Coverage { scannedFiles: number; skipped: Skipped[]; feed: FeedStatus; complete: boolean; inventory: InventoryCounts }
export interface Report { matches: Match[]; secrets: SecretFinding[]; coverage: Coverage; engineVersion: string }
