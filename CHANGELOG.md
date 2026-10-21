# Changelog

## 0.2.0

- Python lockfiles: `requirements.txt` (exact pins; ranges, includes, URLs and paths are
  reported as unchecked), `poetry.lock`, `uv.lock` (the editable project is left out) and
  `Pipfile.lock`, as PyPI packages matched like any other.
- Runtimes declared by the repository: `FROM` in Dockerfiles (official `php`, `node`,
  `python`, `ruby`, `nginx`, `httpd`, `ubuntu`, `debian`, `alpine` images), `.nvmrc`,
  `.node-version`, `.python-version`, `.tool-versions`, `package.json` `engines.node` and
  `composer.json` `require.php`. They are matched against `software` advisories: an exact
  version is a hit, a major-only tag (`php:8.2`) is a possible hit that asks for the exact
  version, ranges and `latest` are reported as unchecked. New `runtimes` row in the report
  and `runtimes`/`runtimeFiles` in coverage; the `software` shard is fetched when a repo
  declares a runtime. `collectInventory` returns `runtimes` (the Seenty scanner reads them).
- Container images: every image a repo pulls (`FROM` in Dockerfiles, `image:` in compose
  files and in manifests under `k8s/`, `kubernetes/`, `deploy/`, `manifests/`, `charts/`,
  `helm/`) is matched by tag or digest against `Docker` advisories (a compromised image
  release, a hijacked tag). Names resolve the way Docker does (`php` is `library/php`);
  tags are opaque, so advisories list exact tags or digests and ranges are refused.
  Untagged images are reported as unchecked. `images` row in the report and
  `images`/`imageFiles` in coverage; the `docker` shard is fetched when a repo pulls images.

## 0.1.7

- New ecosystem `software` for advisories about a runtime, product, framework or OS release
  rather than a registry package (PHP, Node.js, Ubuntu, LiteLLM as a product). The name is
  the Seenty Inventory catalog slug and versions compare as dotted numbers of any width
  (`8.2.33`, `22.04`, `2019`), so `<8.2.34` and `<22.04` work as written. The CLI has
  nothing to match them against yet (lockfiles are packages); it indexes the shard and
  ignores it. Runtime files (`Dockerfile`, `.nvmrc`, `composer.json` `require.php`) come later.

## 0.1.6

- `guarda feed` also reads the publisher's `status.json` (next to the manifest) and prints the
  publication time, the curated advisories per ecosystem, the malicious-package record count
  and the latest curated date. It is informational: offline runs and feeds without the file
  print the manifest summary only. `readFeedStatus`/`formatFeedStatus` are exported.
- The feed now ships `feed.xml`, an Atom feed of the curated advisories (newest 50), for RSS
  readers and Slack's `/feed subscribe`. Nothing changes for `scan`.

## 0.1.5

- Fix: inside Docker or CI, where the scanned directory belongs to another user, git refused
  the repository ("dubious ownership") and every ignore check silently answered "not
  ignored": gitignored secrets were not flagged and a gitignored lockfile looked committed.
  Git now trusts the scanned root only.
- A lockfile that git ignores is reported as "lockfile gitignored", with its own next move.

## 0.1.4

- The at-a-glance counts and the next moves count packages, ranges and actions, not
  advisories (one poisoned version usually matches the curated advisory and the OpenSSF record).

## 0.1.3

- `package.json` is always read. Exact pins count as packages when no lockfile sits next to
  it; semver ranges are checked against the feed as "range exposures": a range that admits a
  poisoned version is reported one severity below the advisory (`info` when a committed
  lockfile pins the install). A lockfile that git ignores never reaches CI, so its ranges count
  as unlocked and coverage says so. Coverage is incomplete without a lockfile (transitive
  dependencies are not checked) and the next moves ask for one.
- `pip` is accepted as a spelling of PyPI (GitHub Advisory Database).

## 0.1.2

- The at-a-glance table says what was checked: "69 packages · 1 lockfile", "3 uses · 2
  workflows", and "no lockfile" / "none found" when there was nothing to check. The JSON
  report carries the same counts in `coverage.inventory`.

## 0.1.1

- Fix: the `guarda` command installed by npm (`npx @seenty/guarda`, global install)
  exited silently without running. 0.1.0 is unusable from npm; use 0.1.1.

## 0.1.0

First release.

- `guarda scan`: npm, pnpm, yarn and bun lockfiles and GitHub Actions `uses:`
  references against the signed Guarda feed (curated advisories plus the
  OpenSSF malicious-packages records for npm and PyPI); secrets detection with
  Guarda's own rules; pretty, `--json` and `--sarif` reports; `--fail-on`,
  `--strict`, `--only`, `--staged`, `--offline`.
- `guarda feed`, `guarda explain`, `guarda report`.
- Feed client with a pinned Ed25519 key, content-addressed shard cache,
  conditional requests and retries. See NETWORK.md for every request made.
- Engine exported as `@seenty/guarda` (inventory, matching, feed build and
  verification) for other tools.
