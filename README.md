# Guarda

**Supply-chain advisories, curated.** Guarda checks your lockfiles and CI workflows against advisories reviewed by [Seenty](https://seenty.com): poisoned releases, hijacked tags, maintainer takeovers and the public malicious-package database, often before a CVE exists. It also finds secrets with its own detectors. One command, no account, and nothing about your project leaves your machine.

```sh
npx @seenty/guarda
```

Browse the advisories at [guarda.seenty.com](https://guarda.seenty.com).

## What it checks

- **Packages** in `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `requirements.txt`, `poetry.lock`, `uv.lock` and `Pipfile.lock`, plus the version ranges in `package.json`.
- **GitHub Actions**: every `uses:` in `.github/workflows`, against malicious commits and the tags that pointed at them.
- **Container images** the repo pulls (`FROM` in Dockerfiles, `image:` in compose files and Kubernetes manifests), by tag or digest.
- **Runtimes** the repo declares (`FROM php:8.2-fpm`, `.nvmrc`, `.node-version`, `.python-version`, `.tool-versions`, `engines.node`, `composer.json`), against advisories on the runtime itself.
- **Secrets**: cloud keys, tokens, private keys and connection strings in the working tree or the git index. Matches are redacted in every report.

The advisory feed is a signed static file set. Guarda verifies the signature with a key pinned in the binary before trusting anything in it, so a tampered or substituted feed is refused. See [NETWORK.md](NETWORK.md) for the one place it talks to.

## Usage

```sh
guarda                               # scan the current directory
guarda scan ./app --json             # machine-readable report
guarda scan --sarif > guarda.sarif   # GitHub code scanning
guarda scan --fail-on high           # exit 1 only at high or critical
guarda scan --strict                 # exit 2 on incomplete coverage or a stale feed
guarda scan --only secrets --staged  # pre-commit hook
guarda explain GUARDA-2026-0038      # one advisory, in full
guarda feed --verify                 # cached feed version and signing key
```

In CI:

```yaml
- run: npx @seenty/guarda --fail-on high
```

Exit codes: `0` nothing found · `1` findings at or above `--fail-on` · `2` error, or incomplete coverage with `--strict` · `3` nothing to scan.

Options: `--offline`, `--cache-dir`, `--only packages,actions,secrets`, `--no-color`, `--no-tips`. Project settings live in `.guarda.json` at the repository root (`failOn`, `only`, `ignore`).

## MCP server

A read-only MCP server at `https://guarda.seenty.com/mcp`, no authentication. It answers from the curated feed and never receives your dependency list: to check a whole repository, the agent runs the CLI where the code is.

Tools: `search_advisories`, `get_advisory`, `check_package` (one name and one version), `feed_status`, `how_to_scan`.

**Claude Code**

```sh
claude mcp add --transport http guarda https://guarda.seenty.com/mcp
```

**Codex**

```sh
codex mcp add guarda --url https://guarda.seenty.com/mcp
```

**Cursor** (`.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "guarda": { "url": "https://guarda.seenty.com/mcp" }
  }
}
```

**OpenCode** (`opencode.json`)

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "guarda": { "type": "remote", "url": "https://guarda.seenty.com/mcp", "enabled": true }
  }
}
```

To have your agent check dependencies on its own, add this to your project's `AGENTS.md` or `CLAUDE.md`:

```md
## Supply-chain advisories

Use the Guarda MCP server (https://guarda.seenty.com/mcp, no API key) and the Guarda CLI:

- Before adding or upgrading a dependency, run `check_package` with its ecosystem, name and version.
- When asked whether this project is affected by an advisory, run `npx @seenty/guarda --json` at the repository root and read the result; do not paste the lockfile into the MCP server.
- For any GUARDA id, run `get_advisory` to get the affected versions and what to do.
- No matches means Guarda found none, not that the packages are safe.
```

## Report a compromised package

Open an issue with the "Report a compromised package" template, or run `guarda report <ecosystem:name@version>` to get the pre-filled link. Reports are reviewed before they enter the feed.

## Licence

AGPL-3.0-only. See [LICENSE](LICENSE), [NOTICE](NOTICE) and [CONTRIBUTING.md](CONTRIBUTING.md). The advisory content is CC-BY-SA-4.0; the OpenSSF malicious-package records keep their Apache-2.0 licence and attribution.
