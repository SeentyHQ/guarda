# Network access

Guarda talks to exactly one place: the feed location (`--feed`, `GUARDA_FEED_URL`, `~/.guarda/config.json`, default `https://feed.seenty.com/guarda/v1`). A feed location can be an `https://` or `http://` URL or a local directory; a directory makes no request at all. The scanned repository's `.guarda.json` cannot change the feed location.

| Request | Which commands | When | What it carries |
|---|---|---|---|
| `GET <feed>/manifest.json` | `scan`, `feed`, `explain` | every run unless `--offline` (`feed --update` forces it); conditional with `If-None-Match` when a cached copy exists | `User-Agent: guarda/<version>` plus ` ci` when the `CI` environment variable is set. With `DO_NOT_TRACK=1` or `--no-tips` the User-Agent is just `guarda` |
| `GET <feed>/manifest.json.sig` | same | only when the manifest changed | same headers |
| `GET <feed>/<shard>.json` | same | only for shards not yet in the cache. `scan` fetches the curated shard plus the shards of the ecosystems found in the project's lockfiles (a project with no lockfiles fetches every shard); `feed` and `explain` fetch every shard | same headers; which shards are fetched reveals which ecosystems the project uses |

Each request is retried up to three times with exponential backoff on network errors and HTTP 5xx. When the download fails and a cached copy exists, the cached copy is used and a warning is printed.

What never leaves the machine: package names, versions, file names, paths, hashes, secrets, findings. `--offline` opens no socket. There is no telemetry, no crash reporting and no update check beyond the manifest request above. The cache lives under `~/.guarda/cache/<hash of the feed location>/` (or `$XDG_CACHE_HOME/guarda/`, or `--cache-dir`).
