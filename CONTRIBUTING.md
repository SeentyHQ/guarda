# Contributing

Issues and pull requests are welcome. To report a compromised package, use the
"Report a compromised package" issue template.

## Working on the code

```sh
npm install
npm run dev -- scan <path>
npm test
npm run typecheck
```

To scan against a feed built locally from your own advisories, generate a dev key pair
(never committed) and point the scan at the output; the production keys are pinned in
`src/client/keys.ts`:

```sh
npm run gen-keys                       # writes ./keys
npm run build-feed -- --advisories test/fixtures/advisories.json --version 1 --out .feed-out
GUARDA_FEED_PUBKEY="$(cat keys/active.public.pem)" npm run dev -- scan . --feed .feed-out
```

Clean-room run with Docker:

```sh
docker compose run --rm test
TARGET=/path/to/repo FEED=./.feed-out GUARDA_FEED_PUBKEY="$(cat keys/active.public.pem)" docker compose run --rm scan
```

## Contributor License Agreement

Guarda is licensed under AGPL-3.0-only. Seenty also distributes this code under
other terms in its own products. By submitting a contribution you agree that
Seenty may license your contribution under AGPL-3.0-only and under any other
licence Seenty chooses, and you confirm you have the right to grant this. Sign
your commits with `git commit -s` to record that agreement (Developer
Certificate of Origin, https://developercertificate.org).
