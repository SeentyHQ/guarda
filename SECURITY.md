# Security policy

## Reporting a vulnerability in Guarda

Please do not open a public issue for a vulnerability in the Guarda CLI, the
engine or the feed verification. Email **security@seenty.com** with a
description, a reproduction and the version (`guarda --version`). You will get
an acknowledgement within 3 business days and a fix or a mitigation plan within
30 days for confirmed reports. We credit reporters in the changelog unless they
ask otherwise.

## Reporting a compromised package

That is not a vulnerability in Guarda: use the
["Report a compromised package"](https://github.com/seentyhq/guarda/issues/new?template=report-compromised-package.yml)
issue template or `guarda report <ecosystem:name@version>`. Reports are public
by design so that others can act on them while Seenty staff review them.

## Feed signing keys

The feed manifest is signed with Ed25519. The public keys are pinned in
`src/client/keys.ts` (an active and a standby key). A key rotation ships the
new key as standby in a release first; the feed switches to it only after
that release has been out long enough for users to update. A compromised key
is announced in the changelog and in the repository's security advisories.

## Supported versions

Only the latest minor release receives fixes.
