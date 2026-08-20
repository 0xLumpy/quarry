# Security policy

Quarry is an offensive-security tool. Use it only on systems and ranges you are
authorized to assess. A product defect that escapes scope, exposes operator
credentials, corrupts evidence, bypasses an execution boundary, or enables
unsafe installation is a security issue even when it requires a hostile target
response.

## Supported versions

Security fixes are made on `main` and, when a release exists, the most recent
stable release line. Older releases may receive a backport only when the
maintainer explicitly announces one. The in-tree release ledger is
authoritative about whether a candidate has actually been nominated or
published; an unreleased version heading in `CHANGELOG.md` is not a release.

## Report a vulnerability privately

Use the repository's private
[GitHub security-advisory form](https://github.com/0xLumpy/quarry/security/advisories/new).
If that form is unavailable, contact the maintainer through the
[0xLumpy GitHub profile](https://github.com/0xLumpy) and ask for a private
reporting channel. Do not include credentials, target evidence, exploit code,
or an unpatched bypass in a public issue.

Please include the affected commit or release, platform, minimal reproduction,
observed impact, and whether any real target was contacted. Synthetic fixtures
are strongly preferred. We will acknowledge a usable report as soon as
practical, coordinate validation and remediation privately, and credit the
reporter unless anonymity is requested.

Public feature requests and non-sensitive bugs belong in the
[issue tracker](https://github.com/0xLumpy/quarry/issues).
