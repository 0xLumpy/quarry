# Releases

- [`v0.3.10.md`](v0.3.10.md) is the sole in-tree scope ledger and documentation projection for the
  pending integrity release; immutable external attestations and their accepted aggregate are result
  authority.
- [`RELEASE-GATES.md`](RELEASE-GATES.md) defines the reusable promotion contract and machine evidence the
  release must eventually produce.

A maintainer-authorized nomination commit may set the final package version and freeze candidate release
notes before accepted gates run; that nominee and its candidate-built packages are not a release. A tag
or publication is permitted only after the external aggregate and detached approval accept one exact
candidate, and publication must use the already-attested artifact bytes. Historical test output and
`SKIP` results are not release evidence.
