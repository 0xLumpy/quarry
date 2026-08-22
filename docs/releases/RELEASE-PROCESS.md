# Release process and integrity

## Applicability

The signing, detached-approval and publication procedure below is dormant
for the unpublished `v0.3.10` internal-integrity milestone. It becomes required
when Quarry is published to an external package index, gains a second
maintainer, or is operated as a service. For `v0.3.10`, acceptance means the
scoped integrity invariants pass on the
maintainer's actual local and Linux CI environments and the maintainer records
an unsigned sign-off in the release ledger. The `v0.3.10` tag is a personal
bookmark whose tag-triggered CI confirms the signed-off tree; it is not a
signed distribution attestation. No production trust policy, detached approval,
CI image attestation, or publication receipt is a milestone prerequisite.

This applicability rule does not relax observation provenance, immutable
sealed-run evidence, content-digest verification, reproducibility, or the
required tool/output receipts. The remaining sections define the deferred
external-distribution procedure and stay dormant until one of the publication
triggers above applies.

This procedure implements the ordering in
[`RELEASE-GATES.md`](RELEASE-GATES.md). It does not replace that contract or the
version-specific scope ledger. A CI result, changelog entry, commit message, or
documentation edit cannot nominate a candidate or close a gate.

## Roles and immutable subjects

- The maintainer authorizes nomination after source, scope, schemas, supported
  matrix, thresholds, and release notes are frozen.
- Gate collectors produce immutable, content-addressed records for one exact
  nominated candidate.
- The aggregator verifies every selected record and artifact and emits a
  deterministic aggregate. It cannot alter an underlying result.
- A named approver reviews and signs the aggregate digest with an approval key
  distinct from gate-collector authority.
- The publisher promotes only the already accepted artifact bytes and records a
  digest-bound receipt.

Private keys, credentials, target evidence, and operator paths never enter the
repository or a public CI log.

## Pre-nomination checklist

1. Start from a clean, reviewed commit. Verify the release-scope registry,
   schemas, workflow/job map, support matrix, thresholds, corpus selection,
   no-live rule, candidate release notes, and production trust policy.
2. Run every pre-release CI gate and the supported non-live lane matrix. A skip,
   deselection, unsupported dependency, or unavailable required tool is not a
   pass.
3. Build source and wheel artifacts in the declared package lane; inspect their
   metadata, data files, license, entry points, dependency closure, SBOM, and
   provenance subjects.
4. Resolve every stop-ship finding. Deferred limitations must be explicit in
   the release ledger and notes; reducing accepted coverage is not a repair.
5. Obtain explicit maintainer authorization for the one nomination commit.

## Nomination and evidence

The nomination commit changes both authoritative package-version sources to the
intended version and freezes the candidate. Collect all scope-selected gate
records against that exact commit and tree in their declared isolation lanes.
Any tracked candidate change invalidates the affected evidence and creates a
new candidate.

Verify artifact digests before deterministic aggregation. The aggregate must
contain every selected Phase A-C result, all four Phase D results or exact
`not_applicable` records, and the pre-publication Phase E records. It must not
contain itself or the later approval. A failed, missing, expired, mismatched, or
untrusted record makes aggregation fail closed.

## Approval, tag, and publication

1. The approver verifies the candidate identity, aggregate, residual risks,
   expected subjects, and key separation, then creates a detached approval over
   the aggregate digest.
2. Create the signed version tag at the exact nominated commit only after the
   aggregate and detached approval validate.
3. Publish the exact accepted source/wheel/SBOM/provenance/checksum bytes. Do not
   rebuild them from the tag or a documentation descendant.
4. Record the repository, tag object, package index, subject digests, timestamps,
   and verification outcome in the immutable publication receipt.
5. A later documentation-only projection may cite those identities. It is not
   the released candidate and cannot rewrite the evidence history.

If any check fails after nomination, stop publication, retain the diagnostic
artifacts privately, repair on a descendant, and repeat every affected gate for
the new candidate. Never move a published tag or replace a published artifact.
