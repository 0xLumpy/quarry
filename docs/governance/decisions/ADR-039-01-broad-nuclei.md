# ADR-039-01: broad active Nuclei verification

**Status:** accepted

**Decision date:** 2026-08-11

**Applies to:** Quarry's default active-vulnerability-verification policy

## Context

Quarry is intended to preserve useful bug-bounty evidence at scale. Its current main Nuclei lane selects
medium-through-critical templates and excludes templates tagged `intrusive`, `fuzz`, `dos`, or
`brute-force`. That filter can still select requests that change state, write files, or execute a payload
on a matching vulnerable target. Calling the lane generically "non-intrusive" is therefore inaccurate.

## Decision

Keep the broad request set. Describe it as **broad active vulnerability verification**, not as a
read-only or non-intrusive scan. Active scope is the operator's consent boundary; Quarry will not add a
second prompt or silently narrow the template selection merely to make the label safer.

## Required controls

- Record the exact Nuclei executable, version and digest.
- Materialize one immutable template/helper corpus for a run and record its identity, signature state,
  selection flags and selected-template inventory.
- Disable mid-run corpus updates so every chunk sees the same inputs.
- Record rates, concurrency, host-error policy, OOB backend class and applicable scope/policy identity.
- Preserve the request/response evidence available for a finding and report uncertainty honestly.

Template tags and signing establish metadata or provenance; neither proves that a request is harmless.
These controls improve reproducibility and disclosure without reducing the accepted coverage.

## Consequences

Authorized targets may experience state-changing requests when a selected template matches. Operators
must account for that behavior in program rules and engagement configuration. A future safer profile may
be offered, but it is an additional explicit policy and does not replace this accepted default.
