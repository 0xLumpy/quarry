# Quarry roadmap

This document owns future sequencing. It does not prove that a release item is
implemented or closed; current status belongs in the release ledger under
[`releases/`](releases/).

## v0.3.10 — integrity and evidence truth

Close the current execution, persistence, revision, campaign, installation,
network-boundary, configuration and report-truth invariants. No new acquisition
breadth belongs in this release. Exact scope and gates are maintained in
[`releases/v0.3.10.md`](releases/v0.3.10.md).

## v0.3.11 — operator evidence and reporting

- Preserve exact occurrence-level provenance for findings, screenshots,
  secrets, technologies, services and provider intelligence.
- Publish a full-fidelity private operator view and a separately requested
  share view.
- Make every acquisition lane conform to one source lifecycle contract.
- Replace display-derived and truncated identifiers with stable typed IDs.
- Add relationship-aware, source-aware ranking without turning absence into a
  negative finding.

## v0.4 — indexed single-host core

- Introduce explicit `RunContext`, repository, executor, artifact-store and
  source-adapter boundaries.
- Replace process-global run state and whole-corpus live materialization.
- Store immutable observations and typed temporal relationships; make reports,
  exports and search indexes rebuildable projections.
- Split large phases only after the adapter and repository contracts have
  survived real lane migrations.
- Add bounded DAG scheduling, backpressure, leases, heartbeats, idempotency and
  durable remainder.

## v0.5+ — distributed execution, collaboration and AI

- Add worker identity, scoped task capabilities, authorization revisions and
  audited artifact access before remote execution.
- Keep canonical evidence immutable and tenant/project scoped.
- Give AI read-only access to a typed policy-filtered view. AI output is an
  append-only assessment that cites observation and artifact IDs and records
  provider, model, prompt/template and input-view identities.
- Require deterministic policy checks and explicit human approval before a
  future AI proposal can become a typed job. AI never receives direct shell,
  vault or scanner authority.

## Reporting v2 prototype

The external reporting prototype is intentionally deferred, not discarded. A
snapshot reviewed on 2026-08-11 lives outside this repository in the prior
audit workspace. Its non-cache source tree had this deterministic inventory
digest:

```text
sha256(sorted(relative-path file-sha256 lines))
ddf6080814716e0e044625014984c387b2eaf0c7d9e254480e4c3c1afe88fdd6
```

The historical handoff reported 106 passing prototype tests; that result has
not been re-run as part of this repository's release gate. Before reuse:

1. copy the exact snapshot into a dedicated experiment branch or signed
   artifact and verify the inventory digest;
2. remove heuristic redaction from the private operator view while preserving
   a distinct policy-controlled share/AI view;
3. adapt it to the accepted observation, artifact and relationship contracts;
4. re-run privacy, integrity, reproducibility and large-corpus tests;
5. keep it a rebuildable projection until the repository migration is proven.

The revisit trigger is completion of the v0.3.10 release gates and acceptance
of the v0.4 observation/artifact/relationship contract. It must not dictate
that contract merely because it already has a working schema.
