# Quarry governance

This directory records Quarry's product intent and the rules used to decide whether the implementation
matches it. It exists to prevent plans, handoffs, tests, and current behavior from being treated as
interchangeable sources of truth.

Phase 0 is a governance and integrity pass. These documents define requirements; their presence does not
mean the current `v0.3.9` implementation satisfies them.

## Documents

- [`PRODUCT-CONTRACT.md`](PRODUCT-CONTRACT.md) defines the operating, evidence, privacy, and future-AI
  behavior Quarry is intended to preserve.
- [`decisions/`](decisions/) contains accepted architecture decisions, including the four operating-posture
  decisions retained during the `v0.3.9` stabilization.
- [`../audit/CURRENT-HEAD.md`](../audit/CURRENT-HEAD.md) records the current audited implementation status
  and maps it to the stable historical finding IDs.
- [`../audit/MARKET-BASELINE-2026-08.md`](../audit/MARKET-BASELINE-2026-08.md) records the dated external
  architecture/professionalism benchmark and clearly separated Quarry inferences.
- [`../releases/v0.3.10.md`](../releases/v0.3.10.md) is the sole scope and evidence ledger for that release.
- [`../releases/RELEASE-GATES.md`](../releases/RELEASE-GATES.md) defines the gate taxonomy and proof
  required for promotion.
- [`../design/GOLDEN-CORPUS.md`](../design/GOLDEN-CORPUS.md) defines private corpus attestation and safe
  synthetic fixture derivation.
- [`../roadmap.md`](../roadmap.md) owns future sequencing, including the deferred reporting prototype.
- [`../archive/audit-v0.3.9/`](../archive/audit-v0.3.9/) preserves the original audits as immutable inputs.

Accepted architecture decisions should be captured as ADRs here when that record is introduced. A plan
is not a closure record, and a historical audit is not a current status ledger.

## Authority

Quarry keeps product intent separate from observed behavior.

### Intended behavior

When statements about what Quarry **should** do conflict, use this order:

1. the maintainer's latest explicit decision, recorded in the repository during the same change;
2. this product contract;
3. an accepted, current ADR;
4. the current release register and its acceptance criteria;
5. a tracked implementation plan;
6. operator and design documentation;
7. handoffs, audit reports, backlog entries, and historical notes.

An older document does not regain authority because its implementation still exists. A decision that
temporarily overrides the tracked contract must be recorded; conversation history alone is not durable
governance.

### Observed behavior

When statements about what Quarry **does now** conflict, use this order:

1. reproducible runtime evidence bound to the exact framework revision, inputs, configuration, tool and
   template identities, and relevant environment;
2. the executable source at that revision;
3. tests actually executed at that revision, including their selection and result;
4. static-analysis and generated inspection results;
5. comments, documentation, plans, handoffs, and unbound historical run output.

Observed behavior never silently changes the product contract. Intended behavior never proves that an
implementation works. A divergence between the two is an open defect or an explicitly recorded design
change.

## Status language

Use these states consistently in registers, plans, release notes, and handoffs:

| State | Meaning |
|---|---|
| `open` | The requirement or defect is understood but its acceptance criteria are not yet satisfied. |
| `implemented` | A candidate change exists. This says nothing about its correctness or completeness. |
| `verified` | Defined positive, negative, boundary, and relevant fault-path checks passed against an exact revision, with evidence recorded. |
| `closed` | The verified result, documentation, migration impact, dependencies, and release register agree; no required work remains. |
| `deferred` | Work is intentionally outside the current release, with rationale and a named future gate. |
| `accepted_by_design` | The observed behavior is an intentional product choice, not a defect. Its consequences and controls remain testable. |
| `accepted_risk` | A known defect or exposure is retained temporarily, with an owner, rationale, scope, and review condition. |
| `blocked` | A specific external dependency prevents progress; the dependency and unblock condition are recorded. |

`implemented`, `verified`, and `closed` are deliberately different. A commit message, passing happy-path
test, or handoff claim cannot close an item by itself. `accepted_by_design` must not be used as a synonym
for `accepted_risk`.

Verification evidence should record, at minimum:

- framework revision and dirty-tree state;
- test or reproduction identifier and exact selection;
- relevant configuration and fixture identity, without Quarry-owned credentials;
- external executable, template, and data-corpus identities where applicable;
- expected and observed outcome, including gaps or unmeasured paths.

If any of those bindings are missing, the result may be useful historical evidence, but it is not a
release-grade verification record.

## Change discipline

- Change the contract deliberately; do not edit it merely to describe a bug.
- Record conflicting observations instead of reconciling them by omission.
- Link closure evidence rather than copying unbound summaries between documents.
- Preserve user-owned notes and historical runs as inputs, not authorities.
- Reopen a closed item when a regression or invalid verification assumption is demonstrated.
