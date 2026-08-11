# Quarry current-HEAD closure ledger

**Audited revision:** `4e4825c6f2a6f2bd81d81da0f231f56845ffd6aa`

**Package version:** `0.3.9`

**Audit date:** 2026-08-11

**Release decision:** **NO-GO** for `v0.3.10`, production-grade, or market-leading claims

This is a closure ledger for the implementation at the audited base revision. It does not repeat the
original audit report. The
historical finding definitions, evidence taxonomy, accepted decisions and `QR39-*` identifiers remain in
the [archived v0.3.9 register](../archive/audit-v0.3.9/AUDIT_REGISTER_RECONCILED.md). This document
supersedes that register only for **current status and release disposition**.

Phase 0 governance/documentation edits made after the audited revision do not close a code finding. If
this ledger is committed on top of `4e4825c`, that commit remains the audited implementation base until a
subsequent source change is verified and recorded here. Every release candidate requires a fresh evidence
set against its own exact identity.

## Authority and status rules

For decisions about this revision, authority is ordered as follows:

1. the maintainer's latest explicit product decisions;
2. current source and reproducible tests at the audited revision;
3. this ledger and the [v0.3.10 release ledger](../releases/v0.3.10.md);
4. the archived register and handoffs as historical evidence;
5. untracked plans and notes as non-authoritative working material.

Status words are deliberately strict:

| Status | Meaning |
|---|---|
| `VERIFIED` | The current implementation and a focused regression meet the complete stated acceptance criterion inspected in this pass. |
| `VERIFIED-NARROW` | A specific former failure is repaired and regression-covered, but the encompassing QR39 acceptance criterion or an adjacent invariant remains open. |
| `REOPENED` | A merged repair exists, but current code or a fresh disposable harness demonstrates an acceptance-breaking path. |
| `OPEN` | Source inspection identifies a release-relevant gap; closure evidence does not exist. |
| `ACCEPTED-DESIGN` | The behavior is intentional. Only its accuracy, provenance, controls and opt-out contract may be defects. |

A commit title and a passing regression are evidence, not automatic closure. A row closes only when its
acceptance criterion passes at the release candidate and the evidence slot in the release ledger is
filled.

## Locked product decisions

The decision identifiers below link to the accepted records in
[`docs/governance/decisions`](../governance/decisions/).

These behaviors are not defects and must not be silently weakened during remediation.

| Decision | Accepted behavior | Boundary that remains enforceable |
|---|---|---|
| [`ADR-039-01`](../governance/decisions/ADR-039-01-broad-nuclei.md) | Broad active Nuclei verification remains enabled with the current medium-through-critical selection and excluded tag set. | Describe it as broad active verification; bind the exact engine, flags, configuration and template corpus to the run. Do not reduce the accepted request set as a substitute for provenance. |
| [`ADR-039-02`](../governance/decisions/ADR-039-02-private-address-reach.md) | Private, RFC1918, CGNAT and ULA reach remains enabled by default and is operator-disableable. | Private reach does not authorize the scanner host, cloud metadata or unrelated control-plane destinations. Preserve the opt-out and prove the selected peer. |
| [`ADR-039-03`](../governance/decisions/ADR-039-03-public-interactsh.md) | Public Interactsh remains the default OOB provider and is operator-disableable. | Record which owner used which provider, protect local credentials/maps, retain callback evidence, and prove the documented disable path emits no callback for the disabled owner. |
| [`ADR-039-04`](../governance/decisions/ADR-039-04-scale-budgets.md) | Workload-scaled and potentially long budgets are intentional for high-scale coverage. | Deadlines still bind termination and evidence drain; large work is checkpointed; stalls, omissions and remainders remain explicit. |

## Evidence baseline

The fresh audit established the following without contacting a target:

- `main` and `origin/main` both resolved to the audited revision when inspected.
- The tree contained 54 source modules, 84 `test_*.py` files, 38 tools, 66 registered sources,
  23 entity kinds and 9 phases.
- The default non-live suite produced 5,444 passes plus 14 environment/sandbox failures. The exact
  failed subset subsequently produced 235 passes in the expected host environment, including all 14
  former failures. This is an **effective diagnostic baseline of 5,458**, not a single clean release-gate
  transcript.
- The integration selection produced 74 passes and 5,458 deselections.
- CI currently selects only `-m offline`: approximately 1,302 default non-live tests are outside that
  positive-selection gate.
- `scripts/verify-quarry.sh` was not accepted as fresh closure evidence because its check 2 can contact a
  configured/live target. It must be separated into a proven-offline gate and an explicitly authorized
  range gate before release use.
- The private case now named `quarry-interrupted-events` is the primary reporting/scale regression corpus.
  Its source mapping is sensitive, is not committed here, and has not yet been bound to an immutable
  inventory. Only aggregate counts were used in this audit.

The suite proves substantial behavior, but it does not override the directly reproduced invariant
failures below.

## Verified closures and verified foundations

| Status | QR39 mapping | Current verified outcome | Evidence at this revision | Residual disposition |
|---|---|---|---|---|
| `VERIFIED` | `QR39-002` | Run enumeration excludes reserved namespaces and validates run identity for latest/status/report/delta selection. | `1968c57`; `src/quarry_recon/store.py::list_runs`; `tests/test_qr39_002_list_runs.py` | Closed for this revision. Any future namespace must be added to the same authority. |
| `VERIFIED` | `QR39-011` | Exit values `0/2/3/4/5/6/130`, precedence and JSON-stdout discipline are implemented and directly covered. | `32ad450`; `src/quarry_recon/state.py::compute_exit`; `src/quarry_recon/exit_contract.py`; `tests/test_qr39_011_exit_contract.py` | Closed as a command-result contract. Individual commands still must supply truthful inputs. |
| `VERIFIED-NARROW` | `QR39-010` | Unknown, empty and duplicate selectors are rejected before run/install side effects; selected phases return in canonical order. | `8263b73`; `src/quarry_recon/cli.py::_select_phases`; `tests/test_qr39_010_selector_validation.py` | A future plugin/dependency graph still needs explicit prerequisite metadata; this does not reopen the present static selector fix. |
| `VERIFIED-NARROW` | `QR39-003`, `QR39-016` | Typed fault/gap records, verdict-after-fault plumbing and a persisted finalization state machine exist. | `45f83e8`, `32ad450`; `src/quarry_recon/state.py`; `tests/test_qr39_003_verdict_after_faults.py`; `tests/test_qr39_016_finalization.py` | Manifest semantics and consumers remain open in `HEAD-04`. |
| `VERIFIED-NARROW` | `QR39-006` | Newly created run/evidence artifacts use private creation primitives rather than depending on umask. | `7e44385`; `src/quarry_recon/privfs.py`; `tests/test_qr39_006_permissions.py` | Existing files, symlinks, ownership and migration remain open in `HEAD-02`/`HEAD-05`. |
| `VERIFIED-NARROW` | `QR39-009` | Normal delayed-OOB ingestion routes through revision supplements rather than appending normalized evidence to a sealed base. | `d598dd7`; `src/quarry_recon/revision.py::ingest`; `tests/test_qr39_009_oob_revision.py`; `tests/test_qr39_009_revision_sealing.py` | Repository sealing and revision publication/certification remain open in `HEAD-02`/`HEAD-03`. |
| `VERIFIED-NARROW` | `QR39-015` | A timed-out individual resolver worker is killable and reclaimed. | `901e093`; `src/quarry_recon/netguard.py::_resolve_batch`; `tests/test_qr39_015_resolver_reclaim.py` | Corpus-wide duration and portable worker-start behavior remain open in `HEAD-06`. |

The remaining recent commits are valuable foundations, but their full QR39 rows are not closed by the
fresh audit.

## Open stop-ship clusters

### `HEAD-01` — subprocess evidence completion

**Status:** `REOPENED`

**Maps to:** `QR39-001`, with resource interaction from `QR39-004` and `QR39-030`

**Evidence.** `src/quarry_recon/runner.py:901-934` rejoins drain threads, but tests only
`stop_reason`; it does not classify a still-alive stdout reader itself as primary incompleteness. A
disposable harness that blocked `_write_all` returned a successful child result with no published raw
artifact and no fault while the drain thread remained alive. `runner.run([])` also reaches `cmd[0]` at
`src/quarry_recon/runner.py:796`, and a configured stdout cap is recorded at
`src/quarry_recon/runner.py:987` without necessarily changing a successful status.

**Preconditions.** A sink write blocks, an escaped process retains a pipe, the caller supplies an empty
argv, or stdout exceeds an enabled retention ceiling.

**Acceptance.** Every started reader/feed thread has one terminal state. A live thread, lost/capped
primary stream, publication failure or invalid argv yields a typed incomplete/failed result; no writer
owns a sink after it is closed or published. Tests inject blocked writes, escaped holders, non-UTF-8,
empty argv, truncation and publication failure and prove bounded return plus exact retained bytes.

### `HEAD-02` — repository boundary, object identity and sealed-run immutability

**Status:** `REOPENED`

**Maps to:** `QR39-005`, `QR39-006`, `QR39-009`, `QR39-016`, `QR39-032`, `QR39-041`

**Evidence.** `Run._refuse_if_sealed()` protects selected verdict methods, but `Run.add()`
(`src/quarry_recon/store.py:992`), `Run.inherit()` (`:1034`), `Run.raw_path()` (`:772`) and `record()`
do not enforce the lifecycle. A disposable harness appended an entity to a finished run while its
manifest count stayed unchanged. `Run.open()` (`:757`) concatenates caller-provided `run_id`, and raw
phase/tool/name components are not containment-validated; disposable paths traversed outside the run.
`Run.add()` also accepts an entity absent from `ENTITY_KEYS`, producing an unmanifested log.

**Preconditions.** A future plugin/API, a malformed internal caller, a delayed observation path, or a
local caller supplies an unexpected entity/path after finalization.

**Acceptance.** All mutation reaches one repository transaction boundary. It validates opaque object
IDs, entity kind and resolved containment; refuses every base mutation after sealing; and directs
authorized late evidence to a staged revision. A matrix covers every public mutation method, traversal,
absolute paths, symlinks, unknown entities and concurrent finalize/append races.

### `HEAD-03` — revision composition, certification and pointer-last publication

**Status:** `REOPENED`

**Maps to:** `QR39-009`, `QR39-024`

**Evidence.** `src/quarry_recon/revision.py:728-772` starts each revision's counts from base counts and
updates only entity kinds materialized by that writer; a later revision can omit an entity introduced by
an earlier revision while publishing `status=valid`. The reader rechecks base and segment evidence, but
does not independently recompute every pointer/view/entity digest. The pointer is written before the
post-publication `read()` certification; a failed certification therefore leaves the bad pointer active.

**Preconditions.** At least two revisions touch different entity kinds, a publication is interrupted or
a pointer/view field is corrupted.

**Acceptance.** A candidate is staged outside the published namespace; the full prior combined view plus
candidate is folded; all counts and digests are recomputed; all artifacts and generated views are
verified; file and directory durability is established; and only then is the pointer atomically swapped.
Crash injection at every boundary leaves the previous pointer valid. Multi-entity/multi-revision tests
must make `combined_fold`, counts, certification and reports agree.

### `HEAD-04` — manifest and campaign terminal truth

**Status:** `REOPENED`

**Maps to:** `QR39-003`, `QR39-012`, `QR39-016`

**Evidence.** `summary_well_formed()` at `src/quarry_recon/store.py:620` checks required-key presence,
not value types, schema identity, digest or reconciliation to entity logs. A manifest whose required
summary fields all contain semantically invalid values can satisfy `manifest_committed()`. Settlement's
`_committed()` at `src/quarry_recon/settle.py:345` accepts any dictionary summary rather than using the
store's committed-manifest predicate. Fresh campaign harnesses showed an earlier gapped child can be
followed by a clean/no-progress child and end `fixed_point`, and a ledger can accept contradictory
stop-cause/success combinations.

**Preconditions.** A child manifest is truncated/crafted, a prior child has gaps, a resume observes a
damaged ledger, or terminal fields disagree.

**Acceptance.** One versioned strict parser validates manifest schema, lifecycle, counters, typed summary,
digests and count consistency; every consumer uses it. Campaign outcome folds the complete child history,
never launders a prior unresolved gap, and validates allowed `(cause, success, clean)` combinations.
Kill/restart and corruption tests cover every transition.

### `HEAD-05` — installation, runtime identity and credential isolation

**Status:** `REOPENED`

**Maps to:** `QR39-007`, `QR39-008`, `QR39-017`, `QR39-027`, `QR39-028`, `QR39-042`

**Evidence.** Binary/source installation has staged activation, but `install_one()` explicitly installs
Go/pipx runtimes in place before final identity/capability verification
(`src/quarry_recon/registry.py:651-678`). A failed verification can therefore leave the new active
payload. The Go non-`renameat2` fallback uses sequential moves and has an absent-active interval
(`src/quarry_recon/bootstrap.py:282-290`). Runtime launch still resolves ordinary commands through
`PATH`, and `runner.py:816` inherits the ambient environment. `secrets.py:214-219` exports
`PDCP_API_KEY` globally, allowing unrelated children to inherit it. Mutable helper/template/runtime
closures are not comprehensively attested.

**Preconditions.** Verification fails after in-place installation, activation falls back during a crash,
`PATH` is shadowed, or any third-party child is launched after secrets were loaded.

**Acceptance.** Every installation strategy stages a complete payload plus receipt, verifies it, then
atomically switches a versioned pointer with proven rollback. Launch uses the verified absolute identity
and records its digest. Each adapter receives a minimal environment and only its declared credentials.
Fault injection preserves the previous healthy install at every step.

### `HEAD-06` — aggregate resource governance and honest remainder

**Status:** `REOPENED`

**Maps to:** `QR39-004`, `QR39-005`, `QR39-015`, `QR39-029`, `QR39-030`, `QR39-039`, `QR39-041`

**Evidence.** The store caps each entity independently while `Run._records` retains every materialized
entity; the private large-corpus case exceeds the 100,000-key per-entity envelope. Refusal entries retain only
`entity/key/kind`, not the refused payload/provenance, so they cannot replay the promised work. The free
space reservation in `DiskGovernor` is process-local when no project maximum is active, and
`stream_to_file()` uses a shared `<dest>.part` name (`src/quarry_recon/contract.py:527`).
`resolve_many()` has bounded concurrency but no corpus deadline; 100,000 hung names at 16 workers and a
five-second timeout require about 8.7 hours before overhead.

**Preconditions.** A large corpus crosses an entity envelope, concurrent processes consume one
filesystem reserve/write one destination, or resolution repeatedly times out.

**Acceptance.** Publish an exact supported v0.3.x envelope. Crossing it either persists complete replayable
work or truthfully records terminal evidence loss; it never calls key-only metadata resumable. Resource
reservation and destination ownership are cross-process. Resolver batches have a corpus budget,
efficient queueing, durable remainder and bounded worker teardown. RSS/disk/deadline gates use fixed
small/medium/large fixtures and recorded hardware.

### `HEAD-07` — connect-time self/metadata exclusion

**Status:** `OPEN`

**Maps to:** `QR39-019`; preserves `ADR-039-02`

**Evidence.** `netguard.guard_hosts()` fresh-resolves before invoking an external tool, but an external
process resolves again and indeterminate names are intentionally passed. Native urllib paths similarly
separate policy resolution from connection and may inherit proxies. Direct CIDR lanes can contain scanner
or metadata addresses without passing through the hostname guard.

**Preconditions.** DNS changes between validation and connect, a proxy resolves/redirects differently,
or an authorized CIDR overlaps a locally protected destination.

**Acceptance.** Private targets remain allowed. Known scanner, metadata and declared control-plane
destinations are denied at egress/connect time; approved addresses are bound to the actual connection
while preserving Host/SNI/certificate checks; every redirect is revalidated; proxy policy is explicit;
and direct-IP/CIDR lanes use the same exclusion set.

### `HEAD-08` — truthful, lossless private reports and complete provenance

**Status:** `OPEN`

**Maps to:** `QR39-013`, `QR39-022`, `QR39-034`, `QR39-043`; extends the original reporting scope

**Evidence.** `triage.build()` treats any false/absent `cdn` field as a likely origin and renders
"no CDN -> no WAF" (`src/quarry_recon/triage.py:199,234`) even when positive WAF evidence exists. The
private rich-corpus case contained 24,068 review rows, but `digest.json` omitted 17,010 of them. Shodan CVE/IP,
screenshot target, Nuclei request/response/extraction, Dalfox proof and secret-occurrence relationships
are reduced or lost in normalized/report paths. `_item()` applies configured-secret redaction to local
digest values, contrary to the maintainer's full-fidelity private-report rule. Target-controlled Markdown
is not renderer-escaped. `params.run()` returns at `src/quarry_recon/phases/params.py:2372-2374` when
the Nuclei live set is empty, skipping independent downstream lanes.

**Preconditions.** CDN attribution is absent, evidence contains a configured credential string or Markdown
control text, a finding needs raw proof/relationships, or Nuclei has no live target while other params
work remains.

**Acceptance.** Canonical evidence and private operator reports remain lossless. Quarry-owned credentials
are excluded from operational telemetry by typed construction. Share/AI projections are explicit derived
views. Unknown is never coerced to false; no-WAF/origin assertions require affirmative evidence; every
finding cites stable observation and artifact references; untrusted text is encoded at rendering; and
independent lanes cannot be skipped by another lane's empty input. Aggregate private-corpus oracle checks reconcile
every included/omitted row with a typed reason.

### `HEAD-09` — registry, CI and release professionalism

**Status:** `OPEN`

**Maps to:** `QR39-026`, `QR39-043`, plus release-process gaps not previously assigned a QR39 ID

**Evidence.** Literal-source inspection found `actuator-probe`, `evidence.ownership`, `openapi` and
`ssti-probe` used outside `data/sources.yaml`; `osint.whoxy` is a documented exception. The existing
boundary test does not scan these native evidence/OSINT modules. Thirty-seven direct runner/contract
calls remain frozen behind an allowlist rather than one adapter interface. CI runs only `pytest -m
offline`; it has no full default-suite, lint, type, coverage, security or dependency-integrity gate.
The repository declares MIT in `pyproject.toml` but has no tracked `LICENSE`, and lacks tracked
`SECURITY.md`, `CONTRIBUTING.md` and a changelog/release process.

**Preconditions.** A new source bypasses the registry, a non-offline-marked regression lands, or Quarry is
distributed to external operators/contributors.

**Acceptance.** Every acquisition owner is registry-governed or named by one reviewed exception contract;
the boundary test scans all source packages. CI runs all non-live tests on supported Python versions plus
committed style/type/security/dependency gates. Network isolation is OS-level for release CI. License,
security reporting, contribution and release-integrity documents are tracked.

## Open non-stop-ship backlog retained from QR39

The stop-ship clusters do not erase the rest of the register. Unless a row above explicitly closes it,
`QR39-013` through `QR39-043` remain open at their archived severity and target, including exact profile
schema (`QR39-018`), OOB request-before-mapping durability (`QR39-020`), token entropy (`QR39-021`),
IDNA/URL authority (`QR39-022`), OSINT YAML serialization (`QR39-025`), mutable behavioral data
(`QR39-027`), stale view generation (`QR39-031`), platform claims (`QR39-035`), exact truncation sentinel
(`QR39-036`), regex complexity (`QR39-037`) and dry-run/dead metadata (`QR39-038`). Deferral must appear
in the release ledger; silence is not closure.

## Decision

`v0.3.10` remains a **NO-GO**. Do not change either version string, create a tag, publish a package or
claim high-scale readiness until every in-scope row in the release ledger is closed with post-fix evidence.
The current architecture may evolve through compatibility boundaries; this decision does not authorize a
big-bang rewrite or reduce reconnaissance coverage.
