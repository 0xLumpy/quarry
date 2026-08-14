# Quarry release gates

Status: Phase 0 gate contract. It defines the evidence required to promote a
release; it does not assert that all required runners, thresholds, schemas, or
evidence collectors already exist.

The current `offline-ci` workflow and historical local test runs are useful
observations, but they do not yet satisfy this contract. In particular, the CI
workflow positively selects only tests marked `offline`, the repository still
contains unclassified non-live tests, several professional toolchain gates are
not configured, and `verify-quarry.sh` treats unavailable live prerequisites as
`SKIP`. Quarry therefore begins Phase 0 with the aggregate release status
**open**, not green.

## Principles

- Promotion is based on a machine-readable evidence set bound to one exact
  candidate commit and source-tree digest.
- A missing, skipped, deselected, uncollected, stale, or unparsable required
  result is not a pass.
- A release does not become green by rerunning only a failed test. After a fix,
  the affected gate is rerun in full against the new candidate identity.
- Live-range success never compensates for a failed hermetic invariant.
- A historical corpus characterizes failures; it is not proof that a fresh scan
  is correct or complete.
- Product decisions to run broad active Nuclei, permit private-address reach,
  and default to public Interactsh are not gate failures. Gates verify that the
  selected policy is explicit, reproducible, accurately labelled, and honored.
- No command printed in documentation constitutes evidence. Evidence comes
  from a configured runner that records identity, isolation, inputs, results,
  and artifacts.

## Result vocabulary and aggregation

Every gate has exactly one status:

| Status | Meaning | Promotion effect for a required gate |
|---|---|---|
| `pass` | All declared assertions ran and passed against the candidate; required evidence is valid | Eligible |
| `fail` | At least one assertion ran and failed, or a safety invariant was violated | Blocks |
| `open` | Requirement is defined but its implementation, threshold, fixture, reviewer, or evidence is not yet ready | Blocks |
| `blocked` | The configured gate could not run because an external prerequisite was unavailable | Blocks |
| `not_applicable` | A versioned scope rule, approved before execution, proves the gate does not apply to this candidate | Does not block |

`skipped`, `deselected`, `xfail`, `xpass`, and "no tests collected" are test
runner events, not gate statuses:

- an unexpected skip, deselection, or zero selection makes the gate `open` or
  `fail`, according to whether configuration or behavior is defective;
- a required assertion under `xfail` leaves its gate `open`; an `xpass` is a
  contract drift requiring review, not an automatic pass;
- a missing optional capability may be `not_applicable` only when the release
  scope declared it optional before the run; and
- a waiver cannot turn a failed invariant green. Changing a requirement needs a
  reviewed scope/ADR revision and a new candidate evidence set.

The release aggregate is `pass` only when every required gate is `pass` or
validly `not_applicable`. Any required `fail`, `open`, `blocked`, missing record,
invalid signature, candidate-identity mismatch, or stale result blocks
promotion.

## Exact execution-lane taxonomy

Every collected test and verification job belongs to one primary lane. An
unmarked test is a classification error. Lane enforcement must occur at the OS
boundary as well as inside Python.

| Lane | Permitted dependencies and I/O | Forbidden behavior | Where it runs |
|---|---|---|---|
| `H0-hermetic` | Repository inputs read-only; owner-private disposable output; controlled interpreter and in-test synthetic processes | Internet, DNS, host network, a real target, undeclared host binaries, user home/config, active installs, private corpus | Every PR and release candidate |
| `H1-tool-integration` | Attested real tool binary; synthetic local fixture service in a dedicated namespace; owner-private disposable output | Default route, external DNS, public/private target access, ambient credentials, unpinned `PATH` resolution, host mutation | Release candidate and scheduled tool-compatibility jobs |
| `C0-private-corpus` | A selected private alias from the golden-corpus registry, opened read-only/no-follow; pure import/recovery/derivation/report replay; private disposable output | Network, target rescanning, writing the source, source paths in output, public artifacts, outcome comparison with competitors | Controlled private release runner only |
| `P0-package-supply` | Candidate sdist/wheel and prefetched attested dependencies in a disposable environment/prefix | Network during verification, modifying an active installation, unsigned/unhashed substitution, use of developer checkout as installed package | Release candidate |
| `L0-authorized-live` | Explicit operator authorization, captured scope revision, declared profile, and allowlisted range endpoints | Opportunistic targets, implicit authorization, PR CI, undeclared scope expansion, using live success to waive hermetic failure | Manual or protected scheduled release job only |

`requires_tool` is a capability annotation, not a safety lane. It must accompany
`H1-tool-integration` or another reviewed lane and name an attested tool
identity. It must never cause a required check to disappear silently.

The intended pytest marker correspondence is:

| Marker | Lane rule |
|---|---|
| `offline` | `H0-hermetic` only |
| `integration` | `H1-tool-integration`; no live network |
| `corpus` | `C0-private-corpus`; private runner only |
| `packaging` | `P0-package-supply` |
| `live` | `L0-authorized-live` only |
| `requires_tool` | Secondary annotation; never selected as a standalone lane |

The `corpus` and `packaging` classifications and a complete classification
manifest are not yet configured. Until they exist and every test maps to one
lane, the taxonomy gate is `open`.

### Isolation requirements

`H0` denies network namespace access and subprocess network escape before test
collection. Python monkeypatches are useful tripwires but are not the boundary.
Synthetic child processes may execute only from the controlled test environment
and inherit a minimal environment.

`H1` runs in a network namespace with no default route or external resolver. If
a tool needs TCP/UDP, the only reachable endpoint is the fixture service inside
that namespace. The result records the executable's absolute path, digest,
version output, payload/template digest, and environment allowlist.

`C0` uses the two-pass attestation and replay boundary in
[`GOLDEN-CORPUS.md`](../design/GOLDEN-CORPUS.md). The source is never copied into
CI artifacts. A stale attestation or unavailable private source is `blocked`,
not skipped.

`P0` verifies what users install, not imports from `src/`. Dependency acquisition
may happen in a separate preparation job, but the verification inputs must then
be content-attested and the verification job itself network-denied.

`L0` records authorization, target alias, scope/policy/config digests, start and
end time, source egress identity, and tool corpus identities. Secrets and raw
target evidence remain in the private evidence sink. Whether `L0` is required is
decided by the release-scope matrix before the candidate runs. If required and
the range is unavailable, the gate is `blocked`; if not required, the evidence
record contains the pre-approved `not_applicable` rationale.

## Gate phases

### Phase A: contract and prerequisite closure

These gates make subsequent results interpretable. They must close before a
release candidate can be declared.

| Gate | Requirement | Evidence | Phase 0 status |
|---|---|---|---|
| `A-IDENTITY` | Candidate is one exact commit; source-tree digest, dirty state, submodule/input identities, package version, and schema versions agree | Candidate identity record; dirty candidates fail | `open` — the v1 collector/schema exist, but an enforced quiescent runner and accepted nominated-candidate record do not |
| `A-TAXONOMY` | Every test/job maps to exactly one primary lane; incompatible markers and unmarked tests fail collection | Classification manifest plus collected/selected/deselected counts | `open` — current markers do not cover the complete suite |
| `A-EVIDENCE-SCHEMA` | Gate records validate against a versioned schema and aggregate deterministically | Schema, validator result, aggregator result, canonical digest | `open` — v1 structural schemas/readers exist; artifact verification, signature trust and the deterministic aggregator remain unimplemented |
| `A-CORPUS` | Selected private sources have accepted two-pass attestations and alias mappings; committed fixtures contain synthetic data only | Private attestation IDs plus public fixture and disclosure-check digests | `open` — design exists; attestations/fixtures are not claimed |
| `A-THRESHOLDS` | Versioned correctness, quality, resource, and regression thresholds exist for the release scope | Reviewed threshold manifest | `open` — numeric performance/coverage baselines are not yet accepted |
| `A-SUPPORT` | Supported OS, architecture, Python, and tool/template matrices are finite and versioned | Support matrix digest | `open` — package metadata alone is not a finite tested matrix |

### Phase B: pull-request gates

These are mandatory on every change and run only in `H0-hermetic`.

| Gate | Type | Requirement | Machine evidence |
|---|---|---|---|
| `B-HERMETIC-ALL` | Functional/quality | Every `H0` test is collected and passes on the declared Python matrix; no unexpected skip/deselection/xfail/xpass; network-denial self-tests pass | Per-interpreter test report, collection manifest, isolation self-test, logs and digests |
| `B-SCHEMA` | Schema | Typed records and JSON schemas round-trip exactly; reject unknown/malformed values as specified; old supported fixtures migrate explicitly | Schema-validation report by schema/version and fixture digest |
| `B-MANIFEST` | Functional | Lifecycle, verdict, counts, digests, revisions, coverage, gaps, faults, and remainders satisfy semantic—not merely shape—validation | Invariant/property-test report and corrupt-fixture matrix |
| `B-QUALITY` | Quality | Formatting, lint, type, documentation/reference parity, dead-code policy, and complexity budgets meet the accepted threshold manifest | Tool identities/config digests and machine reports |
| `B-COVERAGE` | Quality | Line/branch coverage meets versioned repository and critical-module thresholds and does not regress beyond the allowed delta | Coverage data tied to collected test identities and threshold manifest |
| `B-STATIC-SECURITY` | Security | Secret scan, static security rules, unsafe API inventory, archive/path/config fuzz properties, and dependency-manifest checks pass | Findings in a stable machine format with suppression IDs and expiry |
| `B-DETERMINISM` | Functional | Canonical serializers, synthetic fixture generation, reports, manifests, and derived views are byte-stable across two isolated runs | Paired artifact tree digests and structured diff |
| `B-DOCS-POLICY` | Professionalism | CLI/help/config/schema/source registry and policy labels agree; broad Nuclei, private reach, and public Interactsh choices are stated accurately | Generated parity report and policy/config digest |

At Phase 0 these gates are `open` as release gates even when constituent tests
already pass locally, because the complete selection, isolation, threshold, and
machine-evidence contracts have not been configured.

### Phase C: release-candidate gates

These run for the exact candidate after Phase B is green.

#### Package and supply chain

| Gate | Lane | Requirement | Machine evidence |
|---|---|---|---|
| `C-PACKAGE-BUILD` | `P0` | Clean sdist/wheel build; package metadata and version agree; required data, license, notices, schemas, and entry points are present | Artifact inventory and digest, metadata validation, build log |
| `C-PACKAGE-INSTALL` | `P0` | Install into a clean disposable prefix and exercise public imports/CLI from the installed artifact, never the checkout | Install inventory, import/CLI results, environment identity |
| `C-PYTHON-MATRIX` | `P0`/`H0` | Oldest and every stable Python minor satisfying the published metadata pass required gates | Matrix records; any missing advertised interpreter is `blocked` |
| `C-SBOM` | `P0` | Complete direct/transitive dependency and bundled-tool/template inventory, with licenses and content identities | SBOM digest and inventory reconciliation report |
| `C-VULNERABILITY` | `P0` | Dependency/container/tool advisories meet the reviewed disposition policy; exceptions are explicit, owned, and time-bounded | Scanner DB timestamp, findings, signed dispositions |
| `C-PROVENANCE` | `P0` | Release artifacts bind source candidate, builder identity, inputs, dependencies, and subjects; signatures/digests verify | Provenance and signature verification report |
| `C-INSTALL-ROLLBACK` | `H1`/`P0` | Failure at every acquisition/verification/activation point preserves the last-known-good install and never exposes a partial active version | Fault matrix, before/after identities, filesystem trace |

#### Tool integration and compatibility

| Gate | Lane | Requirement | Machine evidence |
|---|---|---|---|
| `C-TOOLS` | `H1` | Every required adapter runs against a synthetic fixture with its attested supported binary/payload identity; optional absence is reported honestly | Adapter/tool matrix, raw/result classification, identities |
| `C-OUTPUT-CONTRACT` | `H1` | Empty, non-empty, malformed, truncated, non-UTF-8, partial, timeout, signal, and tool-specific exit cases map to the documented result contract | Case matrix and typed result records |
| `C-NETWORK-BOUNDARY` | `H1` | Scope, IDNA, redirect, DNS rebinding, proxy, private-reach, scanner-self, and metadata exclusions hold at connect time | Namespace trace plus allow/deny decision records |
| `C-SOURCE-REGISTRY` | `H0`/`H1` | Every acquisition lane and emitted source ID is registered with ownership, policy, input/output schema, and coverage semantics | Static/runtime registry reconciliation report |

#### Private corpus replay

| Gate | Lane | Requirement | Machine evidence |
|---|---|---|---|
| `C-CORPUS-ATTEST` | `C0` | Each selected alias passes pre- and post-replay two-pass identity verification | Private attestation records and opaque pass references |
| `C-CORPUS-RICH` | `C0` | `quarry-complete-rich` imports within the declared envelope and detects historical count/manifest/report inconsistencies without silently repairing source data | Structured assertions, resource metrics, derived-output digest |
| `C-CORPUS-INTERRUPTED` | `C0` | `quarry-interrupted-events` is recognized as non-final; recovery/reporting is idempotent, truthful, and does not rescan | Lifecycle/fault/recovery records and paired derivation digests |
| `C-CORPUS-LEGACY` | `C0` | `quarry-complete-legacy` is parsed or migrated through an explicit supported path | Migration decision, schema results, output digest |
| `C-CORPUS-ORPHAN` | `C0` | `quarry-orphan-no-metadata` receives a deterministic orphan/recovery disposition without guessing paths or completion | Disposition record and repeat-run digest |
| `C-CORPUS-EVOLUTION` | `C0` | The private `quarry-evolution-legacy` pair produces an explicit schema/field evolution report | Versioned structural delta; no quality/yield score |
| `C-CORPUS-SYNTHETIC` | `H0` | Two isolated fixture derivations are byte-identical; schema/disclosure checks prove only inventoried synthetic secrets and identities are committed | Tree digests, schema report, synthetic-value inventory, disclosure report |

Stored BBOT/reconFTW output has no release-outcome gate. Only synthetic shape
fixtures derived under the golden-corpus contract may participate in `H0` parser
or relationship tests.

#### Security invariants

| Gate | Lane | Requirement | Machine evidence |
|---|---|---|---|
| `C-PRIVATE-FILES` | `H0`/`H1` | New and existing sensitive roots/files reject symlinks, wrong owner, and unsafe modes; creation is private from the first descriptor operation under tested umasks | Mode/owner/symlink matrix and filesystem trace |
| `C-PATH-IDENTITY` | `H0` | Project/run/tool/artifact identifiers cannot traverse, alias, or escape roots; reserved namespaces and symlinks are excluded | Property/fuzz corpus and containment decisions |
| `C-SECRETS` | `H0`/`H1` | Quarry credentials enter only per-tool allowlisted environments and never appear in telemetry, reports, crash data, or release evidence; target evidence remains lossless only in private evidence | Canary matrix and sink scan using synthetic credentials |
| `C-EXEC-IDENTITY` | `H1` | Runtime executes the verified absolute tool/payload/template identities and records them; `PATH` substitution fails closed | Launch trace and receipt/digest reconciliation |
| `C-ARCHIVE-FETCH` | `H0`/`H1` | Redirects, archives, payload closures, permissions, expansion, links, and atomic activation obey the fetch/install contract | Adversarial fixture matrix and activation trace |
| `C-NET-DENY` | `H0`/`C0`/`P0` | Each supposedly network-free lane proves that socket, resolver, subprocess, proxy, and native-tool escape attempts are denied | OS-boundary self-test report for every runner image |
| `C-POLICY-TRACE` | `H0`/`H1` | Every executed, omitted, refused, or bounded work unit has a typed policy/coverage record; accepted aggressive defaults are reproducible | Obligation-to-decision reconciliation report |

#### Fault and recovery matrix

Every fault gate injects failures before, during, and after the relevant commit
boundary. A result is not green merely because the process exits.

| Gate | Required scenarios | Required invariant |
|---|---|---|
| `C-FAULT-RUNNER` | Blocked/escaped stdout and stderr holders, sink write failure, output cap, disk full, invalid bytes, timeout, signal, empty command, cancellation | No success before every evidence drain commits; bounded return; explicit incomplete/fault result |
| `C-FAULT-STORE` | Write, flush, fsync, rename, manifest, event-sink, and reopen failures | No unmanifested success; finished base rejects every mutation API; recoverable work is durable |
| `C-FAULT-REVISION` | Crash at every stage/hash/certify/pointer boundary; corrupt counts/digests; multiple entity revisions | Last certified pointer remains active; complete effective view validates; base evidence stays immutable |
| `C-FAULT-FINALIZE` | Failure of each derived view/report before and after base commit; restart at every lifecycle transition | Base commit survives; state is honest; retry is idempotent and requires no rescan |
| `C-FAULT-CAMPAIGN` | Kill/restart at lease/child/settle/union boundaries; earlier gap followed by no-progress child; malformed summary/ledger | Historical gaps persist; terminal cause/success is semantic; no false fixed point |
| `C-FAULT-INSTALL` | Download, extract, verify, payload, receipt, privilege, lock, and activation failure | Last-known-good installation remains active; no partial or unverified executable can launch |
| `C-FAULT-DISK` | Concurrent processes, exhausted reserve, same destination, partial writes, spill failure | Aggregate reservation holds; destination has one owner; bounded partial/remainder is truthful |
| `C-FAULT-RESOLVER` | Hung resolver, late response, worker crash, huge corpus, cancellation | Outstanding work/processes and total deadline are bounded; late results cannot mutate sealed state |
| `C-FAULT-INTERRUPT` | Interrupt at every externally visible transition | Exit/result precedence is deterministic; committed evidence remains readable; resumption is explicit |

#### Performance and scale matrix

Performance claims require a versioned benchmark manifest. It identifies the
fixture digest, operation, concurrency, warmup/repetition rule, CPU/memory/disk
limits, host or runner class, tool identities, and both absolute and regression
thresholds. Until numeric thresholds are reviewed, each performance gate is
`open`; descriptive measurements cannot close it.

| Gate | Measurement | Required threshold classes |
|---|---|---|
| `C-PERF-RUNNER` | Binary stdin/stdout/stderr streaming under slow consumer, large output, timeout, and cancellation | Peak aggregate RSS, wall deadline plus grace, disk bytes, FD/process cleanup, evidence-byte equality |
| `C-PERF-INGEST` | Small/medium/large typed-observation ingestion, reopen, merge, and export | Aggregate RSS—not per-entity only—wall time, write amplification, disk growth, refused/remainder count |
| `C-PERF-REPORT` | Report and projection generation over the accepted large synthetic/private selection | Peak RSS, bounded artifact size, wall time, deterministic output, observation coverage |
| `C-PERF-CAMPAIGN` | Multi-child settle/union/decision processing | Peak RSS/disk, decision latency, no full-corpus duplication beyond budget |
| `C-PERF-DISK` | Multiple concurrent governors and writers | Global reserve never crossed, bounded overshoot, fairness, no destination corruption |
| `C-PERF-RESOLVER` | Large mixed fast/hung input corpus | Corpus deadline, bounded worker/process count, bounded outstanding queue, durable remainder |
| `C-PERF-PHASE-FAIRNESS` | Broad Nuclei plus independent high-signal lanes under a finite run budget | Each declared obligation starts or records an explicit terminal/remainder reason; no silent starvation |

Raw trial records are retained. The aggregate reports median and tail behavior
according to the accepted benchmark manifest; it never drops an outlier without
a machine-recorded invalidation reason and rerunning the complete trial set.

### Phase D: conditional authorized-live gates

Live checks exist to validate real protocol/tool interaction on an explicitly
owned range. They are not part of PR CI and must never execute because a default
domain happened to be configured.

| Gate | Requirement | Evidence |
|---|---|---|
| `D-AUTHORIZATION` | Human-approved range alias, time window, scope revision, allowed techniques, egress identity, and maximum rates/concurrency | Signed/approved authorization record bound to the candidate run |
| `D-RANGE-IDENTITY` | The resolved endpoints and service certificates/content match the owned range attestation before active work | Preflight identity and DNS/address records |
| `D-LIVE-CONTRACT` | In-scope live scenarios exercise only the release-scope matrix and preserve full private evidence/coverage decisions | Private run manifest, exact tool/template identities, scenario results |
| `D-CLEANUP` | OOB sessions, temporary credentials, callbacks, leases, and range mutations are closed or explicitly handed off | Cleanup/retention record |

If no approved scope rule requires Phase D for a candidate, these gates are
`not_applicable` with that rule's digest. If Phase D is required and its range,
tool, or authorization is unavailable, it is `blocked`. A script-level `SKIP`
never closes it.

### Phase E: publication gate

The publication decision is a separate, reproducible aggregation step:

| Gate | Requirement |
|---|---|
| `E-AGGREGATE` | Every required Phase A-D record is present, authentic, schema-valid, candidate-matched, and `pass`/valid `not_applicable` |
| `E-DOCS` | Release notes enumerate behavioral changes, accepted risks, known limitations, migrations, exit/result contract, and supported matrix |
| `E-PROJECT-HYGIENE` | License file, security policy, contribution guidance, changelog, and vulnerability-reporting route are present and package-consistent |
| `E-ARTIFACTS` | Published package, SBOM, provenance, signatures, schemas, and checksums match the candidate evidence subjects |
| `E-APPROVAL` | Named release approver reviews the aggregate and signs the decision; approver cannot overwrite underlying gate results |

No tag or version bump precedes `E-AGGREGATE`. If an artifact is rebuilt after
approval, its subject digest changes and the candidate must repeat every gate
whose inputs include that artifact.

## Machine-readable evidence

The committed v1 candidate-identity, schema-registry and gate-record contracts
are in [`release/evidence`](../../release/evidence/). Their strict reader and
clean-Git identity collector are implemented in
[`release_evidence.py`](../../src/quarry_recon/release_evidence.py). These are a
prerequisite slice, not accepted gate evidence: they do not verify signatures,
open and rehash content-addressed artifacts, aggregate a required gate set or
resolve the nominated-candidate/package-version lifecycle. `A-IDENTITY`,
`A-EVIDENCE-SCHEMA` and `RG00` therefore remain open.

The v1 registry is scoped only to release `0.3.10` and binds its corresponding
scope ledger. The collector and reader refuse any other release label; a later
release requires its own explicit registry/scope contract rather than reusing
the v0.3.10 input under a different label.

Candidate identity hashes the exact committed source independently of checkout
metadata. `quarry.git-tree-sha256.v1` domain-separates the hash and frames each
tracked entry's raw Git path, mode and type followed by its exact blob bytes;
gitlinks contribute their exact commit object ID. Entries are ordered by raw
path. Only canonical Git blob modes (`100644`, `100755`, `120000`) and gitlink
mode/type (`160000 commit`) pairs enter the digest; absolute, empty-component,
`.` and `..` paths are refused. The tree is derived from the captured commit,
never from a second `HEAD` lookup. Within a runner-supplied quiescent
candidate-only epoch, collection refuses staged, unstaged,
non-ignored untracked,
changed-HEAD, changed-submodule and uninitialized-submodule state before it
returns. Index entries marked `assume-unchanged`, `skip-worktree` or another
non-canonical visibility state are refused rather than trusted as clean, both
in the superproject and in every recorded recursive submodule checkout. Each
Git-reported worktree root must also equal that expected resolved checkout;
the top-level root must contain the requested candidate location, and repository
metadata cannot redirect a cleanliness check elsewhere. The absolute Git
directory observed at the requested location must be the same directory
observed from the resolved root, preventing a nested repository from redirecting
the collector to an ancestor worktree.
Ignored paths are outside the candidate and cannot be declared as candidate
inputs; candidate inputs are read from committed blobs, never ambient checkout
bytes. A dirty checkout is refused before nomination rather than represented by
a candidate record; the aggregate consequently blocks on a missing valid
identity instead of treating `dirty: true` as evidence.

The exact tree preimage begins with the NUL-terminated ASCII domain
`quarry.git-tree-sha256.v1`. For every entry in ascending raw-path byte order it
then appends four frames—path, ASCII mode, ASCII type and payload—where each
frame is an unsigned eight-byte big-endian length followed by that many bytes.
Payload is the exact blob body, or the lowercase ASCII full commit object ID for
a gitlink. The committed golden vectors in `test_release_evidence.py` freeze
both blob and gitlink behavior. Canonical release runs must materialize the
captured committed tree in a candidate-only environment; they may not execute
the ambient checkout where ignored files could influence imports, config or
tools. A portable userspace scan cannot itself freeze an arbitrary worktree:
the collector's repeated comparisons detect changes they observe but do not
establish the required isolation epoch. Output collected without an enforced
quiescent runner is structural diagnostic data, not `A-IDENTITY` evidence. The
collector requires an absolute runner-attested Git executable path;
the eventual scope manifest must assign `A-IDENTITY` an execution lane and its
gate record must bind that executable's path-independent digest, version and
runtime identity. The collector supplies only `PATH`, C locale, UTC and its
fixed read-only Git controls to the child; it does not forward `HOME`, loader,
credential or other ambient variables. This minimal environment and absolute
argv also disable repository fsmonitor, `core.ignoreStat` and the untracked
cache for collector queries, and restore default ctime/stat checking; POSIX
collection additionally forces file-mode and symlink checks on. They do not
replace the future runner's executable/runtime-closure attestation, and an
ambient `git` lookup is not eligible as release evidence.

For each superproject/submodule checkout, raw index entries must equal the
captured tree and the non-ignored untracked-name query must be empty. The
collector then opens the actual worktree without Git filters and compares every
committed byte, file type, executable mode and symlink target to its committed
blob. It never invokes a configured clean/smudge filter and never replaces or
refreshes the candidate's real index.

Evidence JSON is strict UTF-8 with duplicate members and non-finite numbers
refused. RFC3339 evidence timestamps require offset hours from 00 through 23
and minutes from 00 through 59, and reject the unknown-local-offset spelling
`-00:00`. Canonical bytes use sorted object keys, compact separators,
unescaped Unicode and no trailing newline in the digest preimage; CLI output
adds one newline as a record delimiter. Arrays retain their contract-defined
semantic order. `quarry.release-evidence.canonical-json.v1` domain-separates
canonical record digests. The v1 gate signature member is only a structural
envelope; until an accepted trust policy and verifier exist, its presence is
not an authenticity claim.

The canonical-record digest preimage is the NUL-terminated ASCII domain
`quarry.release-evidence.canonical-json.v1` followed immediately by the JSON
bytes. Object keys sort by Python Unicode code-point order; strings are not
Unicode-normalized. Records are limited to 1 MiB, 64 nested levels and exact
integers in the inclusive range `-(2^63-1)` through `2^63-1`. A committed
non-ASCII golden vector freezes these v1 choices.

The checked-in JSON Schemas define the portable structural envelopes; the
Python reader additionally enforces path normalization, exact types, ordering,
uniqueness, count reconciliation, status semantics and exact identity binding.
There is not yet an accepted JSON-Schema engine/parity result. Likewise,
`validate candidate` validates a supplied record but does not recompute it from
a repository, while `validate gate --identity` proves structure and embedded
identity agreement only. It does not prove known-gate membership, requiredness,
artifact bytes, signature authenticity or promotion eligibility. Its printed
digest is a content identity, not an acceptance decision; those checks belong
to the still-missing scope manifest, artifact verifier and aggregator.

Each gate eventually emits one canonical record. The v1 gate schema preserves
at least the following structure:

```json
{
  "schema_version": "quarry.release-gate.v1",
  "release": "0.3.10",
  "candidate": {
    "git_commit": "<full-object-id>",
    "git_tree": "<full-object-id>",
    "source_tree_digest": "sha256:<digest>",
    "dirty": false,
    "package_version": "<version>",
    "identity_digest": "sha256:<candidate-identity-record-digest>"
  },
  "gate_id": "C-FAULT-RUNNER",
  "lane": "H0-hermetic",
  "required": true,
  "status": "open",
  "started_at": "<RFC3339 timestamp>",
  "finished_at": "<RFC3339 timestamp>",
  "environment": {
    "runner_image": "sha256:<digest>",
    "os": "<id>",
    "architecture": "<id>",
    "python": "<exact version>",
    "isolation_profile": "sha256:<digest>"
  },
  "inputs": [
    {"name": "threshold-manifest", "digest": "sha256:<digest>"}
  ],
  "toolchain": [
    {"name": "pytest", "path": "/absolute/attested/pytest", "version": "<version>", "digest": "sha256:<digest>"}
  ],
  "selection": {
    "collected": 0,
    "selected": 0,
    "passed": 0,
    "failed": 0,
    "skipped": 0,
    "deselected": 0,
    "xfailed": 0,
    "xpassed": 0
  },
  "assertions": [],
  "artifacts": [
    {"name": "results", "media_type": "application/json", "digest": "sha256:<digest>"}
  ],
  "reason": "prerequisite not configured",
  "not_applicable_rule": null,
  "signature": null
}
```

The placeholder values illustrate the contract and are not a real gate result.
Private evidence may encode opaque corpus references only through the existing
named input/artifact digest records; it never records source paths or target
values. Operational logs must exclude Quarry-owned credentials;
emitters and the still-open disclosure gates enforce that requirement. Evidence
artifacts must be content-addressed; the eventual
aggregate must include their digests and reject an artifact that cannot be
opened and rehashed.

The aggregator must have hermetic tests for every status, missing record,
duplicate gate, wrong candidate, malformed schema, invalid signature, expired
disposition, unexpected skip, and conflicting result. Its output must contain
the ordered gate set, decision, reasons, and aggregate digest.

## Current Phase 0 closure order

The immediate work is prerequisite closure, not running aspirational commands:

1. accept the candidate identity, gate-evidence, lane-classification, support,
   and threshold schemas;
2. classify the complete existing test collection and remove documentation/
   marker contradictions;
3. implement OS-enforced `H0` isolation and the machine evidence collector;
4. attest the selected private corpora and create only the necessary synthetic
   committed fixtures;
5. establish numeric quality and resource baselines without marking them pass;
6. wire Phase B and C runners in disposable environments; and
7. execute a full candidate evidence set only after those prerequisites are
   reviewable.

Until a step is implemented and its evidence validates, its gate remains
`open`. Phase 0 success is an honest, executable gate system—not a document that
labels missing verification as green.
