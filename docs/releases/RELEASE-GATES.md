# Quarry release gates

Status: Phase 0 gate contract. It defines the evidence required to promote a
release; it does not assert that all required runners, thresholds, schemas, or
evidence collectors already exist.

The current `offline-ci` workflow and historical local test runs are useful
observations, but they do not yet satisfy this contract. Pytest rejects any node
without exactly one primary lane and the CI job positively selects the complete
structural `H0` classification, but the CI deny guard is not OS containment.
The separate Linux development runner can now bind an exact candidate, job map
and isolation profile while collecting H0 behind bubblewrap, but it is
deliberately non-authoritative and uses an untrusted host runtime. No accepted
candidate-bound gate record exists. Several professional toolchain gates are
also not configured, and `verify-quarry.sh` treats unavailable live
prerequisites as `SKIP`. Quarry therefore begins Phase 0 with the aggregate
release status **open**, not green.

## Principles

- Promotion is based on a machine-readable evidence set bound to one exact
  candidate commit and source-tree digest.
- The nominated candidate contains the final package version plus the frozen
  scope and validation inputs. Results produced by evaluating that candidate
  live outside its tracked tree as immutable, content-addressed attestations.
- Release evidence is a forward-only object graph: scope and candidate precede
  identity, gate records and artifacts; those precede aggregation, approval,
  tagging and publication. A mutable locator or documentation edit is never an
  evidence identity.
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

The contract universe has 64 obligations. The accepted corpus manifest selects
`S`, a subset of the seven `C-CORPUS-*` gates, so a candidate scope contains
`57 + |S|` obligations and `55 + |S|` pre-aggregate record slots. Each
scope-selected obligation has exactly one status. `E-AGGREGATE` is the
deterministic aggregation operation and output, and `E-APPROVAL` is the later
detached approval; neither occupies a gate-record slot:

| Status | Meaning | Promotion effect for a required obligation |
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

The aggregate payload's decision is `pass` only when every scope-selected
pre-aggregate record is `pass` or validly `not_applicable`. Any selected record
obligation with `fail`, `open`, `blocked`, a missing record, an invalid
signature, a candidate-identity mismatch or a stale result blocks aggregation
and promotion. The later detached approval establishes `E-APPROVAL`; it is not
an aggregate input, but its absence or invalidity still blocks promotion.

## Exact execution-lane taxonomy

Every collected test and verification job belongs to one primary lane. An
unmarked test is a classification error. Classification fails closed in the
collector and accepted job map; each lane's I/O boundary must additionally be
enforced by the OS, not only inside Python.

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

The pytest marker correspondence is now structurally enforced:

| Marker | Lane rule |
|---|---|
| `offline` | `H0-hermetic` only |
| `integration` | `H1-tool-integration`; no live network |
| `corpus` | `C0-private-corpus`; private runner only |
| `packaging` | `P0-package-supply` |
| `live` | `L0-authorized-live` only |
| `requires_tool("name")` | Secondary named capability; H1/P0 only and never selected as a standalone lane |
| `synthetic_process` | Secondary H0-only annotation for the constrained current-interpreter child shape |

At source `19ab50cbdc2415c78e9bb5651dec2e072bb3a71b` (Git tree
`8311829d62be4b7099979e2c0e2f476c2f94fc34`), collection-time validation accounts for all 7,867 pytest
nodes before deselection: 7,796 H0 and 71 H1, with zero C0/P0/L0 nodes and 40 H0 synthetic-process
nodes. Every H1 node carries stable `requires_tool("name")` capabilities. Of those 71 H1 nodes, 53 are
shell/coreutils-backed migration debt; the remaining 18 are Git or bwrap integrations.

The canonical H0-selection `quarry.pytest-taxonomy.v1` diagnostic, produced by CPython 3.13.12 and pytest
9.0.3, has raw-file SHA-256
`732f26bfb49c48ad2bce556d782d43b3952b9dd1b661e5312a30705994c0938b`. The committed development runner
privately exported the exact committed candidate with source-tree digest
`sha256:53e5c9d77e9e234873b44cabbb219652abdf69dc6a0b2b12977d37a108ba8209`, bound the formal job map and
development profile, and performed this collect-only selection behind its bubblewrap boundary. Its
summary has raw-file SHA-256 `9e52b4761325961ca7bbed8d60f2d1c4163163100cee3be61ec06b5c887ad97f`.

This is an exact structural and isolation observation, not a release record. The package is non-nominated
`0.3.9`; the mounted development-host `/usr` runtime is untrusted, its executable dependency closure is
incomplete, and the runner executes no tests. The summary declares `authority: none`,
`promotion_eligible: false`, and `A-TAXONOMY` `open`. No evidence slot is populated; `A-TAXONOMY` remains
`open`, and `RG00` remains `OPEN`.

### Isolation requirements

For release evidence, `H0` denies network namespace access and subprocess
network escape before test collection. Python monkeypatches are useful
tripwires but are not the boundary. The current CI guard blocks ordinary Python
network/subprocess entry points, and `synthetic_process` permits only a
constrained absolute current-interpreter child with a minimal environment. It
does not contain that child's own network APIs.

The committed Linux development runner adds a blank-root bubblewrap boundary,
unshared namespaces, empty capabilities, an exact cleared environment, a
read-only candidate export and read-only `/usr`, isolated `/dev`, read-only
`/proc`, and a private read-write work mount. Its successful diagnostic reported
every inner isolation check true. This is a collection-only development
boundary: it has no seccomp profile, trusts no complete runtime image or
dependency closure, emits no gate record, and cannot promote a candidate. An
accepted release runner must retain the isolation properties, execute the
required selection in an attested runtime, and bind its profile and results to
the gate record.

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
nominated commit can be accepted as the release candidate. Creating a
nomination commit is not promotion and closes none of these gates.

| Gate | Requirement | Evidence | Phase 0 status |
|---|---|---|---|
| `A-IDENTITY` | Candidate is one exact commit; source-tree digest, dirty state, submodule/input identities and schema versions agree, and both package-version sources equal the nominated release | Candidate identity record; dirty candidates fail collection and a release/package-version mismatch blocks this gate | `open` — the v1 collector/schema and private exact-commit development runner exist, but no trusted release runtime or accepted nominated-candidate record exists |
| `A-TAXONOMY` | Every test/job maps to exactly one primary lane; incompatible markers and unmarked tests fail collection | Classification manifest plus collected/selected/deselected counts | `open` — exact-one enforcement, the formal job map and a candidate-bound collect-only diagnostic exist, but no accepted nominated-candidate classification gate record exists |
| `A-EVIDENCE-SCHEMA` | Gate records validate against a versioned schema and the aggregator conforms deterministically to the committed fixed conformance manifest | The candidate-independent manifest plus a candidate-bound report that binds its exact test source/node, paired positive aggregate digests, normalized refusal digests, and gate-evidence counts; this is not the candidate release aggregate | `open` — the v1 manifest/report schema and semantic reconciliation exist, but an accepted nominated-candidate report has not been collected |
| `A-CORPUS` | The selected corpus has a frozen synthetic fixture identity and a candidate-independent disclosure attestation; private aliases/two-pass attestations are required only when a private source is selected | Public fixture and disclosure-attestation digests; private attestations remain private | `open` — A/C semantic reconciliation exists, but the accepted fixture and attestation digests are not populated |
| `A-THRESHOLDS` | Versioned correctness, quality, resource, and regression thresholds exist for the release scope | Reviewed threshold manifest | `open` — numeric performance/coverage baselines are not yet accepted |
| `A-SUPPORT` | Supported OS, architecture, Python, and tool/template matrices are finite and versioned | Support matrix digest | `open` — package metadata alone is not a finite tested matrix |

### Phase B: pull-request gates

These are mandatory on every change and run only in `H0-hermetic`.

| Gate | Type | Requirement | Machine evidence |
|---|---|---|---|
| `B-HERMETIC-ALL` | Functional/quality | Every `H0` test is collected and passes on the declared Python matrix; no unexpected skip/deselection/xfail/xpass; network-denial self-tests pass | Per-interpreter test report, collection manifest, isolation self-test, logs and digests |
| `B-SCHEMA` | Schema | The formal `release_evidence` v1 registry (`candidate_identity`, `gate_record`, and `schema_registry`) round-trips its committed fixtures exactly and rejects unknown versions, unknown members, and malformed values. The v1 supported-legacy-migrations roster is explicitly empty; any future supported migration must be added to that frozen roster. Standalone owner schemas remain verified by their owner-gate contracts. | Candidate-bound schema-validation report binding the exact signed H0 instance, frozen registry, and committed fixture digests |
| `B-MANIFEST` | Functional | Run manifests, revision overlays/pointers, and campaign terminal/history satisfy semantic—not merely shape—validation. Report projections and crash/fault durability are separate gates. | Candidate-bound invariant report and corruption-refusal matrix, each tied to one signed H0 instance and frozen source/material bytes |
| `B-QUALITY` | Quality | Formatting, lint, type, documentation/reference parity, dead-code policy, and complexity budgets meet the accepted threshold manifest. `quality-policy-v1.json` freezes the six local commands, source rosters, exit semantics and non-regression ceilings: a clean check exits `0`; a retained finding exits the frozen Ruff finding code `1`. Its current nonzero Ruff ceilings record existing findings rather than a passing release threshold. | One candidate-bound quality report with retained machine findings, signed tool identities and the exact H0 instance |
| `B-COVERAGE` | Quality | Line/branch coverage meets versioned repository and critical-module thresholds and does not regress beyond the allowed delta | Coverage.py 7.15.4 collects the existing Python 3.12 H0 shards with distinct job contexts; compact report verification binds source roster, branch/line totals, H0 fragments, and the threshold manifest. This is a local/CI measurement substrate only: accepted baseline, numeric limits, and H0 isolation remain open. |
| `B-STATIC-SECURITY` | Security | Python 3.12 H0 shard 0 emits one raw Bandit HIGH/HIGH, tracked-file detect-secrets, AST unsafe-API and named archive/path/config property-test fragment; a later candidate-bound report must reconcile its exact fragment, reviewed exceptions and dependency manifest. This does not run P0 dependency auditing. | Stable findings and suppression IDs/expiry; `unsuppressed_findings` remains null/open, so this substrate does not claim acceptance. |
| `B-DETERMINISM` | Functional | Canonical serializers, synthetic fixture generation, reports, manifests, and derived views are byte-stable across exactly two isolated runs | Retained paired file/tree manifests and a candidate-bound structured diff; `artifact_differences` is exactly zero |
| `B-DOCS-POLICY` | Professionalism | CLI/help/config/schema/source registry and policy labels agree; broad Nuclei, private reach, and public Interactsh choices are stated accurately | Candidate-bound parity report: fixed passing test roster, raw test/material digests, and one signed H0 instance |

At Phase 0 these gates are `open` as release gates even when constituent tests
already pass locally, because accepted full-suite execution, release-runtime,
threshold, and machine-evidence contracts have not been configured.

`B-DOCS-POLICY` therefore remains `open` until its candidate-bound report is
accepted from an H0-hermetic evidence instance; a locally passing parity suite
does not close the gate.

`B-MANIFEST` has local semantic/corruption substrate tests, but remains `open`
until its candidate-bound reports are accepted from an H0-hermetic evidence
instance. This checkpoint does not claim report-projection or crash-durability
closure.

### Phase C: release-candidate gates

These run for the exact candidate after Phase B is green.

The source verifier strictly checks retained collector-produced evidence bytes,
including the `C-PACKAGE-BUILD` clean-build log. CI's captured build output is
diagnostic input only: a trusted P0 collector must assemble, index, and sign a
candidate record externally. That collector and production signing authority
remain open; these checks do not close the release gate.

#### Package and supply chain

| Gate | Lane | Requirement | Machine evidence |
|---|---|---|---|
| `C-PACKAGE-BUILD` | `P0` | Clean sdist/wheel build; package metadata and version agree; required data, license, notices, schemas, and entry points are present | Artifact inventory and digest, metadata validation, build log |
| `C-PACKAGE-INSTALL` | `P0` | Install into a clean disposable prefix and exercise public imports/CLI from the installed artifact, never the checkout | Install inventory, import/CLI results, environment identity |
| `C-PYTHON-MATRIX` | `P0`/`H0` | Oldest and every stable Python minor satisfying the published metadata pass required gates. Every accepted H0/P0 support environment binds its exact B-HERMETIC-ALL or C-PACKAGE-BUILD/C-PACKAGE-INSTALL evidence instance; the report separately rehashes the shared candidate package/install source artifacts | One candidate-bound `quarry.python-matrix-report.v1`, which binds and parses the exact package metadata range; any missing or substituted environment, run, source instance or artifact is `blocked` |
| `C-SBOM` | `P0` | Three raw installed-runtime observations, one for each accepted P0 Python 3.10/3.11/3.12 environment, are merged into a candidate-bound direct/transitive dependency and bundled-tool/template inventory with licenses and content identities | Three raw observation records plus the merged candidate-bound SBOM digest and inventory reconciliation report |
| `C-VULNERABILITY` | `P0` | Three retained `pip-audit` observations of the exact resolved non-root C-SBOM dependency closure are reconciled with their matching C-SBOM environments. A pass additionally requires a trusted, fresh database snapshot attestation that covers dependency, container, tool, and template subjects; exceptions are explicit, owned, approved, and time-bounded. | Three raw observation wrappers (exact stdout/stderr/status and argv), candidate findings/dispositions, and the provider attestation |
| `C-PROVENANCE` | `P0` | The releasable sdist/wheel subjects bind source candidate and the exact trusted P0 builder execution; namespaced materials bind the validated build/install reports, final SBOM graph/observations, and vulnerability/provider evidence; signatures/digests verify | Provenance and signature verification report |
| `C-INSTALL-ROLLBACK` | `H1`/`P0` | Failure at every acquisition/verification/activation point preserves the last-known-good install and never exposes a partial active version | Fault matrix, before/after identities, filesystem trace |

The CI package matrix emits one raw C-SBOM observation per P0 Python
environment and uploads that observation once for the matrix job. A trusted
release collector must bind all three raw observations to their exact accepted
P0 evidence instances and merge them into the candidate-bound C-SBOM. The
accepted P0 runtime and signing evidence remain `OPEN`; CI observations are
inputs and do not close the gate.

The same one `pip-audit --strict --no-deps --disable-pip -r /dev/stdin`
invocation per P0 row audits the exact, sorted non-root dependency closure
derived from that row's C-SBOM observation. Its bounded C-VULNERABILITY wrapper
contains the canonical input roster plus exact CycloneDX stdout, stderr, exit
status, scanner argv, and C-SBOM subject. It is source substrate only: pip-audit output supplies neither a
trusted database snapshot nor current freshness; an independent release
vulnerability authority must return explicit advisory results for every P0
runner-image, tool, and template subject. Until a trusted collector provides that
attestation, this gate and `RG02` remain `OPEN`.

#### Tool integration and compatibility

| Gate | Lane | Requirement | Machine evidence |
|---|---|---|---|
| `C-TOOLS` | `H1` | Every required adapter runs against a synthetic fixture with its attested supported binary/payload identity; optional absence is reported honestly | Adapter/tool matrix, raw/result classification, identities |
| `C-OUTPUT-CONTRACT` | `H1` | Empty, non-empty, malformed, truncated, non-UTF-8, partial, timeout, signal, and tool-specific exit cases map to the documented result contract | Case matrix and typed result records. The in-tree source-only substrate freezes this exact nine-case inventory. Its in-process helper path consumes an exact-object-bound module-internal runner snapshot, which is not a cryptographic or hostile-in-process attestation; serialized raw JSON is explicitly an unauthenticated shape-only diagnostic. The native Gitleaks rows are unavailable until a pinned attested fixture run exists, so the substrate emits no matrix and is not an accepted H1 execution, resolver-indexed raw receipt, release verifier, or gate record. |
| `C-NETWORK-BOUNDARY` | `H1` | Scope, IDNA, redirect, DNS rebinding, proxy, private-reach, scanner-self, and metadata exclusions hold at connect time | Namespace trace plus allow/deny decision records |
| `C-SOURCE-REGISTRY` | `H0`/`H1` | Every acquisition lane and emitted source ID is registered with ownership, policy, input/output schema, and coverage semantics | Static/runtime registry reconciliation report; accepted external H0/H1 collector evidence remains `OPEN` |

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

The committed `C-PATH-IDENTITY` property corpus and containment-decision
producer exercise production identity and descriptor boundaries and record
observed tree, inode-identity, cache, exception and errno facts. The raw
artifact deliberately does not self-attest. Its semantic verifier accepts it
only when one signed H0 instance owns both exact artifacts, encloses the
collection interval and matches the Python/OS/architecture. The gate remains
`OPEN` until such candidate-bound H0 evidence is accepted.

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

The committed `C-FAULT-RUNNER` v1 case manifest freezes eleven stream, process,
cancellation and publication boundaries and 58 exact pytest node IDs across
the required H0 and H1 lanes.  Its candidate-labeled companion is source plan
only: every case is `not_executed`, every outcome digest is null, and all
signing, lane-isolation, ownership, interval and toolchain claims are false.
Local execution is a development check, not release evidence.
The obligation verifier reuses the 32 exact H0 nodes from the already validated
`B-HERMETIC-ALL` run and requires one signed H1 instance to own the 26 remaining
nodes in one exact 58-row machine matrix.  The source plan itself remains
non-promoting.  `C-FAULT-RUNNER` stays `OPEN` until accepted signed H0 and H1
instances own and reconcile those outcomes without changing the frozen plan.

The committed `C-FAULT-STORE` v1 case manifest freezes nine production
boundaries and 60 exact pytest node IDs.  Its candidate-labeled companion is a
source plan only: every case is `not_executed`, every outcome digest is null,
and all signing, H0 isolation, ownership, interval and toolchain claims are
false.  Local execution of the roster checks the implementation during
development, but it is not release evidence.  The obligation verifier reuses
the already validated `B-HERMETIC-ALL` shard results: it requires all 60 nodes
in that exact passing roster and one signed H0 `C-FAULT-STORE` record owning
the unchanged source plan.  This avoids a second pytest pass.  The gate remains
`OPEN` until those accepted signed records exist.

`C-FAULT-REVISION` uses the same retained-H0 rule.  Its matrix freezes all 42
cases in `test_v310_revision_transaction.py`, including staged publication
faults, corruption, rollback/settlement ambiguity, durability ordering and
path-substitution refusals.  The verifier binds that exact source and roster to
one complete passing `B-HERMETIC-ALL` run; it never launches a duplicate suite.
The gate remains `OPEN` until the signed H0 record is accepted.

`C-FAULT-FINALIZE` and `C-FAULT-CAMPAIGN` follow that same no-rerun model.
The former freezes 25 lifecycle, retry, publication and seal cases.  The latter
freezes 50 resume-boundary, absorption, historical-gap, terminal-ledger and
union-truth cases.  Their source files and exact node projections are scope
bound, and each verifier requires one complete passing retained H0 run.  Both
remain `OPEN` until their signed H0 records are accepted.

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

All four Phase D slots always emit records. If no approved scope rule requires
live execution, each emits an exact `not_applicable` record bound to that rule's
digest. If live execution is required, each emits `pass` or `blocked` as
applicable; a violated assertion remains `fail` under the general result
vocabulary. A script-level `SKIP` never closes a slot.

### Phase E: publication gate

The publication decision is a separate, reproducible aggregation step:

| Gate | Requirement |
|---|---|
| `E-AGGREGATE` | Every scope-selected Phase A-C record, all four Phase D outcome/`not_applicable` records, and the `E-DOCS`, `E-PROJECT-HYGIENE`, and pre-publication `E-ARTIFACTS` records are present, authentic, schema-valid, candidate-matched, and `pass`/valid `not_applicable`; deterministic aggregation emits the decision payload |
| `E-DOCS` | Release notes enumerate behavioral changes, accepted risks, known limitations, migrations, exit/result contract, and supported matrix |
| `E-PROJECT-HYGIENE` | License file, security policy, contribution guidance, changelog, and vulnerability-reporting route are present and package-consistent |
| `E-ARTIFACTS` | Candidate-built package, SBOM, provenance, schemas and checksums are accepted publication subjects; the later publication receipt proves those exact bytes, and no substitutes, were promoted |
| `E-APPROVAL` | Named release approver reviews the aggregate and signs a detached approval bound to its digest; approver cannot overwrite underlying gate results |

The pre-publication `E-ARTIFACTS` verifier recomputes the exact subject set from
the indexed candidate sdist, wheel, SBOM, provenance and every scope-bound
schema.  This closes the local reconciliation machinery only; the gate remains
`OPEN` until that canonical subject list is carried by an accepted signed H0
record, and publication still requires the later receipt for those exact bytes.
`E-DOCS` likewise requires the scope-bound release ledger to contain the six
explicit user-facing summary sections, while `E-PROJECT-HYGIENE` rehashes the
license, notice, security policy, contribution guide, changelog and package
metadata and checks their fixed release/package relationships. Both remain
`OPEN` until their exact projections are accepted as signed H0 records.

`E-AGGREGATE` is the operation that creates the aggregate payload, so neither an
`E-AGGREGATE` result nor `E-APPROVAL` is an input to that payload. Successful
deterministic validation constitutes `E-AGGREGATE`; a later detached signature
over its digest constitutes `E-APPROVAL`. This ordering prevents the aggregate
or approval from depending on itself.

The final package version is part of the nominated candidate, not a post-gate
edit. After the source, scope, validation inputs and candidate release notes are
frozen, a maintainer-authorized nomination commit sets both package-version
sources to the intended release before any accepted gate runs. Nomination is
not a tag, publication or green decision. After approval, the signed tag targets
that exact candidate commit and publication promotes the already-attested
artifact bytes. A rebuild or tracked change creates a new subject and repeats
every gate whose inputs it changes.

## Machine-readable evidence

The committed v1 candidate-identity, schema-registry and gate-record contracts
are in [`release/evidence`](../../release/evidence/). Their strict reader and
clean-Git identity collector are implemented in
[`release_evidence.py`](../../src/quarry_recon/release_evidence.py). These are a
prerequisite slice, not accepted gate evidence: they do not verify signatures,
open and rehash content-addressed artifacts, aggregate a scope-selected gate-record set or
implement the nomination, approval, publication or documentation-reconciliation
lifecycle defined below. `A-IDENTITY`, `A-EVIDENCE-SCHEMA` and `RG00` therefore
remain open.

The separate committed development profile, exact job-map contracts and Linux
H0 runner are also prerequisite machinery. The runner privately materializes
one captured commit, collects H0 behind a bounded bubblewrap isolation profile,
and publishes a create-only external bundle whose final file is unmistakably
named `NOT-RELEASE-EVIDENCE.json`. It intentionally emits no
`quarry.release-gate.v1` record. Its host `/usr` runtime and incomplete
dependency closure are untrusted, so a successful development run cannot be
used as candidate evidence or populate a registry slot.

The v1 registry is scoped only to release `0.3.10` and binds its corresponding
scope ledger. The collector and reader refuse any other release label; a later
release requires its own explicit registry/scope contract rather than reusing
the v0.3.10 input under a different label.

### Forward-only evidence lifecycle

The candidate commit contains the final source, package version, scope ledger,
schemas and other validation inputs, but never results produced after
nomination. For an accepted `v0.3.10` nomination, `release`, the semantic
`[project].version` and the literal `quarry_recon.__version__` must all equal
`0.3.10`. A structurally valid identity collected while the package remains
`0.3.9` is diagnostic only and cannot close `A-IDENTITY`.

Candidate identities, gate records, evidence artifacts, aggregate payloads,
approvals and publication receipts are immutable objects outside the candidate
tree. Their declared content digests are authority; a filesystem path, URL, CI
job or "latest" pointer is only a locator. Every consumer must open and rehash
the referenced bytes. Private artifacts use the same digest binding while
exposing only approved opaque references.

References point forward only:

1. the candidate identity binds the frozen commit, tree, source digest, package
   version, scope-ledger digest, registry and schema versions;
2. each gate record binds that candidate-identity digest and the digests of its
   inputs, toolchain and artifacts;
3. the aggregate payload binds the candidate identity, frozen scope-selected gate
   manifest, ordered gate-record digests, verified artifact digests, decision,
   reasons and aggregator identity;
4. a detached approval binds the aggregate digest and accepted signer-policy
   digest;
5. the signed tag targets the candidate commit and binds the candidate,
   aggregate and approval digests; and
6. a publication receipt binds the tag and exact promoted artifact digests.

The digest that addresses an aggregate is computed from its payload and is not
a member of that payload. Its approval is a later detached envelope, never an
input to the aggregate. Gate reruns create new immutable records and a new
aggregate; no status or evidence object is edited in place. A source, scope,
schema, policy or package-version change creates a new candidate identity.

After acceptance, a descendant commit may add a documentation-only projection
of the external result. That projection cites the candidate commit, tree and
identity digest; the aggregate and approval digests; the signed-tag object
identity; and the publication-receipt digest. It is not the release subject,
does not change the signed tag, cannot alter the candidate's frozen scope and
cannot close or reopen a gate. Correcting designated projection fields needs no
gate rerun. A descendant change to normative scope, validation, source, package
bytes or accepted release-note content is not a projection and is a new
candidate instead.

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
replace the accepted release runner's executable/runtime-closure attestation,
and an ambient `git` lookup is not eligible as release evidence.

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

Each record-producing gate eventually emits one canonical record. The
`E-AGGREGATE` payload and detached `E-APPROVAL` use their own still-open
contracts rather than pretending to be inputs to themselves. The v1 gate schema
preserves at least the following structure:

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

`A-EVIDENCE-SCHEMA` has a committed, candidate-independent fixed conformance
manifest. It names the exact public pytest node that exercises the positive
aggregate/verify path and the missing-record, duplicate-gate, wrong-candidate,
malformed-schema, invalid-signature, expired-disposition, unexpected-skip, and
conflicting-result refusals. The manifest contains neither a candidate
aggregate digest nor a scope digest. Its candidate-bound conformance-report
artifact rehashes that manifest, binds the exact test source/node, records two
equal positive canonical aggregate digests, normalized expected error digests,
and exact gate-evidence counts. Semantic verification reconciles those facts
without running the aggregator. This evidence closes `A-EVIDENCE-SCHEMA` only;
it is not a candidate release aggregate. A candidate aggregate output instead
contains the ordered scope-selected gate set, decision, reasons, and aggregate
digest.

## Current Phase 0 closure order

The immediate work is prerequisite closure, not running aspirational commands:

1. accept the candidate identity, gate-evidence, lane-classification, support,
   and threshold schemas;
2. accept the candidate-bound test/job classification manifest and counts for
   the now structurally classified pytest collection;
3. promote the collect-only development boundary into an attested release-image
   runner that executes H0 and emits accepted candidate-bound gate records;
4. attest the selected private corpora and create only the necessary synthetic
   committed fixtures;
5. establish numeric quality and resource baselines without marking them pass;
6. wire Phase B and C runners in disposable environments; and
7. execute a full candidate evidence set only after those prerequisites are
   reviewable.

Until a step is implemented and its evidence validates, its gate remains
`open`. Phase 0 success is an honest, executable gate system—not a document that
labels missing verification as green.
