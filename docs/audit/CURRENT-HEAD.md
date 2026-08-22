# Quarry current-HEAD closure ledger

> **Historical baseline:** this ledger is bound to the audited 2026-08-14
> revision below. Its `NO-GO`, `OPEN`, and `REOPENED` rows are superseded for
> v0.3.10 milestone disposition by the current
> [v0.3.10 release ledger](../releases/v0.3.10.md); they remain unchanged here as
> audit history and are not current release blockers.

**Audited source revision:** `19ab50cbdc2415c78e9bb5651dec2e072bb3a71b`

**Audited Git tree:** `8311829d62be4b7099979e2c0e2f476c2f94fc34`

**Package version:** `0.3.9`

**Audit date:** 2026-08-14

**Release decision:** **NO-GO** for `v0.3.10`, production-grade, or market-leading claims

This is a closure ledger for the implementation at the audited source revision. It combines one exact
current taxonomy diagnostic with explicitly identified historical Phase 1 evidence; it does not turn
either into candidate acceptance. It does not repeat the original audit report. The historical finding
definitions, evidence taxonomy, accepted decisions and `QR39-*` identifiers remain in the
[archived v0.3.9 register](../archive/audit-v0.3.9/AUDIT_REGISTER_RECONCILED.md). This document supersedes
that register only for **current status and release disposition**.

The documentation commit carrying this ledger is deliberately not treated as a self-audited source
revision. `19ab50cbdc2415c78e9bb5651dec2e072bb3a71b` remains the implementation identity for this
reconciliation. Every release candidate requires a fresh machine-readable evidence set against its own
exact identity.

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

The Phase 1 source audit and current taxonomy reconciliation established the following without contacting
a target:

- The exact current source identity is `19ab50cbdc2415c78e9bb5651dec2e072bb3a71b`, with Git tree
  `8311829d62be4b7099979e2c0e2f476c2f94fc34` and domain-separated source-tree digest
  `sha256:53e5c9d77e9e234873b44cabbb219652abdf69dc6a0b2b12977d37a108ba8209`. The tracked worktree was
  clean before the diagnostic and this documentation reconciliation. `pyproject.toml` and
  `quarry_recon.__version__` both remain `0.3.9`.
- On CPython 3.13.12 with pytest 9.0.3, collect-only execution at that identity emitted canonical
  `quarry.pytest-taxonomy.v1` bytes with raw-file SHA-256
  `732f26bfb49c48ad2bce556d782d43b3952b9dd1b661e5312a30705994c0938b`. The positive H0 selection
  accounts for all 7,867 nodes before deselection: 7,796 H0 selected and 71 H1 deselected; C0/P0/L0 each
  contain zero nodes, and 40 H0 nodes carry `synthetic_process`.
- All H1 nodes name real-tool capabilities. The manifest indexes `bwrap`, `cat`, `git`, `head`, `ls`,
  `printf`, `seq`, `setsid`, `sh`, `sleep`, and `true`; capability counts may overlap. The 71 H1 nodes
  comprise 14 Git nodes, 4 bwrap nodes, and 53 shell/coreutils-backed migration-debt nodes.
- The committed Linux development runner privately cloned and exported that exact committed tree, bound
  its candidate identity, development isolation profile, schemas, verification-job map and workflow,
  and collected H0 behind a bubblewrap blank-root boundary. All 14 inner boolean checks were true; outer
  validation also bound the isolated namespace identities to bubblewrap's status. The candidate and
  runtime mounts were read-only, work was read-write, `/dev` was isolated, `/proc` was read-only,
  capabilities were empty, the environment and descriptor inventory were exact, forbidden host roots and
  `.git` were absent, and the candidate source/cwd/hostname matched.
- That run is deliberately non-authoritative. It used an untrusted development-host `/usr` runtime with
  an incomplete executable dependency closure and no seccomp profile; it collected tests but did not
  execute them. Its summary has raw-file SHA-256
  `9e52b4761325961ca7bbed8d60f2d1c4163163100cee3be61ec06b5c887ad97f`, declares `authority: none` and
  `promotion_eligible: false`, and leaves `A-TAXONOMY` `open` for reason
  `non-nominated 0.3.9/development host runtime`. It is not a gate record, occupies no release evidence
  slot, and leaves `RG00` `OPEN`.
- The Phase 1 production-authority audit remains bound to the earlier exact source
  `474d848656a01cd484dd62d817eb21d527202a78` and Git tree
  `d42640ef23b9ae44c2ec09d18ac5a704e4373d05`. Its 65-source-module, 127-test-module and 7,631-node
  inventory and all pass matrices below are historical diagnostics, not current-source or candidate-green
  evidence.
- The final AST writer classifier found 284 terminal-name candidates and excluded 39 value transforms.
  Semantic and call-graph review of the remaining 245 concrete writer/mutation candidates found zero
  ambient canonical Run-base writers.
- All 38 runner policy sites carry the triad: 37 `exec_tool` facade sites plus one internal repository
  delegation. Independently, all 15 production `run_contract` callers supply the triad. All 21 native
  sinks are authorized: 13 through `exec_tool` and 8 through `run_contract`. The all-`None` contract
  compatibility path is non-Run; a partial triad is forwarded whole and fails runner preflight closed.
- The only production `scoped_get_file` call is the evidence acquisition entry point. Authenticated Run
  destinations use the managed acquisition transaction; lexical or resolved aliases into the reserved
  `recon` namespace cannot fall through to legacy I/O. Its three production discard sites use the exact
  managed discard transaction. The remaining legacy path streamer calls serve unmanaged destinations or
  project-state Shodan pages, not Run-base evidence.
- The frozen managed-acquisition integration produced 562 passing transaction/legacy tests, an
  independent 8-case replay matrix and 119 passing transaction tests on Python 3.13. A final
  static/currentness selection produced 11 passes on Python 3.13.12; the independent
  authority/currentness selection produced 71 passes. Earlier focused descriptor, no-replace and
  exported-descriptor selections ran across Python 3.10, 3.12 and 3.13.
- The final writer audit produced 32 focused passes and 2 static passes. Test-hygiene commit `474d848`
  deterministically closes multiprocessing fixture descriptors before exact-HEAD matrix execution; its
  independent Python 3.13 audit repeated the affected sequence 50/50 successfully and preserved exact
  descriptor-set equality on the failure probe.
- The previous 5,458-test effective diagnostic baseline and 74-test integration selection belong to the
  older `4e4825c` audit. They are historical context, not evidence for this source identity.
- The private case named `quarry-interrupted-events` remains the primary reporting/scale regression
  corpus. Its source mapping is sensitive and is not part of the tree; its historical aggregate counts
  are diagnostic only because no accepted immutable corpus attestation binds it to this source identity.
- The repository now contains the v1 candidate-identity collector/readers, structural gate schemas,
  exact pytest lane enforcement, formal taxonomy/job-map artifacts, and a bounded OS-isolated H0
  collect-only development runner. It still lacks an accepted nominated-candidate record, an accepted
  test/job classification gate record, a trusted and complete release runtime image, test execution in
  that runner, the artifact verifier and deterministic aggregator, finite support/threshold manifests,
  package/SBOM/provenance gates, and accepted corpus attestations. Focused passing tests and the successful
  collection diagnostic therefore do not close `RG00`–`RG09`.
- `scripts/verify-quarry.sh` remains unsuitable as release evidence because its check 2 can contact a
  configured/live target. It must be separated into a proven-offline gate and an explicitly authorized
  range gate before release use.

The following fresh sequential clean-archive matrices used the editable package with exact dependencies at
the earlier `474d848` Phase 1 source. Every lane had the same 7,631-test collection:

| Lane | Python | Result | Warnings | Pytest time | Log SHA-256 |
|---|---|---|---:|---:|---|
| Default | 3.10 | 7,528 passed, 103 deselected | 0 | 924.82 s | `ffb51ab88f30724b4c1b82891df4b8dcfd28255743d6bb7433cb2c747b8dc068` |
| Default | 3.12 | 7,528 passed, 103 deselected | 4 | 829.18 s | `ec5a56a08391570fbb96ff93f9f1ddf7c0288091a40dabcef0f0b625898b2c51` |
| Default | 3.13 | 7,528 passed, 103 deselected | 4 | 784.61 s | `d45cb5aceae920d32bb6d272be7c4b93a27c2261e48b20550ba4b47ca40f9b8b` |
| Offline (`QUARRY_OFFLINE_CI=1`) | 3.10 | 6,224 passed, 1,407 deselected | 0 | 805.69 s | `c79effd344ab2b84b01e290acdf8a11d035b6fc63dce729cac20259abba57976` |
| Offline (`QUARRY_OFFLINE_CI=1`) | 3.12 | 6,224 passed, 1,407 deselected | 4 | 755.10 s | `62e63c9baf35adf859e84f0cec3c50ba6912cd01c573b570ea6ac031e0539407` |
| Offline (`QUARRY_OFFLINE_CI=1`) | 3.13 | 6,224 passed, 1,407 deselected | 4 | 707.63 s | `e25fb754615f9f4d52bed7485e71ac0a1f5b15db3b1b2d709927d29d0f94703a` |
| Integration | 3.10 | 103 passed, 7,528 deselected | 0 | 35.97 s | `5146209dbf8f6b745fc19a43bcc579afe1a12b0dd0d0cb5809ff4a2253316e28` |
| Integration | 3.12 | 103 passed, 7,528 deselected | 0 | 35.71 s | `69f94614ab848c2c5076e0a1294d46619cb4d4ed4a43141f38d672fa08e0f017` |
| Integration | 3.13 | 103 passed, 7,528 deselected | 0 | 32.41 s | `aa2e41e94bce98839e075290b508528bb84caccd449a903736ddb4ec9226c19f` |

The four Python 3.12/3.13 default/offline warnings are the known two multithreaded-fork and two tar-filter
deprecations; integration emitted none. These logs are reproducible historical diagnostics, not
schema-valid canonical gate records, and do not populate a release evidence slot. This ledger makes no
whole-suite pass claim for `19ab50c`; its current observation is the OS-isolated, collection-only
development diagnostic above.

The historical Phase 1 suite proves substantial repaired behavior at its recorded source, but does not
override the open canonical gate and non-Phase-1 findings below. In the Phase 1 narrative below, “audited
source” refers to `474d848`, not the current taxonomy-reconciliation identity.

## Verified closures and verified foundations

| Status | QR39 mapping | Current disposition | Phase 1 evidence provenance | Residual disposition |
|---|---|---|---|---|
| `VERIFIED` | `QR39-002` | Run enumeration excludes reserved namespaces and validates run identity for latest/status/report/delta selection. | `1968c57`; `src/quarry_recon/store.py::list_runs`; `tests/test_qr39_002_list_runs.py` | Closed for this revision. Any future namespace must be added to the same authority. |
| `VERIFIED` | `QR39-011` | Exit values `0/2/3/4/5/6/130`, precedence and JSON-stdout discipline are implemented and directly covered. | `32ad450`; `src/quarry_recon/state.py::compute_exit`; `src/quarry_recon/exit_contract.py`; `tests/test_qr39_011_exit_contract.py` | Closed as a command-result contract. Individual commands still must supply truthful inputs. |
| `VERIFIED-NARROW` | `QR39-010` | Unknown, empty and duplicate selectors are rejected before run/install side effects; selected phases return in canonical order. | `8263b73`; `src/quarry_recon/cli.py::_select_phases`; `tests/test_qr39_010_selector_validation.py` | A future plugin/dependency graph still needs explicit prerequisite metadata; this does not reopen the present static selector fix. |
| `VERIFIED-NARROW` | `QR39-003`, `QR39-016` | Typed fault/gap records, verdict-after-fault plumbing and a persisted finalization state machine exist. | `45f83e8`, `32ad450`; `src/quarry_recon/state.py`; `tests/test_qr39_003_verdict_after_faults.py`; `tests/test_qr39_016_finalization.py` | Manifest semantics and consumers remain open in `HEAD-04`. |
| `VERIFIED-NARROW` | `QR39-006` | Newly created run/evidence artifacts use private creation primitives rather than depending on umask. | `7e44385`; `src/quarry_recon/privfs.py`; `tests/test_qr39_006_permissions.py` | Existing files, symlinks, ownership and migration remain open in `HEAD-02`/`HEAD-05`. |
| `VERIFIED-NARROW` | `QR39-009` | Normal delayed-OOB ingestion routes through revision supplements rather than appending normalized evidence to a sealed base. | `d598dd7`; `src/quarry_recon/revision.py::ingest`; `tests/test_qr39_009_oob_revision.py`; `tests/test_qr39_009_revision_sealing.py` | Base sealing has narrow Phase 1 evidence in `HEAD-02`; revision publication/certification remains open in `HEAD-03`. |
| `VERIFIED-NARROW` | `QR39-015` | A timed-out individual resolver worker is killable and reclaimed. | `901e093`; `src/quarry_recon/netguard.py::_resolve_batch`; `tests/test_qr39_015_resolver_reclaim.py` | Corpus-wide duration and portable worker-start behavior remain open in `HEAD-06`. |
| `VERIFIED-NARROW` | `QR39-001`, `QR39-030` | The runner supervises a killable execution owner, authenticates typed stream settlement and publishes requested outputs only through explicit repository policies. Preserved prior finals are not current output. | `579631e`, `246ad1e`, `e27a492`, `00c1095`, `4d1d736`, `5d1b828`, `7a60bfb`, `fedd292`, `3f1bd6b`; worker, supervisor, repository-composition, contract, currentness and nine-case output-contract checks | `C-OUTPUT-CONTRACT` passed the internal nine-case run; candidate-wide `B-HERMETIC-ALL`, `C-FAULT-RUNNER` and the integrity-class `C-PERF-RUNNER` outcome remain separate. |
| `VERIFIED-NARROW` | `QR39-005`, `QR39-006`, `QR39-009`, `QR39-016`, `QR39-032` | Production Run-base writers share mutation/artifact authority; managed HTTP body/receipt acquisition and conditional discard are one serialized transaction; budget-ledger persistence and canonical removal use the same authority; the base seal is irreversible. | `2448b07`, `8b084bf`, `e092fcb`, `53af5f7`, `d11637b`, `117f21e`, `b4a5a13`, `b036a86`, `1f8981b`, `eee5d64`; Phase 1 mutation, claim, finalization, OOB, budget and managed-acquisition regressions | Strict manifest semantics, revision certification and all canonical `V310-02` evidence slots remain open. |

These repaired foundations remain narrow: their full QR39 rows are not release-closed without the
candidate-wide canonical evidence named in their residual dispositions.

## Stop-ship clusters and narrow repairs

### `HEAD-01` — subprocess evidence completion

**Status:** `VERIFIED-NARROW`

**Maps to:** `QR39-001`, with resource interaction from `QR39-004` and `QR39-030`

**Evidence.** The old in-process drain path is no longer the production Run publication authority. A
supervised worker owns the process group, pipes and private stages; the parent authenticates a versioned
settlement record and publishes only after the primary owner is terminal. Invalid argv/input/cap shapes
fail in preflight, a capped or lost primary stream cannot be clean, and retained prefixes carry their own
count/digest rather than authenticating a different final. All 38 runner policy sites at the audited
source carry the triad (37 `exec_tool` facade sites plus one internal repository delegation); all 15
production `run_contract` callers independently supply that triad, while its all-`None` unmanaged
compatibility path remains outside a Run base. Worker/protocol/supervisor, repository-composition,
native-output, blocked/escaped stream, cap, cancellation and currentness
regressions cover the former reproduced failures.

**Narrow result.** A live/unsettled primary owner, invalid invocation, cap, sink failure or uncommitted
publication no longer returns an authoritative current artifact. Prior committed evidence is preserved
without being reported as this attempt's output.

**Residual release work.** `V310-01` remains `OPEN` for candidate-wide hermetic selection,
`C-FAULT-RUNNER`, and the integrity-class `C-PERF-RUNNER` outcome. `C-OUTPUT-CONTRACT` passed its
internal nine-case execution and separate receipt/matrix verification on candidate `3f1bd6b`; this is an
internal integrity record, not a signed distribution attestation. Resource-envelope interactions remain
in `HEAD-06`.

### `HEAD-02` — repository boundary, object identity and sealed-run immutability

**Status:** `VERIFIED-NARROW`

**Maps to:** `QR39-005`, `QR39-006`, `QR39-009`, `QR39-016`, `QR39-032`, `QR39-041`

**Evidence.** Run/project identities and artifact/entity components are validated before construction;
`Run.open()` is descriptor-relative and read-only. Creation, append, `add`, `inherit`, tool/event records,
attempt directories, budget-ledger persistence, exact canonical removal, native/runner publication, OOB
mutation and finalization use the scoped Run mutation/artifact boundary. `running -> finalizing` performs
a strict durability walk and irreversibly seals base evidence; manifest presence seals conservatively.
Managed HTTP acquisition now holds a deterministic destination lease across reconciliation, contact,
body/receipt publication, replay and
conditional discard. The final object-level writer inventory found zero unmanaged production Run-base
writers, including the former fetch/discard residuals. Traversal, substitution, stale-cache,
append-versus-seal, artifact-claim-versus-seal, OOB-versus-seal, cancellation, cross-thread/process and
managed-acquisition fault regressions cover these boundaries.

**Narrow result.** The old post-finish append, unknown-entity and path-traversal reproductions now refuse.
Authorized delayed OOB work cannot append to sealed base evidence. Same-destination managed contact is
serialized and a damaged/uncertain prior acquisition refuses retry rather than overwriting or duplicating
contact.

**Residual release work.** `V310-02` remains `OPEN`: strict manifest semantics are still `HEAD-04`, full
revision composition/certification is `HEAD-03`, and the canonical `B-MANIFEST`, `C-PRIVATE-FILES`,
`C-PATH-IDENTITY` and `C-FAULT-STORE` artifacts are absent. The authority is a cooperative boundary; an
arbitrary same-UID process can still change raw objects after the last authenticated check, which is
outside the Phase 1/`privfs` trust model.

### `HEAD-03` — revision composition, certification and pointer-last publication

**Status:** `REOPENED`

**Maps to:** `QR39-009`, `QR39-024`

**Evidence.** `revision._Supplement._publish()` starts each revision's counts from base counts and updates
only entity kinds materialized by that writer. A later revision can therefore omit an entity introduced
by an earlier revision from its candidate counts. `revision.read()` now recomputes combined counts and
refuses that pointer as unusable, but the pointer is written before the post-publication certification;
the correct refusal therefore occurs only after the previous valid pointer has already been replaced.
The pointer's derived-view and entity-digest claims are not all independently certified before publish.

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

**Evidence.** `store.summary_well_formed()` checks required-key presence, not summary value types, schema
identity, digest or reconciliation to entity logs. A manifest whose required summary fields all contain
semantically invalid values can satisfy `store.manifest_committed()`. Settlement's `_committed()` accepts
any dictionary summary rather than using the store's committed-manifest predicate. Fresh campaign
harnesses showed an earlier gapped child can be followed by a clean/no-progress child and end
`fixed_point`, and a ledger can accept contradictory stop-cause/success combinations.

**Preconditions.** A child manifest is truncated/crafted, a prior child has gaps, a resume observes a
damaged ledger, or terminal fields disagree.

**Acceptance.** One versioned strict parser validates manifest schema, lifecycle, counters, typed summary,
digests and count consistency; every consumer uses it. Campaign outcome folds the complete child history,
never launders a prior unresolved gap, and validates allowed `(cause, success, clean)` combinations.
Kill/restart and corruption tests cover every transition.

### `HEAD-05` — installation, runtime identity and credential isolation

**Status:** `REOPENED`

**Maps to:** `QR39-007`, `QR39-008`, `QR39-017`, `QR39-027`, `QR39-028`, `QR39-042`

**Evidence.** Binary/source installation has staged activation, but `registry.install_one()` explicitly
installs Go/pipx runtimes in place before final identity/capability verification. A failed verification
can therefore leave the new active payload. The Go non-`renameat2` fallback uses sequential moves and has
an absent-active interval. Runtime launch still resolves ordinary commands through `PATH`, and the runner
inherits the ambient environment. `secrets.apply_env()` exports `PDCP_API_KEY` globally, allowing
unrelated children to inherit it. Mutable helper/template/runtime closures are not comprehensively
attested.

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
space reservation in `DiskGovernor` is process-local when no project maximum is active. Phase 1 repairs
the Run-owned destination collision: managed HTTP acquisition holds a deterministic cross-process lease
and uses private stages. The legacy `stream_to_file()` path still uses a shared `<dest>.part` name only
for destinations proven outside a Run base; the two Shodan callers are project-state sinks. This does not
make aggregate reservation or arbitrary unmanaged destinations cross-process safe. `resolve_many()` has
bounded concurrency but no corpus deadline; 100,000 hung names at 16 workers and a five-second timeout
require about 8.7 hours before overhead.

**Preconditions.** A large corpus crosses an entity envelope, concurrent processes consume one
filesystem reserve or an unmanaged helper destination, or resolution repeatedly times out.

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
is not renderer-escaped. `params.run()` returns when the Nuclei live set is empty, skipping independent
downstream lanes.

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
boundary test does not scan these native evidence/OSINT modules. The 38 runner policy sites (37
`exec_tool` facade sites plus one internal repository delegation), 15 `run_contract` callers and 21
native sinks are statically inventoried and authorized. They remain distributed call sites behind several
static inventories rather than one adapter interface. CI positively selects the structurally complete H0
lane and writes a canonical diagnostic taxonomy manifest, but the Python deny guard is not OS containment.
The 71 H1 nodes have no protected compatibility job, the 53 shell/coreutils-backed H1 nodes remain
migration debt, and no accepted candidate-bound test/job classification record exists. CI also has no
lint, type, coverage, security or dependency-integrity gate. The repository declares MIT in
`pyproject.toml` but has no tracked `LICENSE`, and lacks tracked `SECURITY.md`, `CONTRIBUTING.md` and a
changelog/release process.

**Preconditions.** A new source bypasses the registry, a required non-H0 regression has no mapped protected
job, a verification job is absent from the accepted lane map, or Quarry is distributed to external
operators/contributors.

**Acceptance.** Every acquisition owner is registry-governed or named by one reviewed exception contract;
the boundary test scans all source packages. Every required H0/H1/C0/P0/L0 selection has an accepted job
mapping and runs on the supported matrix with committed style/type/security/dependency gates. Network
isolation is OS-level for release CI. License, security reporting, contribution and release-integrity
documents are tracked.

## Open non-stop-ship backlog retained from QR39

The stop-ship clusters do not erase the rest of the register. Unless a row above explicitly closes it,
`QR39-013` through `QR39-043` remain open at their archived severity and target, including exact profile
schema (`QR39-018`), OOB request-before-mapping durability (`QR39-020`), token entropy (`QR39-021`),
IDNA/URL authority (`QR39-022`), OSINT YAML serialization (`QR39-025`), mutable behavioral data
(`QR39-027`), stale view generation (`QR39-031`), platform claims (`QR39-035`), exact truncation sentinel
(`QR39-036`), regex complexity (`QR39-037`) and dry-run/dead metadata (`QR39-038`). Deferral must appear
in the release ledger; silence is not closure.

## Decision

`v0.3.10` remains a **NO-GO**, and both version strings remain `0.3.9` at this audited source. They may
change together only in a maintainer-authorized `0.3.10` nomination after source, scope, validation inputs,
supported matrix and candidate release notes are frozen; nomination closes no row and precedes accepted
candidate evidence. Do not create the signed tag until the accepted aggregate and detached approval close
the pre-publication requirements, do not publish anything except the exact accepted artifact bytes, and do
not project the release complete until the publication receipt satisfies the remaining `RG09` postconditions.
The current architecture may evolve through compatibility boundaries; this decision does not authorize a
big-bang rewrite or reduce reconnaissance coverage.
