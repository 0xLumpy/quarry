# Phase 1: execution and repository authority

**Status:** implemented and verified narrowly; no release gate is closed by this document

**Planning base:** `f014f6c`

**Audited Phase 1 source:** `474d848656a01cd484dd62d817eb21d527202a78`
(`d42640ef23b9ae44c2ec09d18ac5a704e4373d05` Git tree), 2026-08-14

**Release work packages:** `V310-01` and `V310-02`

Phase 1 establishes two invariants on which the rest of `v0.3.10` depends:

1. a tool invocation cannot finish cleanly until its input, output, process tree
   and evidence publication have reached an explicit terminal state; and
2. every run mutation passes through one repository authority, with a single
   point after which base evidence is permanently sealed.

This phase does not redesign reports, change accepted scanning policy, reduce
Nuclei coverage, deny private targets, disable public Interactsh, migrate to
SQLite, or add a universal scan-duration cap. It does not intentionally weaken
privacy or losslessness: lossless private canonical evidence remains a product
requirement, while the existing `HEAD-06`/`HEAD-08` evidence-loss and provenance
gaps remain open. The reporting prototype remains a later rebuildable projection.

## Why these two changes are one phase

The repository cannot truthfully seal while an execution worker may still own
an evidence sink. Conversely, the runner cannot publish evidence safely if its
destination is merely a caller-constructed path with no lifecycle authority.
The contracts therefore meet at an artifact claim:

```text
repository claims private attempt
             |
             v
parent supervises killable execution worker
             |
             v
worker settles streams and fsyncs stages
             |
             v
repository commits attempt or records incomplete ownership
             |
             v
finalizer waits for zero live claims and seals base evidence
```

Implementation stays in small commits, but neither work package is complete
until this seam is tested as a whole.

## Non-negotiable invariants

### Execution

- Invalid invocation input is rejected before path creation, tool lookup or
  process launch and returns a typed machinery failure.
- `timeout=0` continues to mean no execution ceiling. Workload-scaled timeouts
  remain workload-scaled; Phase 1 adds no small global cap.
- Every started stdin, stdout and stderr channel has one typed terminal state.
- `success` and `empty` require a settled process group, a complete primary
  feed/drain, and durable publication of every requested primary sink.
- A capped, abandoned, failed or still-live primary stream is never clean and
  never becomes an authoritative final artifact.
- Observed bytes and retained bytes have separate counts and digests. A digest
  never describes bytes different from the artifact it authenticates.
- A result is immutable after return. No background thread or process may later
  mutate its metadata or a published artifact.
- Prior committed evidence is preserved until the replacement attempt has
  completed the full publication transaction.

### Repository

- Reads do not create, chmod, repair or otherwise mutate a run.
- Project, run, campaign, entity and artifact identities are validated before
  path construction. Unknown entities and reserved namespaces fail closed.
- Managed path traversal is descriptor-relative and no-follow. Existing
  objects are checked for type, owner, mode and link ambiguity.
- One in-process re-entrant lock plus one inter-process lock serializes all
  mutations for a run. Separate finalization, OOB and revision locks may not
  form competing authorities.
- The durable transition from `running` to `finalizing` is the base-evidence
  seal. Once visible, it is irreversible for canonical base evidence.
- Reopening `finished -> finalizing` authorizes derived-view publication only.
  It never reopens raw evidence, normalized observations, events, tool records,
  OOB session state or acquisition faults/gaps.
- A manifest entry seals the base conservatively even when its contents are
  damaged. Unknown or contradictory lifecycle state refuses mutation.
- Generic `Run.add()` never guesses that late evidence belongs in a revision.
  Authorized late acquisition uses an explicit revision transaction.

## Runner design

### Killable capture owner

The current in-process drain threads cannot satisfy the contract. Python cannot
safely cancel a thread blocked inside a filesystem write or input read. Closing
or publishing its sink from another thread creates exactly the race Phase 1 is
meant to remove.

Each invocation will therefore run behind one supervised worker process:

1. The parent validates the request and obtains private, unique staging
   descriptors from the repository/artifact authority.
2. The worker starts in its own process group and launches the tool into that
   group. Tool arguments and environment values travel over bounded internal
   IPC, not the worker command line.
3. The worker exclusively owns the tool pipes and writable stage descriptors.
   It cannot publish final names.
4. It emits a versioned settlement record only after the process and every
   stream owner have terminated and all stable stages have been flushed,
   `fsync`ed and closed.
5. The parent enforces one absolute settlement budget. At an execution timeout
   or cancellation it terminates the worker group, escalates within the same
   budget, and publishes nothing unless the worker is conclusively reaped.
6. The parent validates the settlement record and exact stage inode, size and
   digest. It then commits through the repository authority and `fsync`s the
   containing directory.

If a kernel-level I/O wait makes the worker unreapable, Quarry returns a typed
incomplete result and fences the unique unpublished stage. It does not pretend
that the bytes are stable and does not place them at an authoritative path.

The initial worker may use an internal selector loop or worker-local stream
threads. The externally testable rule is ownership: the whole capture owner is
killable, and no stage is inspected or published until that owner is reaped.

### Stream settlement record

Each stream records at least:

| Field | Contract |
|---|---|
| `role` | `stdin`, `stdout` or `stderr` |
| `terminal` | One of `complete`, `eof`, `peer_closed`, `cancelled`, `deadline`, `source_error`, `sink_error`, `capped`, `worker_crash` |
| `observed_bytes` | Bytes read from or offered to the channel |
| `retained_bytes` | Exact retained bytes in the private stage or published generation |
| `observed_sha256` | Digest of the observed stream when fully known |
| `retained_sha256` | Digest of the exact retained artifact |
| `lines` | Binary-safe line count where applicable |
| `detail` | Bounded, credential-safe diagnostic text |

The serialized records live under `RunResult.meta["streams"]`. Existing public
fields remain during `v0.3.x`, but are derived from this record rather than
maintained independently.

An explicit output cap is evidence loss, not a clean operator sample. The exact
prefix may remain in a private unpublished stage, and the stream terminal record
retains its count and digest; the result is degraded and carries a
completeness-challenging fault. No public partial path is guaranteed. The
uncapped default is unchanged.

### Deadline model

For a finite execution budget, Quarry computes fixed monotonic instants once:

- the execution cutoff; and
- the final settlement cutoff after the documented termination grace.

Every wait receives only the remaining time. Teardown, pipe drain, worker reap,
hashing and publication may not each add another grace window. Natural tool
exit starts a bounded drain window so an escaped descendant holding a pipe
cannot delay settlement until a very large scan timeout.

For `timeout=0`, there is no execution cutoff. Cancellation or natural tool
exit still starts a bounded settlement window.

## Repository design

### One mutation authority

The initial implementation may remain close to `store.py`, but all writers use
one repository-owned transaction interface with explicit scope:

| Scope | Examples | Eligibility |
|---|---|---|
| `BASE_EVIDENCE` | normalized observations, raw attempts, events, tool records, OOB maps, acquisition gaps/faults | only before the base seal |
| `FINALIZATION_METADATA` | stage status, publication faults, manifest and derived-view pointers | valid finalization lifecycle only |
| `REVISION` | late raw proof, supplement observations and revision publication | settled sealed base only |
| `CONTROL` | lifecycle transition and explicit legacy repair | operation-specific |

The per-run lock lives outside canonical evidence at:

```text
recon/state/locks/<validated-run-id>.lock
```

It combines a process-local `RLock` with an inter-process advisory lock. While
holding it, the repository revalidates the run directory inode, stored identity,
lifecycle and destination. Cache entries carry an on-disk signature and are
invalidated when another handle commits. Sealing discards caches and folds the
authoritative disk state under the lock.

### Seal transaction

The CLI will replace scattered `write_state("finalizing")` calls with one
`begin_finalization()` transaction:

1. confirm every execution/artifact claim is settled;
2. finish all canonical classifiers, including gadget classification;
3. persist acquisition gaps, faults, events and tool records;
4. acquire the repository lock and revalidate identity/lifecycle;
5. flush and `fsync` canonical base files and directories;
6. durably publish `state=finalizing`; and
7. release the lock.

The current gadget classifier runs after `finalizing`; it must move before this
transaction. Finalization failures after the seal are separate publication
facts and cannot alter base evidence.

### Identity and compatibility

Opaque run and campaign IDs use one ASCII segment grammar:

```text
[A-Za-z0-9][A-Za-z0-9._-]{0,63}
```

`state`, `campaigns`, `.` and `..` are reserved; absolute paths, separators,
backslashes, NULs, controls and overlength values are rejected. Safe historical
IDs such as `r1`, `fixed` and timestamp/random IDs remain readable.

`Run.open()` no-follow opens a real run directory, reconciles directory name,
`run.json`, manifest identity and the requested target, and never materializes
missing subdirectories. The managed `recon/state/current` link is the only
symlink exception and must resolve to a validated in-repository run.

Legacy handling is explicit:

- symlinks, foreign ownership, wrong object type and mutable hard-link
  ambiguity always fail closed;
- safe owned legacy objects with only loose permission bits may be repaired
  through an explicit compatibility operation using `fstat`/`fchmod`;
- the repair is recorded under `recon/state`, outside sealed base evidence; and
- ordinary reads never repair or rewrite evidence.

### Late OOB boundary

OOB session creation, token mapping and live callback import are base mutations.
They acquire the repository authority. At the race with finalization, exactly
one disposition wins:

- the live transaction commits raw proof and normalized rows before the seal;
- a settled sealed run routes the complete candidate to revision staging; or
- `finalizing`/unknown state refuses with a retryable non-clean result.

A resumed public-Interactsh client never writes its log or session file into a
sealed base tree. Existing public default and the independent operator opt-out
remain unchanged.

## Implementation sequence

Every commit is independently green and is committed locally without pushing.

1. `runner: type preflight and cap failures`
   - reject invalid argv/input combinations before side effects;
   - separate observed and retained metadata;
   - make capped evidence partial and non-authoritative.
2. `store: establish strict repository identity primitives`
   - shared ID/entity/artifact validators;
   - pure, descriptor-safe `Run.open()` and enumeration;
   - no unknown entity path fallback.
3. `privfs: separate strict access from legacy repair`
   - no-follow owner/mode/type/link validation;
   - durable stage/replace primitives;
   - explicit recorded compatibility repair.
4. `runner: supervise stream settlement in a killable worker`
   - versioned IPC and stream states;
   - one settlement deadline;
   - cancellation and stable partial recovery.
5. `runner: publish evidence durably`
   - repository/private-filesystem staging integration;
   - file and directory `fsync` fault matrix;
   - explicit stdout ownership at every production caller.
6. `store: serialize base mutation and seal transition`
   - one run lock and mutation scopes;
   - artifact claims and cache revalidation;
   - `begin_finalization()` and irreversible base seal.
7. `oob: route late evidence through repository authority`
   - safe session paths and sealed-resume staging;
   - atomic live-versus-revision disposition.
8. `docs: record narrow Phase 1 evidence`
   - update recovery/design documentation and current-head dispositions;
   - leave `V310-01`/`V310-02` open until canonical release gates run.

### Implementation record at the audited source

This is an implementation ledger, not a release-gate record. The commits and
focused tests below establish the repaired seams at the audited source, while
the version remains `0.3.9` and every `V310-*` and `RG00`–`RG09` row remains
open in the release ledger.

| Step | Narrow outcome | Representative source evidence | Disposition |
|---|---|---|---|
| 1–3 | Invocation preflight, repository identity and strict descriptor-relative private-filesystem primitives are present. | `d99d1d2`, `9bf6c99`, `cd227e2`; `tests/test_runner_preflight.py`, `tests/test_repository_identity.py`, `tests/test_phase1_privfs_core.py` | `VERIFIED-NARROW`; canonical release evidence is absent. |
| 4 | A supervised worker owns process-tree and binary stream settlement; the parent authenticates the prepared transaction and rejects an unsettled primary stream as clean. Unmanaged compatibility cannot silently accept a partial repository-policy triad. | `579631e`, `246ad1e`, `fef18c8`, `e27a492`, `5d1b828`; worker/protocol/supervisor, execution-transaction and contract regressions | `VERIFIED-NARROW`; `C-FAULT-RUNNER` and `C-PERF-RUNNER` remain open. |
| 5 | Requested stdout, stderr and native argv outputs publish through repository output policies, private stages and exact artifact claims; preserved prior finals are never treated as current output. | `8281636`, `00c1095`, `d052897`, `b5ea9b1`, `5430c4d`, `4d1d736`; publication, native-output, exported-descriptor and stdout-currentness regressions | `VERIFIED-NARROW`; no package, isolation or machine-evidence gate is closed. |
| 6 | Run creation, append, entity/tool records, attempt directories, budget-ledger persistence, exact canonical removal, finalization and managed HTTP acquisition share the repository mutation/claim boundary. The base seal is irreversible. | `2448b07`, `69f2bce`, `8b084bf`, `e092fcb`, `9bfbe13`, `53af5f7`, `d11637b`, `117f21e`, `b4a5a13`, `b036a86`, `1f8981b`, `eee5d64` | `VERIFIED-NARROW`; full manifest semantics, revision composition and canonical `V310-02` gates remain open. |
| 7 | Live OOB mutation and sealed-run disposition are serialized through the Run authority; late evidence cannot append to a sealed base. | `c2db405`, `e092fcb`; `tests/test_phase1_oob_authority.py` and finalization race regressions | `VERIFIED-NARROW`; revision certification remains `HEAD-03`/`V310-03` work. |
| 8 | This design, recovery guidance, current-HEAD ledger and release ledger distinguish the narrow implementation from release closure. | the documentation change following the audited source | Complete as Phase 1 documentation only; release remains **NO-GO**. |

The final committed-source inventory found 65 Python source modules, 127
`test_*.py` modules and 7,631 collected tests, 38 tools, 66 registered sources,
23 entity kinds and 9 phases. The final AST classifier found 284 terminal-name
candidates, excluded 39 value transforms and semantically reviewed the remaining
245 concrete writer/mutation candidates; call-graph review found zero ambient
canonical Run-base writers. All 38 runner policy sites carry the triad (37
`exec_tool` facade sites plus one internal repository delegation); independently,
all 15 production `run_contract` callers supply it. All 21 native sinks are
authorized (13 through `exec_tool`, 8 through `run_contract`). The all-`None`
contract compatibility path is non-Run; any partial triad is forwarded whole and
fails runner preflight closed. The sole production `scoped_get_file` caller
routes authenticated Run destinations through `managed_acquisition_claim`; its
three production discard sites use the exact managed discard transaction. The
remaining path-based streamer calls are legacy/unmanaged or project-state
Shodan sinks, not Run-base writers.

Focused diagnostic evidence at the frozen managed-acquisition integration was
562 passing transaction/legacy tests, an independent 8-case replay matrix and
119 passing transaction tests on Python 3.13. A final static/currentness
selection passed 11 tests on Python 3.13.12, and the final independent
authority/currentness selection passed 71 tests. Earlier focused descriptor,
no-replace and exported-descriptor selections were also run across Python 3.10,
3.12 and 3.13. At the exact audited source, fresh sequential clean-archive
matrices with the editable package and exact dependencies produced, per
interpreter: 7,528 default passes with 103 deselections, 6,224 offline passes
with 1,407 deselections, and 103 integration passes with 7,528 deselections.
Integration had zero warnings; default/offline had zero on Python 3.10 and four
known deprecation warnings on 3.12/3.13. The final writer audit also produced 32
focused passes and 2 static passes. Test-hygiene commit `474d848`
deterministically closes multiprocessing fixture descriptors before these
matrices. Exact transcript hashes and timings are recorded in the current-HEAD
ledger. These transcripts are useful implementation evidence, but they are not schema-valid
`RELEASE-GATES.md` artifacts and therefore do not populate a release evidence
slot.

The authority is a cooperative repository boundary: Run operations and
participating processes serialize and reauthenticate exact descriptors and
names. An arbitrary process with the same UID can still mutate raw filesystem
objects after the last authenticated check; defending against that actor is
outside Phase 1, consistent with the `privfs` trust boundary.

## Acceptance matrix

Focused tests must cover:

- invalid argv and input combinations with zero side effects;
- binary/non-UTF-8, large, empty and malformed output;
- blocked input read and sink write before and after a known prefix;
- escaped pipe holders, timeout, signal, cancellation and worker crash;
- output cap `0`, smaller than output, exact size and unlimited;
- write, flush, file `fsync`, close, rename and directory `fsync` failures;
- prior-final preservation and stable partial identity;
- every public base mutator before and after each lifecycle state;
- append-versus-seal and raw-claim-versus-seal races across threads and
  processes;
- OOB-import-versus-seal with no split base/revision outcome;
- traversal, reserved IDs, unknown entities, symlinked ancestors/files,
  hardlinks, wrong type/owner/mode and explicit legacy repair;
- stale cache detection across two run handles; and
- unchanged default uncapped, workload-scaled and `timeout=0` behavior.

The full Python 3.10 and 3.12 non-live suites must remain green after every
slice. Real local-process cases belong to the tool-integration lane; pure state
machine and filesystem fault cases belong to the hermetic lane.

## Stop/go boundary

Do not start `V310-03` revision publication until all of the following hold:

- a runner cannot return clean with any primary stream owner live or unsettled;
- every requested authoritative artifact is durable and authenticates its own
  exact bytes;
- every production base writer uses the repository authority or an explicit
  live artifact claim;
- `Run.open()` is pure and unknown identities cannot create files;
- finalization and every appender use the same lock and seal predicate;
- late OOB cannot write sealed base bytes; and
- focused concurrency/fault tests plus full Python 3.10/3.12 suites pass.

Until the machine-readable gate runner and candidate evidence set exist, these
results may be recorded as narrow verification only. They do not close
`V310-01`, `V310-02`, `HEAD-01`, or `HEAD-02`.
