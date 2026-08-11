# Errors and recovery

Quarry aims never to report "nothing found" without a stated cause — a blocked or failed tool is flagged,
not read as clean. When a run is not clean, the manifest, checkpoints, and status output name what
happened. This page maps the symptom you see to the safe next
action. It is organised by symptom, not by internal error class.

## Read the state first

```bash
quarry status -t acme                 # per-source state of the latest run
```

The verdict (`complete` / `complete_with_limits` / `complete_with_gaps`) and `manifest.json` tell you
whether a shortfall was an expected limit or a real gap. See
[outputs-and-coverage.md](outputs-and-coverage.md).

## Exit status

Every command encodes its verdict in the process exit status, so a script never has to parse prose.

| Code | Meaning | Typical cause |
|------|---------|---------------|
| 0 | clean | no completeness-challenging gap or machinery fault |
| 2 | invalid | bad selector, profile, schema, path or config — refused in preflight |
| 3 | intentionally bounded | completed under a declared terminal or soft limit |
| 4 | gapped | gaps, unknown coverage, a missing required dependency, or an unresolved remainder |
| 5 | machinery failure | machinery, persistence, installer, runner or finalisation broke |
| 6 | refused | scope, authorization or policy refused the operation before execution |
| 130 | interrupted | the operator stopped it |

Precedence when several apply: `130 > 5 (after start) > 2/6 (preflight) > 4 > 3 > 0`. A per-candidate
scope or policy decision is a `PolicyDecision` record in the run's evidence, never exit 6.

`quarry doctor` follows the same contract: `NOT READY` is exit 4 (a missing required dependency) and
`DEGRADED` is exit 4 (present, but the identity could not be verified).

Add `--json` to `run`, `report`, `status`, `doctor`, `osint`, `install`, `update`, `lock` or the `oob`
subcommands for the same verdict as one machine document on stdout — `{schema_version, command, run_id,
campaign_id, outcome, coverage, faults, gaps, exit_code, remediation}`. Under `--json` every human line
goes to stderr, so stdout parses whole.

The contract covers the errors Click itself decides — an unknown option, a missing required option, an
option without its argument — so those exit 2 with a document too. Put `--json` immediately after the
command name: a trailing option binds it as its own value (`--phases --json` selects a phase named
`--json`, it does not ask for a document).

`quarry status --campaign` reports the campaign's own recorded outcome: a `child_fault` or a machinery
terminal is exit 5, `max_runs`/`budget`/an entitlement terminal is exit 3, an unmeasured or unfinished
campaign is exit 4, and only a fixed point is 0. A child that finished `complete_with_limits` reports
exit 3 on the campaign paths too — the same status a standalone `run` gives for the same evidence.

## Finalisation

A run's base evidence commits before any derived view (exports, delta, HOTLIST, digest, checkpoints) is
published, and `<run>/state.json` records where it got to:
`created → running → finalizing → finished | finalization_failed`.

Telemetry and the manifest commit are contained the same way, so a failure there is recorded rather than
leaving a run stopped mid-flight: losing telemetry still commits the evidence, and a manifest that cannot
be written leaves `finalization_failed` instead of a `finalizing` run with nothing to read.

A report-only failure after the base commit exits 5 and leaves `finalization_failed`; the recon evidence
and its committed manifest are intact. Resume the derived views — no rescanning — with:

```bash
quarry report -t acme --run <run_id>          # republish what is missing or stale
quarry report -t acme --run <run_id> --force  # republish every view
```

Each view is stamped with the generation of the evidence it was built from. For a base-only run that is
the committed base generation; when certified late evidence exists it is the published combined
generation. A resume republishes only stale or missing views unless you pass `--force`.

Re-finalising temporarily reopens the lifecycle (`finished | finalization_failed → finalizing`) so its
success or failure can be recorded, then closes it again. It does **not** reopen the base evidence:
`run.json`, `normalized/*.jsonl` and the evidence-bearing manifest fields stay sealed. Derived base views
may be republished when no late-evidence revision exists. `report` may reconcile only the manifest's
derived-publication bookkeeping
(`summary.faults` and the verdict implied by those faults). A cleared publication fault is not a change to
the evidence a revision certifies; changing counts, coverage, gaps, tool runs, profile or other
evidence-bearing manifest content is.

Late OOB evidence for a committed run is written as an append-only supplement under `<run>/revisions/`.
The last-published `revision.json` pointer identifies the certified segment chain and combined entity
counts. Its combined reports and exports live under the pointed-to `revNNNN/` directory; the base run's
`reports/` and `exports/` remain the base generation. `quarry report` prints the path it actually
republished. The pointer is published last, so an interrupted publication leaves the preceding revision
active rather than exposing a half-written generation.

This describes the supported command path. In `v0.3.9`, complete repository-boundary sealing and
multi-revision composition are still open release blockers; callers must not mutate a run directory or
use internal `Run` writers as an alternative to the revision publisher. See
[`HEAD-02`](audit/CURRENT-HEAD.md#head-02-repository-boundary-object-identity-and-sealed-run-immutability) and
[`HEAD-03`](audit/CURRENT-HEAD.md#head-03-revision-composition-certification-and-pointer-last-publication).

`<run>/state.json` fails closed. An absent file is a run written before this contract (a committed
manifest means it finished); a file that is present but unreadable reads as `unknown`, never `finished`,
and Quarry refuses to advance or overwrite it — inspect or remove it deliberately.

Late observations are not added by reopening the base run. They must use the supplement/revision path.
The finalisation reopen exists only to republish derived views and reconcile publication faults. Ordinary
base-evidence writes against a committed run are outside this recovery contract.

The manifest is "committed" only when it is readable, its `entity_counts` are exact non-negative integers
and its `summary` carries every field the writer emits — a present but damaged manifest is not a
commitment, so `report` refuses it (exit 5) and `status` reports a gap rather than a clean verdict. A
partial summary is damage, not a starting point: an empty one would otherwise reconcile to
`verdict: complete`, because it carries nothing to contradict it. Quarry neither recomputes such a summary
nor repairs it — recomputing after the run has ended would answer from an empty ledger, and repairing it
would author the verdict its missing fields were supposed to carry.

`<run>/state.json` must also be this run's own record and shaped as this version writes them — a known
`schema_version`, a matching `run_id`, and well-formed `stages`. A record copied from another run, or
written by a version this one does not understand, reads as `unknown` rather than being trusted.

A run recorded `finalization_failed` reports that machinery failure (exit 5) whatever its manifest was
left saying: the manifest can predate the failure, and reading it would report a stale verdict as the
answer.

A published revision that can no longer be certified is a **gap, not a fallback**: `report` and `status`
render what they can and exit 4, naming the revision, rather than quietly showing the base run's views as
if the late evidence had never arrived. A derived view deleted since it was stamped is stale however
current the stamp looks, so it is rebuilt rather than certified away.

Two different shortfalls both exit 4, and they report different reasons. Evidence **lost** — the revision
cannot be certified — is a `revision` gap. Evidence **incomplete** — rows the corpus envelope is still
refusing — is an `oob` cap gap; the revision stays certified, and the count is what stands across every
revision, not just what the last import turned away.

## Symptoms → action

| Symptom | Where it shows | Evidence kept? | Retries? | Safe action |
|---------|----------------|----------------|----------|-------------|
| Tool missing | `skipped`, `doctor` | n/a | no | install it (`quarry install --only <tool>`), re-run the phase |
| Tool WAF-blocked / rate-limited | checkpoint warn, `tool_status` | yes | no | not "nothing found" — lower `RATELIMIT`, or treat the host as protected |
| Source gated off (`tool_blocked` event) | `events.jsonl`, status | n/a | no | Quarry's own gate refused it (unregistered source, contact guard, or closed acquisition) — not a target block |
| Tool failed / timed out | `complete_with_gaps`, `tool_status` | usually partial kept | no | inspect `raw/<phase>/<tool>/`; re-run the phase, or raise `--timeout` |
| Coverage gap (`cap`/`timeout`/`tool_omission`) | manifest `coverage` | usually yes | no | eligible input was lost — see the kind; re-run or widen the bound |
| Soft limit (`sample`/`provider`) | `complete_with_limits` | yes | no | expected — an operator or provider bound; raise it only if intended |
| Stored remainder | manifest `remainders` | yes | project_progress only | the lane owes more; a `project_progress` lane resumes (or continue with `--settle`), a `rerun_same_work` lane repeats its prefix |
| Unreadable artifact | coverage `unknown` | usually the bytes are kept | no | if retained, re-run to re-parse or inspect it directly |
| Evidence-ownership refusal | coverage `ownership`, `ownership_transition` | depends on state | depends | `evidence-lost` = the file is gone; an orphan/conflict/damaged state needs the specific operator repair the transition names |
| Provider quota / reserve | `complete_with_limits`, `provider_spend` | yes | no | credits are spent or reserved; adjust reserve in [configuration.md](configuration.md) |
| OOB callback missing | `oob_interaction` empty | Quarry's session kept | Quarry channel via poll | absence ≠ clean; `quarry oob poll` pulls late hits on **Quarry's** channel only ([oob.md](oob.md)) |
| Interrupted run | partial run dir | yes | resumable lanes | re-run the same profile; `project_progress` lanes resume, others repeat their prefix |
| Campaign stopped early | `══ campaign … · <stop>` | yes | via new campaign | check the stop reason; raise `--settle-max-runs`/`--settle-budget` if wanted |
| Several campaigns resumable | `run --settle` refuses (exit 6) | yes | yes | it will not choose for you: `--settle-resume <id>` to continue one, `--settle-resume ''` to start fresh |
| OOB rows past the envelope | `oob import/poll` exit 4, and every later `status`/`report` | the callbacks are held | no | raise the corpus envelope and re-import; the refusal is durable and counted across revisions, so it keeps being reported until it is resolved |
| Campaign cannot be confirmed | `run --settle` refuses (exit 6) | yes | yes | nobody can say the evidence was yours, and a new campaign would repeat acquisition it already paid for: continue it with `--settle-resume <id>`, or start fresh with `--settle-resume ''` |
| Campaign belongs to another target | `run --settle` names it, then starts | yes | no | it is accounted for, just not yours to continue — a new campaign starts normally |
| Damaged campaign ledger | exit 5 (machinery) | yes | no | the ledger points at a child outside the project; it is not resumed — start a new campaign |

## Principles

- **Evidence is not discarded on failure.** A tool that half-ran leaves its bytes; a bounded lane leaves a
  remainder. Recovery re-reads or continues, it does not restart from zero.
- **A gap is not a clean result.** Never read `complete_with_gaps` as "the target is clean" — it means
  eligible work was not done.
- **Resume is not universal.** Re-running the same profile resumes `project_progress` lanes where they
  stopped; `rerun_same_work` lanes repeat their prefix, and some ledgers are run-local. `--settle` drives
  the resumable ones for you ([campaigns.md](campaigns.md)).
