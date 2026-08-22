# Outputs and coverage

A run produces layered evidence and a coverage verdict. A finding count alone is not a result — this page
explains what Quarry stored and whether it covered what it set out to.

## The output tree, by purpose

```
~/projects/<t>/
  target.yaml
  osint/<ts>/                     quarry osint candidates + report (osint/latest -> newest)
  recon/<run-id>/
    raw/<phase>/<tool>/…          retained tool output plus Quarry inputs/state; result says if complete
    normalized/<entity>.jsonl     parsed, append-only observation rows (one file per entity type)
    exports/…                     flat .txt views + secrets.jsonl (compatibility)
    reports/…                     HOTLIST.md, digest.json, delta.md, checkpoints.md
    manifest.json  run.json       the run's verdict/accounting, and its immutable identity
    state.json                    lifecycle and per-view publication generations
    events.jsonl  metrics/…       per-source lifecycle stream, timing
    work/…                        intermediate input lists
    revisions/
      revision.json              last-published certified combined-view pointer
      raw/…                      raw evidence acquired after the base committed
      revNNNN/…                  append-only supplement + combined reports/exports
  recon/state/current -> <run-id>
  recon/state/history/…          cross-run history and scheduling state
  recon/campaigns/<id>/           only from --settle
  state/…                        purchased Shodan evidence reused across runs
  osint/state/…                  purchased Whoxy evidence reused across sessions
```

**Raw** retains the captured bytes Quarry owns from a tool or native acquisition. A raw artifact alone is
not proof that the source stream completed; its typed tool/acquisition result and coverage record carry
that distinction. **Normalized** is Quarry's canonical semantic
observation log. Its JSONL rows are append-only; the effective entity set is a derived fold by canonical
identity, including accumulated provenance, rather than a promise that each log contains only one physical
row per entity. **Exports** are flat convenience views over that fold. `quarry report` re-derives reports
from the stored observation view, not by reparsing raw or contacting the target.

The base generation stays in the run's `reports/` and `exports/`. A certified late-evidence revision
combines the sealed base with its append-only segments and publishes a new generation under
`revisions/revNNNN/`; `revisions/revision.json` is the authority for which revision is current. Consumers
must not silently fall back to base-only reports when that pointer exists but cannot be certified.

## Entities

The normalized store recognises 23 entity types, one JSONL file each:

| Group | Entities |
|-------|----------|
| Hosts / DNS | `subdomain`, `resolved`, `dns_record`, `wildcard_zone`, `ip` |
| Web surface | `live`, `url`, `js_url`, `endpoint`, `parameter`, `web_port`, `tech`, `certificate`, `port` |
| Findings / evidence | `finding`, `secret`, `screenshot`, `review`, `gadget_candidate` |
| JS analysis | `path_observation`, `sink_observation` |
| OOB / bookkeeping | `oob_interaction`, `ownership_transition` |

Observation rows are append-only and most carry provenance (which source produced each; a few, like
`wildcard_zone`, do not). The canonical fold merges rows with the same entity identity, so the effective
view of a host observed by two sources is one entity with both sources recorded. Historical rows remain
on disk.

## Reports

| File | What it is |
|------|-----------|
| `HOTLIST.md` | ranked manual-validation queues with the rationale for each |
| `digest.json` | the structured recon→attack contract (schema 1.0), the machine-readable HOTLIST |
| `delta.md` | per-source contribution and what is new since the previous run |
| `checkpoints.md` | thin / blocked / timed-out warnings with a stated cause (only when any were raised) |
| `manifest.json` | the run's verdict, per-tool status, entity counts, coverage, remainders, faults, provider spend |
| `run.json` | the run's immutable identity |

`quarry report` regenerates **exports, `HOTLIST.md`, `digest.json`, and `delta.md`** from the stored
effective observation view — no scanning. It does not reconstruct `checkpoints.md`, whose original
checkpoint input is not reloaded, and it never rewrites `run.json` or base observations. It may reconcile
only the manifest's derived-publication fault/verdict bookkeeping. On a revised run, the regenerated views
go to the published revision directory rather than replacing the base reports.

## The verdict

Every run ends with one of three verdicts:

| Verdict | Meaning |
|---------|---------|
| `complete` | no gap or limit was recorded — nothing was flagged |
| `complete_with_limits` | an **expected** external or operator bound was hit — a soft limit, not a failure |
| `complete_with_gaps` | something failed or omitted eligible input — coverage needs attention |

Gaps dominate: a run with any gap reads `complete_with_gaps` even if a soft limit was also present.

`complete` means nothing was flagged, **not** a proof that every possible lane ran: Quarry keeps no roster
of expected sources, and some lanes do not yet emit structured coverage.

## Coverage kinds — soft limits vs gaps

A lane that did not cover everything records **why**. Two kinds are soft limits (expected, lift to
`complete_with_limits`); the rest are gaps (something was lost, lift to `complete_with_gaps`):

| Kind | Class | Meaning |
|------|-------|---------|
| `sample` | soft limit | an operator-selected subset (a spending reserve, a provider page budget) |
| `provider` | soft limit | an external provider's own limit (quota, entitlement) |
| `cap` | gap | a Quarry ceiling omitted eligible input |
| `timeout` | gap | the target or network lost the input |
| `tool_omission` | gap | a tool declined input that was submitted to it |
| `ownership` | gap | local evidence-ownership state withheld the input |
| `unknown` | gap | coverage could not be measured (carries no counters) |

## Remainders and unknown

`manifest.json` carries **remainders** — what each bounded lane still owes. A remainder that is **absent
means unknown, not zero**: the lane could not say. Not every remainder resumes: only `project_progress`
lanes advance across runs (a `--settle` campaign drives them); `rerun_same_work` lanes repeat their prefix
next time, and some ledgers are run-local.

Where a lane is instrumented, a "0 result" carries its cause — a blocked tool, a lost connection, an
unmeasurable lane are recorded as such, not as a clean empty. But because some lanes are silent or not yet
instrumented (see the `complete` caveat above), a clean-looking run is not a guarantee every lane ran.
This is why the verdict, not the finding count, tells you whether a run is usable.

## Supported v0.3.x resource envelope

Quarry v0.3.x deliberately publishes a finite support envelope; it does not
claim an unbounded or disk-indexed corpus. The exact machine contract is
`resource_contract.support_envelope()` and is embedded in each resource-gate
report. Its current limits are:

| Area | Supported bound | Behavior at or beyond the bound |
|---|---:|---|
| Store keys | 100,000 effective keys per entity | Refused work is recorded as a terminal unschedulable gap; payload retention is not claimed. |
| Store key size | 65,536 bytes per key | The oversized observation is refused and the run cannot report clean coverage. |
| Store corpus bytes | 33,554,432 bytes per entity | The excess is a terminal gap, not a replayable key-only remainder. |
| Store memory declaration | `rss_budget_mb: 160` | The v0.3 store still materializes the whole supported corpus; the disk-backed indexed repository remains deferred. |
| Acquisition ownership | One cross-process writer per filesystem/destination; 5,000 ms lease wait | Reservations and destination publication serialize across processes; timeout is typed rather than an unowned write. |
| Resolver corpus | At most 100,000 hosts, 253 UTF-8 bytes per host | Oversized input is refused before contact with exact durable work where it fits, otherwise a terminal gap. |
| Resolver execution | 16 workers and 16 outstanding queries; one 30,000 ms corpus deadline | Late results cannot mutate the sealed result; unresolved work is durably retained or truthfully terminal. |
| Resolver teardown | 500 ms terminate grace; 2,500 ms hard-kill fallback | Workers are reclaimed before the batch settles. |
| Resolver records | 65,536-byte worker result; 38,101,405-byte remainder record | Oversized or incomplete records fail closed and cannot be called replayable. |

Latency, throughput, RSS, disk-use, and artifact-size measurements are
measure-and-record for v0.3.10. They do not block this integrity milestone
merely for being slow. Hangs, resource overspend, evidence loss or corruption,
leaked execution state, and silent starvation remain blocking integrity
failures.

## Evidence and sharing boundary

The product contract requires raw artifacts and normalized observations to be private canonical evidence.
Target-derived values are retained in full, including discovered credentials, payloads, requests and
responses. Private operator reports are likewise full-fidelity: a discovered target secret stays readable
with its occurrence and provenance. If the same bytes also happen to equal one of the operator's
configured credentials, the occurrence captured from the target remains target evidence.

Quarry-owned credentials — provider/API tokens, notification secrets and OOB authentication values — are
operational inputs, not evidence. They must be excluded by construction from recorded commands, events,
diagnostics, manifests, metrics, notifications and ordinary logs; masking is defense in depth, not a
license to persist them first. See [secrets.md](secrets.md).

A private Quarry report is therefore **not share-safe by default**. `private-report.json` is the
deterministic full-fidelity machine projection: every effective observation appears exactly once and
carries stable observation, canonical-source and attested-artifact references. `HOTLIST.md` and
`digest.json` remain ranked operator projections rather than lossless inventories. Any future share export must be an
explicit, separately generated derived view that names its policy and records every removed, minimized or
transformed field. An AI input is another separate typed, access-controlled derived view; it never replaces
canonical evidence or the private report. Quarry does not currently claim that its ordinary reports are
safe to upload to a third party or model.

The synthetic 24,068-observation replay is a public shape/determinism check, not a substitute for the
unselected private corpus. Report timing/RSS/size records are descriptive while the reviewed benchmark
manifest and numeric `C-PERF-REPORT` thresholds remain unset; measurements alone cannot close that gate.

The historical current-HEAD audit entries under
[`HEAD-05`](audit/CURRENT-HEAD.md#head-05-installation-runtime-identity-and-credential-isolation) and
[`HEAD-08`](audit/CURRENT-HEAD.md#head-08-truthful-lossless-private-reports-and-complete-provenance)
describe the defects that initiated this milestone. The v0.3.10 release ledger,
not those historical findings, records current acceptance status.
