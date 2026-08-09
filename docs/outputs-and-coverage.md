# Outputs and coverage

A run produces layered evidence and a coverage verdict. A finding count alone is not a result — this page
explains what Quarry stored and whether it covered what it set out to.

## The output tree, by purpose

```
~/projects/<t>/
  target.yaml
  osint/<ts>/                     quarry osint candidates + report (osint/latest -> newest)
  recon/<run-id>/
    raw/<phase>/<tool>/…          exactly what each tool wrote, plus Quarry's inputs/state for the run
    normalized/<entity>.jsonl     parsed, append-only observations (one file per entity type)
    exports/…                     flat .txt views + secrets.jsonl (compatibility)
    reports/…                     HOTLIST.md, digest.json, delta.md, checkpoints.md
    manifest.json  run.json       the run's verdict/accounting, and its immutable identity
    events.jsonl  metrics/…       per-source lifecycle stream, timing
    work/…                        intermediate input lists
  recon/state/current -> <run-id>
  recon/campaigns/<id>/           only from --settle
```

**Raw** is what a tool emitted — the captured input. **Normalized** is Quarry's **canonical** store: typed,
deduplicated observations with merged provenance, and what the reports are built from. **Exports** are flat
convenience views over it. `quarry report` re-derives the reports from the normalized store, not by
reparsing raw.

## Entities

The normalized store recognises 23 entity types, one JSONL file each:

| Group | Entities |
|-------|----------|
| Hosts / DNS | `subdomain`, `resolved`, `dns_record`, `wildcard_zone`, `ip` |
| Web surface | `live`, `url`, `js_url`, `endpoint`, `parameter`, `web_port`, `tech`, `certificate`, `port` |
| Findings / evidence | `finding`, `secret`, `screenshot`, `review`, `gadget_candidate` |
| JS analysis | `path_observation`, `sink_observation` |
| OOB / bookkeeping | `oob_interaction`, `ownership_transition` |

Entities are append-only and most carry provenance (which source produced each; a few, like
`wildcard_zone`, do not). Merge is canonical — the same host from two sources is one entity with both
sources recorded, not a duplicate.

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
normalized entities — no scanning. It does not rebuild `checkpoints.md`, `manifest.json`, or `run.json`.

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

## Redaction boundary

Quarry's **own** configured credentials are stripped (`***`) from recorded commands and notes,
`manifest.json`, `digest.json`, the event stream, and notifications. A **discovered** secret — one found on
the target — is evidence: `HOTLIST.md` and `exports/secrets.jsonl` render it **whole** (that is the point of
finding it), with a preview/fingerprint beside it. Those two are not redaction sinks.

**Known exception:** if one of *your* configured credentials also turns up as discovered evidence (the same
value found on the target), `HOTLIST.md` and `exports/secrets.jsonl` currently show it in full — they redact
nothing. Everywhere else your keys are masked. See [secrets.md](secrets.md).
