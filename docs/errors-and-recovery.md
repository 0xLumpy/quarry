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

## Principles

- **Evidence is not discarded on failure.** A tool that half-ran leaves its bytes; a bounded lane leaves a
  remainder. Recovery re-reads or continues, it does not restart from zero.
- **A gap is not a clean result.** Never read `complete_with_gaps` as "the target is clean" — it means
  eligible work was not done.
- **Resume is not universal.** Re-running the same profile resumes `project_progress` lanes where they
  stopped; `rerun_same_work` lanes repeat their prefix, and some ledgers are run-local. `--settle` drives
  the resumable ones for you ([campaigns.md](campaigns.md)).
