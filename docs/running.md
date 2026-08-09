# Running

`quarry run` executes the recon pipeline against a confirmed profile. This page covers running, the flag
axes, and inspecting a run. For the full worked trace see [example.md](example.md).

## Before a run

```bash
quarry doctor            # host is ready: tools, chromium, resolvers, keys
quarry policy            # the effective machine coverage bounds (it ignores any -t target)
quarry plan              # what would run on this host — scans nothing
```

`plan` takes no target: it reports the registry and machine settings, not a scope preview.

## A normal run

```bash
quarry run -t acme
```

Phases run in order:

```
horizontal → vertical → dns → probe → crawl → enrich → origin → content → params
```

Each tool call captures stdout/stderr/exit/duration, writes raw output under `raw/<phase>/<tool>/`,
classifies the result, and appends normalized entities to `normalized/*.jsonl`. After each phase a
checkpoint evaluates coverage. Results land in `~/projects/acme/recon/<run-id>/`.

## Selecting phases

```bash
quarry run -t acme --phases vertical
quarry run -t acme --phases probe,crawl
```

Phases in **one run** share that run's store, so a later phase reads what earlier ones produced. A phase
run on its own starts a **fresh** store — it does not read a previous run's evidence. Run the phases you
need together (or the whole pipeline); only a `--settle` campaign carries evidence between runs.

## The flag axes

These are independent — each changes a different thing:

| Flag | Axis |
|------|------|
| `--passive` | force passive-only for this run (overrides the profile) — no active probing or scanning |
| `--timeout <s>` | a **floor** on the outer per-tool process kill (default 1800). `0` = no outer kill. Some tools (httpx, ffuf, nuclei, naabu) get larger workload-scaled ceilings; a tool's own internal budget is separate. |
| `--unbound` | lift every registered free-work **volume** ceiling to its unbounded meaning. Obtains no new sources; never changes scope, rate, spending, concurrency, or tool enablement. |
| `--settle` | supervise: keep creating child runs while resumable work advances — see [campaigns.md](campaigns.md) |

`--passive` still runs the passive sources (kaeferjaeger, subfinder, CT lanes, gau, waymore URLs);
active tools (httpx, katana crawl, nuclei, dalfox, naabu, enrich, origin) skip.

## Detached (VPS)

```bash
setsid nohup quarry run -t acme > run.log 2>&1 & disown
```

## Inspect

```bash
quarry status -t acme                 # per-source state of the latest run (from events.jsonl)
quarry status -t acme --run <run-id>  # a specific stored run
quarry report -t acme                 # regenerate HOTLIST / digest / delta + exports from stored evidence, no scanning
```

`status` reads the event stream, so it works during a run and after it. `report` re-derives the reports
from what is already stored — use it after editing nothing, or after a crash.

## A new run or a campaign?

Start a **new run** to re-scan a target from current scope. Use a **campaign** (`--settle`) when a single
run left resumable work — bounded lanes that stopped on a budget — and you want it continued
automatically. See [campaigns.md](campaigns.md).
