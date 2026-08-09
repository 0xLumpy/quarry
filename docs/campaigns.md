# Campaigns

`quarry run --settle` runs a **campaign**: a supervisor that keeps creating ordinary child runs while
resumable work still advances. It is a loop over runs, never a knob inside one.

```bash
quarry run -t acme --settle --settle-max-runs 10 --settle-budget 7200
```

## What a campaign is

Each child is a normal run with its own evidence. The campaign adds two things: a **ledger** over the
child run ids, and a **union** that carries what the children learned between them.

```
        ┌─────────────── campaign ───────────────┐
        │  reserve → launch child → absorb delta  │
        │      ▲                         │        │
        │      └──── advances? yes ──────┘        │
        │              no → stop                  │
        └─────────────────────────────────────────┘
   union: every child's trustworthy entities, merged forward
```

Per child, in order:

- **reserve** — the ledger records the child before it launches.
- **bootstrap** — every child after the first is seeded from the union, provenance intact.
- **close acquisition** — from child 2 on, paid/acquisition lanes are closed (the continuation makes no
  new spending decision).
- **absorb** — the child's trustworthy entities merge into the union; the **delta** is the campaign's
  progress signal.
- **decide** — the stop rules run against the child's own structured summary.

## Stopping

A campaign stops when progress stalls (a child neither added nor enriched entities nor reduced a
remainder — two such children in a row), the **`--settle-max-runs`** cap is reached (default 10), the
**`--settle-budget`** wall-clock in seconds is spent, a child reaches a terminal outcome or fault, or
progress becomes unknown. "Progress" is broader than new entities: enrichment of existing ones and a
shrinking remainder count too. The final line names which:

```
══ campaign <id> · <stop reason> · N child run(s) · Ns
   ledger: ~/projects/acme/recon/campaigns/<id>/ledger.json
```

## Inspect

```bash
quarry status -t acme --campaign            # the latest campaign
quarry status -t acme --campaign <id>       # a specific one
```

Running, finished, and interrupted campaigns all read the same way — the view is derived from the ledger.

## What a campaign cannot change

It creates no scope and decides nothing about a run's contents. An inherited entity is never counted as a
child's own discovery, and a child whose evidence could not be read is never absorbed as if it were empty.
The detailed scheduling contract lives in [`design/STEP4-SCHEDULING-DESIGN.md`](design/STEP4-SCHEDULING-DESIGN.md).
