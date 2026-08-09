# Architecture

How evidence moves through Quarry, and the boundaries that keep it honest. This is an operator-level
as-built view; the detailed rationale lives under [`design/`](design/).

## Data flow

```
target.yaml
    → scope + mode validation            (config.py: what is authorized, what is armed)
    → phase / source registry            (sources.yaml: which lanes are eligible, and why)
    → guarded tool + native acquisition  (runner + contract: nearly every tool through one choke point)
    → raw evidence                       (raw/<phase>/<tool>/: tool output, plus Quarry's inputs/state)
    → normalized JSONL + provenance      (store: typed, append-only observations)
    → events, coverage, remainder, ownership
    → manifest verdict                   (complete / with_limits / with_gaps)
    → reports + exports
    → optional --settle campaign union   (child runs merged forward)
```

The pipeline is nine phases — `horizontal → vertical → dns → probe → crawl → enrich → origin → content →
params` — sharing one evidence store. Each tool call is captured, classified, and normalized; each phase
is followed by a coverage checkpoint.

## Boundaries

Five separations carry most of the design:

- **Machine config vs engagement config.** How hard *this host* works (`config.yaml`) is separate from what
  *this engagement* authorizes (`target.yaml`). One is reused across targets; the other is per-target.
- **Discovery lead vs authorized scope.** OSINT and passive sources surface *candidates*. Nothing enters
  scope until an operator confirms it — Quarry never auto-scopes.
- **Acquisition vs interpretation.** On the migrated evidence-acquisition lanes a response is acquired whole
  and stored before it is parsed, so a bounded or failed parse still leaves the bytes and is re-runnable.
  Other paths (JS fetching among them) keep their own per-item acquisition guards.
- **Raw evidence vs normalized observation.** Raw is what a tool emitted (plus Quarry's run inputs/state);
  the **normalized** store is canonical — the typed, deduplicated reading the reports are built from. Raw is
  kept for re-derivation and audit.
- **Run vs campaign.** A run is one pass with its own evidence. A campaign (`--settle`) is a supervisor
  that continues resumable work across child runs — it owns no evidence of its own, only the union.

## Control plane

Two registries govern what runs. `data/tools.yaml` (the [tool index](tools.md)) is the install/version
registry. `data/sources.yaml` is the source registry: one entry per `phase.source` lane, carrying its
tier (weight), class (passive/active/deep), and default (on/off/key) with an auditable non-runtime reason
for anything off by default. A source not in the registry never reaches the runner. Most tools run through that runner; the exceptions
are launched directly — the long-lived OOB callback client (`interactsh-client`) and the OSINT native calls
(`whois`, `dig`).

Coverage and provenance are first-class: most entities record which source produced them (a few, like
`wildcard_zone`, do not), and a lane that falls short records why where it emits structured coverage (see
[outputs-and-coverage.md](outputs-and-coverage.md)). `complete` means nothing was flagged, not that every
possible lane ran.

## Design references

Rationale and measured shapes live under [`design/`](design/), including provider quota
(`PROVIDER-QUOTA-DESIGN.md`), scheduling (`STEP4-SCHEDULING-DESIGN.md`), Dalfox (`DALFOX-XSS-DESIGN.md`),
evidence extraction (`EVIDENCE-EXTRACTION-DESIGN.md`), Shodan host records (`SHODAN-HOST-DESIGN.md`), and
settle campaigns (`SETTLE-DESIGN.md`). These are internal rationale, not the operator path — their proofs
are not reproduced here.
