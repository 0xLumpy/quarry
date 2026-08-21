# Architecture

How evidence moves through Quarry, and the boundaries that keep it honest. This is an operator-level
as-built view; the detailed rationale lives under [`design/`](design/).

## Data flow

```
target.yaml
    → scope + mode validation            (config.py: what is authorized, what is armed)
    → phase planning + source policy      (phase registry plus sources.yaml where adopted)
    → guarded tool + native acquisition  (runner + contract: nearly every tool through one choke point)
    → raw evidence                       (retained tool/acquisition bytes plus inputs/state)
    → normalized JSONL + provenance      (store: append-only observation rows)
    → events, coverage, remainder, ownership
    → manifest verdict                   (complete / with_limits / with_gaps)
    → generation-addressed reports + exports
    → optional certified late-evidence revision
    → optional --settle campaign union   (child runs merged forward)
```

The pipeline is nine phases — `horizontal → vertical → dns → probe → crawl → enrich → origin → content →
params` — sharing one evidence store. Migrated tool/acquisition paths produce typed results and retained
artifacts; legacy/direct paths that do not yet meet that contract are listed in the current audit. Each
phase is followed by a coverage checkpoint, but a checkpoint cannot account for a silent/unregistered
lane by inference.

## Boundaries

Five separations carry most of the design:

- **Machine config vs engagement config.** How hard *this host* works (`config.yaml`) is separate from what
  *this engagement* authorizes (`target.yaml`). One is reused across targets; the other is per-target.
- **Discovery lead vs authorized scope.** OSINT and passive sources surface *candidates*. Nothing enters
  scope until an operator confirms it — Quarry never auto-scopes.
- **Acquisition vs interpretation.** On the migrated evidence-acquisition lanes a response is acquired whole
  and stored before it is parsed, so a bounded or failed parse still leaves the bytes and is re-runnable.
  Other paths (JS fetching among them) keep their own per-item acquisition guards.
- **Raw evidence vs normalized observation.** Raw retains the tool/acquisition bytes Quarry successfully
  took ownership of (plus run inputs/state); its result record says whether the stream was complete.
  Normalized JSONL contains the append-only semantic observations. Its folded/deduplicated readings and
  reports are derived views; raw is retained for re-derivation and audit. The current store does not yet
  preserve every relationship through folding, which is tracked in the current-HEAD audit.
- **Run vs campaign.** A run is one pass with its own evidence. A campaign (`--settle`) is a supervisor
  that continues resumable work across child runs — it owns no evidence of its own, only the union.
- **Sealed base vs late evidence.** A committed base run is intended to be immutable. Delayed OOB evidence
  is published as a certified revision of the combined view. The current repository-boundary and
  multi-revision residuals are release blockers, not alternate supported write paths.

## Control plane

Two registries describe much of what runs. `data/tools.yaml` (the [tool index](tools.md)) is the
install/version registry. `data/sources.yaml` records adopted `phase.source` lanes, carrying tier, class,
default state and a reason for anything off by default. Its separate `auxiliary_sources` section records
non-planned native evidence, OSINT, local-classification and control-plane identities with the same source
contract plus ownership and transport semantics. Auxiliary contracts do not enter phase plans, but they are
still canonical lifecycle/effect identities; display provenance labels resolve to those IDs when they emit
coverage. Most external tools use the central runner; long-lived OOB and selected native paths have their
own declared transport doors rather than ambient lifecycle exceptions.

Coverage and provenance are first-class: most entities record which source produced them (a few, like
`wildcard_zone`, do not), and a lane that falls short records why where it emits structured coverage (see
[outputs-and-coverage.md](outputs-and-coverage.md)). `complete` means nothing was flagged, not that every
possible lane ran.

Lifecycle and machine-result records are typed in `state.py`. Base evidence commits before derived views;
finalization is resumable, and late OOB evidence uses `revision.py`. Campaign settlement persists child
obligations and union state. These mechanisms are real foundations, while semantic manifest validation,
repository sealing, revision composition and campaign-history truth remain open release invariants.

## Design references

Rationale and measured shapes live under [`design/`](design/), including provider quota
(`PROVIDER-QUOTA-DESIGN.md`), scheduling (`STEP4-SCHEDULING-DESIGN.md`), Dalfox (`DALFOX-XSS-DESIGN.md`),
evidence extraction (`EVIDENCE-EXTRACTION-DESIGN.md`), Shodan host records (`SHODAN-HOST-DESIGN.md`), and
settle campaigns (`SETTLE-DESIGN.md`). These are internal rationale, not the operator path — their proofs
are not reproduced here.
