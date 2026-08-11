# Revisions — late evidence for a sealed run (design, 2026-08-11, rev 1)

> **Verified state 2026-08-11 (Wave B): BUILT** — `revision.py`, routed from `oob.py`, read by
> `campaign.Union.absorb`, `quarry report` and `triage`.

## 1. The problem

A blind SSRF or blind XSS callback arrives minutes or hours after the run that planted the payload has
finished. `quarry oob import` and `quarry oob poll` used to call `Run.add` on that finished run: the row
landed in `normalized/oob_interaction.jsonl` while `manifest.json` kept the `entity_counts` it was
finalized with. The run's own fold then read `degraded` — the manifest count contradicted the log it
certifies — and a campaign dropped the interaction as unusable evidence.

Both halves are unacceptable. Discarding the callback loses the finding; rewriting the manifest destroys
the guarantee that a finished run is a fixed, quotable record.

## 2. The contract

**A run whose base manifest is committed is sealed.** Its `manifest.json`, `run.json`, `normalized/*.jsonl`
and `reports/` are never written again. Late evidence goes to an append-only supplement, and a new
generation of the *combined* view (base plus committed supplement) is published beside it.

Sealed is keyed off the manifest, not off one state name. `write_manifest` runs before the derived views,
so a run that failed finalisation (`finalization_failed`) has a committed manifest and is sealed exactly
like a `finished` one — the failure is in its views, not its evidence. `base_disposition()` returns:

| disposition | when | late evidence |
|---|---|---|
| `sealed` | finalisation settled and the manifest carries `entity_counts` | supplement only |
| `live` | no committed manifest, run still owns its log | `Run.add`, as during the run |
| `finalizing` | the manifest is mid-flight and will be sealed again | refused, retry when it settles |
| `unknown` | `state.json` is present but unreadable, or names a committed state with no manifest | refused |

A run seals its manifest, publishes its views, then seals again, and `quarry report` reopens it to
`finalizing` to republish. A supplement landing in that window would certify against a manifest about to
be replaced, so writing waits. Reading does not: `base_finished()` stays true while a run re-finalises,
because `report` must still render the revision it is republishing. Write gate and read predicate are
deliberately different questions.

`unknown` fails closed on purpose: a lifecycle record we cannot read is not evidence that the run is
writable. A run with *no* `state.json` at all is legacy, and the committed manifest decides.

A revision taken over a `finalization_failed` base is a supplement like any other, and the base stays
sealed: resuming that run (`quarry report`) republishes only the derived views and never calls
`write_manifest`, so the evidence a revision was published over still holds and the resumed report renders
the *combined* view. Only `quarry run` seals a manifest, and it seals a run it just created.

That resume does rewrite one part of the manifest. `Run.reconcile_finalization` answers a publication
fault by clearing `summary.faults` and recomputing the verdict it implies — bookkeeping about the derived
views, not evidence, and expected to change. So a revision certifies the *evidence-bearing* manifest:
everything it records except that pair. Scoping it that way is what keeps a fault-clearing resume from
uncertifying a revision and silently dropping the late rows from the very views it just republished; a
change to `entity_counts`, `tool_runs`, `profile`, `envelope`, `summary.gaps`, `summary.coverage` or
anything else still uncertifies it.

## 3. Layout

    <run>/revisions/
        revision.json                 the pointer — the one authority on what is published
        .publish.lock                 the writer lock (flock) serializing publication
        raw/                          raw evidence acquired after the run was sealed
        rev0001/observations.jsonl    the late observations that revision added (written once, never rewritten)
        rev0001/HOTLIST.md            the combined view's reports, regenerated at that revision
        rev0001/digest.json
        rev0001/exports/

Append-only is meant strictly: no file is ever rewritten. Each revision writes its own segment, and the
supplement is the ordered concatenation of the segments the pointer lists.

## 4. Publication is transactional

Inside the writer lock: adopt whatever pointer is published *now*, re-merge the pending rows onto it, write
the segment whole, regenerate the derived views beside it, then swap the pointer with one atomic write.

The pointer is swapped last, so an interruption leaves the previous revision published and the half-written
directory unreferenced. The next publication numbers strictly above every surviving directory, never
reusing one, and `Revision.orphans` names the bytes that were left. Nothing is silently reclaimed.

Re-adopting the pointer under the lock is what makes concurrent imports safe. Two writers that both opened
at revision 1 would otherwise both publish "revision 2", and the second would carry a segment list that
never mentioned the first — losing a callback that was already on disk. The lock is an `flock` on
`revisions/.publish.lock`, because the writers are separate processes: two `quarry oob import` runs, or an
import racing a `quarry report`.

`reseal_views()` takes the same lock. Re-hashing regenerated views is a read-modify-write of the same
pointer, so unlocked it would write back a pointer that predates a revision published beside it.

## 5. Verification

`revision.read()` is the only way to obtain a published revision, and it certifies before it returns:

- every listed segment is re-hashed against disk (exact bytes and digest);
- the base manifest's evidence-bearing content (§2) is re-hashed against the digest the revision was
  published over — canonical content rather than file bytes, so reformatting alone is not a change;
- every `normalized/*.jsonl` is re-hashed against `base.entity_contents`. The manifest records how MANY
  of each entity a run found, never WHICH, so without this a same-count content swap would leave a
  revision certified over evidence it never saw;
- `views.dir` must name this revision's own directory. It is a path this process creates and writes, so
  an absolute or escaping value would put a run's reports outside the run;
- the segment chain digest must match what the pointer recorded;
- every row's recorded `id`/`fp` must still match its record — one that does not makes the revision
  unusable, not merely degraded;
- the pointer's `entity_counts` are reconciled against the evidence: a supplemented entity is folded
  (base plus committed rows) and must match, an untouched one must equal the base manifest's own count.
  A count nobody reconciles is a claim rather than a record — without this a tampered count certified
  `valid` while the view it described was unusable, and a caller trusting certification exited clean.
  Only supplemented entities are folded, so the cost stays with what actually changed.

Any mismatch yields `unusable` with a reason. A base run whose evidence moved therefore uncertifies every
revision taken over it — which is the immutability guarantee expressed as a check rather than a hope. Per row, the
recorded `id` and `fp` are recomputed from the record, so a tampered segment line is dropped and counted
rather than folded in.

## 6. Who reads the combined view

| reader | call |
|---|---|
| campaign union | `combined_fold(run_dir, kind)` — same `FoldedLog` contract as `store.fold_run_entity` |
| `quarry report` | `combined_view(run)` → a `CombinedRun` rendering into the revision's directory |
| triage | `run.store_ref(entity, record)` — so a digest names the file that actually holds the row |
| any consumer | `view_identity(run_dir)` → `(revision, digest)`, recorded to detect a changed view |

The campaign union records the view identity it absorbed, so a run revised after absorption is folded
again instead of short-circuiting on its run id.

## 7. Bounds

The declared corpus envelope is enforced on the supplement too (`MAX_BYTES_PER_KEY`,
`MAX_KEYS_PER_ENTITY`). Admission is re-run after adopting a concurrently-published revision: the corpus a
row was measured against may have grown, and a bound two writers each honoured alone is not a bound. A
refusal is published with the revision AND returned to the caller as a count, because an ingest that was
entirely turned away must not read as clean success.

Refusals are durable. Each revision republishes the ones still owed — those earlier revisions recorded
plus this writer's, minus any identity actually admitted since — so a refused identity stays refused until
the evidence is really there. Otherwise the next revision would erase the gap: an import would report it,
and the next `status` would report none, while the evidence stayed missing. `refusals(run_dir)` is the
durable query; `outstanding` on an ingest result is its count at that moment.

Whether a base manifest counts as committed is `store.manifest_committed` — called, never copied, so the
rule cannot drift between the store and this module. Supplement data is
discovered evidence: written 0600 through `privfs`, and stored verbatim — only Quarry's own credentials
are ever redacted.
