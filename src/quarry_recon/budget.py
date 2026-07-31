"""Bounded, FAIR, resumable processing of a lane's FULL eligible input.

This replaces first-N input caps (`eligible[:2000]`). The OTC 20260725 audit showed why they had to go: a
flat cap over a store-ordered list let a few JS-heavy hosts consume the whole budget, and WHICH hosts won
depended on discovery order — so the scanned set ROTATED between runs. `influx1.eco.tsi-dev` went from
433/439 JS files downloaded to 0/439 between two runs of the same target, taking the secrets it carried
with it (24 -> 3). An input cap is the worst available bound: the omitted work is never processed, it was
silent until the coverage counters landed, and it is not even deterministic.

The model, borrowed from where each tool gets it right:
  - reconftw bounds by MODE (all-or-skip on a declared limit), never by an arbitrary subset;
  - bbot bounds THROUGHPUT (per-module queue depth), never set membership.
So: keep the FULL eligible set, order it FAIRLY, bound the THROUGHPUT, and persist the REMAINDER.

Consequences that make this strictly better than a cap:
  - nothing is silently dropped — unprocessed input is a counted, resumable remainder;
  - a bounded run's coverage is spread across hosts instead of concentrated in whichever host sorts first;
  - default is UNBOUNDED (budget 0), so normal operation processes everything and the bound is an explicit
    operator choice — runtime is workload, not a knob to trim.

Per-ITEM size guards (a 15 MB ceiling on one JS file) are NOT caps in this sense and stay: they bound one
item's cost, not which items get processed.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import time
from pathlib import Path

from . import events

_MAX_BUDGET_S = 30 * 24 * 3600        # a month; anything larger is a typo, not a policy


def budget_seconds(key: str) -> int:
    """A lane's wall-clock budget from PERFORMANCE, in seconds. 0 (the DEFAULT) = UNBOUNDED: process the
    whole eligible set. Strictly parsed by the shared coverage-knob parser, so a typo cannot silently
    become a tiny budget."""
    from . import settings
    return settings.strict_int(key, default=0, maximum=_MAX_BUDGET_S)


class Budget:
    """A wall-clock throughput bound. `exhausted()` is checked BETWEEN items, so an item already started
    always finishes — a budget must never leave a half-written artifact."""

    def __init__(self, seconds: int):
        self.seconds = max(0, int(seconds))
        self._t0 = time.monotonic()

    @property
    def unbounded(self) -> bool:
        return self.seconds == 0

    def elapsed(self) -> float:
        return round(time.monotonic() - self._t0, 1)

    def exhausted(self) -> bool:
        return not self.unbounded and (time.monotonic() - self._t0) >= self.seconds


def order_fairly(items, key) -> list:
    """Round-robin the items across their `key(item)` groups (the HOST, in practice), so every host gets
    its 1st item before any host gets its 2nd. This is the whole fix for the cap lottery: with a flat
    order, one host with 825 JS URLs ate a 2000-item budget and starved 40 other hosts.

    Deterministic: groups are visited in sorted key order, and within a group the caller's INPUT order is
    preserved (discovery order carries signal — the crawler found it first for a reason). Same input =>
    same output, so a bounded run's coverage is reproducible instead of order-dependent."""
    groups: dict = {}
    for it in items:
        groups.setdefault(key(it), []).append(it)
    order = sorted(groups)
    out: list = []
    i = 0
    while True:
        added = False
        for k in order:
            g = groups[k]
            if i < len(g):
                out.append(g[i])
                added = True
        if not added:
            return out
        i += 1


def publish_bytes(dest: Path, data: bytes, *, digest: str) -> bool:
    """ATOMICALLY publish `data` at a CONTENT-ADDRESSED `dest`, returning True only once dest provably holds
    exactly these bytes.

    review#2: `if not dest.exists(): dest.write_bytes(data)` is not safe at a content-addressed name. A kill
    mid-write leaves a TRUNCATED file at the final name, and the next attempt sees it exists and reuses it —
    so a lane recorded the digest of what it MEANT to write while the file on disk held something else, and
    the miners read the truncated bytes. Write a same-directory temp, verify what actually landed, then
    os.replace. A pre-existing destination is verified before reuse, never trusted for existing."""
    tmp = None
    try:
        if dest.exists():
            if events.file_digest(dest) == digest:
                return True                       # already published, content confirmed
            dest.unlink()                         # wrong/truncated bytes at a content-addressed name
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + f".part-{os.getpid()}")
        tmp.write_bytes(data)
        if events.file_digest(tmp) != digest:      # verify the WRITE, not the intent
            tmp.unlink(missing_ok=True)
            return False
        os.replace(tmp, dest)
        return True
    except OSError:
        # review-B1.3r8#2: the digest-mismatch path cleaned up and this one did not, so a failing
        # os.replace (or a write that ran out of space) left `<name>.part-<pid>` in a tree whose
        # contract is that every file in it is validated evidence. Measured with a failing replace:
        # leftovers=['.quarry-write-probe.part-756343']. Cleanup belongs in the shared primitive, so
        # every publisher gets it rather than each caller re-deriving the temp name.
        if tmp is not None:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass                              # nothing further we can do; the caller still gets False
        return False


def store_writable(attempt_dir) -> bool:
    """Whether a bought page could actually be PUBLISHED — proven by writing, not assumed.

    review-B1.3r7#2: the ledger was probed before spending and the artifact store was not, so a
    read-only attempt directory was discovered by paying for a page and then failing to store it
    (`calls=[1]`, `stop_cause=publish_failed`) — and the next run bought it again. Both sinks are
    required, so both are proven up front.

    The probe exercises the same primitive the real page uses (temp + verify + replace) and then REMOVES
    itself: an artifact directory must contain only real evidence, and a probe we cannot clean up is
    itself a failure — it would be an orphan in a tree whose contract says every file is a validated
    artifact.

    B1.6: moved here from the Shodan coordinator, because the Whoxy paginator needs the identical probe
    and the contract really is the same one. Two copies of a safety precondition would drift."""
    probe = Path(attempt_dir) / ".quarry-write-probe"
    body = b'{"probe":1}'
    try:
        Path(attempt_dir).mkdir(parents=True, exist_ok=True)
        ok = publish_bytes(probe, body, digest=hashlib.sha256(body).hexdigest())
        probe.unlink(missing_ok=True)
        return bool(ok) and not probe.exists()
    except OSError:
        return False


def order_ranked_fair(items, *, rank, group) -> list:
    """Order by RANK TIER first, then round-robin fairly WITHIN each tier.

    Lumpy's rule, encoded: **ranking may determine the order work is done in, but never permanent
    membership.** A lane that prefers origin (non-CDN) hosts, or https over http, keeps that preference as a
    TIER ORDER — every item still appears in the output, so a budget that stops early has simply done the
    most valuable work first rather than excluded anything.

    Fairness applies inside a tier for the same reason it does anywhere: without it, one host's eight ports
    drain the budget before another host's first port is touched."""
    tiers: dict = {}
    for it in items:
        tiers.setdefault(rank(it), []).append(it)
    out: list = []
    for r in sorted(tiers):
        out += order_fairly(tiers[r], group)
    return out


def ledger_writable(ledger) -> bool:
    """Whether completions can actually be JOURNALED — a precondition, not a postcondition.

    review-shodan-r3#1: writability was checked only AFTER every purchase, so a foreign ledger let a run
    buy 15 pages and then report `persisted=False`, and the next lifecycle bought all 15 again. For paid
    work that difference is money; for free work it is a run that cannot resume.

    B1.7: lives HERE because it is a question about a `Ledger` and nothing else. It existed identically in
    `shodan_sched` and `whoxy_page`, and a third copy in the host lane is how three answers to one question
    start to drift apart."""
    return not getattr(ledger, "foreign", False) and not getattr(ledger, "_journal_unsafe", False)


class StateBusy(RuntimeError):
    """Another lifecycle already holds this lane's state.

    CONTENTION ONLY. A read-only filesystem, a bad descriptor or a filesystem without lock support raises
    the underlying OSError instead — reporting those as "another run is active" sends an operator looking
    for a process that does not exist (review-B1.6b2#2, learned on the Whoxy lock)."""


@contextlib.contextmanager
def state_lock(path):
    """An exclusive, ADVISORY, OS-RELEASED lock over one lane's PROJECT state — the lock a `Ledger` needs.

    Every ledger-owning lane has the same problem: two runs of the same project load the same snapshot, do
    the same work twice, then race while compacting and unlinking the journal that supersedes it — which is
    how ownership gets lost outright. THIS is that lock, defined once next to `Ledger`, because three lanes
    answering the same question separately is how the three answers drift apart.

    `flock` and not lockfile EXISTENCE: a stale file from a killed run would block the project forever,
    while the kernel drops an flock when the holder dies, however it dies. The file is never unlinked —
    removing it lets a second process lock a path the first no longer shares.

    Non-blocking: contention raises `StateBusy` immediately rather than parking a run behind another one
    for an unbounded time. A caller decides what contention MEANS for it (a gap, a retry, a skip)."""
    import errno
    import fcntl
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = path.open("a+")
    try:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            if e.errno not in (errno.EACCES, errno.EAGAIN):
                raise
            raise StateBusy(f"another lifecycle holds {path}") from e
        yield path
    finally:
        # closing the descriptor releases the lock on EVERY exit, BaseException included: a cancelled run
        # must not wedge the project until someone notices a leftover file.
        fh.close()


def state_path(base, lane: str, config_fp: str):
    """The per-lane ledger path, namespaced by a COVERAGE-CONFIG fingerprint.

    A per-item ledger cannot use the work_unit trick the chunked lanes use, and it must not skip an item
    whose artifact was produced under a DIFFERENT coverage config (a changed wordlist, changed match codes):
    that artifact still validates by digest and would be wrongly treated as done. Putting the config
    fingerprint in the FILENAME means a config change starts a clean generation — no stale entries, and no
    collision with the foreign-path guard (a same-path different-lane state is a different problem, and
    `Ledger.foreign` must keep meaning exactly that)."""
    return Path(base) / f"{lane.replace('.', '_')}.{config_fp[:12]}.state.json"


def prune_state(base, lane: str, keep_fp: str) -> None:
    """Drop ledgers for superseded coverage configs of this lane, so the run dir does not accumulate them."""
    keep = state_path(base, lane, keep_fp).name
    for old in Path(base).glob(f"{lane.replace('.', '_')}.*.state.json"):
        if old.name != keep:
            old.unlink(missing_ok=True)
            old.with_name(old.name + ".journal").unlink(missing_ok=True)


class Ledger:
    """A per-ITEM record of work already completed for a lane, so an interrupted or budget-bounded run
    RESUMES instead of restarting — and so the remainder is a fact rather than a silent omission.

    Deliberately NOT shaped like nuclei's chunk state, and the difference matters: nuclei keys its state on
    a work_unit folding the whole host list, because its chunks are defined by that list. A fetch lane's
    eligible set GROWS every run (more crawling => more JS URLs), so a work-unit-gated map would invalidate
    on every growth and re-fetch everything. This ledger is keyed per ITEM, so a growing set simply leaves
    the new items as remainder.

    Only SUCCESSES are persisted. A failed fetch is NOT completed work: a transient 502 must be retried on
    the next run, and since we cannot distinguish transient from permanent, retrying is the coverage-first
    choice. Failures are still counted for THIS run's coverage.

    Completed entries are CONTENT-BOUND (sha256): a recorded artifact that was truncated or edited on disk
    is not trusted, the item is redone. Path validity is not content validity.

    The ledger is the AUTHORITY on an item's artifact — callers must ask `artifact(item)` rather than
    recomputing a path. review#4: when the caller derived its own destination and only checked that it
    EXISTED, a state entry could bind item B to item A's (valid) artifact while B's own destination sat
    stale or altered and got skipped with nothing verified. One lookup, one verification, one truth.

    PERSISTENCE IS O(n) (review#5): each completion APPENDS one line to a journal; the compacted snapshot is
    written once, atomically, at `save()`. Re-serializing the whole map every N records was quadratic —
    151k items at a 25-record checkpoint would have serialized ~456M cumulative entries before the lane did
    any real work. Load reads the snapshot then replays the journal, so a kill loses at most the partial last
    line. Digest verification is CACHED PER ARTIFACT, not per item, so a body shared by 400 URLs is hashed
    once instead of 400 times."""

    def __init__(self, state_file: Path, *, lane: str):
        self.path = Path(state_file)
        self.journal = self.path.with_name(self.path.name + ".journal")
        self.lane = lane
        self.done: dict[str, str] = {}        # item -> COMPLETION artifact (relative to the state file's dir)
        self.evid: dict[str, list] = {}       # item -> EVERY retained artifact, append-only (review#2 A1 r3)
        self.digests: dict[str, str] = {}     # relative artifact path -> sha256
        self._journal_unsafe = False          # set when the journal may not be APPENDED to
        self._journal_lost = False            # set when the journal can no longer be REPLAYED
        self.foreign = False                  # set when this PATH belongs to a DIFFERENT lane
        self._raw_evid: dict[str, list] = {}  # unvalidated evidence lists from the snapshot
        self._load()

    def _resolved_base(self) -> Path:
        return self.path.parent.resolve()

    def _safe_path(self, rel) -> Path | None:
        """The artifact for `rel`, or None if it escapes the lane's directory. Uses RESOLVED containment, so
        a symlink pointing outside is rejected too — a lexical `..` check alone does not see through one."""
        if not isinstance(rel, str) or not rel or Path(rel).is_absolute() or ".." in Path(rel).parts:
            return None
        p = self.path.parent / rel
        try:
            if not p.resolve().is_relative_to(self._resolved_base()):
                return None
        except (OSError, ValueError):
            return None
        return p

    def _read_snapshot(self) -> tuple[dict, dict]:
        try:
            raw = json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError):
            return {}, {}
        if not isinstance(raw, dict):
            return {}, {}                     # garbled state: start clean rather than guess
        if raw.get("lane") != self.lane:
            # review#3 (r5): a snapshot belonging to ANOTHER lane must not merely be ignored — save() would
            # then overwrite it and destroy that lane's completions. Mark the path foreign and refuse to write.
            self.foreign = True
            return {}, {}
        done, digests = raw.get("done"), raw.get("digests")
        if not (isinstance(done, dict) and isinstance(digests, dict)):
            return {}, {}
        ev = raw.get("evidence")
        if isinstance(ev, dict):
            for k, v in ev.items():
                if isinstance(k, str) and isinstance(v, list):
                    self._raw_evid[k] = [x for x in v if isinstance(x, str)]
        return done, digests

    JOURNAL_SCHEMA = 1

    def _replay_journal(self, done: dict, digests: dict) -> None:
        """Fold appended completions over the snapshot, then repair a damaged TAIL — but never mutate a
        journal that is not ours.

        review#4 (r3): every line carries its lane and schema, because the snapshot's lane guard was
        bypassable through an uncompacted journal.

        review#4 (r4): the repair itself was destructive. Foreign-lane lines were dropped from `kept` and the
        journal was then rewritten without them — so lane B merely OPENING lane A's uncompacted journal
        DELETED A's completions. A lane mismatch now means "this journal is not mine": no replay, no rewrite,
        nothing touched. Only a torn/garbled tail of OUR OWN records is repaired, and if that repair fails we
        refuse to append (an append onto a fragment corrupts the next record too)."""
        try:
            text = self.journal.read_text()
        except OSError:
            return
        lines = text.splitlines()
        kept: list[str] = []
        pending: list[tuple] = []
        damaged = not text.endswith("\n")          # a partial last write leaves no terminator
        for line in lines:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                damaged = True
                continue
            if not isinstance(rec, dict):
                damaged = True
                continue
            if rec.get("v") != self.JOURNAL_SCHEMA or rec.get("l") != self.lane:
                # NOT OURS. Leave the file completely alone and take nothing from it.
                self.foreign = True
                return
            item, rel, dig = rec.get("i"), rec.get("r"), rec.get("d")
            ev_item = rec.get("e")
            if isinstance(item, str) and isinstance(rel, str) and isinstance(dig, str) and rel and dig:
                pending.append((item, rel, dig))
                kept.append(line)
            elif isinstance(ev_item, str) and isinstance(rel, str) and isinstance(dig, str) and rel and dig:
                self._raw_evid.setdefault(ev_item, []).append(rel)   # evidence-only journal record
                digests[rel] = dig
                kept.append(line)
            elif rec.get("k") == "ckpt":
                kept.append(line)                  # durability probe: carries no state, repairs nothing
            else:
                damaged = True
        for item, rel, dig in pending:
            done[item] = rel
            digests[rel] = dig
        if damaged:
            try:                                    # truncate to the intact prefix so the next append is clean
                tmp = self.journal.with_name(self.journal.name + ".repair")
                tmp.write_text("".join(ln + "\n" for ln in kept))
                os.replace(tmp, self.journal)
            except OSError:
                # repair failed -> appending would land on the fragment. Stop journalling; save() still
                # compacts the in-memory state, so completions are not lost, only un-journalled.
                self._journal_unsafe = True

    def _load(self) -> None:
        done, digests = self._read_snapshot()
        self._replay_journal(done, digests)
        verified: dict[str, bool] = {}         # rel -> ok. ONE hash per artifact, not per item.
        for item, rel in done.items():
            if not isinstance(item, str):
                continue
            want = digests.get(rel) if isinstance(rel, str) else None
            if not (isinstance(want, str) and want):
                continue                       # unverifiable -> redo (fails CLOSED)
            ok = verified.get(rel)
            if ok is None:
                p = self._safe_path(rel)
                try:
                    ok = p is not None and p.is_file() and events.file_digest(p) == want
                except OSError:
                    ok = False
                verified[rel] = ok
            if ok:
                self.done[item] = rel
                self.digests[rel] = want
                # review#3 (A1 r4): a validated COMPLETION is always also evidence. Journal replay restores
                # `done` but never touched `_raw_evid`, so a crash after journalling completion and before
                # compaction resumed the item while replaying NOTHING — reproduced: has=True, evidence=[].
                # Old snapshots written without an `evidence` field hit the same hole. Deriving it here fixes
                # both, and every Ledger caller (vhost included) inherits the fix.
                self._raw_evid.setdefault(item, [])
                if rel not in self._raw_evid[item]:
                    self._raw_evid[item].insert(0, rel)
        # review#2 (A1 r3): retained EVIDENCE is digest-bound too. Replaying whatever matched a glob under
        # attempt-*/ trusted mutable, unbound files — a tampered, planted or symlinked artifact could inject
        # fabricated findings into normalized data. "Immutable" has to be VERIFIED, not assumed.
        for item, rels in self._raw_evid.items():
            keep = []
            for rel in rels:
                want = digests.get(rel)
                if not (isinstance(want, str) and want):
                    continue
                ok = verified.get(rel)
                if ok is None:
                    q = self._safe_path(rel)
                    try:
                        ok = q is not None and q.is_file() and events.file_digest(q) == want
                    except OSError:
                        ok = False
                    verified[rel] = ok
                if ok:
                    keep.append(rel)
                    self.digests[rel] = want
            if keep:
                self.evid[item] = keep

    def has(self, item: str) -> bool:
        return item in self.done

    def evidence(self, item: str) -> list:
        """Every VALIDATED retained artifact for this item, oldest first. Completion is separate: a historical
        artifact contributes EVIDENCE only and can never decide whether the item is done (review#1 A1 r3)."""
        return [q for q in (self._safe_path(r) for r in self.evid.get(item, [])) if q is not None]

    def add_evidence(self, item: str, artifact: Path, *, digest: str | None = None) -> bool:
        """Retain an artifact as evidence WITHOUT claiming completion. Append-only and digest-bound."""
        rel = str(Path(artifact).relative_to(self.path.parent))
        dig = digest or events.file_digest(artifact)
        lst = self.evid.setdefault(item, [])
        if rel not in lst:
            lst.append(rel)
        self.digests[rel] = dig
        return self._append({"e": item, "r": rel, "d": dig})

    def artifact(self, item: str) -> Path | None:
        """The artifact this item's content lives in — THE lookup callers must use. May be SHARED with
        another item: two URLs serving byte-identical bodies are content-addressed to one file, and both
        get an entry pointing at it."""
        rel = self.done.get(item)
        return self._safe_path(rel) if rel else None

    def items(self):
        """(item, artifact) for every validated completion. Lets a downstream lane iterate what was actually
        obtained instead of re-deriving paths and guessing which exist."""
        for item, rel in self.done.items():
            p = self._safe_path(rel)
            if p is not None:
                yield item, p

    def artifacts(self) -> list:
        """The DISTINCT validated artifacts, deduplicated — the exact set that may be published to a derived
        tree. Anything else in the lane's directory is an orphan and must not reach a scanner."""
        seen, out = set(), []
        for _item, p in self.items():
            if p not in seen:
                seen.add(p)
                out.append(p)
        return out

    @property
    def durable(self) -> bool:
        """Whether completions recorded so far will SURVIVE this process — i.e. the journal is intact.
        Independent of `save()`: a successful journal makes a run resumable even if compaction later
        fails, because `_load` replays the journal.

        review-B1.3r5#2: this read `_journal_unsafe`, which answers a DIFFERENT question — "may I append?"
        `save()` sets that flag when the SNAPSHOT write fails, deliberately keeping the journal, so the
        completions still replay on the next open. Measured: `save()=False`, journal present, completion
        survives reopen — and durability nonetheless read False, producing a false persistence gap on
        genuinely resumable work."""
        return not self.foreign and not self._journal_lost

    def record(self, item: str, artifact: Path, *, digest: str | None = None) -> bool:
        """Mark an item complete and bind its artifact's content. APPENDS to the journal (O(1)) — the whole
        map is only re-serialized by save()."""
        rel = str(Path(artifact).relative_to(self.path.parent))
        dig = digest or events.file_digest(artifact)
        self.done[item] = rel
        self.digests[rel] = dig
        if rel not in self.evid.setdefault(item, []):
            self.evid[item].append(rel)        # a completion artifact is always also evidence
        return self._append({"i": item, "r": rel, "d": dig})

    def checkpoint(self) -> bool:
        """PROVE the journal is writable, without claiming anything. review-B1.3r5#3: `ledger_writable`
        only reads flags, and the flags for an unwritable journal are only set BY a failed write — so a
        paid caller had to spend one credit to discover it could not record the result. This appends a
        no-op record that carries no state and is ignored on replay."""
        return self._append({"k": "ckpt"})

    def _append(self, rec: dict) -> bool:
        """True when the record is DURABLY journaled. review-B1.3r4: this swallowed OSError silently and
        left both safety flags clear, so a caller could not tell an appended completion from one that
        exists only in memory — and for PAID work that difference is money."""
        if self.foreign or self._journal_unsafe:
            return False                       # never append onto a foreign or fragmented journal
        try:
            self.journal.parent.mkdir(parents=True, exist_ok=True)
            with self.journal.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"v": self.JOURNAL_SCHEMA, "l": self.lane, **rec}) + "\n")
            return True
        except OSError:
            self._journal_unsafe = True        # in-memory state is correct but NOT appendable
            # APPENDABILITY and REPLAYABILITY differ here too: a torn tail is repaired to its intact
            # prefix on load, so records that already returned True still replay. Only a journal we can
            # no longer read is actually lost.
            try:
                self._journal_lost = not self.journal.is_file()
            except OSError:
                self._journal_lost = True
            return False

    def save(self) -> bool:
        """COMPACT: write the snapshot atomically (temp + os.replace), then drop the journal it supersedes.
        A crash mid-write leaves the previous snapshot AND its journal intact, so nothing is lost.

        Returns False without writing anything when the path is FOREIGN (review#3 r5) — overwriting another
        lane's state would destroy its completions, and the caller reports the failure instead."""
        if self.foreign:
            return False
        # review#3 (r7): the contract is "returns success, never raises". mkdir / write / os.replace can all
        # fail on a full or read-only filesystem, and callers only handled a returned False — so a real IO
        # failure bypassed the state_persisted gap entirely and could surface as an exception from the lane
        # body instead, masking whatever the lane was actually doing.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(self.path.name + ".tmp")
            tmp.write_text(json.dumps({"lane": self.lane, "done": self.done,
                                       "evidence": self.evid, "digests": self.digests}))
            os.replace(tmp, self.path)
        except OSError:
            self._journal_unsafe = True       # the snapshot is not authoritative; keep the journal
            return False
        # review#3 (r5): append safety is restored ONLY if the damaged journal is actually gone. Clearing the
        # flag on a journal we failed to remove sent the next record onto the fragment, where it vanished.
        try:
            self.journal.unlink(missing_ok=True)
            self._journal_unsafe = self.journal.exists()
        except OSError:
            self._journal_unsafe = True
        return True


def report_selection(lane: str, *, measure: str, eligible: int, attempted: int, budget: Budget,
                     noun: str = "item", durable: bool = True) -> None:
    """SELECTION coverage: of everything eligible, how much did we get to at all?

    Emitted EVERY run (omitted=0 when the whole set was processed) so a later unbounded rerun CLEARS a prior
    gap. COVERAGE_CAP: a budget that stopped us short IS a hard ceiling that truncated eligible input, so it
    must read as a gap whenever omitted > 0 — never as an operator-chosen SAMPLE, which would be a soft
    limit and let the run still call itself complete."""
    omitted = max(0, eligible - attempted)
    if omitted:
        # review#4 (r7): only call the remainder RESUMABLE when the completion state was actually persisted.
        # Otherwise the next run starts over, and "resumable" is a false promise.
        tail = ("left as a RESUMABLE remainder" if durable else
                "left over — completion state was NOT persisted, so this lane RESTARTS from the beginning")
        why = (f"{noun} budget exhausted after {budget.elapsed()}s of {budget.seconds}s — "
               f"{attempted}/{eligible} processed, {omitted} {tail}")
    else:
        why = f"{attempted}/{eligible} {noun}(s) processed (whole eligible set)"
    # unit MUST be distinct per measure: reconciliation keeps the latest per (source_id, unit), so leaving
    # it to default to the source_id would make the outcome report OVERWRITE the selection report and one of
    # the two facts would silently vanish from the rollup.
    events.coverage_partial(lane, kind=events.COVERAGE_CAP, measure=measure, unit=measure,
                            eligible=eligible, tested=attempted, omitted=omitted, reason=why)


def report_outcome(lane: str, *, measure: str, attempted: int, obtained: int, classes: dict | None = None,
                   noun: str = "item") -> None:
    """OUTCOME coverage: of what we DID attempt, how much actually came back?

    Separate from selection because the causes differ and so do the fixes: selection loss is ours (a budget),
    outcome loss is the target's (a 403, a timeout, a body over the size guard). COVERAGE_TIMEOUT is the
    lost-in-flight bucket. This measure was entirely invisible before — the OTC runs attempted 2000 JS URLs
    and obtained 628 and then 1321, a 69%/34% failure rate nobody could see."""
    lost = max(0, attempted - obtained)
    detail = f" {dict(sorted(classes.items()))}" if classes else ""
    why = (f"{obtained}/{attempted} attempted {noun}(s) obtained; {lost} failed in flight{detail}"
           if lost else f"all {attempted} attempted {noun}(s) obtained")
    events.coverage_partial(lane, kind=events.COVERAGE_TIMEOUT, measure=measure, unit=measure,
                            eligible=attempted, tested=obtained, omitted=lost, reason=why)
