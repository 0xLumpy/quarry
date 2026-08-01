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
import math
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


#: only `rotation_session` holds this, so only it can build an already-locked progress map. A public
#: `held=True` was an escape hatch: any caller could have written the lane file with no lock at all.
_SESSION = object()


class SchedulerInvariant(RuntimeError):
    """A scheduling fact moved under the holder of the lane lock — a BUG, never an expected disposition.

    One sweeper owns a lane for the whole sweep, so nothing else can re-reserve a slot while it runs. A
    generation that changes anyway means the state was written by something that ignored the lock, or the
    driver reserved twice. Callers report it as MACHINERY and stop the lane; they never treat it as an
    ordinary outcome (step-4 design v9#1)."""


@contextlib.contextmanager
def rotation_session(state_dir, lane: str, *, schema: int, slot_grammar=None):
    """`with rotation_session(dir, "a1d", schema=1) as progress:` — the ONLY way to reach lane progress.

    Takes the lane's lock ONCE and yields a `RotationProgress` that knows the lock is HELD, so no `save()`
    inside the session acquires it a second time. That is structural, not a caller convention: `state_lock`
    is flock-based, so a nested acquisition in the SAME process raises `StateBusy` (proven) — a `save()`
    that re-locked would report every write as contended (step-4 design v8#1 / v9#2).

    Contention is an ACQUISITION fact: `StateBusy` escapes from entering this manager and means another
    lifecycle owns the rotation. A `StateBusy` raised inside the body is the body's own machinery failure
    and must not be reported as contention (v10#2) — so callers enter this manager under their own
    `except`, and run the sweep outside it.
    """
    base = Path(state_dir)
    with state_lock(base / f"{lane}.lock"):
        yield RotationProgress(base / f"{lane}.json", lane=lane, schema=schema,
                               slot_grammar=slot_grammar, _session=_SESSION)


#: how long a save OUTSIDE a session waits for the lane lock, and how often it retries. Giving up does NOT
#: proceed unlocked: `save()` answers False, because a write we could not serialise is not an atomic save.
_ROTATION_LOCK_WAIT_S = 5.0
_ROTATION_LOCK_POLL_S = 0.05


def _acquire_bounded(path: Path):
    """An exclusive lock on `path` within a bounded wait, or None. NEVER blocks indefinitely."""
    import errno
    import fcntl
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fh = path.open("a+")
    except OSError:
        return None
    deadline = time.monotonic() + _ROTATION_LOCK_WAIT_S
    while True:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fh
        except OSError as e:
            if e.errno not in (errno.EACCES, errno.EAGAIN) or time.monotonic() >= deadline:
                fh.close()
                return None
            time.sleep(_ROTATION_LOCK_POLL_S)


class RotationProgress:
    """PROJECT-LEVEL rotation state for one lane: which slot was RESERVED when, and what it last RAN.

    It ORDERS and nothing else. It never records an outcome, never claims completion, and losing it costs
    ordering quality rather than coverage — evidence stays run-scoped (step-4 design).

    Two independently ordered tuples per slot, never merged field-by-field:

        res  = {"gen": int, "at": float}                     # the reservation: taken BEFORE the tool runs
        done = {"gen": int, "at": float, "c": str, "n": int}  # written AFTER the invocation RETURNED

    `c` is the digest of the members actually submitted, so a slot whose membership changed since it last
    ran is DIRTY and outranks clean slots. Writing `c` at reservation time would have made a crash before
    the launch look clean (v4#3).
    """

    def __init__(self, path, *, lane: str, schema: int, slot_grammar=None, _session=None):
        # the CONFIGURED schema is validated too (review v12#4): `int(True)` is 1 and `int("2")` is 2, and a
        # schema that coerces is a rotation that can be read under the wrong meaning.
        if isinstance(schema, bool) or not isinstance(schema, int) or schema < 0:
            raise ValueError(f"schema must be an exact non-negative int, got {schema!r}")
        self.path = Path(path) if path else None
        self.lane = lane
        self.schema = schema
        #: the lane's slot-id grammar, or None for a lane that does not constrain ids. Rank inheritance
        #: walks ids STRUCTURALLY (root + extension bits), so a document holding arbitrary dotted strings
        #: could otherwise make unrelated slots each other's ancestors (v25).
        if slot_grammar is not None and not callable(slot_grammar):
            raise ValueError(f"slot_grammar must be callable, got {slot_grammar!r}")
        self.slot_grammar = slot_grammar
        self.held = _session is _SESSION       # ONLY `rotation_session` can hand over the token
        self.gen = 0
        self.targets: dict = {}
        #: `missing` (no file yet) · `valid` (parsed clean) · `degraded` (parsed, but records were dropped
        #: or repaired, so work may repeat) · `unusable` (present and not trustworthy at all). A driver must
        #: be able to say which of those happened instead of reporting advancement over a prefix it
        #: silently repeated.
        self.state_status = "missing"
        self.state_reason = ""
        self._read()

    # ── validation: every record is fail-closed. An unusable record reads as "never run", which puts the
    #    slot at the FRONT of the rotation — the safe direction for a scheduler that only orders. ──
    @staticmethod
    def _num(value, *, minimum=0.0):
        """A TIMESTAMP we can order by: finite, non-negative, never a bool."""
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        try:
            v = float(value)                       # a 401-digit JSON integer raises OverflowError here
        except (OverflowError, ValueError):
            return None
        if not math.isfinite(v) or v < minimum:
            return None
        return v

    @staticmethod
    def _count(value):
        """An EXACT non-negative integer. `True` is not 1 and `1.9` is not 1: a generation that silently
        truncates breaks the ordering it exists to provide, and a fractional member count is not a count."""
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        return value if value >= 0 else None

    @classmethod
    def _tuple(cls, raw, *, with_content: bool):
        if not isinstance(raw, dict):
            return None
        gen, at = cls._count(raw.get("gen")), cls._num(raw.get("at"))
        # review v13b#1: generations START AT 1. `reserve()` refuses to allocate 0 and `complete()` refuses
        # to accept it, so a PERSISTED 0 cannot have come from this map — and reading it as real made a
        # never-run slot report CLEAN, which is the one direction a rotation must never fail in.
        if gen is None or gen < 1 or at is None:
            return None
        out = {"gen": gen, "at": at}
        if with_content:
            c, n = raw.get("c"), cls._count(raw.get("n"))
            if not isinstance(c, str) or not c or n is None:
                return None
            out["c"] = c
            out["n"] = n
        return out

    @classmethod
    def _parse(cls, text: str, *, lane: str, schema: int, slot_grammar=None) -> tuple:
        """`(gen, targets)` from a state document, or a FRESH rotation when it cannot be trusted.

        A different lane or a different schema starts fresh rather than being reinterpreted: the schema
        binds the bucket count, the hash and the record's meaning, so an old document is not the same
        question asked earlier — it is a different question."""
        try:
            doc = json.loads(text)
        except (ValueError, TypeError):
            return 0, {}, "unusable", "not a JSON document"
        if not isinstance(doc, dict):
            return 0, {}, "unusable", f"top level is a {type(doc).__name__}, not an object"
        if doc.get("lane") != lane:
            return 0, {}, "unusable", f"lane is {doc.get('lane')!r}, not {lane!r}"
        if cls._count(schema) is None:                   # the CALLER's schema, checked at this boundary
            return 0, {}, "unusable", f"configured schema {schema!r} is not an exact non-negative int"
        if cls._count(doc.get("schema")) != schema:      # 1.0 is not 1 here, and False is not 0
            return 0, {}, "unusable", f"schema {doc.get('schema')!r} != {schema} — a different question"
        gen = cls._count(doc.get("gen"))
        raw_targets = doc.get("targets")
        if gen is None or not isinstance(raw_targets, dict):
            return 0, {}, "unusable", "generation or targets malformed"
        targets: dict = {}
        dropped = 0                                        # records we could not trust (review v12#5)
        repaired = 0                                       # records we clamped back into consistency
        for name, raw_t in raw_targets.items():
            # review v13b#2: the same identity rule the mutations enforce — an empty key is not a target,
            # on the way in or the way out.
            if not isinstance(name, str) or not name or not isinstance(raw_t, dict):
                dropped += 1                               # a container we cannot read is not a target
                continue
            seq = cls._count(raw_t.get("seq"))
            raw_slots = raw_t.get("slots")
            if seq is None or not isinstance(raw_slots, dict):
                dropped += 1
                continue
            if seq > gen:
                # review v12#3: a cursor AHEAD of the lane generation would keep this target at the back of
                # the fairness order for as many lifecycles as the gap is wide. Clamp and say so.
                seq, repaired = gen, repaired + 1
            slots: dict = {}
            for bucket, raw_s in raw_slots.items():
                if not isinstance(bucket, str) or not bucket or not isinstance(raw_s, dict):
                    dropped += 1
                    continue
                if slot_grammar is not None:
                    # `_parse` NEVER raises (review v11#1), and that promise now covers a caller-supplied
                    # predicate: a grammar that blows up leaves the rotation unusable, not the read.
                    try:
                        usable = slot_grammar(bucket)
                    except Exception as e:
                        return 0, {}, "unusable", f"slot grammar raised ({type(e).__name__})"
                    if not usable:
                        dropped += 1                   # not an id of this slot space: it may not rank
                        continue
                res = cls._tuple(raw_s.get("res"), with_content=False)
                done = cls._tuple(raw_s.get("done"), with_content=True)
                # a completion without its reservation, or one claiming to precede it, is not a record we
                # can order — it reads as never-run, which is the SAFE direction for a rotation.
                if done is not None and (res is None or done["gen"] > res["gen"]):
                    done, dropped = None, dropped + 1
                if res is not None and res["gen"] > gen:
                    dropped += 1
                    continue                               # a slot ahead of its own lane generation
                if res is None and done is None:
                    if raw_s:
                        dropped += 1
                    continue
                slots[bucket] = {k: v for k, v in (("res", res), ("done", done)) if v is not None}
            highest = max([s["res"]["gen"] for s in slots.values() if "res" in s] or [0])
            # v78: a TARGET-level admission refusal. It orders (never claims execution), so it is parsed
            # fail-closed like everything else: unusable means "never refused", which is the safe
            # direction — the target simply keeps its ordinary tier.
            adm = cls._tuple(raw_t.get("adm"), with_content=False)
            if adm is not None and adm["gen"] > gen:
                adm, dropped = None, dropped + 1
            targets[name] = {"seq": max(seq, highest), "slots": slots}
            if adm is not None:
                targets[name]["adm"] = adm
        if dropped or repaired:
            # salvaging the healthy records is right, but the driver must not present the result as an
            # intact rotation: work may repeat, and that is a fact it has to be able to say.
            return gen, targets, "degraded", (f"{dropped} unusable record(s) dropped, "
                                              f"{repaired} cursor(s) clamped to the lane generation")
        return gen, targets, "valid", ""

    def _read(self) -> None:
        if self.path is None:
            self.state_status, self.state_reason = "missing", "no state path"
            return
        try:
            text = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            self.state_status = "missing"           # a first run, not a loss
            return
        except (OSError, UnicodeError) as e:
            # unreadable progress = a fresh rotation, never a stop — but the driver must be able to SAY so
            self.state_status, self.state_reason = "unusable", f"unreadable ({type(e).__name__})"
            return
        try:
            self.gen, self.targets, self.state_status, self.state_reason = self._parse(
                text, lane=self.lane, schema=self.schema, slot_grammar=self.slot_grammar)
        except Exception as e:                      # `_parse` must never raise (review v11#1)
            self.gen, self.targets = 0, {}
            self.state_status, self.state_reason = "unusable", f"unparseable ({type(e).__name__})"

    # ── reading the rotation ──────────────────────────────────────────────────────────────────────
    def _slot(self, target: str, bucket: str) -> dict:
        return (self.targets.get(target, {}).get("slots", {}) or {}).get(bucket, {})

    def target_seq(self, target: str) -> int:
        """The reservation SEQUENCE this target was last selected at — the fairness cursor. A sequence, not
        a clock: a backward jump in wall time must not reorder the rotation (v4#4)."""
        return int(self.targets.get(target, {}).get("seq", 0))

    @staticmethod
    def _parts(bucket: str) -> tuple:
        """A slot id as (root, bits). `177` is the 8-bit root at extension depth 0; `177.0110` is the same
        root with four extension bits."""
        head, _dot, bits = bucket.partition(".")
        return head, bits                      # no separator -> no extension bits, and `partition` says so

    @classmethod
    def _contains(cls, parent: str, child: str) -> bool:
        """Containment is on the PARSED id, not on the string (v24#1). `177.0` contains `177.00`, whose id
        does NOT begin with `177.0.` — the extension bits extend, they do not nest a second separator.
        Different roots are never related, so slot `70` is not a child of slot `7`."""
        proot, pbits = cls._parts(parent)
        croot, cbits = cls._parts(child)
        return proot == croot and len(cbits) > len(pbits) and cbits.startswith(pbits)

    @staticmethod
    def _ancestors(bucket: str) -> list:
        """The containing slots of a hash-prefix id, NEAREST FIRST: `177.0110` is contained in `177.011`,
        `177.01`, `177.0` and `177`. A flat id has no ancestors, so a lane that never splits is unaffected."""
        head, dot, bits = bucket.partition(".")
        if not dot:
            return []
        out = []
        while bits:
            bits = bits[:-1]
            out.append(f"{head}.{bits}" if bits else head)
        return out

    def _rank_record(self, target: str, bucket: str) -> tuple:
        """The record ORDER may be read from, and whether it is this slot's own.

        A split replaces one slot with two children whose ids nothing has ever seen. Without this, every
        split would send its subtree to the front of the rotation as never-run, ahead of slots that
        genuinely never ran. So an absent id falls back to the nearest ANCESTOR (the slot that actually
        covered these words), or — after a collapse, when only children exist — to the OLDEST descendant,
        which is the conservative direction: it runs sooner, never later.

        This is RANK ONLY (design v22#2). The returned record may supply `tier` and `slot_seq` and nothing
        else: `reserve()` still allocates a generation for the exact id, and `complete()` still demands
        that exact id's own reservation. An inherited record is never authority."""
        own = self._slot(target, bucket)
        if own:
            return own, True
        slots = (self.targets.get(target, {}).get("slots", {}) or {})
        for anc in self._ancestors(bucket):
            rec = slots.get(anc)
            if rec:
                return rec, False
        kids = [rec for key, rec in slots.items() if rec and self._contains(bucket, key)]
        if kids:
            return min(kids, key=lambda r: int((r.get("res") or {}).get("gen", 0))), False
        return {}, True

    def slot_seq(self, target: str, bucket: str) -> int:
        rec, _own = self._rank_record(target, bucket)
        return int((rec.get("res") or {}).get("gen", 0))

    def tier(self, target: str, bucket: str, content: str) -> int:
        """0 never ran (including reserved-then-crashed) · 1 DIRTY (membership changed since it ran) ·
        2 clean · 3 REFUSED by the caller's admission check.

        v78: a refusal left the slot at tier 0, and tier dominates target fairness globally — so a
        permanently refused target won every lifecycle and starved contactable dirty work for ever. The
        refusal is a TARGET fact (nothing about the slot's membership changed), it ranks LAST, and it is
        superseded the moment that slot really runs. A crash BEFORE admission stays never-run: only an
        explicit refusal writes this."""
        refused = (self.targets.get(target, {}) or {}).get("adm")
        if refused:
            done = (self._rank_record(target, bucket)[0] or {}).get("done") or {}
            if int(refused["gen"]) > int(done.get("gen", 0)):
                return 3
        rec, own = self._rank_record(target, bucket)
        done = rec.get("done")
        if not done:
            return 0
        if not own:
            # a CONSERVATIVE policy, not a proof: this record belongs to a containing or contained slot,
            # and a one-sided split can legitimately hand a child exactly the parent's members and digest.
            # Re-running a slot costs one invocation; certifying it clean on another slot's record would
            # claim coverage nothing here ever produced.
            return 1
        return 1 if done.get("c") != content else 2

    # ── writing it ────────────────────────────────────────────────────────────────────────────────
    def next_gen(self) -> int:
        self.gen += 1
        return self.gen

    def _key(self, target, bucket) -> tuple:
        """Slot identity is EXACT (review v13#2). `reserve(7, True, …)` used to succeed and then come back
        from JSON as target `"7"` and bucket `"true"` — the rotation history for a slot orphaned under a
        key nothing will look up again."""
        for name, value in (("target", target), ("bucket", bucket)):
            if isinstance(value, bool) or not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty str, got {value!r}")
        if self.slot_grammar is not None and not self.slot_grammar(bucket):
            # a MUTATION under a foreign id would persist a record the reader then drops (v25)
            raise ValueError(f"slot id {bucket!r} does not belong to this lane's slot space")
        return target, bucket

    @classmethod
    def _checked(cls, *, at=None, members=None, content=None) -> tuple:
        """Validate what a MUTATION is about to persist. review v12#2: these coerced instead of checking,
        so a NaN timestamp, a negative one, `members=2.9` and `content=None` all reached the document —
        and `json.dumps` then wrote a non-standard `NaN` token that nothing else can read back."""
        out = []
        if at is not None:
            v = cls._num(at)
            if v is None:
                raise ValueError(f"timestamp must be finite and non-negative, got {at!r}")
            out.append(v)
        if members is not None:
            n = cls._count(members)
            if n is None:
                raise ValueError(f"members must be an exact non-negative int, got {members!r}")
            out.append(n)
        if content is not None:
            if not isinstance(content, str) or not content:
                raise ValueError(f"content digest must be a non-empty str, got {content!r}")
            out.append(content)
        return tuple(out)

    def reserve(self, target: str, bucket: str, *, at: float) -> int:
        """Take the next generation and reserve this slot with it. Returns the generation.

        review v11#2: the caller used to PASS a generation, so a slot could hold gen 39 while the lane's own
        counter was 0 — the monotonic authority behind ordering and merge, broken by one careless call.
        Allocation belongs to the map."""
        target, bucket = self._key(target, bucket)
        (when,) = self._checked(at=at)
        gen = self.next_gen()
        t = self.targets.setdefault(target, {"seq": 0, "slots": {}})
        t["slots"].setdefault(bucket, {})["res"] = {"gen": gen, "at": when}
        t["seq"] = max(int(t.get("seq", 0)), gen)           # the cursor advances on every pick
        return gen

    def refuse_target(self, target: str, *, at: float) -> int:
        """Record that the caller's admission check REFUSED this target (v78).

        It orders and nothing else: no slot is completed, nothing claims the tool ran, and the next
        lifecycle still re-asks. What changes is the RANK — a refused target sits behind every target
        with work that can actually be attempted, instead of holding the front of tier 0 for ever."""
        if isinstance(target, bool) or not isinstance(target, str) or not target:
            raise ValueError(f"target must be a non-empty str, got {target!r}")
        (when,) = self._checked(at=at)
        gen = self.next_gen()
        t = self.targets.setdefault(target, {"seq": 0, "slots": {}})
        t["adm"] = {"gen": gen, "at": when}
        t["seq"] = max(int(t.get("seq", 0)), gen)
        return gen

    def complete(self, target: str, bucket: str, gen: int, *, at: float, content: str, members: int) -> None:
        """Record that this slot RAN. Raises `SchedulerInvariant` if its reservation moved under us."""
        target, bucket = self._key(target, bucket)
        when, n, digest = self._checked(at=at, members=members, content=content)
        if self._count(gen) is None or gen < 1:
            # generations start at 1, so 0 can only come from a caller that never reserved anything —
            # and `held_gen` defaults to 0 too, which made the two match (review v13#1).
            raise ValueError(f"generation must be an exact positive int, got {gen!r}")
        slot = self._slot(target, bucket)
        if not slot.get("res"):
            raise SchedulerInvariant(f"{self.lane}:{target}/{bucket}: completing a slot never reserved")
        held_gen = int(slot["res"]["gen"])
        if held_gen != gen:
            raise SchedulerInvariant(f"{self.lane}:{target}/{bucket}: reservation gen {held_gen} != {gen}")
        slot["done"] = {"gen": gen, "at": when, "c": digest, "n": n}

    # ── BATCHED mutations: all-or-none, structurally (design v22#3). One invocation may cover several
    #    slots, and a batch that half-applied would leave slots reserved against a run that never happened,
    #    or completed against a reservation the rest of the batch never got. Every member is validated
    #    BEFORE any generation is allocated, and every CAS is checked BEFORE any `done` tuple is written —
    #    so an invariant discovered in the middle of a batch cannot leave half of it mutated. ──
    def reserve_batch(self, target: str, buckets, *, at: float) -> dict:
        """Reserve several slots of ONE target under one clock reading. Returns {bucket: generation}.

        Raises before mutating anything if any id is unusable, repeated, or the timestamp is not a
        timestamp. Generations are still per slot: batching is an execution fact, not a scheduling one.

        The timestamp is a property of the BATCH, so it is validated once and even for an empty batch
        (v29): a caller whose clock returned NaN has a broken clock whether or not there was work, and a
        check that only fires when a member happens to exist is not a contract."""
        (when,) = self._checked(at=at)     # the BATCH CLOCK first, in both primitives (v30)
        keys = []
        seen = set()
        for bucket in buckets:
            _t, key = self._key(target, bucket)
            if key in seen:
                raise ValueError(f"slot {key!r} appears twice in one batch")
            seen.add(key)
            keys.append(key)
        out = {}
        for key in keys:                                   # validation is done: now nothing can fail
            gen = self.next_gen()
            t = self.targets.setdefault(target, {"seq": 0, "slots": {}})
            t["slots"].setdefault(key, {})["res"] = {"gen": gen, "at": when}
            t["seq"] = max(int(t.get("seq", 0)), gen)
            out[key] = gen
        return out

    def complete_batch(self, target: str, items, *, at: float) -> None:
        """Record that several slots RAN, from `(bucket, gen, content, members)` items.

        Every slot keeps its OWN reservation check and its own content digest — completion means the slot
        was ATTEMPTED, and one result may attest several slots, but never one slot's record for another.

        As in `reserve_batch`, the batch timestamp is validated once and even for an empty batch (v29)."""
        (when,) = self._checked(at=at)
        checked = []
        seen = set()
        for bucket, gen, content, members in items:
            _t, key = self._key(target, bucket)
            if key in seen:
                raise ValueError(f"slot {key!r} appears twice in one batch")
            seen.add(key)
            n, digest = self._checked(members=members, content=content)
            if self._count(gen) is None or gen < 1:
                raise ValueError(f"generation must be an exact positive int, got {gen!r}")
            slot = self._slot(target, key)
            if not slot.get("res"):
                raise SchedulerInvariant(f"{self.lane}:{target}/{key}: completing a slot never reserved")
            held_gen = int(slot["res"]["gen"])
            if held_gen != gen:
                raise SchedulerInvariant(f"{self.lane}:{target}/{key}: reservation gen {held_gen} != {gen}")
            checked.append((slot, {"gen": gen, "at": when, "c": digest, "n": n}))
        for slot, done in checked:                         # validation is done: now nothing can fail
            slot["done"] = done

    @staticmethod
    def _merge_slot(mine: dict, theirs: dict) -> dict:
        """Newer GENERATION wins, per TUPLE, whole. Field-wise merging could assemble `at`, digest and
        member count from three different runs (v5#3)."""
        out = dict(theirs)
        for key in ("res", "done"):
            m, o = mine.get(key), theirs.get(key)
            if m and (not o or int(m["gen"]) > int(o["gen"])):
                out[key] = m
        return out

    def save(self) -> bool:
        """MERGE into whatever is on disk and replace atomically. True only when the write really landed."""
        if self.path is None:
            return False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            return False
        fh = None
        if not self.held:
            # Outside a session we serialise ourselves; inside one the lock is already held and a second
            # acquisition would block against our own descriptor. The wait is BOUNDED and non-blocking at
            # the syscall (the Shodan lesson: a `LOCK_EX` that blocks forever turns a best-effort write
            # into a hang) — giving up answers False rather than writing unserialised.
            fh = _acquire_bounded(self.path.parent / f"{self.lane}.lock")
            if fh is None:
                return False
        try:
            # review v12#1: ONLY absence means "there is nothing to merge with". A document we cannot read
            # or parse must not be overwritten — that would silently destroy another lifecycle's rotation.
            try:
                text = self.path.read_text(encoding="utf-8")
            except FileNotFoundError:
                text = None
            except (OSError, UnicodeError):
                return False
            if text is None:
                disk_gen, disk_targets = 0, {}
            else:
                try:
                    disk_gen, disk_targets, status, _why = self._parse(
                        text, lane=self.lane, schema=self.schema, slot_grammar=self.slot_grammar)
                    # v26#1: without the grammar here, a foreign id dropped on LOAD came back through the
                    # merge and was republished — to disk AND to `self.targets`, where it could rank.
                except Exception:
                    return False                            # unparseable: leave the bytes alone
                if status == "unusable":
                    return False
            merged = {name: {k: (dict(v) if k == "slots" else v) for k, v in t.items()
                             if k in ("seq", "slots", "adm")}
                      for name, t in disk_targets.items()}
            for name, mine in self.targets.items():
                theirs = merged.setdefault(name, {"seq": 0, "slots": {}})
                theirs["seq"] = max(int(theirs["seq"]), int(mine.get("seq", 0)))
                mine_adm, their_adm = mine.get("adm"), theirs.get("adm")
                if mine_adm and (not their_adm or int(mine_adm["gen"]) > int(their_adm["gen"])):
                    theirs["adm"] = mine_adm            # newest refusal wins, whole (v78)
                for bucket, slot in mine.get("slots", {}).items():
                    theirs["slots"][bucket] = self._merge_slot(slot, theirs["slots"].get(bucket, {}))
            gen = max(int(self.gen), int(disk_gen))
            tmp = self.path.with_name(f"{self.path.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp")
            try:
                tmp.write_text(json.dumps({"lane": self.lane, "schema": self.schema, "gen": gen,
                                           "targets": merged}), encoding="utf-8")
                os.replace(tmp, self.path)
            finally:
                try:
                    tmp.unlink(missing_ok=True)
                except OSError:
                    pass
            self.gen, self.targets = gen, merged
            return True
        except OSError:
            return False
        finally:
            if fh is not None:
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


def _remainder_tail(omitted: int, durable: bool, unretriable: int) -> str:
    """How to describe what was left. review v33: there were only two states — a RESUMABLE remainder or a
    lane that RESTARTS — and neither is true of work no later run can reach at all (a slot no bound can
    admit). Naming it resumable is a false promise in the opposite direction from the restart case."""
    if isinstance(unretriable, bool) or not isinstance(unretriable, int) or unretriable < 0:
        raise ValueError(f"unretriable must be an exact non-negative int, got {unretriable!r}")
    if unretriable > omitted:
        # v34#2: clamping rewrote inconsistent accounting into a plausible sentence. More unretriable work
        # than there is remainder is a bug in the caller's arithmetic, and it must say so.
        raise ValueError(f"unretriable ({unretriable}) exceeds the remainder ({omitted})")
    resumable = omitted - unretriable
    kept = ("left as a RESUMABLE remainder" if durable else
            "left over — completion state was NOT persisted, so this lane RESTARTS from the beginning")
    if not unretriable:
        return kept
    never = ("UNSCHEDULABLE under the current bounds — no later run reaches them without a corpus or "
             "policy change")
    if not resumable:
        return f"left {never}"
    # v36: the mixed phrase was built by stripping "left " off the pure one, which turned the non-durable
    # sentence into "3 over — completion state was NOT persisted". Both halves are written out instead.
    carried = ("as a RESUMABLE remainder" if durable else
               "with NO persisted completion state (this lane RESTARTS from the beginning)")
    return f"left over: {resumable} {carried}, {unretriable} {never}"


def report_selection(lane: str, *, measure: str, eligible: int, attempted: int, budget: Budget,
                     noun: str = "item", durable: bool = True, stop: str | None = None,
                     unit: str | None = None, cap_reason: str | None = None,
                     unretriable: int = 0, extra: str | None = None) -> None:
    """SELECTION coverage: of everything eligible, how much did we get to at all?

    Emitted EVERY run (omitted=0 when the whole set was processed) so a later unbounded rerun CLEARS a prior
    gap. COVERAGE_CAP: a budget that stopped us short IS a hard ceiling that truncated eligible input, so it
    must read as a gap whenever omitted > 0 — never as an operator-chosen SAMPLE, which would be a soft
    limit and let the run still call itself complete."""
    omitted = max(0, eligible - attempted)
    # `stop` names what ACTUALLY stopped us when it was not the budget — contention, a machinery failure, a
    # missing dependency. Wording every omission as "budget exhausted" would misname those, and the KIND
    # matters too: a budget is a CAP we chose, anything else is a TIMEOUT-class gap (step-4 design v4#3).
    # v34#1: work nothing can schedule is a GAP whatever stopped us — an operator cap that also left
    # unschedulable pairs behind is not a clean sample of the eligible set.
    kind = events.COVERAGE_TIMEOUT if (stop is not None or unretriable) else events.COVERAGE_CAP
    tail = _remainder_tail(omitted, durable, unretriable)
    # v59#1: causes that ALSO applied but did not end the run — an operator cap alongside a clock that
    # fired, say. The head names what stopped us; these are named beside it rather than suppressed.
    also = f" (also: {extra})" if extra and omitted else ""
    if omitted and cap_reason is not None and stop is None:
        # an OPERATOR CAP that is not the wall clock — a per-target candidate bound, say. Still a CAP we
        # chose (never a TIMEOUT-class failure), but "budget exhausted after 0s of 0s" would be a lie.
        why = f"{cap_reason}{also} — {attempted}/{eligible} {noun}(s) processed, {omitted} {tail}"
    elif omitted and stop is not None:
        why = f"{stop}{also} — {attempted}/{eligible} {noun}(s) processed, {omitted} {tail}"
    elif omitted and unretriable == omitted:
        # nothing stopped us and the clock never ran out: the remainder is simply not schedulable, and
        # blaming a budget that did not fire would misname it (v34#1).
        why = f"{attempted}/{eligible} {noun}(s) processed, {omitted} {tail}"
    elif omitted:
        # review#4 (r7): only call the remainder RESUMABLE when the completion state was actually persisted.
        # Otherwise the next run starts over, and "resumable" is a false promise.
        why = (f"{noun} budget exhausted after {budget.elapsed()}s of {budget.seconds}s{also} — "
               f"{attempted}/{eligible} processed, {omitted} {tail}")
    else:
        why = f"{attempted}/{eligible} {noun}(s) processed (whole eligible set)"
    # unit MUST be distinct per measure: reconciliation keeps the latest per (source_id, unit), so leaving
    # it to default to the source_id would make the outcome report OVERWRITE the selection report and one of
    # the two facts would silently vanish from the rollup.
    events.coverage_partial(lane, kind=kind, measure=measure, unit=unit or measure,
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
