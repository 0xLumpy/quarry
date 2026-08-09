"""Bounded, FAIR, resumable processing of a lane's FULL eligible input.

A first-N cap lets a few heavy hosts eat the budget, and which hosts win depends on discovery order —
so the scanned set rotates between runs. Instead: keep the full set, order it fairly, bound THROUGHPUT,
persist the REMAINDER. Unbounded is the default.
"""
from __future__ import annotations

import contextlib
import hashlib
import secrets as _secrets
import json
import math
import os
import stat
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
    """Round-robin items across their `key(item)` groups: every host gets its 1st item before any host
    gets its 2nd. Deterministic — same input, same output."""
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


def _token() -> str:
    return _secrets.token_hex(8)


def _fd_digest(fd) -> str:
    """sha256 of an OPEN descriptor, from offset 0. Takes no pathname: it hashes the inode we hold,
    not whatever the name resolves to now."""
    h = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, 1024 * 1024):
        h.update(chunk)
    return h.hexdigest()


def publish_bytes(dest: Path, data: bytes, *, digest: str) -> bool:
    """Atomically publish `data` at `dest`. True only once dest provably holds exactly these bytes.

    Every step resolves through a DIRECTORY DESCRIPTOR we hold open, so renaming a directory entry in
    the parent cannot redirect it. Same-uid interference is out of scope: a process running as us can
    reach these descriptors directly.
    """
    dfd = sfd = None
    name = None
    created = False
    try:
        if _already_published(dest, digest):
            return True
        dest.parent.mkdir(parents=True, exist_ok=True)
        dfd = os.open(dest.parent, os.O_RDONLY | os.O_DIRECTORY)
        name = f".quarry-stage-{_token()}"
        os.mkdir(name, 0o700, dir_fd=dfd)          # fails if the name exists
        created = True
        # pin the staging directory by INODE: its entry lives in a parent anyone with write access can
        # rename, so everything below resolves through this descriptor and never through that name.
        sfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dfd)
        # ...and prove it is the one we just made. The name could have been swapped between the mkdir
        # and this open, so a directory that is not ours, not private, or not empty is not staging.
        st = os.fstat(sfd)
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid()
                or stat.S_IMODE(st.st_mode) != 0o700 or st.st_nlink != 2):
            return False
        fd = os.open("artifact", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=sfd)
        try:
            with os.fdopen(os.dup(fd), "wb") as fh:
                fh.write(data)
            if _fd_digest(fd) != digest:           # verify the WRITE, through the fd we hold
                return False
            os.replace("artifact", dest.name, src_dir_fd=sfd, dst_dir_fd=dfd)
            return True
        finally:
            os.close(fd)
    except OSError:
        return False
    finally:
        if sfd is not None:
            try:
                os.unlink("artifact", dir_fd=sfd)
            except OSError:
                pass
            # remove the NAME only while it still resolves to the directory we are holding: renamed
            # away and replaced, it belongs to someone else and deleting it would be our doing.
            if created and dfd is not None and _same_inode(name, dfd, sfd):
                try:
                    os.rmdir(name, dir_fd=dfd)
                except OSError:
                    pass
            os.close(sfd)
        if dfd is not None:
            os.close(dfd)


def _same_inode(name: str, dir_fd: int, fd: int) -> bool:
    """Whether `name` under `dir_fd` still resolves to the object `fd` refers to."""
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except OSError:
        return False
    own = os.fstat(fd)
    return (st.st_dev, st.st_ino) == (own.st_dev, own.st_ino)


def _already_published(dest: Path, digest: str) -> bool:
    """Whether `dest` already holds exactly these bytes.

    `O_NONBLOCK`, or a planted FIFO blocks the publisher; only a REGULAR file may answer this."""
    try:
        fd = os.open(dest, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return False                               # absent, a link, or not ours to read
    try:
        return stat.S_ISREG(os.fstat(fd).st_mode) and _fd_digest(fd) == digest
    finally:
        os.close(fd)


def store_writable(attempt_dir) -> bool:
    """Whether a bought page could actually be PUBLISHED — proven by writing, not assumed.

    The probe uses the same primitive a real page does, then removes itself: an artifact tree whose
    contract is "every file is validated evidence" must not gain a probe."""
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
    """Order by RANK TIER first, then round-robin fairly within each tier.

    Ranking decides ORDER, never membership: a budget that stops early has done the most valuable
    work first rather than excluded anything."""
    tiers: dict = {}
    for it in items:
        tiers.setdefault(rank(it), []).append(it)
    out: list = []
    for r in sorted(tiers):
        out += order_fairly(tiers[r], group)
    return out


def ledger_writable(ledger) -> bool:
    """Whether completions can actually be JOURNALED — a precondition, not a postcondition.

    Refuses everything `_append` refuses, or it promises a write the ledger will not perform."""
    return (not getattr(ledger, "foreign", False)
            and not getattr(ledger, "_journal_unsafe", False)
            and not getattr(ledger, "unreadable", ""))


class StateBusy(RuntimeError):
    """Another lifecycle holds this lane's state. Not an error: the holder is advancing the rotation."""


@contextlib.contextmanager
def state_lock(path):
    """An exclusive, advisory, OS-released lock over one lane's PROJECT state.

    `flock`, not lockfile existence: the kernel drops it however the holder dies. Non-blocking, so
    contention raises instead of queueing."""
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
    """The rotation was asked for something its own records forbid. A defect, never an outcome."""


@contextlib.contextmanager
def rotation_session(state_dir, lane: str, *, schema: int, slot_grammar=None):
    """`with rotation_session(dir, lane, schema=1) as progress:` — the only way to reach lane progress.

    Contention escapes from ENTERING this manager; a `StateBusy` from inside the body is the body's
    own machinery failure."""
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


#: lane generations a refused target waits before it is asked again. Tier 3 alone would exclude it
#: permanently, since clean work refills a finite allowance every lifecycle.
ADMISSION_COOLDOWN_GENS = 16


class RotationProgress:
    """Project-level rotation state for one lane: which slot was RESERVED when, and what it last RAN.

    It ORDERS and nothing else — losing it costs ordering quality, never coverage. `done` carries the
    digest of the members actually submitted, so a slot whose membership changed is DIRTY; writing it
    at reservation time would make a crash before launch look clean."""

    def __init__(self, path, *, lane: str, schema: int, slot_grammar=None, _session=None):
        # the CONFIGURED schema is validated too : `int(True)` is 1 and `int("2")` is 2, and a
        # schema that coerces is a rotation that can be read under the wrong meaning.
        if isinstance(schema, bool) or not isinstance(schema, int) or schema < 0:
            raise ValueError(f"schema must be an exact non-negative int, got {schema!r}")
        self.path = Path(path) if path else None
        self.lane = lane
        self.schema = schema
        #: the lane's slot-id grammar, or None. Rank inheritance walks ids structurally, so arbitrary
        #: strings could make unrelated slots each other's ancestors.
        if slot_grammar is not None and not callable(slot_grammar):
            raise ValueError(f"slot_grammar must be callable, got {slot_grammar!r}")
        self.slot_grammar = slot_grammar
        self.held = _session is _SESSION       # ONLY `rotation_session` can hand over the token
        self.gen = 0
        self.targets: dict = {}
        #: `missing` · `valid` · `degraded` (records dropped or repaired, so work may repeat) · `unusable`.
        #: A driver must say which, not report advancement over a prefix it silently repeated.
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
        # generations START AT 1, so a persisted 0 cannot have come from this map. Reading it as real
        # would make a never-run slot report CLEAN — the one direction a rotation must never fail in.
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
        """Parse one persisted tuple, or None when it cannot be trusted.

        NEVER raises, including on a caller-supplied grammar: unusable reads as "never happened", which
        is the safe direction for a rotation."""
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
        dropped = 0                                        # records we could not trust
        repaired = 0                                       # records we clamped back into consistency
        for name, raw_t in raw_targets.items():
            # the same identity rule the mutations enforce: an empty key is not a target, on the way
            # in or the way out
            if not isinstance(name, str) or not name or not isinstance(raw_t, dict):
                dropped += 1                               # a container we cannot read is not a target
                continue
            seq = cls._count(raw_t.get("seq"))
            raw_slots = raw_t.get("slots")
            if seq is None or not isinstance(raw_slots, dict):
                dropped += 1
                continue
            if seq > gen:
                # a cursor AHEAD of the lane generation keeps this target at the back of the fairness
                # order for as many lifecycles as the gap is wide. Clamp, and say so.
                seq, repaired = gen, repaired + 1
            slots: dict = {}
            for bucket, raw_s in raw_slots.items():
                if not isinstance(bucket, str) or not bucket or not isinstance(raw_s, dict):
                    dropped += 1
                    continue
                if slot_grammar is not None:
                    # `_parse` NEVER raises, and that promise now covers a caller-supplied
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
                # a completion with no reservation, or one from a LATER generation than the reservation
                # it claims, cannot be ordered — it reads as never-run, the safe direction.
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
            # TARGET-level admission records: `adm` a refusal, `adm_ok` an admission that supersedes it. They
            # order, never claim execution, and parse fail-closed.
            admission = {}
            for key in ("adm", "adm_ok"):
                raw_adm = raw_t.get(key)
                rec = cls._tuple(raw_adm, with_content=False)
                if rec is None:
                    # a PRESENT but malformed record is a DROP, not an absence — the document is
                    # degraded and must say so.
                    if raw_adm is not None:
                        dropped += 1
                    continue
                if rec["gen"] > gen:
                    dropped += 1
                    continue
                admission[key] = rec
            # the cursor covers every generation this target ORDERS by, admissions included.
            highest = max([highest] + [r["gen"] for r in admission.values()])
            targets[name] = {"seq": max(seq, highest), "slots": slots, **admission}
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
        except Exception as e:                      # `_parse` must never raise
            self.gen, self.targets = 0, {}
            self.state_status, self.state_reason = "unusable", f"unparseable ({type(e).__name__})"

    # ── reading the rotation ──────────────────────────────────────────────────────────────────────
    def _slot(self, target: str, bucket: str) -> dict:
        return (self.targets.get(target, {}).get("slots", {}) or {}).get(bucket, {})

    def target_seq(self, target: str) -> int:
        """The reservation SEQUENCE this target was last selected at — the fairness cursor. A sequence, not
        a clock: a backward jump in wall time must not reorder the rotation."""
        return int(self.targets.get(target, {}).get("seq", 0))

    @staticmethod
    def _parts(bucket: str) -> tuple:
        """A slot id as (root, bits). `177` is the 8-bit root at extension depth 0; `177.0110` is the same
        root with four extension bits."""
        head, _dot, bits = bucket.partition(".")
        return head, bits                      # no separator -> no extension bits, and `partition` says so

    @classmethod
    def _contains(cls, parent: str, child: str) -> bool:
        """Containment is on the PARSED id, not on the string. `177.0` contains `177.00`, whose id
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

        An absent id inherits from the nearest ancestor, or after a collapse the oldest descendant.
        RANK ONLY: `reserve()` and `complete()` still demand the exact id's own records."""
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
        """0 never ran · 1 DIRTY (membership changed) · 2 clean · 3 REFUSED by admission.

        Tier dominates fairness globally, so a refusal must rank LAST — at tier 0 a permanently
        refused target would win every lifecycle. A crash BEFORE admission stays never-run."""
        rec_t = self.targets.get(target, {}) or {}
        refused = rec_t.get("adm")
        if refused:
            # a later admission is a TARGET fact and supersedes a refusal for every slot, including ones that
            # did not exist when it happened
            admitted = int((rec_t.get("adm_ok") or {}).get("gen", 0))
            done = (self._rank_record(target, bucket)[0] or {}).get("done") or {}
            if int(refused["gen"]) > max(admitted, int(done.get("gen", 0))):
                # a COOLDOWN, not an exclusion: the target ranks last while it holds, then returns to its tier
                if int(self.gen) - int(refused["gen"]) < ADMISSION_COOLDOWN_GENS:
                    return 3
        rec, own = self._rank_record(target, bucket)
        done = rec.get("done")
        if not done:
            return 0
        if not own:
            # CONSERVATIVE: this record belongs to a containing or contained slot, so certifying clean on it
            # would claim coverage nothing produced. Re-running costs one invocation.
            return 1
        return 1 if done.get("c") != content else 2

    # ── writing it ────────────────────────────────────────────────────────────────────────────────
    def next_gen(self) -> int:
        self.gen += 1
        return self.gen

    def _key(self, target, bucket) -> tuple:
        """Slot identity is EXACT: `reserve(7, True, …)` would come back from JSON as target `"7"` and
        bucket `"true"`, orphaning that slot's history under a key nothing looks up again."""
        for name, value in (("target", target), ("bucket", bucket)):
            if isinstance(value, bool) or not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty str, got {value!r}")
        if self.slot_grammar is not None and not self.slot_grammar(bucket):
            # a MUTATION under a foreign id would persist a record the reader then drops
            raise ValueError(f"slot id {bucket!r} does not belong to this lane's slot space")
        return target, bucket

    @classmethod
    def _checked(cls, *, at=None, members=None, content=None) -> tuple:
        """Validate what a MUTATION is about to persist. Checked, never coerced: a NaN timestamp reaches
        the document as a token nothing can read back."""
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
        """Take the next generation and reserve this slot with it -> the generation.

        Allocation belongs to the map: a caller that passes one can leave a slot ahead of the lane's
        own counter, breaking the ordering authority."""
        target, bucket = self._key(target, bucket)
        (when,) = self._checked(at=at)
        gen = self.next_gen()
        t = self.targets.setdefault(target, {"seq": 0, "slots": {}})
        t["slots"].setdefault(bucket, {})["res"] = {"gen": gen, "at": when}
        t["seq"] = max(int(t.get("seq", 0)), gen)           # the cursor advances on every pick
        return gen

    def refuse_target(self, target: str, *, at: float) -> int:
        """Record that admission REFUSED this target. Ordering only — it never claims execution."""
        if isinstance(target, bool) or not isinstance(target, str) or not target:
            raise ValueError(f"target must be a non-empty str, got {target!r}")
        (when,) = self._checked(at=at)
        gen = self.next_gen()
        t = self.targets.setdefault(target, {"seq": 0, "slots": {}})
        t["adm"] = {"gen": gen, "at": when}
        t["seq"] = max(int(t.get("seq", 0)), gen)
        return gen

    def admit_target(self, target: str, *, at: float) -> int:
        """Record that admission ACCEPTED this target, superseding any earlier refusal for every slot."""
        if isinstance(target, bool) or not isinstance(target, str) or not target:
            raise ValueError(f"target must be a non-empty str, got {target!r}")
        (when,) = self._checked(at=at)
        gen = self.next_gen()
        t = self.targets.setdefault(target, {"seq": 0, "slots": {}})
        t["adm_ok"] = {"gen": gen, "at": when}
        t["seq"] = max(int(t.get("seq", 0)), gen)
        return gen

    def complete(self, target: str, bucket: str, gen: int, *, at: float, content: str, members: int) -> None:
        """Record that this slot RAN. Raises `SchedulerInvariant` if its reservation moved under us."""
        target, bucket = self._key(target, bucket)
        when, n, digest = self._checked(at=at, members=members, content=content)
        if self._count(gen) is None or gen < 1:
            # generations start at 1, so 0 can only come from a caller that never reserved anything —
            # and `held_gen` defaults to 0 too, which made the two match.
            raise ValueError(f"generation must be an exact positive int, got {gen!r}")
        slot = self._slot(target, bucket)
        if not slot.get("res"):
            raise SchedulerInvariant(f"{self.lane}:{target}/{bucket}: completing a slot never reserved")
        held_gen = int(slot["res"]["gen"])
        if held_gen != gen:
            raise SchedulerInvariant(f"{self.lane}:{target}/{bucket}: reservation gen {held_gen} != {gen}")
        slot["done"] = {"gen": gen, "at": when, "c": digest, "n": n}

    # ── BATCHED mutations: all-or-none ────────────────────────────────────────────────────────────────
    # Every member is validated before any generation is allocated, and every CAS is checked before any
    # `done` is written, so an invariant found mid-batch cannot leave half of it applied.
    def reserve_batch(self, target: str, buckets, *, at: float) -> dict:
        """Reserve several slots of ONE target under one clock reading -> {bucket: generation}.

        Raises before mutating anything if an id is unusable or repeated, or the timestamp is not
        one — validated even for an empty batch, since a broken clock is broken either way."""
        (when,) = self._checked(at=at)     # the BATCH CLOCK first, in both primitives
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
        """Complete several slots of one target. Every CAS is checked before any `done` is written, so an
        invariant found mid-batch cannot leave half of it mutated."""
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
        member count from three different runs."""
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
            # outside a session we serialise ourselves; inside one the lock is held. The wait is bounded and
            # non-blocking: giving up answers False rather than hanging.
            fh = _acquire_bounded(self.path.parent / f"{self.lane}.lock")
            if fh is None:
                return False
        try:
            # ONLY absence means "nothing to merge with": a document we cannot read or parse must not
            # be overwritten, or another lifecycle's rotation is destroyed silently
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
                    # without the grammar here, a foreign id dropped on LOAD came back through the
                    # merge and was republished — to disk AND to `self.targets`, where it could rank.
                except Exception:
                    return False                            # unparseable: leave the bytes alone
                if status == "unusable":
                    return False
            merged = {name: {k: (dict(v) if k == "slots" else v) for k, v in t.items()
                             if k in ("seq", "slots", "adm", "adm_ok")}
                      for name, t in disk_targets.items()}
            for name, mine in self.targets.items():
                theirs = merged.setdefault(name, {"seq": 0, "slots": {}})
                theirs["seq"] = max(int(theirs["seq"]), int(mine.get("seq", 0)))
                for key in ("adm", "adm_ok"):       # newest admission record wins, whole
                    mine_adm, their_adm = mine.get(key), theirs.get(key)
                    if mine_adm and (not their_adm or int(mine_adm["gen"]) > int(their_adm["gen"])):
                        theirs[key] = mine_adm
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

    An artifact produced under a different config still validates by digest, so the fingerprint in
    the FILENAME starts a clean generation rather than letting it read as done."""
    return Path(base) / f"{lane.replace('.', '_')}.{config_fp[:12]}.state.json"


def prune_state(base, lane: str, keep_fp: str) -> None:
    """Drop ledgers for superseded coverage configs of this lane, so the run dir does not accumulate them."""
    keep = state_path(base, lane, keep_fp).name
    for old in Path(base).glob(f"{lane.replace('.', '_')}.*.state.json"):
        if old.name != keep:
            old.unlink(missing_ok=True)
            old.with_name(old.name + ".journal").unlink(missing_ok=True)


class Ledger:
    """A per-ITEM record of completed work, so an interrupted or bounded run RESUMES.

    Keyed per item, not per work unit: a fetch lane's eligible set grows every run, and a unit-gated
    map would re-fetch everything. Only SUCCESSES persist — transient cannot be told from permanent."""

    def __init__(self, state_file: Path, *, lane: str):
        self.path = Path(state_file)
        self.journal = self.path.with_name(self.path.name + ".journal")
        self.lane = lane
        self.done: dict[str, str] = {}        # item -> COMPLETION artifact (relative to the state file's dir)
        self.evid: dict[str, list] = {}       # item -> EVERY retained artifact, append-only
        self.digests: dict[str, str] = {}     # relative artifact path -> sha256
        self._journal_unsafe = False          # set when the journal may not be APPENDED to
        self._journal_lost = False            # set when the journal can no longer be REPLAYED
        self.foreign = False                  # set when this PATH belongs to a DIFFERENT lane
        #: items recorded as done whose artifact no longer verifies. They are correctly redone — the
        #: evidence really is gone — but for a PAID lane "redo" means BUY AGAIN, and a repurchase that
        #: looks identical to a first purchase is the accidental spend the ownership store exists to
        #: prevent. Kept as a fact for the caller; this class never decides what a lost item costs.
        self.lost: dict[str, str] = {}        # item -> the artifact path it was filed under ("" if none)
        #: set when an ownership index EXISTS and cannot be trusted. ABSENT and UNUSABLE are different
        #: states: as one empty dict, a corrupt snapshot reads as a clean store and a PAID lane buys
        #: every page again. The reason is prose because the caller has to say WHY it refused.
        self.unreadable: str = ""
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
        except FileNotFoundError:
            return {}, {}                     # ABSENT: a first run must not be blocked
        except UnicodeError as e:
            # invalid bytes are UNUSABLE, not absent: raising here would take the lane down instead of
            # refusing to trust a store it cannot read.
            self.unreadable = f"state file is not valid text: {e}"
            return {}, {}
        except OSError as e:
            # a file we cannot READ is not a file that is not there: `Path.exists()` returns False for a path we
            # lack permission to inspect, which would clear `unreadable` on the very failure it exists to catch
            self.unreadable = f"state file unreadable: {e}"
            return {}, {}
        except json.JSONDecodeError as e:
            self.unreadable = f"state file is not valid JSON: {e}"
            return {}, {}
        if not isinstance(raw, dict):
            self.unreadable = f"state root is {type(raw).__name__}, not an object"
            return {}, {}
        if raw.get("lane") != self.lane:
            # a snapshot belonging to ANOTHER lane is not merely ignored: save() would overwrite it and
            # destroy that lane's completions, so the path is marked foreign and refuses writes
            self.foreign = True
            return {}, {}
        done, digests = raw.get("done"), raw.get("digests")
        if not (isinstance(done, dict) and isinstance(digests, dict)):
            self.unreadable = ("state has no usable completion index "
                               f"(done={type(done).__name__}, digests={type(digests).__name__})")
            return {}, {}
        ev = raw.get("evidence")
        if isinstance(ev, dict):
            for k, v in ev.items():
                if isinstance(k, str) and isinstance(v, list):
                    self._raw_evid[k] = [x for x in v if isinstance(x, str)]
        return done, digests

    JOURNAL_SCHEMA = 1

    def _replay_journal(self, done: dict, digests: dict) -> None:
        """Fold appended completions over the snapshot, then repair a damaged TAIL of OUR OWN records.

        A lane mismatch means "not mine": nothing is replayed and nothing is rewritten, or the other
        lane's completions are deleted."""
        try:
            text = self.journal.read_text()
        except FileNotFoundError:
            return                                 # ABSENT: nothing was appended since the last compact
        except UnicodeError as e:
            self.unreadable = self.unreadable or f"journal is not valid text: {e}"
            return
        except OSError as e:
            self.unreadable = self.unreadable or f"journal unreadable: {e}"
            return
        lines = text.splitlines()
        kept: list[str] = []
        pending: list[tuple] = []
        damaged = not text.endswith("\n")          # a partial last write leaves no terminator
        last = len(lines) - 1

        def _lost_record(i: int, why: str) -> None:
            """A torn TAIL is what a crash mid-append looks like and costs nothing. A bad record with
            intact records BEHIND it means a completion was destroyed, and this store must not read that
            as "never owned"."""
            if i != last or text.endswith("\n"):
                self.unreadable = self.unreadable or f"journal record {i + 1} {why}"

        for i, line in enumerate(lines):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                damaged = True
                _lost_record(i, "is not valid JSON")
                continue
            if not isinstance(rec, dict):
                damaged = True
                _lost_record(i, "is not an object")
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
                _lost_record(i, "carries no usable completion")
        for item, rel, dig in pending:
            done[item] = rel
            digests[rel] = dig
        if damaged and self.unreadable:
            # UNTRUSTED history is EVIDENCE: rewriting it deletes the record that proved the store is broken
            self._journal_unsafe = True
        elif damaged:
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
                self.lost[item] = rel if isinstance(rel, str) else ""
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
                # a validated COMPLETION is also evidence: replay restores `done` but not the evidence map, so
                # deriving it here covers a crash between journalling and compaction
                self._raw_evid.setdefault(item, [])
                if rel not in self._raw_evid[item]:
                    self._raw_evid[item].insert(0, rel)
            else:
                self.lost[item] = rel          # recorded as done; the bytes do not match what we filed
        # retained EVIDENCE is digest-bound too, or a tampered artifact could inject fabricated findings
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
        artifact contributes EVIDENCE only and can never decide whether the item is done."""
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

        Independent of `save()`: a journalled completion replays on the next open even if compaction
        later fails."""
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
        """PROVE the journal is writable, without claiming anything.

        The safety flags are only set BY a failed write, so a paid caller would spend a credit to
        discover it cannot record the result."""
        return self._append({"k": "ckpt"})

    def _append(self, rec: dict) -> bool:
        """True when the record is DURABLY journaled. A swallowed error would leave a caller unable to
        tell an appended completion from one that exists only in memory."""
        if self.foreign or self._journal_unsafe or self.unreadable:
            # appending to a foreign, fragmented or untrusted journal builds a healthy-looking history
            # on top of one we already know is broken
            return False
        try:
            self.journal.parent.mkdir(parents=True, exist_ok=True)
            with self.journal.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"v": self.JOURNAL_SCHEMA, "l": self.lane, **rec}) + "\n")
            return True
        except OSError:
            self._journal_unsafe = True        # in-memory state is correct but NOT appendable
            # APPENDABILITY and REPLAYABILITY differ here too: a torn tail is repaired to its intact prefix on
            # load, so records that already returned True still replay. Only an unreadable journal is lost.
            try:
                self._journal_lost = not self.journal.is_file()
            except OSError:
                self._journal_lost = True
            return False

    def save(self) -> bool:
        """COMPACT: write the snapshot atomically, then drop the journal it supersedes.

        Refuses a FOREIGN path or an UNTRUSTED store: compaction would write empty maps over another
        lane's completions, or over the only evidence that this store cannot be trusted."""
        if self.foreign or self.unreadable:
            return False
        # the contract is "returns success, never raises": mkdir, write and `os.replace` can all fail on a
        # full or read-only filesystem, and a raised IO error would bypass the state_persisted gap entirely
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(self.path.name + ".tmp")
            tmp.write_text(json.dumps({"lane": self.lane, "done": self.done,
                                       "evidence": self.evid, "digests": self.digests}))
            os.replace(tmp, self.path)
        except OSError:
            self._journal_unsafe = True       # the snapshot is not authoritative; keep the journal
            return False
        # append safety is restored ONLY if the damaged journal is actually gone: clearing the flag on
        # one we failed to remove sends the next record onto the fragment, where it vanishes
        try:
            self.journal.unlink(missing_ok=True)
            self._journal_unsafe = self.journal.exists()
        except OSError:
            self._journal_unsafe = True
        return True


def _remainder_tail(omitted: int, durable: bool, unretriable: int) -> str:
    """How to describe what was left: a RESUMABLE remainder, a lane that RESTARTS, or work no later
    run can reach at all. Calling the third resumable is a false promise."""
    if isinstance(unretriable, bool) or not isinstance(unretriable, int) or unretriable < 0:
        raise ValueError(f"unretriable must be an exact non-negative int, got {unretriable!r}")
    if unretriable > omitted:
        # clamping rewrote inconsistent accounting into a plausible sentence. More unretriable work
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
    # both halves are written out, never derived from each other
    carried = ("as a RESUMABLE remainder" if durable else
               "with NO persisted completion state (this lane RESTARTS from the beginning)")
    return f"left over: {resumable} {carried}, {unretriable} {never}"


def report_selection(lane: str, *, measure: str, eligible: int, attempted: int, budget: Budget,
                     noun: str = "item", durable: bool = True, stop: str | None = None,
                     unit: str | None = None, cap_reason: str | None = None,
                     unretriable: int = 0, extra: str | None = None) -> None:
    """Coverage for what a lane SELECTED to process, against its full eligible set."""
    omitted = max(0, eligible - attempted)
    # `stop` names what ACTUALLY stopped us when it was not the budget: a budget is a CAP we chose,
    # anything else is a TIMEOUT-class gap, and work nothing can schedule is a gap whatever stopped us
    kind = events.COVERAGE_TIMEOUT if (stop is not None or unretriable) else events.COVERAGE_CAP
    tail = _remainder_tail(omitted, durable, unretriable)
    # causes that ALSO applied but did not end the run — an operator cap alongside a clock that
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
        # blaming a budget that did not fire would misname it.
        why = f"{attempted}/{eligible} {noun}(s) processed, {omitted} {tail}"
    elif omitted:
        # only RESUMABLE when the completion state actually persisted, or the next run starts over and
        # "resumable" is a false promise
        why = (f"{noun} budget exhausted after {budget.elapsed()}s of {budget.seconds}s{also} — "
               f"{attempted}/{eligible} processed, {omitted} {tail}")
    else:
        why = f"{attempted}/{eligible} {noun}(s) processed (whole eligible set)"
    # the unit MUST be distinct per measure: reconciliation keeps the latest per (source_id, unit), so a
    # shared one would have the outcome report overwrite the selection report and lose a fact.
    events.coverage_partial(lane, kind=kind, measure=measure, unit=unit or measure,
                            eligible=eligible, tested=attempted, omitted=omitted, reason=why)


def report_outcome(lane: str, *, measure: str, attempted: int, obtained: int, classes: dict | None = None,
                   noun: str = "item") -> None:
    """Coverage for what a lane OBTAINED from what it attempted — the target's losses, not ours."""
    lost = max(0, attempted - obtained)
    detail = f" {dict(sorted(classes.items()))}" if classes else ""
    why = (f"{obtained}/{attempted} attempted {noun}(s) obtained; {lost} failed in flight{detail}"
           if lost else f"all {attempted} attempted {noun}(s) obtained")
    events.coverage_partial(lane, kind=events.COVERAGE_TIMEOUT, measure=measure, unit=measure,
                            eligible=attempted, tested=obtained, omitted=lost, reason=why)
