"""What a lane still owes, in a form a supervisor can read.

`--settle` may only keep a campaign alive for work another child would actually advance, so a record
carries two independent things: the lane's cross-run model (does durable project state carry between
runs, or does a later run repeat the same prefix?) and this remainder's own disposition (retriable now,
retriable after a cooldown, or terminal). It also carries the measure its numbers are in, so
comparability is per `(lane, unit, measure)` exactly like the coverage records these derive from.

A lane that reports nothing is unknown, never zero: silence is not a fixed point.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import events

#: how a lane's remainder behaves across runs. Only `project_progress` may keep a campaign alive.
MODELS = ("project_progress", "rerun_same_work")

#: internal (non-scanner) lanes: they declare a model but are not registered sources, so they are exempt
#: from the registered-source check. Their remainder is attributed to the store, not a provider.
SYNTHETIC_LANES = frozenset({"store.envelope"})

#: every lane that can report a remainder, and its model. Declared, never inferred from a number, and
#: test-enforced: a lane that reports without declaring is one whose remainder nobody can interpret.
LANE_MODEL: dict[str, str] = {
    # corpus-envelope overflow: a raised bound advances the refused keys
    "store.envelope": "project_progress",
    # sweep lanes: the rotation ledger is project-scoped, so a later child continues where this one
    # stopped (`budget.rotation_session`'s per-lane ledger, per-slot content-bound completion)
    "enrich.a1d_brute": "project_progress",
    "enrich.wildcard_a1d": "project_progress",
    "vertical.wildcard_http": "project_progress",
    # the permutation loop: entities are run-scoped, so a later run replays rounds 1..N from an empty
    # frontier — that remainder is `--unbound`'s business, never `--settle`'s
    "vertical.alterx_permute": "rerun_same_work",
    # the lazy-chunk traversal's depth, likewise: only a raised bound reaches a chunk deeper than this
    # one. Its bundles unit behaves differently; see `UNIT_MODEL`.
    "crawl.jxscout_chunks": "rerun_same_work",
}

#: the model is a property of the unit, not the lane — one lane can owe two kinds of work whose repeat
#: behaviour differs. `LANE_MODEL` is the default; a unit listed here must belong to a declared lane.
UNIT_MODEL: dict[tuple, str] = {
    # a later child re-fetches an unreadable bundle and may simply succeed, so this count is real;
    # deterministic failures stay terminal counts on the same record.
    ("crawl.jxscout_chunks", "crawl.jxscout_chunks:bundles"): "project_progress",
}

#: causes that no repetition resolves. `refused` is not one: an admission refusal cools down and is asked
#: again (`budget.ADMISSION_COOLDOWN_GENS`), so it is retriable with a wait.
TERMINAL_CAUSES = ("unschedulable", "entitlement", "dependency", "machinery")

#: what a terminal cause IS, for a caller that must state an outcome: a bound we accepted, coverage
#: nobody could schedule, or machinery that broke. Only `entitlement` is a bound we chose to live with,
#: so only it may be reported as a bounded run rather than as lost coverage.
TERMINAL_DISPOSITIONS = {"entitlement": "bounded", "unschedulable": "gap", "dependency": "gap",
                         "machinery": "fault"}

#: least to most serious; the order a mixed terminal is resolved in.
TERMINAL_CLASSES = ("bounded", "gap", "fault")


def terminal_disposition(cause: str) -> str:
    """One terminal cause as an outcome class. Anything this taxonomy cannot account for is a `fault`: a
    terminal nobody declared is machinery, never a bound we may claim we chose."""
    return TERMINAL_DISPOSITIONS.get(cause, "fault")


def terminal_class(causes) -> str:
    """The one class for a terminal's causes — the most serious wins, and a `{cause: count}` mapping is
    read by its non-zero causes. A terminal that names none is a `gap`: nothing was recorded to classify,
    which is coverage nobody can claim, not machinery anybody saw break."""
    named = [c for c, n in causes.items() if n] if isinstance(causes, dict) else list(causes)
    return max([terminal_disposition(c) for c in named] or ["gap"], key=TERMINAL_CLASSES.index)


@dataclass
class Remainder:
    """What one lane still owes, in one measure."""
    lane: str
    unit: str
    measure: str
    model: str
    now: int = 0                     # a later child, under the same policy, would attempt this
    cooldown: int = 0                # ...once a cooldown expires (a refusal, not an exclusion)
    terminal: dict = field(default_factory=dict)      # {cause: count}, causes from TERMINAL_CAUSES
    detail: dict = field(default_factory=dict)        # sub-measure breakdown, never summed with the above

    def validate(self) -> None:
        for name in ("lane", "unit", "measure"):
            value = getattr(self, name)
            if type(value) is not str or not value.strip():
                raise ValueError(f"a remainder needs an exact non-empty {name}")
        if self.model not in MODELS:
            raise ValueError(f"{self.lane}: unknown remainder model {self.model!r}")
        declared = UNIT_MODEL.get((self.lane, self.unit), LANE_MODEL.get(self.lane))
        if declared != self.model:
            raise ValueError(f"{self.lane}: model {self.model!r} contradicts the declared "
                             f"{declared!r} for unit {self.unit!r}")
        for name, value in (("now", self.now), ("cooldown", self.cooldown)):
            if type(value) is not int or value < 0:
                raise ValueError(f"{self.lane}: {name} must be an exact non-negative int")
        for cause, value in self.terminal.items():
            if cause not in TERMINAL_CAUSES:
                raise ValueError(f"{self.lane}: unknown terminal cause {cause!r}")
            if type(value) is not int or value < 0:
                raise ValueError(f"{self.lane}: terminal {cause} must be an exact non-negative int")

    @property
    def retriable(self) -> int:
        """What repetition could still take — only for a lane where repetition actually advances."""
        return (self.now + self.cooldown) if self.model == "project_progress" else 0

    def as_record(self) -> dict:
        return {"lane": self.lane, "unit": self.unit, "measure": self.measure, "model": self.model,
                "retriable": {"now": self.now, "cooldown": self.cooldown},
                "terminal": {c: self.terminal.get(c, 0) for c in TERMINAL_CAUSES},
                "detail": dict(self.detail)}


#: how one obligation was disposed of by one child. Only `remainder` keeps a campaign alive, and only
#: `unknown` forbids a verdict — an obligation nobody disposed of is never a zero.
DISPOSITIONS = ("known_zero", "remainder", "terminal", "not_applicable", "unknown")

#: exactly the keys one persisted obligation carries.
_OBLIGATION_KEYS = {"lane", "unit", "measure", "disposition", "retriable", "terminal", "why"}


@dataclass
class Obligation:
    """One `(lane, unit, measure)` a campaign must dispose of before it may call anything settled.

    An empty unit is the lane itself, carried from before the lane named any unit; it labels the lane's
    disposition and never counts, so the lane's units carry the numbers exactly once.
    """
    lane: str
    unit: str = ""
    measure: str = ""
    disposition: str = "unknown"
    retriable: int = 0
    terminal: dict = field(default_factory=dict)
    why: str = ""

    @property
    def key(self) -> tuple:
        return (self.lane, self.unit, self.measure)

    def validate(self) -> None:
        for name in ("lane", "unit", "measure", "why"):
            if type(getattr(self, name)) is not str:
                raise ValueError(f"an obligation needs an exact {name}")
        if not self.lane.strip():
            raise ValueError("an obligation needs a lane")
        if self.disposition not in DISPOSITIONS:
            raise ValueError(f"{self.lane}: unknown disposition {self.disposition!r}")
        if type(self.retriable) is not int or self.retriable < 0:
            raise ValueError(f"{self.lane}: retriable must be an exact non-negative int")
        for cause, value in self.terminal.items():
            if cause not in TERMINAL_CAUSES:
                raise ValueError(f"{self.lane}: unknown terminal cause {cause!r}")
            if type(value) is not int or value < 0:
                raise ValueError(f"{self.lane}: terminal {cause} must be an exact non-negative int")
        # The empty `(unit, measure)` row is a lane label.  Its disposition summarizes concrete rows,
        # while those rows carry every count exactly once; the campaign reader reconciles that label
        # against its units.  Concrete obligations must be self-consistent in isolation.
        if self.unit or self.measure:
            has_terminal = any(value > 0 for value in self.terminal.values())
            if self.disposition == "remainder":
                coherent = self.retriable > 0 and not has_terminal
            elif self.disposition == "terminal":
                coherent = self.retriable == 0 and has_terminal
            else:
                coherent = self.retriable == 0 and not has_terminal
            if not coherent:
                raise ValueError(
                    f"{self.lane}: disposition {self.disposition!r} contradicts its "
                    "retriable/terminal counts",
                )

    def as_record(self) -> dict:
        return {"lane": self.lane, "unit": self.unit, "measure": self.measure,
                "disposition": self.disposition, "retriable": self.retriable,
                "terminal": dict(self.terminal), "why": self.why}

    @classmethod
    def from_record(cls, record) -> "Obligation":
        """Rebuild a persisted obligation, refusing anything a reader cannot believe."""
        if not isinstance(record, dict) or set(record) != _OBLIGATION_KEYS:
            raise ValueError(f"an obligation record carries exactly {sorted(_OBLIGATION_KEYS)}")
        if not isinstance(record["terminal"], dict):
            raise ValueError("an obligation's terminal counts must be an object")
        ob = cls(**{**record, "terminal": dict(record["terminal"])})
        ob.validate()
        return ob

    @classmethod
    def of(cls, remainder: "Remainder") -> "Obligation":
        """How one reported remainder disposes of its obligation."""
        remainder.validate()
        terminal = {c: n for c, n in remainder.terminal.items() if n}
        owed = remainder.retriable
        if owed:
            disposition, why = "remainder", ""
        elif terminal:
            disposition, why = "terminal", "no repetition resolves this"
        elif remainder.now or remainder.cooldown:
            # owed, and real, but a later child replays the same prefix: `--unbound`'s business
            disposition, why = "not_applicable", "repetition cannot reach this remainder"
        else:
            disposition, why = "known_zero", ""
        return cls(lane=remainder.lane, unit=remainder.unit, measure=remainder.measure,
                   disposition=disposition, retriable=owed, terminal=terminal, why=why)


def roster(lanes=None) -> dict:
    """One open obligation per declared lane, before any child has run: a lane nobody has heard from yet
    is unknown, never absent."""
    return {(lane, "", ""): Obligation(lane=lane)
            for lane in sorted(LANE_MODEL if lanes is None else lanes)}


def emit(remainder: Remainder) -> dict:
    """Publish a remainder as its own event, so the manifest carries the latest per (lane, unit)."""
    remainder.validate()
    record = remainder.as_record()
    return events.emit("remainder", remainder.lane, unit=remainder.unit, measure=remainder.measure,
                       model=remainder.model, retriable=record["retriable"], terminal=record["terminal"],
                       detail=record["detail"] or None)


def unknown(lane: str, *, measure: str = "targets", why: str = "") -> dict:
    """A lane that ran and cannot say what it owes reports that, so its silence is not read as a fixed
    point. The record carries no model and no counts, so every consumer classifies it as unreadable."""
    return events.emit("remainder", lane, unit=f"{lane}:{measure}", measure=measure,
                       model="unknown", detail={"why": why or "the eligible set was never established"})


def from_sweep(lane: str, swept, *, measure: str = "targets") -> Remainder:
    """What a `run_sweep` lane still owes: liveness from the durable rotation, dispositions as detail.

    Liveness is `targets_remaining` — the cumulative, durability-aware count — not the pair partition,
    which describes this lifecycle only. Dispositions come from the sweep at target level
    (`remaining_now` / `remaining_cooldown` / `remaining_terminal`), because pair totals cannot partition
    target totals. The pair partition rides along as detail, in its own measure, never summed with the
    target counts."""
    parts = swept.pair_remainder()
    terminal = {c: int(n) for c, n in (getattr(swept, "remaining_terminal", {}) or {}).items() if n}
    return Remainder(lane=lane, unit=f"{lane}:{measure}", measure=measure,
                     model=LANE_MODEL.get(lane, "project_progress"),
                     now=max(0, int(getattr(swept, "remaining_now", 0))),
                     cooldown=max(0, int(getattr(swept, "remaining_cooldown", 0))),
                     terminal=terminal,
                     detail={"candidate_pairs": {k: int(v) for k, v in parts.items()},
                             "targets_remaining": int(getattr(swept, "targets_remaining", 0))})


def for_rounds(lane: str, *, stop: str, rounds: int, ran: int, made: bool) -> Remainder:
    """What a convergent loop still owes. A `rerun_same_work` lane's remainder is real even though
    repetition cannot reach it — the record says both."""
    owed = 1 if (stop == "bound" and made) else 0        # the bound cut a producing loop short
    terminal: dict = {}
    if stop == "no_progress":
        terminal["machinery"] = 1                        # a degraded batch, not a fixed point
    return Remainder(lane=lane, unit=f"{lane}:rounds", measure="rounds",
                     model=LANE_MODEL.get(lane, "rerun_same_work"),
                     now=0 if terminal else owed, terminal=terminal,
                     detail={"rounds_ran": int(ran), "bound": int(rounds), "exit": stop})
