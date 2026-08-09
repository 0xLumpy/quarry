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

#: every lane that can report a remainder, and its model. Declared, never inferred from a number, and
#: test-enforced: a lane that reports without declaring is one whose remainder nobody can interpret.
LANE_MODEL: dict[str, str] = {
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
