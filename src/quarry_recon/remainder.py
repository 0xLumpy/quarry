"""What a lane still OWES, in a form a supervisor can read — settle prerequisite B.

A number is not a promise. `--settle` may only keep a campaign alive for work another child would actually
ADVANCE, and that depends on two independent things:

  the LANE's cross-run model      does durable project state carry between runs, or does a later run repeat
                                  the same prefix? (`MAX_ITERS` is the cautionary case: its remainder is
                                  real, entities are run-scoped, and repetition can never reach it — which
                                  is why it belongs to `--unbound`.)
  THIS remainder's disposition    one sweep can hold both work a later child will schedule and work no
                                  bound can ever admit. Collapsing them into one number lets impossible
                                  work keep a campaign running for ever.

So a record carries both, plus the MEASURE its numbers are in — `retriable: 5` is meaningless when targets,
candidate pairs and rounds are all counted somewhere. Comparability is per `(lane, unit, measure)`, exactly
like the coverage records these are derived from.

A lane that reports NOTHING is UNKNOWN, never zero: silence is not a fixed point.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import events

#: how a lane's remainder behaves ACROSS runs. Only `project_progress` may keep a campaign alive.
MODELS = ("project_progress", "rerun_same_work")

#: every lane that can report a remainder, and its model. Declared beside the lane's behaviour rather than
#: inferred from a number, and test-enforced: a lane that reports without declaring is a lane whose
#: remainder nobody can interpret.
LANE_MODEL: dict[str, str] = {
    # the sweep lanes: their rotation ledger is PROJECT-scoped, so a later child continues where this one
    # stopped (`recon/state/sched/v<SCHEMA>/<lane>.json`, per-slot content-bound completion)
    "enrich.a1d_brute": "project_progress",
    "enrich.wildcard_a1d": "project_progress",
    "vertical.wildcard_http": "project_progress",
    # the permutation loop: entities are RUN-scoped, so a later run replays rounds 1..N from an empty
    # frontier — its remainder is `--unbound`'s business, never `--settle`'s
    "vertical.alterx_permute": "rerun_same_work",
}

#: causes that no repetition resolves. `refused` is deliberately NOT here: an admission refusal cools down
#: and is asked again (`budget.ADMISSION_COOLDOWN_GENS`), so it is retriable — with a wait.
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
        if LANE_MODEL.get(self.lane) != self.model:
            raise ValueError(f"{self.lane}: model {self.model!r} contradicts the declared "
                             f"{LANE_MODEL.get(self.lane)!r}")
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
        """What repetition could still take — only for a lane repetition actually advances."""
        return (self.now + self.cooldown) if self.model == "project_progress" else 0

    def as_record(self) -> dict:
        return {"lane": self.lane, "unit": self.unit, "measure": self.measure, "model": self.model,
                "retriable": {"now": self.now, "cooldown": self.cooldown},
                "terminal": {c: self.terminal.get(c, 0) for c in TERMINAL_CAUSES},
                "detail": dict(self.detail)}


def emit(remainder: Remainder) -> dict:
    """Publish a remainder as its own event, so the manifest can carry the LATEST per (lane, unit)."""
    remainder.validate()
    record = remainder.as_record()
    return events.emit("remainder", remainder.lane, unit=remainder.unit, measure=remainder.measure,
                       model=remainder.model, retriable=record["retriable"], terminal=record["terminal"],
                       detail=record["detail"] or None)


def from_sweep(lane: str, swept, *, measure: str = "targets") -> Remainder:
    """What a `run_sweep` lane still owes — LIVENESS from the durable rotation, dispositions as detail.

    The pair partition (`pair_remainder()`, `1a2eefa`) describes THIS LIFECYCLE: a target the allowance
    deferred is in it, and so is one whose slots a later child already finished. Reading liveness off it
    repeats the defect the continuation report had — after the pinned eight-zone trace it still claimed
    three zones owed when the rotation had covered all eight. `targets_remaining` is the cumulative,
    durability-aware answer (`68195e8`), so that is what says whether repetition would advance anything.

    The DISPOSITIONS come from the sweep at TARGET level too (`remaining_now` / `remaining_cooldown` /
    `remaining_terminal`), because pair totals cannot partition target totals: one owed target can be a
    guard refusal while another holds only work no bound can admit, and translating pair counts into target
    counts collapsed both into whichever class was checked first. The pair partition is kept as DETAIL, in
    its own measure, never summed with the target counts.
    """
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
    """What a convergent LOOP still owes. Its model decides what that is worth: a `rerun_same_work` lane's
    remainder is real, and repetition still cannot reach it — the record says both."""
    owed = 1 if (stop == "bound" and made) else 0        # the bound cut a producing loop short
    terminal: dict = {}
    if stop == "no_progress":
        terminal["machinery"] = 1                        # a degraded batch, not a fixed point
    return Remainder(lane=lane, unit=f"{lane}:rounds", measure="rounds",
                     model=LANE_MODEL.get(lane, "rerun_same_work"),
                     now=0 if terminal else owed, terminal=terminal,
                     detail={"rounds_ran": int(ran), "bound": int(rounds), "exit": stop})
