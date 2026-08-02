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

    def validate(self) -> None:
        if self.model not in MODELS:
            raise ValueError(f"{self.lane}: unknown remainder model {self.model!r}")
        if LANE_MODEL.get(self.lane) != self.model:
            raise ValueError(f"{self.lane}: model {self.model!r} contradicts the declared "
                             f"{LANE_MODEL.get(self.lane)!r}")
        if not self.unit or not self.measure:
            raise ValueError(f"{self.lane}: a remainder needs a unit and a measure")
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
                "terminal": {c: self.terminal.get(c, 0) for c in TERMINAL_CAUSES}}


def emit(remainder: Remainder) -> dict:
    """Publish a remainder as its own event, so the manifest can carry the LATEST per (lane, unit)."""
    remainder.validate()
    record = remainder.as_record()
    return events.emit("remainder", remainder.lane, unit=remainder.unit, measure=remainder.measure,
                       model=remainder.model, retriable=record["retriable"], terminal=record["terminal"])


def from_sweep(lane: str, swept, *, measure: str = "candidate_pairs") -> Remainder:
    """The remainder a `run_sweep` result already knows, mapped onto the dispositions.

    The sweep's partition (`pair_remainder()`, `1a2eefa`) answers this almost directly:

        bound / deferred   the per-run allowance and the spend bound — a later child takes them
        refused            the contact guard said no; the rotation asks again after its cooldown
        unselectable       no bound can ever admit these: TERMINAL
        stopped            depends on what stopped the run — a clock is retriable next child, a machinery
                           or dependency stop is not
    """
    parts = swept.pair_remainder()
    stopped = int(parts.get("stopped", 0))
    terminal: dict = {}
    now = int(parts.get("bound", 0)) + int(parts.get("deferred", 0))
    if stopped:
        kind = getattr(swept, "stop_kind", None)
        if kind == "machinery":
            terminal["machinery"] = stopped
        elif kind == "dependency":
            terminal["dependency"] = stopped
        else:
            now += stopped                     # a clock or a cancellation: the next child simply continues
    if parts.get("unselectable"):
        terminal["unschedulable"] = int(parts["unselectable"])
    return Remainder(lane=lane, unit=f"{lane}:{measure}", measure=measure,
                     model=LANE_MODEL.get(lane, "project_progress"),
                     now=now, cooldown=int(parts.get("refused", 0)), terminal=terminal)
