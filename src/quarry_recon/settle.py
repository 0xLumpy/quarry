"""`--settle` — the continuation axis: keep creating runs while resumable work still advances.

A supervisor over runs, never a knob inside one (`docs/design/SETTLE-DESIGN.md`). Each child is an
ordinary run with its own evidence; the campaign adds only a ledger over child run ids plus the union
that carries what they learned between them. This module owns the loop and the bounds, `campaign.py`
owns the ledger, the union and the rules. It never edits a child's evidence and launches nothing itself
— the caller passes `launch`.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from . import campaign as _campaign

#: a campaign id is minted like a run id: second precision alone collides, and a reused id would continue
#: another campaign's ledger as child 2.
_STAMP = "%Y%m%d-%H%M%S"


def new_campaign_id(now=None) -> str:
    import secrets as _secrets
    from datetime import datetime, timezone
    return "c" + (now or datetime.now(timezone.utc)).strftime(_STAMP) + "-" + _secrets.token_hex(4)


def _claim(project_dir) -> str:
    """Mint an id and claim its directory atomically, so even a same-instant clash cannot share one."""
    root = Path(project_dir) / "recon" / "campaigns"
    for _ in range(16):
        cid = new_campaign_id()
        try:
            (root / cid).mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            continue
        return cid
    raise RuntimeError("could not mint a unique campaign id after 16 attempts")


def campaigns(project_dir) -> list[Path]:
    """Every campaign ledger under a project, newest last. Missing directory is not an error — a project
    that never settled simply has no campaigns."""
    root = Path(project_dir) / "recon" / "campaigns"
    try:
        found = [p / "ledger.json" for p in sorted(root.iterdir()) if (p / "ledger.json").is_file()]
    except OSError:
        return []
    return found


class AlreadyRun(RuntimeError):
    """This campaign has already run, and resuming one is not implemented: appending child N+1 to an
    existing ledger would skip part of the campaign's own history, so every existing campaign is refused
    whatever state it is in."""


@dataclass
class ChildRun:
    """One child's outcome, as the campaign saw it."""
    index: int
    run_id: str = ""
    verdict: str = ""
    new: int = 0
    enriched: int = 0
    retriable: int = 0
    progressed: bool = False
    seeded: dict = field(default_factory=dict)
    spend: list = field(default_factory=list)


@dataclass
class Outcome:
    """What the campaign did and why it stopped. Every stop is named."""
    campaign_id: str
    stop: str = ""
    detail: str = ""
    success: bool = False
    children: list = field(default_factory=list)
    elapsed_s: float = 0.0
    recovered: bool = False           # the union was rebuilt after an evidence loss

    @property
    def clean(self) -> bool:
        """A fixed point over a union that was never rebuilt — what a caller consults before calling
        anything complete."""
        return self.success and not self.recovered


def settle(*, project_dir, target: str, launch, max_runs: int = _campaign.MAX_CHILDREN,
           budget_s: int = 0, echo=None, campaign_id: str | None = None, _now=None) -> Outcome:
    """Run children until the stop rules say otherwise.

    `launch(index, prepare)` creates and runs one child, calling `prepare(run)` once the run directory
    exists and before any phase runs, and returns the finished `Run`. Keeping it a callback leaves the CLI
    owning what a run is.

    The project lock is held for the whole campaign, so two supervisors that minted different ids cannot
    spawn children against the same rotation (§6).
    """
    say = echo or (lambda _line: None)
    now = _now or time.monotonic
    cid = campaign_id or _claim(project_dir)
    ledger = _campaign.Campaign(project_dir, cid)
    ledger.require()                     # a fresh id is `new`; a reopened corrupt one refuses here
    if ledger.children:
        interrupted = ledger.interrupted
        raise AlreadyRun(
            f"campaign {cid} already has {len(ledger.children)} child run(s)"
            + (f" and stopped: {ledger.stop['cause']}" if ledger.stop else "")
            + (f"; child {interrupted[0]['index']} is interrupted while {interrupted[0]['state']}"
               if interrupted else "")
            + " — resuming a campaign is not implemented; start a new one")
    out = Outcome(campaign_id=cid)
    t0 = now()

    with ledger.acquire():
        union = _campaign.Union.for_campaign(project_dir, cid, create=True)
        # the roster grows from what the campaign has heard: a lane that reported once and then goes
        # silent is unknown, not zero.
        heard: set = set()
        previous_retriable: int | None = None
        idle = 0
        while True:
            index = len(ledger.children) + 1
            # the budget bounds continuation and is asked only between children; killing a running child
            # is `--timeout`'s axis.
            if budget_s and (now() - t0) >= budget_s:
                _finish(ledger, out, _campaign.Decision(
                    stop="budget", detail=f"{int(now() - t0)}s of a {budget_s}s budget spent before "
                                          f"child {index}"))
                break

            child = ledger.reserve()
            say(f"\n══ campaign {cid} · child {index}/{max_runs} · target={target} ══")

            def prepare(run, _index=index, _child=child):
                # the ledger records the run id before any phase runs, so a crash leaves an interrupted
                # started child rather than a run directory nobody accounts for.
                ledger.started(_child, run.run_id)
                if _index == 1:
                    return
                seeded = union.bootstrap(run)      # refuses an untrustworthy union by raising
                if seeded:
                    say("   seeded from the campaign union: "
                        + ", ".join(f"{k}={v}" for k, v in sorted(seeded.items())))

            if index == 1:
                run_obj = launch(index, prepare)
            else:
                # from child 2 the campaign may process everything it holds, but acquire nothing new
                with _campaign.acquisition_closed():
                    run_obj = launch(index, prepare)
            if child.get("run_id") != run_obj.run_id:
                # absorbing a run the ledger did not record would file one run's evidence under another's id
                raise RuntimeError(f"child {index} recorded {child.get('run_id')!r} but "
                                   f"{run_obj.run_id!r} was returned")

            summary = run_obj._run_summary()
            absorbed = union.absorb(run_obj.dir)
            decision = _campaign.decide(summary, absorbed, expected_lanes=sorted(heard),
                                        idle_children=idle, children=index, max_children=max_runs,
                                        previous_retriable=previous_retriable)
            ledger.manifested(child, summary=summary, absorbed=absorbed, decision=decision)

            record = ChildRun(index=index, run_id=run_obj.run_id, verdict=summary.get("verdict", ""),
                              new=absorbed.new, enriched=absorbed.enriched, retriable=decision.retriable,
                              progressed=decision.progressed, spend=summary.get("provider_spend", []))
            out.children.append(record)
            say(f"   {summary.get('verdict', '?')} · union +{absorbed.new} new / +{absorbed.enriched} "
                f"enriched · {decision.retriable} unit(s) still owed")
            for row in summary.get("provider_spend", []):
                say(f"   spend: {row.get('source_id')} {row.get('provider')} "
                    f"{row.get('amount')} {row.get('measure')}")

            heard |= {row["lane"] for row in summary.get("remainders", [])
                      if isinstance(row, dict) and isinstance(row.get("lane"), str)}
            previous_retriable = decision.retriable
            idle = 0 if decision.progressed else idle + 1

            if decision.stop:
                _finish(ledger, out, decision)
                break

    out.elapsed_s = round(now() - t0, 1)
    out.recovered = union.was_recovered
    return out


def _finish(ledger, out: Outcome, decision) -> None:
    ledger.finish(decision)
    out.stop, out.detail, out.success = decision.stop or "fixed_point", decision.detail, decision.success


# ── reading a campaign back ────────────────────
def report_lines(ledger) -> list[str]:
    """A campaign as an operator reads it: what ran, what it added, what it still owes, and why it stopped.
    Reads the ledger rather than a live process, so a finished, running and interrupted campaign all work."""
    if not ledger.trustworthy:
        return [f"campaign {ledger.campaign_id}: {ledger.status} — {ledger.reason}",
                "  recover it deliberately (`Campaign.recover`) or start a new campaign; "
                "the ledger is left exactly as found"]
    lines = [f"campaign {ledger.campaign_id} · {len(ledger.children)} child run(s)"]
    for entry in ledger.recoveries:
        lines.append(f"  ⚠ recovered #{entry['index']} at {entry['at']}: {entry['reason']} "
                     f"(cause: {entry['cause']})")
    for child in ledger.children:
        state = child.get("state")
        if state == "manifested":
            lines.append(f"  {child['index']}. {child.get('run_id')} · {child.get('verdict')} · "
                         f"+{child.get('new_identities')} new / +{child.get('enriched')} enriched · "
                         f"{child.get('retriable')} owed"
                         + ("" if child.get("progressed") else " · no progress")
                         + (f" · faults: {', '.join(sorted(set(child.get('faults') or [])))}"
                            if child.get("faults") else ""))
        else:
            lines.append(f"  {child['index']}. {child.get('run_id') or '(not launched)'} · "
                         f"INTERRUPTED while {state}")
    stop = ledger.stop
    if stop:
        lines.append(f"  stopped: {stop['cause']}"
                     + (f" — {stop['detail']}" if stop["detail"] else "")
                     + ("  ✔ success" if stop["success"] else ""))
    else:
        lines.append("  no stop recorded — the campaign did not finish")
    return lines
