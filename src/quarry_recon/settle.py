"""`--settle` — the continuation axis: keep creating runs while resumable work still advances.

A supervisor over runs, never a knob inside one (`docs/design/SETTLE-DESIGN.md`). Each child is an
ordinary run with its own evidence; the campaign adds only a ledger over child run ids plus the union
that carries what they learned between them. This module owns the loop and the bounds, `campaign.py`
owns the ledger, the union and the rules. It never edits a child's evidence and launches nothing itself
— the caller passes `launch`.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import campaign as _campaign, store as _store
from .state import ContractError

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
        cid = _campaign.validate_campaign_id(new_campaign_id())
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


def campaign_target(project_dir, campaign_id: str) -> tuple[str | None, str]:
    """`(target, why_not)` — the target every launched child agrees on, `(None, "")` when none launched,
    else why nobody can confirm one and the campaign may not be adopted (SETTLE-DESIGN §7)."""
    ledger = _campaign.Campaign(project_dir, campaign_id)
    if not ledger.trustworthy:
        return None, f"its ledger is {ledger.status} — {ledger.reason}"
    named: set = set()
    for child in ledger.children:
        run_id = child.get("run_id")
        if not run_id:
            continue                        # never launched: it ran against nothing
        try:
            target = _store.read_run_creation_target(project_dir, run_id)
        except (FileNotFoundError, ContractError):
            return None, f"child {child.get('index')} ({run_id}) has no readable creation record"
        named.add(target)
    if len(named) > 1:
        return None, "its children ran against " + ", ".join(repr(t) for t in sorted(named))
    return (named.pop() if named else None), ""


def _triage(project_dir, target: str | None):
    """`(resumable, skipped, unconfirmable)` for every interrupted campaign here, in one pass so the
    answers cannot disagree. `unconfirmable` is the subset a caller cannot rule out as its own: damaged,
    not merely someone else's."""
    found: list = []
    skipped: list = []
    unconfirmable: list = []
    for ledger_path in campaigns(project_dir):
        cid = ledger_path.parent.name
        if not _campaign.valid_campaign_id(cid):
            continue                        # not a directory this project could have minted
        ledger = _campaign.Campaign(project_dir, cid)
        if not ledger.trustworthy:
            skipped.append((cid, f"its ledger is {ledger.status} — {ledger.reason}"))
            unconfirmable.append(cid)
            continue
        if not ledger.children or ledger.stop:
            continue                        # finished, or never recorded a child: nothing interrupted
        union = _campaign.Union.for_campaign(project_dir, cid, create=True)
        if not union.trustworthy:
            skipped.append((cid, f"its union is {union.status} — {union.reason}"))
            unconfirmable.append(cid)
            continue
        ran_against, unconfirmed = campaign_target(project_dir, cid)
        if unconfirmed:
            skipped.append((cid, unconfirmed))
            unconfirmable.append(cid)
        elif target is not None and ran_against not in (None, target):
            # confirmed to be someone else's, which is knowing what it is, not failing to
            skipped.append((cid, f"it ran against {ran_against!r}"))
        else:
            found.append(cid)
    return found, skipped, unconfirmable


def resumable_campaigns(project_dir, target: str | None = None) -> list[str]:
    """Every campaign under this project that `settle(campaign_id=...)` would continue, oldest first: a
    readable ledger that recorded children, recorded no stop, and still has a usable union. A `target`
    narrows that to the campaigns that ran against it — the union is one target's corpus."""
    return _triage(project_dir, target)[0]


def skipped_resumable(project_dir, target: str | None = None) -> list[tuple[str, str]]:
    """`(campaign_id, why_not)` for every interrupted campaign here that `settle()` would refuse, oldest
    first — so a caller says what it is passing over instead of silently minting a new campaign over the
    remains of one that already spent its acquisition."""
    return _triage(project_dir, target)[1]


def unconfirmable_resumable(project_dir, target: str | None = None) -> list[str]:
    """The interrupted campaigns a caller cannot rule out as its own, oldest first: an unreadable ledger,
    a union that is gone, a target nobody can confirm. A campaign confirmed to belong to another target
    is not one of these — knowing whose it is, is not failing to."""
    return _triage(project_dir, target)[2]


def resumable(project_dir, target: str | None = None) -> str | None:
    """The one campaign a caller may continue without choosing for the operator: exactly one candidate,
    and no live supervisor holding the project lease. None otherwise — several is a choice, not a
    default."""
    found = resumable_campaigns(project_dir, target)
    return found[0] if len(found) == 1 and _lease_free(project_dir) else None


def _lease_free(project_dir) -> bool:
    """Whether no live supervisor holds the project lease. Probed and released, never held: the answer is
    a moment old, and `settle()` takes the lease itself."""
    from . import budget
    try:
        with budget.state_lock(Path(project_dir) / "recon" / "campaigns" / ".campaign.lock"):
            return True
    except (budget.StateBusy, OSError):
        return False


class CampaignRefused(RuntimeError):
    """A campaign this caller may not continue. Refused before the lease is taken and before any child."""


class AlreadyRun(CampaignRefused):
    """This campaign has already stated its outcome. Continuing it would append child N+1 to a history
    that is closed; an interrupted campaign is a different thing and resumes."""


class WrongTarget(CampaignRefused):
    """This campaign's children ran against another target. Its union is that target's corpus, and a child
    seeded from it would file one target's evidence under another's."""


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
    elapsed_s: float = 0.0            # this invocation
    spent_s: float = 0.0              # the campaign's total across every incarnation — what the budget bounds
    recovered: bool = False           # the union was rebuilt after an evidence loss
    resumed: bool = False             # this campaign was continued from an interrupted ledger
    abandoned: int = 0                # children nobody could measure
    #: {cause: count} from the decision that ended the campaign, for a caller stating an outcome —
    #: `remainder.terminal_class` says whether that is a bound, a gap or a fault
    terminal: dict = field(default_factory=dict)

    @property
    def clean(self) -> bool:
        """A fixed point over a union that was never rebuilt and with every child measured — what a
        caller consults before calling anything complete."""
        return self.success and not self.recovered and not self.abandoned


def settle(*, project_dir, target: str, launch, max_runs: int = _campaign.MAX_CHILDREN,
           budget_s: int = 0, echo=None, campaign_id: str | None = None, _now=None) -> Outcome:
    """One campaign of child runs under one project lease, bounded and resumable (SETTLE-DESIGN §6-7).

    `launch(index, prepare)` runs one child: it calls `prepare(run)` once the run directory exists and
    before any phase runs, and returns the finished `Run`.
    """
    say = echo or (lambda _line: None)
    now = _now or time.monotonic
    target = _store.validate_target(target)        # before a new campaign directory can be claimed
    cid = (_campaign.validate_campaign_id(campaign_id)
           if campaign_id is not None else _claim(project_dir))
    ledger = _campaign.Campaign(project_dir, cid)
    ledger.require()                     # a fresh id is `new`; a reopened corrupt one refuses here
    if ledger.stop:
        raise AlreadyRun(f"campaign {cid} already has {len(ledger.children)} child run(s) and "
                         f"stopped: {ledger.stop['cause']} — a campaign that stated its outcome is not "
                         f"resumed; start a new one")
    # a campaign is one target's corpus: resuming another's would seed this target's children from it, so
    # an unconfirmable target is refused exactly like a mismatched one
    ran_against, unconfirmed = campaign_target(project_dir, cid)
    if unconfirmed:
        raise WrongTarget(f"campaign {cid} cannot be confirmed as {target!r}: {unconfirmed} — a campaign "
                          f"whose target nobody can read is not adopted under the caller's")
    if ran_against is not None and ran_against != target:
        raise WrongTarget(f"campaign {cid} ran against {ran_against!r}, not {target!r} — resume it under "
                          f"the target it was started for, or start a new campaign")
    out = Outcome(campaign_id=cid, resumed=bool(ledger.children))
    t0 = now()

    # the project lock is the campaign's lease, and the OS releases it when its holder dies — which is
    # why a killed campaign can be resumed while a live one still cannot be joined (§6).
    with ledger.acquire():
        union = _campaign.Union.for_campaign(project_dir, cid, create=True)
        # a child that has a run may already have acquired, so only a campaign whose first child never
        # launched may still open acquisition
        acquired = any(child.get("run_id") for child in ledger.children)
        book, previous_retriable, idle = _history(ledger, out)
        adopted = _adopt(project_dir, ledger, union, book, out, say, max_runs=max_runs,
                         previous_retriable=previous_retriable, idle=idle)
        # after the interrupted child has been charged: the budget bounds the campaign, so a resume
        # spends only what earlier incarnations left of it
        spent_before, unmeasured = _spent(ledger)
        if adopted is not None:
            previous_retriable, idle = adopted.retriable, (0 if adopted.progressed else idle + 1)
            if adopted.stop:
                _finish(ledger, out, adopted)
        while not out.stop:
            index = len(ledger.children) + (0 if _unlaunched(ledger) else 1)
            # the cap counts every child the ledger recorded, abandoned ones included: each of them was a
            # run this campaign started
            if index > max_runs:
                _finish(ledger, out, _campaign.Decision(
                    stop="max_runs", detail=f"{len(ledger.children)} child run(s)"))
                break
            # a campaign that cannot establish what it has already spent may not spend more of a bound it
            # cannot prove it is inside
            if budget_s and unmeasured:
                _finish(ledger, out, _campaign.Decision(
                    stop="unknown",
                    detail=f"child {', '.join(str(i) for i in unmeasured)} left no measurable spend, so "
                           f"this campaign cannot show it is inside its {budget_s}s budget"))
                break
            # the budget bounds continuation and is asked only between children; killing a running child
            # is `--timeout`'s axis.
            spent = spent_before + (now() - t0)
            if budget_s and spent >= budget_s:
                _finish(ledger, out, _campaign.Decision(
                    stop="budget", detail=f"{int(spent)}s of a {budget_s}s budget spent before "
                                          f"child {index}"))
                break

            child = _next_child(ledger)
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

            if index == 1 and not acquired:
                run_obj = launch(index, prepare)
            else:
                # from child 2 the campaign may process everything it holds, but acquire nothing new
                with _campaign.acquisition_closed():
                    run_obj = launch(index, prepare)
            if child.get("run_id") != run_obj.run_id:
                # absorbing a run the ledger did not record would file one run's evidence under another's id
                raise RuntimeError(f"child {index} recorded {child.get('run_id')!r} but "
                                   f"{run_obj.run_id!r} was returned")

            # the committed manifest is the child's verdict; recomputing one here contradicts what the
            # child published and is read back differently by a resume
            summary = _committed(run_obj.dir)
            if summary is None:
                raise RuntimeError(f"child {index} ({run_obj.run_id}) returned without a committed "
                                   f"manifest — a campaign decides on what a child published")
            absorbed = union.absorb(run_obj.dir)
            decision = _campaign.decide(summary, absorbed, settlement=book, idle_children=idle,
                                        children=index, max_children=max_runs,
                                        previous_retriable=previous_retriable)
            ledger.manifested(child, summary=summary, absorbed=absorbed, decision=decision,
                              elapsed_s=spent_before + (now() - t0) - spent)
            _report(out, say, index, run_obj.run_id, summary, absorbed, decision)

            previous_retriable = decision.retriable
            idle = 0 if decision.progressed else idle + 1

            if decision.stop:
                _finish(ledger, out, decision)

    out.elapsed_s = round(now() - t0, 1)
    out.spent_s = round(spent_before + out.elapsed_s, 1)
    out.recovered = union.was_recovered
    return out


# ── resuming an interrupted campaign ────────────
def _unlaunched(ledger) -> bool:
    """Whether the ledger's last child is one a previous incarnation reserved and never launched."""
    return bool(ledger.children) and ledger.children[-1].get("state") == "reserved"


def _next_child(ledger) -> dict:
    """The record to launch under: a reserved child nobody launched is that child, not the next one."""
    return ledger.children[-1] if _unlaunched(ledger) else ledger.reserve()


def _read(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def _committed(run_dir) -> dict | None:
    """The verdict a child committed to its manifest, or None when it never committed a readable one."""
    doc = _read(Path(run_dir) / "manifest.json")
    return doc["summary"] if isinstance(doc, dict) and isinstance(doc.get("summary"), dict) else None


def _when(value):
    """One aware ISO-8601 moment, or None — a naive stamp names no instant anyone can subtract."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    return moment if moment.tzinfo is not None else None


def _last_activity(run_dir: Path):
    """The newest moment this run's own artifacts show, or None when none of them can be read."""
    newest = None
    for name in ("manifest.json", "events.jsonl", "state.json", "run.json", "normalized", ""):
        try:
            stamp = (run_dir / name).stat().st_mtime
        except OSError:
            continue
        newest = stamp if newest is None else max(newest, stamp)
    return None if newest is None else datetime.fromtimestamp(newest, timezone.utc)


def _interrupted_spend(project_dir, child: dict) -> float | None:
    """What a child the campaign never saw finish still cost it: from when the ledger recorded it started
    to the last activity its own run shows. None when neither end can be established — that is time
    nobody measured, never time nobody spent."""
    run_dir = Path(project_dir) / "recon" / child["run_id"]
    began = _when(child.get("started_at")) or _when((_read(run_dir / "run.json") or {}).get("started"))
    ended = _when((_read(run_dir / "manifest.json") or {}).get("finished")) or _last_activity(run_dir)
    if began is None or ended is None:
        return None
    return max(0.0, (ended - began).total_seconds())


def _spent(ledger) -> tuple[float, list]:
    """`(measured seconds, children whose cost is unknown)`. A child that has a run cost the campaign
    time; one that never launched cost it none."""
    spent, unmeasured = 0.0, []
    for child in ledger.children:
        if not child.get("run_id"):
            continue
        if "elapsed_s" in child:
            spent += float(child["elapsed_s"])
        else:
            unmeasured.append(child["index"])
    return spent, unmeasured


def _history(ledger, out: Outcome):
    """What earlier children established: the roster the last of them left, what it owed, and how many in
    a row added nothing. A campaign that forgot its roster would owe nothing and converge on silence.

    The last child is left out: a resume settles that one again, so its own decision must be taken with
    what the campaign knew before it."""
    pending = ledger.children[-1] if ledger.children else None
    book = _campaign.Settlement()
    previous_retriable: int | None = None
    idle = 0
    for child in ledger.children:
        if child is pending:
            continue
        if child.get("state") == "abandoned":
            out.abandoned += 1
        if child.get("state") != "manifested":
            continue
        book.adopt(child.get("obligations") or [])
        previous_retriable = child.get("retriable")
        idle = 0 if child.get("progressed") else idle + 1
        _recall(out, child)
    return book, previous_retriable, idle


def _recall(out: Outcome, child: dict) -> None:
    """A child an earlier incarnation finished, as this campaign's outcome carries it."""
    out.children.append(ChildRun(
        index=child["index"], run_id=child.get("run_id") or "", verdict=child.get("verdict") or "",
        new=child.get("new_identities", 0), enriched=child.get("enriched", 0),
        retriable=child.get("retriable", 0), progressed=bool(child.get("progressed")),
        spend=list(child.get("provider_spend") or [])))


def _adopt(project_dir, ledger, union, book, out: Outcome, say, *, max_runs, previous_retriable, idle):
    """Settle the child a previous incarnation left mid-flight, and return its decision.

    A run that wrote its manifest is finished evidence the campaign already paid for: it is absorbed and
    decided rather than run again, whether the ledger got as far as recording it or not — absorbing is
    idempotent by run id, so its own deltas are the ones that count either time. A run that never wrote a
    manifest cannot be measured at all, so it is abandoned by name and its evidence is left where it lies.
    A child that never launched is left for the loop to launch."""
    child = ledger.children[-1] if ledger.children else None
    if child is None or child.get("state") in ("reserved", "abandoned"):
        if child is not None and child["state"] == "abandoned":
            out.abandoned += 1
        return None
    index, run_id = child["index"], child["run_id"]
    run_dir = Path(project_dir) / "recon" / run_id
    summary = _committed(run_dir)
    if summary is None:
        if child["state"] == "manifested":
            # measured once and its evidence is gone since: the ledger's own record of it is what is left
            book.adopt(child.get("obligations") or [])
            _recall(out, child)
            return _campaign.Decision(retriable=child.get("retriable", 0),
                                      progressed=bool(child.get("progressed")))
        # its coverage is unmeasurable, but the time it burned is not: the campaign is charged what it
        # can establish, and records nothing when it can establish nothing
        ledger.abandoned(child, "interrupted before its manifest: nothing about it can be measured",
                         elapsed_s=_interrupted_spend(project_dir, child))
        out.abandoned += 1
        say(f"   child {index} ({run_id}) was interrupted before its manifest — abandoned")
        return None
    absorbed = union.absorb(run_dir)
    decision = _campaign.decide(summary, absorbed, settlement=book, idle_children=idle, children=index,
                                max_children=max_runs, previous_retriable=previous_retriable)
    if child["state"] == "started":
        ledger.manifested(child, summary=summary, absorbed=absorbed, decision=decision,
                          elapsed_s=_interrupted_spend(project_dir, child))
    say(f"   child {index} ({run_id}) finished before the campaign was interrupted — adopted")
    _report(out, say, index, run_id, summary, absorbed, decision)
    return decision


def _report(out: Outcome, say, index: int, run_id: str, summary: dict, absorbed, decision) -> None:
    out.children.append(ChildRun(index=index, run_id=run_id, verdict=summary.get("verdict", ""),
                                 new=absorbed.new, enriched=absorbed.enriched,
                                 retriable=decision.retriable, progressed=decision.progressed,
                                 spend=summary.get("provider_spend", [])))
    say(f"   {summary.get('verdict', '?')} · union +{absorbed.new} new / +{absorbed.enriched} "
        f"enriched · {decision.retriable} unit(s) still owed")
    for row in summary.get("provider_spend", []):
        say(f"   spend: {row.get('source_id')} {row.get('provider')} "
            f"{row.get('amount')} {row.get('measure')}")


def _finish(ledger, out: Outcome, decision) -> None:
    """Name the stop — and account for a child that was reserved and will now never launch."""
    for child in ledger.children:
        if child.get("state") == "reserved":
            ledger.abandoned(child, "the campaign stopped before this child was launched")
            out.abandoned += 1
    ledger.finish(decision)
    out.stop, out.detail, out.success = decision.stop or "fixed_point", decision.detail, decision.success
    out.terminal = dict(decision.terminal)


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
        elif state == "abandoned":
            lines.append(f"  {child['index']}. {child.get('run_id') or '(not launched)'} · "
                         f"ABANDONED: {child.get('reason')}")
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
