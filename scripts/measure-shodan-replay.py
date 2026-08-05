#!/usr/bin/env python3
"""§5 — MEASURE that a second run replays purchased Shodan pages instead of re-buying them.

The claim under test: purchased pages are project-scoped, so run B in a FRESH run directory replays what
run A bought and spends nothing. Before this repair the pivot ledger lived under `ctx.run.dir`, replay
read only that ledger, and two `quarry run` invocations paid twice for identical bytes.

    A   buys EXACTLY 2 pages          balance delta, lane count and emitted spend must all agree
    B   fresh run dir, same project    requires pages_bought=0, replayed_fresh=2, and BOTH accountings
                                       reading exactly 0 — an unreadable balance is an unmeasured
                                       claim, never a pass

It is HARD-CAPPED at 4 credits and refuses to issue a single request unless every precondition is
PROVEN first — the query set, the ledger identity, a readable balance, and the page cap. A measurement
that spends more than it meant to has measured its own carelessness.

    ./scripts/measure-shodan-replay.py --preflight        # no request, no spend: prove the setup
    ./scripts/measure-shodan-replay.py --run              # A then B, at most 4 credits

Everything measured is written to `--out` (default: `<project>/measurement.json`): both run ids and
manifest paths, the emitted provider-spend records, page dispositions, artifact digests, the ledger's
lost set, and every balance snapshot. A run that FAILS is written too — a spend with no record of itself
is the one outcome this script must never produce.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from quarry_recon import budget, events, secrets, settings, shodan_sched, store  # noqa: E402
from quarry_recon.phases import probe                                          # noqa: E402

#: the WHOLE experiment's ceiling. Two pivots, one page each, twice — B is expected to buy nothing, so
#: 4 is the worst case in which the repair does not work at all and both runs pay.
CREDIT_CAP = 4
#: one page per pivot: the cap has to be a property of the REQUEST, not of our intention
MAX_PAGES = 1
#: the REAL lane, taken from the registry — not a hand-built stand-in. A fake spec carrying only `sid`
#: satisfies this script and not the coordinator, which also reads `facet`, `source` and `note`: the
#: AttributeError would have landed AFTER the pages were paid for. The measurement has to drive the
#: production object or it is measuring something else.
LANE = probe._SHODAN_LANES[0]                       # probe.favicon / http.favicon.hash
#: two pivot values: public infrastructure favicons, not a target's data
VALUES = ["81586312", "708578229"]
PIVOTS = [(LANE.sid, LANE.facet, v) for v in VALUES]


class Abort(RuntimeError):
    """A precondition could not be PROVEN. Nothing has been requested and nothing spent."""


def _enforce_page_cap() -> int:
    """Make `MAX_PAGES` a property of the LANE, not of this script's arithmetic — and prove it took.

    `SHODAN_MAX_PAGES` defaults to 0 = UNBOUNDED and resolves through `settings.concurrency()`, which
    reads `config.yaml` and NOTHING else: `settings.override()` does not reach it. So a cap stated only
    in this file's constant would have bounded the report while the lane paged a favicon hash with
    thousands of results until the balance stopped it. The cap is injected into the settings cache this
    process reads (never the operator's file on disk) and then READ BACK through the lane's own accessor.
    """
    settings.load()                                     # populate the cache from the real config first
    perf = settings._cache.setdefault("PERFORMANCE", {})    # process-local; the file is never written
    perf["SHODAN_MAX_PAGES"] = MAX_PAGES
    effective = settings.concurrency("SHODAN_MAX_PAGES", 0)
    if effective != MAX_PAGES:
        raise Abort(f"the page cap did not take: the lane would use SHODAN_MAX_PAGES={effective}, "
                    f"not {MAX_PAGES} — an unbounded pivot can spend the whole balance")
    return effective


def _balance(key) -> dict:
    """The provider's own account state, read through the same code the lane uses.

    The fields are `ShodanBalance`'s OWN — `remaining` is the provider's finite credit count, and it is
    `None` when unknown, never "unlimited". A stub with an invented `credits` attribute made this read
    `None` and would have aborted a perfectly fundable measurement; the names have to be the real ones."""
    bal = probe._read_shodan_balance(key)
    return {"remaining": bal.remaining, "allowance": bal.allowance, "reserve": bal.reserve,
            "spendable": bal.spendable, "may_spend": bal.may_spend, "reason": bal.reason,
            "read_error": bal.read_error, "stop_kind": bal.stop_kind, "at": time.time()}


def preflight(project: Path) -> dict:
    """Prove every precondition, or raise. NOTHING here issues a paid request."""
    facts: dict = {}
    key = secrets.shodan()
    if not key:
        raise Abort("no Shodan key configured (~/.config/quarry/secrets.yaml → shodan). "
                    "Balance cannot be read, so the cap cannot be proven and nothing may be bought.")
    facts["key_present"] = True

    bal = _balance(key)
    facts["balance_before_preflight"] = bal
    if bal["read_error"]:
        raise Abort(f"/api-info read failed ({bal['read_error']}: {bal['reason']!r}) — a spend we cannot "
                    f"measure is a spend we must not make")
    if not isinstance(bal["remaining"], int):
        raise Abort(f"balance is not readable ({bal['reason']!r}) — a spend we cannot measure is a spend "
                    f"we must not make")
    if bal["remaining"] < CREDIT_CAP:
        raise Abort(f"balance {bal['remaining']} is below the experiment's own cap of {CREDIT_CAP}")
    # a run that may not spend buys nothing, and a B that replays nothing proves nothing
    if not bal["may_spend"]:
        raise Abort(f"the lane may not spend ({bal['stop_kind'] or 'stopped'}: {bal['reason']!r}) — "
                    f"run A would buy nothing and B would have nothing to replay")
    if isinstance(bal["spendable"], int) and bal["spendable"] < CREDIT_CAP:
        raise Abort(f"spendable {bal['spendable']} (reserve {bal['reserve']}) is below the cap "
                    f"{CREDIT_CAP} — the reserve would stop the measurement part-way")

    # the QUERY SET, stated exactly: two pivots, one page each
    facts["pivots"] = [{"lane": l, "facet": f, "value": v} for l, f, v in PIVOTS]
    facts["max_pages"] = _enforce_page_cap()
    facts["max_pages_source"] = settings.source_of("SHODAN_MAX_PAGES")
    facts["worst_case_credits"] = len(PIVOTS) * MAX_PAGES * 2       # both runs buying = the repair failed
    if facts["worst_case_credits"] > CREDIT_CAP:
        raise Abort(f"the query set can cost {facts['worst_case_credits']} > cap {CREDIT_CAP}")

    # the LEDGER IDENTITY: project-scoped, schema-keyed, and the same path for both runs
    sdir = shodan_sched.state_dir(project)
    lpath = budget.state_path(sdir, "probe.shodan", f"v{shodan_sched.SHODAN_WORK_SCHEMA}")
    facts["state_dir"] = str(sdir)
    facts["ledger_path"] = str(lpath)
    if project not in lpath.parents:
        raise Abort(f"the ledger is not inside the project: {lpath}")
    if "recon" in lpath.parts:
        raise Abort(f"the ledger is under a RUN directory — that is the bug being measured: {lpath}")
    facts["ttl_days"] = probe._shodan_page_ttl()
    if facts["ttl_days"] <= 0:
        raise Abort(f"TTL is {facts['ttl_days']}: pages would never replay, so B cannot be measured")

    # a CLEAN ownership store, proven — not assumed (review#5). A project that already owns one of these
    # pages makes A replay instead of buy, and "B replayed what A bought" would then be true of a
    # purchase that never happened. The lost set counts too: those pages are now refused, so A would
    # neither buy nor replay them.
    led = budget.Ledger(lpath, lane="probe.shodan")
    if led.unreadable:
        raise Abort(f"the ownership store exists and cannot be trusted ({led.unreadable}) — a corrupt "
                    f"index reads as an empty one, and every page would be bought again")
    if getattr(led, "foreign", False):
        raise Abort(f"{lpath} belongs to a different lane; refusing to write or spend against it")
    keys = {shodan_sched.item_key(shodan_sched.Pivot(l, f, v), page): (v, page)
            for l, f, v in PIVOTS for page in range(1, MAX_PAGES + 1)}
    held = sorted(f"{v} p{page}" for k, (v, page) in keys.items()
                  if led.has(k) or k in led.lost)
    if held:
        raise Abort(f"this project already holds pages for the tested pivots ({', '.join(held)}) — "
                    f"run A would replay them and prove nothing. Use a fresh --project.")
    facts["store_was_empty"] = True
    facts["owned_at_start"] = len(dict(led.items()))
    return facts


def _spend_events(run_dir: Path) -> list:
    """QUARRY's own accounting for this run: every `spend` event the lane emitted."""
    path = run_dir / "events.jsonl"
    if not path.is_file():
        return []
    out = []
    for line in path.read_text().splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, dict) and e.get("event") == "spend" and e.get("provider") == "shodan":
            out.append(e)
    return out


def _run_one(project: Path, key, label: str, report: dict, save) -> dict:
    """One lane lifecycle over the SAME pivots, in its own fresh run directory.

    The record is assembled and PERSISTED in `finally`, including when the lane raises. A paid request
    that ends in an exception is the case where the evidence matters most, and the old version
    propagated before anything was written — the credit was spent and the experiment had no record of
    it (review#4)."""
    run = store.Run.create(project, "replay-measurement")
    events.reset()
    events.configure(run.dir)
    ctx = type("Ctx", (), {"run": run, "scope": type("S", (), {"in_scope": lambda s, h: False})(),
                           "echo": lambda *a, **k: None})()
    before = _balance(key)
    rec: dict = {"label": label, "run_id": run.run_id, "run_dir": str(run.dir),
                 "balance_before": before, "exception": None}
    report[label] = rec
    res = None
    try:
        try:
            rec["exception"] = None
            work = probe._shodan_work(ctx, key, [(LANE, list(VALUES))])
            res = work.result
            # the RESULT step is where Quarry states its own accounting — `events.spend` and the page
            # dispositions are emitted there, not by the coordinator. Driving acquisition alone left
            # `emitted_spend=None`, i.e. the experiment could not cross-check the provider's balance
            # against Quarry's own books at all (review#3).
            rec["terminal"] = repr(probe._shodan_result(LANE, sorted(VALUES), work))
        except BaseException as e:                       # noqa: BLE001 — recorded, then re-raised below
            rec["exception"] = {"type": type(e).__name__, "message": str(e),
                                "traceback": traceback.format_exc()}
    finally:
        # `_balance` is a NETWORK read. It reports most failures as `read_error`, but it may still raise
        # — and it was the first statement in this block, so a raise here skipped `save()` entirely and
        # destroyed the record of a run that had already spent (review#2). Everything already known is
        # preserved; the experiment still fails, because an unread balance proves nothing.
        try:
            after = _balance(key)
        except BaseException as e:                       # noqa: BLE001 — recorded, never silent
            after = {"remaining": None, "reason": "balance read raised", "read_error": type(e).__name__,
                     "exception": {"type": type(e).__name__, "message": str(e),
                                   "traceback": traceback.format_exc()}, "at": time.time()}
            rec.setdefault("errors", []).append("balance_after unreadable: " + type(e).__name__)
        rec["balance_after"] = after
        rec["credits_spent"] = ((before["remaining"] - after["remaining"])
                                if isinstance(before["remaining"], int)
                                and isinstance(after["remaining"], int) else None)
        rec["lanes"] = {name: {"pages_bought": o.pages_bought, "replayed_fresh": o.pages_replayed,
                               "aged_available": o.pages_aged, "refresh_refused": o.refresh_refused,
                               "lost": o.pages_lost, "repair_refused": o.repair_refused,
                               "oldest_replay_s": round(o.oldest_replay_s, 1)}
                        for name, o in (res.lanes.items() if res is not None else ())}
        rec["provider_spend"] = _spend_events(run.dir)
        # the docstring promised BOTH run manifests and nothing wrote them. A manifest is the run's own
        # account of itself — entity counts, notes, tool runs — and the measurement is worth exactly what
        # it can show afterwards (review#3).
        try:
            run.write_manifest({"measurement": "shodan-replay", "label": label},
                               ["probe"], metrics=None, policy=None)
            rec["manifest"] = str(run.manifest_path)
        except Exception as e:                           # noqa: BLE001 — a missing manifest is reported
            rec["manifest"] = None
            rec.setdefault("errors", []).append(f"manifest not written: {type(e).__name__}: {e}")
        try:
            ledger = budget.Ledger(
                budget.state_path(shodan_sched.state_dir(project), "probe.shodan",
                                  f"v{shodan_sched.SHODAN_WORK_SCHEMA}"), lane="probe.shodan")
            rec["owned_pages"] = [{"item": i, "artifact": str(a), "digest": events.file_digest(a)}
                                  for i, a in ledger.items()]
            rec["lost_items"] = sorted(ledger.lost)
        except OSError as e:
            rec["owned_pages"] = None
            rec["ledger_read_error"] = str(e)
        save()                                           # on disk BEFORE anything can propagate
    return rec


def _emitted_spend(rec: dict) -> "int | None":
    """What QUARRY says this run spent, in PAGES. `None` when its accounting is missing or unusable —
    which is a failed measurement, never a zero."""
    amounts = [e.get("amount") for e in rec.get("provider_spend") or []
               if e.get("measure") == "pages"]
    if not amounts or any(not isinstance(a, int) or isinstance(a, bool) for a in amounts):
        return None
    return sum(amounts)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project", help="an EXISTING-or-new project dir; default: a fresh timestamped one")
    ap.add_argument("--preflight", action="store_true", help="prove the setup; issue nothing")
    ap.add_argument("--run", action="store_true", help="run A then B (at most %d credits)" % CREDIT_CAP)
    ap.add_argument("--out", help="where to write the measurement (default: <project>/measurement.json)")
    args = ap.parse_args()

    # the default project is CLAIMED atomically: `exist_ok=False` means two invocations can never share
    # one ownership store, and a rerun cannot silently inherit the previous run's purchases (review#5).
    project = Path(args.project) if args.project else (
        Path.home() / "workspace" / "shodan-replay-measurement"
        / time.strftime("%Y%m%dT%H%M%S", time.gmtime()))
    try:
        project.mkdir(parents=True, exist_ok=bool(args.project))
    except FileExistsError:
        print(f"ABORT (nothing requested, nothing spent): {project} already exists; "
              f"a measurement claims its own project directory", file=sys.stderr)
        return 2
    report: dict = {"cap": CREDIT_CAP, "project": str(project)}
    try:
        report["preflight"] = preflight(project)
    except Abort as e:
        print(f"ABORT (nothing requested, nothing spent): {e}", file=sys.stderr)
        return 2
    print("preflight OK:")
    for k in ("state_dir", "ledger_path", "ttl_days", "max_pages", "max_pages_source",
              "worst_case_credits"):
        print(f"  {k}: {report['preflight'][k]}")
    b = report["preflight"]["balance_before_preflight"]
    print(f"  balance: {b['remaining']} credits (reserve {b['reserve']}, spendable {b['spendable']})")
    if not args.run:
        print("\n--preflight only: no request issued. Re-run with --run to spend.")
        return 0

    key = secrets.shodan()
    out = Path(args.out) if args.out else (project / "measurement.json")

    def save():
        out.write_text(json.dumps(report, indent=2, default=str))

    expected = len(PIVOTS) * MAX_PAGES
    a = _run_one(project, key, "A", report, save)
    bought_a = sum(l["pages_bought"] for l in a["lanes"].values())
    spent_a, emitted_a = a["credits_spent"], _emitted_spend(a)
    print(f"\nRUN A: bought={bought_a} credits_spent={spent_a} emitted_spend={emitted_a} "
          f"owned_pages={len(a['owned_pages'] or [])}")
    # A is a PRECONDITION for B, so it is checked as one. Anything other than exactly the expected
    # purchase means B would be measuring a different experiment (review#5), and an exception means a
    # credit may have been spent with the lane in an unknown state (review#4).
    if a["exception"]:
        print(f"STOP: run A raised {a['exception']['type']}: {a['exception']['message']}. "
              f"Run B is NOT started; the partial record is in {out}", file=sys.stderr)
        return 1
    if not (spent_a == bought_a == emitted_a == expected):
        print(f"STOP: run A must buy exactly {expected} page(s) with balance, lane and emitted spend "
              f"agreeing — got bought={bought_a} balance_delta={spent_a} emitted={emitted_a}. "
              f"Run B is NOT started; see {out}", file=sys.stderr)
        return 1

    b = _run_one(project, key, "B", report, save)
    bought_b = sum(l["pages_bought"] for l in b["lanes"].values())
    replayed_b = sum(l["replayed_fresh"] for l in b["lanes"].values())
    emitted_b = _emitted_spend(b)
    # BOTH accountings must say zero, and each must have been READ. An unreadable balance is an
    # unmeasured claim, not a successful one (review#2); a missing spend event is missing evidence, not
    # evidence of zero (review#3). `None` therefore fails, and a disagreement between the two fails too.
    report["verdict"] = {
        "b_bought": bought_b, "b_replayed_fresh": replayed_b,
        "b_credits_spent": b["credits_spent"], "b_emitted_spend": emitted_b,
        "a_credits_spent": spent_a, "a_emitted_spend": emitted_a,
        "balance_and_accounting_agree": b["credits_spent"] == emitted_b == 0,
        "replay_works": bool(b["exception"] is None and bought_b == 0 and replayed_b == expected
                             and b["credits_spent"] == 0 and emitted_b == 0)}
    save()
    print(f"RUN B: bought={bought_b} replayed_fresh={replayed_b} "
          f"credits_spent={b['credits_spent']} emitted_spend={emitted_b}")
    if b["credits_spent"] is None or emitted_b is None:
        print("NOT PROVEN: a zero-spend claim needs a READ balance and an emitted spend record; "
              "one of them is missing.", file=sys.stderr)
    print(f"\nVERDICT: {'REPLAY WORKS' if report['verdict']['replay_works'] else 'NOT PROVEN'}  →  {out}")
    return 0 if report["verdict"]["replay_works"] else 1


if __name__ == "__main__":
    sys.exit(main())
