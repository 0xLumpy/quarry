"""B1.3 — the Shodan work COORDINATOR.

One credit buys one search PAGE, so the unit of work is `(lane, facet, value, page)` and the credit
balance is a schedule, not an afterthought. Two facts forced this shape:

  * a shared counter is NOT cross-lane fairness. `probe.favicon` and `probe.cert` are separate provider
    calls, so whichever runs first drains the balance no matter what counter it consults. The work of
    BOTH lanes has to be collected before any credit is spent.
  * `SHODAN_MAX_PAGES = 1` was a cap in its own right — removing the 20-pivot cap while keeping it would
    just move the same silent truncation one level down.

Scheduling is BREADTH FIRST by PAGE NUMBER, with cross-lane fairness inside each page tier. The page has
to be the OUTER rank: grouping by lane alone looked fair on a clean start but broke on RESUME, where a
pivot already holding pages 1-2 took page 3 before an untouched pivot got its first.

The coordinator owns scheduling, purchase, evidence, durability and coverage. It does NOT own ingestion
or HTTP: both are injected, so a lane keeps its own entity semantics and the tests are hermetic by
construction rather than by patching the network.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from . import budget, events

SHODAN_WORK_SCHEMA = 1
SHODAN_PAGE_SIZE = 100                      # Shodan returns up to 100 matches per page


@dataclass(frozen=True)
class Pivot:
    """One searchable value belonging to one lane. `page` is not part of it — pages are work, a pivot is
    the thing worked on."""

    lane: str                               # the registered source_id, e.g. "probe.favicon"
    facet: str                              # e.g. "http.favicon.hash"
    value: str

    @property
    def label(self) -> str:
        return f"{self.facet}:{self.value}"


@dataclass
class PivotState:
    """What we have learned about a pivot, and what remains to buy."""

    pivot: Pivot
    total: "int | None" = None              # the provider's own match count; None until page 1 answers
    pages_done: set = field(default_factory=set)
    attempted: bool = False                 # a request was ISSUED for this pivot (a credit was spent)
    stopped: str = ""                       # a class that ended this pivot early (limit or failure)
    _cursor: int = 1                        # lowest page not known-complete; never rescans the prefix

    def page_count(self) -> "int | None":
        """How many pages this pivot HAS, or None while unknown.

        An unqueried pivot has NO knowable page count, and inventing one would fabricate a denominator.
        `None` is the honest answer and the caller must not sum it into anything."""
        if self.total is None:
            return None
        return max(1, -(-self.total // SHODAN_PAGE_SIZE))    # ceil division

    def next_page(self, max_pages: int = 0) -> "int | None":
        """The lowest page still owed, or None. `max_pages` 0 = unbounded (operator policy only).

        review#6: this scanned from page 1 on EVERY round, so a 100k-page pivot performed billions of set
        lookups across a run — quadratic work behind a docstring claiming laziness. The cursor is
        monotonic, so the completed prefix is walked once in total."""
        if self.stopped:
            return None
        while self._cursor in self.pages_done:
            self._cursor += 1
        pages = self.page_count()
        if pages is None:
            return self._cursor if self._cursor == 1 else None
        limit = pages if not max_pages else min(pages, max_pages)
        return self._cursor if self._cursor <= limit else None

    def withheld_pages(self, max_pages: int = 0) -> int:
        """Pages this pivot HAS, that an operator page policy keeps us from buying, and that we do NOT
        already own.

        review-r2#5: ignoring `pages_done` reported OWNED evidence as withheld — buy all five pages, then
        resume with max_pages=2, and the run replayed all five while still claiming three were withheld.
        Coverage was complete and the verdict said `complete_with_limits` anyway."""
        pages = self.page_count()
        if pages is None or not max_pages:
            return 0
        return sum(1 for p in range(max_pages + 1, pages + 1) if p not in self.pages_done)


def item_key(pivot: Pivot, page: int) -> str:
    """The per-PAGE completion identity: (schema, lane, facet, value, page).

    The RESERVE is deliberately absent. It governs planning, not results — a page bought under reserve 10
    is byte-identical to one bought under reserve 0, so folding the reserve in would make lowering it
    RE-PAY for pages already purchased. (The opposite of the A1/A2 rule, where a coverage-config change
    genuinely invalidates the artifact.)"""
    raw = f"{SHODAN_WORK_SCHEMA}|{pivot.lane}|{pivot.facet}|{pivot.value}|p{page}"
    return hashlib.sha256(raw.encode()).hexdigest()


def owned_index(ledger) -> dict:
    """Every page the ledger demonstrably owns, grouped by pivot: {(lane, facet, value): [pages]}.

    review-B1.3r5#1: the previous version PROBED upward from page 1 and gave up after N consecutive
    misses. That was a hidden recovery cap: with pages 1-6 recorded and 1-5 damaged, page 6 was still
    valid in the ledger and discovery returned NOTHING — the paid evidence was invisible to Quarry, which
    is exactly the loss the ownership work exists to prevent. Documenting the limit did not make the page
    readable.

    No second index is needed to fix it. `Ledger.items()` already enumerates every digest-validated
    completion, and a page document identifies ITSELF, so one pass over the owned pages recovers a hole
    of any width in O(owned pages). The item key is recomputed from the document and must match the key
    it was filed under: that is what stops a page from claiming an identity it was not bought as.

    review-B1.3r6#2: each resumed artifact was read THREE times — here, again inside `_read_page`, and a
    third time in `_replay_one` — on top of the digest `Ledger._load` already computed. The full pass is
    the right trade; reading the same bytes repeatedly is not. The VALIDATED document is returned with
    each page so replay consumes it directly: one JSON read per resumed page."""
    out: dict = {}
    for item, art in ledger.items():
        try:
            doc = json.loads(art.read_text())
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        lane, facet, value, page = doc.get("lane"), doc.get("facet"), doc.get("value"), doc.get("page")
        if not (isinstance(lane, str) and isinstance(facet, str) and isinstance(value, str)):
            continue
        if isinstance(page, bool) or not isinstance(page, int):
            continue
        pivot = Pivot(lane=lane, facet=facet, value=value)
        # the FULL page contract, then the binding: a document is only evidence for the identity it was
        # actually filed under, so a relabelled or transplanted artifact cannot donate ownership.
        if valid_page(doc, pivot, page) is None or item_key(pivot, page) != item:
            continue
        out.setdefault((lane, facet, value), []).append((page, art, doc))
    for pages in out.values():
        pages.sort(key=lambda e: e[0])
    return out


def ledger_writable(ledger) -> bool:
    """Whether completions can actually be journaled. review-r3#1: writability was checked only AFTER
    every purchase, so a foreign ledger let a run buy 15 pages and then report `persisted=False` — and
    the next lifecycle bought all 15 again. For PAID work this is a precondition, not a postcondition."""
    return not getattr(ledger, "foreign", False) and not getattr(ledger, "_journal_unsafe", False)


def store_writable(attempt_dir) -> bool:
    """Whether a bought page could actually be PUBLISHED — proven by writing, not assumed.

    review-B1.3r7#2: the ledger was probed before spending and the artifact store was not, so a
    read-only attempt directory was discovered by paying for a page and then failing to store it
    (`calls=[1]`, `stop_cause=publish_failed`) — and the next run bought it again. Both sinks are
    required, so both are proven up front.

    The probe exercises the same primitive the real page uses (temp + verify + replace) and then REMOVES
    itself: an artifact directory must contain only real evidence, and a probe we cannot clean up is
    itself a failure — it would be an orphan in a tree whose contract says every file is a validated
    artifact."""
    probe = Path(attempt_dir) / ".quarry-write-probe"
    body = b'{"probe":1}'
    try:
        Path(attempt_dir).mkdir(parents=True, exist_ok=True)
        ok = budget.publish_bytes(probe, body, digest=hashlib.sha256(body).hexdigest())
        probe.unlink(missing_ok=True)
        return bool(ok) and not probe.exists()
    except OSError:
        return False


def dedupe(states: "list[PivotState]") -> "list[PivotState]":
    """One state per (lane, facet, value). review#7: two states for the same pivot both appeared in a
    round and BOTH bought page 1 — a round is computed before either records completion, so the duplicate
    is invisible to the in-flight guard. Paying twice for identical bytes."""
    seen: set = set()
    out = []
    for st in states:
        k = (st.pivot.lane, st.pivot.facet, st.pivot.value)
        if k in seen:
            continue
        seen.add(k)
        out.append(st)
    return out


def schedule(states: "list[PivotState]", *, max_pages: int = 0) -> list:
    """The next round of work: at most one page per pivot, ordered PAGE TIER first and fair across lanes
    inside a tier.

    Fairness is computed over PENDING work only — ordering the whole set would interleave completed
    history and push a lane's real remainder behind another lane's finished pages (the A1 lesson)."""
    pending = [(st, st.next_page(max_pages)) for st in states]
    pending = [(st, pg) for st, pg in pending if pg is not None]
    return budget.order_ranked_fair(pending, rank=lambda it: it[1],
                                    group=lambda it: it[0].pivot.lane)


@dataclass
class LaneOutcome:
    """Per-lane facts the caller turns into its own terminal and coverage."""

    lane: str
    pivots: int = 0
    pivots_touched: int = 0                 # at least one page bought or replayed
    pages_bought: int = 0
    pages_replayed: int = 0
    matches: int = 0
    fail_classes: dict = field(default_factory=dict)
    limit_classes: dict = field(default_factory=dict)
    # POSITION and CAUSE are independent facts (review-B1.1r2/r3). A pivot that yielded NOTHING is not
    # the same as one that kept page-1 evidence and lost a later page, and the reason prose must never
    # name a class from the other position. The aggregates above stay, but they are a SUMMARY — these
    # four are what the coverage measures are derived from.
    first_fail_classes: dict = field(default_factory=dict)
    first_limit_classes: dict = field(default_factory=dict)
    later_fail_classes: dict = field(default_factory=dict)
    later_limit_classes: dict = field(default_factory=dict)
    unqueried: list = field(default_factory=list)      # EXACT identities, never a count alone
    pages_left_known: int = 0               # only for pivots whose total is KNOWN
    pages_left_unknown_pivots: int = 0      # pivots whose page count we cannot know
    pages_withheld: int = 0                 # pages an operator policy (max_pages) kept us from buying
    total_drift: int = 0                    # pages whose total disagreed with another page's
    evidence_invalid: int = 0               # recorded pages whose artifact did not validate
    publish_failed: int = 0                 # bought pages we could not durably record


@dataclass
class WorkResult:
    lanes: dict = field(default_factory=dict)
    persisted: bool = True                  # completion state actually reached disk
    records_journaled: bool = True          # every completion recorded THIS RUN reported success
    stop_cause: str = ""                    # WHY scheduling ended — the scheduler's own answer, which
                                            # the balance alone cannot give (it does not know whether we
                                            # ran out mid-flight, hit the reserve, or lost the store)


def observe_total(st, o, total) -> None:
    """Fold one page's reported total into the pivot, by ONE policy for fresh and replayed pages alike.

    review-B1.3r7#1: the live path OVERWROTE the total on every page while replay accepted only the
    first (`if st.total is None`), so the two disagreed about the same evidence. Buy page 1 (total 200)
    and page 2 (total 500) — 3 pages left. Resume, and page 2's larger total was discarded: 0 pages
    left, 0 queries, a clean stop. An incomplete pivot silently became a complete one.

    Shodan's total moves between pages (the index is live), so disagreement is PROVIDER DRIFT, not
    corruption. Quarry is breadth-first: keep the MAXIMUM observed total, so the remainder is never
    understated, and count the disagreement rather than hiding it."""
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        return
    if st.total is not None and st.total != total:
        o.total_drift += 1
    st.total = total if st.total is None else max(st.total, total)


def _page_doc(pivot: Pivot, page: int, total, matches) -> dict:
    return {"schema": SHODAN_WORK_SCHEMA, "lane": pivot.lane, "facet": pivot.facet,
            "value": pivot.value, "page": page, "total": total, "matches": matches}


def valid_page(doc, pivot: Pivot, page: int):
    """The recorded page, or None when the artifact does not prove what it claims.

    review#2: `pages_done` and `pages_replayed` were updated BEFORE the body was validated, and the
    reader accepted any dict — so a digest-bound `{}` became a permanent GHOST completion: replayed
    forever, never re-bought, contributing nothing. The envelope must identify ITSELF."""
    if not isinstance(doc, dict) or doc.get("schema") != SHODAN_WORK_SCHEMA:
        return None
    if (doc.get("lane") != pivot.lane or doc.get("facet") != pivot.facet
            or doc.get("value") != pivot.value):
        return None
    pg = doc.get("page")
    if isinstance(pg, bool) or not isinstance(pg, int) or pg != page:
        return None
    # review-r3#2: `total is None` was accepted, so a digest-valid page with a null total became a ghost
    # completion all over again — never repurchased, and its unknown page count surfaced only in prose.
    # Replay owes exactly what `valid_fresh` demands of the provider.
    if not valid_fresh(doc.get("matches"), doc.get("total")):
        return None
    return doc


def valid_fresh(matches, total) -> bool:
    """Whether a provider answer may be published as a completed page.

    review-r2#2: replayed evidence was validated and FRESH output was not, so the coordinator trusted the
    network more than its own disk. `([], None, None)` recorded a "complete" page whose total was unknown
    — owning a page while being unable to enumerate the rest of them."""
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        return False
    return isinstance(matches, list)


def _read_page(path, pivot: Pivot, page: int):
    try:
        doc = json.loads(path.read_text())
    except Exception:
        return None
    return valid_page(doc, pivot, page)


def run_work(ctx, *, states, balance, search, ingest, ledger, attempt_dir,
             max_pages: int = 0, is_limit=None) -> WorkResult:
    """Buy pages under the balance, replaying anything already owned.

    `search(pivot, page) -> (matches, total, error)` and `ingest(pivot, page, matches, raw_path) -> int`
    are injected. `balance` is the settled B1.2 contract: `may_spend` decides whether ANY credit may be
    spent, `spendable` (None = no computable bound) decides how many."""
    from .contract import is_provider_limit as _default_is_limit
    is_limit = is_limit or _default_is_limit
    states = dedupe(states)
    res = WorkResult()
    for st in states:
        o = res.lanes.setdefault(st.pivot.lane, LaneOutcome(lane=st.pivot.lane))
        o.pivots += 1
    try:
        _replay_indexed(states, res, ledger=ledger, ingest=ingest)
        _work(states, res, balance=balance, search=search, ingest=ingest, ledger=ledger,
              attempt_dir=attempt_dir, max_pages=max_pages, is_limit=is_limit)
        _sweep_owned(states, res, ledger=ledger, ingest=ingest, max_pages=max_pages)
        _remainder(states, res, max_pages=max_pages)
    finally:
        # persistence is the coordinator's job and its RESULT is a fact. Leaving save() to the caller
        # (and ignoring it) let a foreign or unwritable ledger keep bought pages looking resumable in
        # memory while the next run would pay for them all over again.
        #
        # review-B1.3r4#1: COMPACTION and RESUMABILITY are separate facts. `Ledger._load` replays the
        # journal, so completions that were journaled SURVIVE even when the snapshot write fails —
        # reporting `persisted=False` there is a FALSE gap. Conversely a silently-dropped append is a
        # real one. The question is "will the next run see these completions?", which is
        # "snapshot written OR journal intact".
        #
        # review-B1.3r6#1: "journal intact" was not enough. A checkpoint journals fine, the paid page's
        # record() then fails, the journal stays perfectly readable — and compaction fails too. Every
        # individual signal looked survivable while the page reached NEITHER destination. Reproduced:
        # persisted=True, page survives reopen=False. The journal branch needs BOTH facts.
        saved = bool(ledger.save())
        res.persisted = saved or (bool(getattr(ledger, "durable", False)) and res.records_journaled)
    return res


def _replay_one(st, o, *, page, ledger, ingest, owned=None) -> "bool | None":
    """True when the page was replayed from owned evidence, False when the record is unusable, None when
    we do not own it.

    review-r2#3: replay used to be a contiguous pre-pass that STOPPED at the first hole — so a damaged
    page 1 with a perfectly good page 2 behind it caused BOTH to be bought again. The ledger is now
    consulted for each page as it is scheduled, so a repaired page 1 lets page 2 replay for free."""
    if owned is not None:
        # already enumerated, validated and key-bound by `owned_index` — re-reading it would be a third
        # read of bytes we hold (review-B1.3r6#2).
        art, doc = owned
    else:
        key = item_key(st.pivot, page)
        if not ledger.has(key):
            return None
        art = ledger.artifact(key)
        doc = _read_page(art, st.pivot, page) if art is not None else None
    if doc is None:
        o.evidence_invalid += 1
        return False
    first_touch = not st.pages_done
    st.pages_done.add(page)
    st.attempted = True
    o.pages_replayed += 1
    if first_touch:
        o.pivots_touched += 1                 # ANY page, not just page 1 (review-r4#5)
    observe_total(st, o, doc.get("total"))
    o.matches += ingest(st.pivot, page, doc.get("matches") or [], art)
    return True


def _replay_indexed(states, res, *, ledger, ingest) -> None:
    """Replay every page we demonstrably own, BEFORE any scheduling.

    review-r3#3: purchased evidence must replay whether or not an earlier hole is repaired this
    lifecycle. Sequential discovery meant a failed page-1 repair set `stopped`, which removed the pivot
    from scheduling, which hid an owned page 2 that had already been paid for.

    review-B1.3r5#1: the ledger is enumerated ONCE for the whole run rather than probed per pivot."""
    index = owned_index(ledger)
    for st in states:
        o = res.lanes[st.pivot.lane]
        for page, art, doc in index.get((st.pivot.lane, st.pivot.facet, st.pivot.value), ()):
            if page in st.pages_done:
                continue
            _replay_one(st, o, page=page, ledger=ledger, ingest=ingest, owned=(art, doc))


def _work(states, res, *, balance, search, ingest, ledger, attempt_dir, max_pages, is_limit) -> None:
    spendable = balance.spendable
    if not balance.may_spend:
        spendable = 0
    reserve = int(getattr(balance, "reserve", 0) or 0)
    spent = 0
    # A page is PURCHASED AT MOST ONCE PER RUN, whatever else goes wrong.
    #
    # DELIBERATELY UNFALSIFIABLE TODAY: with every current path correct, no page can be rescheduled after
    # a purchase, so removing this guard breaks no test. It is kept anyway because of what it bounds — an
    # unbounded spend of real money — and because it converts that failure mode from a HANG into a
    # failure. (The publish-failure regression looped forever before it existed; the mutation run had to
    # be killed.) A guard that merely duplicates an enforced invariant should be deleted; this one adds a
    # bound no other layer provides.
    tried: set = set()
    probed: list = []

    def sinks_ok() -> bool:
        """Prove BOTH sinks once, immediately before the first purchase.

        Buying what we cannot record means paying twice: this run spends, the next run spends again.

        review-B1.3r5#3: a flag check alone was not a precondition. Nothing SETS those flags until a
        write has already failed, so a journal that was unwritable before the run started was discovered
        by losing a credit to it. `checkpoint()` appends a no-op record — a real write, replay-safe and
        state-free — so the first thing that touches the journal is free. review-B1.3r7#2 added the
        artifact store, because a page needs both sinks.

        review-B1.3r8#1: probing at entry meant a run that BUYS NOTHING was still judged on sinks it
        never needed. A fully-replayed pivot over a read-only store reported `publish_failed` with zero
        publications attempted — a free, complete run calling itself broken. The probes belong on the
        purchase path, which is the only thing that requires them."""
        if not probed:
            if not (ledger_writable(ledger) and ledger.checkpoint()):
                res.stop_cause = "ledger_unwritable"
                probed.append(False)
            elif not store_writable(attempt_dir):
                res.stop_cause = "publish_failed"
                probed.append(False)
            else:
                probed.append(True)
        return probed[0]
    while not res.stop_cause:
        round_items = schedule(states, max_pages=max_pages)
        if not round_items:
            break
        progressed = False
        for st, page in round_items:
            if res.stop_cause:
                break
            o = res.lanes[st.pivot.lane]
            # OWNED evidence is free and is taken whatever the budget says — replay never spends.
            replayed = _replay_one(st, o, page=page, ledger=ledger, ingest=ingest)
            if replayed:
                progressed = True
                continue
            if spendable is not None and spent >= spendable:
                continue                                  # no credit for this page; remainder reports it
            attempt = (st.pivot.lane, st.pivot.facet, st.pivot.value, page)
            if attempt in tried:
                # review-r3#5: `continue` alone made the guard silent — the loop simply ended with no
                # cause, and an unknown balance then labelled the remainder a provider limit. Reaching
                # here means the scheduler offered a page it had already sold us: an invariant break,
                # which is a DEFECT and must read as one.
                res.stop_cause = "scheduler_invariant"
                continue
            if not sinks_ok():
                break                                     # nothing paid for yet; stop_cause is set
            tried.add(attempt)
            matches, total, err = search(st.pivot, page)
            spent += 1                                    # a request was ISSUED — that is the credit
            st.attempted = True
            progressed = True
            if err is not None:
                cls = getattr(err, "error_class", None) or "error"
                st.stopped = cls
                limit = is_limit(cls)
                bucket = o.limit_classes if limit else o.fail_classes
                bucket[cls] = bucket.get(cls, 0) + 1
                # FIRST position = this pivot has no page at all yet, so the error cost us the whole
                # pivot. Otherwise page-1 evidence is already kept and only a later page was lost.
                if not st.pages_done:
                    pos = o.first_limit_classes if limit else o.first_fail_classes
                else:
                    pos = o.later_limit_classes if limit else o.later_fail_classes
                pos[cls] = pos.get(cls, 0) + 1
                if is_limit(cls):
                    # DEGRADE, don't disable: stop buying, keep everything already earned, leave the rest
                    # as a counted remainder. The provider's boundary ends purchasing, not the run.
                    res.stop_cause = f"provider_limit:{cls}"
                continue
            if not valid_fresh(matches, total):
                # the provider answered, but not with something we can call a page.
                st.stopped = "parse"
                o.fail_classes["parse"] = o.fail_classes.get("parse", 0) + 1
                continue
            observe_total(st, o, total)
            raw = attempt_dir / f"{item_key(st.pivot, page)}.json"
            # review-B1.3r8#1: this serialized the RECONCILED total, so the artifact reported something
            # Shodan never said for that page and the drift disappeared on resume (stored 500/500 for a
            # measured 500/200; drift 1 fresh, 0 resumed). Evidence records what the provider ANSWERED;
            # reconciliation is a derived view and lives only in `PivotState`.
            body = json.dumps(_page_doc(st.pivot, page, total, matches)).encode()
            dig = hashlib.sha256(body).hexdigest()
            # atomic + content-verified: a torn write at a content-addressed name would otherwise be
            # reused later as if it were the page we meant to buy.
            if not budget.publish_bytes(raw, body, digest=dig):
                # review-r2#1: leaving the page PENDING scheduled it again — the same page bought over
                # and over, unbounded when the balance is unknown. A store we cannot write to is a
                # GLOBAL problem: every further purchase would be unrecordable too, so stop paying.
                o.publish_failed += 1
                st.stopped = "publish_failed"
                res.stop_cause = "publish_failed"
                continue
            if not st.pages_done:
                o.pivots_touched += 1         # ANY page counts as touching the pivot
            st.pages_done.add(page)
            o.pages_bought += 1
            # the completion and its durability are ONE fact: a page we cannot journal is a page the
            # next run will buy again, so stop paying the moment that becomes true.
            journaled = ledger.record(item_key(st.pivot, page), raw, digest=dig)
            # review-B1.3r6#1: a readable journal proves OLD content survives, not that THIS page reached
            # it. Both facts are needed, and only the record itself carries the second one.
            res.records_journaled = res.records_journaled and journaled
            o.matches += ingest(st.pivot, page, matches, raw)
            if not journaled or not ledger_writable(ledger):
                res.stop_cause = "ledger_unwritable"
        if not progressed:
            # nothing moved: the budget is gone (or every remaining page is unbuyable).
            if spendable is not None and spent >= spendable and not res.stop_cause:
                # review-r2#4: WHO stopped us. A positive reserve means the operator withheld the rest;
                # a zero reserve means the provider's balance is simply the boundary.
                res.stop_cause = "budget_reserve" if reserve > 0 else "budget_provider"
            break


def _sweep_owned(states, res, *, ledger, ingest, max_pages) -> None:
    """Replay owned pages that an operator PAGE POLICY excluded from purchasing.

    `max_pages` bounds what we BUY; it must not discard evidence we already hold. Without this a run that
    once bought all five pages and then resumed with max_pages=2 replayed only two, and the other three —
    already paid for and sitting on disk — were reported as WITHHELD. Complete coverage, presented as a
    limit."""
    if not max_pages:
        return                                            # nothing was excluded from scheduling
    for st in states:
        pages = st.page_count()
        if pages is None:
            continue
        o = res.lanes[st.pivot.lane]
        for page in range(max_pages + 1, pages + 1):
            if page in st.pages_done:
                continue
            _replay_one(st, o, page=page, ledger=ledger, ingest=ingest)


def _remainder(states, res, *, max_pages) -> None:
    for st in states:
        o = res.lanes[st.pivot.lane]
        # "never reached" is not the same as "asked and refused". A pivot whose only page died on a quota
        # WAS queried — a credit was spent on it — so listing it as unqueried would both overstate the
        # remainder and hide that the attempt happened.
        if not st.pages_done and not st.attempted:
            o.unqueried.append(st.pivot.value)
        pages = st.page_count()
        if pages is None:
            if st.pages_done:
                o.pages_left_unknown_pivots += 1
        else:
            limit = pages if not max_pages else min(pages, max_pages)
            # review-r3#4: `len(pages_done)` counted REPLAYED pages from ABOVE the policy window, so a
            # genuine hole inside it vanished — pages 1 and 3 owned with max_pages=2 reported nothing
            # missing while page 2 was absent.
            done_in_window = sum(1 for p in st.pages_done if p <= limit)
            o.pages_left_known += max(0, limit - done_in_window)
            o.pages_withheld += st.withheld_pages(max_pages)


# ── coverage ──────────────────────────────────────────────────────────────────────────────────────
# WHO stopped us decides the KIND, and the kinds mean different things to the verdict:
#   provider  a PROVEN provider boundary (quota/entitlement)   -> soft limit
#   sample    an OPERATOR policy (reserve, max_pages)          -> soft limit
#   timeout   something FAILED (transport/auth/server/parse)   -> gap
# Collapsing any of these is the defect that recurred through B0/B1.1: a soft limit hiding a real failure
# lets a broken run report `complete_with_limits`.
def _unqueried_kind(balance, stop_cause: str = "") -> str:
    """The kind for work we never reached, decided by WHO stopped us.

    review-r2#4: this consulted only the BALANCE, which cannot know how the run actually ended. A finite
    balance with a positive reserve carries NO stop_kind up front — spendable is simply smaller — so
    exhausting it fell through to "provider boundary" when the operator's reserve was the real cause.
    The scheduler's own answer wins; the balance is the fallback for the cases it settled before any
    work began."""
    from .phases.probe import (SHODAN_ENTITLEMENT, SHODAN_OPERATOR_RESERVE, SHODAN_PROVIDER_EXHAUSTED,
                               SHODAN_UNKNOWN_WITH_RESERVE)
    if stop_cause:
        if stop_cause == "budget_reserve":
            return events.COVERAGE_SAMPLE                # the OPERATOR withheld the rest
        if stop_cause == "budget_provider" or stop_cause.startswith("provider_limit:"):
            return events.COVERAGE_PROVIDER              # the provider's balance was the boundary
        # publish_failed / ledger_unwritable / scheduler_invariant — all OURS, all defects
        return events.COVERAGE_TIMEOUT
    kind = getattr(balance, "stop_kind", "") or ""
    if kind in (SHODAN_PROVIDER_EXHAUSTED, SHODAN_ENTITLEMENT):
        return events.COVERAGE_PROVIDER
    if kind in (SHODAN_OPERATOR_RESERVE, SHODAN_UNKNOWN_WITH_RESERVE):
        return events.COVERAGE_SAMPLE                    # our own policy — a soft limit
    if kind:
        return events.COVERAGE_TIMEOUT                   # auth_refused / forbidden / reserve_invalid
    return events.COVERAGE_PROVIDER


def report(lane: str, outcome: LaneOutcome, *, balance, persisted: bool = True,
           max_pages: int = 0, stop_cause: str = "") -> None:
    """Structured coverage for one lane, emitted EVERY lifecycle so a later complete run clears a prior
    remainder, and split so that WHO stopped us stays visible."""
    kind = _unqueried_kind(balance, stop_cause)
    unq = len(outcome.unqueried)
    events.coverage_partial(lane, kind=kind, measure="shodan_pivots_unqueried",
                            unit=f"{lane}.unqueried", eligible=outcome.pivots,
                            tested=outcome.pivots - unq, omitted=unq,
                            reason=(f"{unq}/{outcome.pivots} pivot(s) never queried — "
                                    f"{getattr(balance, 'reason', '')}" if unq else
                                    f"all {outcome.pivots} pivot(s) queried"))
    # pages are counted ONLY where the total is known. A pivot we never bought a page for has no knowable
    # page count, and an invented denominator is the same class of lie as an unmeasured zero.
    done = outcome.pages_bought + outcome.pages_replayed
    # known pages left after a per-pivot FAILURE are a gap, not a provider limit: nothing about the
    # balance stopped those pages, something broke.
    pages_kind = events.COVERAGE_TIMEOUT if outcome.fail_classes else kind
    events.coverage_partial(lane, kind=pages_kind, measure="shodan_pages_left", unit=f"{lane}.pages_left",
                            eligible=done + outcome.pages_left_known, tested=done,
                            omitted=outcome.pages_left_known,
                            reason=(f"{outcome.pages_left_known} known page(s) unbought"
                                    + (f"; {outcome.pages_left_unknown_pivots} pivot(s) have an UNKNOWN "
                                       f"page count (not counted)"
                                       if outcome.pages_left_unknown_pivots else "")
                                    if outcome.pages_left_known or outcome.pages_left_unknown_pivots
                                    else "no known page left unbought"))
    # POSITION x CAUSE, four measures, each naming ONLY its own position's classes. A mid-flight
    # provider limit (quota on page N) is not the same event as a pivot the provider refused outright,
    # and a later-page transport failure is not our page budget. Without these the classes were counted
    # in LaneOutcome and emitted by nothing: a run stopped dead by quota folded as `complete`, because an
    # attempted pivot is not "unqueried" and a pivot with no total has no page remainder.
    #
    #   position   cause      kind                 verdict
    #   first      broke      COVERAGE_TIMEOUT     gap        (the target/network cost us the pivot)
    #   first      refused    COVERAGE_PROVIDER    soft limit (nothing to retry this run)
    #   later      broke      COVERAGE_TIMEOUT     gap
    #   later      refused    COVERAGE_PROVIDER    soft limit
    piv = max(1, outcome.pivots)
    for measure, unit, kind, classes, phrase in (
            ("shodan_pivots", "failed", events.COVERAGE_TIMEOUT, outcome.first_fail_classes,
             "fully failed by class"),
            ("shodan_pivots_limited", "provider_limit", events.COVERAGE_PROVIDER,
             outcome.first_limit_classes,
             "stopped by a PROVIDER LIMIT (not a defect; nothing to retry this run)"),
            ("shodan_results_failed", "later_failed", events.COVERAGE_TIMEOUT,
             outcome.later_fail_classes, "lost a LATER page to a failure (page-1 evidence KEPT)"),
            ("shodan_results_limited", "later_limit", events.COVERAGE_PROVIDER,
             outcome.later_limit_classes,
             "lost a LATER page to a PROVIDER LIMIT (page-1 evidence KEPT)")):
        n = min(sum(classes.values()), piv)
        events.coverage_partial(lane, kind=kind, measure=measure, unit=f"{lane}.{unit}", eligible=piv,
                                tested=piv - n, omitted=n,
                                reason=(f"{n}/{piv} pivot(s) {phrase} {dict(classes)}" if n
                                        else f"no pivot {phrase.split(' (')[0]}"))
    # PROVIDER DRIFT: Shodan's index is live, so two pages of one pivot can report different totals. We
    # keep the maximum, so nothing is omitted and the remainder is never understated.
    #
    # review-B1.4r2#4: this was emitted with `omitted=total_drift`, which made an otherwise complete,
    # unbounded scan fold as `complete_with_limits` because one total moved. Drift is TELEMETRY about the
    # provider's denominator, not a coverage boundary: it must be visible and must not touch the verdict.
    # `omitted=0` says exactly that, and the count lives in the reason where a reader can see it.
    drift_of = max(1, done)
    events.coverage_partial(lane, kind=events.COVERAGE_PROVIDER, measure="shodan_total_drift",
                            unit=f"{lane}.total_drift", eligible=drift_of, tested=drift_of, omitted=0,
                            reason=(f"{outcome.total_drift} of {done} page(s) reported a total that "
                                    f"disagreed with another page of the same pivot — the provider's "
                                    f"index moved; the LARGEST total is kept, so NOTHING is omitted"
                                    if outcome.total_drift
                                    else "every page agreed on its pivot's total"))
    # OUR page policy is a CAP, not a sample. review-B1 (Lumpy): "SHODAN_MAX_PAGES=1 is still a cap" —
    # a soft SAMPLE would let a run that never looked past page 1 call itself complete, which is exactly
    # the silent truncation the bounded-lane work exists to prevent. It is a hard ceiling WE imposed on
    # eligible input, so it reads as a gap whenever it withheld anything.
    events.coverage_partial(lane, kind=events.COVERAGE_CAP, measure="shodan_pages_withheld",
                            unit=f"{lane}.pages_withheld", eligible=done + outcome.pages_withheld,
                            tested=done, omitted=outcome.pages_withheld,
                            reason=(f"{outcome.pages_withheld} page(s) withheld by SHODAN_MAX_PAGES="
                                    f"{max_pages}" if outcome.pages_withheld
                                    else "no page withheld by an operator page policy"))
    # FAILURES are gaps — including the balance read itself, which may have failed while an operator
    # limit was the thing that stopped us. BOTH facts must survive to reconciliation.
    from .contract import is_provider_limit as _is_limit
    fails = sum(outcome.fail_classes.values()) + outcome.evidence_invalid + outcome.publish_failed
    read_err = getattr(balance, "read_error", None)
    # B1.4: a balance read REFUSED by the provider is a limit like any other. Counting every `read_error`
    # as a failure made a depleted account emit a gap from the balance probe while its pivots correctly
    # reported a limit — the exact conflation B0 exists to prevent, arriving through the one channel that
    # had not been classified. Surfaced by integrating the real lane, where /api-info fails the same way
    # the search does.
    read_limited = bool(read_err) and _is_limit(read_err)
    if read_err and not read_limited:
        fails += 1
    denom = max(1, outcome.pivots)
    events.coverage_partial(lane, kind=events.COVERAGE_TIMEOUT, measure="shodan_failures",
                            unit=f"{lane}.failed", eligible=denom,
                            tested=denom - min(fails, denom), omitted=min(fails, denom),
                            reason=(f"failures {dict(outcome.fail_classes)}"
                                    + (f", {outcome.evidence_invalid} unusable recorded page(s)"
                                       if outcome.evidence_invalid else "")
                                    + (f", {outcome.publish_failed} page(s) not durably recorded"
                                       if outcome.publish_failed else "")
                                    + (f", balance read failed ({read_err})"
                                       if read_err and not read_limited else "")
                                    if fails else
                                    (f"no failure (balance read stopped by a provider limit: {read_err})"
                                     if read_limited else "no failure")))
    events.coverage_partial(lane, kind=events.COVERAGE_TIMEOUT, measure="state_persisted",
                            unit=f"{lane}.state_persisted", eligible=1, tested=1 if persisted else 0,
                            omitted=0 if persisted else 1,
                            reason=("completion state persisted" if persisted else
                                    "completion state could NOT be persisted — paid pages will be "
                                    "bought again on the next run"))
