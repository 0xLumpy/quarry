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

import contextlib
import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import budget, events

#: v2: pages carry `bought_at` and live in a PROJECT-scoped store. A schema bump isolates the previous
#: generation rather than deleting it — paid evidence is never pruned automatically.
SHODAN_WORK_SCHEMA = 2
#: POLICY, not a measurement: how long a purchased search page may stand in for a fresh one. A Shodan
#: search result is LIVE intelligence — unlike a WHOIS record, which is why whoxy's cache is permanent
#: and this one is not. 7 days is a default chosen for the operator to change, and the effective value
#: travels with the evidence so a report never implies it was measured.
PAGE_TTL_DAYS_DEFAULT = 7
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
    #: pages this pivot OWNS but which are older than the TTL. Kept apart from `pages_done` because they
    #: are not current evidence — and apart from "missing", because they were paid for and must never be
    #: silently re-bought.
    aged_pages: set = field(default_factory=set)
    #: pages we own on paper and cannot prove. Skipped by `next_page` for the same reason aged pages are:
    #: scheduling one means buying it, and this run has no authority to repair paid evidence.
    lost_pages: set = field(default_factory=set)
    attempted: bool = False                 # a request was ISSUED for this pivot (a credit was spent)
    cardinality: "int | None" = None      # /host/count sizing, held SEPARATELY from `total` so neither
                                          # can contaminate the other (review-B1.5r1#1)
    count_compared: bool = False          # the count has met page evidence at least once
    count_drifted: bool = False            # ...and the CURRENT verdict of that comparison
    stopped: str = ""                       # a class that ended this pivot early (limit or failure)
    _cursor: int = 1                        # lowest page not known-complete; never rescans the prefix

    def effective_total(self) -> "int | None":
        """What we currently believe the pivot holds, for SCHEDULING only.

        review-B1.5r1#1: sizing used to be written INTO `total`, which corrupted the page-derived value
        every later comparison depends on — two pages that agreed on 100 reported drift because a count
        of 500 had overwritten one of them, and a count that disagreed with a fresh page reported none
        because it had already become that page's baseline. `total` stays PURELY page-derived; the count
        is a second, separately-held observation, and only their MAXIMUM decides how much to schedule.

        None while no page has proved a total: a count alone may order a pivot, never size it."""
        if self.total is None:
            return None
        return max(self.total, self.cardinality) if self.cardinality is not None else self.total

    def page_count(self) -> "int | None":
        """How many pages this pivot HAS, or None while unknown.

        An unqueried pivot has NO knowable page count, and inventing one would fabricate a denominator.
        `None` is the honest answer and the caller must not sum it into anything."""
        total = self.effective_total()
        if total is None:
            return None
        return max(1, -(-total // SHODAN_PAGE_SIZE))         # ceil division

    def next_page(self, max_pages: int = 0) -> "int | None":
        """The lowest page still owed, or None. `max_pages` 0 = unbounded (operator policy only).

        review#6: this scanned from page 1 on EVERY round, so a 100k-page pivot performed billions of set
        lookups across a run — quadratic work behind a docstring claiming laziness. The cursor is
        monotonic, so the completed prefix is walked once in total."""
        if self.stopped:
            return None
        # an AGED page is skipped, never scheduled: it is already paid for, and buying it again merely
        # because time passed is a spend the operator did not ask for. The refusal is counted, not hidden.
        while (self._cursor in self.pages_done or self._cursor in self.aged_pages
               or self._cursor in self.lost_pages):
            self._cursor += 1
        pages = self.page_count()
        if pages is None:
            return self._cursor if self._cursor == 1 else None
        limit = pages if not max_pages else min(pages, max_pages)
        return self._cursor if self._cursor <= limit else None

    def refused_refresh(self, max_pages: int = 0) -> int:
        """Aged pages this pivot would otherwise have asked for. Each one is a purchase the run DECLINED
        to make on its own: refreshing paid evidence is an explicit operator decision, and `--unbound`
        is not that decision — it never authorises spending."""
        if not self.aged_pages:
            return 0
        pages = self.page_count()
        limit = pages if pages is not None else max(self.aged_pages)
        if max_pages:
            limit = min(limit, max_pages)
        return sum(1 for p in self.aged_pages if p <= limit)

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


def count_key(pivot: Pivot) -> str:
    """Identity of a pivot's /host/count evidence. A DISTINCT namespace from `item_key`, so count
    evidence can never be mistaken for a purchased page (nor collide with page 0 of anything)."""
    raw = f"{SHODAN_WORK_SCHEMA}|{pivot.lane}|{pivot.facet}|{pivot.value}|count"
    return hashlib.sha256(raw.encode()).hexdigest()


def item_key(pivot: Pivot, page: int) -> str:
    """The per-PAGE completion identity: (schema, lane, facet, value, page).

    The RESERVE is deliberately absent. It governs planning, not results — a page bought under reserve 10
    is byte-identical to one bought under reserve 0, so folding the reserve in would make lowering it
    RE-PAY for pages already purchased. (The opposite of the A1/A2 rule, where a coverage-config change
    genuinely invalidates the artifact.)"""
    raw = f"{SHODAN_WORK_SCHEMA}|{pivot.lane}|{pivot.facet}|{pivot.value}|p{page}"
    return hashlib.sha256(raw.encode()).hexdigest()


def provider_dir(project_dir) -> Path:
    """`<project>/state/shodan-pivot` — the PROVIDER level, above the schema generation."""
    return Path(project_dir) / "state" / "shodan-pivot"


def state_dir(project_dir) -> Path:
    """The DURABLE home for purchased pivot pages: `<project>/state/shodan-pivot/v<schema>/`.

    A run directory is timestamped, so state kept inside one dies with it and the NEXT run buys the same
    pages again — measured in code before this change: the ledger lived under `ctx.run.dir/raw/probe`,
    replay read only that ledger, and nothing project-scoped carried ownership. Two separate `quarry run`
    invocations therefore paid twice for identical pages; a campaign only avoided it by closing
    acquisition after child 1, which is not replay, it is not acquiring at all.

    The ledger and the page artifacts live under the SAME directory because `Ledger.record` stores paths
    relative to its own parent — an artifact outside that tree cannot be owned at all.

    The generation is the WORK SCHEMA and nothing else: not the API key (a page's bytes do not depend on
    which credential paid for it), not the page budget or the reserve (folding those in would make
    lowering a spending policy re-buy pages already paid for). Durability is NOT permanence — a Shodan
    search page is live intelligence, so `PAGE_TTL_DAYS_DEFAULT` decides how long it may stand in for a
    fresh one, and an aged page is kept as history rather than replayed as current.
    """
    return provider_dir(project_dir) / f"v{SHODAN_WORK_SCHEMA}"


class StoreBusy(RuntimeError):
    """Another lifecycle holds this project's purchased-page store. CONTENTION ONLY."""


@contextlib.contextmanager
def lifecycle_lock(project_dir):
    """Exclusive, ADVISORY, OS-RELEASED lock over a project's purchased Shodan pages.

    Without it two runs of the same project load the same snapshot, both see a page as unowned, and both
    spend a credit for identical bytes — then race while journaling and compacting, which is how
    ownership is lost outright. The store only became shareable when it became project-scoped, so the
    lock arrives with it.

    Held across LOAD, REPLAY, PURCHASE, RECORD and SAVE. Contention raises `StoreBusy` BEFORE any of
    that, so a blocked run issues zero paid requests — it refuses acquisition rather than waiting, and
    waiting for a lock is not a spending policy.

    At the PROVIDER level, above the schema generation: two builds on different schemas still share one
    account and must not spend at once (the whoxy precedent, review-B1.6b2#1).

    `flock`, not lockfile existence: a stale file from a killed run would block the project for ever,
    while an flock is released by the kernel when the holder dies, however it dies.

    NOT the account-wide spending lock. Credits are account-wide, so two runs in DIFFERENT projects can
    still each spend toward the same reserve — whoxy solves that with a second, installation-wide
    `spend_lock`, and this lane owes the same (filed, not built here).
    """
    base = provider_dir(project_dir)
    base.mkdir(parents=True, exist_ok=True)
    with contextlib.ExitStack() as stack:
        try:
            stack.enter_context(budget.state_lock(base / ".lock"))
        except budget.StateBusy as e:
            raise StoreBusy(str(e)) from e
        # ONLY the acquisition is translated. Wrapping the body too meant a `StateBusy` raised INSIDE —
        # another lane's ledger, a nested lifecycle — came back out as this lock's contention, and the
        # caller then reported "another run holds this project's store" about a lock it was holding
        # itself (the whoxy precedent, review-B-audit-7#7).
        yield base


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


#: B1.7: one definition, in `budget`, where the Ledger is. This module and `whoxy_page` had identical
#: copies and the host lane needed a third.
ledger_writable = budget.ledger_writable


#: B1.6: the identical probe is now `budget.store_writable` — the Whoxy paginator needs the same one,
#: and the contract is the same. Re-exported so this module's readers still find it where it was.
store_writable = budget.store_writable



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


def _card_key(st: "PivotState"):
    """Ordering position for a pivot's cardinality.

    UNKNOWN sorts after KNOWN inside its page tier. Rare-first exists to reach the most distinct pivots
    per credit, and an unsized pivot could be a five-million-result generic — spending ahead of a proven
    rare one contradicts the policy. It is a position, never an exclusion: the pivot stays eligible, is
    re-sized every lifecycle, and whatever a budget does not reach is a counted, resumable remainder."""
    return (0, st.cardinality) if st.cardinality is not None else (1, 0)


def schedule(states: "list[PivotState]", *, max_pages: int = 0) -> list:
    """The next round of work: at most one page per pivot, ordered PAGE TIER first and fair across lanes
    inside a tier.

    Fairness is computed over PENDING work only — ordering the whole set would interleave completed
    history and push a lane's real remainder behind another lane's finished pages (the A1 lesson)."""
    pending = [(st, st.next_page(max_pages)) for st in states]
    pending = [(st, pg) for st, pg in pending if pg is not None]
    # B1.5: cardinality orders WITHIN a lane, and must not become part of the rank TIER. `order_ranked_fair`
    # buckets by rank and round-robins across lanes inside a bucket, so a rank of (page, cardinality) would
    # give almost every pivot its own tier and collapse cross-lane fairness into a global cardinality sort.
    # Pre-sorting instead keeps the tier on PAGE alone, and `order_fairly` preserves this order inside each
    # lane — so: page one everywhere, lanes alternating, rarest first within a lane.
    pending.sort(key=lambda it: (it[1], _card_key(it[0]), it[0].pivot.value))
    return budget.order_ranked_fair(pending, rank=lambda it: it[1],
                                    group=lambda it: it[0].pivot.lane)


@dataclass
class LaneOutcome:
    """Per-lane facts the caller turns into its own terminal and coverage."""

    lane: str
    pivots: int = 0
    pivots_touched: int = 0                 # at least one page bought or replayed
    pages_bought: int = 0
    #: pages this project ALREADY PAID FOR whose stored artifact can no longer be proven (deleted,
    #: altered, or filed without a digest). The completion is dropped by the ledger and the evidence is
    #: genuinely gone — but it is NOT bought again: an evidence loss is not a spending permission.
    pages_lost: int = 0
    #: a lost page the pivot would otherwise have asked for, that this run declined to re-buy. Sibling of
    #: `refresh_refused`: repairing paid evidence is an explicit operator decision Quarry cannot make for
    #: itself, and `--unbound` is not that decision — it never authorises spending.
    repair_refused: int = 0
    pages_replayed: int = 0                 # replayed FRESH: inside the TTL, used as current evidence
    #: owned, but older than the TTL. The artifact is KEPT and reported as historical evidence; it is not
    #: ingested as a current result, and it is never re-bought merely because time passed.
    pages_aged: int = 0
    #: an aged page whose pivot then wanted it: purchasing it again is an explicit operator decision, so
    #: the run records the refusal instead of spending
    refresh_refused: int = 0
    #: the oldest replayed page's age, so a report can say "current, 2 days old" rather than "current"
    oldest_replay_s: float = 0.0
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
    count_compared: int = 0                 # pivots whose count met a page-derived total
    count_drift: int = 0                    # ...and disagreed with it
    evidence_invalid: int = 0               # recorded pages whose artifact did not validate
    publish_failed: int = 0                 # bought pages we could not durably record
    # review-B1.7a: OWNERSHIP is not CONSUMPTION. A page whose `ingest` raised is bought and journaled —
    # it stays owned, or the scheduler would offer it again and pay for it twice — but its matches never
    # reached the store, and the page remainder cannot express that.
    pages_unconsumed: int = 0
    # review-B1.7a#2: LANE-LOCAL machinery failures. Ingesting a page is one lane's work on one lane's
    # pivot, and filing it globally turned a completed sibling lane PARTIAL — cert with every page bought
    # and stored reported degraded because favicon's ingest raised. Genuinely shared failures (the ledger
    # save, remainder accounting) stay on `WorkResult`, because they really are everyone's.
    machinery: list = field(default_factory=list)


@dataclass
class WorkResult:
    lanes: dict = field(default_factory=dict)
    persisted: bool = True                  # completion state actually reached disk
    records_journaled: bool = True          # every completion recorded THIS RUN reported success
    stop_cause: str = ""                    # WHY scheduling ended — the scheduler's own answer, which
                                            # the balance alone cannot give (it does not know whether we
                                            # ran out mid-flight, hit the reserve, or lost the store)
    # review-B1.7a: every failure of OUR OWN machinery, in order. `stop_cause` keeps the FIRST cause,
    # because a later failure is its consequence; the rest would otherwise vanish entirely.
    machinery: list = field(default_factory=list)


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
    # a total has just become known, so this is the moment a count can be measured against it — RETAINED
    # or FRESH, one call site, no path left to forget (review-B1.5r1#1).
    compare_count(st, o)


def _page_doc(pivot: Pivot, page: int, total, matches, *, bought_at=None) -> dict:
    """The page as stored. `bought_at` rides INSIDE the document on purpose: it is content-addressed and
    digest-verified, so the purchase time is bound to the evidence by the same hash that proves ownership
    — a sidecar could drift from the page it describes."""
    return {"schema": SHODAN_WORK_SCHEMA, "lane": pivot.lane, "facet": pivot.facet,
            "value": pivot.value, "page": page, "total": total, "matches": matches,
            "bought_at": float(time.time() if bought_at is None else bought_at)}


#: tolerance for ordinary clock skew between the machine that bought a page and the one reading it.
#: Beyond this a "bought in the future" timestamp is not skew, it is a page that cannot prove its age.
CLOCK_SKEW_S = 300.0


def page_age_s(doc, *, now=None) -> float | None:
    """How old a stored page is, or None when it cannot say.

    An unreadable age is NEVER treated as fresh: the caller ages it out, because a page that cannot prove
    when it was bought cannot prove it is current. That includes a NaN or infinite timestamp (which
    arithmetic would otherwise collapse into a plausible number) and one dated in the FUTURE beyond
    ordinary clock skew — clamping those to "age zero" made an impossible timestamp certify freshness.
    """
    at = doc.get("bought_at") if isinstance(doc, dict) else None
    if isinstance(at, bool) or not isinstance(at, (int, float)):
        return None
    at = float(at)
    if at != at or at in (float("inf"), float("-inf")):
        return None
    ref = float(now if now is not None else time.time())
    age = ref - at
    if age < -CLOCK_SKEW_S:
        return None                    # dated in the future: not skew, not provable
    return max(0.0, age)


def page_fresh(doc, *, ttl_days: float, now=None) -> bool:
    """Whether a stored page may stand in for a fresh purchase.

    `ttl_days <= 0` means NEVER REPLAY: every owned page is treated as aged, so it is retained as history
    and its refresh is REFUSED. It does not mean "always buy" — nothing here spends, and the scheduler
    skips an aged page precisely so that time passing can never authorise a purchase.
    """
    age = page_age_s(doc, now=now)
    if age is None or ttl_days <= 0:
        return False
    return age <= ttl_days * 86400.0


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


def valid_total(total) -> bool:
    """An EXACT non-negative integer. `bool` is excluded deliberately — it is an int subclass, so `True`
    would otherwise pass as the total 1. Shared by page evidence and /host/count sizing so the two can
    never disagree about what a total is."""
    return not isinstance(total, bool) and isinstance(total, int) and total >= 0


def valid_fresh(matches, total) -> bool:
    """Whether a page may be treated as complete — the ONE contract for fresh output and replayed
    evidence alike, since `valid_page` delegates here.

    review-r2#2: replayed evidence was validated and FRESH output was not, so the coordinator trusted the
    network more than its own disk. `([], None, None)` recorded a "complete" page whose total was unknown
    — owning a page while being unable to enumerate the rest of them.

    review-B1.5br3#1: the ROWS were not checked at all, only that `matches` is a list. The adapter had
    just been taught to reject a non-string hostname member, but a page PAID FOR AND RECORDED before that
    contract existed replayed straight past it and crashed the ingest that trusted it. Validating here
    rather than bumping SHODAN_WORK_SCHEMA is deliberate: a bump invalidates every page already bought,
    including the valid ones, and would have us re-pay for them. A malformed old page simply stops being
    owned, so it is repurchased on its own."""
    if not valid_total(total):
        return False
    if not isinstance(matches, list):
        return False
    for m in matches:
        if not isinstance(m, dict):                       # a null/scalar row is corruption, not empty
            return False
        hns = m.get("hostnames")
        if hns is None:
            continue
        if not isinstance(hns, list) or any(not isinstance(h, str) for h in hns):
            return False
    return True


def _read_page(path, pivot: Pivot, page: int):
    try:
        doc = json.loads(path.read_text())
    except Exception:
        return None
    return valid_page(doc, pivot, page)


def run_work(ctx, *, states, balance, search, ingest, ledger, attempt_dir,
             max_pages: int = 0, is_limit=None, should_stop=None,
             ttl_days: float = PAGE_TTL_DAYS_DEFAULT) -> WorkResult:
    """Buy pages under the balance, replaying anything already owned.

    `search(pivot, page) -> (matches, total, error)` and `ingest(pivot, page, matches, raw_path) -> int`
    are injected. `balance` is the settled B1.2 contract: `may_spend` decides whether ANY credit may be
    spent, `spendable` (None = no computable bound) decides how many."""
    from .contract import is_provider_limit as _default_is_limit
    is_limit = is_limit or _default_is_limit
    # review-B1.5r4#1: "stop requesting" and "soft limit" are DIFFERENT questions, and answering the
    # first by lying about the second put the run's own taxonomy at odds with itself. `should_stop` ends
    # purchasing without touching classification: the class stays whatever it is, and a failure stays a
    # gap. Only `is_limit` decides softness.
    should_stop = should_stop or (lambda cls: False)
    states = dedupe(states)
    res = WorkResult()
    for st in states:
        o = res.lanes.setdefault(st.pivot.lane, LaneOutcome(lane=st.pivot.lane))
        o.pivots += 1
    try:
        try:
            _replay_indexed(states, res, ledger=ledger, ingest=ingest, ttl_days=ttl_days)
            _apply_cardinality(states, res)
            for st in states:                      # what aging DECLINED to buy, per lane
                res.lanes[st.pivot.lane].refresh_refused += st.refused_refresh(max_pages)
            try:
                _work(states, res, balance=balance, search=search, ingest=ingest, ledger=ledger,
                      attempt_dir=attempt_dir, max_pages=max_pages, is_limit=is_limit,
                      should_stop=should_stop)
            except LaneMachineryError as e:
                # review-B1.7a#6: a bought page one lane could not ingest ends PURCHASING — which the
                # stop cause already says — but it must not skip the FREE sweep of pages other lanes
                # already own and paid for.
                _machinery(res, e)
            _sweep_owned(states, res, ledger=ledger, ingest=ingest, max_pages=max_pages)
        except (KeyboardInterrupt, SystemExit):
            raise                      # cancellation ends the run; it is not an outcome
        except Exception as e:
            # review-B1.7a: an exception ANYWHERE here escaped the coordinator, and the caller reported
            # zero pivots attempted over pages it had already replayed and bought. Everything the run
            # established is a fact whatever happened next.
            _machinery(res, e)
    finally:
        # accounting for whatever the pivots DID reach, however this run ended. It runs in `finally` so a
        # machinery failure above still reports its remainder, and it is a SNAPSHOT (see `_remainder`),
        # so running it after a partial failure cannot double-count.
        try:
            _remainder(states, res, max_pages=max_pages)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            _machinery(res, e)
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
        # review-B1.7a: `save()` sat outside the boundary too — a store that RAISED discarded every page
        # the run had bought. A save that raises did not save.
        try:
            saved = bool(ledger.save())
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            saved = False
            _machinery(res, e)
        if saved:
            res.persisted = True               # the snapshot IS the durable answer; nothing else to ask
        else:
            # `durable` is the FALLBACK for a snapshot that did not land. Reading it unconditionally
            # would let a ledger that saved cleanly and then raised here report a false machinery gap.
            try:
                durable = bool(getattr(ledger, "durable", False))
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                durable = False                # a store that cannot even answer is not a durable one
                _machinery(res, e)
            res.persisted = durable and res.records_journaled
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
    try:
        o.matches += ingest(st.pivot, page, doc.get("matches") or [], art)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:
        # the page stays OWNED (dropping it from `pages_done` would have the scheduler sell it to us
        # again) and the shortfall is counted in its own unit — see `LaneOutcome.pages_unconsumed`.
        _lane_machinery(o, e)                  # raises the lane-scoped carrier
    return True


class LaneMachineryError(Exception):
    """An ingestion failure ALREADY attributed to the lane whose page it was.

    review-B1.7a#5: attribution used to be a flag set ON the original exception, so an exception that
    rejects attributes — a `__slots__` class, an overridden `__setattr__` — silently fell back to being
    filed against every lane, and a completed sibling went partial again. Scope is now carried
    STRUCTURALLY by the exception type the boundary receives, which nothing about the ingest callback can
    influence. The original is the `__cause__` and keeps its own type and message."""

    def __init__(self, lane: str, cause: BaseException):
        super().__init__(f"{lane}: {type(cause).__name__}: {cause}")
        self.lane = lane
        self.__cause__ = cause


def _lane_machinery(o, e: BaseException):
    """Attribute an ingestion failure to the lane whose page it was, then RAISE the scoped carrier."""
    o.pages_unconsumed += 1
    o.machinery.append(f"{type(e).__name__}: {e}")
    raise LaneMachineryError(o.lane, e) from e


def _machinery(res, e: BaseException) -> None:
    """Record OUR OWN failure without discarding what the run already established.

    review-B1.7a: ported from `whoxy_page`, where this cost five review rounds. A boundary that only
    stops the crash is not a boundary — the caller fabricates zero accounting over evidence the run is
    holding. The FIRST failure names the stop; a later one is its consequence."""
    lane_scoped = isinstance(e, LaneMachineryError)
    # the CAUSE names the stop either way: `machinery:RuntimeError` says what actually broke, where the
    # carrier's own type would say only that we wrapped it.
    cause = e.__cause__ if lane_scoped and e.__cause__ is not None else e
    if not lane_scoped:
        # a lane-scoped fault is already filed against the lane that owns the work — see
        # `LaneOutcome.machinery`. The STOP is still global (purchasing ends for everyone), the FAULT is not.
        res.machinery.append(f"{type(cause).__name__}: {cause}")
    res.stop_cause = res.stop_cause or f"machinery:{type(cause).__name__}"


def _replay_lane_safe(states, res, replay_one) -> None:
    """Run `replay_one(st, o)` over every state, keeping ONE LANE's ingestion failure from ending the
    others' free replay.

    review-B1.7a#6: the carrier fixed ATTRIBUTION and not control flow — it propagated out of the whole
    replay pass, so a favicon store failure meant an already-owned cert page was never replayed at all
    and cert reported FAILED with its store callback never called. Replay is FREE and per-lane: the
    failing lane stops (its sink is broken; the next page would fail identically), purchasing stops
    globally via `stop_cause`, and every other lane replays exactly what it owns."""
    # review-B1.7a#8: a fresh set per PASS meant indexed replay and the sweep forgot each other, so a
    # lane whose sink had already failed was tried again the moment the next pass began — two unconsumed
    # pages and the same reason twice. A lane's own recorded machinery IS the lifecycle-wide answer to
    # "is this sink broken", and it covers a fault recorded on the paid path too.
    broken = {lane for lane, o in res.lanes.items() if o.machinery}
    for st in states:
        lane = st.pivot.lane
        if lane in broken:
            continue
        o = res.lanes[lane]
        try:
            replay_one(st, o)
        except LaneMachineryError as e:
            broken.add(e.lane)
            _machinery(res, e)                 # the lane keeps the fault; the STOP is global


def _replay_indexed(states, res, *, ledger, ingest, ttl_days: float = PAGE_TTL_DAYS_DEFAULT,
                    now=None) -> None:
    """Replay every page we demonstrably own, BEFORE any scheduling.

    review-r3#3: purchased evidence must replay whether or not an earlier hole is repaired this
    lifecycle. Sequential discovery meant a failed page-1 repair set `stopped`, which removed the pivot
    from scheduling, which hid an owned page 2 that had already been paid for.

    review-B1.3r5#1: the ledger is enumerated ONCE for the whole run rather than probed per pivot."""
    index = owned_index(ledger)

    def one(st, o):
        for page, art, doc in index.get((st.pivot.lane, st.pivot.facet, st.pivot.value), ()):
            if page in st.pages_done:
                continue
            if not page_fresh(doc, ttl_days=ttl_days, now=now):
                # AGED, not gone: a Shodan search page is live intelligence, so replaying a stale one as
                # a current result would be the "eternal cache" the free-host lane warns about. The
                # artifact stays owned and reportable as history; it just does not stand in for today.
                o.pages_aged += 1
                st.aged_pages.add(page)
                continue
            age = page_age_s(doc, now=now) or 0.0
            o.oldest_replay_s = max(o.oldest_replay_s, age)
            _replay_one(st, o, page=page, ledger=ledger, ingest=ingest, owned=(art, doc))

    _replay_lane_safe(states, res, one)


def compare_count(st, o) -> None:
    """Measure a pivot's count against its page-derived total, and keep that verdict CURRENT.

    Only meaningful once a page has proved a total, and the count is compared whether that page was
    RETAINED or FRESH — review-B1.5r1#1: comparing at one of those two moments only reported drift for
    whichever happened to come first.

    review-B1.5r2#2: "once per pivot" is the OUTCOME rule, not "only look at its first page". Freezing
    after the first comparison froze the verdict against page 1 while `total` was still being reconciled
    max-wins — retained totals of 100 then 500 called a count of 500 drift, and a count of 100 agreement.
    Each pivot is still counted once in `count_compared`; its drift fact is REVISED as evidence
    accumulates, so the run reports the comparison against the total it actually ended up with."""
    if st.cardinality is None or st.total is None:
        return
    drift = st.cardinality != st.total
    if not st.count_compared:
        st.count_compared = True
        st.count_drifted = drift
        o.count_compared += 1
        o.count_drift += 1 if drift else 0
        return
    if drift != st.count_drifted:                 # a later page revised the baseline
        st.count_drifted = drift
        o.count_drift += 1 if drift else -1


def _apply_cardinality(states, res) -> None:
    """Fold /host/count sizing into what we know, AFTER replay and BEFORE scheduling.

    Two rules, and the boundary between them is the whole design:

      · NO page-derived total  -> the count orders the pivot and NOTHING else. Letting it size the pivot
        would give an unqueried one a page count, so it would report as `unqueried` AND as "N pages
        left" — a phantom remainder over a denominator no page ever proved.
      · A page-derived total   -> `effective_total` takes the MAXIMUM of the two, which is how a pivot
        that was complete under yesterday's total discovers that new results exist instead of treating
        an old completion as permanent. Neither value is overwritten by the other.

    Runs before `_work`, so growth found here is bought in the SAME lifecycle rather than next time."""
    for st in states:
        compare_count(st, res.lanes[st.pivot.lane])


def _work(states, res, *, balance, search, ingest, ledger, attempt_dir, max_pages, is_limit,
          should_stop=None) -> None:
    should_stop = should_stop or (lambda cls: False)
    # An ownership index that EXISTS and cannot be trusted is not an empty one. Reading it as empty makes
    # a corrupt file into permission to buy every page again — the same laundering route as a lost
    # artifact, one level up (review#1, Lumpy). Nothing is bought until an operator resolves it; replay
    # has already taken whatever could still be proven.
    unreadable = getattr(ledger, "unreadable", "")
    if unreadable:
        res.stop_cause = res.stop_cause or f"ownership_unreadable:{unreadable}"
        return
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
            # a page this project ALREADY PAID FOR whose artifact no longer verifies. The evidence is
            # gone, but "gone" is not an authorisation: buying it again is a fresh charge, and reporting
            # a surprise charge afterwards does not authorise it (review#1, Lumpy). It is refused on
            # exactly the terms an AGED page is — the loss is admitted, the pivot moves on, and repair
            # waits for an explicit operator refresh/repair policy that does not exist yet.
            if item_key(st.pivot, page) in getattr(ledger, "lost", {}):
                o.pages_lost += 1
                o.repair_refused += 1
                st.lost_pages.add(page)
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
                elif should_stop(cls):
                    # a FAILURE that further requests cannot get past — a refused credential, a provider
                    # we keep being throttled by. Purchasing ends; the class is untouched, so this reads
                    # as the gap it is and the remainder is counted like any other.
                    res.stop_cause = f"provider_stop:{cls}"
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
            try:
                o.matches += ingest(st.pivot, page, matches, raw)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                # the credit is spent and the page is owned; its rows are not. Raises the carrier.
                _lane_machinery(o, e)
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
    def one(st, o):
        pages = st.page_count()
        if pages is None:
            return
        for page in range(max_pages + 1, pages + 1):
            if page in st.pages_done:
                continue
            _replay_one(st, o, page=page, ledger=ledger, ingest=ingest)

    _replay_lane_safe(states, res, one)          # the same per-lane rule: owned evidence is FREE


def _remainder(states, res, *, max_pages) -> None:
    # a SNAPSHOT of the states, not an accumulator: it is reachable twice (once normally, once after a
    # machinery failure), and `+=` over a list that already held the first pass would report a remainder
    # twice the size of the real one.
    for o in res.lanes.values():
        o.unqueried = []
        o.pages_left_known = 0
        o.pages_left_unknown_pivots = 0
        o.pages_withheld = 0
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
        # provider_stop:* is a FAILURE we stopped requesting through — a gap, never a soft limit.
        # publish_failed / ledger_unwritable / scheduler_invariant / ownership_unreadable — all OURS,
        # all defects
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
    # review-B1.5r5#1: the reason always quoted the BALANCE, so a lane left unqueried because another
    # lane's credential was refused explained itself with a perfectly healthy credit balance. The
    # scheduler's own answer comes first; the balance is the fallback for stops it settled beforehand.
    why = stop_cause or getattr(balance, "reason", "")
    events.coverage_partial(lane, kind=kind, measure="shodan_pivots_unqueried",
                            unit=f"{lane}.unqueried", eligible=outcome.pivots,
                            tested=outcome.pivots - unq, omitted=unq,
                            reason=(f"{unq}/{outcome.pivots} pivot(s) never queried — {why}" if unq else
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
    # review-B1.7a: an OWNED page whose ingestion failed is out of the page remainder — nothing else in
    # this report can say its rows are missing. Emitted every lifecycle so a later clean run clears it.
    unc = outcome.pages_unconsumed
    events.coverage_partial(lane, kind=events.COVERAGE_TIMEOUT, measure="shodan_pages_unconsumed",
                            unit=f"{lane}.pages_unconsumed", eligible=done, tested=done - unc,
                            omitted=unc,
                            reason=(f"{unc}/{done} owned page(s) could not be ingested — their rows are "
                                    f"NOT in the store" if unc else
                                    f"every one of {done} owned page(s) was ingested"))
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
    # review-B1.5r5#2: a credential refused by the FREE count endpoint is a failure of this run's ability
    # to work at all. It is not a balance-read error (that read succeeded), so it needed its own term —
    # without it `shodan_failures` said "no failure" about a run stopped by a rejected key.
    count_refused = getattr(balance, "count_refused", None)
    if count_refused:
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
                                    + (f", /host/count refused the credential ({count_refused})"
                                       if count_refused else "")
                                    if fails else
                                    (f"no failure (balance read stopped by a provider limit: {read_err})"
                                     if read_limited else "no failure")))
    events.coverage_partial(lane, kind=events.COVERAGE_TIMEOUT, measure="state_persisted",
                            unit=f"{lane}.state_persisted", eligible=1, tested=1 if persisted else 0,
                            omitted=0 if persisted else 1,
                            reason=("completion state persisted" if persisted else
                                    "completion state could NOT be persisted — paid pages will be "
                                    "bought again on the next run"))
