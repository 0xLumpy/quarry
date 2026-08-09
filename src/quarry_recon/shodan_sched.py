"""The Shodan work coordinator.

One credit buys one search PAGE, so the unit of work is `(lane, facet, value, page)` and the credit
balance is a schedule, not an afterthought. Two facts force the shape:

  · a shared counter is NOT cross-lane fairness. `probe.favicon` and `probe.cert` are separate calls, so
    whichever runs first drains the balance whatever counter it consults. BOTH lanes' work is collected
    before any credit is spent.
  · a page cap is a cap in its own right, so it bounds purchasing only — never what we replay or report.

Scheduling is BREADTH FIRST by page number, with cross-lane fairness inside each tier. The page must be
the OUTER rank: grouping by lane looks fair on a clean start and breaks on resume, where a pivot already
holding pages 1-2 takes page 3 before an untouched pivot gets its first.

This owns scheduling, purchase, evidence, durability and coverage. It does NOT own ingestion or HTTP:
both are injected, so a lane keeps its own entity semantics and the tests are hermetic by construction.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import budget, events, pace

#: v2: pages carry `bought_at` and live in a PROJECT-scoped store. A schema bump isolates the previous
#: generation rather than deleting it — paid evidence is never pruned automatically.
SHODAN_WORK_SCHEMA = 2
#: POLICY, not a measurement: how long a purchased page may stand in for a fresh one. A search result
#: is live intelligence, unlike a WHOIS record. The effective value travels with the evidence, so a
#: report never implies it was measured.
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
    #: owned pages older than the TTL. Apart from `pages_done` because they are not current evidence, and
    #: apart from "missing" because they were paid for and must never be silently re-bought.
    aged_pages: set = field(default_factory=set)
    #: pages we own on paper and cannot prove. Skipped by `next_page` for the same reason aged pages are:
    #: scheduling one means buying it, and this run has no authority to repair paid evidence.
    lost_pages: set = field(default_factory=set)
    attempted: bool = False                 # a request was ISSUED for this pivot (a credit was spent)
    cardinality: "int | None" = None      # /host/count sizing, held SEPARATELY from `total` so neither
                                          # contaminates the other
    count_compared: bool = False          # the count has met page evidence at least once
    count_drifted: bool = False            # ...and the CURRENT verdict of that comparison
    stopped: str = ""                       # a class that ended this pivot early (limit or failure)
    _cursor: int = 1                        # lowest page not known-complete; never rescans the prefix

    def effective_total(self) -> "int | None":
        """What we currently believe the pivot holds, for SCHEDULING only.

        `total` stays purely page-derived; the count is a separate observation, and only their MAXIMUM
        decides how much to schedule. Writing sizing into `total` corrupts every later drift comparison.

        None while no page has proved a total: a count alone may order a pivot, never size it."""
        if self.total is None:
            return None
        return max(self.total, self.cardinality) if self.cardinality is not None else self.total

    def page_count(self) -> "int | None":
        """How many pages this pivot HAS, or None while unknown.

        An unqueried pivot has no knowable page count, and inventing one fabricates a denominator. The
        caller must not sum None into anything."""
        total = self.effective_total()
        if total is None:
            return None
        return max(1, -(-total // SHODAN_PAGE_SIZE))         # ceil division

    def next_page(self, max_pages: int = 0) -> "int | None":
        """The lowest page still owed, or None. `max_pages` 0 = unbounded (operator policy only).

        The cursor is monotonic, so the completed prefix is walked once in total rather than rescanned
        from page 1 every round."""
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
        """Pages this pivot has, that a page policy keeps us from buying, and that we do NOT
        already own.

        Ignoring `pages_done` reports owned evidence as withheld — complete coverage presented as a limit."""
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
    """The per-page completion identity: (schema, lane, facet, value, page).

    The RESERVE is absent: it governs planning, not results, so folding it in would re-pay for pages
    already bought when an operator lowers it."""
    raw = f"{SHODAN_WORK_SCHEMA}|{pivot.lane}|{pivot.facet}|{pivot.value}|p{page}"
    return hashlib.sha256(raw.encode()).hexdigest()


def provider_dir(project_dir) -> Path:
    """`<project>/state/shodan-pivot` — the PROVIDER level, above the schema generation."""
    return Path(project_dir) / "state" / "shodan-pivot"


def state_dir(project_dir) -> Path:
    """The durable home for purchased pivot pages: `<project>/state/shodan-pivot/v<schema>/`.

    Project-scoped, not run-scoped: state kept inside a timestamped run directory dies with it and the
    next run buys the same pages again. The ledger and the artifacts share this directory because
    `Ledger.record` stores paths relative to its own parent.

    The generation is the WORK SCHEMA only — not the key, the budget or the reserve. Folding a spending
    control in would re-buy paid pages. A schema change isolates old pages rather than deleting them."""
    return provider_dir(project_dir) / f"v{SHODAN_WORK_SCHEMA}"


class StoreBusy(RuntimeError):
    """Another lifecycle holds this project's purchased-page store. CONTENTION ONLY."""


@contextlib.contextmanager
def lifecycle_lock(project_dir):
    """Exclusive, advisory, OS-released lock over a project's purchased Shodan pages.

    Without it two runs load the same snapshot, both see a page as unowned, both spend for identical
    bytes, then race while journaling and compacting — which is how ownership is lost outright.

    Held across load, replay, purchase, record and save. Contention raises `StoreBusy` BEFORE any of
    that, so a blocked run issues zero paid requests: waiting for a lock is not a spending policy.

    At the PROVIDER level, above the schema generation — two builds on different schemas still share one
    account. `flock`, not lockfile existence: the kernel releases it however the holder dies, and the
    file is never unlinked, or a second process would lock a path the first no longer shares."""
    base = provider_dir(project_dir)
    base.mkdir(parents=True, exist_ok=True)
    with contextlib.ExitStack() as stack:
        try:
            stack.enter_context(budget.state_lock(base / ".lock"))
        except budget.StateBusy as e:
            raise StoreBusy(str(e)) from e
        # only the ACQUISITION is translated: a `StateBusy` raised INSIDE the body belongs to some other
        # lock, and reporting it as this one's contention blames a lock we are holding ourselves
        yield base


def owned_index(ledger) -> dict:
    """Every page the ledger demonstrably owns, grouped by pivot: {(lane, facet, value): [pages]}.

    One pass over `Ledger.items()`, which enumerates every digest-validated completion, so a hole of any
    width is recovered — probing upward from page 1 hides paid evidence behind a damaged page. The item
    key is recomputed from the document and must match the key it was filed under, so a page cannot claim
    an identity it was not bought as."""
    out: dict = {}
    for item, art in ledger.items():
        if isinstance(item, str) and item.startswith(ACQ_PREFIX):
            continue                      # a receipt is not a page; parsing it here would read it twice
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


#: the ledger-owning lanes share one probe each, defined beside `Ledger`.
ledger_writable = budget.ledger_writable
store_writable = budget.store_writable



def dedupe(states: "list[PivotState]") -> "list[PivotState]":
    """One state per (lane, facet, value). Two states for one pivot would both buy page 1: a round is
    computed before either records completion, so the duplicate is invisible to the in-flight guard."""
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
    """Ordering position for a pivot's cardinality. UNKNOWN sorts after KNOWN inside its page tier.

    Rare-first exists to reach the most distinct pivots per credit, and an unsized pivot could be a
    five-million-result generic. A position, never an exclusion: the pivot stays eligible, is re-sized
    every lifecycle, and what a budget does not reach is a counted remainder."""
    return (0, st.cardinality) if st.cardinality is not None else (1, 0)


def schedule(states: "list[PivotState]", *, max_pages: int = 0) -> list:
    """The next round of work: at most one page per pivot, ordered PAGE TIER first and fair across lanes
    inside a tier.

    Fairness is computed over PENDING work only — ordering the whole set would interleave completed
    history and push a lane's real remainder behind another lane's finished pages (the A1 lesson)."""
    pending = [(st, st.next_page(max_pages)) for st in states]
    pending = [(st, pg) for st, pg in pending if pg is not None]
    # cardinality orders WITHIN a lane and must not enter the rank TIER: `order_ranked_fair` buckets by
    # rank, so a rank of (page, cardinality) gives almost every pivot its own tier and collapses
    # cross-lane fairness into a global cardinality sort. Pre-sorting keeps the tier on PAGE alone.
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
    #: pages already PAID FOR whose artifact can no longer be proven. The completion is dropped and the
    #: evidence is gone — but it is not bought again: an evidence loss is not a spending permission.
    pages_lost: int = 0
    #: pages bought whose complete response this box would not parse. Owned, never re-bought, and
    #: eligible for a later run to interpret from the artifact.
    pages_unparsed: int = 0
    #: pages whose paid response did not arrive whole. Owned as far as it got; retry is an operator's
    #: decision, never ours.
    pages_incomplete: int = 0
    #: a purchase this run DECLINED because a previous run already paid for those bytes
    acquisition_refused: int = 0
    #: receipts or paid responses found on disk with no ownership entry behind them. Not "never bought":
    #: refused, counted, and left for an operator to reconcile.
    acquisition_orphans: int = 0
    #: OWNED acquisition keys whose receipt would not validate. Untrusted ownership evidence: it blocks
    #: a purchase exactly like a good receipt, because it cannot prove the page was NOT bought.
    acquisition_invalid: int = 0
    #: requests OUR rate boundary declined to issue. No socket opened and no credit moved.
    pace_refused: int = 0
    #: pages recovered by parsing bytes we already owned — no provider contact, no credit
    pages_parsed_late: int = 0
    #: paid responses we refused to treat as pages. The credit is spent either way, so the bytes are
    #: kept and the objection is NAMED — a bare class counter leaves provider drift and a wrong
    #: contract of ours equally unprovable.
    pages_rejected: int = 0
    reject_reasons: list = field(default_factory=list)     # bounded; first objections, in order
    #: a lost page this run declined to re-buy. Repairing paid evidence is an explicit operator decision,
    #: and `--unbound` is not that decision — it never authorises spending.
    repair_refused: int = 0
    pages_replayed: int = 0                 # replayed FRESH: inside the TTL, used as current evidence
    #: owned but past the TTL. The artifact is KEPT and reported as history; it is not ingested as a
    #: current result and never re-bought merely because time passed.
    pages_aged: int = 0
    #: an aged page whose pivot then wanted it: purchasing it again is an explicit operator decision, so
    #: the run records the refusal instead of spending
    refresh_refused: int = 0
    #: the oldest replayed page's age, so a report can say "current, 2 days old" rather than "current"
    oldest_replay_s: float = 0.0
    matches: int = 0
    fail_classes: dict = field(default_factory=dict)
    limit_classes: dict = field(default_factory=dict)
    # POSITION and CAUSE are independent facts: a pivot that yielded NOTHING is not one that kept page-1
    # evidence and lost a later page, and a reason must never name a class from the other position. The
    # aggregates above are a summary; these four are what the coverage measures derive from.
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
    # OWNERSHIP is not CONSUMPTION: a page whose `ingest` raised stays owned (or the scheduler sells it
    # to us again), but its matches never reached the store and the page remainder cannot say so.
    pages_unconsumed: int = 0
    # LANE-LOCAL machinery failures: ingesting a page is one lane's work on one lane's pivot, and filing
    # it globally turns a completed sibling PARTIAL. Genuinely shared failures stay on `WorkResult`.
    machinery: list = field(default_factory=list)


@dataclass
class WorkResult:
    lanes: dict = field(default_factory=dict)
    persisted: bool = True                  # completion state actually reached disk
    records_journaled: bool = True          # every completion recorded THIS RUN reported success
    stop_cause: str = ""                    # WHY scheduling ended — the scheduler's own answer, which
                                            # the balance alone cannot give (it does not know whether we
                                            # ran out mid-flight, hit the reserve, or lost the store)
    # every failure of OUR OWN machinery, in order. `stop_cause` keeps the FIRST cause,
    # because a later failure is its consequence; the rest would otherwise vanish entirely.
    machinery: list = field(default_factory=list)


def observe_total(st, o, total) -> None:
    """Fold one page's reported total into the pivot — one policy for fresh and replayed pages.

    Shodan's total moves between pages, so disagreement is PROVIDER DRIFT, not corruption. Keep the
    MAXIMUM observed total, so the remainder is never understated, and count the disagreement."""
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        return
    if st.total is not None and st.total != total:
        o.total_drift += 1
    st.total = total if st.total is None else max(st.total, total)
    # a total has just become known, so this is the moment a count can be measured against it — RETAINED
    # or FRESH, one call site, no path left to forget.
    compare_count(st, o)


def _page_doc(pivot: Pivot, page: int, total, matches, *, bought_at=None, raw=None) -> dict:
    """The page as stored.

    `bought_at` rides INSIDE the document: it is digest-verified with the page, so the purchase time is
    bound to the evidence by the same hash that proves ownership. `raw` names the provider's exact bytes,
    kept whole — this document is our reading of the response, that file is the response."""
    doc = {"schema": SHODAN_WORK_SCHEMA, "lane": pivot.lane, "facet": pivot.facet,
           "value": pivot.value, "page": page, "total": total, "matches": matches,
           "bought_at": float(time.time() if bought_at is None else bought_at)}
    if raw:
        doc.update(raw)
    return doc


#: tolerance for ordinary clock skew between the machine that bought a page and the one reading it.
#: Beyond this a "bought in the future" timestamp is not skew, it is a page that cannot prove its age.
CLOCK_SKEW_S = 300.0


def page_age_s(doc, *, now=None) -> float | None:
    """How old a stored page is, or None when it cannot say.

    An unreadable age is NEVER fresh: a page that cannot prove when it was bought cannot prove it is
    current. That includes a NaN or infinite timestamp, and one dated in the future beyond clock skew."""
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

    `ttl_days <= 0` means NEVER REPLAY, not "always buy": nothing here spends, and the scheduler skips an
    aged page precisely so that time passing cannot authorise a purchase."""
    age = page_age_s(doc, now=now)
    if age is None or ttl_days <= 0:
        return False
    return age <= ttl_days * 86400.0


def valid_page(doc, pivot: Pivot, page: int):
    """The recorded page, or None when the artifact does not prove what it claims.

    The envelope must identify ITSELF, or a digest-bound `{}` becomes a permanent ghost completion —
    replayed for ever, never re-bought, contributing nothing."""
    if not isinstance(doc, dict) or doc.get("schema") != SHODAN_WORK_SCHEMA:
        return None
    if (doc.get("lane") != pivot.lane or doc.get("facet") != pivot.facet
            or doc.get("value") != pivot.value):
        return None
    pg = doc.get("page")
    if isinstance(pg, bool) or not isinstance(pg, int) or pg != page:
        return None
    # replay owes exactly what `valid_fresh` demands of the provider: a digest-valid page with a null
    # total is a ghost completion — never repurchased, its page count unknown
    if not valid_fresh(doc.get("matches"), doc.get("total")):
        return None
    return doc


def valid_total(total) -> bool:
    """An exact non-negative integer; `bool` is excluded, since `True` would pass as the total 1.
    Shared by page evidence and /host/count sizing so the two cannot disagree about what a total is."""
    return not isinstance(total, bool) and isinstance(total, int) and total >= 0


def reject_reason(matches, total) -> "str | None":
    """WHY a page cannot be treated as complete, or None when it can.

    A validator that cannot name its objection leaves an operator unable to tell provider drift from a
    wrong contract of ours. Structural only — type names, a row index, the offending total. Never a
    hostname or a row's contents: the reason travels into telemetry, the evidence into the artifact."""
    if not valid_total(total):
        return f"total is not a usable count ({total!r})"
    if not isinstance(matches, list):
        return f"matches is {type(matches).__name__}, not a list"
    for i, m in enumerate(matches):
        if not isinstance(m, dict):                       # a null/scalar row is corruption, not empty
            return f"match row {i} is {type(m).__name__}, not an object"
        hns = m.get("hostnames")
        if hns is None:
            continue
        if not isinstance(hns, list):
            return f"row {i} hostnames is {type(hns).__name__}, not a list"
        for h in hns:
            if not isinstance(h, str):
                return f"row {i} has a {type(h).__name__} hostname, not a string"
    return None


def valid_fresh(matches, total) -> bool:
    """Whether a page may be treated as complete — one contract for fresh output and replayed
    evidence alike.

    Fresh output is validated exactly like replayed evidence, or the coordinator would trust the network
    more than its own disk. The ROWS are checked, not just the container, because a page bought before a
    contract existed would otherwise replay straight past it and crash the ingest that trusts it.

    Validating here rather than bumping the schema is deliberate: a bump invalidates every page already
    bought, including the valid ones. A malformed old page simply stops being owned."""
    return reject_reason(matches, total) is None


#: bodies at or below this ride INSIDE the rejection document, base64-encoded. Anything larger gets
#: its own artifact beside it: a PAID response is kept whole, and a slice of the thing under dispute is
#: not evidence of what arrived.
REJECTED_INLINE_LIMIT = 512 * 1024


def publish_rejected(attempt_dir, pivot: Pivot, page: int, *, reason: str, body=None,
                     matches=None, total=None, raw_path=None):
    """Keep what a PAID request returned when we refuse to treat it as a page.

    The credit is spent, so the response is evidence whatever our contract says. Written OUTSIDE the
    ledger — a rejected page is never owned and never replayed — with the exact bytes preserved, because
    a lossy re-encode of the thing under dispute is not evidence of what arrived.

    Best-effort: this runs on the failure path and must not replace one problem with another."""
    try:
        d = Path(attempt_dir) / "rejected"
        d.mkdir(parents=True, exist_ok=True)
        doc = {"schema": SHODAN_WORK_SCHEMA, "lane": pivot.lane, "facet": pivot.facet,
               "value": pivot.value, "page": page, "at": time.time(), "reason": reason,
               "owned": False}
        if raw_path is not None and Path(raw_path).is_file():
            # the COMPLETE response is already on disk, so this record POINTS at it rather than keeping a
            # truncated second copy. A rejected page is still a page we paid for, and it is kept whole.
            rp = Path(raw_path)
            doc["raw_ref"] = str(rp)
            doc["raw_bytes"] = rp.stat().st_size
            doc["raw_digest"] = events.file_digest(rp)
            body = None
        if isinstance(body, (bytes, bytearray)) and body:
            raw = bytes(body)
            doc["body_bytes"] = len(raw)
            if len(raw) <= REJECTED_INLINE_LIMIT:
                doc["body_b64"] = base64.b64encode(raw).decode()
            else:
                # too large to inline, and truncating a paid response is not an option: write it whole
                # and point at it, exactly as the streamed path does.
                side = d / f"{item_key(pivot, page)}.rejected.bin"
                dig = hashlib.sha256(raw).hexdigest()
                # through the atomic, content-verified primitive: a crash mid-write must not leave a
                # partial artifact standing at the name the document points at.
                if budget.publish_bytes(side, raw, digest=dig):
                    doc["raw_ref"] = str(side)
                    doc["raw_digest"] = dig
                else:
                    doc["body_kept"] = False
        elif matches is not None or total is not None:
            # no raw bytes to keep (the page parsed and then failed the CONTRACT): record what we were
            # handed, best-effort, so the shape that was rejected is still inspectable.
            doc["payload"] = json.loads(json.dumps({"total": total, "matches": matches}, default=repr))
        art = d / f"{item_key(pivot, page)}.rejected.json"
        art.write_text(json.dumps(doc))
        return art
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return None


#: ACQUISITION is committed separately from INTERPRETATION: bytes landing on disk is not ownership.
#: A response we paid for and could not parse, published only as a rejection, is bought again by the
#: next run — the double spend this store exists to prevent.
#:
#:   complete_parsed     the page is ours and readable
#:   complete_unparsed   the whole response is ours; this box would not parse it. Eligible for later
#:                       processing FROM THE ARTIFACT, never re-bought.
#:   incomplete_paid     the transport or disk broke mid-body. The partial bytes are ours, and an
#:                       automatic retry is REFUSED — an operator decides whether to pay again.
ACQ_PARSED = "complete_parsed"
ACQ_UNPARSED = "complete_unparsed"
ACQ_INCOMPLETE = "incomplete_paid"
#: acquisition items share the ledger with page items and must never collide with them
ACQ_PREFIX = "acq:"
#: our own rate boundary declined to let a request out. Not the provider's answer and not a limit it
#: imposed — a gap of ours that a later lifecycle closes for free.
PACE_BUSY = "pace_busy"


def acq_key(pivot: Pivot, page: int) -> str:
    return ACQ_PREFIX + item_key(pivot, page)


def publish_acquisition(attempt_dir, pivot: Pivot, page: int, *, state: str, raw_path=None,
                        reason: str = ""):
    """Record WHAT WE BOUGHT, before anything decides whether we can read it. Returns (path, digest)."""
    doc = {"schema": SHODAN_WORK_SCHEMA, "kind": "acquisition", "state": state, "lane": pivot.lane,
           "facet": pivot.facet, "value": pivot.value, "page": page, "at": time.time(),
           "reason": reason}
    if raw_path is not None and Path(raw_path).is_file():
        rp = Path(raw_path)
        doc["raw_ref"] = str(rp)
        doc["raw_bytes"] = rp.stat().st_size
        doc["raw_digest"] = events.file_digest(rp)
    body = json.dumps(doc).encode()
    dig = hashlib.sha256(body).hexdigest()
    art = Path(attempt_dir) / "acq" / f"{item_key(pivot, page)}.acq.json"
    return (art, dig, body) if budget.publish_bytes(art, body, digest=dig) else (None, None, body)


def verified_raw(acq: dict, *, base) -> "Path | None":
    """The receipt's raw artifact, or None when it cannot prove it is the response we paid for.

    Four questions, all of which must answer yes: is the path CONFINED to the paid store, is it a REGULAR
    FILE, is the byte count EXACT, is the digest EXACT. A digest we store and never verify is decoration."""
    ref = acq.get("raw_ref")
    if not isinstance(ref, str) or not ref:
        return None
    want_digest, want_bytes = acq.get("raw_digest"), acq.get("raw_bytes")
    if not (isinstance(want_digest, str) and want_digest):
        return None
    if isinstance(want_bytes, bool) or not isinstance(want_bytes, int) or want_bytes < 0:
        return None
    try:
        p = Path(ref)
        root = Path(base).resolve()
        if p.is_symlink():
            return None                       # a link may point anywhere, including outside the store
        real = p.resolve()
        if not real.is_relative_to(root):
            return None                       # confined to the store that paid for it
        if not real.is_file():
            return None
        if real.stat().st_size != want_bytes:
            # a CHEAP pre-filter the digest below subsumes: it rejects a substituted artifact without
            # hashing it, which matters when "it" is gigabytes. Not a separate guarantee.
            return None
        if events.file_digest(real) != want_digest:
            return None
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return None
    return p


@dataclass
class OwnershipView:
    """What this project can PROVE about pages it may have paid for.

    Every fact here is a reason NOT to spend. Expressed as an absence — a skipped receipt, an empty index
    from an unreadable store — they read as "never purchased" instead. Failure to inspect ownership must
    block spending, never erase ownership from the decision."""

    by_page: dict = field(default_factory=dict)      # (lane, facet, value, page) -> receipt
    invalid: dict = field(default_factory=dict)      # item_key -> why an OWNED receipt is untrusted
    orphans: dict = field(default_factory=dict)      # item_key -> artifact with no ownership entry
    error: str = ""                                  # ownership could not be inspected AT ALL


def ownership_view(base, ledger) -> OwnershipView:
    """Every ownership fact, from one enumeration of the ledger and one walk of the store.

    `error` is set when the inspection itself failed. For a PAID store, "we could not look" is not "there
    is nothing there": the caller stops."""
    view = OwnershipView()
    try:
        items = list(ledger.items())
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:
        view.error = f"ledger could not be enumerated: {e}"
        return view
    owned = {k for k, _ in items}

    for item, art in items:
        if not (isinstance(item, str) and item.startswith(ACQ_PREFIX)):
            continue
        key = item[len(ACQ_PREFIX):]
        try:
            doc = json.loads(Path(art).read_text())
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            view.invalid[key] = f"receipt unreadable: {e}"
            continue
        if not isinstance(doc, dict) or doc.get("kind") != "acquisition":
            view.invalid[key] = "receipt is not an acquisition document"
            continue
        if doc.get("schema") != SHODAN_WORK_SCHEMA:
            # a receipt from a generation we do not speak still PROVES A PURCHASE — it just may not be
            # interpreted. Invalid blocks the spend without feeding deferred parsing.
            view.invalid[key] = f"receipt schema {doc.get('schema')!r} is not v{SHODAN_WORK_SCHEMA}"
            continue
        if doc.get("state") not in (ACQ_PARSED, ACQ_UNPARSED, ACQ_INCOMPLETE):
            view.invalid[key] = f"receipt state {doc.get('state')!r} is not one we issue"
            continue
        lane, facet, value, page = (doc.get("lane"), doc.get("facet"), doc.get("value"),
                                    doc.get("page"))
        if not (isinstance(lane, str) and isinstance(facet, str) and isinstance(value, str)) \
                or isinstance(page, bool) or not isinstance(page, int):
            view.invalid[key] = "receipt does not name a pivot and page"
            continue
        if item != ACQ_PREFIX + item_key(Pivot(lane, facet, value), page):
            # filed under one identity, describing another: it proves nothing about EITHER, and it is
            # certainly not evidence that this page was never bought.
            view.invalid[key] = "receipt is filed under a different identity than it claims"
            continue
        view.by_page[(lane, facet, value, page)] = doc

    # artifacts that survived WITHOUT an ownership entry: a publish that lands while its journal fails
    # leaves the paid bytes invisible, and the next run buys again. `.part` counts too — a partial
    # response is a paid acquisition that did not finish.
    root = Path(base)
    walk_errors: list = []
    files: list = []
    try:
        # `Path.rglob` SILENTLY OMITS a subtree it cannot read: a directory at mode 000 yields no entries and
        # raises nothing, so an orphaned purchase inside it would be invisible and the page bought again.
        # `os.walk(onerror=…)` is the traversal that can report what it could not enter.
        for dirpath, _dirnames, filenames in os.walk(root, onerror=walk_errors.append):
            for name in filenames:
                files.append(Path(dirpath) / name)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:
        view.error = view.error or f"paid store could not be inspected: {e}"
        return view
    if walk_errors:
        # a store we cannot fully READ cannot rule out a prior purchase
        first = "; ".join(str(e) for e in walk_errors[:3])
        view.error = view.error or (f"paid store could not be fully inspected "
                                    f"({len(walk_errors)} unreadable location(s)): {first}")
        return view
    for art in files:
        name, parent = art.name, art.parent.name
        if parent == "acq" and name.endswith(".acq.json"):
            key, what = name[:-len(".acq.json")], "receipt"
        elif parent == "raw" and name.endswith(".json.part"):
            key, what = name[:-len(".json.part")], "PARTIAL paid response"
        elif parent == "raw" and name.endswith(".json"):
            key, what = name[:-len(".json")], "paid response"
        else:
            continue
        if not key or key in view.orphans:
            continue
        if ACQ_PREFIX + key in owned or key in owned:
            continue
        view.orphans[key] = f"{what} without an ownership entry ({art})"
    return view


def read_acquisition(ledger, pivot: Pivot, page: int) -> "dict | None":
    """The committed acquisition state for one page, or None when we never bought it.

    Bound to its identity like every other artifact: a document that names a different pivot or page is
    not this page's receipt."""
    try:
        art = ledger.artifact(acq_key(pivot, page))
        if art is None or not art.is_file():
            return None
        doc = json.loads(art.read_text())
    except Exception:
        return None
    if not isinstance(doc, dict) or doc.get("kind") != "acquisition":
        return None
    if (doc.get("lane"), doc.get("facet"), doc.get("value"), doc.get("page")) != (
            pivot.lane, pivot.facet, pivot.value, page):
        return None
    if doc.get("state") not in (ACQ_PARSED, ACQ_UNPARSED, ACQ_INCOMPLETE):
        return None
    return doc


def commit_acquisition(o, ledger, attempt_dir, pivot: Pivot, page: int, *, state: str, raw_path=None,
                       reason: str = "") -> bool:
    """Own what we paid for, whatever happens next. A failure to record it is a GLOBAL problem: the next
    run would buy the same page again."""
    art, dig, _body = publish_acquisition(attempt_dir, pivot, page, state=state, raw_path=raw_path,
                                          reason=reason)
    if art is None:
        return False
    return bool(ledger.record(acq_key(pivot, page), art, digest=dig))


#: how many objections a lane keeps. The first ones diagnose the contract; the thousandth is noise, and
#: an unbounded list on a failure path is a memory leak with a story attached.
MAX_REJECT_REASONS = 5


def note_rejected(o, pivot: Pivot, page: int, *, reason: str, attempt_dir, body=None,
                  matches=None, total=None, count: bool = True, raw_path=None) -> None:
    """Keep a paid response's bytes, and — when the objection is OURS — count it and remember why.

    One place, so the two rejection paths cannot drift. `count=False` preserves evidence for a
    provider-side refusal without claiming our contract rejected anything."""
    if not count:
        publish_rejected(attempt_dir, pivot, page, reason=reason, body=body,
                         matches=matches, total=total, raw_path=raw_path)
        return
    o.pages_rejected += 1
    art = publish_rejected(attempt_dir, pivot, page, reason=reason, body=body,
                           matches=matches, total=total, raw_path=raw_path)
    if len(o.reject_reasons) < MAX_REJECT_REASONS:
        o.reject_reasons.append(f"{pivot.facet}:{pivot.value} p{page}: {reason}"
                                + (f" [kept: {art.name}]" if art is not None else " [BYTES NOT KEPT]"))


def _read_page(path, pivot: Pivot, page: int):
    try:
        doc = json.loads(path.read_text())
    except Exception:
        return None
    return valid_page(doc, pivot, page)


def run_work(ctx, *, states, balance, search, ingest, ledger, attempt_dir,
             max_pages: int = 0, is_limit=None, should_stop=None, parse=None,
             ttl_days: float = PAGE_TTL_DAYS_DEFAULT) -> WorkResult:
    """Buy pages under the balance, replaying anything already owned.

    `search(pivot, page) -> (matches, total, error)` and `ingest(pivot, page, matches, raw_path) -> int`
    are injected. `balance` is the settled contract: `may_spend` decides whether ANY credit may be
    spent, `spendable` (None = no computable bound) decides how many."""
    from .contract import is_provider_limit as _default_is_limit
    is_limit = is_limit or _default_is_limit
    # "stop requesting" and "soft limit" are different questions. `should_stop` ends purchasing without
    # touching classification: a failure stays a gap, and only `is_limit` decides softness.
    should_stop = should_stop or (lambda cls: False)
    states = dedupe(states)
    res = WorkResult()
    for st in states:
        o = res.lanes.setdefault(st.pivot.lane, LaneOutcome(lane=st.pivot.lane))
        o.pivots += 1
    try:
        try:
            # REPLAY FIRST, ALWAYS. Owned evidence contacts nobody and spends nothing, so it must not wait behind
            # a provider's slowdown — a cooldown governs provider contact, and replay is not provider contact.
            # It runs whenever a project owns pages: a resumed run, a new run, a campaign child, another lane.
            _replay_indexed(states, res, ledger=ledger, ingest=ingest, ttl_days=ttl_days)
            _apply_cardinality(states, res)
            for st in states:                      # what aging DECLINED to buy, per lane
                res.lanes[st.pivot.lane].refresh_refused += st.refused_refresh(max_pages)
            # ...and ONLY NOW is the provider consulted. `balance` may be a CALLABLE so the balance read and the
            # free `/host/count` sizing happen AFTER replay. They are not skipped when everything is owned:
            # counting is how growth beyond a completed pagination is found.
            if callable(balance):
                try:
                    balance = balance()
                except pace.PaceBusy as e:
                    # OUR boundary refused before any contact. Replay above already happened; the
                    # remainder is reported and a later lifecycle closes it for free.
                    balance = None
                    res.stop_cause = res.stop_cause or f"{PACE_BUSY}:{e}"
                    for st in states:
                        res.lanes[st.pivot.lane].pace_refused += 1
            try:
                if balance is not None:
                    _work(states, res, balance=balance, search=search, ingest=ingest, ledger=ledger,
                          attempt_dir=attempt_dir, max_pages=max_pages, is_limit=is_limit,
                          should_stop=should_stop, parse=parse)
            except LaneMachineryError as e:
                # a page one lane could not ingest ends PURCHASING, but must not skip the FREE sweep of pages other
                # lanes already own
                _machinery(res, e)
            _sweep_owned(states, res, ledger=ledger, ingest=ingest, max_pages=max_pages)
        except (KeyboardInterrupt, SystemExit):
            raise                      # cancellation ends the run; it is not an outcome
        except Exception as e:
            # everything the run established is a fact whatever happened next: an escape here would report zero
            # pivots attempted over pages already replayed and bought
            _machinery(res, e)
    finally:
        # runs in `finally`, over a SNAPSHOT of the states, so a machinery failure still reports its
        # remainder and a second pass cannot double-count
        try:
            _remainder(states, res, max_pages=max_pages)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            _machinery(res, e)
        # persistence is the coordinator's job and its RESULT is a fact: an unwritable ledger leaves bought
        # pages looking resumable in memory while the next run pays for them again.
        #
        # The question is "will the next run see these completions?", which is "snapshot written OR journal
        # intact" — and BOTH facts are needed: a checkpoint can journal cleanly while the page's own record
        # fails and compaction fails too, so every individual signal looks survivable while the page reached
        # neither destination. A save that raises did not save.
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
    """True when the page replayed from owned evidence, False when the record is unusable, None
    when we do not own it.

    The ledger is consulted per page as it is scheduled, so a damaged page 1 does not hide a good page 2
    behind it."""
    if owned is not None:
        # already enumerated, validated and key-bound by `owned_index` — re-reading it would be a third
        # read of bytes we hold.
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
        o.pivots_touched += 1                 # ANY page, not just page 1
    observe_total(st, o, doc.get("total"))
    try:
        o.matches += ingest(st.pivot, page, doc.get("matches") or [], art)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:
        # the page stays OWNED — dropping it would have the scheduler sell it to us again — and the
        # shortfall is counted in its own unit
        _lane_machinery(o, e)                  # raises the lane-scoped carrier
    return True


class LaneMachineryError(Exception):
    """An ingestion failure already attributed to the lane whose page it was.

    Scope is carried STRUCTURALLY by the exception type, not by a flag set on the original: an exception
    that rejects attributes would otherwise be filed against every lane, taking a completed sibling
    partial with it. The original is the `__cause__`."""

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
    """Record OUR OWN failure without discarding what the run established.

    A boundary that only stops the crash is not a boundary: the caller would fabricate zero accounting
    over evidence the run is holding. The FIRST failure names the stop; a later one is its consequence."""
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
    """Run `replay_one` over every state, keeping one lane's ingestion failure from ending
    the others' free replay.

    Replay is free and per-lane: the failing lane stops (its sink is broken, the next page fails
    identically), purchasing stops globally via `stop_cause`, and every other lane replays what it owns."""
    # a lane's own recorded machinery IS the lifecycle-wide answer to "is this sink broken", and it
    # covers a fault recorded on the paid path too — a per-pass set would retry a known-broken sink
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

    Purchased evidence replays whether or not an earlier hole is repaired this lifecycle: sequential
    discovery would remove the pivot from scheduling and hide an owned page behind a failed repair. The
    ledger is enumerated once for the whole run."""
    index = owned_index(ledger)

    def one(st, o):
        for page, art, doc in index.get((st.pivot.lane, st.pivot.facet, st.pivot.value), ()):
            if page in st.pages_done:
                continue
            if not page_fresh(doc, ttl_days=ttl_days, now=now):
                # AGED, not gone: replaying a stale search page as a current result would be the eternal cache the
                # free-host lane warns about. The artifact stays owned and reportable as history.
                o.pages_aged += 1
                st.aged_pages.add(page)
                continue
            age = page_age_s(doc, now=now) or 0.0
            o.oldest_replay_s = max(o.oldest_replay_s, age)
            _replay_one(st, o, page=page, ledger=ledger, ingest=ingest, owned=(art, doc))

    _replay_lane_safe(states, res, one)


def compare_count(st, o) -> None:
    """Measure a pivot's count against its page-derived total, and keep that verdict CURRENT.

    Compared whether the page was retained or fresh, and REVISED as evidence accumulates: `total` is
    reconciled max-wins, so a verdict frozen against page 1 would call a later, larger total drift. Each
    pivot is still counted once."""
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
    """Fold /host/count sizing into what we know, after replay and before scheduling.

    Two rules, and the boundary between them is the design:

      · NO page-derived total  -> the count ORDERS the pivot and nothing else. Sizing an unqueried pivot
        would report it as `unqueried` AND as "N pages left" — a remainder over a denominator no page
        proved.
      · a page-derived total   -> `effective_total` is the MAXIMUM of the two, so a pivot complete under
        yesterday's total discovers new results instead of treating an old completion as permanent.

    Runs before `_work`, so growth found here is bought in the same lifecycle."""
    for st in states:
        compare_count(st, res.lanes[st.pivot.lane])


def _commit_page(st, o, res, *, page, matches, total, ledger, attempt_dir, ingest, raw_path=None,
                 late: bool = False) -> bool:
    """Publish one page, OWN it, and ingest its rows. True when the page is ours.

    One place for both routes into ownership: a fresh purchase, and a page recovered later from bytes we
    already hold (`late=True`, which spends nothing and is not counted as a purchase)."""
    pivot = st.pivot
    raw_meta = None
    if raw_path is not None and Path(raw_path).is_file():
        rp = Path(raw_path)
        # the reference must RESOLVE: a bare name resolves, relative to the page document, to that document
        # itself — the doc would point at its own sibling and call it the provider's response
        try:
            ref = str(rp.relative_to(Path(attempt_dir)))
        except ValueError:
            ref = str(rp)
        raw_meta = {"raw_ref": ref, "raw_bytes": rp.stat().st_size,
                    "raw_digest": events.file_digest(rp)}
    art = Path(attempt_dir) / f"{item_key(pivot, page)}.json"
    # evidence records what the provider ANSWERED for THIS page; reconciliation is a derived view and
    # lives only in `PivotState`, or the drift disappears on resume
    body = json.dumps(_page_doc(pivot, page, total, matches, raw=raw_meta)).encode()
    dig = hashlib.sha256(body).hexdigest()
    # atomic + content-verified: a torn write at a content-addressed name would otherwise be reused
    # later as if it were the page we meant to buy.
    if not budget.publish_bytes(art, body, digest=dig):
        # leaving the page PENDING schedules it again — the same page bought over and over,
        # unbounded when the balance is unknown. A store we cannot write to is a GLOBAL problem.
        o.publish_failed += 1
        st.stopped = "publish_failed"
        res.stop_cause = "publish_failed"
        return False
    if not st.pages_done:
        o.pivots_touched += 1                 # ANY page counts as touching the pivot
    st.pages_done.add(page)
    if not late:
        o.pages_bought += 1
    journaled = ledger.record(item_key(pivot, page), art, digest=dig)
    # ACQUISITION is committed too, and separately: the page doc proves we can READ it, this proves we
    # BOUGHT it. Without the second fact a page we could not parse was never owned at all.
    # the receipt's durability is folded in exactly like the completion's below: an append the
    # snapshot later rescues is not a lost purchase, but one that reaches neither destination is.
    acq_journaled = commit_acquisition(o, ledger, attempt_dir, pivot, page, state=ACQ_PARSED,
                                       raw_path=raw_path)
    if raw_meta is not None:
        # EVIDENCE, not the completion artifact: replay reads the page doc, and this is what the
        # provider actually sent. Retained so it survives beside the page it paid for.
        try:
            ledger.add_evidence(item_key(pivot, page), Path(raw_path), digest=raw_meta["raw_digest"])
        except Exception as e:
            _lane_machinery(o, e)
    # a readable journal proves OLD content survives, not that THIS page reached it.
    res.records_journaled = res.records_journaled and journaled and acq_journaled
    try:
        o.matches += ingest(pivot, page, matches, art)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:
        # the credit is spent and the page is owned; its rows are not. Raises the carrier.
        _lane_machinery(o, e)
    if not journaled or not ledger_writable(ledger):
        res.stop_cause = "ledger_unwritable"
    return True


def _work(states, res, *, balance, search, ingest, ledger, attempt_dir, max_pages, is_limit,
          should_stop=None, parse=None) -> None:
    should_stop = should_stop or (lambda cls: False)
    # an index that exists and cannot be trusted is not an empty one: reading it as empty makes a corrupt
    # file into permission to buy every page again. Nothing is bought until an operator resolves it;
    # replay has already taken whatever could be proven.
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
    # Deliberately unfalsifiable today: with every current path correct, no page can be rescheduled after
    # a purchase. It is kept because of what it bounds — an unbounded spend of real money — and because
    # it converts that failure mode from a hang into a failure.
    tried: set = set()
    probed: list = []
    # every ownership fact, from one enumeration and one walk (see `ownership_view`)
    own = ownership_view(Path(ledger.path).parent, ledger)
    if own.error:
        # UNKNOWN is not EMPTY. An ownership store we could not inspect cannot rule out a prior
        # purchase, so nothing is bought until an operator can say what is in it.
        res.stop_cause = res.stop_cause or f"ownership_uninspectable:{own.error}"
        return
    acquired = own.by_page

    def sinks_ok() -> bool:
        """Prove BOTH sinks once, immediately before the first purchase.

        Buying what we cannot record means paying twice. A flag check is not a precondition: nothing sets
        those flags until a write has already failed, so `checkpoint()` appends a real replay-safe record
        and the artifact store is probed the same way.

        On the PURCHASE path, not at entry: a run that buys nothing needs neither sink, and probing
        anyway made a fully-replayed run over a read-only store call itself broken."""
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
            # a page already PAID FOR whose artifact no longer verifies. "Gone" is not an authorisation: buying
            # it again is a fresh charge, refused on exactly the terms an AGED page is. Repair waits for an
            # explicit operator policy that does not exist yet.
            # EVERY valid receipt blocks acquisition: a receipt without a usable page is evidence loss plus a
            # refused repair, never permission to buy.
            acq = acquired.get((st.pivot.lane, st.pivot.facet, st.pivot.value, page))
            if acq is not None:
                state = acq.get("state")
                # bytes we already own may only be interpreted once they PROVE they are the bytes we
                # bought: confined, regular, exact length, exact digest.
                raw = verified_raw(acq, base=Path(ledger.path).parent)
                if state == ACQ_UNPARSED and parse is not None and raw is not None:
                    got = parse(raw)
                    if got is not None:
                        p_matches, p_total = got
                        if reject_reason(p_matches, p_total) is None:
                            o.pages_parsed_late += 1
                            if _commit_page(st, o, res, page=page, matches=p_matches, total=p_total,
                                            ledger=ledger, attempt_dir=attempt_dir, ingest=ingest,
                                            raw_path=raw, late=True):
                                progressed = True
                                continue
                if state == ACQ_INCOMPLETE:
                    o.pages_incomplete += 1
                elif state == ACQ_PARSED or (state == ACQ_UNPARSED and raw is None):
                    # the receipt stands and the evidence does not: a parsed page whose document is gone, or purchased
                    # bytes that no longer verify. Both are losses we admit and refuse to repair by spending again.
                    o.pages_lost += 1
                    o.repair_refused += 1
                else:
                    o.pages_unparsed += 1
                o.acquisition_refused += 1
                st.lost_pages.add(page)          # never scheduled again: it is BOUGHT, not missing
                continue
            # an OWNED receipt we cannot validate is untrusted ownership evidence — never an absence
            if item_key(st.pivot, page) in own.invalid:
                o.acquisition_invalid += 1
                o.acquisition_refused += 1
                st.lost_pages.add(page)
                continue
            # a receipt or a paid response on disk with NO ownership entry is not "never bought"
            orphan = own.orphans.get(item_key(st.pivot, page))
            if orphan is not None:
                o.acquisition_orphans += 1
                o.acquisition_refused += 1
                st.lost_pages.add(page)
                res.stop_cause = res.stop_cause or "acquisition_orphan"
                continue
            if item_key(st.pivot, page) in getattr(ledger, "lost", {}):
                o.pages_lost += 1
                o.repair_refused += 1
                st.lost_pages.add(page)
                continue
            if spendable is not None and spent >= spendable:
                continue                                  # no credit for this page; remainder reports it
            attempt = (st.pivot.lane, st.pivot.facet, st.pivot.value, page)
            if attempt in tried:
                # reaching here means the scheduler offered a page it had already sold us: an invariant break, which
                # is a DEFECT and must read as one rather than ending the loop with no cause
                res.stop_cause = "scheduler_invariant"
                continue
            if not sinks_ok():
                break                                     # nothing paid for yet; stop_cause is set
            tried.add(attempt)
            try:
                matches, total, err = search(st.pivot, page)
            except pace.PaceBusy as e:
                # NO REQUEST WAS ISSUED, so no credit moved: "contact refused" stays distinct from "request issued"
                # all the way through accounting. Caught BEFORE the boundary below, and purchasing ends — the next
                # pivot would be refused identically.
                o.pace_refused += 1
                st.stopped = PACE_BUSY
                res.stop_cause = res.stop_cause or f"{PACE_BUSY}:{e}"
                tried.discard(attempt)
                break
            spent += 1                                    # a request was ISSUED — that is the credit
            st.attempted = True
            progressed = True
            if err is not None:
                cls = getattr(err, "error_class", None) or "error"
                # the body is kept for EVERY provider error — that is how an interstitial or a quota sentence stays
                # inspectable — but only a `parse` failure is an objection of OURS, so only that one moves the
                # rejection counters.
                err_raw = getattr(err, "raw_path", None)
                note_rejected(o, st.pivot, page, reason=f"{cls}: {err}", attempt_dir=attempt_dir,
                              body=getattr(err, "body_bytes", None), raw_path=err_raw,
                              count=(cls in ("parse", "oversize", "incomplete")))
                # the receipt is committed here, BEFORE any judgement about readability: bytes on disk is not
                # ownership, and a response published only as a rejection is bought again by the next run
                if err_raw is not None and Path(err_raw).is_file():
                    state = ACQ_INCOMPLETE if cls == "incomplete" else (
                        ACQ_UNPARSED if cls == "oversize" else None)
                    if state is not None:
                        if state == ACQ_INCOMPLETE:
                            o.pages_incomplete += 1
                        else:
                            o.pages_unparsed += 1
                        if not commit_acquisition(o, ledger, attempt_dir, st.pivot, page, state=state,
                                                  raw_path=err_raw, reason=f"{cls}: {err}"):
                            # a purchase we cannot record is a purchase the next run repeats
                            o.publish_failed += 1
                            res.stop_cause = "ledger_unwritable"
                        st.lost_pages.add(page)      # bought, not missing: never scheduled again
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
                    # a FAILURE further requests cannot get past — a refused credential, persistent throttling.
                    # Purchasing ends; the class is untouched, so this reads as the gap it is.
                    res.stop_cause = f"provider_stop:{cls}"
                continue
            why = reject_reason(matches, total)
            if why is not None:
                # the provider answered, but not with something we can call a page. The credit is gone;
                # the response is not — it is written outside the ledger and the objection is recorded.
                st.stopped = "parse"
                o.fail_classes["parse"] = o.fail_classes.get("parse", 0) + 1
                # the complete response is on disk here too. Binding it beats keeping
                # a reconstructed, truncated copy of what we rejected.
                rejected_raw = Path(attempt_dir) / "raw" / f"{item_key(st.pivot, page)}.json"
                note_rejected(o, st.pivot, page, reason=why, attempt_dir=attempt_dir,
                              matches=matches, total=total,
                              raw_path=rejected_raw if rejected_raw.is_file() else None)
                if rejected_raw.is_file():
                    # we bought these bytes. They are ours whether or not they are a page we accept.
                    # the receipt is this page's ONLY ownership record — there is no completion to
                    # fall back on — so a lost one is a purchase the next run repeats.
                    # evaluated FIRST: folding it into an `and` would skip the receipt entirely once
                    # an earlier record had already set the flag False.
                    acq_ok = commit_acquisition(o, ledger, attempt_dir, st.pivot, page,
                                                state=ACQ_UNPARSED, raw_path=rejected_raw,
                                                reason=f"rejected: {why}")
                    res.records_journaled = res.records_journaled and acq_ok
                    st.lost_pages.add(page)
                continue
            observe_total(st, o, total)
            if not _commit_page(st, o, res, page=page, matches=matches, total=total, ledger=ledger,
                                attempt_dir=attempt_dir, ingest=ingest,
                                raw_path=Path(attempt_dir) / "raw" / f"{item_key(st.pivot, page)}.json"):
                continue
            progressed = True
            continue

        if not progressed:
            # nothing moved: the budget is gone (or every remaining page is unbuyable).
            if spendable is not None and spent >= spendable and not res.stop_cause:
                # WHO stopped us: a positive reserve means the operator withheld the rest;
                # a zero reserve means the provider's balance is simply the boundary.
                res.stop_cause = "budget_reserve" if reserve > 0 else "budget_provider"
            break


def _sweep_owned(states, res, *, ledger, ingest, max_pages) -> None:
    """Replay owned pages that an operator PAGE POLICY excluded from purchasing.

    `max_pages` bounds what we BUY and must not discard evidence we already hold, or a resumed run
    reports pages it owns and replayed as withheld."""
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
    # a snapshot, not an accumulator: this is reachable twice, and `+=` would double the remainder
    for o in res.lanes.values():
        o.unqueried = []
        o.pages_left_known = 0
        o.pages_left_unknown_pivots = 0
        o.pages_withheld = 0
    for st in states:
        o = res.lanes[st.pivot.lane]
        # "never reached" is not "asked and refused": a pivot whose only page died on a quota WAS queried, so
        # listing it as unqueried would overstate the remainder and hide that the attempt happened
        if not st.pages_done and not st.attempted:
            o.unqueried.append(st.pivot.value)
        pages = st.page_count()
        if pages is None:
            if st.pages_done:
                o.pages_left_unknown_pivots += 1
        else:
            limit = pages if not max_pages else min(pages, max_pages)
            # counted inside the policy window only: replayed pages above it would hide a genuine hole below
            done_in_window = sum(1 for p in st.pages_done if p <= limit)
            o.pages_left_known += max(0, limit - done_in_window)
            o.pages_withheld += st.withheld_pages(max_pages)


# ── coverage ──────────────────────────────────────────────────────────────────────────────────────
# WHO stopped us decides the KIND, and the kinds mean different things to the verdict:
#   provider  a PROVEN provider boundary (quota/entitlement)   -> soft limit
#   sample    an OPERATOR policy (reserve, max_pages)          -> soft limit
#   timeout   something FAILED (transport/auth/server/parse)   -> gap
# Collapsing any of them lets a broken run report `complete_with_limits`.
def _unqueried_kind(balance, stop_cause: str = "") -> str:
    """The kind for work we never reached, decided by WHO stopped us.

    The scheduler's own answer wins; the balance is only the fallback for cases settled before any work
    began. A finite balance with a reserve carries no stop_kind up front, so consulting the balance alone
    blames the provider for the operator's reserve."""
    from .phases.probe import (SHODAN_ENTITLEMENT, SHODAN_OPERATOR_RESERVE, SHODAN_PROVIDER_EXHAUSTED,
                               SHODAN_UNKNOWN_WITH_RESERVE)
    if stop_cause:
        if stop_cause == "budget_reserve":
            return events.COVERAGE_SAMPLE                # the OPERATOR withheld the rest
        if stop_cause == "budget_provider" or stop_cause.startswith("provider_limit:"):
            return events.COVERAGE_PROVIDER              # the provider's balance was the boundary
        # provider_stop:* is a FAILURE we stopped requesting through — a gap, never a soft limit.
        # publish_failed / ledger_unwritable / scheduler_invariant / ownership_unreadable / pace_busy are all
        # OURS. `pace_busy` is the one that is not a defect: a boundary declining to burst is working.
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
    # the scheduler's own answer comes first; the balance is the fallback for stops it settled before any
    # work began, or a lane stopped by another lane's refused credential explains itself with a healthy
    # credit balance
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
    # an OWNED page whose ingestion failed is out of the page remainder — nothing else in
    # this report can say its rows are missing. Emitted every lifecycle so a later clean run clears it.
    unc = outcome.pages_unconsumed
    events.coverage_partial(lane, kind=events.COVERAGE_TIMEOUT, measure="shodan_pages_unconsumed",
                            unit=f"{lane}.pages_unconsumed", eligible=done, tested=done - unc,
                            omitted=unc,
                            reason=(f"{unc}/{done} owned page(s) could not be ingested — their rows are "
                                    f"NOT in the store" if unc else
                                    f"every one of {done} owned page(s) was ingested"))
    # POSITION x CAUSE, four measures, each naming ONLY its own position's classes. A mid-flight quota is
    # not a pivot the provider refused outright, and a later-page transport failure is not our page
    # budget. Without them a run stopped dead by quota folds as `complete`: an attempted pivot is not
    # "unqueried", and a pivot with no total has no page remainder.
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
    # WHAT WE BOUGHT vs WHAT WE COULD READ. A page whose bytes we own but could not parse is coverage we
    # do not have and money we will not spend again, and one number cannot say both.
    owned_paid = (outcome.pages_bought + outcome.pages_parsed_late + outcome.pages_unparsed
                  + outcome.pages_incomplete)
    if owned_paid or outcome.acquisition_refused:
        interpreted = outcome.pages_bought + outcome.pages_parsed_late
        events.coverage_partial(
            lane, kind=events.COVERAGE_TIMEOUT, measure="shodan_pages_acquired",
            unit=f"{lane}.pages_acquired", eligible=owned_paid, tested=interpreted,
            omitted=outcome.pages_unparsed + outcome.pages_incomplete,
            reason=(f"acquired={owned_paid} (interpreted={interpreted}"
                    + (f", of which {outcome.pages_parsed_late} parsed later from bytes already owned"
                       if outcome.pages_parsed_late else "")
                    + f"); complete_unparsed={outcome.pages_unparsed} (OWNED, eligible for a later run, "
                      f"never re-bought); incomplete_paid={outcome.pages_incomplete} (partial response "
                      f"kept; an automatic retry is refused)"
                    + (f"; {outcome.acquisition_refused} purchase(s) declined because this project had "
                       f"already paid for those bytes" if outcome.acquisition_refused else "")))
    # A PAID RESPONSE WE REFUSED, in its own measure: the position measures answer "which pivots failed,
    # first or later, broken or refused", and an objection about a page's SHAPE is neither. The credit is
    # spent either way, so this is emitted every lifecycle and says where the bytes went.
    rej = outcome.pages_rejected
    events.coverage_partial(lane, kind=events.COVERAGE_TIMEOUT, measure="shodan_pages_rejected",
                            unit=f"{lane}.pages_rejected", eligible=done + rej, tested=done, omitted=rej,
                            reason=(f"{rej} paid response(s) refused as unusable — "
                                    + "; ".join(outcome.reject_reasons) if rej else
                                    "no paid response was refused"))
    # PROVIDER DRIFT: the index is live, so two pages of one pivot can report different totals. We keep
    # the maximum, so nothing is omitted. Drift is TELEMETRY about the provider's denominator, not a
    # coverage boundary — `omitted=0`, and the count lives in the reason where a reader can see it.
    drift_of = max(1, done)
    events.coverage_partial(lane, kind=events.COVERAGE_PROVIDER, measure="shodan_total_drift",
                            unit=f"{lane}.total_drift", eligible=drift_of, tested=drift_of, omitted=0,
                            reason=(f"{outcome.total_drift} of {done} page(s) reported a total that "
                                    f"disagreed with another page of the same pivot — the provider's "
                                    f"index moved; the LARGEST total is kept, so NOTHING is omitted"
                                    if outcome.total_drift
                                    else "every page agreed on its pivot's total"))
    # OUR page policy is a CAP, not a sample: a soft sample would let a run that never looked past page 1
    # call itself complete. A hard ceiling WE imposed reads as a gap whenever it withheld anything.
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
    # a balance read REFUSED by the provider is a limit like any other: counting every `read_error` as a
    # failure makes a depleted account emit a gap from the balance probe while its pivots report a limit
    read_limited = bool(read_err) and _is_limit(read_err)
    if read_err and not read_limited:
        fails += 1
    # a credential refused by the FREE count endpoint is a failure of this run's ability to work at all,
    # and not a balance-read error — that read succeeded
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
