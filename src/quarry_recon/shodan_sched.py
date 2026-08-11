"""The Shodan work coordinator: one credit buys one search page.

The unit of work is `(lane, facet, value, page)`, and both lanes' work is collected before any credit is
spent — a shared counter is not cross-lane fairness. Scheduling is breadth first by page number, with
cross-lane fairness inside each tier; the page must be the outer rank, or a pivot already holding pages
1-2 takes page 3 before an untouched pivot gets its first.

This owns scheduling, purchase, evidence, durability and coverage. Ingestion and HTTP are injected.
Provider semantics: docs/design/PROVIDER-QUOTA-DESIGN.md.
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

from . import budget, contract, events, pace

#: v2: pages carry `bought_at` and live in a project-scoped store. A schema bump isolates the previous
#: generation rather than deleting it — paid evidence is never pruned automatically.
SHODAN_WORK_SCHEMA = 2
#: policy, not a measurement: how long a purchased page may stand in for a fresh one. The effective
#: value travels with the evidence.
PAGE_TTL_DAYS_DEFAULT = 7
SHODAN_PAGE_SIZE = 100                      # Shodan returns up to 100 matches per page


@dataclass(frozen=True)
class Pivot:
    """One searchable value belonging to one lane. Pages are work; a pivot is the thing worked on."""

    lane: str                               # the registered source_id, e.g. "probe.favicon"
    facet: str                              # e.g. "http.favicon.hash"
    value: str

    @property
    def label(self) -> str:
        return f"{self.facet}:{self.value}"


@dataclass
class PivotState:

    pivot: Pivot
    total: "int | None" = None              # the provider's own match count; None until page 1 answers
    pages_done: set = field(default_factory=set)
    #: owned pages older than the TTL. Apart from `pages_done` because they are not current evidence, and
    #: apart from "missing" because they were paid for and must never be silently re-bought.
    aged_pages: set = field(default_factory=set)
    #: pages we own on paper and cannot prove. Skipped by `next_page` for the same reason aged pages are:
    #: scheduling one means buying it, and this run has no authority to repair paid evidence.
    lost_pages: set = field(default_factory=set)
    attempted: bool = False                 # a request was issued for this pivot (a credit was spent)
    cardinality: "int | None" = None      # /host/count sizing, held separately from `total` so neither
                                          # contaminates the other
    count_compared: bool = False          # the count has met page evidence at least once
    count_drifted: bool = False            # ...and the current verdict of that comparison
    stopped: str = ""                       # a class that ended this pivot early (limit or failure)
    _cursor: int = 1                        # lowest page not known-complete; never rescans the prefix

    def effective_total(self) -> "int | None":
        """What we currently believe the pivot holds, for scheduling only: `total` stays page-derived, and a
        count never becomes evidence of pages."""
        if self.total is None:
            return None
        return max(self.total, self.cardinality) if self.cardinality is not None else self.total

    def page_count(self) -> "int | None":
        """How many pages this pivot has, or None while unknown. An unqueried pivot has no knowable count."""
        total = self.effective_total()
        if total is None:
            return None
        return max(1, -(-total // SHODAN_PAGE_SIZE))         # ceil division

    def next_page(self, max_pages: int = 0) -> "int | None":
        """The lowest page still owed, or None. The cursor is monotonic, so a gap is never re-offered inside one
        lifecycle."""
        if self.stopped:
            return None
        # an aged page is skipped, never scheduled: it is already paid for, and buying it again merely
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
        """Aged pages this pivot would otherwise have asked for — each one a purchase the run declined."""
        if not self.aged_pages:
            return 0
        pages = self.page_count()
        limit = pages if pages is not None else max(self.aged_pages)
        if max_pages:
            limit = min(limit, max_pages)
        return sum(1 for p in self.aged_pages if p <= limit)

    def withheld_pages(self, max_pages: int = 0) -> int:
        """Pages this pivot has that a page policy keeps us from buying and we do not already own."""
        pages = self.page_count()
        if pages is None or not max_pages:
            return 0
        return sum(1 for p in range(max_pages + 1, pages + 1) if p not in self.pages_done)


def count_key(pivot: Pivot) -> str:
    raw = f"{SHODAN_WORK_SCHEMA}|{pivot.lane}|{pivot.facet}|{pivot.value}|count"
    return hashlib.sha256(raw.encode()).hexdigest()


def item_key(pivot: Pivot, page: int) -> str:
    """The per-page completion identity: (schema, lane, facet, value, page). The reserve is absent: it
    governs purchasing, never what a bought page is."""
    raw = f"{SHODAN_WORK_SCHEMA}|{pivot.lane}|{pivot.facet}|{pivot.value}|p{page}"
    return hashlib.sha256(raw.encode()).hexdigest()


def provider_dir(project_dir) -> Path:
    return Path(project_dir) / "state" / "shodan-pivot"


def state_dir(project_dir) -> Path:
    """The durable home for purchased pivot pages. Project-scoped, not run-scoped, and the generation is the
    work schema only — folding a spending control in would re-buy paid pages."""
    return provider_dir(project_dir) / f"v{SHODAN_WORK_SCHEMA}"


class StoreBusy(RuntimeError):
    """Another lifecycle holds this project's purchased-page store. Contention only."""


@contextlib.contextmanager
def lifecycle_lock(project_dir):
    """Exclusive, advisory, OS-released lock over a project's purchased Shodan pages, at the provider level:
    two builds on different schemas still share one account.

    Held across load, replay, purchase, record and save. Contention raises `StoreBusy` before any of it,
    so a blocked run issues zero paid requests."""
    base = provider_dir(project_dir)
    base.mkdir(parents=True, exist_ok=True)
    with contextlib.ExitStack() as stack:
        try:
            stack.enter_context(budget.state_lock(base / ".lock"))
        except budget.StateBusy as e:
            raise StoreBusy(str(e)) from e
        # only the acquisition is translated: a `StateBusy` raised inside the body belongs to some other
        # lock, and reporting it as this one's contention blames a lock we are holding ourselves
        yield base


def owned_index(ledger) -> dict:
    """Every page the ledger demonstrably owns, grouped by pivot: {(lane, facet, value): [pages]}. One pass
    over every digest-validated completion."""
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
        # the full page contract, then the binding: a document is only evidence for the identity it was
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
    return (0, st.cardinality) if st.cardinality is not None else (1, 0)


def schedule(states: "list[PivotState]", *, max_pages: int = 0) -> list:
    """The next round of work: at most one page per pivot, page tier first and fair across lanes inside a
    tier."""
    pending = [(st, st.next_page(max_pages)) for st in states]
    pending = [(st, pg) for st, pg in pending if pg is not None]
    # cardinality orders within a lane and must not enter the rank tier: a rank of (page, cardinality)
    # gives almost every pivot its own tier, collapsing fairness into a global cardinality sort
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
    #: pages already paid for whose artifact can no longer be proven. The completion is dropped and the
    #: evidence is gone — but it is not bought again: an evidence loss is not a spending permission.
    pages_lost: int = 0
    #: pages bought whose complete response this box would not parse. Owned, never re-bought, and
    #: eligible for a later run to interpret from the artifact.
    pages_unparsed: int = 0
    #: pages whose paid response did not arrive whole. Owned as far as it got; retry is an operator's
    #: decision, never ours.
    pages_incomplete: int = 0
    #: a purchase this run declined because a previous run already paid for those bytes
    acquisition_refused: int = 0
    #: receipts or paid responses found on disk with no ownership entry behind them. Not "never bought":
    #: refused, counted, and left for an operator to reconcile.
    acquisition_orphans: int = 0
    #: owned acquisition keys whose receipt would not validate. Untrusted ownership evidence: it blocks
    #: a purchase exactly like a good receipt, because it cannot prove the page was not bought.
    acquisition_invalid: int = 0
    #: requests our rate boundary declined to issue. No socket opened and no credit moved.
    pace_refused: int = 0
    #: requests our disk/byte governor declined to issue. No socket opened and no credit moved.
    budget_refused: int = 0
    #: pages recovered by parsing bytes we already owned — no provider contact, no credit
    pages_parsed_late: int = 0
    #: paid responses we refused to treat as pages: the bytes are kept and the objection is named, or
    #: provider drift and a wrong contract of ours are equally unprovable
    pages_rejected: int = 0
    reject_reasons: list = field(default_factory=list)     # bounded; first objections, in order
    #: a lost page this run declined to re-buy. Repairing paid evidence is an explicit operator decision,
    #: and `--unbound` is not that decision — it never authorises spending.
    repair_refused: int = 0
    pages_replayed: int = 0                 # replayed fresh: inside the TTL, used as current evidence
    #: owned but past the TTL. The artifact is kept and reported as history; it is not ingested as a
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
    # position and cause are independent, and the coverage measures derive from these four
    first_fail_classes: dict = field(default_factory=dict)
    first_limit_classes: dict = field(default_factory=dict)
    later_fail_classes: dict = field(default_factory=dict)
    later_limit_classes: dict = field(default_factory=dict)
    unqueried: list = field(default_factory=list)      # exact identities, never a count alone
    pages_left_known: int = 0               # only for pivots whose total is known
    pages_left_unknown_pivots: int = 0      # pivots whose page count we cannot know
    pages_withheld: int = 0                 # pages an operator policy (max_pages) kept us from buying
    total_drift: int = 0                    # pages whose total disagreed with another page's
    count_compared: int = 0                 # pivots whose count met a page-derived total
    count_drift: int = 0                    # ...and disagreed with it
    evidence_invalid: int = 0               # recorded pages whose artifact did not validate
    publish_failed: int = 0                 # bought pages we could not durably record
    # ownership is not consumption: a page whose `ingest` raised stays owned (or the scheduler sells it
    # to us again), but its matches never reached the store and the page remainder cannot say so.
    pages_unconsumed: int = 0
    # lane-local machinery failures: ingesting a page is one lane's work on one lane's pivot, and filing
    # it globally turns a completed sibling partial. Genuinely shared failures stay on `WorkResult`.
    machinery: list = field(default_factory=list)


@dataclass
class WorkResult:
    lanes: dict = field(default_factory=dict)
    persisted: bool = True                  # completion state actually reached disk
    records_journaled: bool = True          # every completion recorded this run reported success
    stop_cause: str = ""                    # why scheduling ended — the scheduler's own answer, which
                                            # the balance alone cannot give
    machinery: list = field(default_factory=list)   # every failure of ours, in order; `stop_cause`
                                                    # keeps the first, a later one is its consequence


def observe_total(st, o, total) -> None:
    """Fold one page's reported total into the pivot — one policy for fresh and replayed pages."""
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        return
    if st.total is not None and st.total != total:
        o.total_drift += 1
    st.total = total if st.total is None else max(st.total, total)
    # a total has just become known, so this is the moment a count can be measured against it — retained
    # or fresh, one call site, no path left to forget.
    compare_count(st, o)


def _page_doc(pivot: Pivot, page: int, total, matches, *, bought_at=None, raw=None) -> dict:
    """The page as stored. `bought_at` rides inside the document, so it is digest-verified with the page."""
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
    """How old a stored page is, or None when it cannot say. An unreadable age is never fresh."""
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
    """Whether a stored page may stand in for a fresh purchase. `ttl_days <= 0` means never replay, not
    always replay."""
    age = page_age_s(doc, now=now)
    if age is None or ttl_days <= 0:
        return False
    return age <= ttl_days * 86400.0


def valid_page(doc, pivot: Pivot, page: int):
    """The recorded page, or None when the artifact does not prove what it claims — the envelope must
    identify its own pivot and page."""
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
    return not isinstance(total, bool) and isinstance(total, int) and total >= 0


def reject_reason(matches, total) -> "str | None":
    """Why a page cannot be treated as complete, or None when it can. A validator that cannot name its
    objection cannot report one."""
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
    """Whether a page may be treated as complete — one contract for fresh output and replayed evidence, rows
    included, or the coordinator would trust the network more than its own disk."""
    return reject_reason(matches, total) is None


#: bodies at or below this ride inside the rejection document, base64-encoded; anything larger gets
#: its own artifact beside it, because a paid response is kept whole
REJECTED_INLINE_LIMIT = 512 * 1024


def publish_rejected(attempt_dir, pivot: Pivot, page: int, *, reason: str, body=None,
                     matches=None, total=None, raw_path=None):
    """Keep what a paid request returned when we refuse to treat it as a page: the credit is spent, so the
    response is evidence whatever our contract says."""
    try:
        d = Path(attempt_dir) / "rejected"
        d.mkdir(parents=True, exist_ok=True)
        doc = {"schema": SHODAN_WORK_SCHEMA, "lane": pivot.lane, "facet": pivot.facet,
               "value": pivot.value, "page": page, "at": time.time(), "reason": reason,
               "owned": False}
        if raw_path is not None and Path(raw_path).is_file():
            # the complete response is already on disk, so this record points at it rather than keeping a
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
            # no raw bytes to keep (the page parsed and then failed the contract): record what we were
            # handed, best-effort, so the shape that was rejected is still inspectable.
            doc["payload"] = json.loads(json.dumps({"total": total, "matches": matches}, default=repr))
        art = d / f"{item_key(pivot, page)}.rejected.json"
        art.write_text(json.dumps(doc))
        return art
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return None


#: acquisition is committed separately from interpretation: bytes on disk is not ownership, and a
#: response we could not parse would otherwise be bought again. States and their consequences:
#: docs/design/PROVIDER-QUOTA-DESIGN.md.
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
    """Record what we bought, before anything decides whether we can read it. Returns (path, digest)."""
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
    """The receipt's raw artifact, or None when it cannot prove it is the response we paid for."""
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
            # a cheap pre-filter the digest below subsumes: it rejects a substituted artifact without
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
    """What this project can prove about pages it may have paid for. Every fact here is a reason not to
    spend."""

    by_page: dict = field(default_factory=dict)      # (lane, facet, value, page) -> receipt
    invalid: dict = field(default_factory=dict)      # item_key -> why an owned receipt is untrusted
    orphans: dict = field(default_factory=dict)      # item_key -> artifact with no ownership entry
    error: str = ""                                  # ownership could not be inspected at all


def ownership_view(base, ledger) -> OwnershipView:
    """Every ownership fact, from one enumeration of the ledger and one walk of the store. `error` is set
    when the store could not be inspected, and an uninspectable store is never empty."""
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
            # a receipt from a generation we do not speak still proves A purchase — it just may not be
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
            # filed under one identity, describing another: it proves nothing about either, and it is
            # certainly not evidence that this page was never bought.
            view.invalid[key] = "receipt is filed under a different identity than it claims"
            continue
        view.by_page[(lane, facet, value, page)] = doc

    # artifacts that survived without an ownership entry, `.part` included: a publish that lands while
    # its journal fails leaves paid bytes invisible
    root = Path(base)
    walk_errors: list = []
    files: list = []
    try:
        # `Path.rglob` silently omits a subtree it cannot read; `os.walk(onerror=…)` reports what it could
        # not enter
        for dirpath, _dirnames, filenames in os.walk(root, onerror=walk_errors.append):
            for name in filenames:
                files.append(Path(dirpath) / name)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:
        view.error = view.error or f"paid store could not be inspected: {e}"
        return view
    if walk_errors:
        # a store we cannot fully read cannot rule out a prior purchase
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
    """The committed acquisition state for one page, or None when we never bought it."""
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
    """Own what we paid for, whatever happens next: a failure to record it would have the next run buy the
    same page."""
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
    """Keep a paid response's bytes, and — when the objection is ours — count it and remember why."""
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

    `search(pivot, page) -> (matches, total, error)` never raises. A page cap bounds purchasing only,
    never what we replay or report."""
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
            # replay first, always: owned evidence contacts nobody and spends nothing, so it never waits behind
            # a cooldown that governs provider contact
            _replay_indexed(states, res, ledger=ledger, ingest=ingest, ttl_days=ttl_days)
            _apply_cardinality(states, res)
            for st in states:                      # what aging declined to buy, per lane
                res.lanes[st.pivot.lane].refresh_refused += st.refused_refresh(max_pages)
            # ...and only now is the provider consulted: `balance` is a callable, so the read and the free
            # sizing happen after replay. Never skipped when everything is owned — counting finds growth.
            if callable(balance):
                try:
                    balance = balance()
                except pace.PaceBusy as e:
                    # our boundary refused before any contact. Replay above already happened; the
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
                # a page one lane could not ingest ends purchasing, but must not skip the free sweep of pages other
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
        # in `finally`, over a snapshot: a machinery failure still reports its remainder
        try:
            _remainder(states, res, max_pages=max_pages)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            _machinery(res, e)
        # will the next run see these completions? — snapshot written or journal intact, both facts needed.
        # A save that raises did not save.
        try:
            saved = bool(ledger.save())
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            saved = False
            _machinery(res, e)
        if saved:
            res.persisted = True               # the snapshot is the durable answer; nothing else to ask
        else:
            # `durable` is the fallback for a snapshot that did not land. Reading it unconditionally
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
    """True when the page replayed from owned evidence, False when the record is unusable, None when we do
    not own it."""
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
        o.pivots_touched += 1                 # any page, not just page 1
    observe_total(st, o, doc.get("total"))
    try:
        o.matches += ingest(st.pivot, page, doc.get("matches") or [], art)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:
        # the page stays owned — dropping it would have the scheduler sell it to us again — and the
        # shortfall is counted in its own unit
        _lane_machinery(o, e)                  # raises the lane-scoped carrier
    return True


class LaneMachineryError(Exception):
    """An ingestion failure already attributed to the lane whose page it was. Scope is carried structurally,
    never parsed back out of a sentence."""

    def __init__(self, lane: str, cause: BaseException):
        super().__init__(f"{lane}: {type(cause).__name__}: {cause}")
        self.lane = lane
        self.__cause__ = cause


def _lane_machinery(o, e: BaseException):
    o.pages_unconsumed += 1
    o.machinery.append(f"{type(e).__name__}: {e}")
    raise LaneMachineryError(o.lane, e) from e


def _machinery(res, e: BaseException) -> None:
    """Record our own failure without discarding what the run established. The first cause names the stop."""
    lane_scoped = isinstance(e, LaneMachineryError)
    # the cause names the stop either way: `machinery:RuntimeError` says what actually broke, where the
    # carrier's own type would say only that we wrapped it.
    cause = e.__cause__ if lane_scoped and e.__cause__ is not None else e
    if not lane_scoped:
        # a lane-scoped fault is already filed against the lane that owns the work — see
        # `LaneOutcome.machinery`. The stop is still global (purchasing ends for everyone), the fault is not.
        res.machinery.append(f"{type(cause).__name__}: {cause}")
    res.stop_cause = res.stop_cause or f"machinery:{type(cause).__name__}"


def _replay_lane_safe(states, res, replay_one) -> None:
    """Run `replay_one` over every state, so one lane's ingestion failure cannot end the others' free
    replay."""
    # a lane's own recorded machinery is the lifecycle-wide answer to "is this sink broken", and it
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
            _machinery(res, e)                 # the lane keeps the fault; the stop is global


def _replay_indexed(states, res, *, ledger, ingest, ttl_days: float = PAGE_TTL_DAYS_DEFAULT,
                    now=None) -> None:
    """Replay every page we demonstrably own, before any scheduling: purchased evidence replays whether or
    not a policy would buy it again."""
    index = owned_index(ledger)

    def one(st, o):
        for page, art, doc in index.get((st.pivot.lane, st.pivot.facet, st.pivot.value), ()):
            if page in st.pages_done:
                continue
            if not page_fresh(doc, ttl_days=ttl_days, now=now):
                # aged, not gone: replaying a stale search page as a current result would be the eternal cache the
                # free-host lane warns about. The artifact stays owned and reportable as history.
                o.pages_aged += 1
                st.aged_pages.add(page)
                continue
            age = page_age_s(doc, now=now) or 0.0
            o.oldest_replay_s = max(o.oldest_replay_s, age)
            _replay_one(st, o, page=page, ledger=ledger, ingest=ingest, owned=(art, doc))

    _replay_lane_safe(states, res, one)


def compare_count(st, o) -> None:
    """Measure a pivot's count against its page-derived total, and keep that verdict current."""
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

    With no page-derived total the count orders the pivot and nothing else; with one, `effective_total`
    is the maximum of the two, so a pivot complete under yesterday's total discovers new results."""
    for st in states:
        compare_count(st, res.lanes[st.pivot.lane])


def _commit_page(st, o, res, *, page, matches, total, ledger, attempt_dir, ingest, raw_path=None,
                 late: bool = False) -> bool:
    """Publish one page, own it, and ingest its rows. True when the page is ours. One place for both routes
    in, so a replayed page and a bought one owe the same handshake."""
    pivot = st.pivot
    raw_meta = None
    if raw_path is not None and Path(raw_path).is_file():
        rp = Path(raw_path)
        # the reference must resolve: a bare name resolves, relative to the page document, to that document
        # itself — the doc would point at its own sibling and call it the provider's response
        try:
            ref = str(rp.relative_to(Path(attempt_dir)))
        except ValueError:
            ref = str(rp)
        raw_meta = {"raw_ref": ref, "raw_bytes": rp.stat().st_size,
                    "raw_digest": events.file_digest(rp)}
    art = Path(attempt_dir) / f"{item_key(pivot, page)}.json"
    # evidence records what the provider answered for this page; reconciliation is a derived view and
    # lives only in `PivotState`, or the drift disappears on resume
    body = json.dumps(_page_doc(pivot, page, total, matches, raw=raw_meta)).encode()
    dig = hashlib.sha256(body).hexdigest()
    # atomic + content-verified: a torn write at a content-addressed name would otherwise be reused
    # later as if it were the page we meant to buy.
    if not budget.publish_bytes(art, body, digest=dig):
        # leaving the page pending schedules it again — the same page bought over and over,
        # unbounded when the balance is unknown. A store we cannot write to is a global problem.
        o.publish_failed += 1
        st.stopped = "publish_failed"
        res.stop_cause = "publish_failed"
        return False
    if not st.pages_done:
        o.pivots_touched += 1                 # any page counts as touching the pivot
    st.pages_done.add(page)
    if not late:
        o.pages_bought += 1
    journaled = ledger.record(item_key(pivot, page), art, digest=dig)
    # the page doc proves we can read it; the receipt proves we bought it
    acq_journaled = commit_acquisition(o, ledger, attempt_dir, pivot, page, state=ACQ_PARSED,
                                       raw_path=raw_path)
    if raw_meta is not None:
        # evidence, not the completion artifact: replay reads the page doc, this is what arrived
        try:
            ledger.add_evidence(item_key(pivot, page), Path(raw_path), digest=raw_meta["raw_digest"])
        except Exception as e:
            _lane_machinery(o, e)
    # a readable journal proves old content survives, not that this page reached it.
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
    # an untrusted index is not an empty one: nothing is bought until an operator resolves it, and
    # replay has already taken whatever could be proven
    unreadable = getattr(ledger, "unreadable", "")
    if unreadable:
        res.stop_cause = res.stop_cause or f"ownership_unreadable:{unreadable}"
        return
    spendable = balance.spendable
    if not balance.may_spend:
        spendable = 0
    reserve = int(getattr(balance, "reserve", 0) or 0)
    spent = 0
    # a page is purchased at most once per run, whatever else goes wrong. Unfalsifiable while every
    # path is correct, and kept because of what it bounds: an unbounded spend of real money.
    tried: set = set()
    probed: list = []
    # every ownership fact, from one enumeration and one walk (see `ownership_view`)
    own = ownership_view(Path(ledger.path).parent, ledger)
    if own.error:
        # unknown is not empty. An ownership store we could not inspect cannot rule out a prior
        # purchase, so nothing is bought until an operator can say what is in it.
        res.stop_cause = res.stop_cause or f"ownership_uninspectable:{own.error}"
        return
    acquired = own.by_page

    def sinks_ok() -> bool:
        """Prove both sinks once, immediately before the first purchase: buying what we cannot record means
        paying twice."""
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
            # owned evidence is free and is taken whatever the budget says — replay never spends.
            replayed = _replay_one(st, o, page=page, ledger=ledger, ingest=ingest)
            if replayed:
                progressed = True
                continue
            # paid for, and the artifact no longer verifies. "Gone" is not an authorisation: buying it again is
            # a fresh charge, refused on the terms an aged page is, and every valid receipt blocks acquisition.
            acq = acquired.get((st.pivot.lane, st.pivot.facet, st.pivot.value, page))
            if acq is not None:
                state = acq.get("state")
                # bytes we already own may only be interpreted once they prove they are the bytes we
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
                st.lost_pages.add(page)          # never scheduled again: it is bought, not missing
                continue
            # an owned receipt we cannot validate is untrusted ownership evidence — never an absence
            if item_key(st.pivot, page) in own.invalid:
                o.acquisition_invalid += 1
                o.acquisition_refused += 1
                st.lost_pages.add(page)
                continue
            # a receipt or a paid response on disk with no ownership entry is not "never bought"
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
                # is a defect and must read as one rather than ending the loop with no cause
                res.stop_cause = "scheduler_invariant"
                continue
            if not sinks_ok():
                break                                     # nothing paid for yet; stop_cause is set
            tried.add(attempt)
            try:
                matches, total, err = search(st.pivot, page)
            except pace.PaceBusy as e:
                # no request was issued, so no credit moved: "contact refused" stays distinct from "request issued"
                # all the way through accounting, and purchasing ends
                o.pace_refused += 1
                st.stopped = PACE_BUSY
                res.stop_cause = res.stop_cause or f"{PACE_BUSY}:{e}"
                tried.discard(attempt)
                break
            except contract.AcquisitionBudgetExhausted as e:
                # our disk governor issued NO request: no credit moved and nothing to own, kept distinct
                # from pacing and from a provider limit
                o.budget_refused += 1
                st.stopped = "disk_budget"
                res.stop_cause = res.stop_cause or f"disk_budget:{e.layer}"
                tried.discard(attempt)
                break
            spent += 1                                    # a request was issued — that is the credit
            st.attempted = True
            progressed = True
            if err is not None:
                cls = getattr(err, "error_class", None) or "error"
                # the body is kept for every provider error, but only a `parse` failure is an objection of ours,
                # so only that one moves the rejection counters
                err_raw = getattr(err, "raw_path", None)
                note_rejected(o, st.pivot, page, reason=f"{cls}: {err}", attempt_dir=attempt_dir,
                              body=getattr(err, "body_bytes", None), raw_path=err_raw,
                              count=(cls in ("parse", "oversize", "incomplete", "truncated")))
                # the receipt is committed here, before any judgement about readability: bytes on disk is not
                # ownership, and a response published only as a rejection is bought again by the next run
                if err_raw is not None and Path(err_raw).is_file():
                    # a policy `truncated` partial is owned exactly like a transport `incomplete` one
                    state = ACQ_INCOMPLETE if cls in ("incomplete", "truncated") else (
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
                # first position = this pivot has no page at all yet, so the error cost us the whole
                # pivot. Otherwise page-1 evidence is already kept and only a later page was lost.
                if not st.pages_done:
                    pos = o.first_limit_classes if limit else o.first_fail_classes
                else:
                    pos = o.later_limit_classes if limit else o.later_fail_classes
                pos[cls] = pos.get(cls, 0) + 1
                if is_limit(cls):
                    # degrade, don't disable: stop buying, keep everything already earned, leave the rest
                    # as a counted remainder. The provider's boundary ends purchasing, not the run.
                    res.stop_cause = f"provider_limit:{cls}"
                elif should_stop(cls):
                    # a failure further requests cannot get past — a refused credential, persistent throttling.
                    # Purchasing ends; the class is untouched, so this reads as the gap it is.
                    res.stop_cause = f"provider_stop:{cls}"
                continue
            why = reject_reason(matches, total)
            if why is not None:
                # the provider answered, but not with something we can call a page. The credit is gone;
                # the response is not — it is written outside the ledger and the objection is recorded.
                st.stopped = "parse"
                o.fail_classes["parse"] = o.fail_classes.get("parse", 0) + 1
                # bind the complete response rather than a reconstructed, truncated copy
                rejected_raw = Path(attempt_dir) / "raw" / f"{item_key(st.pivot, page)}.json"
                note_rejected(o, st.pivot, page, reason=why, attempt_dir=attempt_dir,
                              matches=matches, total=total,
                              raw_path=rejected_raw if rejected_raw.is_file() else None)
                if rejected_raw.is_file():
                    # the receipt is this page's only ownership record — there is no completion behind
                    # it — so a lost one is a purchase the next run repeats
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
                # who stopped us: a positive reserve means the operator withheld the rest;
                # a zero reserve means the provider's balance is simply the boundary.
                res.stop_cause = "budget_reserve" if reserve > 0 else "budget_provider"
            break


def _sweep_owned(states, res, *, ledger, ingest, max_pages) -> None:
    """Replay owned pages that an operator page policy excluded from purchasing: `max_pages` bounds what we
    buy, never what we report."""
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

    _replay_lane_safe(states, res, one)          # the same per-lane rule: owned evidence is free


def _remainder(states, res, *, max_pages) -> None:
    # a snapshot, not an accumulator: this is reachable twice, and `+=` would double the remainder
    for o in res.lanes.values():
        o.unqueried = []
        o.pages_left_known = 0
        o.pages_left_unknown_pivots = 0
        o.pages_withheld = 0
    for st in states:
        o = res.lanes[st.pivot.lane]
        # "never reached" is not "asked and refused": a pivot whose only page died on a quota was queried, so
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
# who stopped us decides the kind, and collapsing any two lets a broken run report
# `complete_with_limits`. The mapping: docs/design/PROVIDER-QUOTA-DESIGN.md.
def _unqueried_kind(balance, stop_cause: str = "") -> str:
    """The kind for work we never reached, decided by who stopped us. The scheduler's own answer wins."""
    from .phases.probe import (SHODAN_ENTITLEMENT, SHODAN_OPERATOR_RESERVE, SHODAN_PROVIDER_EXHAUSTED,
                               SHODAN_UNKNOWN_WITH_RESERVE)
    if stop_cause:
        if stop_cause == "budget_reserve":
            return events.COVERAGE_SAMPLE                # the operator withheld the rest
        if stop_cause == "budget_provider" or stop_cause.startswith("provider_limit:"):
            return events.COVERAGE_PROVIDER              # the provider's balance was the boundary
        # `provider_stop:*` is a failure we stopped requesting through: a gap, never a soft limit. The rest
        # are ours, and only `pace_busy` is not a defect.
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
    """Structured coverage for one lane, emitted every lifecycle so a later complete run clears a prior
    remainder."""
    kind = _unqueried_kind(balance, stop_cause)
    unq = len(outcome.unqueried)
    # the scheduler's own answer comes first; the balance is the fallback for stops settled before any
    # work began
    why = stop_cause or getattr(balance, "reason", "")
    events.coverage_partial(lane, kind=kind, measure="shodan_pivots_unqueried",
                            unit=f"{lane}.unqueried", eligible=outcome.pivots,
                            tested=outcome.pivots - unq, omitted=unq,
                            reason=(f"{unq}/{outcome.pivots} pivot(s) never queried — {why}" if unq else
                                    f"all {outcome.pivots} pivot(s) queried"))
    # pages are counted only where the total is known. A pivot we never bought a page for has no knowable
    # page count, and an invented denominator is the same class of lie as an unmeasured zero.
    done = outcome.pages_bought + outcome.pages_replayed
    # known pages left after a per-pivot failure are a gap, not a provider limit: nothing about the
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
    # an owned page whose ingestion failed is out of the page remainder — nothing else in
    # this report can say its rows are missing. Emitted every lifecycle so a later clean run clears it.
    unc = outcome.pages_unconsumed
    events.coverage_partial(lane, kind=events.COVERAGE_TIMEOUT, measure="shodan_pages_unconsumed",
                            unit=f"{lane}.pages_unconsumed", eligible=done, tested=done - unc,
                            omitted=unc,
                            reason=(f"{unc}/{done} owned page(s) could not be ingested — their rows are "
                                    f"NOT in the store" if unc else
                                    f"every one of {done} owned page(s) was ingested"))
    # position x cause, four measures, each naming only its own position's classes: without them a run
    # stopped dead by quota folds as `complete`. The matrix: docs/design/PROVIDER-QUOTA-DESIGN.md.
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
    # what we bought vs what we could read. A page whose bytes we own but could not parse is coverage we
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
    # a paid response we refused, in its own measure: an objection about a page's shape is not a pivot
    # that failed. Emitted every lifecycle, because the credit is spent either way.
    rej = outcome.pages_rejected
    events.coverage_partial(lane, kind=events.COVERAGE_TIMEOUT, measure="shodan_pages_rejected",
                            unit=f"{lane}.pages_rejected", eligible=done + rej, tested=done, omitted=rej,
                            reason=(f"{rej} paid response(s) refused as unusable — "
                                    + "; ".join(outcome.reject_reasons) if rej else
                                    "no paid response was refused"))
    # the index is live, so two pages of one pivot can report different totals. The maximum is kept, so
    # this is telemetry about the provider's denominator, not a boundary: `omitted=0`.
    drift_of = max(1, done)
    events.coverage_partial(lane, kind=events.COVERAGE_PROVIDER, measure="shodan_total_drift",
                            unit=f"{lane}.total_drift", eligible=drift_of, tested=drift_of, omitted=0,
                            reason=(f"{outcome.total_drift} of {done} page(s) reported a total that "
                                    f"disagreed with another page of the same pivot — the provider's "
                                    f"index moved; the LARGEST total is kept, so NOTHING is omitted"
                                    if outcome.total_drift
                                    else "every page agreed on its pivot's total"))
    # our page policy is a cap, not a sample: a soft sample would let a run that never looked past page 1
    # call itself complete. A hard ceiling we imposed reads as a gap whenever it withheld anything.
    events.coverage_partial(lane, kind=events.COVERAGE_CAP, measure="shodan_pages_withheld",
                            unit=f"{lane}.pages_withheld", eligible=done + outcome.pages_withheld,
                            tested=done, omitted=outcome.pages_withheld,
                            reason=(f"{outcome.pages_withheld} page(s) withheld by SHODAN_MAX_PAGES="
                                    f"{max_pages}" if outcome.pages_withheld
                                    else "no page withheld by an operator page policy"))
    # failures are gaps — including the balance read itself, which may have failed while an operator
    # limit was the thing that stopped us. both facts must survive to reconciliation.
    from .contract import is_provider_limit as _is_limit
    fails = sum(outcome.fail_classes.values()) + outcome.evidence_invalid + outcome.publish_failed
    read_err = getattr(balance, "read_error", None)
    # a balance read refused by the provider is a limit like any other: counting every `read_error` as a
    # failure makes a depleted account emit a gap from the balance probe while its pivots report a limit
    read_limited = bool(read_err) and _is_limit(read_err)
    if read_err and not read_limited:
        fails += 1
    # a credential refused by the free count endpoint is a failure of this run's ability to work at all,
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
