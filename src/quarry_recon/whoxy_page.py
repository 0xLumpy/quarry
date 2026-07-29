"""B1.6 — the Whoxy reverse-whois PAGINATOR.

Whoxy-local by design. It reuses Quarry's provider VOCABULARY (the outcome taxonomy, the bounded-lane
ordering rule, `budget.Ledger`) but not the Shodan coordinator's machinery: `OsintSession` is a different
execution world from the phase runner, and shared transport is earned by matching contracts, not assumed.

MEASURED 2026-07-29, both query forms (`company` and `email`), identical in every respect that matters:

    page 1 of a 39,766-result anchor:  {"status": 1, "api_query": "reverse_whois",
                                        "search_identifier": {"company": "<verbatim>"},
                                        "total_results": "39766",   <- a STRING when non-empty
                                        "total_pages": 398, "current_page": 1,
                                        "search_result": [ ...100 rows... ]}
    one page past the end:             {"status": 0, "status_reason": "Invalid Page Number"}   COST 0
    account=balance:                    FREE (two consecutive reads, no change)

Three facts drive the whole design:

  · ONE CREDIT PER PAGE. A single anchor at 398 pages can drain a 200-credit account, so pages are
    ordered PAGE TIER FIRST — page 1 of every anchor before page 2 of any — and whatever a budget does
    not reach is a counted, RESUMABLE remainder. Ranking decides order, never membership.
  · CARDINALITY IS FREE. `total_pages` arrives with page 1, so ordering rare anchors first costs nothing
    extra. Unlike Shodan there is no sizing pass to build.
  · `total_pages` IS AUTHORITATIVE. Past-end is `status: 0`, which classifies as a plain `error`, so a
    paginator that probed for the end would turn a clean completion into a provider failure.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from . import budget

#: bump when the stored page ARTIFACT's meaning changes — it is part of every page's identity, so a bump
#: deliberately re-buys every page. The row SHAPE differs between query forms (the email form carries
#: registrant/administrative contacts, the company form carries create_date/domain_status), but that is
#: the provider's own variation within one schema, not a change in what we store.
WHOXY_WORK_SCHEMA = 1
WHOXY_PAGE_SIZE = 100          # measured: 100 rows/page on both query forms


@dataclass(frozen=True)
class Anchor:
    """One reverse-whois question: `param` is `company` or `email`, `value` is what we ask about."""

    param: str
    value: str


def error_key(anchor: Anchor, page: int) -> str:
    """Identity of a FAILED page's response body. A distinct namespace from `item_key`, so a retained
    explanation can never be mistaken for a page we own."""
    raw = f"{WHOXY_WORK_SCHEMA}|{anchor.param}|{anchor.value}|p{page}|error"
    return hashlib.sha256(raw.encode()).hexdigest()


def item_key(anchor: Anchor, page: int) -> str:
    """The per-PAGE completion identity: (schema, param, value, page).

    The BUDGET and the RESERVE are deliberately absent. They govern how much we are willing to spend,
    not what a page contains — a page bought under reserve 50 is byte-identical to one bought under
    reserve 0, so folding either in would make changing an operator's spending policy re-buy pages that
    were already paid for."""
    raw = f"{WHOXY_WORK_SCHEMA}|{anchor.param}|{anchor.value}|p{page}"
    return hashlib.sha256(raw.encode()).hexdigest()


@dataclass
class AnchorState:
    """What we know about one anchor's pagination, within a lifecycle."""

    anchor: Anchor
    total_pages: "int | None" = None     # from the provider, with page 1 — never invented
    total_results: "int | None" = None
    pages_done: set = field(default_factory=set)
    attempted: bool = False
    stopped: str = ""                    # the error class that ended this anchor, if any
    _cursor: int = 1

    def next_page(self) -> "int | None":
        """The lowest page still owed, or None.

        Page 1 is always owed first, and until it answers we have no page count — so exactly one page is
        offered for an unopened anchor. `total_pages` then bounds the walk: it is authoritative, and
        asking past it costs nothing but classifies as a provider failure."""
        if self.stopped:
            return None
        while self._cursor in self.pages_done:
            self._cursor += 1
        if self.total_pages is None:
            return self._cursor if self._cursor == 1 else None
        return self._cursor if self._cursor <= self.total_pages else None

    def pages_left(self) -> int:
        """Pages this anchor is known to hold and we do not own. 0 while the count is unknown — an
        unopened anchor has no knowable page count, and inventing one is the same class of lie as an
        unmeasured zero."""
        if self.total_pages is None:
            return 0
        return max(0, self.total_pages - sum(1 for p in self.pages_done if p <= self.total_pages))


def usable_page_count(total_pages, total_results) -> "int | None":
    """`total_pages`, accepted only when the provider's own two fields AGREE.

    MEASURED on both query forms: `total_pages == ceil(total_results / 100)` (39766 -> 398, 355 -> 4).
    That is a checkable contract, and checking it matters because `total_pages` is the ONLY thing that
    terminates an unbounded walk — a corrupted or absurd value would have us paginate, and PAY, for as
    long as it says to. Two fields that disagree are drift: the page is NOT owned (it is kept as
    evidence and stays retryable, so a transient contradiction cannot become permanent — see
    `classify_page`), and the run reports it rather than spending against a number it cannot
    corroborate."""
    if isinstance(total_pages, bool) or not isinstance(total_pages, int) or total_pages < 1:
        return None
    if not isinstance(total_results, int) or isinstance(total_results, bool) or total_results < 0:
        return None                                  # no corroboration -> not usable as a bound
    expected = max(1, -(-total_results // WHOXY_PAGE_SIZE))
    return total_pages if total_pages == expected else None


#: how a validated success body describes its own place in a walk.
PAGE_PAGED = "paged"           # carries corroborated pagination -> the walk continues to `pages`
PAGE_TERMINAL = "terminal"     # the MEASURED compact ZERO-result answer -> exactly one page
PAGE_CONTRADICTORY = "bad"     # pagination fields that do not corroborate -> not a page we can own


def classify_page(doc) -> tuple:
    """`(kind, pages)` for a success body.

    review-B1.6r2#3: a body whose pagination fields contradicted each other was still RECORDED as a
    completion, so the anchor owned a page it could not size — and because owning it stopped the page
    being re-bought, it could never repair itself. A contradictory count keeps the bytes as evidence and
    the page stays owed.

    The MEASURED compact no-match carries no `total_pages` and no `current_page` at all, AND a
    `total_results` of zero. That is not drift, it is the whole answer: one page, nothing more to walk.

    review-B1.6r3#1: "no pagination fields" alone was far wider than the measurement. A body claiming 250
    results, returning 100 rows and simply omitting its pagination became an owned one-page completion
    with no remainder — 150 results silently dropped, by a body we have never seen. Terminal means the
    compact ZERO shape and nothing else."""
    if not isinstance(doc, dict):
        return PAGE_CONTRADICTORY, None
    if "total_pages" not in doc and "current_page" not in doc:
        total = doc.get("total_results_int")
        rows = doc.get("search_result")
        if total == 0 and not isinstance(total, bool) and not rows:
            return PAGE_TERMINAL, 1
        return PAGE_CONTRADICTORY, None
    pages = usable_page_count(doc.get("total_pages"), doc.get("total_results_int"))
    return (PAGE_PAGED, pages) if pages is not None else (PAGE_CONTRADICTORY, None)


def read_page(artifact):
    """The PRODUCTION reader: a stored page, strictly validated, reporting WHICH page it is.

    `-> {"anchor", "page", "doc"} | None`. Whoxy pages identify themselves — `search_identifier` echoes
    the question verbatim on every page (MEASURED on both query forms) — so one reader serves ownership
    enumeration and the check on a page just bought.

    Validation is `contract`'s, not a second parser: `whoxy_envelope` for the status envelope and
    `whoxy_reverse_page` for the row, cardinality and page-position contract. The identity is read from
    the body FIRST and then handed back to that validator, so the body must agree with itself.

    review-B1.6r3: the paginator's own tests used a permissive stand-in, which is what let a body with
    250 results and no pagination pass as a terminal page. A test reader that is laxer than production
    hides exactly the defects the tests exist to find."""
    from .contract import ProviderBodyError, whoxy_envelope, whoxy_reverse_page
    try:
        body = json.loads(artifact.read_text())
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    # review-B1.6r6: the endpoint check lived here AND in `whoxy_reverse_page`. One rule, one authority
    # — the parser owns it, and this reader consumes that contract. What happens here is IDENTITY
    # DISCOVERY, not enforcement: the body is asked who it answers, and the parser is then asked to agree.
    ident = body.get("search_identifier")
    if not isinstance(ident, dict) or len(ident) != 1:
        return None
    (param, value), = ident.items()
    if param not in ("company", "email") or not isinstance(value, str) or not value.strip():
        return None
    # THE TERMINAL-PAGE CONTRACT: the measured compact answer carries no position of its own, and is only
    # ever a coherent answer to page 1 (the rule B0 settled for the envelope). Everything else must name
    # its own page.
    if "current_page" not in body and "total_pages" not in body:
        page = 1
    else:
        page = body.get("current_page")
        if isinstance(page, bool) or not isinstance(page, int) or page < 1:
            return None
    try:
        rows, total, _truncated = whoxy_reverse_page(whoxy_envelope(body), page=page,
                                                     param=param, value=value)
    except ProviderBodyError:
        return None
    doc = dict(body)
    doc["total_results_int"] = total
    doc["rows"] = rows
    return {"anchor": Anchor(param, value), "page": page, "doc": doc}


def dedupe(states: "list[AnchorState]") -> "list[AnchorState]":
    """One state per (param, value). Two states for the same anchor would both buy page 1: a round is
    computed before either records completion, so the duplicate is invisible to any in-flight guard."""
    seen: set = set()
    out = []
    for st in states:
        k = (st.anchor.param, st.anchor.value)
        if k in seen:
            continue
        seen.add(k)
        out.append(st)
    return out


def _rank(st: AnchorState):
    """Ordering position for an anchor's cardinality: fewest pages first, unknown last.

    A rare anchor yields a complete answer for fewer credits, so it goes first. An UNOPENED anchor has no
    count yet — it sorts last within its tier, which costs it nothing, because page 1 of every anchor is
    in tier 1 and every anchor therefore gets opened before any second page is bought."""
    return (0, st.total_pages) if st.total_pages is not None else (1, 0)


def schedule(states: "list[AnchorState]") -> list:
    """The next round of work: at most one page per anchor, PAGE TIER first, fair across anchors.

    `order_ranked_fair` buckets by rank and round-robins within a bucket, so the rank must be the PAGE
    alone — putting cardinality in the rank would give almost every anchor its own tier and collapse
    fairness into a global cardinality sort (the B1.5 lesson). Pre-sorting instead keeps the tier on the
    page while ordering rare anchors first inside it.

    The GROUP is the anchor TYPE, not the anchor. Grouping by anchor made every anchor its own group, and
    `order_fairly` visits groups in SORTED KEY ORDER — so the round-robin re-sorted them alphabetically
    and threw the cardinality pre-sort away. Cross-anchor fairness is already guaranteed by the page
    tier (one page per anchor per round); what the group buys is fairness between the two QUESTION
    FORMS, so a scope with fifty company anchors cannot starve its registrant-email anchors."""
    pending = [(st, st.next_page()) for st in states]
    pending = [(st, pg) for st, pg in pending if pg is not None]
    pending.sort(key=lambda it: (it[1], _rank(it[0]), it[0].anchor.param, it[0].anchor.value))
    return budget.order_ranked_fair(pending, rank=lambda it: it[1],
                                    group=lambda it: it[0].anchor.param)


@dataclass(frozen=True)
class SpendPolicy:
    """How many pages this run may buy, and whether the controls themselves were usable.

    review-B1.6r1#5: the controls were coerced with `int()` and clamped, so `run_budget=-1` became 0 —
    which MEANS "no operator ceiling" — i.e. a typo in a spending control granted permission to spend the
    whole balance. A negative reserve disabled the reserve, and `True` was accepted as 1. A cost guard
    that fails OPEN is worse than none: invalid controls now stop paid work and are reported as the
    configuration defect they are."""

    pages: "int | None" = None       # None = no computable bound
    invalid: str = ""                # which OPERATOR control is unusable, if any
    balance_invalid: str = ""        # the PROVIDER's balance was unreadable as a number


def _exact_count(v) -> "int | None":
    """An exact non-negative int. `bool` is excluded — it is an int subclass, and `True` is not a count."""
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        return None
    return v


def spend_policy(balance: "int | None", reserve, run_budget) -> SpendPolicy:
    """The settled spending contract. See `spendable` for the arithmetic.

    review-B1.6r2#2: the operator's controls were validated and the PROVIDER's balance was not, though it
    is the least trustworthy of the three — it arrives over the network. `int()` turned `"200"` into 200
    pages, `True` into 1, `12.5` into 12, and `-1` into a silent zero with no fact recorded. Unknown is
    allowed (a balance we could not read is not a balance of zero); anything else must be exact."""
    res, run = _exact_count(reserve), _exact_count(run_budget)
    bad = [n for n, v in (("WHOXY_CREDIT_RESERVE", res), ("WHOXY_PAGE_BUDGET", run)) if v is None]
    # review-B1.6r3#4: a malformed BALANCE is provider schema drift, not a broken operator setting.
    # Reporting it as configuration would send an operator to fix a knob that is perfectly correct.
    bal_bad = "" if (balance is None or _exact_count(balance) is not None) else \
        f"provider balance {balance!r} is not an exact count"
    if bad or bal_bad:
        return SpendPolicy(pages=0, invalid=", ".join(bad), balance_invalid=bal_bad)
    return SpendPolicy(pages=spendable(balance, res, run))


def spendable(balance: "int | None", reserve: int, run_budget: int) -> "int | None":
    """How many pages this run may buy. None = no computable bound (the balance is unknown).

    Two controls, two problems: the RESERVE protects credits for manual or later use, the RUN BUDGET
    limits this invocation. Effective spend is bounded by both, and `0` means "no operator ceiling" for
    each — the established rule.

    An UNKNOWN balance is not zero — with no reserve and no run budget there is nothing to compute a
    bound from, and refusing to work would turn "we could not read the balance" into "there are no
    credits". But an unknown balance WITH a reserve is contradictory (the B1.2 rule, settled for Shodan):
    a reserve says "keep N credits back", and we cannot honour that without knowing how many there are.
    Our own caution stops us, and it is an OPERATOR limit — not the provider refusing."""
    res = max(0, int(reserve or 0))
    run = max(0, int(run_budget or 0))
    if balance is None:
        if res:
            return 0                             # cannot honour a reserve against an unknown balance
        return run or None
    available = max(0, int(balance) - res)
    return min(available, run) if run else available


@dataclass
class Outcome:
    """What a lifecycle did. Every field is a FACT the caller reports; none is a threshold."""

    anchors: int = 0
    anchors_touched: int = 0            # at least one page bought or replayed
    pages_bought: int = 0
    pages_replayed: int = 0
    domains: int = 0
    fail_classes: dict = field(default_factory=dict)
    limit_classes: dict = field(default_factory=dict)
    unopened: list = field(default_factory=list)     # EXACT anchors, never a count alone
    pages_left_known: int = 0
    pages_left_unknown_anchors: int = 0
    evidence_invalid: int = 0           # a recorded page whose artifact no longer validates
    publish_failed: int = 0
    total_drift: int = 0                # pages whose total disagreed with another page of the anchor
    requests_issued: int = 0            # requests SENT on the paid endpoint. NOT a credit count: the
                                        # measured past-end refusal cost nothing, and what a transport
                                        # failure or a refusal bills is unknown. The allowance is
                                        # decremented per attempt (conservative), but only the provider
                                        # balance says what was actually charged (review-B1.6r2#4)
    error_bodies: int = 0               # non-empty failure bodies retained as evidence
    records_journaled: bool = True      # every LEDGER WRITE this run reported success — completions and
                                        # evidence binds alike, since both must survive for the run to
                                        # be resumable and for its evidence to be findable
    config_invalid: str = ""            # OPERATOR spending controls that could not be used
    balance_invalid: str = ""           # the PROVIDER's balance was not a readable count
    stop_cause: str = ""
    persisted: bool = True


def owned_index(ledger, read) -> dict:
    """Pages the ledger demonstrably owns, per anchor: {(param, value): [(page, artifact, doc)]}.

    review-B1.6r1#1: this probed upward from page 1 and STOPPED at the first hole, so damaging page 1
    made pages 2 and 3 invisible and they were bought again — paid evidence lost to a gap above it.
    `Ledger.items()` already enumerates every digest-validated completion, and a Whoxy page identifies
    ITSELF (`search_identifier` echoes the question verbatim, `current_page` names the page), so one pass
    recovers a hole of any width. The identity is recomputed from the document and must match the key it
    was filed under: that is what stops a transplanted artifact donating ownership."""
    out: dict = {}
    for item, art in ledger.items():
        ident = read(art)
        if ident is None:
            continue
        anchor, page = ident["anchor"], ident["page"]
        if item_key(anchor, page) != item:
            continue
        # review-B1.6r3#2: enumeration accepted anything the reader could identify, so a digest-valid
        # CONTRADICTORY completion replayed for free and stayed permanently unsized. Fresh output and
        # replayed evidence owe the same contract — the Shodan lesson, again.
        if classify_page(ident["doc"])[0] == PAGE_CONTRADICTORY:
            continue
        out.setdefault((anchor.param, anchor.value), []).append((page, art, ident["doc"]))
    for v in out.values():
        v.sort(key=lambda e: e[0])
    return out


def run_pages(states, *, spend, fetch, ingest, read, ledger, attempt_dir, is_limit=None) -> Outcome:
    """Buy pages under the budget, replaying anything already owned.

    `fetch(anchor, page) -> (raw_bytes, error)` returns the provider's EXACT response bytes, and never
    raises. `read(artifact) -> {"anchor", "page", "doc"} | None` validates a stored page and reports WHICH
    page it is — a Whoxy page identifies itself, and one self-identifying reader serves both ownership
    enumeration and the check on a page we just bought. `ingest(anchor, page, doc, artifact) -> int`
    turns it into candidates and returns how many domains it yielded.

    `spend` is the page allowance from `spend_policy()`; None means no computable bound."""
    from .contract import is_provider_limit as _default_is_limit
    is_limit = is_limit or _default_is_limit
    states = dedupe(states)
    o = Outcome(anchors=len(states))
    try:
        _replay(states, o, ledger=ledger, ingest=ingest, read=read)
        _buy(states, o, spend=spend, fetch=fetch, ingest=ingest, read=read, ledger=ledger,
             attempt_dir=attempt_dir, is_limit=is_limit)
        _remainder(states, o)
    finally:
        # persistence is this function's job and its RESULT is a fact: a ledger we could not write leaves
        # every page bought this run to be bought again, and the caller must be able to say so.
        # review-B1.6r1#2: `saved or durable` called a page persisted when the checkpoint had journaled,
        # the page's own append had failed, and compaction failed too — every signal survivable while the
        # page reached NEITHER destination. The journal branch needs both facts.
        saved = bool(ledger.save())
        o.persisted = saved or (bool(getattr(ledger, "durable", False)) and o.records_journaled)
    return o


def _take(st, o, *, page, art, doc, ingest, replayed: bool) -> None:
    """Fold one validated page into the state and the outcome, however it was obtained."""
    first = not st.pages_done
    st.pages_done.add(page)
    st.attempted = True
    if first:
        o.anchors_touched += 1
    # review-B1.6r1#4: totals were adopted only while unknown, so page 1 saying 200 and page 2 saying
    # 300 left the walk bounded by the FIRST answer — two pages fetched, no remainder reported, the rest
    # silently uncollected. Every page is reconciled, MAX-WINS so the remainder is never understated, and
    # a disagreement is a fact about the provider's index rather than something to absorb.
    seen_total = doc.get("total_results_int")
    _kind, seen_pages = classify_page(doc)
    if isinstance(seen_total, int) and not isinstance(seen_total, bool):
        if st.total_results is not None and st.total_results != seen_total:
            o.total_drift += 1
        st.total_results = seen_total if st.total_results is None else max(st.total_results, seen_total)
    if seen_pages is not None:
        st.total_pages = seen_pages if st.total_pages is None else max(st.total_pages, seen_pages)
    if replayed:
        o.pages_replayed += 1
    else:
        o.pages_bought += 1
    o.domains += ingest(st.anchor, page, doc, art)


def _replay(states, o, *, ledger, ingest, read) -> None:
    """Replay every owned page BEFORE any scheduling, so a resumed run spends nothing on what it holds
    and still ingests it — the candidates belong to THIS run's report as much as the run that paid."""
    index = owned_index(ledger, read)
    for st in states:
        for page, art, doc in index.get((st.anchor.param, st.anchor.value), ()):
            if page in st.pages_done:
                continue
            _take(st, o, page=page, art=art, doc=doc, ingest=ingest, replayed=True)


def _keep_evidence(o, ledger, attempt_dir, key, raw) -> bool:
    """Retain bytes as EVIDENCE, never a completion, under the same durability handshake as a page.

    review-B1.6r2#1: `add_evidence` was called and its result thrown away, so an evidence bind could fail
    while the run reported `error_bodies=2` and `persisted=True` — and a reopened ledger held nothing.
    A ledger write is a ledger write: if this one did not land, neither will the next, and continuing to
    pay for pages we cannot bind is the same defect as continuing without a journal.

    Returns "" on success, else WHICH sink failed — review-B1.6r3#3: the caller collapsed both into one
    cause, and then a simultaneous provider limit overwrote it entirely."""
    art = attempt_dir / f"{key}.json"
    dig = hashlib.sha256(raw).hexdigest()
    if not budget.publish_bytes(art, raw, digest=dig):
        o.publish_failed += 1
        return "publish_failed"
    if not ledger.add_evidence(key, art, digest=dig):
        o.records_journaled = False
        return "ledger_unwritable"
    return ""


def _buy(states, o, *, spend, fetch, ingest, read, ledger, attempt_dir, is_limit) -> None:
    spent = 0
    tried: set = set()
    probed: list = []

    def sinks_ok() -> bool:
        """Prove BOTH sinks once, immediately before the first purchase.

        Buying what we cannot record means paying twice: this run spends, the next run spends again. The
        flags alone are not a precondition — nothing SETS them until a write has already failed — so
        `checkpoint()` performs a real, state-free, replay-safe write and `store_writable` publishes and
        removes a probe through the same primitive a page uses.

        review-B1.6r1#3: only the ledger was probed, so a read-only artifact store was discovered by
        paying for a page and then failing to store it. LAZY and memoized: a run that buys nothing
        (a full replay, no work, a zero budget) probes neither sink, because it needs neither."""
        if not probed:
            if not (ledger_writable(ledger) and ledger.checkpoint()):
                o.stop_cause = "ledger_unwritable"
                probed.append(False)
            elif not budget.store_writable(attempt_dir):
                o.stop_cause = "publish_failed"
                probed.append(False)
            else:
                probed.append(True)
        return probed[0]
    while not o.stop_cause:
        round_items = schedule(states)
        if not round_items:
            break
        progressed = False
        for st, page in round_items:
            if o.stop_cause:
                break
            if spend is not None and spent >= spend:
                continue                                  # no credit for this page; the remainder reports it
            attempt = (st.anchor.param, st.anchor.value, page)
            if attempt in tried:
                o.stop_cause = "scheduler_invariant"       # the scheduler offered a page it already sold us
                continue
            if not sinks_ok():
                break                                      # nothing paid for yet; stop_cause is set
            tried.add(attempt)
            raw, err = fetch(st.anchor, page)
            o.requests_issued += 1
            spent += 1              # the ALLOWANCE is decremented per attempt, conservatively: we
                                    # cannot know what was billed until the balance is read again
            st.attempted = True
            progressed = True
            if err is not None:
                cls = getattr(err, "error_class", None) or "error"
                st.stopped = cls
                # review-B1.6r1#6: the response bytes were discarded whenever an error was present — and
                # Whoxy reports failure INSIDE an HTTP 200 status envelope, so that is exactly where the
                # explanation lives. Retained as EVIDENCE, never a completion: the page is still owed.
                if raw:
                    why = _keep_evidence(o, ledger, attempt_dir, error_key(st.anchor, page), raw)
                    if why:
                        # OUR storage failed: the response is lost, whatever the provider also said.
                        o.stop_cause = why
                    else:
                        o.error_bodies += 1
                bucket = o.limit_classes if is_limit(cls) else o.fail_classes
                bucket[cls] = bucket.get(cls, 0) + 1
                if is_limit(cls) and not o.stop_cause:
                    # DEGRADE, don't disable: stop buying, keep what is earned, count the rest. A storage
                    # failure already recorded is OURS and outranks it — the provider's boundary explains
                    # why we stopped asking, not why we lost the answer (review-B1.6r3#3).
                    o.stop_cause = f"provider_limit:{cls}"
                continue
            dig = hashlib.sha256(raw).hexdigest()
            art = attempt_dir / f"{item_key(st.anchor, page)}.json"
            # the provider's EXACT bytes, published atomically and content-verified before they are
            # trusted. Never reserialized: a page we re-encode is our account of the answer, not the
            # answer, and PII fields we do not parse must survive verbatim.
            if not budget.publish_bytes(art, raw, digest=dig):
                o.publish_failed += 1
                st.stopped = "publish_failed"
                o.stop_cause = "publish_failed"
                continue
            ident = read(art)
            doc = ident["doc"] if (ident is not None and ident["anchor"] == st.anchor
                                   and ident["page"] == page) else None
            kind = classify_page(doc)[0] if doc is not None else PAGE_CONTRADICTORY
            if doc is None or kind == PAGE_CONTRADICTORY:
                # the bytes are stored, but this is not a page we can OWN — unreadable, not the page we
                # asked for, or carrying pagination fields that contradict each other. Recording it would
                # stop it ever being re-bought, so it could never repair itself. Evidence only, and the
                # page stays owed. The artifact is bound under the ERROR namespace, so an unusable body
                # can never be mistaken for a page we hold.
                o.evidence_invalid += 1
                st.stopped = "parse"
                o.fail_classes["parse"] = o.fail_classes.get("parse", 0) + 1
                art.unlink(missing_ok=True)
                why = _keep_evidence(o, ledger, attempt_dir, error_key(st.anchor, page), raw)
                if why:
                    o.stop_cause = why
                continue
            journaled = ledger.record(item_key(st.anchor, page), art, digest=dig)
            # a readable journal proves OLD content survives, not that THIS page reached it. Both facts
            # are needed, and only the record itself carries the second one (review-B1.6r1#2).
            o.records_journaled = o.records_journaled and journaled
            _take(st, o, page=page, art=art, doc=doc, ingest=ingest, replayed=False)
            if not journaled or not ledger_writable(ledger):
                o.stop_cause = "ledger_unwritable"
        if not progressed:
            if spend is not None and spent >= spend and not o.stop_cause:
                o.stop_cause = "budget_exhausted"
            break


def ledger_writable(ledger) -> bool:
    """Whether completions can actually be journaled. For PAID work this is a precondition, not a
    postcondition: discovering it afterwards means the credits are already gone."""
    return not getattr(ledger, "foreign", False) and not getattr(ledger, "_journal_unsafe", False)


def _remainder(states, o) -> None:
    for st in states:
        # "never opened" is not "asked and refused": an anchor whose page 1 died on a limit WAS queried.
        if not st.pages_done and not st.attempted:
            o.unopened.append(f"{st.anchor.param}={st.anchor.value}")
        if st.total_pages is None:
            if st.pages_done:
                o.pages_left_unknown_anchors += 1
        else:
            o.pages_left_known += st.pages_left()
