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

import contextlib
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

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


def provider_dir(project_dir) -> "Path":
    """`<project>/osint/state/whoxy` — the PROVIDER level, ABOVE the schema generation.

    review-B1.6b2#1: the lock lived inside the schema directory, so a v1 process and a v2 process took
    DIFFERENT locks and could spend against the same account at the same time. Concurrency is a property
    of the provider and the project, not of whichever schema a build happens to be on."""
    return Path(project_dir) / "osint" / "state" / "whoxy"


def state_dir(project_dir) -> "Path":
    """The DURABLE home for Whoxy page ownership: `<project>/osint/state/whoxy/v<schema>/`.

    An `OsintSession` directory is timestamped, so state kept inside one dies with it and every run
    re-buys page 1. This sibling survives sessions, and the ledger and the page artifacts live under the
    SAME schema directory because `Ledger.record` stores paths relative to its own parent — an artifact
    outside that tree cannot be owned at all.

    The generation is the WORK SCHEMA and nothing else. Not the API key: a page's bytes do not depend on
    which credential paid for it. Not the anchors: they are the work, not the configuration. Not the
    reserve or the page budget: those govern how much we are willing to spend, and folding them in would
    make lowering a spending policy re-buy pages already paid for. A SCHEMA change is the one thing that
    genuinely invalidates stored pages, and it isolates them rather than deleting them — paid evidence
    is never pruned automatically."""
    return provider_dir(project_dir) / f"v{WHOXY_WORK_SCHEMA}"


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
    # review-B1.6b24#2: whether any page of this anchor was actually INGESTED. `not pages_done` answers
    # "is this the first page we took", which is a different question — an anchor whose page 1 failed to
    # ingest and whose page 2 succeeded would never be counted as delivered at all.
    delivered: bool = False
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
    total = doc.get("total_results_int")
    pages = usable_page_count(doc.get("total_pages"), total)
    if pages is None:
        return PAGE_CONTRADICTORY, None
    # review-B1.6b18#2: the page count was corroborated and the ROW COUNT was not, so a page claiming 50
    # results across one page and returning ONE row was accepted as a complete answer — 49 results lost
    # to a body that contradicted itself, and OWNED, so it could never be re-bought. The measured
    # contract fixes both numbers: 100 rows a page, and `total_pages == ceil(total / 100)`.
    page = doc.get("current_page")
    if isinstance(page, bool) or not isinstance(page, int) or not 1 <= page <= pages:
        return PAGE_CONTRADICTORY, None
    want = WHOXY_PAGE_SIZE if page < pages else total - WHOXY_PAGE_SIZE * (pages - 1)
    rows = doc.get("rows")
    if rows is None:
        rows = doc.get("search_result")
    if not isinstance(rows, list) or len(rows) != want:
        return PAGE_CONTRADICTORY, None
    return PAGE_PAGED, pages


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
    limit: str = ""                  # the provider PROVED paid work is pointless — a soft limit
    gap: str = ""                    # something FAILED; coverage is incomplete and must say so
    # review-B1.6b13#4: `pages` alone could not say WHOSE boundary produced it, so once the allowance ran
    # out the lane could not tell provider exhaustion from an operator ceiling. Applies only if work
    # actually remains — a run that finished inside its allowance hit no boundary at all.
    stop_kind: str = ""              # "provider_balance" | "operator_reserve" | "run_budget" | ""
    # review-B1.6b16#3: the balance outcome's own class had no way to reach the terminal, so a 401 or a
    # 500 on the balance endpoint produced a gap with no class at all — the operator could see that
    # something failed but not what.
    error_class: str = ""


def _exact_count(v) -> "int | None":
    """An exact non-negative int. `bool` is excluded — it is an int subclass, and `True` is not a count."""
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        return None
    return v


def spend_policy(balance, reserve, run_budget) -> SpendPolicy:
    """The settled spending contract. `balance` MUST be a `BalanceRead` from `read_balance` — there is
    no path here without having asked. See `spendable` for the arithmetic.

    review-B1.6b7#1: a PROVEN refusal must stop purchasing, and WHY decides how it reads:

      · a provider LIMIT (quota, entitlement) -> no paid work, and it is a SOFT limit: nothing went
        wrong, the account is simply spent.
      · any other explicit refusal (auth, forbidden, a status we cannot classify) -> no paid work, and
        it is a GAP: something needs fixing.
      · a balance we ASKED for and could not read -> no paid work either, and a GAP. A cost guard that
        does not understand the body in front of it must not spend against it (review-B1.6r3#2).

    Every path fails CLOSED. `BalanceRead` cannot be built without either a figure or a reason, so there
    is no third outcome where spending proceeds against something we do not know.

    review-B1.6r2#2: the operator's controls were validated and the PROVIDER's balance was not, though it
    is the least trustworthy of the three — it arrives over the network. `int()` turned `"200"` into 200
    pages, `True` into 1, `12.5` into 12, and `-1` into a silent zero with no fact recorded. The figure
    must now be exact, and `BalanceRead` refuses to hold anything else."""
    from .contract import is_provider_limit
    if not isinstance(balance, BalanceRead):
        # review-B1.6b8#1: accepting a bare int|None left `spend_policy(None, 0, 0)` granting UNBOUNDED
        # spending — a caller that skipped the mandatory balance preflight got the most permissive
        # answer available. Reading the balance is not optional, and forgetting it is a defect in the
        # CALL, so it fails here rather than becoming a spending decision.
        raise TypeError(f"spend_policy needs a BalanceRead from read_balance(), got {type(balance).__name__}")
    res, run = _exact_count(reserve), _exact_count(run_budget)
    invalid = ", ".join(n for n, v in (("WHOXY_CREDIT_RESERVE", res), ("WHOXY_PAGE_BUDGET", run))
                        if v is None)
    # review-B1.6b9#2: an invalid knob used to RETURN immediately, erasing a provider response we had
    # already observed — an operator would fix their config, rerun, and only then discover the account
    # was refused. Both facts are kept; pages are zero either way, and gaps still dominate.
    if balance.refused:
        # the provider spoke. Not an unknown, and never a licence to spend.
        if is_provider_limit(balance.error_class):
            return SpendPolicy(pages=0, invalid=invalid, error_class=balance.error_class,
                               limit=f"{balance.error_class}: {balance.reason}")
        return SpendPolicy(pages=0, invalid=invalid, error_class=balance.error_class,
                           gap=f"{balance.error_class}: {balance.reason}")
    if balance.error_class:
        # We ASKED and could not read the answer. review-B1.6r3#2: that permits no paid work — a cost
        # guard reading a body it does not understand must not spend against it. There is no longer a
        # "never asked" case to fall back for: `BalanceRead` cannot be constructed without either a
        # figure or a reason. review-B1.6r3#4: it is provider schema drift, not a broken operator
        # setting — reporting it as configuration would send an operator to fix a correct knob.
        return SpendPolicy(pages=0, invalid=invalid, error_class=balance.error_class,
                           balance_invalid=f"{balance.error_class}: {balance.reason}",
                           gap=f"balance unreadable ({balance.error_class}): {balance.reason}")
    if invalid:
        return SpendPolicy(pages=0, invalid=invalid)
    pages = spendable(balance.remaining, res, run)
    available = max(0, balance.remaining - res)
    if run and pages == run and run <= available:
        kind = "run_budget"                       # OUR per-invocation ceiling bit first
    elif res and pages == available:
        kind = "operator_reserve"                 # the reserve is what withheld the rest
    else:
        kind = "provider_balance"                 # the account itself is the boundary
    return SpendPolicy(pages=pages, stop_kind=kind)


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
    # the provider's OWN WORDS, kept verbatim. A class counter says `{"quota": 1}`; an operator needs
    # "Zero Account Balance" — that is the sentence B0 exists to surface, and a count is not it.
    limit_reason: str = ""              # ...paired with the class it came from, so several failures
    fail_reason: str = ""               #    cannot cross-associate class and wording
    unopened: list = field(default_factory=list)     # EXACT anchors, never a count alone
    # review-B1.6b14#6: anchors we actually SENT a request for this lifecycle. `anchors - unopened`
    # counted a replay-only run as having attempted every anchor while issuing zero requests.
    requested: set = field(default_factory=set)
    pages_left_known: int = 0
    pages_left_unknown_anchors: int = 0
    evidence_invalid: int = 0           # a recorded page whose artifact no longer validates
    # review-B1.6b23#1: OWNERSHIP is not CONSUMPTION. A page whose `ingest` raised is bought and stored
    # — it stays owned, or the scheduler would offer it again and pay twice — but its rows never reached
    # the report, and the page remainder alone cannot express that.
    pages_unconsumed: int = 0
    # review-B1.6b23#3: every machinery failure, in order. `stop_cause`/`fail_reason` keep the FIRST
    # cause, which is right, but a later one is a real fact too and used to vanish entirely.
    machinery: list = field(default_factory=list)
    publish_failed: int = 0
    total_drift: int = 0                # pages whose total disagreed with another page of the anchor
    requests_issued: int = 0            # requests SENT on the paid endpoint. NOT a credit count: the
                                        # measured past-end refusal cost nothing, and what a transport
                                        # failure or a refusal bills is unknown. The allowance is
                                        # decremented per attempt (conservative), but only the provider
                                        # balance says what was actually charged (review-B1.6r2#4)
    error_bodies: int = 0               # non-empty failure bodies retained as evidence
    # review-B1.6b20: the allowance was ACTUALLY used up, as counted by the scheduler. A policy's
    # `stop_kind` only says what it WOULD bound; if our own machinery stopped the run first, no boundary
    # was reached and reporting one invents a limit that never applied.
    allowance_exhausted: bool = False
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


class LockBusy(Exception):
    """A Whoxy lock is held by another lifecycle.

    Either of two, and the caller usually cares which: the PROJECT lock (another run is using this
    project's page state — nothing can proceed) or the ACCOUNT lock (another project is spending the
    shared credit balance — replayed evidence is still valid, and only the unpaid remainder is
    blocked)."""


@dataclass(frozen=True)
class BalanceRead:
    """What `account=balance` actually told us — the FACTS kept apart, as everywhere else in Quarry.

    review-B1.6b7#1: this returned a bare `int | None`, so a PROVEN refusal ("Zero Account Balance",
    HTTP 200, `status: 0`) came back as None — identical to "we could not read it" — and with no reserve
    that means UNBOUNDED. The provider stating plainly that there are no credits became permission to
    spend. It also lost the reason, so nothing survived for the verdict to report."""

    remaining: "int | None" = None
    error_class: str = ""        # the provider-outcome class, when it refused or could not be read
    reason: str = ""             # verbatim, as the provider said it
    refused: bool = False        # the provider EXPLICITLY refused, as opposed to us failing to read

    def __post_init__(self):
        """Only VALID outcomes exist. review-B1.6b9#1: making this the boundary type moved the
        validation off `spend_policy`'s argument and onto nothing at all — `BalanceRead()` meant
        unbounded spending, `BalanceRead(remaining=True)` bought a page, and `remaining="200"` was
        coerced downstream. An unconstructable bad state is worth more than a checked one."""
        from .contract import PROVIDER_CLASSES, PROVIDER_LIMITS, PROVIDER_PARSE
        # review-B1.6b10#1: "unconstructable" was overstated — the success branch never looked at
        # `reason`, the failure branch tested truthiness rather than TYPE, and `refused` accepted any
        # truthy value. `BalanceRead(remaining=5, reason="contradiction")` and
        # `BalanceRead(error_class=123, ...)` both constructed happily.
        if not isinstance(self.refused, bool):
            raise ValueError(f"refused must be a bool, got {type(self.refused).__name__}")
        if not isinstance(self.error_class, str) or not isinstance(self.reason, str):
            raise ValueError("error_class and reason must be strings")
        if self.remaining is not None:
            if _exact_count(self.remaining) is None:
                raise ValueError(f"balance {self.remaining!r} is not an exact non-negative count")
            if self.error_class or self.reason or self.refused:
                raise ValueError("a balance that was read cannot also carry a failure")
            return
        if self.error_class not in PROVIDER_CLASSES:
            raise ValueError(f"error_class {self.error_class!r} is not a provider-outcome class")
        if not self.reason.strip():
            raise ValueError("a balance with no figure must say WHY — a reason is required")
        if self.refused and self.error_class == PROVIDER_PARSE:
            raise ValueError("a body we could not parse is not the provider refusing us")
        # review-B1.6b11#1: a PROVEN limit is a refusal by definition — the provider told us plainly.
        # `BalanceRead(error_class="quota", refused=False)` was accepted and then read as an unreadable
        # balance, i.e. a GAP, so the one outcome that is emphatically not a defect reported as one.
        if self.error_class in PROVIDER_LIMITS and not self.refused:
            raise ValueError(f"{self.error_class} is a PROVEN provider limit and must be refused=True")


def read_balance(raw) -> BalanceRead:
    """Whoxy's `account=balance` reply, as a structured outcome.

    MEASURED 2026-07-29: `account=balance` is FREE — two consecutive reads left the balance unchanged —
    and answers `{"status": 1, "live_whois_balance": N, "whois_history_balance": N,
    "reverse_whois_balance": N}`. Only the reverse-whois figure funds this lane.

    The envelope is `contract.whoxy_envelope`, not a second status authority (review-B1.6b7#2): it
    already excludes `True` — which `== 1` in Python — and it classifies a refusal from the provider's
    OWN words, so "Zero Account Balance" arrives as a proven quota rather than an opaque failure.

    A missing or malformed figure is UNKNOWN, never zero — but it is an unknown that carries its reason,
    so the gap survives to the verdict."""
    from .contract import ProviderBodyError, whoxy_envelope
    try:
        doc = json.loads(raw)
    except Exception:
        return BalanceRead(error_class="parse", reason="balance response was not JSON")
    if not isinstance(doc, dict):
        # a non-object is not the provider REFUSING us — it is a body we cannot read at all.
        return BalanceRead(error_class="parse", reason="balance response was not a JSON object")
    from .contract import PROVIDER_PARSE
    try:
        env = whoxy_envelope(doc)
    except ProviderBodyError as e:
        # review-B1.6b8#2: EVERY envelope rejection was marked as a refusal, so `status: true` or a
        # missing status claimed Whoxy had explicitly refused the request. A body we cannot parse is our
        # inability to read it, not the provider saying no — and the two lead an operator to look in
        # completely different places.
        return BalanceRead(error_class=e.error_class, reason=e.reason,
                           refused=e.error_class != PROVIDER_PARSE)
    n = _exact_count(env.get("reverse_whois_balance"))
    if n is None:
        return BalanceRead(error_class="parse",
                           reason=f"provider balance unusable: reverse_whois_balance="
                                  f"{env.get('reverse_whois_balance')!r}")
    return BalanceRead(remaining=n)


#: where the installation-wide spending lock lives. The Whoxy KEY comes from the single global
#: `~/.config/quarry/secrets.yaml`, so every project on this machine spends the SAME account.
SPEND_LOCK = Path.home() / ".config" / "quarry" / "whoxy-spend.lock"


@contextlib.contextmanager
def _flock(path):
    """An exclusive, ADVISORY, OS-RELEASED lock on `path`. Raises `LockBusy` on contention only.

    The mechanism lives in `budget.state_lock` — the same lock every ledger-owning lane needs, defined once
    beside `Ledger`. This wrapper exists only to keep Whoxy's own contention type: callers here catch
    `LockBusy`, and a provider lane's vocabulary should not change because a primitive moved."""
    with contextlib.ExitStack() as stack:
        try:
            p = stack.enter_context(budget.state_lock(path))
        except budget.StateBusy as e:
            # review-B-audit-7#7: ONLY the acquisition is translated. Wrapping the yielded body too meant a
            # `StateBusy` raised by the CALLER (an inner lock, a nested lifecycle) came back out as this
            # lock's contention — an alias for a completely different lock.
            raise LockBusy(str(e)) from e
        yield p


@contextlib.contextmanager
def spend_lock(path=None):
    """The installation-wide Whoxy SPENDING lock — the INNER of the two, taken last and briefly.

    review-B1.6b3: the project lock protects one project's ledger, and that is all it protects. The KEY
    is global, so two runs in DIFFERENT projects take different project locks, read the SAME account
    balance, and can each spend down to the reserve — together crossing or exhausting it. Credits are an
    account-wide resource and need an account-wide lock.

    WHAT EACH LOCK COVERS, and the order is fixed:

        project lock (`open_state`)
          -> replay owned pages                    -- FREE, never waits on the account
          -> if paid work remains: THIS lock
               -> balance read
               -> purchases, each journaled durably as it lands
             (this lock released here)
          -> final ledger compaction / save        -- under the PROJECT lock only

    The account lock covers the balance read and the purchases, including each page's own journal
    record. It does NOT cover `ledger.save()`: compaction happens in `run_pages`'s `finally`, after the
    paid phase has exited, and it is the project lock that makes that safe. Nothing is lost by the
    narrower scope — a journaled page survives without the snapshot.

    Taken ONLY when paid work actually remains, and released as soon as it is done. review-B1.6b4: it
    was once the outermost lock, held for the whole lifecycle — which meant a project that owned every
    page it needed was blocked by another project's purchasing, and reported a gap for account access it
    never wanted. Free operations continue; only spending is serialised.

    `run_pages` composes the paid phase, so a caller supplies this lock and the balance read together
    and cannot take them in the wrong order. Anything that ever holds BOTH must take the project lock
    first. These are non-blocking acquisitions, so disagreeing call sites do not deadlock — they fail
    each other's acquisition, which is a live-lock at best and an unexplained `LockBusy` at worst."""
    with _flock(Path(path) if path is not None else SPEND_LOCK) as p:
        yield p


@contextlib.contextmanager
def lifecycle_lock(project_dir):
    """Exclusive, ADVISORY, OS-RELEASED lock over a project's Whoxy page state.

    review-B1.6b#1: `open_state` could be opened by two `quarry osint` runs at once. Both would load the
    same snapshot, buy the same pages — paying twice for identical bytes — and then race while compacting
    the ledger and unlinking the journal it supersedes, which is how ownership gets lost outright.

    `flock` and not lockfile EXISTENCE: a stale file from a killed run would block the project forever,
    while an flock is released by the KERNEL when the holder dies, however it dies. The file itself is
    never removed — unlinking it lets a second process lock a path the first no longer shares.

    Held across the whole lifecycle: the balance read, ledger load, replay, purchases and the final save.
    Contention raises `LockBusy` BEFORE any of that, so a blocked run issues zero paid requests.

    This one protects one project's LEDGER. Credits are account-wide and need `spend_lock` as well —
    the project lock cannot see another project at all (review-B1.6b3).

    It is at the PROVIDER level, above the schema generation: two builds on different schemas still
    share one account and must not spend at once (review-B1.6b2#1)."""
    base = provider_dir(project_dir)
    with _flock(base / ".lock"):
        yield base


@contextlib.contextmanager
def open_state(project_dir):
    """`with open_state(project) as (ledger, pages):` — the ONLY way to reach Whoxy page state.

    Takes the PROJECT lock only. review-B1.6b4: taking the account-wide spend lock here blocked free
    work — while project A was purchasing, project B could not replay pages it already owns, discover it
    has no remainder, or run under a zero-spend policy, and got a gap for needing no account access at
    all. That contradicts the rule this whole batch is built on: free operations continue.

    The account lock is acquired LAZILY, by `run_pages`, only once replay has finished and paid work
    actually remains. Order stays fixed where both are held: project, then account.

    review-B1.6b2#2: locking and state-opening were separable, so a caller could construct the `Ledger`,
    load its snapshot and read the balance with no lock held, and the durable-state tests did exactly
    that. Making the safe path the STRUCTURAL one means future wiring cannot get the order wrong: the
    provider lock is taken first, and everything — balance read, replay, purchases, final save — happens
    inside it.

    Both the ledger and the pages live under `state_dir`, so `Ledger.record`'s relative-path validation
    holds. Nothing here is pruned: a page was paid for, and a later run inherits it."""
    with lifecycle_lock(project_dir):
        base = state_dir(project_dir)
        pages = base / "pages"
        pages.mkdir(parents=True, exist_ok=True)
        yield budget.Ledger(base / "ledger.json", lane="osint.whoxy"), pages


@contextlib.contextmanager
def fixed_allowance(pages):
    """A paid phase with a KNOWN allowance and no lock — for callers that already settled both."""
    yield pages


def run_pages(states, *, paid, fetch, ingest, read, ledger, attempt_dir, is_limit=None) -> Outcome:
    """Buy pages under the budget, replaying anything already owned.

    `fetch(anchor, page) -> (raw_bytes, error)` returns the provider's EXACT response bytes, and never
    raises. `read(artifact) -> {"anchor", "page", "doc"} | None` validates a stored page and reports WHICH
    page it is — a Whoxy page identifies itself, and one self-identifying reader serves both ownership
    enumeration and the check on a page we just bought. `ingest(anchor, page, doc, artifact) -> int`
    turns it into candidates and returns how many domains it yielded.

    `paid` is a zero-argument callable returning a CONTEXT MANAGER that yields the page allowance. It is
    entered ONLY when replay has finished and pending work remains, so a lifecycle that owns everything
    it needs never touches the account — that is where the caller takes the installation-wide spend lock
    and reads the balance (review-B1.6b4). If it raises `LockBusy`, replayed evidence is KEPT and only
    the unpaid remainder is reported as blocked."""
    from .contract import is_provider_limit as _default_is_limit
    is_limit = is_limit or _default_is_limit
    states = dedupe(states)
    o = Outcome(anchors=len(states))
    try:
        try:
            _replay(states, o, ledger=ledger, ingest=ingest, read=read)
            # An ownership index that EXISTS and cannot be trusted must never read as an empty one: a
            # corrupt file would otherwise be permission to buy every page of this account again. Same
            # laundering route as the Shodan store (review#1, Lumpy) — this one holds a PERMANENT cache,
            # so an unnoticed re-buy here is charged for evidence the project already owns for ever.
            unreadable = getattr(ledger, "unreadable", "")
            if unreadable and schedule(states):
                o.stop_cause = o.stop_cause or f"ownership_unreadable:{unreadable}"
            elif schedule(states):
                # PENDING WORK ONLY. A run that owns everything never enters the paid phase, so it never
                # waits on the account and never reports a gap for access it did not need.
                try:
                    with paid() as spend:
                        _buy(states, o, spend=spend, fetch=fetch, ingest=ingest, read=read,
                             ledger=ledger, attempt_dir=attempt_dir, is_limit=is_limit)
                except LockBusy:
                    # another project is spending this account. What we replayed is real and stays; only
                    # the part we could not buy is blocked.
                    o.stop_cause = "account_busy"
                except Exception as e:
                    # review-B1.6b21: anything unexpected in the PAID phase used to propagate, discarding
                    # every page this lifecycle had already replayed or bought along with it. Caught HERE
                    # rather than only at the lifecycle boundary so `_remainder` still runs and the run
                    # reports what is left as well as what it got.
                    _machinery(o, e)
        except (KeyboardInterrupt, SystemExit):
            raise                                  # cancellation ends the run; it is not an outcome
        except Exception as e:
            # review-B1.6b22: only the PAID phase was covered, so a failure in REPLAY — an ingest that
            # raised on page 2 after page 1 had already yielded 100 candidates — escaped this function
            # entirely and the caller fabricated `attempted=0, completed=0` over evidence it held.
            # Replay is machinery too, and every page it accepted before the failure is a fact.
            _machinery(o, e)
    finally:
        # accounting for whatever the states DID reach, however this lifecycle ended. It runs in
        # `finally` so a machinery failure anywhere above still reports its remainder, and it is a
        # SNAPSHOT of the states (see `_remainder`), so running it after a partial failure cannot
        # double-count. Its own failure is machinery like any other and must not mask the outcome.
        try:
            _remainder(states, o)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            _machinery(o, e)
        # persistence is this function's job and its RESULT is a fact: a ledger we could not write leaves
        # every page bought this run to be bought again, and the caller must be able to say so.
        # review-B1.6r1#2: `saved or durable` called a page persisted when the checkpoint had journaled,
        # the page's own append had failed, and compaction failed too — every signal survivable while the
        # page reached NEITHER destination. The journal branch needs both facts.
        # review-B1.6b23#2: this call sat OUTSIDE the machinery boundary, so a store that raised on save
        # — after pages had replayed and been bought — escaped the whole function and the caller
        # fabricated `attempted=0, completed=0` over them. A save that raises did not save.
        try:
            saved = bool(ledger.save())
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            saved = False
            _machinery(o, e)
        if saved:
            o.persisted = True                 # the snapshot IS the durable answer; nothing else to ask
        else:
            # review-B1.6b25: the fallback was read unconditionally, so a ledger that saved cleanly and
            # then raised answering `durable` reported a machinery gap over evidence we no longer needed.
            # This branch exists only when the snapshot did NOT land.
            try:
                durable = bool(getattr(ledger, "durable", False))
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                # a store that cannot even answer is not a durable one — review-B1.6b24#3: swallowing
                # the exception contradicted the contract the rest of this function keeps.
                durable = False
                _machinery(o, e)
            o.persisted = durable and o.records_journaled
    return o


def _take(st, o, *, page, art, doc, ingest, replayed: bool) -> None:
    """Fold one validated page into the state and the outcome, however it was obtained."""
    st.pages_done.add(page)
    st.attempted = True
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
    try:
        o.domains += ingest(st.anchor, page, doc, art)
        # review-B1.6b24#2: `anchors_touched` was incremented BEFORE ingestion, so an anchor whose page 1
        # died on ingest was published as `completed=1` beside `pages_unconsumed=1, domains=0` — the same
        # anchor reported as completed and as failed. An anchor is delivered when a page of it lands.
        if not st.delivered:
            st.delivered = True
            o.anchors_touched += 1
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        # review-B1.6b23#1: the page counted as read or bought and then dropped out of the remainder,
        # so a ten-page anchor that died ingesting page 2 reported "8 pages remaining" for NINE pages
        # this lifecycle never delivered. It stays owned — dropping it from `pages_done` would have the
        # scheduler sell it to us again — and the shortfall is counted in its own unit.
        o.pages_unconsumed += 1
        raise


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
            o.requested.add((st.anchor.param, st.anchor.value))
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
                limited = is_limit(cls)
                bucket = o.limit_classes if limited else o.fail_classes
                bucket[cls] = bucket.get(cls, 0) + 1
                # review-B1.6b13#6: these were declared and never assigned, so the provider's real words
                # — "Zero Account Balance" — never reached an operator, who saw `{"quota": 1}` instead.
                # FIRST of each kind wins and is stored WITH its own class, so two different failures can
                # never have one's class read against the other's wording.
                why = f"{cls}: {(getattr(err, 'reason', '') or str(err) or cls).strip()}"
                if limited and not o.limit_reason:
                    o.limit_reason = why
                elif not limited and not o.fail_reason:
                    o.fail_reason = why
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
        if spend is not None and spent >= spend:
            o.allowance_exhausted = True
        if not progressed:
            if spend is not None and spent >= spend and not o.stop_cause:
                o.stop_cause = "budget_exhausted"
            break


#: B1.7: shared with every other ledger consumer — see `budget.ledger_writable`.
ledger_writable = budget.ledger_writable


def _machinery(o, e: BaseException) -> None:
    """Record OUR OWN failure without discarding what the lifecycle already established.

    The first failure names the stop: a later one is a consequence, and overwriting would report the
    symptom instead of the cause."""
    o.machinery.append(f"{type(e).__name__}: {e}")
    o.stop_cause = o.stop_cause or f"machinery:{type(e).__name__}"
    # the reason must SAY it was our own machinery: it is what the operator reads on the terminal, and
    # a bare exception string is indistinguishable from a provider failure.
    o.fail_reason = o.fail_reason or f"page state machinery failed ({type(e).__name__}: {e})"


def _remainder(states, o) -> None:
    # a SNAPSHOT of the states, not an accumulator: it is reachable twice (once normally, once after a
    # machinery failure), and `+=` over a list that already held the first pass would report a remainder
    # twice the size of the real one.
    o.unopened = []
    o.pages_left_known = 0
    o.pages_left_unknown_anchors = 0
    for st in states:
        # "never opened" is not "asked and refused": an anchor whose page 1 died on a limit WAS queried.
        if not st.pages_done and not st.attempted:
            o.unopened.append(f"{st.anchor.param}={st.anchor.value}")
        if st.total_pages is None:
            if st.pages_done:
                o.pages_left_unknown_anchors += 1
        else:
            o.pages_left_known += st.pages_left()
