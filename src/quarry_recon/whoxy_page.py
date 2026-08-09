"""The Whoxy reverse-whois paginator.

Whoxy-local by design: it reuses Quarry's provider vocabulary (the outcome taxonomy, host-fair
ordering, `budget.Ledger`) but not the Shodan coordinator's machinery.

Three facts drive the design:

  · ONE CREDIT PER PAGE, and a single anchor can run to hundreds. Pages are ordered PAGE TIER FIRST —
    page 1 of every anchor before page 2 of any — and what a budget does not reach is a counted,
    resumable remainder. Ranking decides order, never membership.
  · CARDINALITY IS FREE: `total_pages` arrives with page 1, so ordering rare anchors first costs
    nothing and there is no sizing pass to build.
  · `total_pages` IS AUTHORITATIVE. Asking past the end is free but answers `status: 0`, so a
    paginator that probed for the end would turn a clean completion into a provider failure.

Measured response shapes: docs/design/PROVIDER-QUOTA-DESIGN.md.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from . import budget

#: bump when a stored page's MEANING changes — it is part of every page's identity, so a bump
#: deliberately re-buys every page. Row shape varies between query forms; that is the provider's
#: own variation within one schema.
WHOXY_WORK_SCHEMA = 1
WHOXY_PAGE_SIZE = 100          # measured: 100 rows/page on both query forms


@dataclass(frozen=True)
class Anchor:
    """One reverse-whois question: `param` is `company` or `email`, `value` is what we ask about."""

    param: str
    value: str


def provider_dir(project_dir) -> "Path":
    """`<project>/osint/state/whoxy` — the PROVIDER level, above the schema generation.

    Concurrency is a property of the provider and the project, so the lock must not live inside a
    schema directory where two builds would take different locks against one account."""
    return Path(project_dir) / "osint" / "state" / "whoxy"


def state_dir(project_dir) -> "Path":
    """The durable home for Whoxy page ownership: `<project>/osint/state/whoxy/v<schema>/`.

    Outside the timestamped session directory, or every run re-buys page 1. The generation is the WORK
    SCHEMA only: folding in a key, an anchor or a spending control would re-buy paid pages."""
    return provider_dir(project_dir) / f"v{WHOXY_WORK_SCHEMA}"


def error_key(anchor: Anchor, page: int) -> str:
    """Identity of a FAILED page's response body. A distinct namespace from `item_key`, so a retained
    explanation can never be mistaken for a page we own."""
    raw = f"{WHOXY_WORK_SCHEMA}|{anchor.param}|{anchor.value}|p{page}|error"
    return hashlib.sha256(raw.encode()).hexdigest()


def item_key(anchor: Anchor, page: int) -> str:
    """The per-page completion identity: (schema, param, value, page).

    The budget and reserve are deliberately absent: they govern what we may spend, not what a page
    contains."""
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
    # whether any page of this anchor was INGESTED. `not pages_done` answers a different question,
    # and would never count an anchor whose page 1 failed to ingest and whose page 2 succeeded.
    delivered: bool = False
    _cursor: int = 1

    def next_page(self) -> "int | None":
        """The lowest page still owed, or None.

        Exactly one page is offered for an unopened anchor: until page 1 answers there is no count.
        `total_pages` then bounds the walk — asking past it is free but classifies as a failure."""
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
    """`total_pages`, accepted only when the provider's own two fields agree.

    `total_pages == ceil(total_results / 100)` is measured on both query forms. It is the only thing
    that terminates the walk, so an uncorroborated value would have us paginate — and pay — for as long
    as it says to. Disagreement is drift: the page stays owed."""
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

    A contradictory count keeps the bytes as evidence and leaves the page OWED, so a transient
    contradiction cannot become permanent ownership of a page we could not size.

    Terminal means the measured compact zero shape and nothing else: "no pagination fields" would let a
    body claiming 250 results and returning 100 rows own a one-page completion with no remainder."""
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
    # both numbers are checked: 100 rows a page, and `total_pages == ceil(total / 100)`. A page
    # claiming 50 results and returning one row contradicts itself and must not be owned.
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
    """A stored page, strictly validated -> {"anchor", "page", "doc"} | None.

    Validation is `contract`'s, not a second parser: the identity is read from the body and handed back
    to that validator, so the body must agree with itself. Tests use this reader too — a laxer stand-in
    hides the defects they exist to find."""
    from .contract import ProviderBodyError, whoxy_envelope, whoxy_reverse_page
    try:
        body = json.loads(artifact.read_text())
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    # identity DISCOVERY, not enforcement: the body is asked who it answers, and the parser is then
    # asked to agree. One rule, one authority.
    ident = body.get("search_identifier")
    if not isinstance(ident, dict) or len(ident) != 1:
        return None
    (param, value), = ident.items()
    if param not in ("company", "email") or not isinstance(value, str) or not value.strip():
        return None
    # the compact answer carries no position of its own and is only ever coherent as page 1;
    # everything else must name its own page.
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

    A rare anchor answers completely for fewer credits. An unopened anchor sorts last within its tier at
    no cost, since page 1 of every anchor is tier 1."""
    return (0, st.total_pages) if st.total_pages is not None else (1, 0)


def schedule(states: "list[AnchorState]") -> list:
    """The next round: at most one page per anchor, PAGE TIER first, fair across anchors.

    Rank must be the PAGE alone — cardinality in the rank gives almost every anchor its own tier and
    collapses fairness into a global cardinality sort. Rare anchors are ordered by pre-sorting instead.

    The group is the anchor TYPE, so fifty company anchors cannot starve the email ones. Grouping by
    anchor would re-sort alphabetically and discard the pre-sort."""
    pending = [(st, st.next_page()) for st in states]
    pending = [(st, pg) for st, pg in pending if pg is not None]
    pending.sort(key=lambda it: (it[1], _rank(it[0]), it[0].anchor.param, it[0].anchor.value))
    return budget.order_ranked_fair(pending, rank=lambda it: it[1],
                                    group=lambda it: it[0].anchor.param)


@dataclass(frozen=True)
class SpendPolicy:
    """How many pages this run may buy, and whether the controls themselves were usable.

    A cost guard that fails open is worse than none: `run_budget=-1` must not coerce to 0, which means
    "no ceiling". Invalid controls stop paid work and are reported as the configuration defect."""

    pages: "int | None" = None       # None = no computable bound
    invalid: str = ""                # which OPERATOR control is unusable, if any
    balance_invalid: str = ""        # the PROVIDER's balance was unreadable as a number
    limit: str = ""                  # the provider PROVED paid work is pointless — a soft limit
    gap: str = ""                    # something FAILED; coverage is incomplete and must say so
    # which boundary produced the allowance, so exhaustion can be told from an operator ceiling.
    # Applies only if work remains: a run that finished inside its allowance hit no boundary.
    stop_kind: str = ""              # "provider_balance" | "operator_reserve" | "run_budget" | ""
    # the balance outcome's class, so a 401 or 500 on the balance endpoint is more than "failed"
    error_class: str = ""


def _exact_count(v) -> "int | None":
    """An exact non-negative int. `bool` is excluded — it is an int subclass, and `True` is not a count."""
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        return None
    return v


def spend_policy(balance, reserve, run_budget) -> SpendPolicy:
    """The settled spending contract. Every path fails closed, and WHY decides how it reads:

      · a provider limit (quota, entitlement)               -> no paid work, a SOFT limit
      · any other refusal (auth, forbidden, unclassifiable) -> no paid work, a GAP
      · a balance we asked for and could not read           -> no paid work, a GAP"""
    from .contract import is_provider_limit
    if not isinstance(balance, BalanceRead):
        # reading the balance is not optional: a caller that skipped it would otherwise get the most
        # permissive answer available. Forgetting it is a defect in the CALL, not a spending decision.
        raise TypeError(f"spend_policy needs a BalanceRead from read_balance(), got {type(balance).__name__}")
    res, run = _exact_count(reserve), _exact_count(run_budget)
    invalid = ", ".join(n for n, v in (("WHOXY_CREDIT_RESERVE", res), ("WHOXY_PAGE_BUDGET", run))
                        if v is None)
    # both facts are kept: pages are zero either way, and an operator who fixes the knob should not
    # then discover the account was refused.
    if balance.refused:
        # the provider spoke. Not an unknown, and never a licence to spend.
        if is_provider_limit(balance.error_class):
            return SpendPolicy(pages=0, invalid=invalid, error_class=balance.error_class,
                               limit=f"{balance.error_class}: {balance.reason}")
        return SpendPolicy(pages=0, invalid=invalid, error_class=balance.error_class,
                           gap=f"{balance.error_class}: {balance.reason}")
    if balance.error_class:
        # we asked and could not read the answer: no paid work. A cost guard that does not understand
        # the body must not spend against it. Reported as provider drift, not as a broken knob.
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

    The reserve protects credits for later, the run budget limits this invocation, and `0` means "no
    ceiling" for each. An unknown balance is not zero — but an unknown balance WITH a reserve is
    contradictory, and stops us as an operator limit rather than a provider refusal."""
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
    # the provider's own words, verbatim: an operator needs "Zero Account Balance", not `{"quota": 1}`
    limit_reason: str = ""              # ...paired with the class it came from, so several failures
    fail_reason: str = ""               #    cannot cross-associate class and wording
    unopened: list = field(default_factory=list)     # EXACT anchors, never a count alone
    # anchors we actually sent a request for; `anchors - unopened` counts a replay-only run as having
    # attempted every one of them
    requested: set = field(default_factory=set)
    pages_left_known: int = 0
    pages_left_unknown_anchors: int = 0
    evidence_invalid: int = 0           # a recorded page whose artifact no longer validates
    # ownership is not consumption: a page whose `ingest` raised stays owned (or the scheduler sells
    # it to us again) but its rows never reached the report
    pages_unconsumed: int = 0
    # every machinery failure in order: the first cause governs, but a later one is still a fact
    machinery: list = field(default_factory=list)
    publish_failed: int = 0
    total_drift: int = 0                # pages whose total disagreed with another page of the anchor
    requests_issued: int = 0            # requests SENT, not credits: a past-end refusal costs nothing,
                                        # and only the next balance read says what was charged
    error_bodies: int = 0               # non-empty failure bodies retained as evidence
    # the allowance was actually used up. A policy's `stop_kind` says what it WOULD bound; if our own
    # machinery stopped first, no boundary was reached and reporting one invents a limit.
    allowance_exhausted: bool = False
    records_journaled: bool = True      # every LEDGER WRITE this run reported success — completions and
                                        # evidence binds alike, since both must survive for the run to
                                        # be resumable and for its evidence to be findable
    config_invalid: str = ""            # OPERATOR spending controls that could not be used
    balance_invalid: str = ""           # the PROVIDER's balance was not a readable count
    stop_cause: str = ""
    persisted: bool = True


def owned_index(ledger, read) -> dict:
    """Pages the ledger demonstrably owns: {(param, value): [(page, artifact, doc)]}.

    One pass over every digest-validated completion, so a hole of any width is recovered — probing
    upward from page 1 would lose paid evidence above a damaged page. The identity is recomputed from
    the document and must match the key it was filed under, so a transplanted artifact cannot donate
    ownership."""
    out: dict = {}
    for item, art in ledger.items():
        ident = read(art)
        if ident is None:
            continue
        anchor, page = ident["anchor"], ident["page"]
        if item_key(anchor, page) != item:
            continue
        # replayed evidence owes the same contract as fresh output: a digest-valid but contradictory
        # completion would otherwise replay for free and stay permanently unsized
        if classify_page(ident["doc"])[0] == PAGE_CONTRADICTORY:
            continue
        out.setdefault((anchor.param, anchor.value), []).append((page, art, ident["doc"]))
    for v in out.values():
        v.sort(key=lambda e: e[0])
    return out


class LockBusy(Exception):
    """A Whoxy lock is held by another lifecycle.

    Either the PROJECT lock (nothing can proceed) or the ACCOUNT lock (replayed evidence is still valid;
    only the unpaid remainder is blocked)."""


@dataclass(frozen=True)
class BalanceRead:
    """What `account=balance` told us, with the facts kept apart.

    A proven refusal must not read as "we could not tell" — with no reserve that would mean unbounded
    spending — and the reason must survive for the verdict."""

    remaining: "int | None" = None
    error_class: str = ""        # the provider-outcome class, when it refused or could not be read
    reason: str = ""             # verbatim, as the provider said it
    refused: bool = False        # the provider EXPLICITLY refused, as opposed to us failing to read

    def __post_init__(self):
        """Only valid outcomes exist: a bad state is unconstructable rather than checked downstream,
        because `BalanceRead()` alone would mean unbounded spending."""
        from .contract import PROVIDER_CLASSES, PROVIDER_LIMITS, PROVIDER_PARSE
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
        # a proven limit IS a refusal: without this it reads as an unreadable balance, i.e. a gap
        if self.error_class in PROVIDER_LIMITS and not self.refused:
            raise ValueError(f"{self.error_class} is a PROVEN provider limit and must be refused=True")


def read_balance(raw) -> BalanceRead:
    """Whoxy's `account=balance` reply, as a structured outcome.

    The call is free, and only the reverse-whois figure funds this lane. The envelope is
    `contract.whoxy_envelope`, so a refusal arrives classified from the provider's own words.

    A missing or malformed figure is UNKNOWN, never zero, and carries its reason."""
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
        # a body we cannot parse is our inability to read it, not the provider saying no — the two send
        # an operator to completely different places
        return BalanceRead(error_class=e.error_class, reason=e.reason,
                           refused=e.error_class != PROVIDER_PARSE)
    n = _exact_count(env.get("reverse_whois_balance"))
    if n is None:
        return BalanceRead(error_class="parse",
                           reason=f"provider balance unusable: reverse_whois_balance="
                                  f"{env.get('reverse_whois_balance')!r}")
    return BalanceRead(remaining=n)


#: the Whoxy key is global, so every project on this machine spends the SAME account
SPEND_LOCK = Path.home() / ".config" / "quarry" / "whoxy-spend.lock"


@contextlib.contextmanager
def _flock(path):
    """An exclusive, advisory, OS-released lock on `path`. Raises `LockBusy` on contention only.

    The mechanism is `budget.state_lock`; this wrapper only preserves Whoxy's own contention type."""
    with contextlib.ExitStack() as stack:
        try:
            p = stack.enter_context(budget.state_lock(path))
        except budget.StateBusy as e:
            # only the ACQUISITION is translated: a `StateBusy` from the body belongs to some other lock
            raise LockBusy(str(e)) from e
        yield p


@contextlib.contextmanager
def spend_lock(path=None):
    """The installation-wide Whoxy SPENDING lock — the inner of the two, taken last and briefly.

    Credits are account-wide, so two projects would otherwise each spend down to the reserve. Taken only
    once paid work remains, so owning everything never waits on another project's purchasing.

    Order is fixed — project lock first, always. These acquisitions are non-blocking, so a call site
    that disagrees live-locks rather than deadlocks. Full order: docs/design/PROVIDER-QUOTA-DESIGN.md."""
    with _flock(Path(path) if path is not None else SPEND_LOCK) as p:
        yield p


@contextlib.contextmanager
def lifecycle_lock(project_dir):
    """Exclusive, advisory, OS-released lock over a project's Whoxy page state.

    `flock`, not lockfile existence: the kernel releases it however the holder dies, and the file is
    never unlinked, or a second process would lock a path the first no longer shares.

    Held across the whole lifecycle, and contention raises before any of it, so a blocked run issues
    zero paid requests. Protects one project's LEDGER; credits need `spend_lock` as well."""
    base = provider_dir(project_dir)
    with _flock(base / ".lock"):
        yield base


@contextlib.contextmanager
def open_state(project_dir):
    """`with open_state(project) as (ledger, pages):` — the only way to reach Whoxy page state.

    Takes the PROJECT lock only. The account lock is acquired lazily by `run_pages`, once replay has
    finished and paid work remains, so free operations never wait on another project's spending.

    Locking and state-opening are one step by design: the safe order cannot be got wrong by a caller
    that constructs the ledger itself."""
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

    `fetch(anchor, page) -> (raw_bytes, error)` never raises; `read(artifact)` validates a stored page;
    `ingest(...) -> int` returns domains yielded.

    `paid` yields the page allowance and is entered only once replay has finished and work remains —
    where the caller takes the spend lock. On `LockBusy` replayed evidence is kept."""
    from .contract import is_provider_limit as _default_is_limit
    is_limit = is_limit or _default_is_limit
    states = dedupe(states)
    o = Outcome(anchors=len(states))
    try:
        try:
            _replay(states, o, ledger=ledger, ingest=ingest, read=read)
            # an index that exists and cannot be trusted must never read as empty: that is permission to
            # re-buy every page of a permanent cache
            unreadable = getattr(ledger, "unreadable", "")
            if unreadable and schedule(states):
                o.stop_cause = o.stop_cause or f"ownership_unreadable:{unreadable}"
            elif schedule(states):
                # pending work only: a run that owns everything never waits on the account
                try:
                    with paid() as spend:
                        _buy(states, o, spend=spend, fetch=fetch, ingest=ingest, read=read,
                             ledger=ledger, attempt_dir=attempt_dir, is_limit=is_limit)
                except LockBusy:
                    # another project is spending: what we replayed stays, only the unbought part is blocked
                    o.stop_cause = "account_busy"
                except Exception as e:
                    # caught here rather than at the lifecycle boundary, so `_remainder` still runs and the run
                    # reports what is left as well as what it got
                    _machinery(o, e)
        except (KeyboardInterrupt, SystemExit):
            raise                                  # cancellation ends the run; it is not an outcome
        except Exception as e:
            # replay is machinery too: every page it accepted before a failure is a fact
            _machinery(o, e)
    finally:
        # runs in `finally`, and over a SNAPSHOT of the states, so a machinery failure still reports its
        # remainder and a second pass cannot double-count
        try:
            _remainder(states, o)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            _machinery(o, e)
        # a ledger we could not write leaves every page bought this run to be bought again, so the
        # result is a fact the caller must be able to report. Inside the machinery boundary: a save
        # that raises did not save, and a journaled checkpoint does not prove THIS page's append landed.
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
            # only when the snapshot did NOT land, or a clean save that then raises reports a gap
            try:
                durable = bool(getattr(ledger, "durable", False))
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                # a store that cannot answer is not a durable one
                durable = False
                _machinery(o, e)
            o.persisted = durable and o.records_journaled
    return o


def _take(st, o, *, page, art, doc, ingest, replayed: bool) -> None:
    """Fold one validated page into the state and the outcome, however it was obtained."""
    st.pages_done.add(page)
    st.attempted = True
    # every page is reconciled MAX-WINS, so the remainder is never understated and a disagreement
    # between pages stays a fact about the provider's index
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
        # an anchor is delivered when a page of it LANDS, not when one is fetched
        if not st.delivered:
            st.delivered = True
            o.anchors_touched += 1
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        # a page that failed to ingest stays owned — dropping it would have the scheduler sell it again —
        # and the shortfall is counted in its own unit
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


def _keep_evidence(o, ledger, attempt_dir, key, raw) -> str:
    """Retain bytes as EVIDENCE, never a completion, under a page's durability handshake.

    Returns "" on success, else which sink failed. If this write did not land neither will the next, and
    paying for pages we cannot bind is the same defect as running without a journal."""
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

        Buying what we cannot record means paying twice. The flags alone are not a precondition —
        nothing sets them until a write has already failed — so this performs a real replay-safe write
        and a publish/remove probe. Lazy and memoized: a run that buys nothing probes neither."""
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
            spent += 1              # per ATTEMPT: what was billed is unknown until the next balance read
            st.attempted = True
            progressed = True
            if err is not None:
                cls = getattr(err, "error_class", None) or "error"
                st.stopped = cls
                # Whoxy reports failure inside an HTTP 200, so the bytes are where the explanation lives.
                # Kept as evidence, never a completion: the page is still owed.
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
                # FIRST of each kind wins, stored WITH its own class, so two failures cannot cross-associate
                # one's class with the other's wording
                why = f"{cls}: {(getattr(err, 'reason', '') or str(err) or cls).strip()}"
                if limited and not o.limit_reason:
                    o.limit_reason = why
                elif not limited and not o.fail_reason:
                    o.fail_reason = why
                if is_limit(cls) and not o.stop_cause:
                    # degrade, don't disable: stop buying, keep what is earned, count the rest. A storage failure
                    # is ours and outranks the provider's boundary.
                    o.stop_cause = f"provider_limit:{cls}"
                continue
            dig = hashlib.sha256(raw).hexdigest()
            art = attempt_dir / f"{item_key(st.anchor, page)}.json"
            # the provider's exact bytes: never reserialized, or PII we do not parse would not survive
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
                # stored but NOT owned — unreadable, wrong page, or self-contradictory. Recording it would stop
                # it ever being re-bought, so it could never repair itself. Bound under the ERROR namespace.
                o.evidence_invalid += 1
                st.stopped = "parse"
                o.fail_classes["parse"] = o.fail_classes.get("parse", 0) + 1
                art.unlink(missing_ok=True)
                why = _keep_evidence(o, ledger, attempt_dir, error_key(st.anchor, page), raw)
                if why:
                    o.stop_cause = why
                continue
            journaled = ledger.record(item_key(st.anchor, page), art, digest=dig)
            # a readable journal proves old content survives, not that THIS page reached it
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


#: shared with every other ledger consumer — see `budget.ledger_writable`
ledger_writable = budget.ledger_writable


def _machinery(o, e: BaseException) -> None:
    """Record OUR OWN failure without discarding what the lifecycle already established.

    The first failure names the stop: a later one is a consequence, and overwriting would report the
    symptom instead of the cause."""
    o.machinery.append(f"{type(e).__name__}: {e}")
    o.stop_cause = o.stop_cause or f"machinery:{type(e).__name__}"
    # the reason must say it was OUR machinery: a bare exception string reads as a provider failure
    o.fail_reason = o.fail_reason or f"page state machinery failed ({type(e).__name__}: {e})"


def _remainder(states, o) -> None:
    # a snapshot, not an accumulator: this is reachable twice, and `+=` would double the remainder
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
