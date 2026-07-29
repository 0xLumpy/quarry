"""Phase 4: Probe / fingerprint / screenshots / ports.

httpx json (source of truth for live services) with the methodology's full flag set
(follow-host-redirects, asn, location, random-agent) at RoE rate limit + full-monty ports;
gowitness screenshots; naabu ports → nmap -sV service detection (only on in-scope CIDR);
optional smap passive (Shodan-backed) port scan.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass as _dataclass

import json as _json
import ipaddress as _ipaddress
import dataclasses
import math as _math
import re as _re
import time as _time
import urllib.parse
import urllib.request

from .. import budget, contract, events, netguard, normalize, secrets, settings, shodan_sched, store
from ..contract import (PROVIDER_RATE_LIMIT, ProviderResult, capture_error_body, is_provider_limit,
                        provider_error_class, run_contract, run_provider)
from ..runner import (Status, ffuf_results, ffuf_usable_rows, fresh_artifact_dir, have,
                      nuclei_timeout, reclassify_ffuf,
                      reclassify_from_artifact, reclassify_from_files, run as exec_tool, scaled_timeout,
                      skipped)

# Serialized-object / token markers that surface in Set-Cookie + response headers. Spotting the
# FORMAT is PASSIVE recon evidence (a hand-off to the attack layer), never exploitation. Only
# distinctive markers are used — pickle (`gAR`) / Ruby-Marshal (`BAg`) base64 prefixes are too
# collision-prone from a raw header string to include without noise. Source: TBHM cheatsheet §9.
_DESER_MARKERS = (
    ("java-serialized", "rO0AB"),            # ObjectOutputStream AC ED 00 05 → base64
    ("dotnet-binaryformatter", "AAEAAAD"),   # 00 01 00 00 00 FF FF FF FF → base64 AAEAAAD/////
    ("node-serialize", "_$$ND_FUNC$$_"),     # node-serialize function marker
)
_PHP_OBJ_RX = _re.compile(r'O:\d+:"[A-Za-z0-9_\\]+":')          # PHP serialize() object in a cookie
_JWT_RX = _re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")


_SHODAN_PAGE = 100                                          # Shodan host/search returns up to 100 matches/page


class ShodanPageError(Exception):
    """Carries a page failure's STRUCTURED class when the original exception cannot hold one.

    B1.4: the coordinator reads `err.error_class` and asks `is_provider_limit` about it — that is the
    whole interface between the lane and the scheduler. An exception that reaches it unclassified would
    be counted as a generic `error`, which is the difference between a provider LIMIT and a defect."""

    def __init__(self, error_class: str, cause: BaseException):
        super().__init__(str(cause) or error_class)
        self.error_class = error_class
        self.__cause__ = cause


def _classified(e: BaseException) -> BaseException:
    """Every Shodan exception leaves the adapter carrying a class the coordinator can act on."""
    cls = provider_error_class(e)
    try:
        e.error_class = cls                                   # type: ignore[attr-defined]
        return e
    except Exception:                                         # frozen/slotted exception types
        return ShodanPageError(cls, e)


#: characters a DNS owner name may use beyond a hostname's. `_` appears in real records (`_dmarc`,
#: `_acme-challenge`); `*` is a wildcard owner. Neither is a valid HOSTNAME, and neither is junk.
_DNS_OWNER_EXTRA = "_*"


def _dns_owner_name(h: str):
    """A syntactically valid DNS OWNER NAME that is not a valid hostname, or None.

    review-B1.5br2#1: `_dmarc.acme.com` was kept on the strength of containing a dot — and so were
    `../admin.acme.com`, `a/b.acme.com` and `bad name.acme.com`. The first is real evidence; the rest are
    malformed. Separating them is what lets the real one be retained without letting the others through.

    This is deliberately NOT a hostname check (`normalize.canon_host_strict` is that, and it is the one
    a caller about to CONTACT a name must use)."""
    s = str(h).strip().lower().rstrip(".")
    if not s or "." not in s or ".." in s or "/" in s or any(c.isspace() for c in s):
        return None
    if len(s) > 253:
        return None
    ok = "abcdefghijklmnopqrstuvwxyz0123456789-" + _DNS_OWNER_EXTRA
    for label in s.split("."):
        if not (1 <= len(label) <= 63) or label[0] == "-" or label[-1] == "-":
            return None
        if any(c not in ok for c in label):
            return None
    return s


#: cooldown applied when Shodan answers 429 without a usable `Retry-After`. A provider-driven backoff,
#: NOT an operator knob and NOT the target rate limit (`RATELIMIT.HTTP` is pressure on the target; using
#: it for a third-party API would be a category error).
_SHODAN_BACKOFF_S = 5.0
#: the longest slowdown we will honor from a header. Beyond this the value is not usable as pacing — a
#: run must not silently stall for an hour on one — so the fallback applies and the class still stops
#: work by its own rules.
_SHODAN_BACKOFF_MAX_S = 300.0



class _ProviderCooldown:
    """A provider-imposed slowdown, honored by EVERY Shodan request that follows it.

    review-B1.5r1#2: issuing counts serially is not pacing, and stopping sizing on a 429 while entering
    paid search immediately means the provider's "slow down" was heard and ignored. One cooldown, shared
    by sizing and purchasing, so honoring it is not something a caller can forget."""

    def __init__(self):
        self.until = 0.0
        self.hits = 0

    def note(self, err) -> None:
        self.hits += 1
        wait = _SHODAN_BACKOFF_S
        hdrs = getattr(err, "headers", None)
        raw = hdrs.get("Retry-After") if hdrs is not None else None
        try:
            if raw is not None:
                # review-B1.5r3#3: `float()` accepts `inf` and `1e309`, and `sleep(inf)` raises
                # OverflowError while a huge finite value stalls the run outright. Only a FINITE,
                # non-negative, usable value is honored; anything else falls back.
                got = float(str(raw).strip())
                if _math.isfinite(got) and 0.0 <= got <= _SHODAN_BACKOFF_MAX_S:
                    wait = got
        except (TypeError, ValueError):
            pass
        self.until = max(self.until, _time.monotonic() + wait)

    def wait(self) -> None:
        left = self.until - _time.monotonic()
        if left > 0:
            _time.sleep(left)


def _shodan_count(key, facet, v):
    """ONE free `/shodan/host/count` -> `(total, error)`. NEVER raises.

    B1.5 sizing. Count is FREE: query credits gate `/shodan/host/search` only, and `/host/count` keeps
    working at a zero balance (measured), which is why sizing continues when paid credits are exhausted
    or reserved. `total` is validated strictly — an exact non-negative int, `bool` excluded — and
    anything else is UNKNOWN. Never zero: a count we could not read says nothing about the pivot.

    Returns `(total, raw_bytes, error)`. review-B1.5r1#3: the response bytes were parsed and DISCARDED,
    and a fresh document was synthesized to stand in for them — so the "raw evidence" was Quarry's
    account of the answer rather than the answer. The exact bytes come back and are what gets stored."""
    url = (f"https://api.shodan.io/shodan/host/count?key={key}"
           f"&query={urllib.parse.quote(f'{facet}:{v}')}")
    raw = b""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read(4 * 1024 * 1024)
        data = _json.loads(raw.decode("utf-8", "replace"))
        if not isinstance(data, dict):
            raise ValueError("shodan: non-object count response")
        total = data.get("total")
        if not shodan_sched.valid_total(total):
            raise ValueError(f"shodan: invalid count total {total!r}")
    except Exception as e:
        capture_error_body(e, provider="shodan")
        return None, raw, _classified(e)
    return total, raw, None


def _shodan_page(key, facet, v, page):
    """ONE page of a Shodan search, as the coordinator's `(matches, total, error)` triple. NEVER raises.

    B1.4: pagination, retention and position accounting used to live here (`_shodan_search` looped pages
    and decided whether a failure discarded evidence). All of that is now the coordinator's, which owns
    ordering, budget, replay and durability across lanes. What is left is exactly one HTTP exchange and
    its validation — the part that is genuinely Shodan-specific.

    FULLY FAIL-CLOSED, unchanged from `_shodan_search`: a non-object body, a non-int/negative `total`, a
    non-list `matches`, a NON-DICT row, or a NON-LIST `hostnames` is an ERROR, never laundered into a
    clean empty. `{"total":1,"matches":[null]}` therefore fails."""
    url = (f"https://api.shodan.io/shodan/host/search?key={key}"
           f"&query={urllib.parse.quote(f'{facet}:{v}')}&page={page}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = _json.loads(r.read(4 * 1024 * 1024).decode("utf-8", "replace"))
        if not isinstance(data, dict):
            raise ValueError("shodan: non-object response — not a valid empty result")
        page_total = data.get("total")
        if not isinstance(page_total, int) or page_total < 0:
            raise ValueError(f"shodan: invalid total {page_total!r}")
        page_matches = data.get("matches")
        if not isinstance(page_matches, list):
            raise ValueError("shodan: matches is not a list")
        page_rows = []
        for m in page_matches:
            if not isinstance(m, dict):                       # a null/scalar row is corruption, not empty
                raise ValueError("shodan: non-object match row")
            hns = m.get("hostnames")
            if hns is not None and not isinstance(hns, list):
                raise ValueError(f"shodan: non-list hostnames {type(hns).__name__}")
            # review-B1.5br1#1: the LIST was validated and its MEMBERS were not, so the ingest side
            # stringified whatever arrived. `{"x": "a.evil.com"}` became the literal `"{'x': ...}"`,
            # kept because it contains a dot; `null` and `123` vanished before any counter moved. A
            # non-string member is corruption, exactly like a non-dict row — fail closed here rather
            # than guess downstream.
            for _h in (hns or []):
                if not isinstance(_h, str):
                    raise ValueError(f"shodan: non-string hostname {type(_h).__name__}")
            page_rows.append(m)
    except Exception as e:
        # B1.1: read the error BODY here, while it is still readable, and stamp the refined class onto
        # the exception. Shodan answers a spent balance with HTTP 401 + JSON and a bad key with HTTP
        # 401 + HTML, so the status code alone would report every exhausted account as a broken
        # credential. Capturing later is unreliable: an HTTPError wraps a live socket.
        capture_error_body(e, provider="shodan")
        return [], None, _classified(e)
    return page_rows, page_total, None


# ── B1.2: the Shodan CREDIT BALANCE contract ─────────────────────────────────────────────────────────
# `/api-info` is FREE and works at a ZERO balance (measured 2026-07-28), so the remaining credits are a
# fact we can always read rather than a number we have to guess or track locally across runs. A MONTHLY
# quota cannot be protected by per-run bookkeeping anyway — another client may spend concurrently — so the
# provider's own answer is the planning input and its 401-quota body stays the authority.
_SHODAN_RESERVE_MAX = 1_000_000


@_dataclass(frozen=True)
class ShodanBalance:
    """The settled credit contract. Facts stay DISTINCT — collapsing any two of them loses the only
    information the number carries:

      remaining   finite credits the provider reports   (None = UNKNOWN — never "unlimited": the
                                                         top-level field has no documented -1 sentinel,
                                                         and assuming one fails OPEN on a cost guard)
      allowance   the plan's monthly limit              (context; None when unreadable or unlimited)
      reserve     credits the OPERATOR withholds        (our own config, always known)
      spendable   what this run may use                 (None = UNKNOWN, i.e. no computable bound —
                                                         permitted only when no reserve is set)
      allowance_unlimited  the PLAN has no monthly ceiling (usage_limits.query_credits == -1)
      stop_kind   WHY we may not spend, as a token      (never inferred from prose; NOT all stops are
                                                         soft limits — see `stop_is_limit`)
      read_error  how the /api-info read FAILED         (None on success — kept even when the balance
                                                         itself is unusable, so a bad key stays visible)
      count_refused  how a /host/count refused the KEY   (None unless a free count proved the credential
                                                         is refused AFTER /api-info had succeeded — a
                                                         separate fact from the balance read's own)"""

    remaining: "int | None"
    allowance: "int | None"
    reserve: int
    spendable: "int | None"
    may_spend: bool
    reason: str
    allowance_unlimited: bool = False
    stop_kind: str = ""
    read_error: "str | None" = None
    count_refused: "str | None" = None

    @property
    def known(self) -> bool:
        return self.remaining is not None

    @property
    def stop_is_limit(self) -> bool:
        """Whether a stop is an EXPECTED soft limit (-> complete_with_limits) or a real gap.

        review-B1.2r3#2: one `read_refused` token held auth, generic forbidden AND entitlement, so a BAD
        KEY would have softened into complete_with_limits alongside a genuinely exhausted account. A
        credential that does not work is a defect in our setup; an account that ran out is not."""
        return self.stop_kind in _STOP_LIMITS


# stop_kind tokens — a machine-readable WHY, so no consumer has to parse `reason`.
SHODAN_PROVIDER_EXHAUSTED = "provider_exhausted"   # the account really is empty          -> LIMIT
SHODAN_ENTITLEMENT = "entitlement"                 # the PLAN cannot reach the endpoint   -> LIMIT
SHODAN_OPERATOR_RESERVE = "operator_reserve"       # credits exist; WE withhold them      -> LIMIT
SHODAN_UNKNOWN_WITH_RESERVE = "unknown_with_reserve"  # our own caution stopped us        -> LIMIT
SHODAN_AUTH_REFUSED = "auth_refused"               # the credential does not work         -> GAP
SHODAN_FORBIDDEN = "forbidden"                     # refused, reason unproven             -> GAP
SHODAN_RESERVE_INVALID = "reserve_invalid"         # the knob is present but unusable     -> GAP

#: stops that are EXPECTED boundaries rather than defects. Everything else is a gap: a bad key, an
#: unexplained refusal and a broken cost guard are all things the operator must FIX, not accept.
_STOP_LIMITS = frozenset({SHODAN_PROVIDER_EXHAUSTED, SHODAN_ENTITLEMENT, SHODAN_OPERATOR_RESERVE,
                          SHODAN_UNKNOWN_WITH_RESERVE})

#: a stop that the PROVIDER proved, as the error class the terminal speaks. Only these two are the
#: provider's own boundary; an operator reserve or an unreadable balance is OUR policy or OUR problem and
#: must not be dressed up as the provider refusing us (B1.4).
_STOP_CLASS = {SHODAN_PROVIDER_EXHAUSTED: "quota", SHODAN_ENTITLEMENT: "entitlement"}
#: count-endpoint outcomes that stop SIZING, mapped to whether they also prove the CREDENTIAL is
#: refused. `auth` is global — the key does not work anywhere, so paid work must stop too and read as a
#: gap. `forbidden` and `entitlement` are proven only for the endpoint that returned them, so they end
#: sizing and leave the paid lane to discover its own answer (review-B1.5r3#2).
_COUNT_STOPS = {"auth": True, "forbidden": False, "entitlement": False}

#: balance-read outcomes that mean Shodan is NOT accepting this key, so even FREE calls must stop. Quota,
#: entitlement and an operator reserve are all "the key works, the spend does not" — sizing continues
#: through those, because /host/count costs nothing (review-B1.5r2#1).
_SIZING_REFUSED = {SHODAN_AUTH_REFUSED: "auth_refused", SHODAN_FORBIDDEN: "forbidden"}


#: stops that are OURS: the outcome is LIMITED (deliberately bounded), never a provider class and never
#: a degraded execution.
_OPERATOR_STOPS = frozenset({SHODAN_OPERATOR_RESERVE, SHODAN_UNKNOWN_WITH_RESERVE})

#: read outcomes that PROVE paid work is pointless. transport/parse/server say nothing about the account,
#: so they keep the ordinary unknown fallback; these four are the provider telling us plainly.
_BLOCKING_READ = frozenset({"auth", "quota", "entitlement", "forbidden"})


def _exact_int(v, *, minimum: int = 0):
    """An exact int >= minimum, or None. `True` is an int in Python, and a float or numeric string is a
    different kind of claim — none of them may pass for a credit count."""
    if isinstance(v, bool) or not isinstance(v, int) or v < minimum:
        return None
    return v


def _allowance_field(v):
    """-> (value, unlimited). `usage_limits.query_credits == -1` is Shodan's DOCUMENTED unlimited-plan
    sentinel, so rejecting it would report an unlimited plan as unreadable."""
    if isinstance(v, bool) or not isinstance(v, int):
        return None, False
    if v == -1:
        return None, True
    return (v, False) if v >= 0 else (None, False)


def _remaining_field(v):
    """-> value or None. An EXACT non-negative int, with NO -1 sentinel.

    review-B1.2r3#1: I had the top-level `query_credits` share the allowance parser, so `-1` there meant
    "unlimited" and disabled the reserve entirely. Nothing establishes that sentinel for this field —
    Shodan's own documented example pairs a FINITE `query_credits` with `usage_limits.query_credits: -1`,
    and the test asserting it was a shape I invented rather than measured. Guessing here fails OPEN on a
    spending control, so an unproven `-1` is schema drift until a real payload says otherwise."""
    return _exact_int(v)


def _shodan_reserve_setting():
    """-> (reserve, valid). ABSENT means 0 and is fine. PRESENT-BUT-INVALID is NOT: a typo, a bool, a
    float or an oversized value would otherwise fall back to 0 and silently DISABLE the operator's cost
    guard — failing open on a control whose whole purpose is to withhold spending."""
    raw = settings.performance().get("SHODAN_CREDIT_RESERVE")
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return 0, True
    v = _exact_int(raw)
    if v is None and isinstance(raw, str):
        s = raw.strip()
        if s.isdigit():
            v = int(s)
    if v is None or v > _SHODAN_RESERVE_MAX:
        return 0, False
    return v, True


def shodan_balance(doc, *, reserve: "int | None" = None) -> ShodanBalance:
    """Turn an `/api-info` body (or None, when the read failed) into the settled contract.

    The cases that matter, each with a distinct `stop_kind` (and see `stop_is_limit` — not every stop is
    an expected boundary):

      remaining 0, reserve 0   -> PROVIDER EXHAUSTED. The account really is empty.            LIMIT
      remaining <= reserve     -> OPERATOR RESERVE. Credits exist; Shodan would still serve   LIMIT
                                  us, and calling this exhaustion would blame the provider
                                  for our own policy.
      unknown + reserve 0      -> may spend: exhaustion is a clean, self-announcing outcome.
      unknown + reserve >0     -> NO paid searches: we cannot tell where the reserve begins.  LIMIT
      reserve knob invalid     -> NO paid searches: a broken cost guard must not read as      GAP
                                  'no guard'.

    An unlimited PLAN ALLOWANCE (`usage_limits.query_credits == -1`) is context only — it never makes
    this month's finite balance unbounded, and it never suspends the reserve."""
    reserve_valid = True
    if reserve is None:
        reserve, reserve_valid = _shodan_reserve_setting()
    else:
        strict = _exact_int(reserve)
        if strict is None:                       # a caller passing True/12.9/"abc" is a bug, not a policy
            reserve, reserve_valid = 0, False
        else:
            reserve = strict
    remaining = allowance = None
    unlimited = False
    allowance_unlimited = False
    if isinstance(doc, dict):
        remaining = _remaining_field(doc.get("query_credits"))
        limits = doc.get("usage_limits")
        if isinstance(limits, dict):
            allowance, allowance_unlimited = _allowance_field(limits.get("query_credits"))
    # review-B1.2r2#1: the ALLOWANCE and the REMAINING balance are separate facts. Shodan's own /api-info
    # example returns a finite `query_credits: 100000` alongside `usage_limits.query_credits: -1` — an
    # unlimited PLAN with a finite balance right now. Letting the allowance flip the account to unlimited
    # discarded the real number and would have spent against a ceiling that does not describe this month.
    if not reserve_valid:
        return ShodanBalance(remaining, allowance, 0, 0, False,
                             "SHODAN_CREDIT_RESERVE is set but unusable — refusing to spend rather than "
                             "silently disabling the operator's cost guard",
                             allowance_unlimited=allowance_unlimited,
                             stop_kind=SHODAN_RESERVE_INVALID)
    if remaining is None:
        if reserve:
            return ShodanBalance(None, allowance, reserve, 0, False,
                                 "balance UNKNOWN and a reserve is set — cannot tell where the reserve "
                                 "begins, so no paid search is issued (free operations continue)",
                                 allowance_unlimited=allowance_unlimited,
                                 stop_kind=SHODAN_UNKNOWN_WITH_RESERVE)
        return ShodanBalance(None, allowance, reserve, None, True,
                             "balance UNKNOWN, no reserve — spending until the provider refuses "
                             "(exhaustion is a clean, self-announcing outcome)",
                             allowance_unlimited=allowance_unlimited)
    spendable = max(0, remaining - reserve)
    if spendable == 0:
        if remaining <= 0:
            return ShodanBalance(remaining, allowance, reserve, 0, False,
                                 f"provider balance EXHAUSTED ({remaining} credit(s) remain)"
                                 + (f"; reserve {reserve} is not the cause" if reserve else ""),
                                 allowance_unlimited=allowance_unlimited,
                                 stop_kind=SHODAN_PROVIDER_EXHAUSTED)
        return ShodanBalance(remaining, allowance, reserve, 0, False,
                             f"{remaining} credit(s) remain but SHODAN_CREDIT_RESERVE={reserve} withholds "
                             f"them — an OPERATOR limit, not provider exhaustion",
                             allowance_unlimited=allowance_unlimited,
                             stop_kind=SHODAN_OPERATOR_RESERVE)
    return ShodanBalance(remaining, allowance, reserve, spendable, True,
                         f"{spendable} spendable of {remaining} remaining"
                         + (" (plan allowance UNLIMITED)" if allowance_unlimited else
                            f" (plan allowance {allowance})" if allowance is not None else "")
                         + (f", reserve {reserve}" if reserve else ""),
                         allowance_unlimited=allowance_unlimited)


def _blocked_read(bal: ShodanBalance, cls: str) -> ShodanBalance:
    """A read outcome that PROVES paid work is pointless must also STOP it.

    review-B1.2r2#2: the failure paths were `replace(shodan_balance(None), read_error=...)`, and with
    reserve 0 that unknown contract says `may_spend=True`. So `/api-info` could prove a bad key or an
    exhausted account and the coordinator would still have gone and spent credits against it. The read
    error was recorded and then ignored by the only field anyone acts on."""
    if cls not in _BLOCKING_READ:
        return dataclasses.replace(bal, read_error=cls)      # transport/parse/server: says nothing
    kind = {"quota": SHODAN_PROVIDER_EXHAUSTED, "entitlement": SHODAN_ENTITLEMENT,
            "auth": SHODAN_AUTH_REFUSED}.get(cls, SHODAN_FORBIDDEN)
    why = {"quota": "the provider reports the query-credit balance EXHAUSTED",
           "entitlement": "the PLAN cannot reach this endpoint",
           "auth": "the credential was REJECTED — a setup defect, not an expected boundary",
           }.get(cls, f"the provider REFUSED the balance read ({cls})")
    # review-B1.5r3#4: this told every operator that "free operations continue", which stopped being
    # true when a REFUSED CREDENTIAL began blocking free sizing too. What continues depends on WHY we
    # stopped: a spend the provider will not honor still leaves free endpoints usable; a key it will not
    # accept leaves nothing usable at all.
    free = "free operations continue" if kind not in _SIZING_REFUSED else \
        "no free operation is issued either — the key itself was refused"
    return dataclasses.replace(bal, read_error=cls, may_spend=False, spendable=0, stop_kind=kind,
                               reason=f"{why} — no paid search is issued ({free})")


def _read_shodan_balance(key, timeout: int = 15, cooldown=None) -> ShodanBalance:
    """Read `/api-info` (FREE, and it works at a ZERO balance) and settle the contract.

    review-B1.2#3: the READ OUTCOME is preserved separately from the balance facts. Collapsing every
    failure into an undifferentiated "unknown" hid a real problem: with a reserve configured no paid
    request follows, so a BAD KEY produced no other signal and stayed invisible behind "balance unknown;
    reserve protected". `read_error` keeps auth/quota/transport/parse distinguishable — and, for the
    classes that PROVE refusal, also blocks spending.

    A failure yields UNKNOWN, never zero: "we could not look" and "there is nothing left" are different
    facts with different consequences."""
    try:
        url = f"https://api.shodan.io/api-info?key={urllib.parse.quote(str(key))}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(64 * 1024).decode("utf-8", "replace")
    except Exception as e:
        # B1.1 helper: reads the body AT THE RAISE SITE, closes the stream, and refines 401 by body —
        # so an exhausted account reads `quota` here and a bad key reads `auth`, not one blurred class.
        capture_error_body(e, provider="shodan")
        cls = provider_error_class(e)
        if cooldown is not None and cls == PROVIDER_RATE_LIMIT:
            # review-B1.5r2#1: the balance read sat OUTSIDE the shared cooldown, so a 429 here was
            # followed straight away by a count for every pivot. Noted at the raise site, where the
            # response (and any Retry-After) is still readable.
            cooldown.note(e)
        return _blocked_read(shodan_balance(None), cls)
    try:
        doc = _json.loads(body)
    except Exception:
        return _blocked_read(shodan_balance(None), "parse")
    bal = shodan_balance(doc)
    # review-B1.2r2#3: decoding is not validating. A well-formed JSON body carrying `"85"`, `-2` or no
    # `query_credits` at all is SCHEMA drift at the read boundary, and reporting it as a successful read
    # of an unknown balance let a broken response look like a healthy one. (A malformed `usage_limits`
    # stays non-fatal — it is context, not the balance.)
    if not bal.known:
        return _blocked_read(bal, "parse")
    return bal


def _emit_shodan_balance(sid: str, bal: ShodanBalance) -> None:
    """Publish the balance as its OWN ledger event, every lifecycle.

    Emitted unconditionally, INCLUDING the unknown case — a run that could not read the balance must
    still say so, or the previous run's numbers stay on display as if current. `remaining`/`allowance`
    are null when unknown and never defaulted to 0, which would read as a spent account.

    SCOPE (review-B1.2#4): nothing CONSUMES this yet — `views._fold_events` keeps only produced/consumed
    from a ledger event. B1.3 adds the reconciling consumer; until then this is an honest record, not a
    reconciled fact, and no code should claim the latest one supersedes the rest."""
    events.ledger(sid, produced=None, consumed=None, balance={
        "provider": "shodan", "remaining": bal.remaining, "allowance": bal.allowance,
        "reserve": bal.reserve, "spendable": bal.spendable, "known": bal.known,
        "may_spend": bal.may_spend, "allowance_unlimited": bal.allowance_unlimited,
        "stop_kind": bal.stop_kind or None, "stop_is_limit": bal.stop_is_limit,
        "read_error": bal.read_error, "count_refused": bal.count_refused, "reason": bal.reason})


#: B1.5b: there is no OOS cap. RoE boundary — OBSERVE and mine OOS evidence, never actively expand
#: against it. A first-N slice bounded MEMBERSHIP by page order, so which related hosts an operator ever
#: saw depended on which page they happened to appear on; the last hidden membership cap in the lane.
#: Bound a DISPLAY if a report is long. Never the stored evidence.


@_dataclass
class _SharedWork:
    """What ONE coordinator run produced for ALL lanes. Each field is per-source_id; nothing here is a
    lane-agnostic aggregate, because every one of these facts belongs to exactly one lane."""

    balance: "ShodanBalance"
    result: "shodan_sched.WorkResult"
    found: dict                     # sid -> in-scope hosts
    errs: dict                      # sid -> {"last", "last_fail"}
    oos: dict                       # sid -> {"seen", "invalid", "kept": set of identities}
    names: dict                     # sid -> {"seen", "unusable", "noncanonical"} hostname members
    sizing: dict                    # sid -> /host/count lifecycle stats (diagnostic, verdict-inert)
    max_pages: int


@_dataclass(frozen=True)
class _LaneSpec:
    """One Shodan pivot lane: where its values come from and what a match MEANS."""

    sid: str                       # the REGISTERED source_id (literal — never constructed)
    facet: str                     # the Shodan search facet
    source: str                    # provenance tag written onto every ingested entity
    entity: str                    # store entity the pivot values are read from
    field: str                     # field on that entity holding the value
    note: str                      # review note template for an off-scope related host


#: every Shodan search lane, collected TOGETHER so one coordinator can order them fairly.
_SHODAN_LANES = (
    _LaneSpec("probe.favicon", "http.favicon.hash", "favicon-shodan", "live", "favicon",
              "same favicon (hash {}) as an in-scope host — VERIFY OWNERSHIP"),
    _LaneSpec("probe.cert", "ssl.cert.fingerprint", "cert-shodan", "certificate", "sha1",
              "same TLS cert (sha1 {}) as an in-scope host — VERIFY OWNERSHIP"),
)


def _shodan_work(ctx, key, lanes):
    """Spend ONE credit budget across ALL Shodan pivot lanes, under ONE coordinator.

    review-B1.4r2#1: each lane used to build its own balance, ledger and coordinator run, and they were
    then called in sequence — so favicon could consume every spendable credit before certificate work
    was even collected. The coordinator's cross-lane fairness was real in isolation and absent in
    production. Collecting first and spending once is the whole point of it.

    Returns `(balance, WorkResult, {sid: found set})`. Each lane's TERMINAL is still produced inside its
    own `run_provider` bracket, so per-source telemetry and coverage generations are unchanged."""
    max_pages = settings.concurrency("SHODAN_MAX_PAGES", 0)
    scope = ctx.scope
    cooldown = _ProviderCooldown()
    bal = _read_shodan_balance(key, cooldown=cooldown)
    try:
        found: dict = {spec.sid: set() for spec, _vals in lanes}
        oos: dict = {spec.sid: {"seen": 0, "invalid": 0, "kept": set()} for spec, _vals in lanes}
        hostnames: dict = {spec.sid: {"seen": 0, "unusable": 0, "noncanonical": 0} for spec, _vals in lanes}

        # ONE ledger for the coordinator's own lane. Pages never collide inside it: `item_key` is namespaced
        # by the pivot's lane, so a favicon page and a cert page are distinct identities by construction.
        cfg_fp = events.work_unit("probe.shodan", inputs={}, config={"facets": [s.facet for s, _v in lanes]},
                                  schema_version=shodan_sched.SHODAN_WORK_SCHEMA)
        sbase = ctx.run.dir / "raw" / "probe"
        sbase.mkdir(parents=True, exist_ok=True)
        budget.prune_state(sbase, "probe.shodan", cfg_fp)
        ledger = budget.Ledger(budget.state_path(sbase, "probe.shodan", cfg_fp), lane="probe.shodan")
        attempt_dir = fresh_artifact_dir(sbase / "shodan" / cfg_fp[:16])
        by_sid = {spec.sid: spec for spec, _vals in lanes}
        # review-B1.4r3#2: ONE global last-error let a failure in one lane decide another lane's terminal —
        # cert taking a 500 and favicon a quota reported BOTH as FAILED/server. Error evidence is per SOURCE,
        # exactly like every other per-lane fact.
        errs: dict = {spec.sid: {"last": None, "last_fail": None} for spec, _vals in lanes}

        def search(pivot, page):
            # review-B1.5r3#1: only ONE wait ran, before the whole paid loop, so a 429 mid-purchase was
            # neither recorded nor honored and the scheduler went straight to the next pivot. Every paid
            # request now passes through the same cooldown that sizing uses.
            cooldown.wait()
            matches, total, err = _shodan_page(key, pivot.facet, pivot.value, page)
            if err is not None and provider_error_class(err) == PROVIDER_RATE_LIMIT:
                cooldown.note(err)
            if err is not None:
                slot = errs[pivot.lane]
                slot["last"] = err
                if not is_provider_limit(provider_error_class(err)):
                    slot["last_fail"] = err
            return matches, total, err

        def ingest(pivot, page, matches, raw_path):
            """Turn one page's rows into entities. `raw_path` IS the page artifact the coordinator published,
            so every ingested host's `raw_ref` points at a file that provably contains its evidence."""
            spec = by_sid[pivot.lane]
            label = spec.sid.split(".", 1)[-1]
            v = pivot.value
            names = hostnames[spec.sid]
            for m in matches:
                for raw_hn in (m.get("hostnames") or []):
                    names["seen"] += 1
                    hn = raw_hn.strip().lower().rstrip(".")
                    # ONE canonical form decides identity AND scope, so a Unicode name and its punycode
                    # spelling are the same host to both. `canon_host_strict` is Quarry's single IDNA policy.
                    canon = normalize.canon_host_strict(hn)
                    if canon is None:
                        # review-B1.5br2#1: a name that is not a valid HOSTNAME must never become a
                        # `subdomain`. That entity is consumed by ACTIVE lanes elsewhere — resolution,
                        # alterx, takeover checks, httpx — so "this lane never contacts it" was true of this
                        # lane and false of Quarry. A valid DNS OWNER NAME (`_dmarc`, `_acme-challenge`, a
                        # wildcard) is real evidence and is retained as PASSIVE review evidence; anything
                        # else is malformed and counted as unusable.
                        owner = _dns_owner_name(hn)
                        if owner is None:
                            names["unusable"] += 1      # counted, never silently skipped
                            continue
                        names["noncanonical"] += 1
                        where = "in-scope" if (scope.in_scope(owner) and not scope.is_oos(owner)) else "off-scope"
                        rec = {"id": f"{label}:{v}:{owner}", "klass": "dns-owner-name", "value": owner,
                               "note": f"{where} DNS owner name (not a hostname) seen alongside "
                                       + spec.note.format(v),
                               "sources": [spec.source], "raw_ref": str(raw_path)}
                        if store.canonical_key("review", rec):
                            ctx.run.add("review", rec)
                        continue
                    hn = canon
                    if "." not in hn:
                        # a bare label canonicalizes cleanly but names no domain, so it can neither be
                        # scoped nor attributed. Counted, like every other name we cannot use.
                        names["unusable"] += 1
                        continue
                    if scope.in_scope(hn) and not scope.is_oos(hn):
                        # review-r6#1: the response HAD this in-scope host — it belongs in `found` REGARDLESS
                        # of whether the store already had it (dedup is a storage concern, NOT presence).
                        found[spec.sid].add(hn)
                        ctx.run.add("subdomain", {"host": hn, "sources": [spec.source],
                                                  "raw_ref": str(raw_path)})
                    else:
                        # OFF-SCOPE. The RoE boundary is OBSERVE, never expand: a host returned by a page we
                        # already BOUGHT is evidence we hold, and mining it is passive. It reaches a REVIEW
                        # queue — `related-host` is consumed by nothing active (every active lane filters on
                        # its own klass AND `scope.active_allowed`), so retention adds no traffic.
                        #
                        # B1.5b: retained in FULL. The old first-N slice per pivot dropped candidates by page
                        # order, so which related hosts an operator ever saw depended on where they appeared.
                        # Deduplicate by identity; never truncate.
                        rec = {"id": f"{label}:{v}:{hn}", "klass": "related-host", "value": hn,
                               "note": spec.note.format(v), "sources": [spec.source],
                               "raw_ref": str(raw_path)}
                        stats = oos[spec.sid]
                        stats["seen"] += 1
                        if not store.canonical_key("review", rec):
                            stats["invalid"] += 1       # unidentifiable -> unstorable: a REAL loss, reported
                            continue
                        ctx.run.add("review", rec)      # False here means ALREADY KNOWN, which is not a loss
                        stats["kept"].add(rec["id"])
            return len(matches)

        states = [shodan_sched.PivotState(shodan_sched.Pivot(spec.sid, spec.facet, v))
                  for spec, vals in lanes for v in vals]
        sizing, refused = _size_pivots(key, states, ledger=ledger, attempt_dir=attempt_dir,
                                       cooldown=cooldown, refused=_SIZING_REFUSED.get(bal.stop_kind))
        if refused:
            # a count PROVED the credential is refused. /api-info may well have SUCCEEDED — a key can be
            # revoked between the two — so spending stops while the measured balance and `read_error` are
            # left exactly as /api-info reported them. review-B1.5r4#3: overwriting `read_error` made
            # reconciliation announce "balance read failed" about a read that worked.
            bal = dataclasses.replace(bal, may_spend=False, spendable=0, count_refused=refused,
                                      stop_kind=SHODAN_AUTH_REFUSED,
                                      reason=f"shodan refused the credential on /host/count ({refused})")
        def should_stop(cls):
            """Failures further requests cannot get past. NOT a reclassification (review-B1.5r4#1): these
            stay exactly what they are — gaps — and only stop us ASKING.

              auth        the credential is refused; every remaining pivot would be refused identically
              forbidden   the shared search endpoint said no; the next pivot uses the same endpoint
              rate_limit  once is "back off and retry"; twice is a provider we would be hammering
            """
            return cls in ("auth", "forbidden") or (cls == PROVIDER_RATE_LIMIT and cooldown.hits > 1)

        res = shodan_sched.run_work(ctx, states=states, balance=bal, search=search, ingest=ingest,
                                    ledger=ledger, attempt_dir=attempt_dir, max_pages=max_pages,
                                    should_stop=should_stop)
        return _SharedWork(balance=bal, result=res, found=found, errs=errs, oos=oos, names=hostnames,
                           sizing=sizing, max_pages=max_pages)
    finally:
        # review-B1.5r5#3: emitting after sizing made the record reflect what the run ACTED on, but
        # also meant a failure in state setup, the cooldown or sizing itself left NO balance event —
        # reopening the missing-lifecycle hole this telemetry exists to close. Exactly one record per
        # lane, on every path, carrying the final state of `bal`.
        for spec, _vals in lanes:
            _emit_shodan_balance(spec.sid, bal)


def _hostname_facts(nm: dict) -> list:
    """Every hostname fact, stated INDEPENDENTLY.

    review-B1.5br4#2: this was one if/else, so any unusable name suppressed the noncanonical count — a
    page carrying `_dmarc.acme.com` alongside one malformed value stopped reporting that passive DNS
    owner evidence had been retained at all. Two different facts about two different names cannot share
    a branch."""
    facts = [f"{nm['seen']} hostname(s) read"]
    if nm["unusable"]:
        facts.append(f"{nm['unusable']} not usable as a host name")
    if nm["noncanonical"]:
        facts.append(f"{nm['noncanonical']} valid DNS owner name(s) retained as PASSIVE evidence "
                     f"(not hostnames, never actively expanded)")
    return facts


def _size_pivots(key, states, *, ledger, attempt_dir, cooldown, refused=None) -> tuple:
    """Size EVERY eligible pivot with a free `/host/count`, every lifecycle. Returns per-lane stats.

    Including pivots whose pages are all already owned: that is how Quarry finds results that appeared
    since the pagination completed, instead of treating an old completion as permanent.

    Order is CROSS-LANE FAIR (review-B1.5r1#2): sizing in lane order meant an early stop sized every
    favicon pivot and no certificate one, so a provider slowdown decided which lane got ordered at all.

    Returns `(stats, refused_credential)`; the second is set when a count proved the KEY is refused,
    which must stop paid work too.

    PROVIDER-SAFE without a new knob. Requests are serial, carry the same per-request timeout as a paid
    search, and go through a shared cooldown — so a 429 is honored by everything that follows, including
    the paid run. A first 429 backs off and continues; a REPEATED one stops sizing for this lifecycle.
    Unsized pivots keep unknown cardinality, which is a position and not an exclusion.

    A count is used for ORDERING only once its evidence is durably bound (review-B1.5r1#3): ranking
    scarce paid credits by something we did not keep would make the ordering unauditable."""
    stats: dict = {}
    refused_credential = [None]                      # set when a count PROVES the key itself is refused

    def stat(sid):
        return stats.setdefault(sid, {"attempted": 0, "succeeded": 0, "not_attempted": 0,
                                      "failed_by_class": {}, "evidence_failed": 0, "stop_reason": ""})

    ordered = budget.order_fairly(list(states), lambda st: st.pivot.lane)
    # a PROVEN refusal of the credential means not one request: free or not, hammering every pivot with a
    # key Shodan has already rejected is exactly what the contract's "while Shodan still accepts the key"
    # excludes (review-B1.5r2#1).
    stopped = refused or ""
    for st in ordered:
        sid = st.pivot.lane
        if stopped:
            stat(sid)["not_attempted"] += 1
            continue
        cooldown.wait()                              # honor any slowdown already in force
        stat(sid)["attempted"] += 1
        total, raw, err = _shodan_count(key, st.pivot.facet, st.pivot.value)
        if err is not None:
            cls = provider_error_class(err)
            fbc = stat(sid)["failed_by_class"]
            fbc[cls] = fbc.get(cls, 0) + 1
            if cls == PROVIDER_RATE_LIMIT:
                cooldown.note(err)                   # the paid run waits this out too
                if cooldown.hits > 1:
                    stopped = "rate_limit"
            elif cls in _COUNT_STOPS:
                # a refusal does not become acceptable by repetition: asking every remaining pivot the
                # same rejected question is exactly the fan-out this stops (review-B1.5r3#2).
                stopped = cls
                if _COUNT_STOPS[cls]:
                    refused_credential[0] = cls
            continue                                 # unknown cardinality; the pivot stays eligible
        # the EXACT response bytes, named by an identity that binds them to the request that produced
        # them (`count_key` = schema|lane|facet|value|count). Evidence, never a completion: sizing is
        # redone every lifecycle and must never let a later run skip a count.
        ckey = shodan_sched.count_key(st.pivot)
        dig = hashlib.sha256(raw).hexdigest()
        art = attempt_dir / f"{ckey}.json"
        if not (budget.publish_bytes(art, raw, digest=dig) and ledger.add_evidence(ckey, art, digest=dig)):
            stat(sid)["evidence_failed"] += 1
            continue                                 # unbound evidence may not order paid work
        st.cardinality = total
        stat(sid)["succeeded"] += 1
        events.ledger(sid, produced=None, consumed=None, shodan_count={
            "facet": st.pivot.facet, "value": st.pivot.value, "total": total,
            "artifact": str(art), "digest": dig, "item": ckey})
    for st in states:
        stat(st.pivot.lane)
    if stopped:
        # review-B1.5r2#3: the reason was written only while walking LATER unattempted pivots, so a stop
        # on the final one left every lane reporting None. Stamp it on each participating lane.
        for s in stats.values():
            s["stop_reason"] = stopped
    return stats, refused_credential[0]


def _shodan_result(spec, values, work):
    """One lane's COVERAGE and TERMINAL, derived from the shared coordinator run.

    Runs inside that lane's own `run_provider` bracket, because `coverage_reset` opens the generation
    there — coverage emitted before the bracket would be wiped by it.

    review-r3#4 terminal truth: a plain set (SUCCESS/EMPTY) when nothing failed; a PARTIAL
    ProviderResult (with the dominant class) when evidence exists alongside errors; and a RAISE when the
    lane yielded nothing and something either broke or refused us."""
    bal, res, max_pages = work.balance, work.result, work.max_pages
    o = res.lanes.get(spec.sid) or shodan_sched.LaneOutcome(lane=spec.sid)
    shodan_sched.report(spec.sid, o, balance=bal, persisted=res.persisted, max_pages=max_pages,
                        stop_cause=res.stop_cause)
    hits = work.found.get(spec.sid) or set()
    lane_errs = work.errs.get(spec.sid) or {"last": None, "last_fail": None}
    # B1.5b: OOS RETENTION is its own fact. Deduplication is not omission, so only candidates we could
    # not IDENTIFY (and therefore could not store) count as omitted — a real evidence loss, reported as
    # a gap rather than absorbed silently. Emitted every run so a later clean run clears it.
    st = work.oos.get(spec.sid) or {"seen": 0, "invalid": 0, "kept": set()}
    events.coverage_partial(spec.sid, kind=events.COVERAGE_TIMEOUT, measure="shodan_oos_retained",
                            unit=f"{spec.sid}.oos", eligible=st["seen"],
                            tested=st["seen"] - st["invalid"], omitted=st["invalid"],
                            reason=(f"{st['invalid']} off-scope candidate(s) could not be identified "
                                    f"and were NOT stored" if st["invalid"] else
                                    f"{len(st['kept'])} distinct off-scope related host(s) retained "
                                    f"from {st['seen']} observation(s) — no cap"))
    # SIZING is DIAGNOSTIC, and says what actually happened rather than what was hoped. It is a ledger
    # event, not a coverage counter: review-B1.5r1#4 — forced into coverage it had to report every pivot
    # as `tested` even when a first-call 429 meant none were attempted, could not carry the attempt count
    # or the stop reason, and claimed agreement where no baseline had existed. Coverage is decided by
    # PAID SEARCH; a failed count changes nothing about it.
    sz = work.sizing.get(spec.sid) or {}
    events.ledger(spec.sid, produced=None, consumed=None, shodan_sizing={
        "pivots": len(values), "attempted": sz.get("attempted", 0),
        "succeeded": sz.get("succeeded", 0), "not_attempted": sz.get("not_attempted", 0),
        "failed_by_class": sz.get("failed_by_class") or {},
        "evidence_failed": sz.get("evidence_failed", 0),
        "stop_reason": sz.get("stop_reason") or None,
        "compared": o.count_compared, "drift": o.count_drift})
    # hostname MEMBERS are their own contract: a name we cannot use at all is a lost observation, and a
    # name that is not canonical is usable but deduplicates on the weaker form. Both are stated.
    nm = work.names.get(spec.sid) or {"seen": 0, "unusable": 0, "noncanonical": 0}
    events.coverage_partial(spec.sid, kind=events.COVERAGE_TIMEOUT, measure="shodan_hostnames",
                            unit=f"{spec.sid}.hostnames", eligible=nm["seen"],
                            tested=nm["seen"] - nm["unusable"], omitted=nm["unusable"],
                            reason="; ".join(_hostname_facts(nm)))
    fail_classes, limit_classes = dict(o.fail_classes), dict(o.limit_classes)
    errored = sum(fail_classes.values()) + sum(limit_classes.values())
    evidence = o.pages_bought + o.pages_replayed
    if values and not evidence and not errored:
        stop_cls = _STOP_CLASS.get(bal.stop_kind)
        if stop_cls:
            # the balance PROVED further work is pointless, so no request was issued. There is no
            # exception to raise (nothing failed), and a bare empty set would read as a clean EMPTY —
            # the lane silently doing nothing on a depleted account.
            return ProviderResult(hits, partial=True, partial_kind="degraded", error_class=stop_cls,
                                  partial_reason=f"no page queried — {bal.reason}")
        if bal.stop_kind and not bal.stop_is_limit:
            # review-B1.4r2#3: a stop that is NOT a soft limit — a credential that does not work, an
            # unexplained refusal, a broken cost guard — is a DEFECT in our setup. It used to fall
            # through to `return found`, producing a ghost EMPTY terminal with no class while the
            # coverage said "gap": the verdict was right and `failed_tools` was a lie.
            # the CANONICAL class, not the internal stop token: `count_refused` is set when a free
            # count proved the key is refused, and it is what a consumer can act on (review-B1.5r5#2).
            raise ShodanPageError(bal.count_refused or bal.read_error or bal.stop_kind,
                                  RuntimeError(f"shodan: {bal.reason}"))
    if values and errored and not hits and not evidence:
        # everything we attempted yielded NOTHING. A REAL failure outranks a limit: if something actually
        # broke, the run must not read as "merely limited" (review#2 — the outcome used to depend on
        # which pivot happened to be last).
        raise (lane_errs["last_fail"] if lane_errs["last_fail"] is not None else lane_errs["last"])
    # review-B1.4r3#3 / r4#2: work this lane did not reach. `unqueried` alone was not the remainder —
    # a pivot with one bought page and four provider-bounded pages left is just as incomplete, and it
    # reported EMPTY (or SUCCESS, with a non-empty first page) while its own coverage said omitted=4.
    # The scheduler already models the whole remainder; the terminal must read ALL of it.
    left = len(o.unqueried) + o.pages_left_known
    if left and not errored:
        stop = res.stop_cause or ""
        if stop in ("ledger_unwritable", "publish_failed", "scheduler_invariant"):
            # OUR machinery failed. That is a defect and must read as one.
            raise ShodanPageError(stop, RuntimeError(f"shodan: scheduling stopped — {stop}"))
        cls = stop.split(":", 1)[1] if stop.startswith("provider_limit:") else None
        if stop.startswith("provider_stop:"):
            # review-B1.5r5#1: another lane's FAILURE ended purchasing. This lane is incomplete for a
            # real reason, and that reason is a gap — reporting it as a bare PARTIAL with no class said
            # "something is missing" while withholding the one fact that explains it.
            return ProviderResult(hits, partial=True, partial_kind="degraded",
                                  error_class=stop.split(":", 1)[1],
                                  partial_reason=f"{len(o.unqueried)} pivot(s) never queried, "
                                                 f"{o.pages_left_known} page(s) unbought — {stop}")
        if stop == "budget_provider" and not cls:
            cls = _STOP_CLASS.get(SHODAN_PROVIDER_EXHAUSTED)
        # review-B1.4r4#3: an OPERATOR boundary is a LIMIT, not a degraded execution and not the
        # provider's fault. It carries no provider class, so it says `limited` in its own right.
        operator = stop == "budget_reserve" or (not stop and bal.stop_kind in _OPERATOR_STOPS)
        why = (f"{len(o.unqueried)} pivot(s) never queried, {o.pages_left_known} page(s) unbought — "
               f"{stop or bal.reason or 'credit budget exhausted'}")
        if bal.read_error:
            # the balance read ALSO failed: keep both facts (an `unknown_with_reserve` stop is our
            # caution, and the read error is still a gap in its own coverage measure).
            why += f"; balance read failed ({bal.read_error})"
        return ProviderResult(hits, partial=True, partial_kind="degraded", error_class=cls,
                              limited=operator, partial_reason=why)
    if errored:
        # review#2: pick the dominant class from REAL failures when there are any, so a single transport
        # error is never relabelled as a provider limit (nor the reverse).
        pool = fail_classes or limit_classes
        dominant = max(pool.items(), key=lambda kv: (kv[1], kv[0]))[0]
        limited = sum(limit_classes.values())
        detail = (f"{errored}/{len(values)} shodan pivot(s) errored ({dominant})"
                  + (f", incl. {limited} provider-limited" if limited and fail_classes else "")
                  + " — evidence KEPT")
        return ProviderResult(hits, partial=True, partial_kind="degraded", error_class=dominant,
                              partial_reason=detail)
    return hits


def _shodan_pivot(ctx, key, values, facet, source, sid, note):
    """ONE lane through the shared path: collect, spend, produce that lane's result.

    Production calls `_shodan_pivots`, which hands the coordinator EVERY lane at once so credits are
    ordered fairly across them. This is the same two functions with a single lane — a seam for driving
    one lane directly, not a second implementation."""
    spec = _LaneSpec(sid, facet, source, "", "", note)
    vals = sorted({str(v) for v in values if v})
    return _shodan_result(spec, vals, _shodan_work(ctx, key, [(spec, vals)]))


def _shodan_pivots(ctx) -> None:
    """Every Shodan search pivot: collect ALL lanes' values first, then spend one budget across them.

    review-B1.4r2#2: pivot values are NEVER sliced. A first-N cap picked WHICH pivots to query by store
    order — silent, non-deterministic breadth loss — and reporting it as a gap made it honest without
    making it right. Throughput is bounded by the credit balance and the page policy; MEMBERSHIP is not
    bounded at all.

    review-B1.4r3#1/#4: every lane is STARTED before a single credit is spent, and every lane gets a
    terminal even when it cannot run. A silent early return left the previous run's terminal and coverage
    generation standing as though they were current."""
    key = secrets.shodan()
    lanes = [(spec, sorted({str(r.get(spec.field)) for r in ctx.run.read(spec.entity)
                            if r.get(spec.field)}))
             for spec in _SHODAN_LANES]
    shared: list = []

    def collect():
        if not key or not any(vals for _spec, vals in lanes):
            return                                  # nothing to spend on; each lane finalizes as SKIPPED
        shared.append(_shodan_work(ctx, key, [(s, v) for s, v in lanes if v]))

    def finalize(spec, values):
        if not key:
            raise contract.ProviderSkip("no shodan key configured")
        if not values:
            raise contract.ProviderSkip(f"no {spec.field} value to pivot on")
        if not shared:
            raise ShodanPageError("error", RuntimeError("shodan: shared work produced no result"))
        return _shodan_result(spec, values, shared[0])

    entries = []
    for spec, values in lanes:
        # review-r3#5: a stable work_unit from the bounded inputs + effective config — the C07/C10
        # resume key. review-r4#4 + r5#5: the credential fingerprint scopes it to the ACCOUNT.
        wu = events.work_unit(spec.sid, inputs={"values": values},
                              config={"facet": spec.facet,
                                      "max_pages": settings.concurrency("SHODAN_MAX_PAGES", 0),
                                      "oos_cap": 0,        # B1.5b: no cap; kept in the key so a
                                                           # resumed unit from a CAPPED generation is
                                                           # not mistaken for a complete one
                                      "cred_fp": secrets.fingerprint(key) if key else None})
        entries.append((spec.sid, wu, lambda s=spec, v=values: finalize(s, v)))
    results = contract.run_providers(entries, collect)
    for spec, _values in lanes:
        hosts = results.get(spec.sid)
        if hosts:
            ctx.echo(f"  {spec.sid.split('.', 1)[-1]}: +{len(hosts)} in-scope host(s) via Shodan "
                     f"{spec.facet} pivot")


def _vhost_wordlist():
    """Locate a DEDICATED vhost wordlist (small, label-per-line). We deliberately do NOT fall back to
    the big DNS brute list — vhost fuzzing is IPs×apexes×words, so an unbounded list is a footgun.
    None → the step records a skip (opt-in by dropping a list at one of these paths)."""
    from pathlib import Path
    home = Path.home()
    for p in (home / ".config/quarry/wordlists/vhost.txt",     # canonical (clean layout)
              home / ".config/quarry/vhost-wordlist.txt",      # back-compat (pre-reorg installs)
              home / "wordlists/vhosts.txt", home / "wordlists/subdomains-top1million-5000.txt"):
        if p.exists():
            return p
    return None


_VHOST_SCHEMA = 2        # v2: typed status + canonical-host + wordlist-membership row validation


def _vhost_unknown_lifecycle(ctx, why) -> None:
    """Emit an UNKNOWN-coverage generation for the vhost lane, then record the skip.

    review#1 (vhost r5): distinct from _vhost_zero_lifecycle. A missing ffuf binary or a missing wordlist is
    not "zero eligible input" — we could not LOOK at the input at all, so a clean 0/0 would assert there was
    nothing to find. COVERAGE_UNKNOWN carries no counters, forces coverage_valid=False and reaches the verdict
    as a gap. Both exits previously returned without opening any generation, so a PRIOR run's vhost counters
    stayed current after the tool or wordlist went away."""
    for m in ("base_services", "base_services_scanned", "state_persisted"):
        events.coverage_partial("probe.ffuf_vhost", kind=events.COVERAGE_UNKNOWN, measure=m, unit=m,
                                reason=why)
    ctx.run.record("probe", skipped("ffuf-vhost", why))


def _vhost_zero_lifecycle(ctx, why, *, excluded=0, invalid=0) -> None:
    """Emit a COMPLETE zero-valued lifecycle for the vhost lane, then record the skip.

    review#1 (vhost r4): both early returns used to leave a PRIOR run's `base_services`,
    `base_services_scanned`, `result_rows` and persistence state standing as current — so after a scope or
    live-service change that leaves nothing eligible, the operator still saw the old numbers. Every exit path
    now goes through here, which is the same emit-every-lifecycle rule the sourcemap ledger taught us."""
    events.ledger("probe.ffuf_vhost",
                  consumed={"wordlist_submitted": 0, "wordlist_oos_excluded": excluded,
                            "wordlist_invalid": invalid})
    for m in ("base_services", "base_services_scanned", "state_persisted"):
        events.coverage_partial("probe.ffuf_vhost", kind=events.COVERAGE_TIMEOUT, measure=m, unit=m,
                                eligible=0, tested=0, omitted=0, reason=why)
    ctx.run.record("probe", skipped("ffuf-vhost", why))


def _vhost_effective_wordlist(ctx, wl, apex, scope):
    """Build the per-apex wordlist containing ONLY candidates we are allowed to CONTACT.

    review#1 (vhost r1): ffuf sends every word as `Host: FUZZ.<apex>`, so an OOS name was ACTIVELY PROBED and
    only filtered after the response came back. Post-filtering cannot un-send a request to an explicitly
    excluded host. The boundary Lumpy set is: observe and mine OOS evidence, never actively expand against
    OOS — so the exclusion has to happen BEFORE the request, in the wordlist itself.

    Returns (path, digest, submitted_set, eligible_n, excluded_n, invalid_n). The digest binds this EFFECTIVE
    file into the work unit and ledger generation, so a scope change re-scans instead of resuming a narrower
    sweep."""
    words, excluded, invalid = [], 0, 0
    seen = set()
    for raw in wl.read_text(errors="replace").splitlines():
        w = raw.strip().lower().strip(".")
        if not w or w.startswith("#"):
            continue
        # review#1 (vhost r2): CANONICALIZE AND VALIDATE HERE. Validating after the response meant `../admin`,
        # `a/b`, bad labels and Unicode had already been sent in a Host header. The submitted file must
        # contain only names we are willing to contact.
        # review#2 (vhost r3): via the SHARED canonicalizer, so this lane uses the same IDNA2008/UTS-46
        # non-transitional policy as scope canonicalization. The builtin codec maps `faß` -> `fass`, a
        # DIFFERENT domain, which would mean actively contacting a name the operator never scoped.
        host = normalize.canon_host_strict(f"{w}.{apex}")
        if host is None or not host.endswith("." + apex):
            invalid += 1                                 # never contactable: malformed / not under this apex
            continue
        w = host[: -(len(apex) + 1)]                     # the canonical label(s) we will actually submit
        if w in seen:
            continue
        seen.add(w)
        if not scope.active_allowed(host):
            excluded += 1                                # OOS / passive-skipped: never contacted
            continue
        words.append(w)
    eff = ctx.tmp(f"vhost-{apex}.txt")
    eff.write_text("\n".join(words) + ("\n" if words else ""))
    return eff, events.file_digest(eff), set(words), len(words), excluded, invalid


def _vhost_row(row, submitted, apex, scope) -> bool:
    """A usable vhost row — validated, not merely present (review#3 vhost r1).

    Requires a real integer HTTP status (bool excluded: it is an int subclass), a FUZZ value that BELONGS to
    the wordlist we actually submitted (so a fabricated or mangled row cannot invent a candidate), and a
    canonical in-scope final hostname (`../admin` and friends never become a host)."""
    st = row.get("status")
    if not isinstance(st, int) or isinstance(st, bool) or not (100 <= st <= 599):
        return False
    inp = row.get("input")
    if not isinstance(inp, dict):
        return False
    word = inp.get("FUZZ")
    if not isinstance(word, str):
        return False
    w = word.strip().lower().strip(".")
    if not w or w not in submitted:                      # not something we asked for
        return False
    host = normalize.canon_host_strict(f"{w}.{apex}")
    if host is None:
        return False
    return scope.in_scope(host)



def _vhost_status(out, submitted, apex, scope) -> tuple:
    """(trustworthy, clean_rows) for ONE artifact — the completion judgement for the CURRENT attempt only.
    History contributes evidence and must never decide whether this unit is done."""
    rows = ffuf_results(out)
    if rows is None:
        return False, False
    _usable, dropped = ffuf_usable_rows(rows, lambda r: _vhost_row(r, submitted, apex, scope))
    return True, dropped == 0


def _vhost_ingest(ctx, scope, known, base, addrs, apex, unit_id, artifacts, current, seen_hosts,
                  launched, submitted) -> int:
    """Ingest EVERY retained artifact for one BASE SERVICE x apex, then report coverage for the CURRENT one.

    Mirrors the cleared content lane: history is PROVENANCE only (so a dirty old artifact cannot keep the
    coverage gap open forever), coverage is emitted AFTER consumption, and candidate identities are counted
    UNIQUELY per lifecycle so replay cannot inflate them."""
    added = 0
    try:
        for out in artifacts:
            rows = ffuf_results(out)
            if rows is None:
                continue                                     # untrustworthy history: replay nothing from it
            usable, _dropped = ffuf_usable_rows(rows, lambda r: _vhost_row(r, submitted, apex, scope))
            for hit in usable:
                word = hit["input"]["FUZZ"].strip().lower().strip(".")
                host = f"{word}.{apex}"                  # already validated by _vhost_row
                # a vhost that's ALREADY a known subdomain isn't the signal — the value is DNS-INVISIBLE names
                if host in known:
                    continue
                # review#2 (vhost r2): the identity is the BASE SERVICE that served it. Keying on a
                # hostname-as-"origin" wrote a host into the `ip` field, collapsed http://h:80 and
                # https://h:443 into one identity (so two distinct observations merged and could conflict on
                # status), and the note claimed an "origin" served it. `addrs` stays as CONTEXT only.
                if ctx.run.add("review", {"id": f"vhost:{base}:{host}", "klass": "vhost",
                                          "value": host, "host": host, "base": base,
                                          "a": list(addrs) or None,
                                          "status_code": hit.get("status"),
                                          "note": f"base service {base} serves vhost {host} "
                                                  f"(may not resolve in DNS) — VERIFY",
                                          "sources": ["ffuf-vhost"], "raw_ref": str(out)}):
                    added += 1
                seen_hosts.add(f"{base}:{host}")
    except Exception:
        events.coverage_partial("probe.ffuf_vhost", kind=events.COVERAGE_UNKNOWN,
                                unit=f"rows:{unit_id}", measure="result_rows",
                                reason=f"{base}/{apex}: ingestion failed mid-artifact — UNMEASURED")
        raise
    if current is None:
        events.coverage_partial("probe.ffuf_vhost", kind=events.COVERAGE_UNKNOWN,
                                unit=f"rows:{unit_id}", measure="result_rows",
                                reason=(f"{base}/{apex}: "
                                        + ("attempted but produced no ffuf artifact" if launched
                                           else "no current artifact this lifecycle (not launched)")
                                        + " — row coverage UNMEASURED"))
        return added
    rows = ffuf_results(current)
    if rows is None:
        events.coverage_partial("probe.ffuf_vhost", kind=events.COVERAGE_UNKNOWN,
                                unit=f"rows:{unit_id}", measure="result_rows",
                                reason=f"{base}/{apex}: current artifact missing/malformed — UNMEASURED")
        return added
    usable, dropped = ffuf_usable_rows(rows, lambda r: _vhost_row(r, submitted, apex, scope))
    if dropped:
        events.coverage_partial("probe.ffuf_vhost", kind=events.COVERAGE_UNKNOWN,
                                unit=f"rows:{unit_id}", measure="result_rows",
                                reason=f"{base}/{apex}: {dropped} row(s) failed the input/FUZZ contract "
                                       f"— row coverage UNMEASURED")
        return added
    events.coverage_partial("probe.ffuf_vhost", kind=events.COVERAGE_TIMEOUT,
                            unit=f"rows:{unit_id}", measure="result_rows",
                            eligible=len(usable), tested=len(usable), omitted=0,
                            reason=f"{base}/{apex}: {len(usable)} vhost row(s) ingested")
    return added


def _vhost_scan(ctx, base, apex, out, wl, wl_digest, mc, ffuf_to, prof):
    """One ffuf vhost sweep for one BASE SERVICE x apex, under the contract. Extracted FIRST, as a
    standalone no-behaviour-change step, because the enclosing function is a 120-line doubly-nested
    loop and patching it in place is what broke it twice."""
    # -mc = "served/exists" (2xx/3xx/401/403), NOT `all`: a 404/5xx means the server does NOT
    # serve that Host, so it isn't a vhost. -ac drops the catch-all baseline. NO -r: a redirecting
    # vhost is matched on its 3xx (in -mc) and -ac folds a uniform catch-all by size regardless —
    # so we never follow a Location to another (possibly off-scope) host.
    # -maxtime: ffuf GRACEFULLY stops the run at the ceiling (writing its partial -o), so a
    # slow/calibration-stuck service yields real partial results instead of a hard SIGKILL that
    # loses the buffered artifact. exec_tool's timeout is now the hard BACKSTOP (ceiling + margin).
    # -noninteractive: no interactive keybinding console (batch hygiene). -ach not needed — one
    # base service per ffuf call, so -ac already calibrates per-service. (T2.2)
    cmd = ["ffuf", "-w", f"{wl}:FUZZ", "-H", f"Host: FUZZ.{apex}",
           "-u", f"{base}/", "-ac", "-timeout", "7", "-noninteractive",
           "-t", str(settings.workers("ffuf", 40)), "-s",
           "-mc", mc,
           "-o", str(out), "-of", "json"]
    if ffuf_to:                                  # 0 = fully unbounded (RoE no-cut) -> no ceiling at all
        cmd += ["-maxtime", str(ffuf_to)]
    if prof.http_rl:
        cmd += ["-rate", str(prof.http_rl)]
    hard = ffuf_to + 60 if ffuf_to else 0        # backstop when bounded; stays UNBOUNDED (0) when ffuf_to==0
    # C07 inc3: per-base×apex work_unit binds the semantic inputs + coverage-affecting config (match codes,
    # effective wordlist) + that wordlist's digest, so a completed unit is re-run on any change.
    # the unit is BASE SERVICE x apex. The base is what the scan actually CONNECTS through — scheme, host and
    # port — so it IS the identity; a different representative for the same address set is a different unit.
    wu = events.work_unit("probe.ffuf_vhost", inputs={"base": base, "apex": apex},
                          config={"mc": mc, "wordlist": wl.name},
                          file_digests={"wordlist": wl_digest}, schema_version=_VHOST_SCHEMA)
    errf = out.with_suffix(".stderr.log")            # FULL stderr: the -maxtime marker must not be evictable
    r = run_contract("probe.ffuf_vhost", cmd, work_unit=wu, timeout=hard, stderr_path=errf,
                     reclassify=lambda res, o=out, e=errf: reclassify_ffuf(res, o, e, ffuf_to or None))   # graceful -maxtime; hard backstop
    return r


def _vhost_enum(ctx) -> None:
    """Virtual-host enumeration (ffuf `-H 'Host: FUZZ.<apex>'`): a web server frequently serves name-based
    vhosts that DON'T resolve in public DNS (staging/internal/legacy/pre-prod). We fuzz the Host header
    against every non-CDN active-allowed live BASE SERVICE — NOT `http://<ip>/`. A bare-IP request
    fails on HTTPS/redirecting origins: Caddy/CDN answers port 80 with a uniform redirect that `-ac`
    folds to nothing, and a bare-IP TLS handshake fails SNI. Connecting via a real live host (valid
    scheme + SNI + cert) still reaches the same server, and the overridden Host header surfaces the
    DNS-invisible vhosts. `-ac` drops the catch-all so a distinct response stands out. Hits are `vhost`
    review candidates (a 200 isn't proof the name resolves/is owned — human verifies). Active; needs
    ffuf + a vhost wordlist. Membership is base services (that is what ffuf connects through); the address
    set only RANKS them, so one co-hosted representative is fuzzed first and the rest follow — never dropped.

    Only DNS-INVISIBLE hits are surfaced — a vhost that's already a known subdomain is dropped (the
    signal is names that DON'T resolve). Base URL is chosen HTTPS-first + subdomain-first (the apex is
    often a separate static site). Matching is the "served/exists" set (2xx/3xx/401/403) + `-ac` (drops
    the catch-all baseline) — broader than a bare 200/301, but a 404/5xx means the Host isn't served so
    it's excluded. Redirects are NOT followed (no `-r`): a vhost that 30x's is already a hit via `-mc`
    (3xx matched) and `-ac` folds a uniform catch-all by response SIZE whether or not we follow — so we
    classify on the 3xx itself and never chase a Location cross-host / off-scope."""
    if not have("ffuf"):
        _vhost_unknown_lifecycle(ctx, "ffuf not installed — vhost coverage UNMEASURED")
        return
    wl = _vhost_wordlist()
    if wl is None:
        _vhost_unknown_lifecycle(ctx, "no vhost wordlist (~/.config/quarry/wordlists/vhost.txt) "
                                      "— vhost coverage UNMEASURED")
        return
    scope, prof = ctx.scope, ctx.profile
    # EVERY non-CDN active-allowed base service is a unit; the score only RANKS them. Prefer HTTPS (valid
    # SNI, no port-80 redirect dance) and a SUBDOMAIN host — the bare apex is often a SEPARATE static site,
    # not the vhost-routing app, so fuzzing it first would miss the app's vhosts. score = https(2) + sub(1).
    apexset = {a.lower() for a in prof.apex_domains}
    # review#2 (vhost r1): "origin coverage" was FICTIONAL. Keeping only `a[0]` collapsed 74 distinct A-record
    # origins to 47 keys on the OTC data, silently dropping 27 before any budget — and ffuf connects to
    # `base`, a HOSTNAME, so it never routed through the origin key at all; DNS decided which address
    # answered. ffuf 2.1.0-dev offers `-sni` (static) but NO address-pinning flag, so honestly scanning a
    # chosen A record is not achievable with this tool. So membership is what we ACTUALLY scan: BASE SERVICES.
    #
    # The ADDRESS SET survives as a RANK ONLY: one representative per co-hosted set is fuzzed first, then
    # the rest. A bounded run therefore gets full origin spread before it spends time on likely-redundant
    # co-hosted names — and nothing is excluded.
    bases: list = []
    for l in ctx.run.read("live"):
        if l.get("cdn"):
            continue
        url = (l.get("url") or "").strip()
        m = _re.match(r"(?i)(https?://[^/]+)", url)
        host = normalize.host_of_url(url)
        if not m or not scope.active_allowed(host):
            continue
        score = (2 if url.lower().startswith("https://") else 0) + (1 if host not in apexset else 0)
        addrs = tuple(sorted(l.get("a") or []))          # the FULL A set, not just the first
        bases.append({"base": m.group(1), "host": host, "score": score, "addrs": addrs})
    # rank tier 0 = the best-scoring representative of each co-hosted address set; tier 1 = every other base
    best_of: dict = {}
    for b in bases:
        k = b["addrs"] or (b["host"],)
        if k not in best_of or b["score"] > best_of[k]["score"]:
            best_of[k] = b
    reps = {id(b) for b in best_of.values()}
    for b in bases:
        b["tier"] = 0 if id(b) in reps else 1
    if not bases:
        _vhost_zero_lifecycle(ctx, "no non-CDN active-allowed live service to fuzz")
        return
    # a vhost that's ALREADY a known subdomain isn't the signal — vhost enum's value is the
    # DNS-INVISIBLE hosts. Filter results against everything we already discovered.
    known = set(ctx.run.values("subdomain")) | set(ctx.run.values("resolved"))
    apexes = [a for a in prof.apex_domains if scope.in_scope(a)]
    found = 0
    # per-call ceiling scaled by wordlist size (each ffuf fuzzes one base-service x apex over the list);
    # the flat 1800s cut a big-wordlist run. Higher -t (I/O-bound concurrency) makes each call faster.
    # review#1 (vhost r1): one EFFECTIVE wordlist per apex, containing only names we may CONTACT. Built here
    # so the exclusion happens before any request, and digested into the resume identity.
    eff: dict = {}
    excluded_total = invalid_total = 0
    for apex in apexes:
        path, digest, submitted, n_ok, n_ex, n_bad = _vhost_effective_wordlist(ctx, wl, apex, scope)
        excluded_total += n_ex
        invalid_total += n_bad
        # review#5 (vhost r2): an apex whose every candidate is OOS or malformed has NOTHING contactable.
        # Building units for it produced repeated ffuf failures against an empty file; skip it cleanly.
        if n_ok == 0:
            ctx.run.record("probe", skipped("ffuf-vhost", f"{apex}: no contactable vhost candidate "
                                                          f"({n_ex} out of scope, {n_bad} malformed)"))
            continue
        eff[apex] = {"path": path, "digest": digest, "submitted": submitted, "n": n_ok}
    if excluded_total or invalid_total:
        ctx.echo(f"  vhost: {excluded_total} out-of-scope + {invalid_total} malformed candidate(s) "
                 f"removed BEFORE contact")
    apexes = [a for a in apexes if a in eff]                 # only apexes with contactable candidates
    if not apexes:
        _vhost_zero_lifecycle(ctx, "no contactable vhost candidate for any apex (scope policy)",
                              excluded=excluded_total, invalid=invalid_total)
        return
    # review#4 (vhost r2): NOT a coverage measure. COVERAGE_SAMPLE means an operator-chosen subset of
    # otherwise-eligible input and yields complete_with_limits — but an OOS or malformed candidate was never
    # eligible ACTIVE input at all, so calling it "omitted" would invent a shortfall. It is policy context.
    events.ledger("probe.ffuf_vhost",
                  consumed={"wordlist_submitted": sum(e["n"] for e in eff.values()),
                            "wordlist_oos_excluded": excluded_total,
                            "wordlist_invalid": invalid_total})
    wl_n = max([e["n"] for e in eff.values()] or [0])
    ffuf_to = scaled_timeout(wl_n, ctx.http_timeout, per_unit=0.4)
    wl_digest = events.file_digest(wl)                       # provenance: the SOURCE list this run derived from
    # EXECUTION completion and ARTIFACT usability are separate counters (content review#4).
    ffuf_clean = ffuf_partial = ffuf_blocked = ffuf_errors = ffuf_total = 0
    ffuf_resumed = ffuf_unusable = 0
    _mc = "200-299,301,302,303,307,308,401,403"
    # ledger namespaced by the COVERAGE CONFIG: an artifact from a different wordlist/match-set validates by
    # digest and must not count as this generation's completed work. schema_version tracks the row parser.
    cfg_fp = events.work_unit("probe.ffuf_vhost", inputs={}, config={"mc": _mc, "wordlist": wl.name},
                              file_digests={"wordlist": wl_digest,
                                            **{f"eff:{a}": e["digest"] for a, e in eff.items()}},
                              schema_version=_VHOST_SCHEMA)
    sbase = ctx.run.dir / "raw" / "probe"
    sbase.mkdir(parents=True, exist_ok=True)
    budget.prune_state(sbase, "probe.ffuf_vhost", cfg_fp)
    ledger = budget.Ledger(budget.state_path(sbase, "probe.ffuf_vhost", cfg_fp), lane="probe.ffuf_vhost")
    vh_budget = budget.Budget(budget.budget_seconds("VHOST_BUDGET_S"))
    cfg_dir = sbase / "ffuf-vhost" / cfg_fp[:16]
    attempt_dir = fresh_artifact_dir(cfg_dir)
    # One unit = BASE SERVICE x apex. The base carries scheme + host + port, which is exactly what ffuf
    # connects through, so it IS the identity. The ADDRESS SET only ranks the order (co-hosted
    # representative first), never membership.
    units = [(b, a) for b in bases for a in apexes]
    # rank: co-hosted representatives first (tier 0), then by descending service score. ORDER only.
    ordered = budget.order_ranked_fair(units, rank=lambda u: (u[0]["tier"], -u[0]["score"]),
                                       group=lambda u: u[0]["host"])
    seen_hosts: set = set()                      # unique vhost identities this lifecycle, not per-replay
    attempted = 0
    for b, apex in ordered:
        base = b["base"]
        item = f"{base}|{apex}"                          # the BASE service is the identity (it carries scheme+port)

        unit_id = hashlib.sha256(item.encode()).hexdigest()
        done = ledger.has(item)
        current, ran_clean, launched = None, False, False
        if not done:
            if not vh_budget.exhausted():        # the budget gates LAUNCHING only; replay is unconditional
                launched = True
                current = attempt_dir / f"{unit_id}.json"
                current.unlink(missing_ok=True)  # our OWN fresh attempt file, never a recorded one
                r = _vhost_scan(ctx, base, apex, current, eff[apex]["path"],
                                eff[apex]["digest"], _mc, ffuf_to, prof)
                ctx.run.record("probe", r)
                ffuf_total += 1
                if r.status == Status.BLOCKED:
                    ffuf_blocked += 1
                    events.coverage_partial("probe.ffuf_vhost", reason=f"{base}/{apex}: blocked — {r.note}")
                elif r.status == Status.PARTIAL:
                    ffuf_partial += 1
                    events.coverage_partial("probe.ffuf_vhost", reason=f"{base}/{apex}: partial — {r.note}")
                elif r.status in (Status.SUCCESS, Status.EMPTY):
                    ffuf_clean += 1              # EXECUTION completed (says nothing about the rows)
                else:
                    ffuf_errors += 1             # FAILED / TIMED_OUT / SKIPPED
                    events.coverage_partial("probe.ffuf_vhost",
                                            reason=f"{base}/{apex}: {r.status.value} — {r.note}")
                ran_clean = r.status in (Status.SUCCESS, Status.EMPTY)
                if not current.exists():
                    current = None
                elif ffuf_results(current) is not None:
                    ledger.add_evidence(item, current)   # retain ANY trustworthy artifact; not a completion
                attempted += 1
        else:
            ffuf_resumed += 1
            attempted += 1
            current = ledger.artifact(item)
        artifacts = ledger.evidence(item)        # digest-bound: contained, no symlinks, content-verified
        if current is not None and current not in artifacts:
            artifacts = artifacts + [current]
        if not launched and not artifacts:
            continue                             # never launched, nothing retained -> selection covers it
        found += _vhost_ingest(ctx, scope, known, base, b["addrs"], apex, unit_id, artifacts, current,
                               seen_hosts, launched, eff[apex]["submitted"])
        if done or current is None:
            continue
        cur_ok, cur_clean = _vhost_status(current, eff[apex]["submitted"], apex, scope)
        if ran_clean and cur_ok and cur_clean:
            ledger.record(item, current)         # completion needs a CLEAN EXECUTION and a usable artifact
        elif ran_clean:
            ffuf_unusable += 1
            events.coverage_partial("probe.ffuf_vhost",
                                    reason=f"{base}/{apex}: unusable/untrustworthy rows — not resumable")
    persisted = ledger.save()
    if not persisted:
        ctx.echo("    probe.ffuf_vhost: completion state NOT persisted"
                 + (" (state file belongs to another lane)" if ledger.foreign else ""))
    events.coverage_partial("probe.ffuf_vhost", kind=events.COVERAGE_TIMEOUT, measure="state_persisted",
                            unit="state_persisted", eligible=1, tested=1 if persisted else 0,
                            omitted=0 if persisted else 1,
                            reason=("completion state persisted" if persisted else
                                    "completion state could not be persisted; a resume will redo this lane"))
    # measure = BASE SERVICES, not "origins": that is what we actually scan (review#2 vhost r1).
    budget.report_selection("probe.ffuf_vhost", measure="base_services", eligible=len(units),
                            attempted=attempted, budget=vh_budget, noun="service x apex", durable=persisted)
    budget.report_outcome("probe.ffuf_vhost", measure="base_services_scanned", attempted=attempted,
                          obtained=ffuf_clean - ffuf_unusable + ffuf_resumed,
                          classes={k: v for k, v in (("partial", ffuf_partial), ("blocked", ffuf_blocked),
                                                     ("error", ffuf_errors),
                                                     ("unusable_output", ffuf_unusable)) if v},
                          noun="service x apex")
    _left = len(units) - attempted
    if ffuf_total or ffuf_resumed:
        ctx.echo(f"  vhost ffuf: {ffuf_clean}/{ffuf_total} clean · {ffuf_partial} partial · "
                 f"{ffuf_blocked} blocked · {ffuf_errors} error · {ffuf_unusable} unusable · "
                 f"{ffuf_resumed} resumed · {len(seen_hosts)} candidate(s)"
                 + (f" · {_left} left by budget — "
                    f"{'resumable' if persisted else 'NOT saved, will restart'}" if _left else ""))


def _httpx_probe_cmd(hosts_file, ports, http_rl) -> list[str]:
    """The shared httpx fingerprint command (v0.3.4 discipline: NO -probe-all-ips / -no-fallback
    multipliers, bounded -timeout/-retries; rich response-derived flags kept — they cost only on hosts
    that answer). Used by the bulk probe, every prefilter port-group, the direct fallback, and enrich."""
    cmd = ["httpx", "-l", str(hosts_file), "-json", "-silent",
           "-ports", ",".join(str(p) for p in ports),
           "-td", "-title", "-sc", "-cl", "-favicon", "-cdn", "-web-server",
           "-asn", "-location", "-ip", "-cname", "-irh",
           # -follow-host-redirects (NOT -follow-redirects): follow only SAME-HOST 30x (http->https on the
           # same host), never cross-host/off-scope — an in-scope host that 30x's off-scope is not fetched.
           # `-location` still records the Location for cross-host redirects (intel without following).
           "-follow-host-redirects", "-random-agent", "-timeout", "7", "-retries", "0",
           # never connect to the SCAN BOX itself / cloud metadata (small deny; private targets are contacted)
           "-deny", netguard.self_deny_list(),
           "-t", str(settings.workers("httpx", 15))]
    if http_rl:
        cmd += ["-rl", str(http_rl)]
    return cmd


def _run_httpx(ctx, hosts, ports, phase, tag):
    """Probe `hosts` on `ports` (hostnames, so Host/SNI/cert/CDN stay correct) → record + return
    (raw_ref, lines) so each live entity keeps its OWN immutable raw evidence file (per httpx call).
    Timeout scales with host × port-weight."""
    hf = ctx.write_list(f"{tag}_targets.txt", sorted(set(hosts)))
    hx = ctx.run.raw_path(phase, "httpx", f"{tag}.jsonl")
    cmd = _httpx_probe_cmd(hf, ports, ctx.profile.http_rl)
    to = scaled_timeout(len(hosts), ctx.http_timeout, per_unit=max(6, len(ports) // 12))
    # C07 inc3: this httpx GROUP's work_unit = its exact host set + port set (a resumable unit); a changed
    # group (different hosts/ports) is a different unit. source_id is phase-scoped (probe/enrich .httpx).
    # review#10: fold the EFFECTIVE probe config (rate + a flag-profile marker) so a probe-flag/rate change
    # invalidates the unit — not just the host/port set. Bump "flags" when _httpx_probe_cmd's flags change.
    wu = events.work_unit(f"{phase}.httpx", inputs={"hosts": sorted(set(hosts)), "ports": sorted(ports)},
                          config={"flags": "v0.3.4-probe", "rl": ctx.profile.http_rl})
    r = run_contract(f"{phase}.httpx", cmd, work_unit=wu, raw_path=hx, timeout=to)
    ctx.run.record(phase, r)
    return str(hx), (r.raw_path.read_text().splitlines() if r.raw_path else [])


def _host_public_ip_map(ctx, hosts):
    """Returns (contactmap, a_known). contactmap = {host: [CONTACTABLE A-record IPs]} from resolved.a +
    dns_record A — used ONLY to give naabu concrete IPv4 targets for the SYN prefilter. CONTACTABLE = the
    offensive default: private (RFC1918/CGNAT/ULA) IS included unless MODES.BLOCK_PRIVATE_TARGETS; only the
    scan-box/cloud-metadata self-hits are dropped (is_contactable_ip). a_known = hosts with ANY A record.
    The BLOCK/unresolved decision is NOT made here — netguard.guard_hosts already recorded intel + withheld
    the scan-box/metadata self-hits before this is called."""
    want = set(hosts)
    a_by_host: dict[str, set] = {}
    for r in ctx.run.read("resolved"):
        h = r.get("host")
        if h in want and r.get("a"):
            a_by_host.setdefault(h, set()).update(r["a"])
    for d in ctx.run.read("dns_record"):
        if d.get("type") == "a" and d.get("host") in want and d.get("value"):
            a_by_host.setdefault(d["host"], set()).add(d["value"])
    a_known = set(a_by_host)
    _bp = netguard._block_private(ctx)
    pubmap = {h: sorted({ip for ip in a_by_host.get(h, ()) if netguard.is_contactable_ip(ip, block_private=_bp)})
              for h in hosts}
    return pubmap, a_known


def _cdn_shared_ips(ctx, ips):
    """Offline-classify `ips`; return the subset sitting on SHARED third-party edge — CDN or WAF — which
    raw SYN must avoid (multi-tenant infra, and not the origin anyway). Uses cdncheck: a LOCAL IP-range
    dataset, NO target contact. CLOUD (aws/gcp/azure) is deliberately NOT excluded — cloud classification
    alone does not prove shared infrastructure (the IP may be the target's own dedicated instance), and
    excluding it would suppress coverage of the target's real servers. Returns a set of shared IPs, or None
    when classification was NOT trustworthy (cdncheck missing / errored / any malformed or schema-invalid
    row) so the caller fails CLOSED — decline to SYN un-vetted IPs rather than packet-scan shared infra.
    This gate NEVER drops a host: a CDN/WAF host is still probed by name. cdncheck emits one JSONL row PER
    classified IP with an `ip` key and cdn/waf/cloud booleans; unclassified IPs are simply absent, so an
    empty valid artifact is a legitimate 'none shared' result — but a malformed row is not."""
    if not ips or not have("cdncheck"):
        return None                                          # cannot vet -> caller withholds SYN (httpx by name)
    ipf = ctx.write_list("cdncheck_ips.txt", ips)
    out = ctx.run.raw_path("probe", "cdncheck", "classified.jsonl")
    out.unlink(missing_ok=True)                              # stale artifact must not influence this run's decision
    r = exec_tool("cdncheck", ["cdncheck", "-i", str(ipf), "-jsonl", "-silent", "-duc", "-o", str(out)],
                  timeout=scaled_timeout(len(ips), ctx.http_timeout, per_unit=0.02))
    ctx.run.record("probe", r)
    if r.status not in (Status.SUCCESS, Status.EMPTY) or not out.exists():
        return None                                          # errored/truncated -> treat as un-vetted (no SYN)
    want = set(ips)
    try:
        raw_lines = out.read_text().splitlines()
    except (OSError, UnicodeError):
        return None                                          # unreadable artifact -> fail CLOSED
    shared: set = set()
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        try:
            o = _json.loads(line)
        except (_json.JSONDecodeError, ValueError):
            return None                                      # malformed row -> classification untrustworthy, fail CLOSED
        if not isinstance(o, dict):                          # [], null, "text", 5 are valid JSON but not a row
            return None                                      # -> fail CLOSED (a shared IP could hide behind a bad line)
        ip = o.get("ip") or o.get("input")
        if not isinstance(ip, str) or ip not in want:        # missing / non-str (e.g. list) / unexpected ip
            return None                                      # -> fail CLOSED (never .add() a non-hashable / stray ip)
        if o.get("cdn") or o.get("waf"):                     # cloud NOT excluded (not proof of shared infra)
            shared.add(ip)
    return shared


def _nmap_services(path):
    """Parse nmap -oX XML. Returns (services, complete):
      - services = [(ip, port, proto, service, product, version) for OPEN ports]. VALID rows are kept even
        when other rows are malformed.
      - complete = True ONLY when the XML parsed AND nmap reported clean completion
        (<runstats><finished exit="success">) AND no malformed row was seen. A malformed host/port (missing
        address, missing <state>, non-int / out-of-range portid) keeps valid rows but sets complete False;
        an errored/absent <finished exit="success"> also sets it False (the caller -> PARTIAL). A closed or
        filtered port is NORMAL, not malformed.
    Returns (None, False) only when there is NO salvageable artifact: missing / unreadable / malformed XML /
    non-<nmaprun> root."""
    if not path or not path.exists():
        return None, False
    import xml.etree.ElementTree as _ET
    try:
        root = _ET.parse(str(path)).getroot()
    except (OSError, _ET.ParseError, ValueError):
        return None, False
    if root is None or root.tag != "nmaprun":
        return None, False
    out, complete = [], True
    for host in root.findall("host"):
        addr = None
        for a in host.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6") and a.get("addr"):
                addr = a.get("addr"); break
        if not addr:
            complete = False; continue                       # malformed: host with no usable address
        for port in host.findall("./ports/port"):
            st = port.find("state")
            state = st.get("state") if st is not None else None
            if state is None:
                complete = False; continue                   # malformed: a port with no <state>
            if state != "open":
                continue                                     # closed/filtered = normal, not malformed
            try:
                pn = int(port.get("portid"))
            except (TypeError, ValueError):
                complete = False; continue                   # malformed portid
            if not (1 <= pn <= 65535):
                complete = False; continue
            svc = port.find("service")
            g = (lambda k: (svc.get(k) or "") if svc is not None else "")
            out.append((addr, pn, port.get("protocol") or "tcp", g("name"), g("product"), g("version")))
    fin = root.find("runstats/finished")                     # nmap DTD: runstats/finished is the completion marker
    if fin is None or fin.get("exit") != "success":
        complete = False                                     # nmap did not report clean completion
    return out, complete


def _valid_ip(s) -> bool:
    try:
        _ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _smap_records(path):
    """Parse smap's -oJ JSON — a list of per-IP records {ip, user_hostname, hostnames:[...],
    ports:[{port,service,...}]}. Returns (records, complete):
      - records = validated [(ip, user_hostname|None, [shodan_hostname,...], [(port,service),...]), ...].
        VALID evidence is KEPT even when other rows/ports are malformed — a strict parse must not suppress
        good findings.
      - complete = True only when EVERY record + port was well-formed; any malformed record (non-dict, bad
        ip, non-list ports) or bad port (non-int, out of 1..65535) sets it False (caller -> PARTIAL).
    Returns (None, False) only when there is NO salvageable evidence: missing / unreadable / invalid UTF-8 /
    malformed JSON / non-list root. smap OMITS no-data IPs, so record-count < input-count is NORMAL."""
    if not path or not path.exists():
        return None, False
    try:
        data = _json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, _json.JSONDecodeError, ValueError):
        return None, False
    if not isinstance(data, list):
        return None, False
    records, complete = [], True
    for rec in data:
        if not isinstance(rec, dict):
            complete = False; continue
        ip = rec.get("ip")
        if not isinstance(ip, str) or not _valid_ip(ip):     # semantic IP validity, not just str
            complete = False; continue
        ports_raw = rec.get("ports")
        if not isinstance(ports_raw, list):
            complete = False; continue
        rp = []
        for p in ports_raw:
            pn = p.get("port") if isinstance(p, dict) else None
            if isinstance(pn, bool) or not isinstance(pn, int) or not (1 <= pn <= 65535):
                complete = False; continue                   # bad port -> drop that port, keep the rest
            svc = p.get("service")
            rp.append((pn, svc if isinstance(svc, str) else ""))
        uh = rec.get("user_hostname")
        uh = uh.lower().rstrip(".") if isinstance(uh, str) else None
        hn = rec.get("hostnames")
        hn = [h.lower().rstrip(".") for h in hn if isinstance(h, str)] if isinstance(hn, list) else []
        records.append((ip, uh, hn, rp))
    return records, complete


def _smap_ingest(ctx, r, sm, phase, targets):
    """Shared smap file-output handling for BOTH probe and enrich (enrich previously ran smap but never
    parsed it — its passive port yield was lost, C12). Parse -oJ, reclassify the run status from the port
    YIELD via the shared adapter (clean+ports -> SUCCESS, clean+0 -> EMPTY, degraded stays degraded,
    unreadable/malformed-root -> hard/PARTIAL); a partially-malformed artifact -> PARTIAL while KEEPING the
    valid records. Attribute each record's ports to the exact submitted `user_hostname` (priority), else our
    stored resolved ip->host map, else Shodan's hostnames. smap is passive (Shodan-backed, no packets) and
    CANNOT prove per-target completion (omits a no-data IP the same as a swallowed failure), so
    returned/eligible is a VISIBILITY note, never forced to PARTIAL. Returns the in-scope port count."""
    records, complete = _smap_records(sm)
    reclassify_from_artifact(r, None if records is None else sum(len(rp) for *_, rp in records), label="smap")
    if records is not None and not complete and r.status in (Status.SUCCESS, Status.EMPTY):
        r.status = Status.PARTIAL                            # malformed rows -> completion uncertain (valid kept)
    if records is not None:
        r.note = (f"smap: {len(records)}/{len(set(targets))} target IP(s) had InternetDB records"
                  f"{' (malformed rows dropped)' if not complete else ''}; {r.note or ''}").strip()
    ctx.run.record(phase, r)
    if not records:
        return 0
    target_set = set(targets)
    ip_to_hosts: dict[str, set] = {}
    for rec in ctx.run.read("resolved"):
        h = rec.get("host")
        if h in target_set and ctx.scope.in_scope(h) and not ctx.scope.is_oos(h):
            for ip in (rec.get("a") or []):
                ip_to_hosts.setdefault(ip, set()).add(h)
    def _inscope(h):
        return bool(h) and ctx.scope.in_scope(h) and not ctx.scope.is_oos(h)
    n = 0
    for ip, uh, hostnames, rp in records:
        # attribution priority: exact submitted user_hostname > our resolved ip->host map > Shodan hostnames
        host = None
        if _inscope(uh):
            host = uh
        elif ip_to_hosts.get(ip):
            host = sorted(ip_to_hosts[ip])[0]
        else:
            insc = sorted(h for h in hostnames if _inscope(h))
            host = insc[0] if insc else None
        if not host:
            continue
        for port, svc in rp:
            if ctx.run.add("port", {"id": f"{ip}:{port}", "host": host, "port": port,
                                    "service": svc, "sources": ["smap"], "raw_ref": str(sm)}):
                n += 1
    return n


def _web_port_prefilter(ctx, hosts, phase, pubmap):
    """v0.3.5 SYN web-port prefilter (bbot-style, NOT the infra portscan). `hosts` carry a CONTACTABLE IP
    (scan-box/metadata self-hits already withheld by netguard; private IS scanned by default). naabu SYN
    over their contactable IPs × prof.ports (never top-1000/CIDR/nmap) → open ip:ports → mapped back to
    hosts → {host:[open ports]}. TRI-STATE (T1.1), for honest coverage:
      - dict of open host:ports  → usable_with_ports (httpx on the open ports)
      - {} (empty dict)          → usable_empty: CLEAN scan, nothing open. The caller STILL direct-probes
                                   these hosts (a clean SYN 0-open is never trusted to DROP a host — SYN
                                   false-negatives from filtering/rate-limit/loss); it is only a recorded
                                   coverage state, not a reason to skip.
      - None                     → unusable: truncated/timeout/block/error → full direct fallback, so a
                                   few ports found mid-failure can't silently thin coverage.
    Only a CLEAN completion is trusted. Stores web_port evidence + records the coverage state."""
    if not have("naabu"):
        return None
    prof = ctx.profile
    ip_to_hosts: dict[str, list] = {}
    for h in hosts:
        for ip in pubmap.get(h, ()):
            ip_to_hosts.setdefault(ip, []).append(h)
    unique_ips = sorted(ip_to_hosts)
    if not unique_ips:
        return None
    ips_file = ctx.write_list(f"{phase}_webports_ips.txt", unique_ips)
    raw = ctx.run.raw_path(phase, "naabu-web", "open.json")
    raw.unlink(missing_ok=True)                          # clear stale artifact: a prior run must not narrow this one
    cmd = ["naabu", "-list", str(ips_file), "-p", ",".join(str(p) for p in prof.ports),
           "-json", "-scan-type", "s", "-Pn", "-silent", "-o", str(raw)]   # SYN, no host-disco, web ports only
    if prof.portscan_rate:
        cmd += ["-rate", str(prof.portscan_rate)]
    to = scaled_timeout(len(unique_ips) * len(prof.ports), ctx.http_timeout, per_unit=0.02)
    res = exec_tool("naabu", cmd, timeout=to)
    raw_status = res.status
    # naabu writes findings to the -o FILE (empty stdout, -json). Parse it FAIL-CLOSED: any malformed row,
    # non-object, unparseable port, unexpected IP (not one we scanned), or out-of-profile port makes the
    # WHOLE scan UNUSABLE (full fallback) — narrowing httpx to a subset off a stale/garbled artifact would
    # silently drop coverage. A missing/empty file is NOT malformed (just no open ports).
    want_ips = set(unique_ips)
    want_ports = set(prof.ports)
    open_by_ip: dict[str, set] = {}
    parse_ok = True
    if raw.exists():
        try:
            raw_lines = raw.read_text().splitlines()
        except (OSError, UnicodeError):
            raw_lines = []; parse_ok = False            # unreadable/invalid-encoding artifact -> unusable
        for line in raw_lines:
            line = line.strip()
            if not line:
                continue
            try:
                o = _json.loads(line)
            except (_json.JSONDecodeError, ValueError):
                parse_ok = False; break                 # malformed row -> untrust the whole scan
            if not isinstance(o, dict):
                parse_ok = False; break
            ip = o.get("ip") or o.get("host")
            pr = o.get("port")
            if isinstance(pr, bool):                    # JSON true/false is not a port (bool is an int subclass)
                parse_ok = False; break
            try:
                port = int(pr)
            except (TypeError, ValueError):
                parse_ok = False; break
            if not isinstance(ip, str) or ip not in want_ips or port not in want_ports:  # list/dict ip, stale, oob port
                parse_ok = False; break
            open_by_ip.setdefault(ip, set()).add(port)
    n_open = sum(len(v) for v in open_by_ip.values())
    # TRI-STATE (T1.1): the state is recorded in RunResult.note (per-source truth). NON-hit outcomes behave
    # IDENTICALLY for routing — both send their hosts to direct httpx via the caller (a clean SYN 0-open is
    # NEVER trusted to DROP a host). usable_empty is a normal clean result (note only, no coverage event);
    # unusable is a degraded execution (truncated/error/garbled → full fallback) and DOES flag an event.
    clean = raw_status in (Status.SUCCESS, Status.EMPTY) and parse_ok
    if not clean:
        state = "unusable"
    elif n_open == 0:
        state = "usable_empty"
    else:
        state = "usable_with_ports"
    if state == "usable_with_ports" and raw_status == Status.EMPTY:   # empty-stdout mislabel: CLEAN findings in file
        res.status = Status.SUCCESS                                   # NOT promoted when a later row was malformed
        res.stdout_lines = n_open
    res.note = f"prefilter {state}: {n_open} open ip:port(s) over {len(unique_ips)} IP(s)"
    ctx.run.record(phase, res)
    if state == "unusable":
        events.coverage_partial("probe.naabu_web", reason=f"naabu UNUSABLE ({raw_status.value}, "
                                f"parse_ok={parse_ok}) over {len(unique_ips)} IP(s) — full direct-httpx fallback")
        return None                                     # truncated/error/garbled -> caller full-fallback
    if state == "usable_empty":
        return {}                                       # clean, nothing open — hosts still probed direct (note carries it)
    host_ports: dict[str, set] = {}
    for ip, ports in open_by_ip.items():
        for h in ip_to_hosts.get(ip, []):
            host_ports.setdefault(h, set()).update(ports)
            for p in sorted(ports):
                ctx.run.add("web_port", {"id": f"{h}|{ip}|{p}", "host": h, "ip": ip, "port": p,
                                         "sources": ["naabu-web"], "raw_ref": str(raw)})
    host_ports = {h: sorted(ps) for h, ps in host_ports.items()}
    n_targets = sum(len(ps) for ps in host_ports.values())
    ctx.echo(f"  web-port prefilter: {len(unique_ips)} SYN-eligible IPs × {len(prof.ports)} ports -> "
             f"{n_open} open ip:ports -> {n_targets} host:port probes")
    ctx.run.notes.append(f"{phase} web-port prefilter: syn_eligible_ips={len(unique_ips)} "
                         f"ports={len(prof.ports)} ip_port_checks={len(unique_ips) * len(prof.ports)} "
                         f"open_ip_ports={n_open} httpx_host_port_targets={n_targets}")
    return host_ports


def fingerprint_hosts(ctx, hosts, phase):
    """Fingerprint `hosts` → list of (raw_ref, json_lines) per httpx call (callers parse each with its
    REAL raw file for per-entity provenance). v0.3.5: SYN-prefilter → httpx only on OPEN host:ports
    (grouped by open-port set); hosts with NO known IP → direct-httpx by hostname. SAFETY RAILS:
    - hosts whose CURRENT answer is a scan-box/metadata self-hit are withheld by netguard; private IS scanned.
    - FALLBACK-SAFE: prefilter off / naabu missing / truncated / zero-open → v0.3.4 direct-httpx over the
      contactable + unknown-IP hosts (private included by default; never a thin run). Shared by probe + enrich."""
    prof = ctx.profile
    # self-attack guard (contact-by-default): RECORD every private/self-resolving host as internal-resolution
    # intel, WITHHOLD only the scan-box/metadata self-hits (private space is scanned — it's a lead). Every
    # downstream active tool derives from what this produces, so the gate lives here.
    hosts = netguard.guard_hosts(ctx, hosts, phase=phase)
    if not hosts:
        return []
    pubmap, a_known = _host_public_ip_map(ctx, hosts)                     # {host: contactable A IPs} (private incl. by default)
    prefilter_on = settings.web_port_prefilter()
    # CDN-aware SYN gate (T0.3): raw SYN must not hit SHARED third-party edge (CDN/WAF) — multi-tenant infra
    # that isn't the origin anyway. Classify offline (cdncheck, no target contact) and drop CDN/WAF IPs from
    # the SYN target set only; CLOUD + unclassified IPs are still scanned (unclassified is NOT proof of a
    # dedicated origin, but it isn't shared edge either). A host left with no SYN-eligible IP is NOT dropped
    # — it falls to direct httpx-by-name (zero coverage loss).
    shared: set = set()
    if prefilter_on:
        all_ips = sorted({ip for ips in pubmap.values() for ip in ips})
        cls = _cdn_shared_ips(ctx, all_ips)
        # None => could not vet (cdncheck missing/errored): withhold SYN for un-vetted IPs rather than
        # packet-scan possible shared infra — httpx by name still probes every host (no discovery lost).
        shared = set(all_ips) if cls is None else cls
        if cls:
            ctx.run.notes.append(f"{phase} cdn-aware SYN gate: {len(cls)}/{len(all_ips)} contactable IPs are "
                                 f"CDN/WAF edge — excluded from SYN, hosts probed by name")
    # A host is SYN-eligible only when ALL its contactable IPs are non-shared. If ANY answer is CDN/WAF, the
    # whole hostname goes direct: httpx probes BY NAME, whose DNS answer may be the CDN IP, so ports found on
    # a non-CDN sibling IP wouldn't match what httpx-by-name actually hits (partial-prefilter mismatch).
    syn_map = {h: ([] if any(ip in shared for ip in ips) else ips) for h, ips in pubmap.items()}
    public_hosts = [h for h in hosts if syn_map[h]]                      # ALL contactable IPs non-shared -> SYN-eligible
    no_ip = [h for h in hosts if not syn_map[h]]                         # any shared IP / no IP -> httpx by name

    def _direct(targets):
        return [_run_httpx(ctx, targets, prof.ports, phase, "httpx")] if targets else []

    if not prefilter_on:
        return _direct(public_hosts + no_ip)                             # v0.3.4 direct (contactable incl. private)
    host_ports = _web_port_prefilter(ctx, public_hosts, phase, syn_map) if public_hosts else None
    if host_ports is None:
        return _direct(public_hosts + no_ip)                             # fallback: full direct over every guarded host
    results = []
    groups: dict[tuple, list] = {}
    for h, ps in host_ports.items():
        groups.setdefault(tuple(ps), []).append(h)
    for i, (ps, hs) in enumerate(sorted(groups.items())):
        results.append(_run_httpx(ctx, hs, list(ps), phase, f"httpx-g{i}"))   # httpx on OPEN ports only
    # A SYN-eligible host that came back with ZERO open ports is NOT dropped: SYN can false-negative
    # (filtered/rate-limited/packet loss), so probe it directly over the full port set. A host's outcome
    # must never depend on another host's scan — only on its own evidence. Union with the by-name hosts.
    covered = set(host_ports)
    direct_targets = no_ip + [h for h in public_hosts if h not in covered]
    if direct_targets:
        results.append(_run_httpx(ctx, direct_targets, prof.ports, phase, "httpx-direct"))
    return results


def run(ctx) -> None:
    prof, scope = ctx.profile, ctx.scope
    if scope.passive_only:
        ctx.run.record("probe", skipped("httpx", "passive-only mode"))
        return

    hosts = ctx.run.values("resolved") or ctx.run.values("subdomain")
    hosts = scope.filter_hosts(hosts, active=True)
    if not hosts:
        ctx.run.record("probe", skipped("httpx", "no in-scope hosts to probe"))
        ctx.run.notes.append("probe: no hosts (run vertical first)")
        return

    # ── httpx full fingerprint -> live services (v0.3.5: SYN-prefilter → httpx on open ports only) ──
    groups = fingerprint_hosts(ctx, hosts, "probe")     # [(raw_ref, json_lines)] per httpx call
    lines = [ln for _ref, gl in groups for ln in gl]    # combined, for the CSP/deser pass below
    if groups:
        n = 0
        for raw_ref, glines in groups:                  # parse each group with its OWN raw file (provenance)
            for e in normalize.httpx_json("\n".join(glines), "httpx", raw_ref):
                if scope.in_scope(e.get("host") or normalize.host_of_url(e["url"])):
                    if ctx.run.add("live", e):
                        n += 1
                        for tech in e.get("tech") or []:
                            ctx.run.add("tech", {"id": f"{e['url']}|{tech}", "tech": tech,
                                                 "url": e["url"], "sources": ["httpx"]})
        ctx.echo(f"  httpx: {n} live services")

        # ── CSP-advertised siblings (horizontal discovery from live response headers) ──
        # httpx -irh carries the Content-Security-Policy; in-scope hosts named there (e.g. an
        # internal/staging host in script-src) are a real discovery channel. Parsed here over
        # live hosts because the CSP lives on a probed host (www), not the bare apex — which is
        # why csprecon over apex roots in horizontal found nothing.
        _CSP_HOST = _re.compile(r"\b(?:https?://)?((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b", _re.I)
        csp_added = deser_n = 0
        for line in lines:
            try:
                o = _json.loads(line)
            except _json.JSONDecodeError:
                continue
            hdr = o.get("header") or {}
            rhost = (o.get("input") or o.get("host") or "").lower().rstrip(".")
            # ── deserialization / token FORMAT fingerprint (passive: Set-Cookie + response headers) ──
            if hdr and rhost and scope.in_scope(rhost):
                blob = " ".join(str(v) for v in hdr.values())
                fmts = [f for f, marker in _DESER_MARKERS if marker in blob]
                if _PHP_OBJ_RX.search(blob):
                    fmts.append("php-serialized")
                if _JWT_RX.search(blob):
                    fmts.append("jwt")
                for fmt in fmts:
                    hint = ("check alg:none / weak HS256 secret / RS256→HS256 confusion"
                            if fmt == "jwt" else "untrusted-deserialization surface")
                    if ctx.run.add("review", {
                            "id": f"deser:{rhost}:{fmt}", "klass": "deser", "value": rhost,
                            "host": rhost, "format": fmt,
                            "note": f"{fmt} marker in response headers/cookies — {hint} "
                                    "(attack-layer target; verify)",
                            "sources": ["deser-fingerprint"]}):
                        deser_n += 1
            # ── CSP-advertised siblings ──
            csp = hdr.get("content_security_policy")
            if not csp:
                continue
            for host in {m.lower() for m in _CSP_HOST.findall(csp)}:
                if scope.in_scope(host) and ctx.run.add(
                        "subdomain", {"host": host, "sources": ["csp"]}):
                    csp_added += 1
        if csp_added:
            ctx.echo(f"  csp: +{csp_added} sibling host(s) from response headers")
        if deser_n:
            ctx.echo(f"  deser: {deser_n} serialization/token fingerprint(s) in headers/cookies")

    # ── tlsx over in-scope hosts — cert SAN harvest (new sibling hostnames) + cert context ──
    # tlsx is used in horizontal over IP RANGES; here it runs over the resolved HOST set: cert SANs
    # reveal sibling hostnames we'd otherwise miss (coverage → enrich resolves/probes them), and the
    # cert (cn/issuer/expiry/wildcard) is stored as first-class context (the `certificate` entity).
    if have("tlsx"):
        thosts = sorted(h for h in set(ctx.run.values("resolved"))
                        if h and scope.in_scope(h) and not scope.is_oos(h))
        if thosts:
            tf = ctx.write_list("tls_targets.txt", thosts)
            tr = ctx.run.raw_path("probe", "tlsx", "certs.jsonl")
            # C10b resume: work_unit = the resolved-host set + probed ports. A changed host set is a new unit.
            tls_wu = events.work_unit("probe.tlsx_certs", inputs={"hosts": thosts},
                                      config={"ports": "443,8443,4443"})
            r = run_contract("probe.tlsx_certs", ["tlsx", "-l", str(tf), "-p", "443,8443,4443",
                                   "-json", "-silent"], work_unit=tls_wu, raw_path=tr, timeout=ctx.http_timeout)
            ctx.run.record("probe", r)
            san_new = 0
            if r.raw_path and r.raw_path.exists():
                for c in normalize.tlsx_certs(r.raw_path.read_text(), "tlsx", str(tr)):
                    all_san = c.get("san") or []
                    # scope-safe normalized entity: keep only in-scope SANs (shared/CDN/vendor certs
                    # carry unrelated names). Full SAN list stays in raw via raw_ref. Context counts.
                    in_scope_san = [s for s in all_san if scope.in_scope(s) and not scope.is_oos(s)]
                    c["san"] = in_scope_san
                    c["san_count"] = len(all_san)
                    c["oos_san_count"] = len(all_san) - len(in_scope_san)
                    c["has_oos_sans"] = c["oos_san_count"] > 0
                    ctx.run.add("certificate", c)
                    for s in in_scope_san:                     # in-scope SANs → new hosts (coverage)
                        if not s.startswith("*.") and ctx.run.add(
                                "subdomain", {"host": s, "sources": ["tlsx-san"]}):
                            san_new += 1
            if san_new:
                ctx.echo(f"  tlsx: +{san_new} sibling host(s) from cert SANs")

    # ── Shodan pivots (key-gated, silent): same favicon + same TLS cert fingerprint → related hosts ──
    _shodan_pivots(ctx)          # B1.4: ALL Shodan lanes, one collection, one credit budget

    # ── virtual-host enumeration (ffuf Host-header fuzz over base services; needs a vhost wordlist) ──
    _vhost_enum(ctx)

    # ── WAF fingerprint (nuclei waf-detect templates over live hosts) ──
    # Recon-side only: identify WHICH WAF fronts each host (Cloudflare/Akamai/F5…).
    # Bypass tooling (nomore403/nowafpls/NewTowner) stays human/Burp work.
    if have("nuclei") and ctx.run.count("live"):
        waf_in = ctx.write_list("waf_targets.txt", ctx.run.values("live"))
        waf_out = ctx.run.raw_path("probe", "nuclei", "waf.jsonl")
        waf_cmd = ["nuclei", "-l", str(waf_in), "-tags", "waf", "-jsonl", "-o", str(waf_out)]
        if prof.http_rl:                       # else native default (empty = fast)
            waf_cmd += ["-rl", str(prof.http_rl)]
        r = exec_tool("nuclei", waf_cmd,
                      timeout=nuclei_timeout(ctx.run.count("live"), ctx.http_timeout))
        ctx.run.record("probe", r)
        if waf_out.exists():
            n = 0
            for line in waf_out.read_text().splitlines():
                try:
                    o = _json.loads(line)
                except _json.JSONDecodeError:
                    continue
                ex = o.get("extracted-results") or []
                name = (ex[0] if ex else None) or o.get("matcher-name") or "unknown"
                host = o.get("matched-at", o.get("host", ""))
                ctx.run.add("tech", {"id": f"{host}|waf:{name}", "tech": f"WAF:{name}",
                                     "url": host, "sources": ["nuclei-waf"]})
                n += 1
            ctx.echo(f"  waf: {n} hosts fingerprinted")

    # ── screenshots (write structured jsonl too for the asset DB) ──
    if prof.screenshots and ctx.run.count("live"):
        live_file = ctx.write_list("live.txt", ctx.run.values("live"))
        shot_dir = fresh_artifact_dir(ctx.run.dir / "raw" / "probe" / "gowitness")   # FRESH per invocation
        # gowitness writes to FILES, not stdout → the runner mislabels it BLOCKED on a stderr WAF line even
        # when it screenshotted most hosts. Reclassify from shots in THIS attempt's fresh dir (a reused dir
        # must not inflate the count). Done inside the contract so the terminal event has the FINAL status.
        def _gw_reclassify(res):
            shots = len(list(shot_dir.glob("*.jpeg"))) + len(list(shot_dir.glob("*.png")))
            return reclassify_from_files(res, shots, "screenshot")
        # C10b resume: work_unit = the live-host set being screenshotted. A changed live set is a new unit.
        gw_wu = events.work_unit("probe.gowitness", inputs={"live": sorted(ctx.run.values("live"))})
        r = run_contract("probe.gowitness",
                ["gowitness", "scan", "file", "-f", str(live_file),
                 "--screenshot-path", str(shot_dir), "--write-jsonl",
                 "--write-jsonl-file", str(shot_dir / "gowitness.jsonl")],
                work_unit=gw_wu, reclassify=_gw_reclassify, timeout=ctx.http_timeout)
        ctx.run.record("probe", r)
        for img in shot_dir.glob("*.jpeg"):
            ctx.run.add("screenshot", {"url": str(img), "sources": ["gowitness"]})
        for img in shot_dir.glob("*.png"):
            ctx.run.add("screenshot", {"url": str(img), "sources": ["gowitness"]})

    # ── ports: naabu (in-scope CIDR) → nmap -sV service detection ──
    if prof.portscan and prof.cidr:
        cidr_file = ctx.write_list("cidr.txt", prof.cidr)
        cmd = ["naabu", "-list", str(cidr_file), "-top-ports", "1000", "-silent"]
        if prof.portscan_rate:
            cmd += ["-rate", str(prof.portscan_rate)]
        pr = ctx.run.raw_path("probe", "naabu", "ranges.txt")
        # naabu concurrency is RATE-based (portscan_rate), not thread-based — but a big CIDR can still
        # wall the flat timeout, so scale the ceiling by range count.
        naabu_to = scaled_timeout(len(prof.cidr), ctx.http_timeout, per_unit=300)
        r = exec_tool("naabu", cmd, raw_path=pr, timeout=naabu_to)
        ctx.run.record("probe", r)
        open_ports = {}
        if r.raw_path:
            for line in r.raw_path.read_text().splitlines():
                line = line.strip()
                if ":" in line:
                    ip, _, port = line.rpartition(":")
                    open_ports.setdefault(ip, set()).add(port)
        # nmap -sV only on the ports naabu found open (methodology: don't full-scan). Group IPs by their
        # EXACT open-port set → one nmap call per group on JUST those ports, not the Cartesian union of every
        # port over every IP (which probed host:port pairs naabu never found — C12). -oX structured so the
        # service yield is parsed (was previously recorded raw, never ingested). nmap ingests BEFORE the
        # naabu-bare fill below, so its richer service entity wins the shared {ip}:{port} id.
        if open_ports and have("nmap"):
            groups: dict[tuple, list] = {}
            for ip, ports in open_ports.items():
                groups.setdefault(tuple(sorted(ports, key=int)), []).append(ip)
            for gi, (ptup, ips) in enumerate(sorted(groups.items())):
                g_ips = ctx.write_list(f"nmap_ips_{gi}.txt", sorted(ips))
                nm = ctx.run.raw_path("probe", "nmap", f"service_{gi}.xml")
                nm.unlink(missing_ok=True)                   # -oX file: clear stale before the run
                # C07 inc3: reclassify (status-only) inside the contract so the terminal event has the final
                # nmap status; re-read below for ingest. work_unit = this port-group's ports + its IP set.
                def _nmap_reclassify(res, xml=nm):
                    svcs, complete = _nmap_services(xml)
                    reclassify_from_artifact(res, None if svcs is None else len(svcs), label="nmap")
                    if svcs is not None and not complete and res.status in (Status.SUCCESS, Status.EMPTY):
                        res.status = Status.PARTIAL          # malformed rows / no clean finish -> uncertain (valid kept)
                    return res
                # review#10: fold the nmap scan config (flags decide coverage) so a flag change flips the unit.
                wu = events.work_unit("probe.nmap_service", inputs={"ports": list(ptup), "ips": sorted(ips)},
                                      config={"flags": "sV-Pn-T4"})
                nr = run_contract("probe.nmap_service",
                                  ["nmap", "-sV", "-Pn", "-T4", "-iL", str(g_ips),
                                   "-p", ",".join(ptup), "-oX", str(nm)],
                                  work_unit=wu, reclassify=_nmap_reclassify,
                                  timeout=scaled_timeout(len(ips) * len(ptup), ctx.http_timeout, per_unit=30))
                ctx.run.record("probe", nr)
                svcs, _ = _nmap_services(nm)                 # re-read for ingest (status already set)
                for sip, sport, proto, service, product, version in (svcs or []):
                    # naabu OBSERVED the open port (triggering nmap); nmap ENRICHED it — carry both sources.
                    ctx.run.add("port", {"id": f"{sip}:{sport}", "ip": sip, "port": sport, "proto": proto,
                                         "service": service, "product": product, "version": version,
                                         "sources": ["naabu", "nmap"], "raw_ref": str(nm)})
        # naabu bare ports — fills any ip:port nmap didn't enrich (dedup: skipped where nmap already added)
        for ip, ports in open_ports.items():
            for port in ports:
                ctx.run.add("port", {"id": f"{ip}:{port}", "sources": ["naabu"]})
    elif prof.portscan:
        ctx.run.record("probe", skipped("naabu", "no in-scope CIDR — port scan skipped"))

    # ── smap: passive (Shodan-backed) port scan, no packets to target (optional) ──
    if have("smap") and ctx.run.count("live"):
        sm_targets = [normalize.host_of_url(u) for u in ctx.run.values("live")]
        sm_in = ctx.write_list("smap_targets.txt", sm_targets)
        sm = ctx.run.raw_path("probe", "smap", "smap.json")
        sm.unlink(missing_ok=True)                          # -o file: clear stale before the run
        # -oJ structured output (verified schema) instead of scraping nmap-text; parse + reclassify + ingest
        # via the shared helper (it was recorded raw ONLY: 505 lines, 0 entities on the OTC run).
        r = exec_tool("smap", ["smap", "-iL", str(sm_in), "-oJ", str(sm)], timeout=600)
        smn = _smap_ingest(ctx, r, sm, "probe", sm_targets)
        if smn:
            ctx.echo(f"  smap: +{smn} passive port(s) (Shodan-backed, no packets to target)")
