"""Phase 4: Probe / fingerprint / screenshots / ports.

httpx json (source of truth for live services) with the methodology's full flag set
(follow-host-redirects, asn, location, random-agent) at RoE rate limit + full-monty ports;
gowitness screenshots; naabu ports → nmap -sV service detection (only on in-scope CIDR);
optional smap passive (Shodan-backed) port scan.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass as _dataclass

import json as _json
import ipaddress as _ipaddress
import dataclasses
import math as _math
import re as _re
import time as _time
import urllib.parse
import urllib.request
from pathlib import Path

from .. import (budget, contract, events, netguard, normalize, pace, secrets, settings, shodan_host,
                shodan_sched, store)
from ..contract import (PROVIDER_CLASSES, PROVIDER_ERROR, PROVIDER_PACE_BUSY, PROVIDER_PARSE,
                        PROVIDER_RATE_LIMIT,
                        AcquisitionBudgetExhausted, IncompleteAcquisition, ProviderResult, ProviderSkip,
                        ResponseTooLarge, capture_error_body, default_governor,
                        is_provider_limit, provider_error_class, read_bounded, run_contract,
                        run_provider, stream_to_file)
from ..runner import (Status, ffuf_results, ffuf_usable_rows, fresh_artifact_dir, have,
                      native_output_current, nuclei_timeout, reclassify_ffuf,
                      reclassify_from_artifact, reclassify_from_files, run as exec_tool, scaled_timeout,
                      skipped)
from ..runner_repository import RepositoryOutput
from ..runner_native import RepositoryNativeOutput

# Serialized-object / token markers in Set-Cookie + response headers; passive format evidence only.
# Distinctive markers only — pickle (`gAR`) / Ruby-Marshal (`BAg`) prefixes collide too easily.
_DESER_MARKERS = (
    ("java-serialized", "rO0AB"),            # ObjectOutputStream AC ED 00 05 → base64
    ("dotnet-binaryformatter", "AAEAAAD"),   # 00 01 00 00 00 FF FF FF FF → base64 AAEAAAD/////
    ("node-serialize", "_$$ND_FUNC$$_"),     # node-serialize function marker
)
_PHP_OBJ_RX = _re.compile(r'O:\d+:"[A-Za-z0-9_\\]+":')          # PHP serialize() object in a cookie
_JWT_RX = _re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")


_SHODAN_PAGE = 100                              # Shodan host/search returns up to 100 matches/page


class ShodanPageError(Exception):
    """Carries a page failure's `error_class` when the original exception cannot hold one.

    The coordinator reads that attribute and asks `is_provider_limit` about it; an unclassified
    exception counts as a generic `error`."""

    def __init__(self, error_class: str, cause: BaseException):
        super().__init__(str(cause) or error_class)
        self.error_class = error_class
        self.__cause__ = cause


def _classified(e: BaseException) -> BaseException:
    cls = provider_error_class(e)
    try:
        e.error_class = cls                                   # type: ignore[attr-defined]
        return e
    except Exception:                                         # frozen/slotted exception types
        return ShodanPageError(cls, e)


#: characters a DNS owner name may use beyond a hostname's: `_` (`_dmarc`) and `*` (wildcard owner).
_DNS_OWNER_EXTRA = "_*"


def _dns_owner_name(h: str):
    """A syntactically valid DNS owner name that is not a valid hostname, or None.

    Not a hostname check — `normalize.canon_host_strict` is that, and a caller about to CONTACT a name
    must use it instead."""
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


#: cooldown applied when Shodan answers 429 without a usable `Retry-After`. Provider-driven, not an
#: operator knob and not the target rate limit.
_SHODAN_BACKOFF_S = 5.0
#: the minimum gap between two Shodan requests; Shodan documents ~1 request/second.
_SHODAN_MIN_INTERVAL_S = 1.05
#: the longest slowdown honored from a `Retry-After` header; beyond it the fallback applies.
_SHODAN_BACKOFF_MAX_S = 300.0



class _ProviderCooldown:
    """This ACCOUNT's rate boundary — honored by every Shodan request, from any lane or process.

    One cooldown shared by sizing and purchasing."""

    def __init__(self, key=None):
        self.until = 0.0
        self.hits = 0
        self.last = 0.0                 # when this object last issued a request (monotonic, fallback)
        # keyed by a fingerprint of the credential, never the credential itself
        self.account = pace.account("shodan", key)
        #: set when a provider penalty could NOT be shared with the account; this lifecycle then stops
        #: contacting the provider rather than pretending it is coordinated.
        self.unshared_penalty = ""

    def note(self, err) -> None:
        self.hits += 1
        wait = _SHODAN_BACKOFF_S
        hdrs = getattr(err, "headers", None)
        raw = hdrs.get("Retry-After") if hdrs is not None else None
        try:
            if raw is not None:
                # only a finite, non-negative, in-range value is honored; anything else falls back
                got = float(str(raw).strip())
                if _math.isfinite(got) and 0.0 <= got <= _SHODAN_BACKOFF_MAX_S:
                    wait = got
        except (TypeError, ValueError):
            pass
        self.until = max(self.until, _time.monotonic() + wait)
        # a 429 is about the CREDENTIAL: persisted so concurrent and later runs honour it too
        if not pace.note_penalty(self.account, _time.time() + wait):
            self.unshared_penalty = (f"a {wait:g}s provider slowdown could not be shared with this "
                                     f"account — other runs would not honour it")

    def wait(self) -> None:
        """Honour this ACCOUNT's slowdown and minimum interval, then mark the request.

        Called immediately before PROVIDER CONTACT and nowhere else — replaying owned evidence never
        waits here. The account boundary is authoritative and shared installation-wide; the in-process
        interval is the fallback for when that state cannot be read or written."""
        if self.unshared_penalty:
            # a penalty we cannot coordinate: refuse rather than burst
            raise pace.PaceBusy(self.unshared_penalty)
        penalty = self.until - _time.monotonic()
        pace.wait(self.account, _SHODAN_MIN_INTERVAL_S,
                  penalty_until=(_time.time() + penalty) if penalty > 0 else 0.0)
        now = _time.monotonic()
        left = max(self.until - now, (self.last + _SHODAN_MIN_INTERVAL_S) - now if self.last else 0.0)
        if left > 0:
            _time.sleep(left)
        self.last = _time.monotonic()


#: the client identifier every Shodan request sends. A browser User-Agent is answered on
#: `/shodan/host/search` by Cloudflare's interstitial (403); this is an API we identify ourselves to.
SHODAN_UA = "quarry-recon"

#: how large an artifact this process will parse in memory. A paid response has no byte ceiling; over
#: this bound the page is still acquired and owned, only its ingest is deferred
SHODAN_PARSE_LIMIT = 256 * 1024 * 1024
#: how much of a FREE endpoint's response we hold in memory (nothing is bought, so a re-read is free)
SHODAN_READ_LIMIT = 64 * 1024 * 1024


#: kept as an alias so a caller can name the Shodan case specifically; the machinery is shared
ShodanResponseTooLarge = ResponseTooLarge


class ShodanPageTooLargeToParse(ValueError):
    """The page was ACQUIRED and KEPT; this process will not parse it in memory. Not a provider defect
    and not a lost purchase — the artifact is on disk and owned."""

    error_class = "oversize"


def _read_bounded(r, limit: "int | None" = None) -> bytes:
    """`contract.read_bounded` with this lane's bound, read at CALL TIME rather than frozen into the
    signature as a default."""
    return read_bounded(r, SHODAN_READ_LIMIT if limit is None else limit, provider="shodan",
                        bound="SHODAN_READ_LIMIT")


def _shodan_count(key, facet, v):
    """ONE free `/shodan/host/count` -> `(total, raw_bytes, error)`. NEVER raises.

    Count is free and keeps working at a zero balance, so sizing continues when paid credits are
    exhausted or reserved. `total` is an exact non-negative int (`bool` excluded) or None for UNKNOWN,
    never zero. `raw_bytes` are the provider's exact bytes, which is what gets stored."""
    url = (f"https://api.shodan.io/shodan/host/count?key={key}"
           f"&query={urllib.parse.quote(f'{facet}:{v}')}")
    raw = b""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": SHODAN_UA})
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = _read_bounded(r)
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


def _parse_page_bytes(raw: bytes):
    """Validate one page's BYTES into `(rows, total)`. Raises on anything we will not call a page.

    Separate from acquisition so a response we already own can be interpreted later, from its artifact
    and for no credit, without contacting Shodan."""
    data = _json.loads(raw.decode("utf-8", "replace"))
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
        # a non-string member is corruption, exactly like a non-dict row
        for _h in (hns or []):
            if not isinstance(_h, str):
                raise ValueError(f"shodan: non-string hostname {type(_h).__name__}")
        page_rows.append(m)
    return page_rows, page_total


def _parse_owned_page(path):
    """`(rows, total)` from bytes we already paid for, or None when they still cannot be read.

    Never raises and never contacts the provider; a page that still will not parse stays owned and
    unparsed."""
    try:
        p = Path(path)
        if p.stat().st_size > SHODAN_PARSE_LIMIT:
            return None                                   # still too large for this box
        return _parse_page_bytes(p.read_bytes())
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return None


#: how much of a streamed error body is read back for CLASSIFICATION. The body itself is kept whole on
#: disk; this only bounds what one classification holds in memory.
_ERROR_CLASSIFY_BYTES = 64 * 1024


def _partial_size_and_digest(path, *, fallback: int):
    """(size, sha256) of a retained partial so a paid partial exports its real digest; falls back to the
    reported byte count with no digest when the file cannot be read."""
    if path is None:
        return fallback, None
    h = hashlib.sha256()
    n = 0
    try:
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(block)
                n += len(block)
        return n, h.hexdigest()
    except OSError:
        return fallback, None


def _shodan_page(key, facet, v, page, *, sink):
    """ONE page of a Shodan search, as the coordinator's `(matches, total, error)` triple. NEVER raises.

    The response is streamed to `sink` and kept whole — a paid page has no byte ceiling (see
    `SHODAN_PARSE_LIMIT`). Parsing reads that file, so the artifact is the evidence of record, and every
    error carries the artifact it was raised over so the coordinator can publish the bytes whatever the
    outcome.

    Fail-closed: a non-object body, a non-int/negative `total`, a non-list `matches`, a non-dict row or a
    non-list `hostnames` is an error, never laundered into a clean empty."""
    url = (f"https://api.shodan.io/shodan/host/search?key={key}"
           f"&query={urllib.parse.quote(f'{facet}:{v}')}&page={page}")
    sink = Path(sink)
    # admit against the disk governor before the paid open: an exhausted/tripped budget must not spend a
    # credit for bytes we cannot keep, and leaves nothing owned (raises, so no request is issued)
    gov = default_governor()
    sink.parent.mkdir(parents=True, exist_ok=True)
    denied = gov.admit(sink.parent)
    if denied is not None:
        raise AcquisitionBudgetExhausted(denied)
    size = 0
    digest = None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": SHODAN_UA})
        with urllib.request.urlopen(req, timeout=20) as r:
            size, digest = stream_to_file(r, sink, governor=gov)
        if size > SHODAN_PARSE_LIMIT:
            raise ShodanPageTooLargeToParse(
                f"shodan: page is {size} bytes, beyond SHODAN_PARSE_LIMIT ({SHODAN_PARSE_LIMIT}) — the "
                f"response is KEPT and owned; its rows are not ingested by this process")
        page_rows, page_total = _parse_page_bytes(sink.read_bytes())
    except Exception as e:
        # a paid error response is still paid: streamed to `.error` (outside the acquisition namespace, or
        # the ownership scan reads it as an unowned paid response)
        err_sink = None
        response = e                      # the ORIGINAL response, whatever `e` becomes below
        if isinstance(e, IncompleteAcquisition):
            # the paid 200 body was cut by our disk policy (truncated) or a transport break: the `.part`
            # bytes are ours and owned, so report their real count and digest, never zero/None
            err_sink = e.partial
            size, digest = _partial_size_and_digest(e.partial, fallback=e.bytes_written)
        elif size == 0 and hasattr(e, "read"):
            err_sink = sink.with_name(sink.name + ".error")
            try:
                size, digest = stream_to_file(e, err_sink, governor=gov)
            except IncompleteAcquisition as inc:
                # the partial bytes are ours: the incomplete acquisition carries its own class and
                # `.part` to the coordinator, with the retained bytes' real digest
                inc.__cause__ = e
                e, err_sink = inc, inc.partial
                size, digest = _partial_size_and_digest(inc.partial, fallback=inc.bytes_written)
            except Exception:
                size, digest, err_sink = 0, None, None
            if size and err_sink is not None:
                try:
                    with Path(err_sink).open("rb") as fh:
                        e.body_bytes = head = fh.read(_ERROR_CLASSIFY_BYTES)
                    e.body_text = head.decode("utf-8", "replace")
                except Exception:
                    pass
            # a stamped `body_text` makes `capture_error_body` skip its own read, and its close with it:
            # closed here on every path, and on the ORIGINAL response — `e` may now be the carrier.
            try:
                response.close()
            except Exception:
                pass
        # Shodan answers a spent balance with 401 + JSON and a bad key with 401 + HTML, so the class is
        # refined by body. A body already stamped above is left alone.
        capture_error_body(e, provider="shodan")
        # the artifact travels with the failure; the coordinator publishes what it is handed
        kept = err_sink if err_sink is not None else (sink if size else getattr(e, "partial", None))
        for attr, val in (("raw_path", kept), ("raw_digest", digest), ("raw_bytes", size)):
            try:
                setattr(e, attr, val)
            except Exception:
                pass
        return [], None, _classified(e)
    return page_rows, page_total, None


# ── the Shodan credit-balance contract ──

# `/api-info` is free at a zero balance, so the provider's answer is the planning input, and its
# 401-quota body stays the authority
_SHODAN_RESERVE_MAX = 1_000_000


@_dataclass(frozen=True)
class ShodanBalance:
    """The settled credit contract. Each field is a distinct fact:

      remaining   finite credits the provider reports   (None = UNKNOWN, never "unlimited")
      allowance   the plan's monthly limit              (context; None when unreadable or unlimited)
      reserve     credits the OPERATOR withholds        (our own config, always known)
      spendable   what this run may use                 (None = UNKNOWN, i.e. no computable bound —
                                                         permitted only when no reserve is set)
      allowance_unlimited  the PLAN has no monthly ceiling (usage_limits.query_credits == -1)
      stop_kind   WHY we may not spend, as a token      (not all stops are soft limits — see
                                                         `stop_is_limit`)
      read_error  how the /api-info read FAILED         (None on success; kept even when the balance
                                                         itself is unusable)
      count_refused  how a /host/count refused the KEY   (set only when a free count proved the
                                                         credential is refused after /api-info
                                                         succeeded)"""

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
        """Whether a stop is an expected soft limit (-> complete_with_limits) or a real gap. A
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
SHODAN_PAGE_CEILING_INVALID = "page_ceiling_invalid"  # SHODAN_MAX_PAGES unusable         -> GAP

#: stops that are expected boundaries rather than defects. Everything else is a gap the operator fixes.
_STOP_LIMITS = frozenset({SHODAN_PROVIDER_EXHAUSTED, SHODAN_ENTITLEMENT, SHODAN_OPERATOR_RESERVE,
                          SHODAN_UNKNOWN_WITH_RESERVE})

#: every stop token that is not already a taxonomy class, mapped to the one it means. A broken cost
#: guard, an unwritable ledger, a failed publish and a scheduler invariant are all `error`.
_TOKEN_CLASS = {SHODAN_AUTH_REFUSED: "auth", SHODAN_RESERVE_INVALID: PROVIDER_ERROR,
                SHODAN_PAGE_CEILING_INVALID: PROVIDER_ERROR,
                "ledger_unwritable": PROVIDER_ERROR, "publish_failed": PROVIDER_ERROR,
                "scheduler_invariant": PROVIDER_ERROR}


#: stop causes that are OUR OWN machinery, not the provider's.
_INTERNAL_STOPS = frozenset({"ledger_unwritable", "publish_failed", "scheduler_invariant"})


def _internal_stop(stop: str) -> bool:
    return stop in _INTERNAL_STOPS or stop.startswith("machinery:")


def _canonical_class(token) -> str:
    """A canonical `PROVIDER_CLASSES` value for an internal stop token; the token itself stays in the
    reason."""
    if token in PROVIDER_CLASSES:
        return token
    return _TOKEN_CLASS.get(token, PROVIDER_ERROR)


#: a stop the PROVIDER proved, as the error class the terminal speaks. An operator reserve or an
#: unreadable balance is our own policy or problem and is not dressed up as the provider refusing us.
_STOP_CLASS = {SHODAN_PROVIDER_EXHAUSTED: "quota", SHODAN_ENTITLEMENT: "entitlement"}
#: count-endpoint outcomes that stop sizing, and whether they also prove the credential refused.
#: `auth` is global; `forbidden`/`entitlement` are proven only for their own endpoint.
_COUNT_STOPS = {"auth": True, "forbidden": False, "entitlement": False}

#: balance-read outcomes that mean the key is not accepted, so even free calls stop. Quota,
#: entitlement and a reserve are "key works, spend does not", so sizing continues through those.
_SIZING_REFUSED = {SHODAN_AUTH_REFUSED: "auth_refused", SHODAN_FORBIDDEN: "forbidden"}


#: stops that are OURS: the outcome is LIMITED, never a provider class and never a degraded execution.
_OPERATOR_STOPS = frozenset({SHODAN_OPERATOR_RESERVE, SHODAN_UNKNOWN_WITH_RESERVE})

#: read outcomes that prove paid work is pointless. transport/parse/server say nothing about the
#: account, so they keep the ordinary unknown fallback.
_BLOCKING_READ = frozenset({"auth", "quota", "entitlement", "forbidden"})


def _exact_int(v, *, minimum: int = 0):
    """An exact int >= minimum, or None. `bool`, floats and numeric strings never pass."""
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
    """-> value or None. An exact non-negative int, with NO -1 sentinel: the top-level `query_credits`
    has no documented unlimited value, so `-1` here is schema drift."""
    return _exact_int(v)


def _shodan_reserve_setting():
    """-> (reserve, valid). Absent means 0 and is fine; present-but-invalid (a typo, a bool, a float, an
    oversized value) is not valid and must not fall back to 0, which would disable the cost guard."""
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

    Each case has a distinct `stop_kind` (and see `stop_is_limit` — not every stop is an expected
    boundary):

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
        if strict is None:                       # True/12.9/"abc" from a caller is a bug, not a policy
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
    # the plan ALLOWANCE and the REMAINING balance are separate facts: an unlimited plan can still
    # report a finite balance for this month, and that number is the one we spend against.
    if not reserve_valid:
        return ShodanBalance(remaining, allowance, 0, 0, False,
                             "SHODAN_CREDIT_RESERVE is set but unusable — refusing to spend rather than "
                             "silently disabling the operator's cost guard",
                             allowance_unlimited=allowance_unlimited,
                             stop_kind=SHODAN_RESERVE_INVALID)
    if not _page_ceiling(settings.raw("SHODAN_MAX_PAGES", None))[1]:
        # the OTHER cost knob, same rule: a page ceiling we cannot read is not an absent ceiling.
        return ShodanBalance(remaining, allowance, 0, 0, False,
                             "SHODAN_MAX_PAGES is set but unusable — refusing to spend rather than "
                             "removing the page ceiling the operator meant to set",
                             allowance_unlimited=allowance_unlimited,
                             stop_kind=SHODAN_PAGE_CEILING_INVALID)
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
    """A read outcome that PROVES paid work is pointless must also STOP it — `read_error` alone is
    recorded and not acted on."""
    if cls not in _BLOCKING_READ:
        return dataclasses.replace(bal, read_error=cls)      # transport/parse/server: says nothing
    kind = {"quota": SHODAN_PROVIDER_EXHAUSTED, "entitlement": SHODAN_ENTITLEMENT,
            "auth": SHODAN_AUTH_REFUSED}.get(cls, SHODAN_FORBIDDEN)
    why = {"quota": "the provider reports the query-credit balance EXHAUSTED",
           "entitlement": "the PLAN cannot reach this endpoint",
           "auth": "the credential was REJECTED — a setup defect, not an expected boundary",
           }.get(cls, f"the provider REFUSED the balance read ({cls})")
    # a spend the provider will not honor leaves free endpoints usable; a key it will not accept does not
    free = "free operations continue" if kind not in _SIZING_REFUSED else \
        "no free operation is issued either — the key itself was refused"
    return dataclasses.replace(bal, read_error=cls, may_spend=False, spendable=0, stop_kind=kind,
                               reason=f"{why} — no paid search is issued ({free})")


def _read_shodan_balance(key, timeout: int = 15, cooldown=None) -> ShodanBalance:
    """Read `/api-info` (FREE, and it works at a ZERO balance) and settle the contract.

    The READ OUTCOME is kept separately from the balance facts: `read_error` keeps auth/quota/transport/
    parse distinguishable, and for the classes that prove refusal it also blocks spending. A failure
    yields UNKNOWN, never zero."""
    try:
        url = f"https://api.shodan.io/api-info?key={urllib.parse.quote(str(key))}"
        req = urllib.request.Request(url, headers={"User-Agent": SHODAN_UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(64 * 1024).decode("utf-8", "replace")
    except Exception as e:
        # reads the body at the raise site, closes the stream, and refines 401 by body: an exhausted
        # account reads `quota` and a bad key reads `auth`
        capture_error_body(e, provider="shodan")
        cls = provider_error_class(e)
        if cooldown is not None and cls == PROVIDER_RATE_LIMIT:
            # noted at the raise site, where the response (and any Retry-After) is still readable
            cooldown.note(e)
        return _blocked_read(shodan_balance(None), cls)
    try:
        doc = _json.loads(body)
    except Exception:
        return _blocked_read(shodan_balance(None), "parse")
    bal = shodan_balance(doc)
    # a well-formed body carrying `"85"`, `-2` or no `query_credits` is schema drift, not an unknown
    # balance. A malformed `usage_limits` stays non-fatal: it is context, not the balance.
    if not bal.known:
        return _blocked_read(bal, "parse")
    return bal


def _emit_shodan_balance(sid: str, bal: ShodanBalance) -> None:
    """Publish the balance as its OWN ledger event, every lifecycle.

    Emitted unconditionally, including the unknown case, so a previous run's numbers never stay on
    display as current. `remaining`/`allowance` are null when unknown, never 0."""
    events.ledger(sid, produced=None, consumed=None, balance={
        "provider": "shodan", "remaining": bal.remaining, "allowance": bal.allowance,
        "reserve": bal.reserve, "spendable": bal.spendable, "known": bal.known,
        "may_spend": bal.may_spend, "allowance_unlimited": bal.allowance_unlimited,
        "stop_kind": bal.stop_kind or None, "stop_is_limit": bal.stop_is_limit,
        "read_error": bal.read_error, "count_refused": bal.count_refused, "reason": bal.reason})


#: There is no OOS cap: the RoE boundary is OBSERVE and mine OOS evidence, never actively expand
#: against it. Bound a DISPLAY if a report is long; never the stored evidence.


@_dataclass
class _SharedWork:
    """What ONE coordinator run produced for ALL lanes. Every field is per-source_id."""

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


#: every Shodan search lane, collected together so one coordinator can order them fairly
_SHODAN_LANES = (
    _LaneSpec("probe.favicon", "http.favicon.hash", "favicon-shodan", "live", "favicon",
              "same favicon (hash {}) as an in-scope host — VERIFY OWNERSHIP"),
    _LaneSpec("probe.cert", "ssl.cert.fingerprint", "cert-shodan", "certificate", "sha1",
              "same TLS cert (sha1 {}) as an in-scope host — VERIFY OWNERSHIP"),
)


def _page_ceiling(v) -> "tuple[int, bool]":
    """-> (pages, valid). `0` = no page ceiling, the default; the credit balance is then the only bound.
    Absent means 0 and is valid.

    A bool, float, string or negative is present-but-invalid and does NOT become unbounded — the caller
    refuses paid acquisition instead, the same contract `_shodan_reserve_setting` holds for the other
    cost knob."""
    if v is None or (isinstance(v, str) and not v.strip()):
        return 0, True
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        return 0, False
    return v, True


def _shodan_work(ctx, key, lanes):
    """See `_shodan_work_locked`. The PROJECT lock wraps the whole page lifecycle: two runs of one
    project would otherwise both see a page as unowned and both pay for it."""
    try:
        with shodan_sched.lifecycle_lock(ctx.run.project_dir):
            return _shodan_work_locked(ctx, key, lanes)
    except shodan_sched.StoreBusy as e:
        # refuse rather than wait: this run issues zero paid requests, and the holder's evidence is not
        # ours — a gap local to this run
        for spec, _vals in lanes:
            events.coverage_partial(
                spec.sid, kind=events.COVERAGE_TIMEOUT, measure="shodan_pages", unit=f"{spec.sid}.pages",
                reason=f"no page queried — another run holds this project's purchased-page store ({e})")
        raise ShodanPageError("busy", RuntimeError(
            f"shodan: another run holds this project's purchased-page store ({e})"))


def _shodan_work_locked(ctx, key, lanes):
    """Spend ONE credit budget across ALL Shodan pivot lanes, under ONE coordinator: collect every
    lane's values first, spend once, so credits are ordered fairly across them.

    Returns a `_SharedWork`. Each lane's TERMINAL is still produced inside its own `run_provider`
    bracket, so per-source telemetry and coverage generations are unchanged."""
    # SHODAN_MAX_PAGES is a spending control, read raw and strict, not through `concurrency()` whose
    # `max(1, ...)` floor would turn a configured 0 (no ceiling) into one page
    max_pages, _pages_valid = _page_ceiling(settings.raw("SHODAN_MAX_PAGES", None))
    scope = ctx.scope

    def settled_balance():
        """The balance as it FINALLY stood, or an explicit "not consulted" when the run never asked."""
        if paid["bal"] is not None:
            return paid["bal"]
        if paid["pace_busy"]:
            # our own rate boundary declined to let a request out. `stop_kind` stays empty so nothing
            # reads this as a reserve or as exhaustion; the lane's `pace_busy` stop cause carries it.
            return ShodanBalance(
                remaining=None, allowance=None, reserve=_shodan_reserve_setting(), spendable=0,
                may_spend=False,
                reason=f"no provider contact this lifecycle — {paid['pace_busy']}")
        return ShodanBalance(
            remaining=None, allowance=None, reserve=_shodan_reserve_setting(), spendable=None,
            may_spend=True,
            reason="balance not consulted — the run ended before any provider contact was needed")

    cooldown = _ProviderCooldown(key)
    # the balance IS provider contact: read lazily, after replay, and only if pages remain to buy, so a
    # project that already owns everything it needs issues no request at all.
    paid: dict = {"bal": None, "sizing": None, "consulted": False, "pace_busy": ""}
    try:
        found: dict = {spec.sid: set() for spec, _vals in lanes}
        oos: dict = {spec.sid: {"seen": 0, "invalid": 0, "kept": set()} for spec, _vals in lanes}
        hostnames: dict = {spec.sid: {"seen": 0, "unusable": 0, "noncanonical": 0} for spec, _vals in lanes}

        # ONE ledger for the coordinator's own lane; `item_key` is namespaced by the pivot's lane, so a
        # favicon page and a cert page are distinct identities.
        cfg_fp = events.work_unit("probe.shodan", inputs={}, config={"facets": [s.facet for s, _v in lanes]},
                                  schema_version=shodan_sched.SHODAN_WORK_SCHEMA)
        # PROJECT-scoped, not run-scoped: purchased pages must not be paid for twice. The TTL below is
        # what keeps this from becoming an eternal cache.
        sbase = shodan_sched.state_dir(ctx.run.project_dir)
        sbase.mkdir(parents=True, exist_ok=True)
        # the ledger's identity is the schema, not the enabled pivot set. Nothing is pruned, or paid-for
        # artifacts become unreplayable and buyable again.
        ledger = budget.Ledger(
            budget.state_path(sbase, "probe.shodan", f"v{shodan_sched.SHODAN_WORK_SCHEMA}"),
            lane="probe.shodan")
        # the artifacts live UNDER the ledger's own directory, or they cannot be owned at all
        attempt_dir = fresh_artifact_dir(sbase / "pages" / cfg_fp[:16])
        page_ttl = _shodan_page_ttl()
        by_sid = {spec.sid: spec for spec, _vals in lanes}
        # error evidence is per SOURCE: one global last-error would let a failure in one lane decide
        # another lane's terminal
        errs: dict = {spec.sid: {"last": None, "last_fail": None} for spec, _vals in lanes}

        def search(pivot, page):
            # `cooldown.wait()` may refuse (PaceBusy) and that propagates: the coordinator must see it before
            # it crosses "a request was issued", or it charges a credit for a socket that never opened
            cooldown.wait()
            # streamed under the ledger's own directory, so a page we paid for exists on disk before
            # anything decides whether we can use it
            sink = attempt_dir / "raw" / f"{shodan_sched.item_key(pivot, page)}.json"
            matches, total, err = _shodan_page(key, pivot.facet, pivot.value, page, sink=sink)
            if err is not None and provider_error_class(err) == PROVIDER_RATE_LIMIT:
                cooldown.note(err)
            if err is not None:
                slot = errs[pivot.lane]
                slot["last"] = err
                if not is_provider_limit(provider_error_class(err)):
                    slot["last_fail"] = err
            return matches, total, err

        def ingest(pivot, page, matches, raw_path):
            """Turn one page's rows into entities. `raw_path` is the page artifact the coordinator
            published, so every ingested host's `raw_ref` points at the file containing its evidence."""
            spec = by_sid[pivot.lane]
            label = spec.sid.split(".", 1)[-1]
            v = pivot.value
            names = hostnames[spec.sid]
            for m in matches:
                for raw_hn in (m.get("hostnames") or []):
                    names["seen"] += 1
                    hn = raw_hn.strip().lower().rstrip(".")
                    # ONE canonical form decides identity AND scope, so a Unicode name and its punycode
                    # spelling are the same host to both. `canon_host_strict` is Quarry's IDNA policy.
                    canon = normalize.canon_host_strict(hn)
                    if canon is None:
                        # a name that is not a valid hostname never becomes a `subdomain` (consumed by active
                        # lanes); a valid DNS owner name is retained as passive review evidence
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
                        # the store comes first: `found` drives the terminal, so a storage failure must not
                        # report the host as produced. A `False` return is dedup and still counts.
                        ctx.run.add("subdomain", {"host": hn, "sources": [spec.source],
                                                  "raw_ref": str(raw_path)})
                        found[spec.sid].add(hn)
                    else:
                        # off-scope: mining a page we already bought is passive, and `related-host` feeds
                        # nothing active. Kept in full, deduplicated, never truncated.
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

        def enter_paid_phase():
            """Everything that touches Shodan, entered once replay has finished — and only then.

            Balance first (free, and it decides whether spending is permitted at all), then sizing —
            both paced by the same cooldown as purchasing, because both are provider contact."""
            paid["consulted"] = True
            try:
                cooldown.wait()          # the balance read is provider contact like any other
            except pace.PaceBusy as e:
                # no contact at all this lifecycle. Raised, not returned: the coordinator records
                # `pace_busy` as the stop cause, so this reads as our gap rather than a quiet skip.
                paid["pace_busy"] = str(e)
                raise
            bal = _read_shodan_balance(key, cooldown=cooldown)
            # held immediately, so a failure in sizing or later still leaves one balance record per lane
            paid["bal"] = bal
            sizing, refused = _size_pivots(key, states, ledger=ledger, attempt_dir=attempt_dir,
                                           cooldown=cooldown,
                                           refused=_SIZING_REFUSED.get(bal.stop_kind))
            paid["sizing"] = sizing
            if refused:
                # a count PROVED the credential is refused, and /api-info may still have succeeded (a
                # key can be revoked between the two), so its balance and `read_error` stay as reported
                bal = dataclasses.replace(bal, may_spend=False, spendable=0, count_refused=refused,
                                          stop_kind=SHODAN_AUTH_REFUSED,
                                          reason=f"shodan refused the credential on /host/count "
                                                 f"({refused})")
            paid["bal"] = bal
            return bal

        def should_stop(cls):
            """Failures further requests cannot get past. Not a reclassification: these stay gaps and
            only stop us ASKING.

              auth        the credential is refused; every remaining pivot would be refused identically
              forbidden   the shared search endpoint said no; the next pivot uses the same endpoint
              rate_limit  once is "back off and retry"; twice is a provider we would be hammering
            """
            return cls in ("auth", "forbidden") or (cls == PROVIDER_RATE_LIMIT and cooldown.hits > 1)

        res = shodan_sched.run_work(ctx, states=states, balance=enter_paid_phase, search=search,
                                    ingest=ingest,
                                    parse=_parse_owned_page,
                                    ledger=ledger, attempt_dir=attempt_dir, max_pages=max_pages,
                                    should_stop=should_stop, ttl_days=page_ttl)
        return _SharedWork(balance=settled_balance(), result=res, found=found, errs=errs, oos=oos, names=hostnames,
                           sizing=paid["sizing"] or {}, max_pages=max_pages)
    finally:
        # exactly one balance record per lane, on every path, carrying the final state of `bal`
        settled = settled_balance()
        for spec, _vals in lanes:
            _emit_shodan_balance(spec.sid, settled)


def _hostname_facts(nm: dict) -> list:
    """Every hostname fact, stated independently — two facts about two different names never share a
    branch."""
    facts = [f"{nm['seen']} hostname(s) read"]
    if nm["unusable"]:
        facts.append(f"{nm['unusable']} not usable as a host name")
    if nm["noncanonical"]:
        facts.append(f"{nm['noncanonical']} valid DNS owner name(s) retained as PASSIVE evidence "
                     f"(not hostnames, never actively expanded)")
    return facts


def _shodan_page_ttl() -> float:
    """How long a purchased page may stand in for a fresh one, as configured. A DURATION, not a lane
    count: `settings.concurrency()` would clamp to >= 1 and make the documented `0 = never replay`
    unreachable."""
    return settings.policy_days("SHODAN_PAGE_TTL_DAYS", shodan_sched.PAGE_TTL_DAYS_DEFAULT)


def _size_pivots(key, states, *, ledger, attempt_dir, cooldown, refused=None) -> tuple:
    """Size EVERY eligible pivot with a free `/host/count`, every lifecycle — including pivots whose
    pages are all already owned, so results that appeared since pagination completed are found.

    Returns `(stats, refused_credential)`; the second is set when a count proved the KEY is refused,
    which must stop paid work too.

    Order is cross-lane fair, so a provider slowdown does not decide which lane got sized at all.
    Requests are serial, carry the same per-request timeout as a paid search, and share the paid run's
    cooldown; a first 429 backs off and continues, a repeated one stops sizing for this lifecycle.
    Unsized pivots keep unknown cardinality, which is a position and not an exclusion. A count orders
    paid work only once its evidence is durably bound."""
    stats: dict = {}
    refused_credential = [None]                      # set when a count PROVES the key itself is refused

    def stat(sid):
        return stats.setdefault(sid, {"attempted": 0, "succeeded": 0, "not_attempted": 0,
                                      "failed_by_class": {}, "evidence_failed": 0, "stop_reason": ""})

    ordered = budget.order_fairly(list(states), lambda st: st.pivot.lane)
    # a proven refusal of the credential means not one request, free or not
    stopped = refused or ""
    for st in ordered:
        sid = st.pivot.lane
        if stopped:
            stat(sid)["not_attempted"] += 1
            continue
        try:
            cooldown.wait()                          # honor any slowdown already in force
        except pace.PaceBusy as e:
            # the account boundary refused: this pivot and every one after it go unattempted, counted
            # rather than disguised as a zero count
            stat(sid)["not_attempted"] += 1
            stat(sid)["stop_reason"] = PROVIDER_PACE_BUSY
            stopped = True
            del e
            continue
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
                # asking every remaining pivot the same rejected question is the fan-out this stops
                stopped = cls
                if _COUNT_STOPS[cls]:
                    refused_credential[0] = cls
            continue                                 # unknown cardinality; the pivot stays eligible
        # the EXACT response bytes, under an identity binding them to the request that produced them.
        # Evidence, never a completion: sizing is redone every lifecycle.
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
        # stamped on every participating lane, including one stopped on its final pivot
        for s in stats.values():
            s["stop_reason"] = stopped
    return stats, refused_credential[0]


def _shodan_result(spec, values, work):
    """One lane's COVERAGE and TERMINAL, derived from the shared coordinator run.

    Runs inside that lane's own `run_provider` bracket: `coverage_reset` opens the generation there, so
    coverage emitted before the bracket would be wiped by it.

    Returns a plain set (SUCCESS/EMPTY) when nothing failed, a PARTIAL `ProviderResult` carrying the
    dominant class when evidence exists alongside errors, and RAISES when the lane yielded nothing and
    something either broke or refused us."""
    bal, res, max_pages = work.balance, work.result, work.max_pages
    o = res.lanes.get(spec.sid) or shodan_sched.LaneOutcome(lane=spec.sid)
    shodan_sched.report(spec.sid, o, balance=bal, persisted=res.persisted, max_pages=max_pages,
                        stop_cause=res.stop_cause)
    hits = work.found.get(spec.sid) or set()
    lane_errs = work.errs.get(spec.sid) or {"last": None, "last_fail": None}
    # OOS retention is its own fact: deduplication is not omission, so only candidates we could not
    # IDENTIFY count as omitted. Emitted every run so a later clean run clears it.
    st = work.oos.get(spec.sid) or {"seen": 0, "invalid": 0, "kept": set()}
    events.coverage_partial(spec.sid, kind=events.COVERAGE_TIMEOUT, measure="shodan_oos_retained",
                            unit=f"{spec.sid}.oos", eligible=st["seen"],
                            tested=st["seen"] - st["invalid"], omitted=st["invalid"],
                            reason=(f"{st['invalid']} off-scope candidate(s) could not be identified "
                                    f"and were NOT stored" if st["invalid"] else
                                    f"{len(st['kept'])} distinct off-scope related host(s) retained "
                                    f"from {st['seen']} observation(s) — no cap"))
    # SIZING is DIAGNOSTIC — a ledger event, not a coverage counter. Coverage is decided by PAID SEARCH;
    # a failed count changes nothing about it.
    sz = work.sizing.get(spec.sid) or {}
    events.ledger(spec.sid, produced=None, consumed=None, shodan_sizing={
        "pivots": len(values), "attempted": sz.get("attempted", 0),
        "succeeded": sz.get("succeeded", 0), "not_attempted": sz.get("not_attempted", 0),
        "failed_by_class": sz.get("failed_by_class") or {},
        "evidence_failed": sz.get("evidence_failed", 0),
        "stop_reason": sz.get("stop_reason") or None,
        "compared": o.count_compared, "drift": o.count_drift})
    # hostname members: a name we cannot use at all is a lost observation, a non-canonical one is usable
    # but deduplicates on the weaker form. Both are stated.
    nm = work.names.get(spec.sid) or {"seen": 0, "unusable": 0, "noncanonical": 0}
    events.coverage_partial(spec.sid, kind=events.COVERAGE_TIMEOUT, measure="shodan_hostnames",
                            unit=f"{spec.sid}.hostnames", eligible=nm["seen"],
                            tested=nm["seen"] - nm["unusable"], omitted=nm["unusable"],
                            reason="; ".join(_hostname_facts(nm)))
    fail_classes, limit_classes = dict(o.fail_classes), dict(o.limit_classes)
    errored = sum(fail_classes.values()) + sum(limit_classes.values())
    evidence = o.pages_bought + o.pages_replayed
    # what this lane BOUGHT, in the unit it is charged in; replayed pages cost nothing
    events.spend(spec.sid, provider="shodan", measure="pages", amount=int(o.pages_bought))
    # the four page dispositions, so a reader can tell CURRENT evidence from history and from a purchase
    # this run declined to make. `replayed_fresh` carries its age: "current" without one is a cache claim.
    if (o.pages_bought or o.pages_replayed or o.pages_aged or o.refresh_refused
            or o.pages_lost):
        events.coverage_partial(
            spec.sid, kind=events.COVERAGE_TIMEOUT, measure="shodan_pages", unit=f"{spec.sid}.pages",
            # a LOST page is evidence this project paid for and cannot show: it belongs in the
            # denominator and in `omitted`, beside the aged ones
            eligible=o.pages_bought + o.pages_replayed + o.pages_aged + o.pages_lost,
            tested=o.pages_bought + o.pages_replayed, omitted=o.pages_aged + o.pages_lost,
            reason=(f"bought={o.pages_bought}"
                    + (f"; lost={o.pages_lost} (already paid for; the stored artifact no longer "
                       f"verifies), repair_refused={o.repair_refused} (NOT re-bought: an evidence "
                       f"loss is not a spending permission)" if o.pages_lost else "")
                    + f"; replayed_fresh={o.pages_replayed}"
                    + (f" (oldest {o.oldest_replay_s / 86400:.1f}d)" if o.pages_replayed else "")
                    + f"; aged_available={o.pages_aged} (kept as history, excluded from current "
                      f"evidence); refresh_refused={o.refresh_refused} (a purchase this run did NOT "
                      f"make: refreshing paid evidence is an explicit operator decision)"))
    if values and not evidence and not errored:
        stop_cls = _STOP_CLASS.get(bal.stop_kind)          # already canonical: quota / entitlement
        if stop_cls:
            # the balance PROVED further work is pointless, so no request was issued. Nothing failed, so
            # there is no exception to raise, and a bare empty set would read as a clean EMPTY.
            return ProviderResult(hits, partial=True, partial_kind="degraded", error_class=stop_cls,
                                  partial_reason=f"no page queried — {bal.reason}")
        if bal.stop_kind and not bal.stop_is_limit:
            # a stop that is not a soft limit (a broken credential, a refusal, a broken cost guard)
            # is a defect, raised with the canonical class, not the internal stop token
            token = bal.count_refused or bal.read_error or bal.stop_kind
            raise ShodanPageError(_canonical_class(token),
                                  RuntimeError(f"shodan: {bal.reason} ({token})"))
    if values and errored and not hits and not evidence:
        # everything we attempted yielded NOTHING, and a REAL failure outranks a limit
        raise (lane_errs["last_fail"] if lane_errs["last_fail"] is not None else lane_errs["last"])
    # THIS lane's machinery, plus failures that belong to every lane (the ledger save, remainder
    # accounting). Another lane's ingest defect is not this lane's outcome.
    machinery = list(o.machinery) + list(res.machinery)
    # the whole remainder, not just `unqueried`: a pivot with one bought page and four provider-bounded
    # pages left is just as incomplete
    left = len(o.unqueried) + o.pages_left_known
    # a global internal stop reaches this lane only if it cost it something: work left, or state that
    # did not persist. `persisted` is the durability handshake (snapshot written or journal intact).
    if machinery or o.pages_unconsumed or (_internal_stop(res.stop_cause)
                                          and (left or not res.persisted)):
        # every part is added only when it says something, so no dangling dash or empty clause
        parts = [x for x in ("; ".join(machinery),
                             (f"{o.pages_unconsumed} owned page(s) could not be ingested"
                              if o.pages_unconsumed else ""),
                             ("page state was NOT persisted — bought pages will be bought again"
                              if not res.persisted else "")) if x]
        # `res.stop_cause` is a SCHEDULER TOKEN, not a provider class: our own defect is the canonical
        # `error` and the token stays in the reason.
        if res.stop_cause:
            parts.append(f"stopped: {res.stop_cause}")
        why = "; ".join(parts)
        # a gap dominates a limit; the limit survives in its own coverage measures and is named here.
        # `limited=True` beside a non-limit class changes no status, kind or verdict.
        if limit_classes:
            why += f"; {sum(limit_classes.values())} page(s) provider-limited {dict(limit_classes)}"
        if not hits and not evidence:
            raise ShodanPageError(PROVIDER_ERROR,
                                  RuntimeError(f"shodan: page state machinery failed — {why}"))
        return ProviderResult(hits, partial=True, partial_kind="degraded", error_class=PROVIDER_ERROR,
                              partial_reason=f"evidence KEPT; page state machinery failed — {why}")
    if left and not errored:
        stop = res.stop_cause or ""
        # OUR OWN machinery is handled above, whether or not a remainder is left (`_internal_stop`)
        cls = stop.split(":", 1)[1] if stop.startswith("provider_limit:") else None
        if stop.startswith("provider_stop:"):
            # another lane's FAILURE ended purchasing: this lane is incomplete for a real reason, and
            # that reason is a gap that must be named rather than left as a classless PARTIAL
            return ProviderResult(hits, partial=True, partial_kind="degraded",
                                  error_class=stop.split(":", 1)[1],
                                  partial_reason=f"{len(o.unqueried)} pivot(s) never queried, "
                                                 f"{o.pages_left_known} page(s) unbought — {stop}")
        if stop == "budget_provider" and not cls:
            cls = _STOP_CLASS.get(SHODAN_PROVIDER_EXHAUSTED)
        # an OPERATOR boundary is a LIMIT, not a degraded execution and not the provider's fault: it
        # carries no provider class, so it says `limited` in its own right
        operator = stop == "budget_reserve" or (not stop and bal.stop_kind in _OPERATOR_STOPS)
        why = (f"{len(o.unqueried)} pivot(s) never queried, {o.pages_left_known} page(s) unbought — "
               f"{stop or bal.reason or 'credit budget exhausted'}")
        if bal.read_error:
            # the balance read ALSO failed; both facts are kept
            why += f"; balance read failed ({bal.read_error})"
        return ProviderResult(hits, partial=True, partial_kind="degraded", error_class=cls,
                              limited=operator, partial_reason=why)
    if errored:
        # the dominant class comes from REAL failures when there are any, so a single transport error is
        # never relabelled as a provider limit (nor the reverse)
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

    A seam for driving a single lane directly, not a second implementation — production calls
    `_shodan_pivots`, which hands the coordinator every lane at once."""
    spec = _LaneSpec(sid, facet, source, "", "", note)
    vals = sorted({str(v) for v in values if v})
    return _shodan_result(spec, vals, _shodan_work(ctx, key, [(spec, vals)]))


def _shodan_pivots(ctx) -> None:
    """Every Shodan search pivot: collect ALL lanes' values first, then spend one budget across them.

    Pivot values are never sliced — throughput is bounded by the credit balance and the page policy;
    MEMBERSHIP is not bounded at all. Every lane is started before a single credit is spent and gets a
    terminal even when it cannot run, so no previous run's coverage generation stands as current."""
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
            raise ShodanPageError(PROVIDER_ERROR,
                                  RuntimeError("shodan: shared work produced no result"))
        return _shodan_result(spec, values, shared[0])

    entries = []
    for spec, values in lanes:
        # the resume key: bounded inputs + effective config, scoped to the ACCOUNT by credential
        # fingerprint
        wu = events.work_unit(spec.sid, inputs={"values": values},
                              config={"facet": spec.facet,
                                      # the effective ceiling the lane ran under, plus whether the knob was
                                      # usable: a broken-bound refusal must not share a clean-0 spend's key
                                      "max_pages": _page_ceiling(settings.raw("SHODAN_MAX_PAGES", None)),
                                      "oos_cap": 0,        # no cap; kept in the key so a unit resumed
                                                           # from a CAPPED generation is not mistaken
                                                           # for a complete one
                                      "cred_fp": secrets.fingerprint(key) if key else None})
        entries.append((spec.sid, wu, lambda s=spec, v=values: finalize(s, v)))
    results = contract.run_providers(entries, collect)
    for spec, _values in lanes:
        hosts = results.get(spec.sid)
        if hosts:
            ctx.echo(f"  {spec.sid.split('.', 1)[-1]}: +{len(hosts)} in-scope host(s) via Shodan "
                     f"{spec.facet} pivot")


def _vhost_wordlist():
    """Locate a DEDICATED vhost wordlist (small, label-per-line), or None → the step records a skip.
    There is no fallback to the big DNS brute list: vhost fuzzing is IPs x apexes x words."""
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

    For the case where we could not LOOK at the input at all (no ffuf, no wordlist), as distinct from
    `_vhost_zero_lifecycle`'s zero eligible input. COVERAGE_UNKNOWN carries no counters, forces
    coverage_valid=False and reaches the verdict as a gap."""
    for m in ("base_services", "base_services_scanned", "state_persisted"):
        events.coverage_partial("probe.ffuf_vhost", kind=events.COVERAGE_UNKNOWN, measure=m, unit=m,
                                reason=why)
    ctx.run.record("probe", skipped("ffuf-vhost", why))


def _vhost_zero_lifecycle(ctx, why, *, excluded=0, invalid=0) -> None:
    """Emit a COMPLETE zero-valued lifecycle for the vhost lane, then record the skip.

    Every early exit goes through here, so a scope or live-service change that leaves nothing eligible
    cannot leave a prior run's counters standing as current."""
    events.ledger("probe.ffuf_vhost",
                  consumed={"wordlist_submitted": 0, "wordlist_oos_excluded": excluded,
                            "wordlist_invalid": invalid})
    for m in ("base_services", "base_services_scanned", "state_persisted"):
        events.coverage_partial("probe.ffuf_vhost", kind=events.COVERAGE_TIMEOUT, measure=m, unit=m,
                                eligible=0, tested=0, omitted=0, reason=why)
    ctx.run.record("probe", skipped("ffuf-vhost", why))


def _vhost_effective_wordlist(ctx, wl, apex, scope):
    """Build the per-apex wordlist containing ONLY candidates we are allowed to CONTACT.

    ffuf sends every word as `Host: FUZZ.<apex>`, so the OOS exclusion happens here, in the wordlist,
    before the request — post-filtering cannot un-send it.

    Returns (path, digest, submitted_set, eligible_n, excluded_n, invalid_n). The digest binds this
    effective file into the work unit and ledger generation, so a scope change re-scans instead of
    resuming a narrower sweep."""
    words, excluded, invalid = [], 0, 0
    seen = set()
    for raw in wl.read_text(errors="replace").splitlines():
        w = raw.strip().lower().strip(".")
        if not w or w.startswith("#"):
            continue
        # canonicalized and validated here through the shared canonicalizer, so the submitted file holds
        # only names we will contact under the same IDNA2008/UTS-46 policy as scope
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
    """A usable vhost row — validated, not merely present.

    Requires a real integer HTTP status (`bool` excluded), a FUZZ value belonging to the wordlist we
    submitted, and a canonical in-scope final hostname."""
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
    """Ingest EVERY retained artifact for one BASE SERVICE x apex, then report coverage for the CURRENT
    one.

    History is PROVENANCE only, so a dirty old artifact cannot keep the coverage gap open forever;
    coverage is emitted after consumption, and candidate identities are counted uniquely per lifecycle
    so replay cannot inflate them."""
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
                # the identity is the BASE SERVICE that served it — it carries scheme and port, so
                # http://h:80 and https://h:443 stay distinct observations. `addrs` is CONTEXT only.
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
    """One ffuf vhost sweep for one BASE SERVICE x apex, under the contract."""
    # -mc = "served/exists" (2xx/3xx/401/403), not `all`; -ac drops the catch-all; no -r, so a redirecting
    # vhost matches on its 3xx. -maxtime: ffuf stops gracefully, exec_tool's timeout is the backstop.
    cmd = ["ffuf", "-w", f"{wl}:FUZZ", "-H", f"Host: FUZZ.{apex}",
           "-u", f"{base}/", "-ac", "-timeout", "7", "-noninteractive",
           "-t", str(settings.workers("ffuf", 40)), "-s",
           "-mc", mc,
           "-o", str(out), "-of", "json"]
    if ffuf_to:                                  # 0 = fully unbounded (RoE no-cut) -> no ceiling at all
        cmd += ["-maxtime", str(ffuf_to)]
    if prof.http_rl:
        cmd += ["-rate", str(prof.http_rl)]
    hard = ffuf_to + 60 if ffuf_to else 0        # backstop when bounded; stays unbounded when ffuf_to==0
    # the unit is base-service x apex — the base is what the scan connects through, so it is the
    # identity; match codes and the effective-wordlist digest ride along to force a re-run on change
    wu = events.work_unit("probe.ffuf_vhost", inputs={"base": base, "apex": apex},
                          config={"mc": mc, "wordlist": wl.name},
                          file_digests={"wordlist": wl_digest}, schema_version=_VHOST_SCHEMA)
    errf = out.with_suffix(".stderr.log")            # FULL stderr: the -maxtime marker must not be evictable
    r = run_contract("probe.ffuf_vhost", cmd,
        repository=ctx.run,
        stdout=RepositoryOutput.discard(),
        stderr=RepositoryOutput.publish(*errf.relative_to(ctx.run.dir).parts),
        native_outputs=(RepositoryNativeOutput.file(
            17, *out.relative_to(ctx.run.dir).parts,
        ),),
        work_unit=wu, timeout=hard,
        reclassify=lambda res, o=out, e=errf: reclassify_ffuf(res, o, e, ffuf_to or None),
    )   # graceful -maxtime; hard backstop
    return r


def _vhost_enum(ctx) -> None:
    """Virtual-host enumeration (ffuf `-H 'Host: FUZZ.<apex>'`) over every non-CDN active-allowed live
    BASE SERVICE. Active; needs ffuf + a vhost wordlist.

    The Host header is fuzzed against a real live host, not `http://<ip>/`: a bare-IP request fails SNI
    on HTTPS origins and folds to nothing against a uniform port-80 redirect. Membership is base
    services (what ffuf connects through); the address set only RANKS them, so one co-hosted
    representative is fuzzed first and the rest follow, never dropped. Base URL is chosen HTTPS-first +
    subdomain-first, the apex often being a separate static site.

    Hits are `vhost` review candidates — a 200 is not proof the name resolves or is owned. Only
    DNS-invisible hits are surfaced; a vhost that is already a known subdomain is dropped."""
    if not have("ffuf"):
        _vhost_unknown_lifecycle(ctx, "ffuf not installed — vhost coverage UNMEASURED")
        return
    wl = _vhost_wordlist()
    if wl is None:
        _vhost_unknown_lifecycle(ctx, "no vhost wordlist (~/.config/quarry/wordlists/vhost.txt) "
                                      "— vhost coverage UNMEASURED")
        return
    scope, prof = ctx.scope, ctx.profile
    # every non-CDN active-allowed base service is a unit; the score only ranks them, preferring HTTPS
    # and a subdomain host (the bare apex is often a separate static site, not the vhost-routing app)
    apexset = {a.lower() for a in prof.apex_domains}
    # membership is what we actually scan: base services (ffuf connects to a hostname and has no
    # address-pinning flag). The address set survives as a rank only, so nothing is excluded.
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
    # per-call ceiling scaled by wordlist size, since a flat 1800s cut a big-wordlist run. One effective
    # wordlist per apex, holding only names we may contact, digested into the resume identity.
    eff: dict = {}
    excluded_total = invalid_total = 0
    for apex in apexes:
        path, digest, submitted, n_ok, n_ex, n_bad = _vhost_effective_wordlist(ctx, wl, apex, scope)
        excluded_total += n_ex
        invalid_total += n_bad
                # an apex whose every candidate is OOS or malformed has nothing contactable;
                # building units for it just fails ffuf against an empty file, so skip it cleanly
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
    # not a coverage measure: COVERAGE_SAMPLE is an operator-chosen subset of eligible input, but an OOS
    # or malformed candidate was never eligible active input, so calling it "omitted" invents a shortfall
    events.ledger("probe.ffuf_vhost",
                  consumed={"wordlist_submitted": sum(e["n"] for e in eff.values()),
                            "wordlist_oos_excluded": excluded_total,
                            "wordlist_invalid": invalid_total})
    wl_n = max([e["n"] for e in eff.values()] or [0])
    ffuf_to = scaled_timeout(wl_n, ctx.http_timeout, per_unit=0.4)
    wl_digest = events.file_digest(wl)                       # provenance: the SOURCE list this run derived from
        # execution completion and artifact usability are separate counters
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
    # one unit = base-service x apex — the base carries scheme + host + port, exactly what ffuf connects
    # through, so it is the identity; the address set only ranks the order, never membership
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
                if not native_output_current(r, current) or not current.exists():
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
        # measure = base services, not "origins": that is what we actually scan
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
    """The shared httpx fingerprint command: no -probe-all-ips / -no-fallback multipliers, bounded
    -timeout/-retries, rich response-derived flags kept. Used by the bulk probe, every prefilter port-group,
    the direct fallback, and enrich.
    """
    cmd = ["httpx", "-l", str(hosts_file), "-json", "-silent",
           "-ports", ",".join(str(p) for p in ports),
           "-td", "-title", "-sc", "-cl", "-favicon", "-cdn", "-web-server",
           "-asn", "-location", "-ip", "-cname", "-irh",
           # -follow-host-redirects, not -follow-redirects: follow only same-host 30x. `-location`
           # still records the Location for cross-host redirects (intel without following).
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
    # this httpx group's work_unit = its exact host set + port set. The effective probe config folds in,
    # so a flag/rate change invalidates the unit, not just the host/port set.
    wu = events.work_unit(f"{phase}.httpx", inputs={"hosts": sorted(set(hosts)), "ports": sorted(ports)},
                          config={"flags": "v0.3.4-probe", "rl": ctx.profile.http_rl})
    r = run_contract(
        f"{phase}.httpx", cmd,
        repository=ctx.run,
        stdout=RepositoryOutput.publish(*hx.relative_to(ctx.run.dir).parts),
        stderr=RepositoryOutput.discard(), work_unit=wu, timeout=to,
    )
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
    r = exec_tool(
        "cdncheck", ["cdncheck", "-i", str(ipf), "-jsonl", "-silent", "-duc", "-o", str(out)],
        repository=ctx.run,
        stdout=RepositoryOutput.discard(),
        stderr=RepositoryOutput.discard(),
        native_outputs=(RepositoryNativeOutput.file(
            7, *out.relative_to(ctx.run.dir).parts, required=False,
        ),),
        timeout=scaled_timeout(len(ips), ctx.http_timeout, per_unit=0.02),
    )
    ctx.run.record("probe", r)
    if (r.status not in (Status.SUCCESS, Status.EMPTY)
            or not native_output_current(r, out) or not out.exists()):
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


# ── probe.shodan_host — the free per-IP passive record lane ──

# `/shodan/host/{ip}` costs no query credit, so this lane sits outside the credit coordinator. Entity
# choices are rules of engagement: docs/design/SHODAN-HOST-DESIGN.md.
_SHODAN_HOST_SID = "probe.shodan_host"


def _shodan_host_get(url: str, timeout: int):
    """One free GET -> `(raw_bytes, http_code, error)`. NEVER raises.

    The error carries `error_class` AND, for a 404, the response BODY — which is where the provider's
    measured "no information available" answer lives. Without the body a 404 is indistinguishable from a
    failure, and every address Shodan has never seen would report as a lane gap."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": SHODAN_UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            # the status travels with the body: the no-data contract is `404 + wording` and the
            # record contract `200 + shape`, so assuming 200 would store a 201 as the answer
            return r.read(), int(getattr(r, "status", 0) or getattr(r, "code", 0) or 0), None
    except Exception as e:                                   # noqa: BLE001 - classified, never swallowed
        capture_error_body(e, provider="shodan")             # keeps `body_bytes` for the 404 contract
        # the carrier holds `error_class` instead of assigning it onto the exception (which can raise), and
        # forwards everything a consumer reads — code, body_bytes, and headers (`Retry-After` for pacing)
        err = ShodanPageError(getattr(e, "error_class", None) or provider_error_class(e), e)
        err.code = getattr(e, "code", 0) or 0
        err.body_bytes = getattr(e, "body_bytes", b"") or b""
        err.headers = getattr(e, "headers", None)
        return b"", err.code, err


def _shodan_host_ingest(ctx, target, rec, art, wrote) -> None:
    """Write one address's passive record, reporting each entity as it is stored. The store keys a `port` on
    `ip:port`, so 53/tcp and 53/udp are one row: the observations for one port are merged, keeping all of
    them, so nothing depends on which banner arrived first.
    """
    ref = str(art)
    hosts = list(target.hosts)
    by_port: dict = {}
    for obs in rec.ports:
        by_port.setdefault(obs.port, []).append(obs)
    for port, group in sorted(by_port.items()):
        # LIST-valued provenance so a later active observation of the same ip:port coexists with this one
        # instead of overwriting it (or being dropped as a duplicate id).
        ctx.run.add("port", {"id": f"{rec.ip}:{port}", "ip": rec.ip, "port": port,
                             "observations": [{"transport": g.transport, "module": g.module,
                                               "tls": g.tls, "seen": g.seen or None} for g in group],
                             "transports": sorted({g.transport for g in group if g.transport}),
                             "modules": sorted({g.module for g in group if g.module}),
                             # ANY observation seeing TLS means TLS was seen; the LATEST sighting is the one
                             # worth reporting. Neither may depend on banner order.
                             "tls": any(g.tls for g in group),
                             "passive": True,
                             "observed_at": max((g.seen for g in group if g.seen), default=None),
                             "hosts": hosts, "sources": ["shodan-host"], "raw_ref": ref})
        # one row, but `len(group)` observations: `_fold` counts per (port, transport), so one write per row
        # would fabricate an omission on every host with both 53/tcp and 53/udp
        wrote(shodan_host.WROTE_PORT, len(group))
        wrote(shodan_host.WROTE_PORT_ROW)      # one ROW, however many observations it carries
    for name in rec.hostnames:
        # a hostname Shodan associates with this address. IN or OUT of scope it is REVIEW evidence: the
        # record does not prove current resolution, and `related-host` is consumed by nothing active.
        in_scope = ctx.scope.in_scope(name) and not ctx.scope.is_oos(name)
        ctx.run.add("review", {"id": f"shodan-host:{rec.ip}:{name}", "klass": "related-host",
                               "value": name,
                               "note": (f"Shodan associates {name} with {rec.ip}"
                                        + (" (IN SCOPE — verify DNS before treating as live)" if in_scope
                                           else " — VERIFY OWNERSHIP")),
                               "sources": ["shodan-host"], "raw_ref": ref})
        wrote(shodan_host.WROTE_HOSTNAME)
    for cve in rec.vulns:
        ctx.run.add("review", {"id": f"shodan-vuln:{rec.ip}:{cve}", "klass": "shodan-vuln", "value": cve,
                               "note": (f"{cve} inferred by Shodan from a banner on {rec.ip} — UNVERIFIED "
                                        f"version inference, not a confirmed finding"),
                               "sources": ["shodan-host"], "raw_ref": ref})
        wrote(shodan_host.WROTE_VULN)


def _shodan_host_class(o):
    """`(error_class, reason)` for a lane with failures — one pair, never a class from one event beside a
    sentence from another. Gaps dominate limits, so a real failure alongside a quota reports the failure;
    among classes of one kind the most frequent wins, ties broken by name.
    """
    if not o.fail_classes:
        return None, ""
    real = {c: n for c, n in o.fail_classes.items() if not is_provider_limit(c)}
    pool = real or dict(o.fail_classes)
    cls = max(pool.items(), key=lambda kv: (kv[1], kv[0]))[0]
    return cls, o.fail_reasons.get(cls, o.fail_reason)


def _shodan_host_terminal(ctx, o, bound) -> "ProviderResult | set":
    """The lane's terminal, from the outcome's own facts."""
    left = len(o.not_attempted)
    machinery = list(o.machinery)
    # the class the terminal speaks and the sentence it quotes must be one event, and gaps dominate
    # limits: picking the most frequent class would let two quota failures outrank one transport failure
    cls, gap = _shodan_host_class(o)
    if machinery:
        cls, gap = PROVIDER_ERROR, ""          # our own defect: no provider class describes it
    parts = [x for x in (("; ".join(machinery) if machinery else ""),
                         (f"{o.unconsumed} record(s) could not be ingested" if o.unconsumed else ""),
                         (f"{o.evidence_invalid} stored record(s) were unusable" if o.evidence_invalid
                          else ""),
                         ("host state was NOT persisted — records will be fetched again"
                          if not o.persisted else "")) if x]
        # a budget stop is an operator bound, not a defect: it belongs to the selection report below and
        # must not turn the terminal into a machinery gap
    if o.stop_cause and o.stop_cause != "budget_time":
        parts.append(f"stopped: {o.stop_cause}")
        # a record with parts we could not read is owned but a parse gap; `incomplete`/`unusable_parts`
        # are the fact
    if o.publish_failed or not o.records_journaled:
                # our own evidence loss: a body we could not keep is a gap that outranks a limit
        parts.append("evidence could not be retained")
        if cls is None or is_provider_limit(cls):
            cls, gap = PROVIDER_ERROR, ""
    if o.incomplete:
        parts.append(f"{o.incomplete} record(s) had {o.unusable_parts} unusable part(s)")
        if cls is None:
            cls, gap = PROVIDER_PARSE, ""
    counts = (f"{o.attempted}/{o.eligible} address(es) queried · {o.records} record(s) · {o.empty} with no "
              f"data · {o.replayed} replayed · {o.ports} port(s) · {o.hostnames} hostname(s)"
              + (f" · {o.vulns} unverified CVE lead(s)" if o.vulns else "")
              + (f" · {left} address(es) not reached" if left else ""))
    limit_classes = {c: n for c, n in o.fail_classes.items() if is_provider_limit(c)}
    gap_classes = {c: n for c, n in o.fail_classes.items() if not is_provider_limit(c)}
    meta = {"eligible": o.eligible, "attempted": o.attempted, "completed": o.owned + o.replayed,
            "failed": sum(o.fail_classes.values()) + o.publish_failed + o.unconsumed,
            "not_sent": left, "truncated_pages": 0,
            "records": o.records, "empty": o.empty, "replayed": o.replayed,
            "ports": o.ports, "ports_seen": o.ports_seen, "hostnames": o.hostnames,
            "hostnames_seen": o.hostnames_seen, "vulns": o.vulns, "vulns_seen": o.vulns_seen,
            "incomplete_records": o.incomplete, "unusable_parts": o.unusable_parts,
            "unconsumed": o.unconsumed, "evidence_invalid": o.evidence_invalid,
            "publish_failed": o.publish_failed, "persisted": o.persisted,
            "error_bodies": o.error_bodies, "progress_saved": o.progress_saved,
            "not_attempted": list(o.not_attempted), "machinery": machinery,
            "stop_cause": o.stop_cause or None, "requests": o.requests,
            "answered": o.answered, "owned": o.owned, "port_rows": o.port_rows,
            "port_observations": o.ports, "gap_classes": gap_classes,
            # `provider_limit` is structured, not hard-coded False: a free lane withholds no spend,
            # but the provider can refuse us, and a transport-then-quota run must keep the limit
            "limit_classes": limit_classes,
            "provider_limit": bool(limit_classes), "operator_limit": False}
        # selection and outcome are different facts: selection loss to a budget is a hard COVERAGE_CAP,
        # outcome loss the lost-in-flight bucket. One measure would let an all-failed run read "all answered".
    reached = o.eligible - left
    limit_stop = (o.stop_cause.startswith("provider_stop:")
                  and is_provider_limit(o.stop_cause.split(":", 1)[1]))
    if left and limit_stop:
                # a proven limit is a provider boundary, not the target or our machinery: filing it as a
                # timeout made a `complete_with_limits` run read as a gap
        events.coverage_partial(
            _SHODAN_HOST_SID, kind=events.COVERAGE_PROVIDER, measure="shodan_host_addresses",
            unit="shodan_host_addresses", eligible=o.eligible, tested=reached, omitted=left,
            reason=(f"{left}/{o.eligible} address(es) not queried — the provider refused "
                    f"({o.stop_cause.split(':', 1)[1]}); nothing to retry this run"))
    elif left and o.stop_cause != "budget_time":
        events.coverage_partial(
            _SHODAN_HOST_SID, kind=events.COVERAGE_TIMEOUT, measure="shodan_host_addresses",
            unit="shodan_host_addresses", eligible=o.eligible, tested=reached, omitted=left,
            reason=(f"{reached}/{o.eligible} address(es) reached; {left} not asked about — "
                    f"{o.stop_cause or 'unknown stop'}"
                    + ("" if o.persisted else " (state was NOT persisted, so this lane RESTARTS)")))
    else:
        # `durable` is whether the remainder can be picked up: this lane needs both evidence persisted and the
        # rotation recorded, or a bounded run restarts from the same prefix and "resumable" is a false promise
        budget.report_selection(_SHODAN_HOST_SID, measure="shodan_host_addresses", eligible=o.eligible,
                                attempted=reached, budget=bound, noun="address",
                                durable=o.persisted and o.progress_saved)
    # two measures, two units, two kinds: one measure could carry only one kind, so a run with both a
    # failure and a proven limit lost the limit. The reconciler keeps the latest per (source_id, unit).
    lost_gap = sum(gap_classes.values())
    lost_limit = sum(limit_classes.values())
    # `answered` is the only count of what came back: `attempted - lost_gap` would report a quota-only run
    # as "all attempted obtained" though the request was refused before any answer existed
    answer_attempted = max(0, o.attempted - lost_limit)
    budget.report_outcome(_SHODAN_HOST_SID, measure="shodan_host_answers",
                          attempted=answer_attempted, obtained=o.answered,
                          classes=gap_classes, noun="address")
    events.coverage_partial(
        _SHODAN_HOST_SID, kind=events.COVERAGE_PROVIDER, measure="shodan_host_refused",
        unit="shodan_host_refused", eligible=o.attempted, tested=o.attempted - lost_limit,
        omitted=lost_limit,
        reason=(f"{lost_limit} request(s) the provider refused {dict(sorted(limit_classes.items()))} — "
                f"nothing to retry this run" if lost_limit else "no request was refused"))
    budget.report_outcome(_SHODAN_HOST_SID, measure="shodan_host_consumed",
                          attempted=o.ports_seen, obtained=o.ports, noun="observed port")
    # `meta` is emitted via `events.ledger`, the honest home for record counts, carrying facts a consumer
    # would otherwise parse out of prose
    events.ledger(_SHODAN_HOST_SID, produced={"port": o.port_rows, "review": o.hostnames + o.vulns},
                  # consumed = what we got an answer for and kept; a refused request and an
                  # unpersisted answer are neither
                  consumed={"address": o.owned + o.replayed}, shodan_host=meta)
    # the parts we could not read are a coverage fact, emitted every run so a later sweep clears it.
    # Records and parts cannot share a denominator: the unit is records, and the part count is in the reason.
    events.coverage_partial(_SHODAN_HOST_SID, kind=events.COVERAGE_TIMEOUT,
                            measure="shodan_host_record_parts", unit="shodan_host_record_parts",
                            eligible=o.records, tested=o.records - o.incomplete, omitted=o.incomplete,
                            reason=(f"{o.incomplete}/{o.records} record(s) carried {o.unusable_parts} "
                                    f"part(s) we could not read" if o.incomplete else
                                    f"all {o.records} record(s) came back whole"))
    ctx.echo(f"  shodan-host: {counts}")
    # ROWS are what `produced` claims — one `ip:53` row holding TCP and UDP is one entity, not two.
    produced = {"port": o.port_rows, "review": o.hostnames + o.vulns}
    gap_why = "; ".join([x for x in (gap, "; ".join(parts)) if x])
    if gap_why:
        got = o.records + o.empty + o.replayed
        if not got:
            raise ShodanPageError(cls, RuntimeError(f"shodan-host: {gap_why}"))
        return ProviderResult(set(), partial=True, partial_kind="degraded", error_class=cls,
                              produced=produced, partial_reason=f"evidence KEPT; {gap_why}")
    if left:
        # a proven limit never reaches here: `provider_stop:<cls>` is set only after `_count_fail`,
        # so `gap_why` is non-empty and the branch above returns first. This branch is unreachable.
        return ProviderResult(set(), partial=True, partial_kind="degraded",
                              error_class=None, produced=produced,
                              partial_reason=f"{left} address(es) not reached — {o.stop_cause}")
        # a lane that stored ports and review rows is not empty: `produced` is what it wrote, and
        # `run_provider` reads status from that, not a hostname set this lane never fills
    return ProviderResult(set(), produced=produced)


def shodan_host_lane(ctx) -> None:
    """Run the free host lane, under its own provider bracket. Best-effort: never raises into the phase."""
    def body():
        key = secrets.shodan()
        if not key:
            raise ProviderSkip("no Shodan API key configured")
        targets = shodan_host.eligible_ips(ctx)
        if not targets:
            raise ProviderSkip("no observed in-scope address to look up")
        sbase = ctx.run.dir / "raw" / "probe"
        sbase.mkdir(parents=True, exist_ok=True)
        cfg_fp = events.work_unit(_SHODAN_HOST_SID, inputs={}, config={},
                                  schema_version=shodan_host.SHODAN_HOST_SCHEMA)
        budget.prune_state(sbase, _SHODAN_HOST_SID, cfg_fp)
        # run-scoped by construction: the endpoint is free and its records live, so a project-global
        # ledger would replay a stale snapshot forever rather than asking again for nothing
        ledger = budget.Ledger(budget.state_path(sbase, _SHODAN_HOST_SID, cfg_fp), lane=_SHODAN_HOST_SID)
        attempt_dir = fresh_artifact_dir(sbase / "shodan-host" / cfg_fp[:16])
        cooldown = _ProviderCooldown(key)      # the SAME account boundary as the paid pivot lanes
        timeout = min(getattr(ctx, "http_timeout", 20) or 20, 30)

        def fetch(ip):
            cooldown.wait()
            url = (f"https://api.shodan.io/shodan/host/{urllib.parse.quote(ip)}"
                   f"?key={urllib.parse.quote(str(key))}")
            raw, code, err = _shodan_host_get(url, timeout)
            if err is not None and getattr(err, "error_class", "") == PROVIDER_RATE_LIMIT:
                cooldown.note(err)             # the provider said slow down; every later request honors it
            return raw, code, err

        # `budget.budget_seconds`, not `settings.concurrency`: the latter clamps 0 to 1, right for a worker
        # pool but catastrophic for a wall-clock budget where 0 means unbounded
        bound = budget.Budget(budget.budget_seconds("SHODAN_HOST_BUDGET_S"))
        # evidence is run-scoped, scheduling progress project-level (a fresh run dir every run). The session
        # holds the progress lock across load/schedule/note/save, or both runs pick the same address.
        try:
            with shodan_host.sweep_session(shodan_host.progress_path(ctx.run.project_dir)) as progress:
                o = shodan_host.run_hosts(
                    targets,
                    fetch=fetch,
                    ingest=lambda t, rec, art, wrote: _shodan_host_ingest(ctx, t, rec, art, wrote),
                    ledger=ledger, attempt_dir=attempt_dir, bound=bound, progress=progress,
                    # a proven limit refuses every remaining address identically, so
                    # asking anyway fans out a known answer
                    should_stop=lambda cls: (cls in ("auth", "forbidden") or is_provider_limit(cls)
                                             or (cls == PROVIDER_RATE_LIMIT and cooldown.hits > 1)))
        except shodan_host.SweepBusy as e:
            # another run holds the sweep: a gap local to this run, not a skip — evidence is run-scoped,
            # so this run gets none of the holder's records and every eligible address is unattempted
            events.coverage_partial(
                _SHODAN_HOST_SID, kind=events.COVERAGE_TIMEOUT, measure="shodan_host_addresses",
                unit="shodan_host_addresses", eligible=len(targets), tested=0, omitted=len(targets),
                reason=(f"0/{len(targets)} address(es) queried — another run on this project holds the "
                        f"sweep ({e}); its evidence belongs to that run, not this one"))
            ctx.echo(f"  shodan-host: contended — {len(targets)} address(es) left to the run holding "
                     f"the sweep")
                        # a FAILED terminal folding to `complete_with_gaps`, not PARTIAL:
                        # this run produced and inherited nothing
            raise ShodanPageError(PROVIDER_ERROR,
                                  RuntimeError(f"shodan-host: {len(targets)} address(es) not queried — "
                                               f"another run holds this project's sweep ({e})"))
        return _shodan_host_terminal(ctx, o, bound)

    run_provider(_SHODAN_HOST_SID, body)


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
    """Shared smap file-output handling for probe and enrich. Parse -oJ, reclassify the run status from the
    port yield (clean+ports -> SUCCESS, clean+0 -> EMPTY, degraded stays degraded, unreadable -> hard/PARTIAL),
    attributing each record's ports to the submitted host, else the resolved ip->host map, else Shodan's
    hostnames. smap is passive and cannot prove per-target completion, so returned/eligible is a visibility
    note, never forced to PARTIAL. Returns the in-scope port count.
    """
    records, complete = (_smap_records(sm) if native_output_current(r, sm)
                         else (None, False))
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
    """SYN web-port prefilter (bbot-style, not the infra portscan). naabu SYN over each host's contactable IPs x
    prof.ports (never top-1000/CIDR/nmap) -> open ip:ports mapped back to hosts. Tri-state, for honest
    coverage:
    - dict of open host:ports  -> usable_with_ports (httpx on the open ports)
    - {} empty                 -> usable_empty: a clean scan with nothing open. The caller still
    direct-probes these (a clean SYN 0-open never drops a host).
    - None                     -> unusable: truncated/timeout/block/error -> full direct fallback.
    Only a clean completion is trusted. Stores web_port evidence and records the coverage state.
    """
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
    cmd = ["naabu", "-list", str(ips_file), "-p", ",".join(str(p) for p in prof.ports),
           "-json", "-scan-type", "s", "-Pn", "-silent", "-o", str(raw)]   # SYN, no host-disco, web ports only
    if prof.portscan_rate:
        cmd += ["-rate", str(prof.portscan_rate)]
    to = scaled_timeout(len(unique_ips) * len(prof.ports), ctx.http_timeout, per_unit=0.02)
    res = exec_tool(
        "naabu", cmd,
        repository=ctx.run,
        stdout=RepositoryOutput.discard(),
        stderr=RepositoryOutput.discard(),
        native_outputs=(RepositoryNativeOutput.file(
            11, *raw.relative_to(ctx.run.dir).parts, required=False,
        ),),
        timeout=to,
    )
    raw_status = res.status
    # naabu writes findings to the -o file. Parse fail-closed: any malformed row or out-of-profile
    # port makes the whole scan unusable (full fallback). A missing/empty file is not malformed.
    want_ips = set(unique_ips)
    want_ports = set(prof.ports)
    open_by_ip: dict[str, set] = {}
    parse_ok = True
    if native_output_current(res, raw) and raw.exists():
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
    # tri-state in RunResult.note: a non-hit routes hosts to direct httpx (a clean SYN 0-open never drops
    # a host); usable_empty is a clean note-only result; unusable is a degraded execution that flags an event
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
    """Fingerprint `hosts` -> list of (raw_ref, json_lines) per httpx call. SYN-prefilter -> httpx only on open
    host:ports (grouped by open-port set); hosts with no known IP go direct by hostname. Safety rails: a host
    whose current answer is a scan-box/metadata self-hit is withheld by netguard (private is scanned); on
    prefilter-off / naabu-missing / truncated / zero-open it falls back to direct httpx (never a thin run).
    Shared by probe and enrich.
    """
    prof = ctx.profile
    # self-attack guard: record every private/self-resolving host as internal-resolution intel, withhold
    # only the scan-box/metadata self-hits. The gate lives here, before any downstream active tool.
    hosts = netguard.guard_hosts(ctx, hosts, phase=phase)
    if not hosts:
        return []
    pubmap, a_known = _host_public_ip_map(ctx, hosts)                     # {host: contactable A IPs} (private incl. by default)
    prefilter_on = settings.web_port_prefilter()
    # CDN-aware SYN gate: raw SYN must not hit shared third-party edge, so classify offline (cdncheck) and
    # drop CDN/WAF IPs from the SYN set only. A host left with no SYN-eligible IP falls to httpx-by-name.
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
    # a host is SYN-eligible only when all its contactable IPs are non-shared: httpx probes by name, so
    # ports found on a non-CDN sibling IP would not match what httpx-by-name hits
    syn_map = {h: ([] if any(ip in shared for ip in ips) else ips) for h, ips in pubmap.items()}
    public_hosts = [h for h in hosts if syn_map[h]]                      # ALL contactable IPs non-shared -> SYN-eligible
    no_ip = [h for h in hosts if not syn_map[h]]                         # any shared IP / no IP -> httpx by name

    def _direct(targets):
        return [_run_httpx(ctx, targets, prof.ports, phase, "httpx")] if targets else []

    if not prefilter_on:
        return _direct(public_hosts + no_ip)                             # direct (contactable incl. private)
    host_ports = _web_port_prefilter(ctx, public_hosts, phase, syn_map) if public_hosts else None
    if host_ports is None:
        return _direct(public_hosts + no_ip)                             # fallback: full direct over every guarded host
    results = []
    groups: dict[tuple, list] = {}
    for h, ps in host_ports.items():
        groups.setdefault(tuple(ps), []).append(h)
    for i, (ps, hs) in enumerate(sorted(groups.items())):
        results.append(_run_httpx(ctx, hs, list(ps), phase, f"httpx-g{i}"))   # httpx on OPEN ports only
    # a SYN-eligible host with zero open ports is not dropped: SYN can false-negative, so probe it directly.
    # A host's outcome must depend only on its own evidence.
    covered = set(host_ports)
    direct_targets = no_ip + [h for h in public_hosts if h not in covered]
    if direct_targets:
        results.append(_run_httpx(ctx, direct_targets, prof.ports, phase, "httpx-direct"))
    return results


def run(ctx) -> None:
    prof, scope = ctx.profile, ctx.scope
    # the free Shodan host lane sends no packet to the target, so the early returns below cannot end the
    # phase: it runs on whatever addresses the run observed, last on the active path
    if scope.passive_only:
        ctx.run.record("probe", skipped("httpx", "passive-only mode"))
        shodan_host_lane(ctx)                   # passive by construction: no packets to the target
        return

    hosts = ctx.run.values("resolved") or ctx.run.values("subdomain")
    hosts = scope.filter_hosts(hosts, active=True)
    if not hosts:
        ctx.run.record("probe", skipped("httpx", "no in-scope hosts to probe"))
        ctx.run.notes.append("probe: no hosts (run vertical first)")
        shodan_host_lane(ctx)                   # resolved addresses may exist even with nothing probeable
        return

    # ── httpx full fingerprint -> live services (SYN-prefilter -> httpx on open ports only) ──
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

        # httpx -irh carries the CSP; in-scope hosts named there are a discovery channel. Parsed over live
        # hosts because the CSP lives on a probed host (www), not the bare apex.
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

    # ── tlsx over in-scope hosts — cert SAN harvest + cert context ──

    # runs over the resolved host set: cert SANs reveal sibling hostnames, and the cert is stored as
    # first-class context (the `certificate` entity)
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
                                   "-json", "-silent"],
                             repository=ctx.run,
                             stdout=RepositoryOutput.publish(*tr.relative_to(ctx.run.dir).parts),
                             stderr=RepositoryOutput.discard(),
                             work_unit=tls_wu, timeout=ctx.http_timeout)
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
    _shodan_pivots(ctx)          # all Shodan lanes, one collection, one credit budget

    # ── virtual-host enumeration (ffuf Host-header fuzz over base services; needs a vhost wordlist) ──
    _vhost_enum(ctx)

    # ── WAF fingerprint (nuclei waf-detect templates over live hosts) ──

    # recon-side only: identify which WAF fronts each host. Bypass tooling stays human/Burp work.
    if have("nuclei") and ctx.run.count("live"):
        waf_in = ctx.write_list("waf_targets.txt", ctx.run.values("live"))
        waf_out = ctx.run.raw_path("probe", "nuclei", "waf.jsonl")
        waf_cmd = ["nuclei", "-l", str(waf_in), "-tags", "waf", "-jsonl", "-o", str(waf_out)]
        if prof.http_rl:                       # else native default (empty = fast)
            waf_cmd += ["-rl", str(prof.http_rl)]
        r = exec_tool("nuclei", waf_cmd,
                      repository=ctx.run,
                      stdout=RepositoryOutput.discard(),
                      stderr=RepositoryOutput.discard(),
                      native_outputs=(RepositoryNativeOutput.file(
                          7, *waf_out.relative_to(ctx.run.dir).parts, required=False,
                      ),),
                      timeout=nuclei_timeout(ctx.run.count("live"), ctx.http_timeout))
        ctx.run.record("probe", r)
        if native_output_current(r, waf_out) and waf_out.exists():
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
        shot_dir = ctx.run.raw_path(
            "probe", "gowitness", f"attempt-{os.urandom(16).hex()}",
        )
        # gowitness writes to files, so the runner mislabels it BLOCKED on a stderr WAF line; reclassify from
        # shots in this attempt's fresh dir, inside the contract so the terminal event has the final status
        def _gw_reclassify(res):
            shots = (len(list(shot_dir.glob("*.jpeg"))) + len(list(shot_dir.glob("*.png")))
                     if native_output_current(res, shot_dir) else 0)
            return reclassify_from_files(res, shots, "screenshot")
        # C10b resume: work_unit = the live-host set being screenshotted. A changed live set is a new unit.
        gw_wu = events.work_unit("probe.gowitness", inputs={"live": sorted(ctx.run.values("live"))})
        r = run_contract("probe.gowitness",
                ["gowitness", "scan", "file", "-f", str(live_file),
                 "--screenshot-path", str(shot_dir), "--write-jsonl",
                 "--write-jsonl-file", str(shot_dir / "gowitness.jsonl")],
                repository=ctx.run,
                stdout=RepositoryOutput.discard(),
                stderr=RepositoryOutput.discard(),
                native_outputs=(RepositoryNativeOutput.tree(
                    ((6, ()), (9, ("gowitness.jsonl",))),
                    *shot_dir.relative_to(ctx.run.dir).parts,
                ),),
                work_unit=gw_wu, reclassify=_gw_reclassify, timeout=ctx.http_timeout)
        ctx.run.record("probe", r)
        if native_output_current(r, shot_dir):
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
        r = exec_tool(
            "naabu", cmd,
            repository=ctx.run,
            stdout=RepositoryOutput.publish(*pr.relative_to(ctx.run.dir).parts),
            stderr=RepositoryOutput.discard(), timeout=naabu_to,
        )
        ctx.run.record("probe", r)
        open_ports = {}
        if r.raw_path:
            for line in r.raw_path.read_text().splitlines():
                line = line.strip()
                if ":" in line:
                    ip, _, port = line.rpartition(":")
                    open_ports.setdefault(ip, set()).add(port)
                # nmap -sV only on the ports naabu found open, grouped by exact open-port set (one call per
                # group). -oX so the service yield is parsed; nmap ingests first, so its richer entity wins.
        if open_ports and have("nmap"):
            groups: dict[tuple, list] = {}
            for ip, ports in open_ports.items():
                groups.setdefault(tuple(sorted(ports, key=int)), []).append(ip)
            for gi, (ptup, ips) in enumerate(sorted(groups.items())):
                g_ips = ctx.write_list(f"nmap_ips_{gi}.txt", sorted(ips))
                nm = ctx.run.raw_path("probe", "nmap", f"service_{gi}.xml")
                # reclassify (status-only) inside the contract so the terminal event has the final
                # nmap status; re-read below for ingest. work_unit = this port-group's ports + its IP set.
                def _nmap_reclassify(res, xml=nm):
                    svcs, complete = (_nmap_services(xml) if native_output_current(res, xml)
                                      else (None, False))
                    reclassify_from_artifact(res, None if svcs is None else len(svcs), label="nmap")
                    if svcs is not None and not complete and res.status in (Status.SUCCESS, Status.EMPTY):
                        res.status = Status.PARTIAL          # malformed rows / no clean finish -> uncertain (valid kept)
                    return res
                                # fold the nmap scan config, so a flag change flips the unit
                wu = events.work_unit("probe.nmap_service", inputs={"ports": list(ptup), "ips": sorted(ips)},
                                      config={"flags": "sV-Pn-T4"})
                nr = run_contract("probe.nmap_service",
                                  ["nmap", "-sV", "-Pn", "-T4", "-iL", str(g_ips),
                                   "-p", ",".join(ptup), "-oX", str(nm)],
                                  repository=ctx.run,
                                  stdout=RepositoryOutput.discard(),
                                  stderr=RepositoryOutput.discard(),
                                  native_outputs=(RepositoryNativeOutput.file(
                                      9, *nm.relative_to(ctx.run.dir).parts,
                                  ),),
                                  work_unit=wu, reclassify=_nmap_reclassify,
                                  timeout=scaled_timeout(len(ips) * len(ptup), ctx.http_timeout, per_unit=30))
                ctx.run.record("probe", nr)
                svcs, _ = (_nmap_services(nm) if native_output_current(nr, nm)
                           else (None, False))                # re-read authenticated current output
                for sip, sport, proto, service, product, version in (svcs or []):
                    # naabu OBSERVED the open port (triggering nmap); nmap ENRICHED it — carry both sources.
                    ctx.run.add("port", {"id": f"{sip}:{sport}", "ip": sip, "port": sport, "proto": proto,
                                         "service": service, "product": product, "version": version,
                                         "sources": ["naabu", "nmap"], "raw_ref": str(nm)})
        # naabu bare ports — fills any ip:port nmap did not enrich. The rows are structured here (ip, port),
        # not just an `"ip:port"` id; `shodan_host.eligible_ips` keeps an id fallback for older rows.
        for ip, ports in open_ports.items():
            for port in ports:
                ctx.run.add("port", {"id": f"{ip}:{port}", "ip": ip, "port": port,
                                     "sources": ["naabu"]})
    elif prof.portscan:
        ctx.run.record("probe", skipped("naabu", "no in-scope CIDR — port scan skipped"))

    # ── smap: passive (Shodan-backed) port scan, no packets to target (optional) ──
    if have("smap") and ctx.run.count("live"):
        sm_targets = [normalize.host_of_url(u) for u in ctx.run.values("live")]
        sm_in = ctx.write_list("smap_targets.txt", sm_targets)
        sm = ctx.run.raw_path("probe", "smap", "smap.json")
        # -oJ structured output (verified schema) instead of scraping nmap-text; parse + reclassify + ingest
        # via the shared helper (raw-only recording dropped the passive port yield)
        r = exec_tool(
            "smap", ["smap", "-iL", str(sm_in), "-oJ", str(sm)],
            repository=ctx.run,
            stdout=RepositoryOutput.discard(),
            stderr=RepositoryOutput.discard(),
            native_outputs=(RepositoryNativeOutput.file(
                4, *sm.relative_to(ctx.run.dir).parts, required=False,
            ),),
            timeout=600,
        )
        smn = _smap_ingest(ctx, r, sm, "probe", sm_targets)
        if smn:
            ctx.echo(f"  smap: +{smn} passive port(s) (Shodan-backed, no packets to target)")

    # ── the free per-IP Shodan record lane — last, so it sees every address this phase observed ──

    # placed here, not beside the other Shodan lanes: it consumes the `port`/`web_port` rows naabu and
    # smap write above, and running earlier would give it only the resolved set on the first lifecycle
    shodan_host_lane(ctx)
