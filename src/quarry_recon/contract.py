"""run_contract() — the enforced-contract wrapper over runner.run (v0.3 stabilization, step 2).

THIN by design. It:
  1. reads the source's contract from the registry (``sources.get``),
  2. emits structured events (``events``) around the call, and
  3. delegates execution UNCHANGED to ``runner.run``, returning its RunResult untouched.

It does NOT rewrite runner behavior, and no phase imports it yet — additive, zero behavior change,
same safety posture as step 1's declarative registry. The danger-tool conversion (step 4) is where
call sites move onto it, one bounded source at a time.

Produced/consumed counts are NOT emitted here: the parser/store runs later inside the phase, so the
honest place to report real counts is a ``events.ledger(source_id, produced=…, consumed=…)`` call the
phase makes AFTER it parses. We never guess counts from stdout. See [[quarry-bbot-control-surface]].
"""
from __future__ import annotations

import json as _json
import re as _re
import socket as _socket
import urllib.error as _urlerr

from . import events, normalize, sources
from .runner import Status, run as _run, skipped

# Non-clean terminal statuses that warrant a dedicated event before the normal tool_finish.
_PARTIAL = (Status.PARTIAL, Status.TIMED_OUT)


def _exact_counts(produced) -> dict:
    """`produced` as a validated `{entity: count}` map. Raises on anything that could lie about a count —
    constructing an impossible outcome is a defect, not something to normalise away."""
    if not isinstance(produced, dict):
        raise ValueError(f"produced must be a dict of counts, got {type(produced).__name__}")
    out: dict = {}
    for key, value in produced.items():
        if not isinstance(key, str) or not key:
            raise ValueError(f"produced key must be a non-empty entity name, got {key!r}")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"produced[{key!r}] must be an exact non-negative int, got {value!r}")
        out[key] = value
    return out


class ProviderResult(set):
    """A provider's hostname set that can also carry PAGINATION COMPLETION metadata (C06). A plain set means
    'complete'; `partial=True` means the page cap was hit with a live continuation cursor, so collection was
    TRUNCATED — run_provider then records PARTIAL (not SUCCESS) and a structured coverage_partial, so a
    consumer can tell complete collection from a bounded/truncated one and resume from `cursor`."""
    def __init__(self, iterable=(), *, partial=False, cursor=None, pages=None, error_class=None,
                 partial_kind=None, partial_reason=None, limited=False, produced=None):
        super().__init__(iterable)
        # review-B1.7r9#3: this type assumed every provider produces HOSTNAMES, so a lane whose evidence is
        # ports and review rows had only two ways to report a productive run — fabricate a hostname count,
        # or return an empty set and be recorded as a clean EMPTY after storing real evidence. `produced` is
        # the entity counts the lane ACTUALLY wrote, e.g. {"port": 3, "review": 2}; absent (None) keeps the
        # hostname-set behaviour every other provider relies on.
        # review-B1.7r10#4: `dict(produced) if produced else None` accepted `{"port": True, "review": -2}`
        # — a status sum of -1, which is TRUTHY and therefore reported SUCCESS — and turned an explicit `{}`
        # back into None, resurrecting the fabricated `{"host": 0}` fallback for a lane that genuinely
        # produced nothing. A count is an exact non-negative int; a key is a name.
        self.produced = None if produced is None else _exact_counts(produced)
        # review-B1.4r5#1: `limited` without `partial` was a silent SUCCESS/EMPTY — a bounded outcome
        # reported as a complete one. A limit IS incompleteness, so it implies partial rather than
        # depending on the caller to say both. And it is never PAGINATION truncation, so an unstated
        # kind resolves to "degraded" instead of inheriting a default that fabricates a cursor reason.
        self.partial = partial or limited
        self.cursor = cursor
        self.pages = pages
        self.error_class = error_class      # set when a LATER page failed (earlier pages preserved as PARTIAL)
        # review-r4#2: a partial result is EITHER "pagination" (cap/cursor truncation — emits a pagination
        # coverage gap) OR "degraded" (a generic partial, e.g. some Shodan pivots failed — NOT pagination, so
        # run_provider must not fabricate a "TRUNCATED at None pages" reason or a pagination coverage unit).
        self.partial_kind = partial_kind or ("degraded" if limited else "pagination")
        self.partial_reason = partial_reason
        # review-B1.4r4#3: an OPERATOR boundary (a credit reserve, a withheld budget) is a LIMIT that no
        # provider error class describes. Without this it could only be expressed by borrowing `quota` —
        # blaming the provider for our own policy — or by falling through to PARTIAL, which asserts a
        # DEGRADED execution when nothing went wrong. `limited` says the outcome was bounded on purpose.
        self.limited = limited


# ── shared PROVIDER OUTCOME taxonomy (B0) ────────────────────────────────────────────────────────────
# ONE taxonomy for every external provider, whether it runs in the events pipeline (vertical/probe) or in
# the standalone OSINT session (whoxy). Each class implies a DIFFERENT operator action, so collapsing any
# two of them destroys the only information the label carries:
#
#   auth         bad/missing credential          -> the operator fixes a key
#   forbidden    the server said no, reason UNKNOWN -> a plain failure until something proves otherwise
#   entitlement  the PLAN cannot, per provider EVIDENCE -> an external LIMIT
#   rate_limit   too fast RIGHT NOW               -> back off and retry; the quota is untouched
#   quota        the account's CREDITS are spent  -> an external LIMIT, not a failure; nothing to retry
#   transport / server / parse / error            -> ordinary failures
#
# review-B0#1: a bare 403 is NOT entitlement. A WAF, an IP allow-list, a permission error and a malformed
# request all return 403, and calling any of them an expected LIMIT would let a real defect pass the run
# as "the plan is just too small". 403 maps to `forbidden`; only provider EVIDENCE promotes it.
#
# QUOTA IS NEVER INFERRED FROM AN HTTP STATUS. It is proven from the provider's own response body or its
# balance endpoint. Measured 2026-07-27: Whoxy reports exhaustion as `{"status":0,"status_reason":"Zero
# Account Balance"}` inside an HTTP **200** — no status code could ever have revealed it.
PROVIDER_AUTH = "auth"
PROVIDER_FORBIDDEN = "forbidden"
PROVIDER_ENTITLEMENT = "entitlement"
PROVIDER_RATE_LIMIT = "rate_limit"
PROVIDER_QUOTA = "quota"
PROVIDER_TRANSPORT = "transport"
PROVIDER_SERVER = "server"
PROVIDER_PARSE = "parse"
#: OUR ceiling, not the provider's answer. A response we refused to read past is not malformed — measured
#: 2026-08-05: a 4 MiB read cap truncated two Shodan pages mid-string and the run reported
#: `JSONDecodeError` twice, i.e. Quarry called its own limit a provider defect and billed 2 credits for
#: the privilege. The distinction is the whole point of this taxonomy: `parse` sends you reading the
#: provider's schema, `oversize` sends you to our own constant.
PROVIDER_OVERSIZE = "oversize"
PROVIDER_HTTP = "http"
PROVIDER_ERROR = "error"

#: classes that are an EXTERNAL LIMIT rather than a defect — coverage is incomplete, but nothing failed
#: and nothing is retryable within the run. These feed `complete_with_limits`, never `complete_with_gaps`.
PROVIDER_LIMITS = frozenset({PROVIDER_QUOTA, PROVIDER_ENTITLEMENT})
#: every class this taxonomy defines. A consumer validating an error class checks membership here rather
#: than accepting any non-empty string — "quota " or "Quota" would compare unequal everywhere it matters.
PROVIDER_CLASSES = frozenset({PROVIDER_AUTH, PROVIDER_FORBIDDEN, PROVIDER_ENTITLEMENT,
                              PROVIDER_RATE_LIMIT, PROVIDER_QUOTA, PROVIDER_TRANSPORT, PROVIDER_SERVER,
                              PROVIDER_PARSE, PROVIDER_OVERSIZE, PROVIDER_HTTP, PROVIDER_ERROR})


def is_provider_limit(error_class) -> bool:
    """True when the class is an external provider LIMIT (quota/entitlement) rather than a failure."""
    return error_class in PROVIDER_LIMITS


_ERROR_BODY_LIMIT = 8192                                     # an error body is a sentence, not a payload


def capture_error_body(exc, *, provider: str = "", limit: int = _ERROR_BODY_LIMIT):
    """Read an HTTPError's body ONCE, AT THE RAISE SITE, and stamp the refined class onto the exception.

    It has to happen here: an HTTPError is a live file wrapper over the socket, so by the time the
    exception has propagated out of the requesting function the body may be unreadable or gone. Capturing
    late would silently degrade every quota into whatever the status code alone implies.

    Bounded and best-effort — a body we cannot read simply yields no extra signal, never an error."""
    if not isinstance(exc, _urlerr.HTTPError):
        return exc
    if getattr(exc, "body_text", None) is None:
        try:
            raw = exc.read(limit)
        except Exception:
            raw = b""
        # review-B1.6b14#5: `body_text` is a lossy decode — invalid UTF-8 becomes replacement characters,
        # so re-encoding it does not give back what the provider sent. A caller persisting failure
        # EVIDENCE needs the bytes, not our reading of them.
        try:
            exc.body_bytes = raw
        except Exception:
            pass
        finally:
            # review-B1.1#3: an HTTPError holds a LIVE response stream. Reading it without closing leaks
            # the connection, and a lane that fails repeatedly (auth or quota on every pivot) leaks once
            # per failure. body_text, status, headers and the stamped class all survive the close.
            try:
                exc.close()
            except Exception:
                pass
        # review-B1.7r8#4: both stamps are BEST-EFFORT, like the read above. An exception with `__slots__`
        # or an overridden `__setattr__` rejects them, and this function's contract is that a body we
        # cannot use yields no extra signal — never an error out of a raise-site helper.
        try:
            exc.body_text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else ""
        except Exception:
            pass
    if provider and getattr(exc, "error_class", None) is None:
        try:
            exc.error_class = classify_provider_http(exc, provider=provider)
        except Exception:
            pass
    return exc


_DETAIL_CHARS = 160                                          # a terminal reason is a line, not a document


def error_detail(exc) -> "str | None":
    """A SHORT, redacted summary of what the provider actually said, for the operator-visible reason.

    `error_body_reason` covers JSON error bodies and returns None for anything else, which is most of a
    refusal's interesting cases. Measured 2026-08-05: Shodan's paid search endpoint answered our
    `Mozilla/5.0` User-Agent with Cloudflare's HTML interstitial, and the terminal read
    `HTTPError: HTTP Error 403: Forbidden` — the status code alone, while the body on the exception said
    "Just a moment..." and would have named the cause immediately. A captured body nobody surfaces is a
    body nobody has.

    HTML is summarised by its <title>, because that is where an interstitial states its business.
    Redacted through the same sink as every other prose channel: an error body can echo a request that
    carried our key."""
    from . import secrets
    reason = error_body_reason(exc)
    text = getattr(exc, "body_text", None)
    if reason is None and isinstance(text, str) and text.strip():
        title = _re.search(r"<title[^>]*>(.*?)</title>", text, _re.I | _re.S)
        stripped = _re.sub(r"<[^>]+>", " ", title.group(1) if title else text)
        reason = _re.sub(r"\s+", " ", stripped).strip() or None
    if not reason:
        return None
    reason = secrets.redact(reason) or ""
    return (reason[:_DETAIL_CHARS] + "…") if len(reason) > _DETAIL_CHARS else reason


class ResponseTooLarge(ValueError):
    """A response longer than the caller's read bound. Its class is OURS, never the provider's."""

    error_class = PROVIDER_OVERSIZE


def read_bounded(r, limit: int, *, provider: str = "", bound: str = "") -> bytes:
    """Read a response and KNOW whether it was complete.

    Reading exactly `limit` bytes cannot distinguish a response that just fits from one that was cut, so
    this reads one byte past and treats that as the signal. MEASURED 2026-08-05 on the Shodan pivot lane:
    a bare `r.read(4 MiB)` truncated a page mid-string, the fragment went to `json.loads`, and the run
    reported `JSONDecodeError` — our own ceiling, billed to the provider's reputation and to two credits.
    Every provider read shares this helper so the next one cannot repeat it.

    The bytes actually read travel on the exception: a request that hit our ceiling still happened, and
    the caller can only preserve what it is handed.

    `bound` names the CONSTANT that stopped us. An operator reading "our read cap" still has to go
    looking; the whole value of separating `oversize` from `parse` is that it points at a specific line
    of ours, so the message carries the name."""
    raw = r.read(limit + 1)
    if len(raw) > limit:
        size = (f"{limit // (1024 * 1024)} MiB" if limit >= 1024 * 1024 else
                f"{limit // 1024} KiB" if limit >= 1024 else f"{limit} bytes")
        e = ResponseTooLarge(
            f"{provider + ': ' if provider else ''}response exceeds our {size} read cap"
            f"{f' ({bound})' if bound else ''} — the body was NOT parsed and nothing was dropped "
            f"silently")
        try:
            e.body_bytes = bytes(raw)
        except Exception:
            pass
        raise e
    return raw


def error_body_reason(exc) -> "str | None":
    """The provider's own reason string from a JSON error body, or None when the body is not that shape.

    A non-JSON body (Shodan answers auth failures with an HTML page) is NOT a parse failure — it simply
    carries no signal, and the caller falls back to the status code. Turning it into `parse` would report
    a plain bad key as schema drift."""
    text = getattr(exc, "body_text", None)
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        doc = _json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(doc, dict):
        return None
    err = doc.get("error")
    return err.strip() if isinstance(err, str) and err.strip() else None


def classify_provider_http(exc, *, provider: str) -> str:
    """Classify an HTTP error, letting the provider's own BODY refine the status code.

    MEASURED (Shodan, 2026-07-28): 401 + HTML = a bad key; 401 + `{"error": "Insufficient query credits,
    ..."}` = spent credits. The code is identical, so a status-only taxonomy would send the operator to
    re-key a credential that was never wrong while reporting a failure where the truth is a LIMIT.

    An UNRECOGNISED reason falls back to the status class (401 -> auth), never to a limit: an unknown
    failure must stay visible, and inventing `quota` would let a real defect pass as an expected boundary."""
    cls = classify_provider_error(exc)
    reason = error_body_reason(exc)
    if reason is None:
        return cls
    refined = classify_provider_reason(provider, reason)
    return refined if refined != PROVIDER_ERROR else cls


def provider_error_class(exc) -> str:
    """THE accessor for a provider error's class: one PROVEN at the raise site wins over the generic
    exception-type mapping, which cannot see a body."""
    return getattr(exc, "error_class", None) or classify_provider_error(exc)


def classify_provider_error(exc) -> str:
    """C06: map an in-process provider exception to an EXPLICIT class so a consumer can tell a real failure
    from 'nothing found' and pick the right response (auth → fix the key, entitlement → the plan is the
    limit, rate_limit → back off, transport → retry). A coarse, HTTP-aware taxonomy over stdlib urllib —
    never a guess, only a mapping of the raised type.

    B0 (review r1): 401 and 403 were both `auth`, and 429 was `quota`. Both were wrong — but so was the
    first fix. A 403 is only ever `forbidden` here: entitlement is a claim about the PLAN, and a status
    code cannot distinguish it from a WAF, an IP restriction or a malformed request (review-B0#1).
    Neither `quota` nor `entitlement` may EVER be returned from this function: both are LIMITS, and a
    limit must be proven from the provider's body or balance endpoint, never inferred from a code."""
    if isinstance(exc, _urlerr.HTTPError):
        code = getattr(exc, "code", None)
        if code == 401:
            return PROVIDER_AUTH                             # bad/missing key — do not retry
        if code == 403:
            return PROVIDER_FORBIDDEN                        # reason unknown — NOT assumed to be the plan
        if code == 429:
            return PROVIDER_RATE_LIMIT                       # too fast now — back off; credits untouched
        if code is not None and 500 <= code < 600:
            return PROVIDER_SERVER                           # upstream 5xx — transient, retryable
        return PROVIDER_HTTP                                 # other 4xx
    if isinstance(exc, (_urlerr.URLError, _socket.timeout, TimeoutError, ConnectionError, OSError)):
        return PROVIDER_TRANSPORT                            # DNS/connect/timeout — retryable
    if isinstance(exc, (_json.JSONDecodeError, ValueError)):
        return PROVIDER_PARSE                                # malformed/schema-drift body
    return PROVIDER_ERROR                                    # unclassified


class ProviderBodyError(Exception):
    """A provider reported failure INSIDE a successful HTTP response.

    The whole point of the class: an HTTP-status-only taxonomy cannot see these. Whoxy answers 200 with
    `{"status":0,"status_reason":"Zero Account Balance"}`; parsing straight past that envelope turned a
    spent account into a clean `0 domains` result — a false EMPTY, which is worse than an error because
    nothing looks wrong. Carries the class AND the provider's verbatim reason (never paraphrased: an
    unrecognised reason must reach the operator intact)."""

    def __init__(self, error_class: str, reason: str, provider: str = ""):
        super().__init__(f"{provider or 'provider'}: {reason}" if reason else (provider or "provider error"))
        self.error_class = error_class
        self.reason = reason
        self.provider = provider


#: Body-reason substrings that PROVE an exhausted-credit condition, per provider. Matching is deliberately
#: NARROW and allow-list only: an unrecognised failure reason stays a generic error, because calling an
#: unknown failure a "limit" would let a real defect read as an expected boundary and quietly pass the run.
#: (Fail-closed in the direction that keeps problems visible.)
#: review-B0#7: EXACT (normalised) match, not substring. "Non-zero Account Balance" contains the measured
#: string and would have been classified as exhausted — a substring test cannot distinguish a message from
#: its own negation. Normalisation is case + whitespace only; add variants when they are MEASURED.
_QUOTA_REASONS = {
    "whoxy": frozenset({"zero account balance"}),            # MEASURED 2026-07-27, inside an HTTP 200
    # MEASURED 2026-07-28 by depleting a real account: Shodan answers a spent balance with HTTP **401** and
    # a JSON body. The status code is the SAME one it returns for a bad key (with an HTML body), so 401
    # alone cannot tell auth from quota — see classify_provider_http.
    "shodan": frozenset({"insufficient query credits, please upgrade your api plan or wait for the "
                         "monthly limit to reset"}),
}


#: a provider's own words for "I HAVE NO DATA", which is not a failure. Same discipline as
#: `_QUOTA_REASONS`: EXACT normalised match, never substring, because a message cannot be distinguished
#: from its own negation by containment. Add variants only when they are MEASURED.
_EMPTY_REASONS = {
    # MEASURED 2026-07-30 at a ZERO query-credit balance: `/shodan/host/{ip}` answers an IP it has never
    # seen with HTTP **404** and this body, and answers a known IP with 200 and a full record. Without
    # this rule a 404 classifies as `http` (see `classify_provider_http`) and "not in Shodan" — the
    # ordinary case for most eligible addresses — would report as a lane failure on nearly every IP.
    "shodan": frozenset({"no information available for that ip."}),
}


def _norm_reason(reason: str) -> str:
    return " ".join((reason or "").split()).strip().lower()


def is_measured_empty(provider: str, reason: str) -> bool:
    """True when the provider SAID it has no data, in words we have measured.

    A provider that answers "nothing here" is reporting COVERAGE, not failing: the lane asked, got a
    definitive answer, and there is nothing to retry. Anything else about the same status code stays a
    failure — an unmeasured 404 body is a 404 we do not understand."""
    return _norm_reason(reason) in _EMPTY_REASONS.get(provider, frozenset())


def classify_provider_reason(provider: str, reason: str) -> str:
    """Map a provider's own failure reason to a taxonomy class. Only the MEASURED exhaustion strings become
    PROVIDER_QUOTA; everything else is PROVIDER_ERROR with the reason preserved verbatim by the caller."""
    if _norm_reason(reason) in _QUOTA_REASONS.get(provider, frozenset()):
        return PROVIDER_QUOTA
    return PROVIDER_ERROR


def whoxy_envelope(doc, *, provider: str = "whoxy"):
    """Validate Whoxy's status envelope, raising ProviderBodyError on a reported failure.

    MEASURED (HTTP 200 in every case):
        success   {"status": 1, ...}
        exhausted {"status": 0, "status_reason": "Zero Account Balance"}
        balance   {"status": 1, "live_whois_balance": 0, "whois_history_balance": 0,
                   "reverse_whois_balance": 0}

    `status` is the authority, not the presence of a results key: a failure body simply has no results
    key, which is exactly how an exhausted account previously read as "0 domains found".

    review-B0#5: the SUCCESS side must be validated too, or the fix is only half a fix. `status == 1`
    accepted `True` and `1.0` (in Python `True == 1`), and a bodiless `{"status": 1}` sailed through as a
    clean success — so a drifted or truncated response still produced a confident empty result. A success
    envelope must be an exact int 1 AND carry the documented result shape."""
    if not isinstance(doc, dict):
        raise ProviderBodyError(PROVIDER_PARSE, "response was not a JSON object", provider)
    status = doc.get("status")
    if isinstance(status, bool) or not isinstance(status, int):
        raise ProviderBodyError(PROVIDER_PARSE, f"non-integer status {status!r}", provider)
    if status != 1:
        reason = doc.get("status_reason")
        reason = reason.strip() if isinstance(reason, str) and reason.strip() else f"status={status!r}"
        raise ProviderBodyError(classify_provider_reason(provider, reason), reason, provider)
    return doc


#: an upper bound on the digits in `total_results`. A count of domain names cannot approach this, and it
#: keeps the conversion well inside CPython's int-from-string limit so the result never depends on the
#: interpreter's configuration.
_WHOXY_TOTAL_MAX_DIGITS = 15


def whoxy_total(value):
    """Whoxy's `total_results` as an exact non-negative int, or None when it is not usable.

    MEASURED 2026-07-29 — the type VARIES BY VALUE. A no-match answers `"total_results": 0` (an int); a
    non-empty reverse-whois answers `"total_results": "39766"` (a STRING). The int-only check therefore
    fail-closed on every successful query that actually found something, which is every query the lane
    exists for. B0 had only ever measured the empty case, so the non-empty branch was written from the
    documented schema and had never met a live answer.

    Deliberately NOT `int(value)`: that accepts `" 39766\n"`, `"+39766"`, `"-1"`, `True`, and Unicode
    digits (`str.isdigit()` accepts superscripts and Devanagari alike). Only a CANONICAL ASCII decimal is
    a value we can claim to have read — anything else is drift, and drift is reported, not guessed at.
    Leading zeros are non-canonical for the same reason: one value, one spelling.

    review-B1.6r1#1: the string form is accepted only for a POSITIVE total. What was measured is exact:
    an EMPTY answer carries the integer `0`, and a non-empty one carries a string. Accepting `"0"` would
    let an unmeasured shape take the zero-result path — a clean EMPTY produced by a body we have never
    seen, which is the false empty this whole contract exists to prevent.

    review-B1.6r1#2: the digit count is BOUNDED. CPython refuses to convert an over-long decimal string
    (`sys.get_int_max_str_digits()`, 4300 by default), so a long run of digits passed the character check
    and then made `int()` raise — breaking this function's one promise, that unusable input returns None.
    15 digits is past any conceivable count of registered domain names, and far below the interpreter
    limit, so the answer never depends on how the interpreter is configured."""
    if isinstance(value, bool):
        return None                                  # bool is an int subclass; `True` is not a count
    if isinstance(value, int):
        return value if value >= 0 else None
    if not isinstance(value, str) or not value:
        return None
    if any(c not in "0123456789" for c in value):     # no sign, space, separator or Unicode digit
        return None
    if value[0] == "0":                               # "0" is the MEASURED INT form only; "007" is drift
        return None
    if len(value) > _WHOXY_TOTAL_MAX_DIGITS:
        return None
    return int(value)


def whoxy_reverse_rows(doc, *, provider: str = "whoxy") -> list:
    """A VALIDATED reverse-whois result list from an already-enveloped Whoxy body -> [domain, ...].

    review-B0#5: the old read was `doc.get("domainsList") or [d.get("domain_name") for d in
    doc.get("search_result", [])]`, which fails OPEN in three ways: a missing results key becomes a clean
    empty, a non-dict row raises deep in the caller, and a `None` domain becomes a candidate. The
    documented schema carries `total_results` + `search_result`, so a success body that has neither is
    schema drift, not an empty answer.

    Cardinality is CHECKED, not trusted: `total_results` is the provider's own count of matches, and a
    page holding fewer rows than that is PAGINATED — reporting the page as the whole answer is a silent
    coverage loss. The caller receives the rows and the shortfall is surfaced by `whoxy_reverse_page`."""
    rows = doc.get("search_result")
    if rows is None and isinstance(doc.get("domainsList"), list):
        rows = [{"domain_name": d} for d in doc["domainsList"]]   # documented alternate shape
    if not isinstance(rows, list):
        raise ProviderBodyError(PROVIDER_PARSE, "success body has no search_result list", provider)
    out = []
    for row in rows:
        if not isinstance(row, dict):
            raise ProviderBodyError(PROVIDER_PARSE, f"non-object result row ({type(row).__name__})", provider)
        name = row.get("domain_name")
        # review-B0r2#6: "contains a dot" is not a hostname test — it admitted `a..b`, `../evil.com`,
        # `http://evil.com` and names with whitespace, each of which would have become an apex CANDIDATE
        # (and a path-shaped one is a traversal primitive the moment anything derives a filename from it).
        # Reuse Quarry's ONE strict IDNA canonicaliser instead of inventing a third policy.
        canon = normalize.canon_host_strict(name) if isinstance(name, str) else None
        if not canon or "." not in canon:
            raise ProviderBodyError(PROVIDER_PARSE, f"result row has no usable domain_name ({name!r})",
                                    provider)
        out.append(canon)
    return out


def whoxy_reverse_page(doc, *, param: str, value: str, provider: str = "whoxy",
                       page: int = 1) -> tuple:
    """-> (rows, total_results, truncated). `truncated` is True when the provider says it holds more
    matches than this page returned — a PAGINATION shortfall the caller must report rather than absorb.

    `param`/`value` are the REQUEST IDENTITY (e.g. ``("company", "Acme Inc")``) and are REQUIRED — every
    response is bound to the question it answers, and the compact zero-result shape has nothing else
    tying it to ours. review-B1.6r6: they defaulted to None while being mandatory in effect, so a caller
    that simply forgot them got a `ProviderBodyError` blaming the PROVIDER for a defect in the call.

    review-B0r3#4: the page position is REQUIRED, not validated-if-present. Optional validation let a body
    missing both fields through unchecked, and would have accepted a page-2 response for our page-1
    request — silently attributing one slice of the answer to another. `page` is what we ASKED for, and
    the response must say it is that page.

    review-B1.6r5#1: the ENDPOINT and REQUEST binding applied to the compact empty shape ONLY, so a
    PAGED body could arrive with `api_query` missing or saying `account_balance`, with no
    `search_identifier` at all, or with one naming a different company, and its rows still became
    confident domain results. B1.6's reader enforced this — but the LIVE lane calls this function
    directly, so the enforcement has to be HERE, where every caller gets it. A response that cannot be
    tied to the question we asked is not an answer to it."""
    if doc.get("api_query") != "reverse_whois":
        raise ProviderBodyError(PROVIDER_PARSE,
                                f"not a reverse_whois answer (api_query={doc.get('api_query')!r})",
                                provider)
    if param not in ("company", "email") or not isinstance(value, str) or not value.strip():
        raise ProviderBodyError(PROVIDER_PARSE,
                                f"a reverse-whois response cannot be bound to a request "
                                f"(param={param!r} value={value!r})", provider)
    ident = doc.get("search_identifier")
    if ident != {param: value}:
        raise ProviderBodyError(PROVIDER_PARSE,
                                f"response identifies {ident!r}, not exactly the {param}={value!r} "
                                f"we asked", provider)
    raw_total = doc.get("total_results")
    total = whoxy_total(raw_total)
    # MEASURED 2026-07-27 — a genuine reverse-whois NO-MATCH (HTTP 200):
    #   {"status": 1, "api_query": "reverse_whois", "search_identifier": {"company": "<what we asked>"},
    #    "total_results": 0, "api_execution_time": 0.01}
    # i.e. NO `search_result`, NO `current_page`, NO `total_pages`. The first fix accepted "any body whose
    # total_results is 0", which was far wider than the evidence: a bare {"status":1,"total_results":0},
    # an `account_balance` answer, or a half-paged hybrid all became a clean EMPTY — re-creating the very
    # false-empty this batch exists to kill. EXACTLY TWO shapes are accepted, and nothing in between.
    if total == 0:
        sr, dl = doc.get("search_result"), doc.get("domainsList")
        cur, pages = doc.get("current_page"), doc.get("total_pages")
        # a zero count with actual rows is contradictory in EITHER supported carrier
        for name, v in (("search_result", sr), ("domainsList", dl)):
            if v is not None and (not isinstance(v, list) or v):
                raise ProviderBodyError(PROVIDER_PARSE,
                                        f"total_results is 0 but {name} carries rows", provider)
        # review-B0r7#1: ABSENCE, not None. `doc.get()` cannot tell a missing key from an explicit null,
        # so `{"search_result": null}` / `{"current_page": null}` looked like the measured compact shape
        # and became a clean EMPTY. A present-but-null key is a MALFORMED presence, not an absence.
        has_carrier = "search_result" in doc or "domainsList" in doc
        has_paging = "current_page" in doc or "total_pages" in doc
        if not has_carrier and not has_paging:
            # SHAPE A — the MEASURED compact empty. Bound to the REQUEST: without this a response to a
            # different question (another anchor, or `account=balance`) counted as "this query found
            # nothing", which is a false empty wearing the measured shape.
            # review-B0r7#2: the binding is MANDATORY and EXACT — now enforced above for EVERY shape,
            # because a paged body needs it just as much as this one (review-B1.6r5#1).
            # review-B0r8: the compact body carries NO page identity, so it can only ever prove the
            # INITIAL request. Accepting it for page 2 would let B1's pagination complete a page it never
            # actually received — the shape says "this query matched nothing", which is only a coherent
            # answer to the first page.
            if isinstance(page, bool) or not isinstance(page, int) or page != 1:
                raise ProviderBodyError(PROVIDER_PARSE,
                                        f"compact zero-result body carries no page identity and cannot "
                                        f"answer page {page!r}", provider)
            return [], 0, False
        if has_carrier and "current_page" in doc and "total_pages" in doc:
            # SHAPE B — a strict PAGED empty: an empty collection plus BOTH pagination fields, valid.
            # the carrier must be a real (empty) LIST — a null one is malformed, not empty.
            if not (isinstance(sr, list) or isinstance(dl, list)):
                raise ProviderBodyError(PROVIDER_PARSE,
                                        f"zero-result carrier is not a list "
                                        f"(search_result={sr!r} domainsList={dl!r})", provider)
            for label, v in (("current_page", cur), ("total_pages", pages)):
                if isinstance(v, bool) or not isinstance(v, int) or v < 1:
                    raise ProviderBodyError(PROVIDER_PARSE, f"invalid {label} ({v!r})", provider)
            if pages > 1:
                raise ProviderBodyError(PROVIDER_PARSE,
                                        f"total_results is 0 but total_pages is {pages}", provider)
            if cur != page:
                raise ProviderBodyError(PROVIDER_PARSE,
                                        f"response is page {cur}, but page {page} was requested", provider)
            return [], 0, False
        # anything between the two: half-present pagination, a carrier without paging, paging without a
        # carrier. Unrecognised shape -> fail closed rather than guess which half to trust.
        raise ProviderBodyError(PROVIDER_PARSE,
                                "zero-result body is neither the compact empty shape nor a fully paged "
                                f"empty (search_result={sr!r} domainsList={dl!r} "
                                f"current_page={cur!r} total_pages={pages!r})", provider)
    rows = whoxy_reverse_rows(doc, provider=provider)
    # review-B0r2#4: an ABSENT or garbled cardinality is schema drift, not "no claim to check". Treating
    # it as unknown-but-fine let a drifted body finish CLEAN — the same fail-open shape as the original
    # false empty, one level up. The documented success schema carries total_results, so its absence,
    # its wrong type, a negative value, or a count SMALLER than the rows actually delivered are all
    # unusable cardinality and must fail closed.
    if total is None:
        raise ProviderBodyError(PROVIDER_PARSE,
                                f"success body has no usable total_results ({raw_total!r})", provider)
    if total < len(rows):
        raise ProviderBodyError(PROVIDER_PARSE,
                                f"total_results {total} is smaller than the {len(rows)} rows returned",
                                provider)
    # the documented schema carries the page position — both fields, always.
    cur, pages = doc.get("current_page"), doc.get("total_pages")
    for label, v in (("current_page", cur), ("total_pages", pages)):
        if isinstance(v, bool) or not isinstance(v, int) or v < 1:
            raise ProviderBodyError(PROVIDER_PARSE, f"missing/invalid {label} ({v!r})", provider)
    if cur > pages:
        raise ProviderBodyError(PROVIDER_PARSE, f"current_page {cur} exceeds total_pages {pages}", provider)
    if cur != page:
        raise ProviderBodyError(PROVIDER_PARSE,
                                f"response is page {cur}, but page {page} was requested", provider)
    truncated = total > len(rows) or pages > 1
    return rows, total, truncated


def _emit_terminal(source_id, src, res, *, work_unit, parent_id, scope_distance, discovery_context):
    """Emit the source's TERMINAL event. Called from a finally so it fires even if execution/reclassify
    raised (res is None then → a synthetic FAILED terminal, so every executed source ALWAYS has a
    terminal event). A BLOCKED/degraded status also gets its dedicated event first. ``work_unit`` ties the
    terminal to the same stable unit as tool_start (the C10b resume key)."""
    if res is None:
        events.tool_finish(source_id, status=Status.FAILED.value, reason="execution raised before a result",
                           work_unit=work_unit, parent_id=parent_id, scope_distance=scope_distance,
                           discovery_context=discovery_context)
        return
    raw_ref = str(res.raw_path) if res.raw_path else None
    # review#8: this runs in run_contract's finally — the terminal guarantee. stat() can raise (TOCTOU race,
    # permission, vanished file); a throw here would defeat the guarantee (or mask the real exception). Guard it.
    artifact_size = None
    if res.raw_path:
        try:
            artifact_size = res.raw_path.stat().st_size
        except OSError:
            artifact_size = None
    if res.status == Status.BLOCKED:
        events.tool_blocked(source_id, reason=res.note or "blocked")
    elif res.status in _PARTIAL:
        events.coverage_partial(source_id, reason=res.note or res.status.value)
    events.tool_finish(source_id, status=res.status.value, reason=res.note or None,
                       duration=round(res.duration, 2), exit_code=res.exit_code, work_unit=work_unit,
                       rss=res.peak_rss_mb, cpu_s=res.cpu_s,
                       raw_ref=raw_ref, artifact_size=artifact_size,
                       fallback=src.get("fallback"),
                       parent_id=parent_id, scope_distance=scope_distance,
                       discovery_context=discovery_context)


def run_provider(source_id, fn, *, work_unit=None, input_total=None):
    """Contract bracket for an IN-PROCESS provider (native HTTP, not a subprocess): emit tool_start before,
    tool_finish ALWAYS after. Registry-AUTHORITATIVE (review#3): an unknown source_id is NOT executed
    (tool_blocked + return None), same as run_contract. The provider must NOT swallow its own errors — this
    bracket catches them so a failure is recorded as a FAILED terminal, NOT a clean EMPTY (review#2: else
    C10b could skip a provider after an auth/transport/quota/parse failure). Best-effort is preserved: on a
    failure the phase still continues (returns None). Returns fn()'s result on success. C06: a FAILED terminal
    carries an ``error_class`` (auth/quota/transport/parse/server) so a consumer can tell a real failure from
    'nothing found' and choose retry/backoff."""
    if not _provider_start(source_id, work_unit=work_unit, input_total=input_total):
        return None
    return _provider_terminal(source_id, fn, work_unit=work_unit)


class ProviderSkip(Exception):
    """A lane that did not run and did not fail: no credential, no input. It still needs a LIFECYCLE —
    without one the previous run's terminal and coverage generation stay standing as if current."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _partial_status(error_class, limited: bool) -> str:
    """The ONE precedence for every incomplete provider result, in both partial branches.

    review-B1.4r5#1: `limited` was consulted only in the generic-partial branch, so the same flag meant
    different things depending on `partial_kind` — and where it WAS read it outranked `error_class`, so a
    transport failure alongside an operator bound reported LIMITED/transport. Gaps dominate limits:

      1. a NON-limit error_class is a real failure          -> PARTIAL (a degraded execution)
      2. a PROVEN provider limit, or a deliberate operator bound -> LIMITED (clean, cut short)
      3. otherwise (incomplete, nothing broke, nobody refused)   -> PARTIAL
    """
    if error_class and not is_provider_limit(error_class):
        return Status.PARTIAL.value
    if is_provider_limit(error_class) or limited:
        return Status.LIMITED.value
    return Status.PARTIAL.value


def terminal_is_limit(status, error_class) -> bool:
    """Whether a provider TERMINAL is a soft limit (-> complete_with_limits) rather than a gap.

    review-B1.4r7#1: reconciliation recognised a limit only by a PROVEN provider class, so an OPERATOR
    boundary — `LIMITED` with deliberately no provider class — fell into the generic gap branch and
    reversed the terminal and coverage semantics at the last step. `Status.LIMITED` means "ran clean,
    something bounded it"; WHY is carried separately by `error_class`.

    Malformed combinations are guarded rather than trusted, in BOTH directions — the status and the
    class must agree, and either one alone is not enough:

      · `LIMITED` + a NON-limit class (a transport failure) is a contradiction; it must not soften that
        failure, so it reads as a gap.
      · review-B1.4r8#1: any OTHER status + a proven limit class was accepted on the strength of the
        class alone, so a FAILED/quota terminal folded as `complete_with_limits` with an EMPTY failure
        list — a hard failure laundered into a soft limit. Every producer already emits `LIMITED` for a
        genuine quota (`_partial_status`, and the exception path in `_provider_terminal`), so nothing
        legitimate needs the permissive fallback.

    Fail closed: the status decides, the class may only disqualify."""
    if status != Status.LIMITED.value:
        return False
    return not error_class or is_provider_limit(error_class)


def _partial_coverage_kind(error_class, limited: bool) -> str:
    """WHOSE boundary truncated a paginating provider — the same precedence as `_partial_status`.

    review-B1.4r6#1: this was derived from the STATUS, so every LIMITED outcome emitted
    `COVERAGE_PROVIDER`. That collapsed the two ways a run can be limited and told the reader the
    provider had refused us when the truth was our own operator boundary — the attribution the whole
    B0/B1 taxonomy exists to keep apart, reappearing one layer downstream of the terminal that had just
    been fixed."""
    if error_class and not is_provider_limit(error_class):
        return events.COVERAGE_TIMEOUT               # a later page was LOST — the target's cost
    if is_provider_limit(error_class):
        return events.COVERAGE_PROVIDER              # a PROVEN provider limit (credits/plan)
    if limited:
        return events.COVERAGE_SAMPLE                # an OPERATOR policy — deliberately bounded
    return events.COVERAGE_CAP                       # OUR configured ceiling truncated it


def _provider_start(source_id, *, work_unit=None, input_total=None) -> bool:
    """Open a provider lane: registry check, generation reset, tool_start. False = not in the registry."""
    if sources.get(source_id) is None:
        events.tool_blocked(source_id, reason=f"unknown source_id {source_id!r} — not in registry; not executed")
        return False
    if not acquisition_open(source_id, announce=False):
        # a campaign closed acquisition. The lane still gets a LIFECYCLE — start, then a skipped terminal
        # with the reason — because a manifest that simply lacks the lane says "nobody ran it", and an
        # un-terminated start would leave an earlier generation standing.
        from . import campaign as _campaign
        why = _campaign.acquisition_allowed(source_id)[1]
        events.tool_blocked(source_id, reason=why)
        reset = events.mark_provider_generation(source_id)
        events.tool_start(source_id, input_total=input_total, work_unit=work_unit, provider=True,
                          reset_generation=reset)
        # ...and the COVERAGE generation moves with it, ALWAYS — not only when this is the session's first
        # terminal. A campaign refusal is a SOURCE-WIDE decision, and leaving the previous snapshot standing
        # made the lane say both "policy skipped this" and "this omitted a page": one lane, two stories.
        events.coverage_reset(source_id)
        events.tool_finish(source_id, status=Status.SKIPPED.value, reason=why, work_unit=work_unit,
                           provider=True)
        return False
    # review-r5#1: stamp the generation reset on the START (persisted BEFORE execution) so a crash between
    # start and terminal still supersedes the prior generation, and the un-terminated start reads as
    # INCOMPLETE.
    reset_gen = events.mark_provider_generation(source_id)   # first terminal per source per session
    events.tool_start(source_id, input_total=input_total, work_unit=work_unit,
                      provider=True, reset_generation=reset_gen)
    if reset_gen:
        # review-B0r5#1: the TERMINAL generation and the COVERAGE generation were independent. A provider
        # that emitted `coverage:cap` last session and then stops on page 1 this session (quota, or any
        # failure) emits NO pagination counter at all — so nothing superseded the old cap, and a stale
        # gap from a previous run dragged this run's honest `complete_with_limits` back to
        # `complete_with_gaps`. Opening the coverage generation alongside the provider generation makes
        # the two move together: prior units are a stale snapshot the moment this source runs again.
        events.coverage_reset(source_id)
    return True


def run_providers(entries, shared):
    """Bracket SEVERAL provider lanes around ONE shared body.

    `entries` is [(source_id, work_unit, finalize)]; `shared` runs ONCE, after every lane has started and
    before any lane is finalized. Returns {source_id: result or None}.

    review-B1.4r3#1: work shared by several lanes — a coordinator spending one credit budget across them
    — used to run BEFORE either bracket. Requests were then issued before `tool_start` and before the
    generation reset, so an interruption mid-spend left credits gone with no lane lifecycle to show for
    it, and a stale previous generation still standing. Starting every participating lane first makes the
    un-terminated start the honest record of exactly that.

    A raise from `shared` is every started lane's failure: none of them can produce a result."""
    live = [(sid, wu, fin) for sid, wu, fin in entries
            if _provider_start(sid, work_unit=wu)]
    if not live:
        # every lane was refused — an unknown source id, or a campaign that closed acquisition. The shared
        # body is what SPENDS, so running it for nobody would buy pages no lane will ever report.
        return {}
    cancel = failed = None
    try:
        shared()
    except (KeyboardInterrupt, SystemExit) as e:
        cancel = e
    except Exception as e:
        # review-B1.4r4#4: this caught BaseException and always re-raised, so an ordinary failure in
        # shared setup aborted the surrounding PHASE — while the single-lane `run_provider` records
        # FAILED and returns None. Best-effort is the provider contract; only cancellation propagates.
        failed = e
    results: dict = {}
    # fixed BEFORE the loop: only a failure of the SHARED body kills every lane. A cancellation raised
    # by one lane's finalizer must not be replayed into the others — their results are already computed
    # and finalizing them is pure bookkeeping, which is exactly what must not be skipped.
    dead = cancel if cancel is not None else failed
    for sid, wu, fin in live:
        body = fin if dead is None else (lambda e=dead: (_ for _ in ()).throw(e))
        try:
            results[sid] = _provider_terminal(sid, body, work_unit=wu)
        except BaseException as e:
            # review-B1.4r4#1: `_provider_terminal` re-raises cancellation PAST its own finally — the
            # terminal for THIS lane is already written, but an un-caught re-raise ended the loop and
            # left every later lane permanently started. Remember it, finish the lanes, raise after.
            results[sid] = None
            cancel = cancel if cancel is not None else e
    if cancel is not None:
        raise cancel
    return results


def _provider_terminal(source_id, fn, *, work_unit=None):
    """Run `fn` and emit this lane's terminal, whatever happens. The lane must already be STARTED."""
    result = None
    status = Status.FAILED.value                             # default: covers a raise BEFORE a result is computed
    reason = n = error_class = None
    is_pagination = False                                     # this result reports pagination COMPLETION (emit a counter)
    partial_limited = False                                   # the truncation was a DELIBERATE bound
    try:
        result = fn()
        n = len(result) if hasattr(result, "__len__") else None
        produced = getattr(result, "produced", None)
        if produced is not None:
            # the lane told us what it wrote. Status follows THAT, not a hostname set it never fills.
            n = sum(v for v in produced.values() if isinstance(v, int))
        if isinstance(result, ProviderResult):
            if result.partial and result.partial_kind == "pagination":
                is_pagination = True
                error_class = result.error_class
                partial_limited = bool(result.limited)
                # review-B0r4#1: the PAGINATION branch ran BEFORE any limit check, so a later page that
                # died on spent credits became a degraded PARTIAL *and* a COVERAGE_CAP — i.e. Quarry
                # claiming its own hard ceiling truncated the input. A proven provider limit is LIMITED
                # with provider-limit coverage, whatever stopped us and on whichever page.
                status = _partial_status(error_class, result.limited)
                reason = (f"pagination TRUNCATED at {result.pages} page(s), cursor={result.cursor!r}"
                          + (f" — {error_class} on a later page (earlier pages KEPT)" if error_class else ""))
            elif result.partial:                            # review-r4#2: a GENERIC degraded partial (NOT pagination)
                error_class = result.error_class
                # a partial caused by a PROVIDER LIMIT is not degradation either (r3#1)
                status = _partial_status(error_class, result.limited)
                reason = result.partial_reason or f"partial result ({error_class or 'degraded'}) — earlier evidence KEPT"
            else:                                            # a complete ProviderResult — a paginating provider
                is_pagination = result.pages is not None     # (only paginating providers carry a completion counter)
                status = Status.SUCCESS.value if n else Status.EMPTY.value
        else:
            status = Status.SUCCESS.value if n else Status.EMPTY.value
    except ProviderSkip as e:                                # did not run and did not fail
        status, reason, result = Status.SKIPPED.value, e.reason, None
    except Exception as e:                                   # ordinary provider error — record FAILED, don't crash phase
        # the provider's OWN words, when it gave any. A status code is what happened; the body is why.
        _detail = error_detail(e)
        reason, result = f"{type(e).__name__}: {e}" + (f" — {_detail}" if _detail else ""), None
        # B0: a ProviderBodyError already carries a class PROVEN from the provider's own body, which the
        # generic HTTP/type mapping cannot see (it would flatten a measured "Zero Account Balance" into
        # `error`) — so a body-proven LIMIT could never reach the terminal or the verdict. The proven
        # class wins; everything else falls back to the exception-type mapping.
        error_class = provider_error_class(e)
        # review-B0r2#1 / r3#1: a PROVEN limit is neither a FAILED nor a DEGRADED execution. FAILED left
        # tool_status.failed lying; PARTIAL then left tool_status.partial lying, because "degraded" asserts
        # something went wrong HERE and nothing did. Status.LIMITED is the distinct, non-degraded outcome:
        # the execution was clean and a third party cut it short. The provider OUTCOME (error_class) and
        # the EXECUTION status stay independent facts.
        if is_provider_limit(error_class):
            status = Status.LIMITED.value
    finally:
        # review#7: emit from a finally so a terminal ALSO fires on KeyboardInterrupt/SystemExit (which are NOT
        # `Exception`) — the BaseException then re-raises past this finally, cancelling the run, but the
        # provider is no longer left permanently 'started'. Status stays FAILED for the cancellation case.
        if is_pagination:
            # review-r2#1: a STRUCTURED per-unit completion counter the VERDICT can see. Emitted EVERY run
            # (omitted=0 when complete) so a later complete rerun CLEARS a prior truncation; keyed on work_unit
            # so each apex reconciles alone. Only for PAGINATION outcomes — never for a generic degraded partial.
            truncated = status in (Status.PARTIAL.value, Status.LIMITED.value)
            # the KIND records WHOSE boundary stopped us, and attribution matters for tuning (and for the
            # future AI interface) even when the verdict is a gap either way:
            #   provider -> a PROVEN limit (credits/plan): a soft limit, not a defect
            #   timeout  -> a later page was LOST IN FLIGHT (429 / transport / 5xx) — the target's cost
            #   cap      -> OUR configured max_pages ceiling truncated it — the only one that is ours
            # review-B0r5#2: everything non-limit was labelled `cap`, which blamed Quarry's ceiling for a
            # rate-limited or broken page it never reached.
            _kind = _partial_coverage_kind(error_class, partial_limited)
            events.coverage_partial(source_id, kind=_kind, measure="pagination",
                                    unit=(work_unit or source_id), eligible=1,
                                    tested=0 if truncated else 1, omitted=1 if truncated else 0,
                                    reason=(reason if truncated else "pagination complete"))
        _produced = getattr(result, "produced", None)
        events.tool_finish(source_id, status=status, work_unit=work_unit,
                           reason=reason, error_class=error_class, provider=True,   # verdict folds provider terminals
                           produced=(dict(_produced) if _produced is not None else
                                     ({"host": n} if n is not None else None)))     # (reset is on the START now)
    return result                                            # None on failure — caller guards (best-effort)


def acquisition_open(source_id: str, *, announce: bool = True) -> bool:
    """The ACQUISITION gate, consulted by every execution path (settle: acquisition closure).

    A campaign closes acquisition after its first child, and there are three doors into a provider —
    `run_provider`, `run_providers` and `run_contract` — so the check lives here, where all three pass, and
    a closed lane records a SKIP with its cause rather than a silent absence."""
    from . import campaign
    allowed, why = campaign.acquisition_allowed(source_id)
    if allowed:
        return True
    if announce:
        events.tool_blocked(source_id, reason=why)
    return False


def registered(source_id: str) -> bool:
    """Whether this source may execute, emitting `tool_blocked` when it may not.

    The registry is authoritative for EXECUTION, and that authority lives here — `run_contract` and
    `run_provider` are the only places that consult it, so a phase never imports `sources` (the registry
    stays declarative from a phase's point of view).

    For a lane that runs SEVERAL units under ONE lifecycle — nuclei's chunks, arjun's targets, the
    xnLinkFinder inputs — `run_contract` per unit would emit competing terminals under one source id. Such
    a lane brackets itself with `tool_start`/`tool_finish` and asks THIS for the same gate."""
    if sources.get(source_id) is not None:
        return True
    events.tool_blocked(source_id, reason=f"unknown source_id {source_id!r} — not in registry; not executed")
    return False


def run_contract(source_id, cmd, *, input_total=None, env=None, reclassify=None, work_unit=None,
                 parent_id=None, scope_distance=None, discovery_context=None,
                 **run_kwargs):
    """Run a source under its registry contract: emit tool_start, execute via ``runner.run``, apply an
    optional ``reclassify(RunResult) -> RunResult`` (file-output adapter) so the TERMINAL event carries the
    FINAL status, and ALWAYS emit a terminal event (try/finally). Returns the (reclassified) RunResult.

    ``run_kwargs`` pass straight through to runner.run (raw_path, timeout, stdin_data, input_file,
    ok_empty, ok_codes, stderr_path). The event layer is ADDITIVE — the phase still records the RunResult to the
    manifest itself. Provenance fields ride on the events only; they never alter execution.
    """
    # No tool runs outside a contract. An unknown source_id fails LOUD before execution: emit a
    # blocked event and return a SKIPPED RunResult — the command is never handed to runner.run.
    src = sources.get(source_id)
    if src is None:
        reason = f"unknown source_id {source_id!r} — not in registry; not executed"
        events.tool_blocked(source_id, reason=reason)
        return skipped(source_id, reason)
    if not acquisition_open(source_id):        # a campaign closed acquisition: this lane does not run
        from . import campaign as _campaign
        return skipped(source_id, _campaign.acquisition_allowed(source_id)[1])
    tool = src.get("tool") or source_id.split(".", 1)[-1]

    events.tool_start(source_id, cmd=cmd, env=env, input_total=input_total, work_unit=work_unit,
                      workers=src.get("workers"), rate=src.get("rate"),
                      timeout=run_kwargs.get("timeout", src.get("timeout")),
                      parent_id=parent_id, scope_distance=scope_distance,
                      discovery_context=discovery_context)

    res = None
    try:
        res = _run(tool, cmd, env=env, **run_kwargs)
        if reclassify is not None:
            res = reclassify(res)                           # file-output adapter → FINAL status on the terminal event
        return res
    finally:
        _emit_terminal(source_id, src, res, work_unit=work_unit, parent_id=parent_id,
                       scope_distance=scope_distance, discovery_context=discovery_context)
