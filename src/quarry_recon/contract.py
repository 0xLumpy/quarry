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
import socket as _socket
import urllib.error as _urlerr

from . import events, normalize, sources
from .runner import Status, run as _run, skipped

# Non-clean terminal statuses that warrant a dedicated event before the normal tool_finish.
_PARTIAL = (Status.PARTIAL, Status.TIMED_OUT)


class ProviderResult(set):
    """A provider's hostname set that can also carry PAGINATION COMPLETION metadata (C06). A plain set means
    'complete'; `partial=True` means the page cap was hit with a live continuation cursor, so collection was
    TRUNCATED — run_provider then records PARTIAL (not SUCCESS) and a structured coverage_partial, so a
    consumer can tell complete collection from a bounded/truncated one and resume from `cursor`."""
    def __init__(self, iterable=(), *, partial=False, cursor=None, pages=None, error_class=None,
                 partial_kind="pagination", partial_reason=None):
        super().__init__(iterable)
        self.partial = partial
        self.cursor = cursor
        self.pages = pages
        self.error_class = error_class      # set when a LATER page failed (earlier pages preserved as PARTIAL)
        # review-r4#2: a partial result is EITHER "pagination" (cap/cursor truncation — emits a pagination
        # coverage gap) OR "degraded" (a generic partial, e.g. some Shodan pivots failed — NOT pagination, so
        # run_provider must not fabricate a "TRUNCATED at None pages" reason or a pagination coverage unit).
        self.partial_kind = partial_kind
        self.partial_reason = partial_reason


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
PROVIDER_HTTP = "http"
PROVIDER_ERROR = "error"

#: classes that are an EXTERNAL LIMIT rather than a defect — coverage is incomplete, but nothing failed
#: and nothing is retryable within the run. These feed `complete_with_limits`, never `complete_with_gaps`.
PROVIDER_LIMITS = frozenset({PROVIDER_QUOTA, PROVIDER_ENTITLEMENT})


def is_provider_limit(error_class) -> bool:
    """True when the class is an external provider LIMIT (quota/entitlement) rather than a failure."""
    return error_class in PROVIDER_LIMITS


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
}


def _norm_reason(reason: str) -> str:
    return " ".join((reason or "").split()).strip().lower()


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


def whoxy_reverse_page(doc, *, provider: str = "whoxy", page: int = 1,
                       param: "str | None" = None, value: "str | None" = None) -> tuple:
    """-> (rows, total_results, truncated). `truncated` is True when the provider says it holds more
    matches than this page returned — a PAGINATION shortfall the caller must report rather than absorb.

    `param`/`value` are the REQUEST IDENTITY (e.g. ``("company", "Acme Inc")``) — the compact zero-result
    shape carries no rows to check, so the only thing tying it to our question is its own echo of it.

    review-B0r3#4: the page position is REQUIRED, not validated-if-present. Optional validation let a body
    missing both fields through unchecked, and would have accepted a page-2 response for our page-1
    request — silently attributing one slice of the answer to another. `page` is what we ASKED for, and
    the response must say it is that page."""
    total = doc.get("total_results")
    # MEASURED 2026-07-27 — a genuine reverse-whois NO-MATCH (HTTP 200):
    #   {"status": 1, "api_query": "reverse_whois", "search_identifier": {"company": "<what we asked>"},
    #    "total_results": 0, "api_execution_time": 0.01}
    # i.e. NO `search_result`, NO `current_page`, NO `total_pages`. The first fix accepted "any body whose
    # total_results is 0", which was far wider than the evidence: a bare {"status":1,"total_results":0},
    # an `account_balance` answer, or a half-paged hybrid all became a clean EMPTY — re-creating the very
    # false-empty this batch exists to kill. EXACTLY TWO shapes are accepted, and nothing in between.
    if isinstance(total, int) and not isinstance(total, bool) and total == 0:
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
            if doc.get("api_query") != "reverse_whois":
                raise ProviderBodyError(PROVIDER_PARSE,
                                        f"compact zero-result body is not a reverse_whois answer "
                                        f"(api_query={doc.get('api_query')!r})", provider)
            # review-B0r7#2: the binding is MANDATORY and EXACT. It was optional (so a caller that simply
            # forgot the identity got a free clean empty) and it matched only ONE key, so an identifier
            # ALSO naming a different anchor passed. A body with no rows has nothing else tying it to our
            # question — the echo IS the evidence, so it must be complete and it must be present.
            if param not in ("company", "email") or not isinstance(value, str) or not value.strip():
                raise ProviderBodyError(PROVIDER_PARSE,
                                        f"compact zero-result body cannot be bound to a request "
                                        f"(param={param!r} value={value!r})", provider)
            ident = doc.get("search_identifier")
            if ident != {param: value}:
                raise ProviderBodyError(PROVIDER_PARSE,
                                        f"compact zero-result body identifies {ident!r}, "
                                        f"not exactly the {param}={value!r} we asked", provider)
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
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        raise ProviderBodyError(PROVIDER_PARSE, f"success body has no usable total_results ({total!r})",
                                provider)
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
    if sources.get(source_id) is None:
        events.tool_blocked(source_id, reason=f"unknown source_id {source_id!r} — not in registry; not executed")
        return None
    # review-r5#1: stamp the generation reset on the START (persisted BEFORE execution) so a crash between start
    # and terminal still supersedes the prior generation, and the un-terminated start reads as INCOMPLETE.
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
    result = None
    status = Status.FAILED.value                             # default: covers a raise BEFORE a result is computed
    reason = n = error_class = None
    is_pagination = False                                     # this result reports pagination COMPLETION (emit a counter)
    try:
        result = fn()
        n = len(result) if hasattr(result, "__len__") else None
        if isinstance(result, ProviderResult):
            if result.partial and result.partial_kind == "pagination":
                is_pagination = True
                error_class = result.error_class
                # review-B0r4#1: the PAGINATION branch ran BEFORE any limit check, so a later page that
                # died on spent credits became a degraded PARTIAL *and* a COVERAGE_CAP — i.e. Quarry
                # claiming its own hard ceiling truncated the input. A proven provider limit is LIMITED
                # with provider-limit coverage, whatever stopped us and on whichever page.
                status = (Status.LIMITED.value if is_provider_limit(error_class)
                          else Status.PARTIAL.value)
                reason = (f"pagination TRUNCATED at {result.pages} page(s), cursor={result.cursor!r}"
                          + (f" — {error_class} on a later page (earlier pages KEPT)" if error_class else ""))
            elif result.partial:                            # review-r4#2: a GENERIC degraded partial (NOT pagination)
                error_class = result.error_class
                # a partial caused by a PROVIDER LIMIT is not degradation either (r3#1)
                status = (Status.LIMITED.value if is_provider_limit(error_class)
                          else Status.PARTIAL.value)
                reason = result.partial_reason or f"partial result ({error_class or 'degraded'}) — earlier evidence KEPT"
            else:                                            # a complete ProviderResult — a paginating provider
                is_pagination = result.pages is not None     # (only paginating providers carry a completion counter)
                status = Status.SUCCESS.value if n else Status.EMPTY.value
        else:
            status = Status.SUCCESS.value if n else Status.EMPTY.value
    except Exception as e:                                   # ordinary provider error — record FAILED, don't crash phase
        reason, result = f"{type(e).__name__}: {e}", None
        # B0: a ProviderBodyError already carries a class PROVEN from the provider's own body, which the
        # generic HTTP/type mapping cannot see (it would flatten a measured "Zero Account Balance" into
        # `error`) — so a body-proven LIMIT could never reach the terminal or the verdict. The proven
        # class wins; everything else falls back to the exception-type mapping.
        error_class = getattr(e, "error_class", None) or classify_provider_error(e)
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
            if status == Status.LIMITED.value:
                _kind = events.COVERAGE_PROVIDER
            elif error_class:
                _kind = events.COVERAGE_TIMEOUT
            else:
                _kind = events.COVERAGE_CAP
            events.coverage_partial(source_id, kind=_kind, measure="pagination",
                                    unit=(work_unit or source_id), eligible=1,
                                    tested=0 if truncated else 1, omitted=1 if truncated else 0,
                                    reason=(reason if truncated else "pagination complete"))
        events.tool_finish(source_id, status=status, work_unit=work_unit,
                           reason=reason, error_class=error_class, provider=True,   # verdict folds provider terminals
                           produced={"host": n} if n is not None else None)         # (reset is on the START now)
    return result                                            # None on failure — caller guards (best-effort)


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
