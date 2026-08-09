"""Every source executes under its registry entry, and always leaves a terminal event.

    run_contract    a subprocess tool, via runner.run
    run_provider    an in-process HTTP provider
    run_providers   several provider lanes sharing one body

The registry is authoritative: an unregistered source is refused, not executed. Entity counts are not
emitted here — the phase reports what it stored, after it parses.

Provider outcome semantics: docs/design/PROVIDER-QUOTA-DESIGN.md.
"""
from __future__ import annotations

import hashlib as _hashlib
import json as _json
import os as _os
import re as _re
import socket as _socket
import urllib.error as _urlerr
from pathlib import Path as _Path

from . import events, normalize, sources
from .runner import Status, run as _run, skipped

# Non-clean terminal statuses that warrant a dedicated event before the normal tool_finish.
_PARTIAL = (Status.PARTIAL, Status.TIMED_OUT)


def _exact_counts(produced) -> dict:
    """`produced` as a validated `{entity: count}` map. Raises on anything that could lie."""
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
    """A provider's hostname set plus how complete it is.

    `partial` means cut short, `cursor` where to continue. `produced` carries entity counts for a lane
    whose evidence is not hostnames. `limited` marks a deliberate bound and implies `partial`."""
    def __init__(self, iterable=(), *, partial=False, cursor=None, pages=None, error_class=None,
                 partial_kind=None, partial_reason=None, limited=False, produced=None):
        super().__init__(iterable)
        # `{}` produced nothing; None has no count to report
        self.produced = None if produced is None else _exact_counts(produced)
        self.partial = partial or limited
        self.cursor = cursor
        self.pages = pages
        self.error_class = error_class      # set when a LATER page failed (earlier pages preserved)
        # only "pagination" may report a pagination coverage gap
        self.partial_kind = partial_kind or ("degraded" if limited else "pagination")
        self.partial_reason = partial_reason
        self.limited = limited


# Provider outcome classes. Each implies a different operator action, so two must never collapse into
# one. 403 is `forbidden`, never `entitlement`; quota and entitlement are proven from a body or a
# balance endpoint, never from a status code. See docs/design/PROVIDER-QUOTA-DESIGN.md.
PROVIDER_AUTH = "auth"
PROVIDER_FORBIDDEN = "forbidden"
PROVIDER_ENTITLEMENT = "entitlement"
PROVIDER_RATE_LIMIT = "rate_limit"
PROVIDER_QUOTA = "quota"
PROVIDER_TRANSPORT = "transport"
PROVIDER_SERVER = "server"
PROVIDER_PARSE = "parse"
#: our read ceiling, not the provider's answer: `parse` points at their schema, `oversize` at ours
PROVIDER_OVERSIZE = "oversize"
#: our pacing refused to issue the request — a gap of ours, closable for free later
PROVIDER_PACE_BUSY = "pace_busy"
PROVIDER_HTTP = "http"
PROVIDER_ERROR = "error"

#: external limits, not defects: these feed `complete_with_limits`, never `complete_with_gaps`
PROVIDER_LIMITS = frozenset({PROVIDER_QUOTA, PROVIDER_ENTITLEMENT})
#: consumers check membership here rather than accepting any non-empty string
PROVIDER_CLASSES = frozenset({PROVIDER_AUTH, PROVIDER_FORBIDDEN, PROVIDER_ENTITLEMENT,
                              PROVIDER_RATE_LIMIT, PROVIDER_QUOTA, PROVIDER_TRANSPORT, PROVIDER_SERVER,
                              PROVIDER_PARSE, PROVIDER_OVERSIZE, PROVIDER_PACE_BUSY, PROVIDER_HTTP,
                              PROVIDER_ERROR})


def is_provider_limit(error_class) -> bool:
    """True when the class is an external provider LIMIT (quota/entitlement) rather than a failure."""
    return error_class in PROVIDER_LIMITS


_ERROR_BODY_LIMIT = 8192                                     # an error body is a sentence, not a payload


def capture_error_body(exc, *, provider: str = "", limit: int = _ERROR_BODY_LIMIT):
    """Read an HTTPError's body at the RAISE SITE and stamp the refined class on it.

    Must happen here: the body is a live socket and is gone once the exception has propagated.
    Best-effort — an unreadable body yields no signal, never an error."""
    if not isinstance(exc, _urlerr.HTTPError):
        return exc
    if getattr(exc, "body_text", None) is None:
        try:
            raw = exc.read(limit)
        except Exception:
            raw = b""
        # evidence needs the bytes: `body_text` is a lossy decode and cannot be re-encoded back
        try:
            exc.body_bytes = raw
        except Exception:
            pass
        finally:
            # a live stream: unclosed leaks a connection per failure. Stamped fields survive.
            try:
                exc.close()
            except Exception:
                pass
        # best-effort: `__slots__` rejects the stamp, and a raise-site helper must not raise
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
    """A short, redacted summary of what the provider said, for the operator-visible reason.

    HTML is summarised by its <title>, where an interstitial states its business."""
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


class IncompleteAcquisition(RuntimeError):
    """An acquired response that did not arrive whole.

    The evidence is partial (and, for a paid lane, the credit is already spent), so nothing retries
    automatically."""

    error_class = "incomplete"

    def __init__(self, message: str, *, bytes_written: int = 0, partial=None):
        super().__init__(message)
        self.bytes_written = bytes_written
        self.partial = partial


def stream_to_file(r, dest, *, chunk: int = 1024 * 1024, deadline_s: float = 300.0) -> "tuple[int, str]":
    """Stream a response to `dest` atomically -> (bytes, sha256). No byte ceiling.

    Memory and time are bounded instead; a byte cap would only convert an acquired response into
    incomplete evidence (and, for a paid lane, spend money for nothing). A break mid-stream leaves the
    bytes as `.part` and raises IncompleteAcquisition."""
    import time as _time
    dest = _Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    digest = _hashlib.sha256()
    written = 0
    end = _time.monotonic() + deadline_s if deadline_s and deadline_s > 0 else None
    try:
        with open(part, "wb") as fh:
            while True:
                if end is not None and _time.monotonic() > end:
                    raise TimeoutError(f"still receiving after {deadline_s:g}s")
                buf = r.read(chunk)
                if not buf:
                    break
                fh.write(buf)
                digest.update(buf)
                written += len(buf)
            fh.flush()
            _os.fsync(fh.fileno())
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:
        # the partial file stays: a request that half-arrived is evidence of what we got
        raise IncompleteAcquisition(f"response incomplete after {written} byte(s): {e}",
                                    bytes_written=written, partial=part) from e
    _os.replace(part, dest)
    return written, digest.hexdigest()


class ResponseTooLarge(ValueError):
    """A response longer than the caller's read bound. Its class is OURS, never the provider's."""

    error_class = PROVIDER_OVERSIZE


def read_bounded(r, limit: int, *, provider: str = "", bound: str = "") -> bytes:
    """Read a response, raising ResponseTooLarge when it exceeds `limit`.

    Reads one byte past the limit, because reading exactly `limit` cannot tell a response that fits
    from one that was cut. The bytes read travel on the exception; `bound` names the constant."""
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
    """The provider's reason string from a JSON error body, or None for any other shape.

    A non-JSON body carries no signal; calling it `parse` would report a bad key as schema drift."""
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
    """Classify an HTTP error, letting the provider's own body refine the status code.

    An unrecognised reason falls back to the status class, never to a limit."""
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
    """Map a provider exception to an error class.

    Never returns `quota` or `entitlement`: a limit is proven from a body or balance endpoint."""
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
    """A provider reported failure inside a successful HTTP response.

    Carries the class and the provider's VERBATIM reason, so an unrecognised one reaches the operator."""

    def __init__(self, error_class: str, reason: str, provider: str = ""):
        super().__init__(f"{provider or 'provider'}: {reason}" if reason else (provider or "provider error"))
        self.error_class = error_class
        self.reason = reason
        self.provider = provider


#: Measured reasons that PROVE exhausted credits. Allow-list only, and matched EXACTLY after case and
#: whitespace normalisation — a substring test cannot tell a message from its own negation
#: ("Non-zero Account Balance"). An unrecognised reason stays a generic error.
_QUOTA_REASONS = {
    "whoxy": frozenset({"zero account balance"}),            # both measured; Shodan returns 401 for a spent balance AND for a bad key, so the body decides
    "shodan": frozenset({"insufficient query credits, please upgrade your api plan or wait for the "
                         "monthly limit to reset"}),
}


#: measured words for "I have no data", which is coverage, not failure. Exact match, as above.
_EMPTY_REASONS = {
    # without this, "not in Shodan" — the ordinary case for most IPs — reports as a lane failure
    "shodan": frozenset({"no information available for that ip."}),
}


def _norm_reason(reason: str) -> str:
    return " ".join((reason or "").split()).strip().lower()


def is_measured_empty(provider: str, reason: str) -> bool:
    """True when the provider said it has no data, in words we have measured.

    Any other body under the same status stays a failure."""
    return _norm_reason(reason) in _EMPTY_REASONS.get(provider, frozenset())


def classify_provider_reason(provider: str, reason: str) -> str:
    """Map a provider's own failure reason to a taxonomy class. Only the measured exhaustion strings become
    PROVIDER_QUOTA; everything else is PROVIDER_ERROR with the reason preserved verbatim.
    """
    if _norm_reason(reason) in _QUOTA_REASONS.get(provider, frozenset()):
        return PROVIDER_QUOTA
    return PROVIDER_ERROR


def whoxy_envelope(doc, *, provider: str = "whoxy"):
    """Validate Whoxy's status envelope, raising ProviderBodyError on a reported failure.

    `status` is the authority, not the presence of a results key, and success must be an exact int 1
    with the documented result shape."""
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


#: keeps the conversion inside CPython's int-from-string limit, so the result never depends on how the
#: interpreter is configured
_WHOXY_TOTAL_MAX_DIGITS = 15


def whoxy_total(value):
    """Whoxy's `total_results` as an exact non-negative int, or None when unusable.

    The type varies by value: `0` is an int, a non-empty total is a string. Only a canonical ASCII
    decimal is accepted, and `"0"` is not — an unmeasured shape must not take the empty path."""
    if isinstance(value, bool):
        return None                                  # bool is an int subclass; `True` is not a count
    if isinstance(value, int):
        return value if value >= 0 else None
    if not isinstance(value, str) or not value:
        return None
    if any(c not in "0123456789" for c in value):     # no sign, space, separator or Unicode digit
        return None
    if value[0] == "0":                               # "0" is the canonical int form; "007" is drift
        return None
    if len(value) > _WHOXY_TOTAL_MAX_DIGITS:
        return None
    return int(value)


def whoxy_reverse_rows(doc, *, provider: str = "whoxy") -> list:
    """A validated reverse-whois result list -> [domain, ...].

    Fails closed: a success body with no results key is drift, not an empty answer. Cardinality is
    checked against `total_results`, since a short page is paginated."""
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
        # a path- or URL-shaped name would become an apex CANDIDATE, so use the strict canonicaliser
        canon = normalize.canon_host_strict(name) if isinstance(name, str) else None
        if not canon or "." not in canon:
            raise ProviderBodyError(PROVIDER_PARSE, f"result row has no usable domain_name ({name!r})",
                                    provider)
        out.append(canon)
    return out


def whoxy_reverse_page(doc, *, param: str, value: str, provider: str = "whoxy",
                       page: int = 1) -> tuple:
    """-> (rows, total_results, truncated). `truncated` means more matches than this page holds.

    `param`/`value` and `page` bind the response to the request we made, and are required: a
    zero-result body has nothing else identifying it, and an unchecked position accepts page 2 for a
    page-1 request."""
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
    # EXACTLY TWO empty shapes are accepted, and nothing between them: anything wider lets a body we
    # have never measured take the clean-empty path.
    if total == 0:
        sr, dl = doc.get("search_result"), doc.get("domainsList")
        cur, pages = doc.get("current_page"), doc.get("total_pages")
        # a zero count with actual rows is contradictory in EITHER supported carrier
        for name, v in (("search_result", sr), ("domainsList", dl)):
            if v is not None and (not isinstance(v, list) or v):
                raise ProviderBodyError(PROVIDER_PARSE,
                                        f"total_results is 0 but {name} carries rows", provider)
        # membership, not `.get()`: a present-but-null key is a malformed presence, not an absence
        has_carrier = "search_result" in doc or "domainsList" in doc
        has_paging = "current_page" in doc or "total_pages" in doc
        if not has_carrier and not has_paging:
            # SHAPE A — the compact empty. It carries no page identity, so it can only answer page 1;
            # accepting it later would complete a page we never received.
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
        # an unrecognised shape fails closed rather than guessing which half to trust
        raise ProviderBodyError(PROVIDER_PARSE,
                                "zero-result body is neither the compact empty shape nor a fully paged "
                                f"empty (search_result={sr!r} domainsList={dl!r} "
                                f"current_page={cur!r} total_pages={pages!r})", provider)
    rows = whoxy_reverse_rows(doc, provider=provider)
    # an absent or garbled cardinality is drift, not "no claim to check" — fail closed
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
    """Emit the source's terminal event. Called from a finally, so a raise still terminates
    the lane (res None -> synthetic FAILED)."""
    if res is None:
        events.tool_finish(source_id, status=Status.FAILED.value, reason="execution raised before a result",
                           work_unit=work_unit, parent_id=parent_id, scope_distance=scope_distance,
                           discovery_context=discovery_context)
        return
    raw_ref = str(res.raw_path) if res.raw_path else None
    # runs in the finally that guarantees a terminal: a throw here would defeat it
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
    """Contract bracket for an in-process provider -> fn()'s result, or None on failure.

    The provider must not swallow its own errors: a failure recorded as a clean EMPTY would let resume
    treat it as done. A FAILED terminal carries an `error_class`."""
    if not _provider_start(source_id, work_unit=work_unit, input_total=input_total):
        return None
    return _provider_terminal(source_id, fn, work_unit=work_unit)


class ProviderSkip(Exception):
    """A lane that did not run and did not fail. Still needs a lifecycle, or the previous
    run's terminal stands as current."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _partial_status(error_class, limited: bool) -> str:
    """The one precedence for an incomplete provider result. Gaps dominate limits.

      1. a non-limit error_class            -> PARTIAL
      2. a proven limit or operator bound   -> LIMITED
      3. otherwise                          -> PARTIAL"""
    if error_class and not is_provider_limit(error_class):
        return Status.PARTIAL.value
    if is_provider_limit(error_class) or limited:
        return Status.LIMITED.value
    return Status.PARTIAL.value


def terminal_is_limit(status, error_class) -> bool:
    """Whether a provider terminal is a soft limit rather than a gap.

    Fail closed: the status decides and the class may only disqualify, because either signal alone can
    launder a failure into `complete_with_limits`."""
    if status != Status.LIMITED.value:
        return False
    return not error_class or is_provider_limit(error_class)


def _partial_coverage_kind(error_class, limited: bool) -> str:
    """Whose boundary truncated a paginating provider.

    Read from the class and the operator bound, never the status — that would blame every limit on the
    provider."""
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
        # a refused lane still needs a lifecycle: a missing lane reads as "nobody ran it"
        from . import campaign as _campaign
        why = _campaign.acquisition_allowed(source_id)[1]
        events.tool_blocked(source_id, reason=why)
        reset = events.mark_provider_generation(source_id)
        events.tool_start(source_id, input_total=input_total, work_unit=work_unit, provider=True,
                          reset_generation=reset)
        # the coverage generation moves with it, or the lane reports both "skipped" and "omitted"
        events.coverage_reset(source_id)
        events.tool_finish(source_id, status=Status.SKIPPED.value, reason=why, work_unit=work_unit,
                           provider=True)
        return False
    # stamped on the START, which persists first: a crash still supersedes the prior generation
    reset_gen = events.mark_provider_generation(source_id)   # first terminal per source per session
    events.tool_start(source_id, input_total=input_total, work_unit=work_unit,
                      provider=True, reset_generation=reset_gen)
    if reset_gen:
        # opened together, or last session's counter still stands when this run emits none
        events.coverage_reset(source_id)
    return True


def run_providers(entries, shared):
    """Bracket several provider lanes around one shared body -> {source_id: result or None}.

    Every lane starts before the body runs: the body spends, so an interruption must leave a lifecycle
    behind. A raise from `shared` fails every started lane."""
    live = [(sid, wu, fin) for sid, wu, fin in entries
            if _provider_start(sid, work_unit=wu)]
    if not live:
        # the body SPENDS: running it for no lane buys pages nobody will report
        return {}
    cancel = failed = None
    try:
        shared()
    except (KeyboardInterrupt, SystemExit) as e:
        cancel = e
    except Exception as e:
        # best-effort, as in `run_provider`: recorded, not propagated. Only cancellation escapes.
        failed = e
    results: dict = {}
    # fixed before the loop: only a SHARED failure kills every lane. One finalizer's cancellation
    # must not be replayed into the others, whose results are already computed.
    dead = cancel if cancel is not None else failed
    for sid, wu, fin in live:
        body = fin if dead is None else (lambda e=dead: (_ for _ in ()).throw(e))
        try:
            results[sid] = _provider_terminal(sid, body, work_unit=wu)
        except BaseException as e:
            # this lane's terminal is written; re-raising now would leave later lanes started
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
                # a proven limit stays LIMITED on whichever page it struck
                status = _partial_status(error_class, result.limited)
                reason = (f"pagination TRUNCATED at {result.pages} page(s), cursor={result.cursor!r}"
                          + (f" — {error_class} on a later page (earlier pages KEPT)" if error_class else ""))
            elif result.partial:                            # a GENERIC degraded partial, not pagination
                error_class = result.error_class
                # a partial caused by a provider LIMIT is not degradation either
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
        # a body-proven class wins: the type mapping would flatten it to `error`
        error_class = provider_error_class(e)
        # a proven limit is neither failed nor degraded: the run was clean and a third party cut it
        if is_provider_limit(error_class):
            status = Status.LIMITED.value
    finally:
        # a finally, so a terminal fires on cancellation too and no lane is left permanently started
        if is_pagination:
            # emitted every run (omitted=0 when complete), so a clean rerun clears a prior truncation
            truncated = status in (Status.PARTIAL.value, Status.LIMITED.value)
            # the kind records WHOSE boundary stopped us: provider limit, a page lost in flight, or
            # our own configured ceiling — the only one of the three that is ours

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
    """The acquisition gate, consulted by all three provider doors.

    A closed lane records a SKIP with its cause rather than a silent absence."""
    from . import campaign
    allowed, why = campaign.acquisition_allowed(source_id)
    if allowed:
        return True
    if announce:
        events.tool_blocked(source_id, reason=why)
    return False


def registered(source_id: str) -> bool:
    """Whether this source may execute, emitting `tool_blocked` when it may not.

    A lane running several units under one lifecycle brackets itself and asks this for the same gate."""
    if sources.get(source_id) is not None:
        return True
    events.tool_blocked(source_id, reason=f"unknown source_id {source_id!r} — not in registry; not executed")
    return False


def run_contract(source_id, cmd, *, input_total=None, env=None, reclassify=None, work_unit=None,
                 parent_id=None, scope_distance=None, discovery_context=None,
                 **run_kwargs):
    """Run a source under its registry contract -> the (reclassified) RunResult.

    `reclassify` runs before the terminal event, so it carries the final status. `run_kwargs` pass
    through to runner.run. Additive: the phase still records the result itself."""
    # no tool runs outside a contract: an unknown source_id never reaches runner.run
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
