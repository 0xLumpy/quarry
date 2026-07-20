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

from . import events, sources
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


def classify_provider_error(exc) -> str:
    """C06: map an in-process provider exception to an EXPLICIT class so a consumer can tell a real failure
    from 'nothing found' and pick the right response (auth → stop, quota → backoff, transport → retry). A
    coarse, HTTP-aware taxonomy over stdlib urllib — never a guess, only a mapping of the raised type."""
    if isinstance(exc, _urlerr.HTTPError):
        code = getattr(exc, "code", None)
        if code in (401, 403):
            return "auth"                                    # bad/missing key, forbidden — do not retry
        if code == 429:
            return "quota"                                   # rate/quota exhausted — back off
        if code is not None and 500 <= code < 600:
            return "server"                                  # upstream 5xx — transient, retryable
        return "http"                                        # other 4xx
    if isinstance(exc, (_urlerr.URLError, _socket.timeout, TimeoutError, ConnectionError, OSError)):
        return "transport"                                   # DNS/connect/timeout — retryable
    if isinstance(exc, (_json.JSONDecodeError, ValueError)):
        return "parse"                                       # malformed/schema-drift body
    return "error"                                           # unclassified


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
                status = Status.PARTIAL.value
                error_class = result.error_class
                reason = (f"pagination TRUNCATED at {result.pages} page(s), cursor={result.cursor!r}"
                          + (f" — {error_class} on a later page (earlier pages KEPT)" if error_class else ""))
            elif result.partial:                            # review-r4#2: a GENERIC degraded partial (NOT pagination)
                status = Status.PARTIAL.value
                error_class = result.error_class
                reason = result.partial_reason or f"partial result ({error_class or 'degraded'}) — earlier evidence KEPT"
            else:                                            # a complete ProviderResult — a paginating provider
                is_pagination = result.pages is not None     # (only paginating providers carry a completion counter)
                status = Status.SUCCESS.value if n else Status.EMPTY.value
        else:
            status = Status.SUCCESS.value if n else Status.EMPTY.value
    except Exception as e:                                   # ordinary provider error — record FAILED, don't crash phase
        reason, result = f"{type(e).__name__}: {e}", None
        error_class = classify_provider_error(e)            # C06: auth/quota/transport/parse/server/error
    finally:
        # review#7: emit from a finally so a terminal ALSO fires on KeyboardInterrupt/SystemExit (which are NOT
        # `Exception`) — the BaseException then re-raises past this finally, cancelling the run, but the
        # provider is no longer left permanently 'started'. Status stays FAILED for the cancellation case.
        if is_pagination:
            # review-r2#1: a STRUCTURED per-unit completion counter the VERDICT can see. Emitted EVERY run
            # (omitted=0 when complete) so a later complete rerun CLEARS a prior truncation; keyed on work_unit
            # so each apex reconciles alone. Only for PAGINATION outcomes — never for a generic degraded partial.
            truncated = status == Status.PARTIAL.value
            events.coverage_partial(source_id, kind=events.COVERAGE_CAP, measure="pagination",
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
    ok_empty, ok_codes). The event layer is ADDITIVE — the phase still records the RunResult to the
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
