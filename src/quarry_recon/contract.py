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

from . import events, sources
from .runner import Status, run as _run, skipped

# Non-clean terminal statuses that warrant a dedicated event before the normal tool_finish.
_PARTIAL = (Status.PARTIAL, Status.TIMED_OUT)


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
    failure the phase still continues (returns None). Returns fn()'s result on success. Finer error
    CLASSIFICATION (auth vs quota vs transport vs parse) is C06."""
    if sources.get(source_id) is None:
        events.tool_blocked(source_id, reason=f"unknown source_id {source_id!r} — not in registry; not executed")
        return None
    events.tool_start(source_id, input_total=input_total, work_unit=work_unit)
    result = None
    status = Status.FAILED.value                             # default: covers a raise BEFORE a result is computed
    reason = n = None
    try:
        result = fn()
        n = len(result) if hasattr(result, "__len__") else None
        status = Status.SUCCESS.value if n else Status.EMPTY.value
    except Exception as e:                                   # ordinary provider error — record FAILED, don't crash phase
        reason, result = f"{type(e).__name__}: {e}", None
    finally:
        # review#7: emit from a finally so a terminal ALSO fires on KeyboardInterrupt/SystemExit (which are NOT
        # `Exception`) — the BaseException then re-raises past this finally, cancelling the run, but the
        # provider is no longer left permanently 'started'. Status stays FAILED for the cancellation case.
        events.tool_finish(source_id, status=status, work_unit=work_unit,
                           reason=reason, produced={"host": n} if n is not None else None)
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
