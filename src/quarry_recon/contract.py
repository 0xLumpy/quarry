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


def run_contract(source_id, cmd, *, input_total=None, env=None,
                 parent_id=None, scope_distance=None, discovery_context=None,
                 **run_kwargs):
    """Run a source under its registry contract, emitting tool_start before and tool_finish after
    ``runner.run``. Returns runner.run's RunResult UNCHANGED.

    ``run_kwargs`` pass straight through to runner.run (raw_path, timeout, stdin_data, input_file,
    ok_empty, ok_codes). ``input_total`` (count of inputs, if the caller knows it) and the provenance
    fields are recorded on the events only — they never alter execution.
    """
    # No tool runs outside a contract. An unknown source_id fails LOUD before execution: emit a
    # blocked event and return a SKIPPED RunResult — the command is never handed to runner.run.
    src = sources.get(source_id)
    if src is None:
        reason = f"unknown source_id {source_id!r} — not in registry; not executed"
        events.tool_blocked(source_id, reason=reason)
        return skipped(source_id, reason)
    tool = src.get("tool") or source_id.split(".", 1)[-1]

    events.tool_start(source_id, cmd=cmd, env=env, input_total=input_total,
                      workers=src.get("workers"), rate=src.get("rate"),
                      timeout=run_kwargs.get("timeout", src.get("timeout")),
                      parent_id=parent_id, scope_distance=scope_distance,
                      discovery_context=discovery_context)

    res = _run(tool, cmd, env=env, **run_kwargs)

    raw_ref = str(res.raw_path) if res.raw_path else None
    artifact_size = None
    if res.raw_path is not None and res.raw_path.exists():
        artifact_size = res.raw_path.stat().st_size

    if res.status == Status.BLOCKED:
        events.tool_blocked(source_id, reason=res.note or "blocked")
    elif res.status in _PARTIAL:
        events.coverage_partial(source_id, reason=res.note or res.status.value)

    events.tool_finish(source_id, status=res.status.value, reason=res.note or None,
                       duration=round(res.duration, 2), exit_code=res.exit_code,
                       rss=res.peak_rss_mb, cpu_s=res.cpu_s,
                       raw_ref=raw_ref, artifact_size=artifact_size,
                       fallback=src.get("fallback"),
                       parent_id=parent_id, scope_distance=scope_distance,
                       discovery_context=discovery_context)
    return res
