"""Structured run events — the control-plane RECORD (v0.3 stabilization, step 2).

Appends one JSON object per line to ``<run>/events.jsonl``. This file is the record; a console
renderer / ``quarry status`` / a messenger read FROM it — we never scrape terminal text. Mirrors
BBOT's control SUBSTRATE (typed events + a Produced/Consumed ledger, its ``scan-stats``), NOT BBOT's
runtime UI: Quarry stays clean and Quarry-style, no 15s module-list dumps.

Additive + declarative: no phase imports this yet, so there is NO behavior change (same safety as
step 1's registry). ``contract.run_contract`` and, later, chunked danger-tools emit through it.

Design rules encoded here:
- ``emit`` DROPS any optional field whose value is None — no fake precision (a tool that cannot report
  a queue triple simply does not carry those fields).
- EVERY event field is redacted via the proven ``secrets.redact`` at the sink before it touches disk —
  not just cmd/env, but reason/fallback/discovery_context/paths/produced/consumed too, since any of
  them can later carry a secret.
- produced/consumed are NEVER computed here from stdout; ``ledger()`` carries REAL parser/store counts
  that a phase passes in explicitly.
- Best-effort: a sink failure never breaks a run (recon must not die because a log write failed).
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from . import secrets

# The event types (the ledger rides on a tool_finish-class update, see ledger(); coverage_reset marks a
# coverage generation boundary).
TOOL_START = "tool_start"
TOOL_PROGRESS = "tool_progress"
TOOL_FINISH = "tool_finish"
ARTIFACT_WRITTEN = "artifact_written"
COVERAGE_PARTIAL = "coverage_partial"
TOOL_BLOCKED = "tool_blocked"
COVERAGE_RESET = "coverage_reset"       # generation boundary: units of a source before it are a STALE snapshot
EVENT_TYPES = (TOOL_START, TOOL_PROGRESS, TOOL_FINISH,
               ARTIFACT_WRITTEN, COVERAGE_PARTIAL, TOOL_BLOCKED, COVERAGE_RESET)

_sink: Path | None = None
_coverage_seen: set = set()             # source_ids that emitted a coverage unit THIS session (for the snapshot)


def configure(run_dir) -> Path:
    """Point the sink at ``<run_dir>/events.jsonl`` (created if missing). Idempotent; returns path.
    Clears the per-session coverage-snapshot guard so this process's first coverage unit per source opens a
    FRESH generation — a resume (new process appending to the same events.jsonl) thereby supersedes the prior
    run's units, so a capped unit that DISAPPEARS on rerun no longer leaves a stale gap."""
    global _sink, _coverage_seen
    _sink = Path(run_dir) / "events.jsonl"
    _sink.parent.mkdir(parents=True, exist_ok=True)
    _coverage_seen = set()
    return _sink


def reset() -> None:
    """Detach the sink (tests / between runs). emit() then returns records without persisting."""
    global _sink, _coverage_seen
    _sink = None
    _coverage_seen = set()


def _redact(v):
    """Defensively redact known secrets from strings, recursing into lists/dicts. Non-secret text is
    returned unchanged — secrets.redact only masks CONFIGURED keys/values (same call notify.py uses)."""
    if isinstance(v, str):
        return secrets.redact(v)
    if isinstance(v, (list, tuple)):
        return [_redact(x) for x in v]
    if isinstance(v, dict):
        return {k: _redact(x) for k, x in v.items()}
    return v


def emit(event: str, source_id: str, **fields) -> dict:
    """Append one event. Fields with value None are omitted (no fabricated precision). EVERY field is
    redacted at this sink (secrets never reach disk regardless of which field carried them). Every
    event carries ``ts`` and ``source_id``. Best-effort write; returns the record (also used by tests)."""
    rec = {"ts": round(time.time(), 3), "event": event, "source_id": source_id}
    for k, val in fields.items():
        if val is not None:
            rec[k] = _redact(val)
    if _sink is not None:
        try:
            # explicit utf-8 (events carry redacted UTF-8 payloads; Windows would else default to cp)
            with _sink.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, default=str, ensure_ascii=False) + "\n")
        except Exception:
            pass  # a log failure must never break a recon run
    return rec


def tool_start(source_id, *, cmd=None, env=None, input_total=None,
               workers=None, rate=None, timeout=None,
               parent_id=None, scope_distance=None, discovery_context=None) -> dict:
    """Emitted before a source runs. cmd/env (like all fields) are redacted at the sink; workers/rate/
    timeout are the PLANNED contract values (from the registry). Provenance rides along for v0.4."""
    return emit(TOOL_START, source_id,
                cmd=list(cmd) if cmd is not None else None,
                env=dict(env) if env else None,
                input_total=input_total, workers=workers, rate=rate, timeout=timeout,
                parent_id=parent_id, scope_distance=scope_distance, discovery_context=discovery_context)


def tool_progress(source_id, *, input_total=None, current_index=None,
                  chunk_index=None, chunk_total=None,
                  elapsed=None, rss=None, artifact_size=None, last_output_at=None,
                  queued=None, running=None, done=None) -> dict:
    """OPTIONAL progress — every field is optional and None-dropped. Modes (use only what is REAL):
    input_total/current_index (countable inputs) · chunk_index/chunk_total (chunked) ·
    elapsed/rss/artifact_size/last_output_at (opaque long-runners) · queued/running/done (true queues).
    Do NOT invent a queue triple for a tool that has none."""
    return emit(TOOL_PROGRESS, source_id,
                input_total=input_total, current_index=current_index,
                chunk_index=chunk_index, chunk_total=chunk_total,
                elapsed=elapsed, rss=rss, artifact_size=artifact_size, last_output_at=last_output_at,
                queued=queued, running=running, done=done)


def tool_finish(source_id, *, status=None, reason=None, duration=None, exit_code=None,
                rss=None, cpu_s=None, raw_ref=None, artifact_size=None,
                produced=None, consumed=None, fallback=None,
                parent_id=None, scope_distance=None, discovery_context=None) -> dict:
    """Emitted after a source finishes. produced/consumed are absent unless the caller passes REAL
    parser/store counts (never guessed here). raw_ref/artifact_size point at the persisted output."""
    return emit(TOOL_FINISH, source_id, status=status, reason=reason, duration=duration,
                exit_code=exit_code, rss=rss, cpu_s=cpu_s, raw_ref=raw_ref, artifact_size=artifact_size,
                produced=produced, consumed=consumed, fallback=fallback,
                parent_id=parent_id, scope_distance=scope_distance, discovery_context=discovery_context)


def artifact_written(source_id, *, path=None, count=None, artifact_size=None) -> dict:
    """A source persisted an artifact (raw file / normalized entity batch)."""
    return emit(ARTIFACT_WRITTEN, source_id,
                path=str(path) if path is not None else None, count=count, artifact_size=artifact_size)


# kinds of coverage shortfall — they reconcile into the run verdict DIFFERENTLY (see store._run_summary):
COVERAGE_SAMPLE = "sample"    # operator-CHOSEN subset: a soft LIMIT (complete_with_limits), never a gap
COVERAGE_CAP = "cap"          # a hard ceiling truncated eligible input: a gap whenever omitted>0 (10%/100 = priority only)
COVERAGE_TIMEOUT = "timeout"  # per-item timeout/deps-fail skipped input: ALWAYS feeds the verdict


def coverage_reset(source_id) -> dict:
    """Open a new coverage GENERATION for a source. Reconciliation ignores this source's units emitted
    BEFORE the latest reset, so a unit that disappears on rerun (e.g. a per-host ffuf unit whose host is
    gone) is superseded instead of leaving a stale gap. Auto-emitted by the first coverage_partial per
    source per session; callers rarely need it directly."""
    return emit(COVERAGE_RESET, source_id)


def coverage_partial(source_id, *, reason=None, produced=None,
                     eligible=None, tested=None, omitted=None, kind=None, unit=None, measure=None) -> dict:
    """Ran but did not fully cover its input (timeout, deps-fail, a hard cap, a designed sample).

    Carries structured COUNTERS when the site can count them (None-dropped otherwise, so the legacy
    timeout callers that pass only ``reason`` are unchanged):
      - ``eligible`` — countable inputs the source COULD have processed (compute AFTER scope/active gating,
                       so a passive-skipped source never reports phantom `tested`)
      - ``tested``   — how many it actually processed
      - ``omitted``  — eligible - tested (derived when omitted is None)
      - ``kind``     — COVERAGE_SAMPLE / COVERAGE_CAP / COVERAGE_TIMEOUT. VERDICT policy (truth, not a
                       threshold): a CAP or TIMEOUT with omitted>0 is a gap regardless of fraction; an
                       operator SAMPLE is a soft limit; the 10%/100 rule is only a major/minor PRIORITY.
      - ``unit``     — a STABLE id for the capping unit (default = source_id). Reconciliation keeps only the
                       LATEST record per (source_id, unit); emit EVERY run (omitted=0 when uncapped) so a
                       later uncapped rerun clears a prior cap.
      - ``measure``  — WHAT is being counted (files / hosts / result_rows / …). Counters are aggregated ONLY
                       within the same (source_id, measure) — files and params are NEVER summed together.

    Counters are validated: non-negative ints with ``tested + omitted == eligible``. An inconsistent triple
    is flagged ``coverage_valid=False`` so the verdict treats it as UNKNOWN (a gap), never fake completion.
    """
    # Auto-open a generation ONLY for STRUCTURED coverage (eligible given). A legacy reason-only partial must
    # not reset — it carries no replacement counters, so resetting would wrongly clear the real prior units.
    if eligible is not None and source_id not in _coverage_seen:
        _coverage_seen.add(source_id)
        coverage_reset(source_id)
    coverage_valid = None
    if eligible is not None:
        try:
            eligible = int(eligible)
            tested = int(tested) if tested is not None else 0
            omitted = int(omitted) if omitted is not None else eligible - tested
            coverage_valid = (eligible >= 0 and tested >= 0 and omitted >= 0
                              and tested + omitted == eligible)
        except (TypeError, ValueError):
            coverage_valid = False
    return emit(COVERAGE_PARTIAL, source_id, reason=reason, produced=produced,
                eligible=eligible, tested=tested, omitted=omitted, kind=kind,
                unit=unit if unit is not None else (source_id if eligible is not None else None),
                measure=measure, coverage_valid=coverage_valid)


def tool_blocked(source_id, *, reason=None) -> dict:
    """Stopped by the target (WAF / rate-limit / forbidden) — not a genuine empty."""
    return emit(TOOL_BLOCKED, source_id, reason=reason)


def ledger(source_id, *, produced=None, consumed=None, **extra) -> dict:
    """Report REAL produced/consumed counts from the parser/store layer (BBOT scan-stats analog =
    the review-4992 answer). Counts come from the caller's parse/store step, NEVER from stdout.
    Emitted as a tool_finish-class update tagged ``ledger`` so a scan-stats view can aggregate it.
    ``extra`` keyword fields (e.g. 4.3.A's reduction_percent / top_collapsed) ride along on the same
    ledger event so the reduction stays one clear record."""
    return emit(TOOL_FINISH, source_id, produced=produced, consumed=consumed, ledger=True, **extra)
