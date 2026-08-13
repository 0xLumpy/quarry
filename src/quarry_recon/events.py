"""Structured run events — the control-plane record.

One JSON object per line in `<run>/events.jsonl`. This file IS the record: `quarry status`, a console
renderer and a messenger read from it, and nothing scrapes terminal text.

Four rules:

  · `emit` drops any optional field that is None — a tool with no queue simply carries no queue fields.
  · every field is redacted at the sink before it touches disk, not only `cmd`/`env`.
  · produced/consumed are never computed here from stdout; `ledger()` carries real parser counts.
  · a sink failure never breaks a run, but it IS recorded (see `observability_degraded`).
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from . import privfs, secrets


# ── work-unit identity (the resume key) ──────────────────────────────────────────────────────────────
# A work unit identifies one unit of a source's work ACROSS RUNS, so resume skips only what genuinely
# completed. Target identity alone is not enough: a wider wordlist, a new rate, a changed input file or
# a parser upgrade must all produce a different unit, so the id hashes a versioned envelope of them.
_WORKUNIT_ENVELOPE_VERSION = 2       # v2 widened the key to 128 bits


def file_digest(path) -> str:
    """sha256 of a coverage-affecting INPUT FILE (wordlist, target list) so a changed file yields a
    different work_unit. Streamed; '' when the file is missing/unreadable (a missing input is itself a
    distinct state, folded into the envelope)."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def work_unit(source_id, *, inputs=None, config=None, file_digests=None, schema_version=1) -> str:
    """Stable work-unit id: a short sha256 over source_id, normalized inputs, coverage-affecting config,
    input-file digests and the adapter's schema version.

    Deterministic across runs, so any coverage-affecting change flips the id and resume cannot skip work
    whose meaning has moved. Inputs are SEMANTIC — never a loop index."""
    envelope = {
        "v": _WORKUNIT_ENVELOPE_VERSION,
        "source_id": source_id,
        "inputs": inputs,
        "config": config,
        "file_digests": file_digests or {},
        "schema": schema_version,
    }
    blob = json.dumps(envelope, sort_keys=True, separators=(",", ":"), default=str)
    # 128 bits, not 64: this keys resume across every lane, and a collision makes a run skip DIFFERENT
    # work as already done. 64 bits hits a ~2^32 birthday bound; the full digest is free to compute.
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]

# Event types. LEDGER is its own type, so a source keeps exactly one terminal-shaped event.
TOOL_START = "tool_start"
TOOL_PROGRESS = "tool_progress"
TOOL_FINISH = "tool_finish"
ARTIFACT_WRITTEN = "artifact_written"
COVERAGE_PARTIAL = "coverage_partial"
TOOL_BLOCKED = "tool_blocked"
COVERAGE_RESET = "coverage_reset"       # generation boundary: units of a source before it are a STALE snapshot
LEDGER = "ledger"                       # REAL produced/consumed counts — NOT a terminal (one per source lifecycle)
EVENT_TYPES = (TOOL_START, TOOL_PROGRESS, TOOL_FINISH,
               ARTIFACT_WRITTEN, COVERAGE_PARTIAL, TOOL_BLOCKED, COVERAGE_RESET, LEDGER)

_sink: Path | None = None
_run = None                           # repository authority for a managed run sink
_coverage_seen: set = set()             # source_ids that emitted a coverage unit THIS session (for the snapshot)
_provider_seen: set = set()             # source_ids whose provider terminal opened a generation THIS session
# event-sink write failures this session. Best-effort is preserved, but the loss is not silent: it
# surfaces as `observability_degraded`, so a run built on an incomplete log is a recorded fact.
_degraded: dict = {"writes_failed": 0, "first_error": None}


def _fresh_degraded() -> dict:
    return {"writes_failed": 0, "first_error": None}


def _degraded_path() -> "Path | None":
    return (_sink.parent / "events.degraded.json") if _sink is not None else None


def _load_degraded() -> dict:
    """Load the ACCUMULATED degradation record persisted by a prior session (so a resume inherits it).
    Fresh {writes_failed:0} when absent/unreadable."""
    p = _degraded_path()
    if p:
        try:
            with os.fdopen(privfs.open_ro_private(p), "r", encoding="utf-8") as fh:   # symlink-safe read
                v = json.loads(fh.read())
            if isinstance(v, dict) and "writes_failed" in v:
                return {"writes_failed": int(v["writes_failed"]), "first_error": v.get("first_error")}
        except (OSError, json.JSONDecodeError, ValueError, TypeError):
            pass
    return _fresh_degraded()


def persist_degraded() -> None:
    """Atomically write the accumulated degradation record, so the next resume inherits it.

    Written the instant a write first fails, not deferred to manifest time: a crash must not take the
    marker with it. Best-effort — the in-memory record still reflects this session either way."""
    p = _degraded_path()
    if p is None:
        return
    try:
        body = json.dumps(_degraded).encode("utf-8")
        if _run is not None:
            from .store import MutationScope
            _run._replace_artifact(MutationScope.BASE_EVIDENCE, ("events.degraded.json",), body)
        else:
            privfs.write_private(p, body.decode("utf-8"))  # legacy non-repository sink
    except Exception:
        pass


def configure(run_dir) -> Path:
    """Point the sink at `<run_dir>/events.jsonl` (created if missing). Idempotent; returns path.

    Opens a fresh coverage generation for this process, so a resume supersedes the prior run's units
    rather than inheriting a gap from one that has since disappeared. Loads the persisted degradation
    record, which ACCUMULATES: a run whose earlier session lost events can never be recorded clean."""
    global _sink, _run, _coverage_seen, _provider_seen, _degraded
    from . import store
    if isinstance(run_dir, store.Run):
        _run = run_dir
        _sink = run_dir.dir / "events.jsonl"
    else:
        _sink = Path(run_dir) / "events.jsonl"
        managed = store.managed_run_for_artifact(_sink)
        _run = managed[0] if managed is not None else None
    if _run is None:
        privfs.private_dir(_sink.parent)         # compatibility sink outside a managed repository
    _coverage_seen = set()
    _provider_seen = set()
    _degraded = _load_degraded()
    return _sink


def reset() -> None:
    """Detach the sink (tests / between runs). emit() then returns records without persisting."""
    global _sink, _run, _coverage_seen, _provider_seen, _degraded
    _sink = None
    _run = None
    _coverage_seen = set()
    _provider_seen = set()
    _degraded = _fresh_degraded()


def observability_degraded() -> dict | None:
    """Non-None when an event write failed this session: the log is incomplete, so any verdict folded
    from it is provisional. The manifest carries it, so telemetry loss is a recorded fact."""
    return dict(_degraded) if _degraded["writes_failed"] else None


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
    """Append one event, dropping None fields and redacting every value. Returns the record."""
    rec = {"ts": round(time.time(), 3), "event": event, "source_id": source_id}
    for k, val in fields.items():
        if val is not None:
            rec[k] = _redact(val)
    if _sink is not None:
        try:
            # 0600 sink (privfs), utf-8 (events carry redacted UTF-8 payloads; Windows would else default to cp)
            line = (json.dumps(rec, default=str, ensure_ascii=False) + "\n").encode("utf-8")
            if _run is not None:
                if _sink != _run.dir / "events.jsonl":
                    raise RuntimeError("managed event sink identity changed")
                _run._append_base_artifact(("events.jsonl",), line)
            else:
                with os.fdopen(privfs.open_private(_sink, append=True), "a", encoding="utf-8") as fh:
                    fh.write(line.decode("utf-8"))
        except Exception as e:
            # best-effort — a log write must not break a run — but the loss is recorded, not swallowed
            _degraded["writes_failed"] += 1
            if _degraded["first_error"] is None:
                _degraded["first_error"] = f"{type(e).__name__}: {e}"
            persist_degraded()   # now, not at manifest time: a crash must not take the marker with it
    return rec


def tool_start(source_id, *, cmd=None, env=None, input_total=None, work_unit=None,
               workers=None, rate=None, timeout=None, provider=None, reset_generation=None,
               parent_id=None, scope_distance=None, discovery_context=None) -> dict:
    """Emitted before a source runs; `work_unit` is the resume key.

    A start with no terminal reads as INCOMPLETE, so a provider stamps its generation reset here."""
    return emit(TOOL_START, source_id,
                cmd=list(cmd) if cmd is not None else None,
                env=dict(env) if env else None,
                input_total=input_total, work_unit=work_unit, workers=workers, rate=rate, timeout=timeout,
                provider=provider, reset_generation=reset_generation,
                parent_id=parent_id, scope_distance=scope_distance, discovery_context=discovery_context)


def tool_progress(source_id, *, input_total=None, current_index=None, work_unit=None,
                  chunk_index=None, chunk_total=None,
                  elapsed=None, rss=None, artifact_size=None, last_output_at=None,
                  queued=None, running=None, done=None) -> dict:
    """Optional progress. Pass only what the tool really reports — never invent a queue triple."""
    return emit(TOOL_PROGRESS, source_id,
                input_total=input_total, current_index=current_index, work_unit=work_unit,
                chunk_index=chunk_index, chunk_total=chunk_total,
                elapsed=elapsed, rss=rss, artifact_size=artifact_size, last_output_at=last_output_at,
                queued=queued, running=running, done=done)


def tool_finish(source_id, *, status=None, reason=None, duration=None, exit_code=None, work_unit=None,
                rss=None, cpu_s=None, raw_ref=None, artifact_size=None, partial_ref=None,
                stderr_partial_ref=None, faults=None,
                produced=None, consumed=None, fallback=None, error_class=None, provider=None,
                reset_generation=None, parent_id=None, scope_distance=None, discovery_context=None) -> dict:
    """The source's terminal event. `partial_ref`/`stderr_partial_ref` reference retained unpublished
    stdout/stderr artifacts, `faults` records the typed faults, and `provider` marks an in-process lane."""
    return emit(TOOL_FINISH, source_id, status=status, reason=reason, duration=duration,
                exit_code=exit_code, work_unit=work_unit, rss=rss, cpu_s=cpu_s,
                raw_ref=raw_ref, artifact_size=artifact_size, partial_ref=partial_ref,
                stderr_partial_ref=stderr_partial_ref, faults=faults,
                produced=produced, consumed=consumed, fallback=fallback, error_class=error_class,
                provider=provider, reset_generation=reset_generation,
                parent_id=parent_id, scope_distance=scope_distance,
                discovery_context=discovery_context)


def artifact_written(source_id, *, path=None, count=None, artifact_size=None) -> dict:
    """A source persisted an artifact (raw file / normalized entity batch)."""
    return emit(ARTIFACT_WRITTEN, source_id,
                path=str(path) if path is not None else None, count=count, artifact_size=artifact_size)


# Kinds of coverage shortfall. They reconcile into the verdict differently: only SAMPLE and PROVIDER
# are soft limits, every other kind gates. Each exists because the wrong label sends an operator to
# the wrong place — see store._run_summary.
COVERAGE_SAMPLE = "sample"               # operator-selected subset; soft limit
COVERAGE_PROVIDER = "provider"           # external provider limit; soft limit
COVERAGE_CAP = "cap"                     # a Quarry ceiling omitted input; gap
COVERAGE_TIMEOUT = "timeout"             # the target or network lost the input; gap
COVERAGE_TOOL_OMISSION = "tool_omission"  # the tool declined input we submitted; gap
COVERAGE_OWNERSHIP = "ownership"         # local ownership state withheld input; gap
COVERAGE_UNKNOWN = "unknown"             # coverage cannot be measured; gap


def mark_provider_generation(source_id) -> bool:
    """True the FIRST time a provider terminal is emitted for `source_id` this session.

    The terminal analog of a coverage generation: it supersedes this source's prior-session terminals, so
    a changed work unit or a retry cannot leave a stale failure gating the run."""
    if source_id in _provider_seen:
        return False
    _provider_seen.add(source_id)
    return True


def coverage_reset(source_id) -> dict:
    """Open a new coverage generation: units emitted before the latest reset are ignored, so one that
    disappears on rerun is superseded rather than left as a stale gap. Auto-emitted per source."""
    return emit(COVERAGE_RESET, source_id)


def coverage_partial(source_id, *, reason=None, produced=None,
                     eligible=None, tested=None, omitted=None, kind=None, unit=None, measure=None) -> dict:
    """Ran but did not fully cover its input.

    Counters are optional and validated: `tested + omitted == eligible`, or `coverage_valid=False` and
    the verdict reads UNKNOWN. `unit` is what reconciliation replaces (latest record per source+unit, so
    emit every run — omitted=0 clears a prior cap); `measure` is what aggregation groups by, so files and
    params are never summed. COVERAGE_UNKNOWN carries no counters and still gates.
    """
    structured = eligible is not None or kind == COVERAGE_UNKNOWN
    # structured coverage only: a reason-only partial carries no replacement counters, so resetting on it
    # would clear the real prior units
    if structured and source_id not in _coverage_seen:
        _coverage_seen.add(source_id)
        coverage_reset(source_id)
    coverage_valid = None
    if kind == COVERAGE_UNKNOWN:
        coverage_valid = False           # unmeasurable is NOT valid coverage; the verdict must read it as a gap
    elif eligible is not None:
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
                unit=unit if unit is not None else (source_id if structured else None),
                measure=measure, coverage_valid=coverage_valid)


def tool_blocked(source_id, *, reason=None) -> dict:
    """A source Quarry's own gate prevented from running (not registered, a guard refusal, acquisition
    closed) — distinct from a genuine empty."""
    return emit(TOOL_BLOCKED, source_id, reason=reason)


def spend(source_id, *, provider: str, measure: str, amount, unit=None) -> dict:
    """What one acquisition lane spent, in the unit it is charged in.

    There is no single number meaning "spend" — Shodan charges query credits, Whoxy sells pages — so the
    MEASURE is part of the record and nothing is summed across measures."""
    return emit("spend", source_id, provider=provider, measure=measure,
                amount=amount if type(amount) is int and amount >= 0 else None, unit=unit)


def ledger(source_id, *, produced=None, consumed=None, **extra) -> dict:
    """Real produced/consumed counts from the caller's parse step. Its own event, not a second
    tool_finish, so a source keeps exactly one terminal."""
    return emit(LEDGER, source_id, produced=produced, consumed=consumed, **extra)
