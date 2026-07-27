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

import hashlib
import json
import os
import time
from pathlib import Path

from . import secrets


# ── C07 increment 3: stable work-unit identity (the resume key) ───────────────────────────────────────
# A work_unit identifies ONE unit of a source's work across runs so C10b resume can skip only genuinely
# completed units. Target identity ALONE is insufficient: a completed unit must NOT be skipped after a
# coverage-affecting change (a wider wordlist, a new rate, a changed input file, a parser upgrade). So the
# unit is a hash over a VERSIONED CANONICAL ENVELOPE binding all of those — change any, get a new unit.
_WORKUNIT_ENVELOPE_VERSION = 2       # review#10: v2 widens the key to 128-bit (see work_unit truncation)


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
    """Stable work-unit id = short sha256 over a versioned canonical envelope:
      - source_id      — the lane
      - inputs         — normalized SEMANTIC inputs (origin URL, apex, sorted host/port set) — NOT loop index
      - config         — coverage-affecting configuration (wordlist name, ports, recursion depth, mode, rate)
      - file_digests   — {label: sha256} of coverage-affecting input files (see file_digest)
      - schema_version — the adapter's output-schema version (a parser change invalidates old units)
    Deterministic across runs; any coverage-affecting change flips the id so resume can't skip stale work."""
    envelope = {
        "v": _WORKUNIT_ENVELOPE_VERSION,
        "source_id": source_id,
        "inputs": inputs,
        "config": config,
        "file_digests": file_digests or {},
        "schema": schema_version,
    }
    blob = json.dumps(envelope, sort_keys=True, separators=(",", ":"), default=str)
    # review#10: 128-bit, not 64-bit. This is a resume key across EVERY lane — a collision makes C10b skip
    # DIFFERENT work as already-done. 64 bits (16 hex) hits a ~2^32 birthday bound; 128 bits (32 hex) is
    # collision-free for any realistic unit count, and the full digest is free to compute.
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]

# The event types. LEDGER is its OWN type (was a tool_finish-class update, which gave a source TWO
# terminal-shaped events and broke the exactly-one-terminal invariant); coverage_reset marks a coverage
# generation boundary.
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
_coverage_seen: set = set()             # source_ids that emitted a coverage unit THIS session (for the snapshot)
_provider_seen: set = set()             # source_ids whose provider terminal opened a generation THIS session
# C11: in-memory record of event-sink write failures THIS session. Best-effort is preserved (a log-write
# failure never crashes the run), but the loss is no longer SILENT — it's surfaced in the manifest as
# `observability_degraded` so a run built on an incomplete events.jsonl is a recorded fact, not a clean lie.
_degraded: dict = {"writes_failed": 0, "first_error": None}


def _fresh_degraded() -> dict:
    return {"writes_failed": 0, "first_error": None}


def _degraded_path() -> "Path | None":
    return (_sink.parent / "events.degraded.json") if _sink is not None else None


def _load_degraded() -> dict:
    """Load the ACCUMULATED degradation record persisted by a prior session (so a resume inherits it).
    Fresh {writes_failed:0} when absent/unreadable."""
    p = _degraded_path()
    if p and p.exists():
        try:
            v = json.loads(p.read_text())
            if isinstance(v, dict) and "writes_failed" in v:
                return {"writes_failed": int(v["writes_failed"]), "first_error": v.get("first_error")}
        except (OSError, json.JSONDecodeError, ValueError, TypeError):
            pass
    return _fresh_degraded()


def persist_degraded() -> None:
    """ATOMICALLY write the accumulated degradation record so the NEXT resume inherits it (review#6). Called
    from emit() the instant a write first fails (review#4: crash-durable — not deferred to manifest time) AND
    at manifest time. Best-effort — if this write fails, the in-memory record still reflects the session."""
    p = _degraded_path()
    if p is None:
        return
    try:
        tmp = p.with_name(p.name + ".tmp")
        tmp.write_text(json.dumps(_degraded))
        os.replace(tmp, p)                                  # atomic: a crash mid-write can't leave a torn file
    except OSError:
        pass


def configure(run_dir) -> Path:
    """Point the sink at ``<run_dir>/events.jsonl`` (created if missing). Idempotent; returns path.
    Clears the per-session coverage-snapshot guard so this process's first coverage unit per source opens a
    FRESH generation — a resume (new process APPENDING to the same events.jsonl) thereby supersedes the prior
    run's units, so a capped unit that DISAPPEARS on rerun no longer leaves a stale gap. LOADS the persisted
    degradation record (review#6: a resume ACCUMULATES it, so a run whose prior session lost events can never
    be recorded clean)."""
    global _sink, _coverage_seen, _provider_seen, _degraded
    _sink = Path(run_dir) / "events.jsonl"
    _sink.parent.mkdir(parents=True, exist_ok=True)
    _coverage_seen = set()
    _provider_seen = set()
    _degraded = _load_degraded()
    return _sink


def reset() -> None:
    """Detach the sink (tests / between runs). emit() then returns records without persisting."""
    global _sink, _coverage_seen, _provider_seen, _degraded
    _sink = None
    _coverage_seen = set()
    _provider_seen = set()
    _degraded = _fresh_degraded()


def observability_degraded() -> dict | None:
    """C11: non-None when >=1 event write FAILED this session — the events.jsonl is INCOMPLETE, so any
    coverage/verdict folded from it is provisional. Returns {writes_failed, first_error}; None when clean.
    The manifest reads this so a silent telemetry loss becomes a recorded fact."""
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
        except Exception as e:
            # C11: best-effort — never break a recon run — but RECORD the loss (was silently swallowed).
            _degraded["writes_failed"] += 1
            if _degraded["first_error"] is None:
                _degraded["first_error"] = f"{type(e).__name__}: {e}"
            persist_degraded()   # review#4: crash-durable — persist the marker NOW, not only at manifest time
    return rec


def tool_start(source_id, *, cmd=None, env=None, input_total=None, work_unit=None,
               workers=None, rate=None, timeout=None, provider=None, reset_generation=None,
               parent_id=None, scope_distance=None, discovery_context=None) -> dict:
    """Emitted before a source runs. cmd/env (like all fields) are redacted at the sink; workers/rate/
    timeout are the PLANNED contract values (from the registry). ``work_unit`` (C07 inc 3) is the stable
    resume key for a looped/grouped lane. ``provider``/``reset_generation`` (review-r5#1): an in-process
    provider stamps its generation reset on the START (persisted BEFORE execution) so a crash between start and
    terminal still supersedes the prior generation — and a start with no matching terminal reads as INCOMPLETE
    (a gap), never the prior generation's success. Provenance rides along for v0.4."""
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
    """OPTIONAL progress — every field is optional and None-dropped. Modes (use only what is REAL):
    input_total/current_index (countable inputs) · chunk_index/chunk_total (chunked) ·
    elapsed/rss/artifact_size/last_output_at (opaque long-runners) · queued/running/done (true queues).
    Do NOT invent a queue triple for a tool that has none."""
    return emit(TOOL_PROGRESS, source_id,
                input_total=input_total, current_index=current_index, work_unit=work_unit,
                chunk_index=chunk_index, chunk_total=chunk_total,
                elapsed=elapsed, rss=rss, artifact_size=artifact_size, last_output_at=last_output_at,
                queued=queued, running=running, done=done)


def tool_finish(source_id, *, status=None, reason=None, duration=None, exit_code=None, work_unit=None,
                rss=None, cpu_s=None, raw_ref=None, artifact_size=None,
                produced=None, consumed=None, fallback=None, error_class=None, provider=None,
                reset_generation=None, parent_id=None, scope_distance=None, discovery_context=None) -> dict:
    """Emitted after a source finishes. produced/consumed are absent unless the caller passes REAL
    parser/store counts (never guessed here). raw_ref/artifact_size point at the persisted output.
    ``work_unit`` (C07 inc 3) ties this terminal to the same stable unit as its tool_start (resume key).
    ``error_class`` (C06) tags a FAILED terminal as auth/quota/transport/parse/server/error so a consumer can
    tell a real failure from 'nothing found' and pick retry/backoff — never guessed, only set on a failure.
    ``provider`` (C06) marks an IN-PROCESS provider terminal (run_provider) — providers never hit _tool_runs,
    so the verdict reads their terminals from the event log; the flag lets it fold them without double-counting
    a subprocess lane's tool_finish."""
    return emit(TOOL_FINISH, source_id, status=status, reason=reason, duration=duration,
                exit_code=exit_code, work_unit=work_unit, rss=rss, cpu_s=cpu_s,
                raw_ref=raw_ref, artifact_size=artifact_size,
                produced=produced, consumed=consumed, fallback=fallback, error_class=error_class,
                provider=provider, reset_generation=reset_generation,
                parent_id=parent_id, scope_distance=scope_distance,
                discovery_context=discovery_context)


def artifact_written(source_id, *, path=None, count=None, artifact_size=None) -> dict:
    """A source persisted an artifact (raw file / normalized entity batch)."""
    return emit(ARTIFACT_WRITTEN, source_id,
                path=str(path) if path is not None else None, count=count, artifact_size=artifact_size)


# kinds of coverage shortfall — they reconcile into the run verdict DIFFERENTLY (see store._run_summary):
COVERAGE_SAMPLE = "sample"    # operator-CHOSEN subset: a soft LIMIT (complete_with_limits), never a gap
COVERAGE_PROVIDER = "provider"  # an EXTERNAL provider LIMIT (credits spent / plan) truncated the input: a soft
                              # LIMIT like sample, NOT a gap — nothing here failed and there is nothing to
                              # retry in this run. review-B0r4#1: emitting COVERAGE_CAP for a later-page
                              # quota called the provider's boundary "a hard ceiling of OURS", so a
                              # depletion produced complete_with_gaps.
COVERAGE_CAP = "cap"          # a hard ceiling truncated eligible input: a gap whenever omitted>0 (10%/100 = priority only)
COVERAGE_TIMEOUT = "timeout"  # input the TARGET/network cost us — a per-item timeout, an error-driven skip (e.g.
                              # nuclei -mhe dropping a host after N request errors), a deps-fail: ALWAYS feeds
                              # the verdict. The name is narrower than the bucket; the bucket is "not our
                              # ceiling, not the operator's choice — it was lost in flight".
COVERAGE_UNKNOWN = "unknown"  # the source RAN but its coverage is UNMEASURABLE (stats missing/corrupt). Carries NO
                              # counters, so it is never summed — it forces coverage_valid=False, which the verdict
                              # reads as a GAP. Unmeasured must never be indistinguishable from fully covered.


def mark_provider_generation(source_id) -> bool:
    """review-r4#3: True the FIRST time a provider terminal is emitted for `source_id` THIS session. run_provider
    stamps that terminal reset_generation=True so the verdict supersedes this source's PRIOR-session terminals
    (a changed work_unit / retry no longer leaves a stale failure gating the run) — the terminal analog of a
    coverage generation. Cleared by configure()/reset()."""
    if source_id in _provider_seen:
        return False
    _provider_seen.add(source_id)
    return True


def coverage_reset(source_id) -> dict:
    """Open a new coverage GENERATION for a source. Reconciliation ignores this source's units emitted
    BEFORE the latest reset, so a unit that disappears on rerun (e.g. a per-host ffuf unit whose host is
    gone) is superseded instead of leaving a stale gap. Auto-emitted by the first coverage_partial per
    source per session; callers rarely need it directly."""
    return emit(COVERAGE_RESET, source_id)


def coverage_partial(source_id, *, reason=None, produced=None,
                     eligible=None, tested=None, omitted=None, kind=None, unit=None, measure=None) -> dict:
    """Ran but did not fully cover its input (timeout, deps-fail, a hard cap, a designed sample, or an
    external PROVIDER limit).

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

    ``kind=COVERAGE_UNKNOWN`` is the FIRST-CLASS "ran but unmeasurable" record: it carries no counters yet is
    still a STRUCTURED unit — it opens a generation and reaches the rollup. Without that, an unmeasurable unit
    was a reason-only event, which (a) the rollup skipped entirely, so a first run with no stats read as fully
    covered, and (b) did not reset, so a PRIOR run's counters kept standing in for it. Both made unmeasured
    indistinguishable from complete.
    """
    structured = eligible is not None or kind == COVERAGE_UNKNOWN
    # Auto-open a generation for STRUCTURED coverage only. A legacy reason-only partial must not reset — it
    # carries no replacement counters, so resetting would wrongly clear the real prior units.
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
    """Stopped by the target (WAF / rate-limit / forbidden) — not a genuine empty."""
    return emit(TOOL_BLOCKED, source_id, reason=reason)


def ledger(source_id, *, produced=None, consumed=None, **extra) -> dict:
    """Report REAL produced/consumed counts from the parser/store layer (BBOT scan-stats analog =
    the review-4992 answer). Counts come from the caller's parse/store step, NEVER from stdout.
    Emitted as a tool_finish-class update tagged ``ledger`` so a scan-stats view can aggregate it.
    ``extra`` keyword fields (e.g. 4.3.A's reduction_percent / top_collapsed) ride along on the same
    ledger event so the reduction stays one clear record. Emitted as its OWN LEDGER event (NOT a second
    tool_finish) so a source has exactly one terminal."""
    return emit(LEDGER, source_id, produced=produced, consumed=consumed, **extra)
