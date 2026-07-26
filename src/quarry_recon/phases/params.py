"""Phase 7: Params + lightweight scanning (deepened).

gf vuln-class buckets over the URL corpus -> ranked candidate queues; arjun param
discovery; non-intrusive nuclei with built-in interactsh OOB; dalfox XSS/open-redirect
on reflected/redirect candidates. Scanner output is NEVER a finding without manual
confirmation (design §7) — entities carry confirmed:false.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path
from urllib.parse import urlsplit

from .. import events, evidence, fetch, netguard, normalize, oob, secrets, settings
from ..runner import (RunResult, Status, have, nuclei_timeout, reclassify_from_artifact, run as exec_tool,
                      scaled_timeout, skipped)

GF_PATTERNS = ["xss", "sqli", "ssrf", "redirect", "lfi", "idor", "rce", "ssti", "interestingparams"]


def _arjun_urls(path):
    """FAIL-CLOSED read of arjun's -oT output (one param-bearing URL per line, e.g. `.../search?q=7101`).
    Returns the list of query-bearing URLs (the completion signal for the file-output adapter), or None
    when the file is missing/unreadable — so a chatty arjun stdout can't mask a missing/empty -oT as
    SUCCESS (the OTC false-success: 3954 stdout lines, no arjun.txt, 0 params)."""
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return [ln.strip() for ln in text.splitlines() if ln.strip() and "?" in ln]


def _apply_nuclei_oob(cmd: list[str]) -> list[str]:
    """Append self-hosted interactsh flags to a nuclei command (else nuclei's built-in public
    server). Shared by EVERY nuclei invocation so they all use the same OOB endpoint — no drift
    where one nuclei call silently uses the public server. `secrets.oob()` is the single source of
    truth for OOB config (future OOB consumers read it too)."""
    oob = secrets.oob()
    if oob.get("interactsh_server"):
        cmd += ["-iserver", str(oob["interactsh_server"])]
        if oob.get("interactsh_token"):
            cmd += ["-itoken", str(oob["interactsh_token"])]
    return cmd


def _chunk_terminal(sid, chunk_wu, res, cf, *, status) -> None:
    """review#1: emit a chunk's TERMINAL event from a finally so a chunk NEVER stays 'started'. `status` is the
    chunk OUTCOME the caller promotes to the tool's status ONLY after ALL per-chunk bookkeeping (logging, state
    save, artifact parse, run.add) succeeded — it stays FAILED when execution OR any post-execution step raised,
    so a chunk whose processing was incomplete is never recorded SUCCESS."""
    reason = None
    if status == Status.FAILED.value:
        reason = (res.note if (res and res.note) else "chunk raised before completing bookkeeping")
    elif res:
        reason = res.note or None
    events.tool_finish(sid, work_unit=chunk_wu, status=status, reason=reason,
                       duration=round(res.duration, 2) if res else None,
                       raw_ref=str(cf) if cf.exists() else None)


def _nuclei_templates_fp() -> str | None:
    """review#6/#10: a coverage-affecting fingerprint of the INSTALLED nuclei template set, so a templates
    update (new/changed detections) invalidates the resume work_unit — else C10b would skip a chunk that a
    fresh template set would now flag differently. nuclei records its templates state in its config dir; read
    it (honoring NUCLEI_CONFIG / XDG / ~/.config) and fold the COMPLETE effective state — version AND the
    ignore-hash (a changed .nuclei-ignore alters which templates run even at the same version). Returns a
    stable JSON string of every present field, or None when the state cannot be read (the caller then makes
    the unit NON-RESUMABLE — an unknown template set must never be treated as unchanged)."""
    base = (os.environ.get("NUCLEI_CONFIG")
            or os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "nuclei"))
    cfg = Path(base) / ".templates-config.json"
    try:
        data = json.loads(cfg.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    parts = {k: str(data[k]) for k in
             ("nuclei-templates-version", "nuclei-templates-latest-version", "nuclei-ignore-hash")
             if isinstance(data, dict) and data.get(k)}
    return json.dumps(parts, sort_keys=True) if parts else None


_NUCLEI_MHE_DEFAULT = 0        # FULL DEPTH (-nmhe). nuclei's own default is 30, which SILENTLY drops a host
_NUCLEI_MHE_MAX = 100_000      # after 30 request errors — on the OTC run that cost 459,930 unsent requests.
_ANSI_RX = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _nuclei_mhe() -> int:
    """`PERFORMANCE.NUCLEI_MAX_HOST_ERROR` — errors tolerated per host before nuclei SKIPS it (`-mhe`).
    Quarry's 0 means FULL DEPTH: no host is ever dropped for erroring (`-nmhe`), and that is the DEFAULT.
    Quarry is coverage-first — a host that errors is exactly the kind of host worth finishing, and nuclei's
    own default of 30 quietly turns a flaky target into an unscanned one. A nonzero value is an EXPLICITLY
    bounded coverage policy the operator opted into, never Quarry's normal behaviour.

    This is a COVERAGE policy, not a runtime knob — it decides which hosts get scanned at all, so it is
    folded into the resume fingerprint and a change re-scans rather than silently resuming a shallower
    generation. (It does cost wall-clock: the requests `-mhe` was suppressing now actually go out.)

    STRICT parse (mirrors SUBFINDER_MAX_TIME): an exact int (never a bool) or a clean int-string in
    0.._NUCLEI_MHE_MAX; anything else — bool, float, negative, oversized, garbage — falls back to the
    default rather than inventing a policy from a typo."""
    raw = settings.performance().get("NUCLEI_MAX_HOST_ERROR")
    if isinstance(raw, bool):
        return _NUCLEI_MHE_DEFAULT
    if isinstance(raw, int):
        return raw if 0 <= raw <= _NUCLEI_MHE_MAX else _NUCLEI_MHE_DEFAULT
    if isinstance(raw, str) and raw.strip().isdigit():
        v = int(raw.strip())
        return v if 0 <= v <= _NUCLEI_MHE_MAX else _NUCLEI_MHE_DEFAULT
    return _NUCLEI_MHE_DEFAULT


def _nuclei_progress(text: str) -> dict:
    """Read nuclei's OWN stderr for what only nuclei can tell us (the OTC 20260725 lesson: a generic stderr
    signature conflates execution with coverage and gets BOTH wrong).

      1. `planned` / `requests` / `errors` — how much of the planned request budget it actually COVERED, from
         the LAST `-stats` line. This is the ONLY coverage oracle; absent, coverage is UNKNOWN. nuclei skips a
         host after `-mhe` errors, so a finished scan can still leave requests unsent — a COVERAGE gap, never
         an execution one.
      2. `completed` — whether nuclei's own terminal line `Scan completed in <dur>.` (with either
         `N matches found.` or `No results found.`) was recognized. review#P1.4: this is CORROBORATING
         TELEMETRY ONLY. It must never gate resumability — execution completion is `exit_code == 0`, full stop.
         Requiring this sentence meant a nuclei release that reworded only its terminal (while keeping the stats
         JSON) would mark every chunk retryable forever.

    stderr is ANSI-coloured, so strip escapes before matching. Counters are returned RAW (not clamped): an
    impossible triple must reach events.coverage_partial's validator and surface as coverage UNKNOWN rather
    than be quietly repaired into a plausible-looking lie."""
    completed, planned, requests, errors = False, None, None, None
    for line in (text or "").splitlines():
        s = _ANSI_RX.sub("", line).strip()
        if not s:
            continue
        if "scan completed in" in s.lower():
            completed = True
            continue
        if not (s.startswith("{") and s.endswith("}")):
            continue
        try:
            d = json.loads(s)
        except json.JSONDecodeError:
            continue
        if not (isinstance(d, dict) and "requests" in d and "total" in d):
            continue
        try:                                       # nuclei emits these as STRINGS; last valid line wins
            planned, requests = int(d["total"]), int(d["requests"])
            errors = int(d["errors"]) if str(d.get("errors", "")).lstrip("-").isdigit() else None
        except (TypeError, ValueError):
            continue
    return {"completed": completed, "planned": planned, "requests": requests, "errors": errors}


def _nuclei_cmd(targets_file, out_file, prof, mhe: int) -> list[str]:
    """The nuclei main-scan command for one target file — identical flags for every chunk, only -l/-o
    differ (non-intrusive, severity-scoped, governor-scaled -c/-bs, explicit host-error policy, shared
    OOB endpoint)."""
    cmd = ["nuclei", "-l", str(targets_file), "-jsonl", "-o", str(out_file),
           "-etags", "intrusive,fuzz,dos,brute-force",
           "-s", "critical,high,medium", "-stats", "-si", "30",
           "-c", str(settings.workers("nuclei", 25)),      # H2: core-scaled concurrency (rate stays separate)
           "-bs", str(settings.concurrency("NUCLEI_BULK_SIZE", 25))]   # hosts/template batch
    cmd += ["-nmhe"] if mhe == 0 else ["-mhe", str(mhe)]   # 0 = full depth: never drop an erroring host
    if prof.http_rl:
        cmd += ["-rl", str(prof.http_rl)]
    _apply_nuclei_oob(cmd)                                 # self-hosted interactsh (else public default)
    return cmd


def _nuclei_scan(ctx, live, findings, log, prof) -> RunResult:
    """Chunked nuclei main scan (step 4.2 Commit B). Split live hosts into NUCLEI_CHUNK_HOSTS-sized
    batches and scan SEQUENTIALLY — rate is target-wide (RoE), so parallel batches would blow the
    budget; chunking buys resume + progress + per-batch isolation, NOT speed (work is rate-bound and
    fixed: OTC = 448 hosts / 5.08M req / 7h41 @ 183rps, died at 93%). Each batch gets its own
    nuclei_timeout, so one slow batch -> coverage_partial instead of a whole-run kill.

    RESUME is keyed on EXECUTION COMPLETION, not on a clean status — the two are independent facts. A chunk is
    done when the process EXITED 0 (it reached its own end; a kill leaves exit_code None, a crash nonzero).
    Degraded COVERAGE (host-error skips, WAF-blocked requests) is reported separately as structured request
    counters and does NOT make the chunk retryable; unmeasurable coverage is reported as coverage:unknown, never
    as complete. nuclei's `Scan completed in …` line is corroborating telemetry only — gating on it would let a
    reworded terminal lock resumability forever. The OTC 20260725 run proved why: at ~610k requests/chunk a generic stderr
    signature ALWAYS matched (one `i/o timeout` line is inevitable), so every chunk read PARTIAL, no chunk
    was ever recorded done, and `chunks` stayed `{}` — a resume would have repeated all 8.5 hours while the
    real gap (92.44% of planned requests sent, 459,930 skipped by `-mhe`) went unmeasured. A chunk that did
    NOT complete stays retryable. Its OUTPUT is still KEPT — the aggregate is rebuilt
    idempotently from every per-chunk artifact (findings_<ci>.jsonl), so a WAF/timeout-degraded chunk's
    real findings are never discarded and a re-scan can't duplicate. The state is tied to the
    INPUT (hash of the ordered live list + chunk size) so a changed host set / chunk size invalidates it
    instead of skipping the wrong hosts. Emits source-level tool_start / tool_progress / tool_finish;
    returns a RunResult for the manifest."""
    sid = "params.nuclei_scan"
    chunk_n = max(1, settings.concurrency("NUCLEI_CHUNK_HOSTS", 50))
    batches = [live[i:i + chunk_n] for i in range(0, len(live), chunk_n)]
    state_f = ctx.run.raw_path("params", "nuclei", "chunks.state.json")
    # C07 inc4: resume validity is a WORK_UNIT that folds the coverage-affecting CONFIG (severity + excluded
    # tags + chunk size), not just the host list. The old input_hash keyed on hosts+chunk_size ALONE, so a
    # template-scope change (a different severity/etags) would wrongly RESUME done chunks — the same
    # skip-after-settings-change bug fixed for ffuf. Any coverage-affecting change now invalidates the state.
    _tpl = _nuclei_templates_fp()                           # review#10: template SET is coverage-affecting
    mhe = _nuclei_mhe()                                     # host-error policy = WHICH hosts get scanned at all
    _cfg = {"severity": "critical,high,medium", "etags": "intrusive,fuzz,dos,brute-force", "chunk": chunk_n,
            "templates": _tpl if _tpl is not None else "unknown", "mhe": mhe}
    if _tpl is None:
        # review#6: template state UNKNOWN -> non-resumable. A per-run nonce makes scan_wu/chunk_wu differ every
        # run, so resume NEVER skips a chunk we cannot prove ran against the same templates (re-scan is a safe
        # superset; silently skipping on an unverifiable set is not).
        _cfg["_nonce"] = os.urandom(8).hex()
    scan_wu = events.work_unit(sid, inputs={"hosts": live}, config=_cfg)
    # review#4: a work_unit is NOT an execution attempt. Layout is wu_<scan_wu>/attempt_<attempt_id>/, and the
    # state maps each DONE chunk to the ARTIFACT PATH that produced it. A same-work-unit RETRY writes to a FRESH
    # attempt dir, so it can NEVER overwrite a prior attempt's chunk evidence; done chunks are read back from
    # their recorded paths. Raw attempt dirs are RETAINED (pruning is a separate explicit GC, never part of
    # publishing an aggregate — a publish must not delete raw evidence).
    wu_dir = state_f.parent / f"wu_{scan_wu}"
    wu_root = wu_dir.resolve()
    attempt_id = time.strftime("%Y%m%d-%H%M%S") + "-" + os.urandom(4).hex()   # UNIQUE per execution attempt
    attempt_dir = wu_dir / f"attempt_{attempt_id}"        # created lazily, only if a chunk actually runs

    def _valid_entry(ci_str, rel, digests=None) -> bool:
        """review#1/#2: a loaded state entry is trusted to skip/aggregate a chunk ONLY if it is fully valid — a
        non-negative in-range index, and a RELATIVE path with no absolute/`..` escape that resolves INSIDE THIS
        work_unit's dir (review#2: not merely the nuclei dir — a corrupt path must not borrow ANOTHER work unit's
        artifact) AND whose filename is exactly this chunk's `findings_<ci>.jsonl`, pointing at a readable file.
        Anything else is dropped so the chunk RE-RUNS (an invalid/foreign artifact is never a silent skip).

        review#P3: path validity is not CONTENT validity. An artifact recorded as done, then truncated/edited/
        replaced on disk, satisfied every path check and was still trusted — so a resume skipped the chunk and
        aggregated whatever the file now says. Each recorded artifact therefore carries its sha256 and must
        still match. A state file with no digest for an entry (written by an older Quarry) fails CLOSED: the
        chunk re-runs. Re-running costs time; trusting an unverifiable artifact costs silent surface."""
        if not (isinstance(ci_str, str) and ci_str.isdigit() and 0 <= int(ci_str) < len(batches)):
            return False
        if not isinstance(rel, str) or not rel or os.path.isabs(rel) or ".." in Path(rel).parts:
            return False
        if Path(rel).name != f"findings_{int(ci_str)}.jsonl":   # must be THIS chunk's artifact, not another's
            return False
        p = state_f.parent / rel
        try:
            if not p.resolve().is_relative_to(wu_root):      # containment: under the CURRENT work-unit dir only
                return False
            if not p.is_file():                              # missing artifact -> NOT done (re-run)
                return False
            with open(p, "rb"):                              # readability
                pass
        except (OSError, ValueError):
            return False
        want = (digests or {}).get(rel)
        if not isinstance(want, str) or not want:
            return False                                     # no recorded digest -> unverifiable -> re-run
        try:
            if events.file_digest(p) != want:                # content changed since it was recorded
                return False
        except OSError:
            return False
        return True

    def _prev():
        if not state_f.exists():
            return None
        try:
            prev = json.loads(state_f.read_text())
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(prev, dict):                       # review#7: [], null, or a scalar -> reject (rerun all)
            return None
        return prev if prev.get("work_unit") == scan_wu else None   # config-inclusive key: mismatch → fresh

    def _load_digests(prev) -> dict:                          # {rel: sha256} — content binding for every artifact
        m = (prev or {}).get("digests")
        if not isinstance(m, dict):
            return {}
        return {str(k): str(v) for k, v in m.items() if isinstance(k, str) and isinstance(v, str) and v}

    def _load_map(prev, digests) -> dict:                     # {ci: rel} — validated + digest-bound
        m = (prev or {}).get("chunks")
        if not isinstance(m, dict):
            return {}
        return {str(k): str(v) for k, v in m.items() if _valid_entry(str(k), v, digests)}

    def _load_evidence(prev, digests) -> dict:               # review#1: {ci: [rel, ...]} — a LIST, each validated
        m = (prev or {}).get("evidence")
        out: dict[str, list[str]] = {}
        if isinstance(m, dict):
            for k, v in m.items():
                vals = v if isinstance(v, list) else [v]     # tolerate a legacy scalar
                kept = [str(x) for x in vals if _valid_entry(str(k), x, digests)]
                if kept:
                    out[str(k)] = kept
        return out

    def _load_coverage(prev, done: dict) -> dict:
        """{ci: {"planned": int, "requests": int}} — the request coverage a DONE chunk reported, persisted so a
        RESUME can re-emit it. Without this a resumed run re-emits counters only for the chunks it actually ran
        and the skipped ones read as zero-eligible, understating the run's real gap. Validated: an in-range
        index and two non-negative ints (an impossible pair is dropped, not repaired)."""
        m = (prev or {}).get("coverage")
        out: dict[str, dict] = {}
        if not isinstance(m, dict):
            return out
        for k, v in m.items():
            if not (isinstance(k, str) and k.isdigit() and 0 <= int(k) < len(batches)):
                continue
            if not isinstance(v, dict):
                continue
            p, r = v.get("planned"), v.get("requests")
            if all(isinstance(x, int) and not isinstance(x, bool) and x >= 0 for x in (p, r)):
                out[k] = {"planned": p, "requests": r}
        # A coverage record is only meaningful for a chunk that COMPLETED — an entry for a chunk we are about
        # to RE-RUN is stale by definition, and keeping it would let last attempt's numbers stand in for this
        # one if the re-run finishes without a parseable stats line.
        return {k: v for k, v in out.items() if k in done}

    # done_map: chunks whose EXECUTION COMPLETED -> artifact (controls SKIP). evidence_map: for EVERY chunk that
    # produced output (complete OR not), the LIST of every preserved artifact across attempts (controls
    # AGGREGATION). review#1: a list, not a single pointer — PARTIAL(A) then PARTIAL(B) must keep BOTH, aggregate
    # + dedup all evidence. cov_map: per-chunk request coverage, so resume re-reports the gap it did not re-run.
    _p = _prev()
    digest_map: dict[str, str] = _load_digests(_p)            # {rel: sha256} — binds every recorded artifact
    done_map: dict[str, str] = _load_map(_p, digest_map)
    evidence_map: dict[str, list[str]] = _load_evidence(_p, digest_map)
    cov_map: dict[str, dict] = _load_coverage(_p, done_map)
    # drop digests whose artifact no longer survives validation, so the state file cannot grow a tail of
    # references to entries that are no longer trusted
    _kept_rels = set(done_map.values()) | {r for v in evidence_map.values() for r in v}
    digest_map = {k: v for k, v in digest_map.items() if k in _kept_rels}

    def _bind(rel, path) -> None:
        """Record an artifact's sha256 at the moment we trust it. A later resume re-verifies against this."""
        try:
            digest_map[rel] = events.file_digest(path)
        except OSError:
            digest_map.pop(rel, None)                         # cannot digest -> leave it unverifiable -> re-run

    def _add_evidence(ci_str, rel):                          # append-only, unique, per chunk
        lst = evidence_map.setdefault(ci_str, [])
        if rel not in lst:
            lst.append(rel)

    for _ci, _rel in done_map.items():                       # a done chunk's artifact is always also evidence
        _add_evidence(_ci, _rel)

    def _save():
        state_f.write_text(json.dumps(
            {"work_unit": scan_wu, "chunk_size": chunk_n, "chunks": done_map,
             "evidence": evidence_map, "coverage": cov_map, "digests": digest_map}))

    def _emit_coverage(ci: int, planned, requests, *, why: str) -> None:
        """Per-chunk REQUEST coverage as structured counters, one stable unit per chunk so the store's
        latest-per-unit reconciliation sums them into a single (source, "requests") rollup for the run.

        COVERAGE_TIMEOUT, not CAP: nothing here is OUR ceiling or the operator's chosen subset — the requests
        were lost in flight (target/network errors, or nuclei dropping a host once `-mhe` is exceeded, which is
        off by default). That is exactly the TIMEOUT bucket's policy contract: always feeds the verdict. The
        constant's name is narrower than its bucket; see the note on events.COVERAGE_TIMEOUT.

        Counters go through RAW — the validator flags an impossible triple as coverage UNKNOWN instead of us
        inventing a consistent-looking one."""
        if planned is None or requests is None:
            # review#P1.1: COVERAGE_UNKNOWN, not a reason-only event. A reason-only partial neither opens a
            # generation nor reaches the rollup, so an unmeasurable chunk read as fully covered and a PRIOR
            # run's counters kept standing in for it. Unknown must reach the verdict as a gap.
            events.coverage_partial(sid, kind=events.COVERAGE_UNKNOWN, unit=f"chunk_{ci}", measure="requests",
                                    reason=f"chunk {ci + 1}/{len(batches)}: {why} (request counters unavailable "
                                           f"— coverage UNMEASURED, not assumed complete)")
            return
        events.coverage_partial(sid, kind=events.COVERAGE_TIMEOUT, measure="requests", unit=f"chunk_{ci}",
                                eligible=planned, tested=requests, omitted=planned - requests,
                                reason=(f"chunk {ci + 1}/{len(batches)}: {requests}/{planned} planned request(s) "
                                        f"sent ({why})"))

    events.tool_start(sid, cmd=["nuclei", "-l", "<chunk>", "-jsonl"], input_total=len(live), work_unit=scan_wu)
    t0 = time.monotonic()
    incomplete = 0                                        # chunks whose EXECUTION did not complete (retryable)

    def _completed_hosts():                               # UX #4: hosts in EXECUTION-COMPLETE chunks (NOT attempted)
        return sum(len(batches[j]) for j in (int(k) for k in done_map) if j < len(batches))

    # C07 inc4: a source terminal ALWAYS fires (try/finally) even if the loop raises. status starts FAILED
    # (an exception mid-loop must NOT emit a scan-level success) and is set to SUCCESS/PARTIAL only after the
    # loop + aggregate complete. Each executed chunk gets its OWN start+terminal (keyed on chunk_wu), and the
    # resume record is chunks.state.json (keyed on scan_wu). The source lifecycle is scan_wu; no duplicates.
    status = Status.FAILED
    try:
        for ci, batch in enumerate(batches):
            chunk_wu = events.work_unit(sid, inputs={"hosts": batch}, config=_cfg)
            # UX #2: progress BEFORE the chunk — status shows STARTING chunk ci+1, with CLEANLY-completed
            # host count; the per-chunk work_unit is the stable unit id (resume/audit key).
            events.tool_progress(sid, chunk_index=ci + 1, chunk_total=len(batches),
                                 current_index=_completed_hosts(), work_unit=chunk_wu)
            if str(ci) in done_map:                       # resume: EXECUTION already completed in a prior attempt
                _prior = cov_map.get(str(ci)) or {}        # (artifact recorded + preserved; do not re-run)
                _emit_coverage(ci, _prior.get("planned"), _prior.get("requests"),
                               why="resumed — coverage as first recorded")
                continue
            attempt_dir.mkdir(parents=True, exist_ok=True)   # lazy: only create the attempt dir if a chunk runs
            bf = ctx.write_list(f"nuclei_targets_{ci}.txt", batch)
            cf = attempt_dir / f"findings_{ci}.jsonl"        # review#4: THIS attempt's artifact (never overwrites a prior)
            ef = attempt_dir / f"stderr_{ci}.log"            # per-chunk FULL stderr: the completion/coverage oracle
            rel = f"wu_{scan_wu}/attempt_{attempt_id}/findings_{ci}.jsonl"   # recorded in state, relative to the state dir
            events.tool_start(sid, work_unit=chunk_wu, input_total=len(batch))   # this chunk's own lifecycle
            res = None
            chunk_status = Status.FAILED.value               # review#1: promoted ONLY after ALL bookkeeping below
            try:                                             # review#1: chunk terminal ALWAYS fires (finally)
                res = exec_tool("nuclei", _nuclei_cmd(bf, cf, prof, mhe),
                                timeout=nuclei_timeout(len(batch), ctx.http_timeout), stderr_path=ef)
                if res.stderr_tail:
                    with log.open("a", encoding="utf-8") as lf:
                        lf.write(res.stderr_tail + "\n")
                # Ask NUCLEI whether it finished, from its OWN terminal line in the FULL stderr (the 8-line tail
                # can be evicted by a trailing [INF] burst, so prefer the file and fall back only if it is absent).
                try:
                    _err = ef.read_text(encoding="utf-8", errors="replace") if ef.is_file() else res.stderr_tail
                except OSError:
                    _err = res.stderr_tail
                prog = _nuclei_progress(_err)
                # ── the split, in one line each ────────────────────────────────────────────────────────────
                # EXECUTION COMPLETE  <- res.exit_code == 0. NOTHING else. The process reached its own end; a
                #                        kill leaves exit_code None (TIMED_OUT) and a crash leaves it nonzero.
                # COVERAGE            <- the -stats counters. Absent -> coverage:unknown, never "complete".
                # `Scan completed in …` is CORROBORATING TELEMETRY only (it rides the reason string) — it must
                #                        NOT gate resumability.
                #
                # review#P1.4: requiring that sentence whenever ANY stats line was recognized left a second way
                # to lock resumability forever — a nuclei release that keeps the stats JSON but reworded only its
                # terminal would give completed=False, exit 0, and a chunk retryable on every future run: the
                # 8.5-hour bug again, through a PARTIAL format change. (review#P1.2 closed the same hole for the
                # status fallback; this is its twin.) Consequence worth naming: "we sent fewer requests than
                # planned" is now ALWAYS a coverage fact, never a resumability one — which is correct, because a
                # process that ran to its own end has no work left to resume.
                complete = res.exit_code == 0
                terminal_seen = bool(prog["completed"])      # telemetry: did we recognize nuclei's own terminal?
                planned, requests = prog["planned"], prog["requests"]
                # KEEP a chunk's findings regardless of outcome — real even if WAF/timeout-degraded.
                if complete:
                    if not cf.exists():
                        cf.touch()                           # review#1: explicit zero-byte artifact for a clean-EMPTY
                    done_map[str(ci)] = rel                  # execution complete -> controls SKIP
                    _add_evidence(str(ci), rel)              # ...and joins this chunk's evidence history
                    _bind(rel, cf)                           # content binding: a later edit invalidates the skip
                    if planned is not None and requests is not None:
                        cov_map[str(ci)] = {"planned": planned, "requests": requests}
                    _save()
                    _emit_coverage(ci, planned, requests,
                                   why=("exit 0" + ("" if terminal_seen else ", nuclei terminal not recognized")
                                        + (f", {prog['errors']} error(s)" if prog["errors"] is not None else "")))
                    # status now reflects EXECUTION, not a stderr signature: findings -> SUCCESS, none -> EMPTY.
                    chunk_status = (Status.SUCCESS if cf.stat().st_size > 0 else Status.EMPTY).value
                else:
                    incomplete += 1
                    _emit_coverage(ci, planned, requests,
                                   why=f"execution INCOMPLETE (exit {res.exit_code}, {res.status.value}) "
                                       f"— chunk stays retryable")
                    # review#1: a chunk that produced real output APPENDS to this chunk's evidence list
                    # (PARTIAL(A) then PARTIAL(B) keeps BOTH). A degraded/failed retry with NO output appends
                    # nothing, so an earlier attempt's findings are never erased.
                    if cf.exists() and cf.stat().st_size > 0:
                        _add_evidence(str(ci), rel)
                        _bind(rel, cf)
                        _save()
                    # never launder an incomplete execution into a clean status
                    chunk_status = (res.status if res.status not in (Status.SUCCESS, Status.EMPTY)
                                    else Status.PARTIAL).value
            finally:
                _chunk_terminal(sid, chunk_wu, res, cf, status=chunk_status)   # FAILED if exec OR bookkeeping raised
        # review#1/#2/#4: rebuild the aggregate into a TEMP file, then swap ATOMICALLY — the prior findings.jsonl
        # is only replaced once the new one is fully written, so a crash mid-rebuild leaves the old aggregate
        # intact. For each chunk, read EVERY preserved evidence artifact (all attempts, clean OR degraded — so a
        # later degraded/failed retry can't drop an earlier attempt's findings) and DEDUPLICATE lines. Falls back
        # to THIS attempt's file for a chunk just run but not yet recorded. Prior attempt dirs are RETAINED — NO
        # pruning here (a publish must never delete raw evidence; attempt-dir GC is a separate operation).
        tmp = findings.with_name(findings.name + ".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            for ci in range(len(batches)):
                rels = list(evidence_map.get(str(ci)) or [])
                paths = [state_f.parent / r for r in rels] or [attempt_dir / f"findings_{ci}.jsonl"]
                seen_lines: set[str] = set()                  # dedup PER CHUNK (across its attempts) — never across
                for p in paths:                               # chunks, whose identical-looking lines are distinct hosts
                    if not (p.exists() and p.stat().st_size > 0):
                        continue
                    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                        if line and line not in seen_lines:
                            seen_lines.add(line)
                            fh.write(line + "\n")
        os.replace(tmp, findings)
        # Scan STATUS tracks EXECUTION only. Degraded request coverage does NOT go here — it rides the
        # structured counters and reaches the operator through the run verdict (complete_with_gaps), so the
        # status stays a signal that can actually discriminate "a chunk needs re-running" from "the target
        # dropped some requests". Before this split every real-target run read PARTIAL and told us nothing.
        status = Status.PARTIAL if incomplete else Status.SUCCESS
    finally:
        events.tool_progress(sid, chunk_index=len(batches), chunk_total=len(batches),
                             current_index=_completed_hosts(), work_unit=scan_wu)   # final: execution-complete
        try:                                                 # review#1: a stat() raise must NOT defeat the scan terminal
            size = findings.stat().st_size
        except OSError:
            size = None
        events.tool_finish(sid, status=status.value, work_unit=scan_wu,
                           reason=(f"{incomplete}/{len(batches)} chunk(s) execution-incomplete (retryable)"
                                   if incomplete else None),
                           duration=round(time.monotonic() - t0, 2),
                           raw_ref=str(findings), artifact_size=size, discovery_context="params")
    lines = len(findings.read_text().splitlines()) if findings.exists() else 0
    _planned = sum(v["planned"] for v in cov_map.values())
    _sent = sum(v["requests"] for v in cov_map.values())
    if _planned:
        # Say WHICH chunks the percentage covers — nuclei may not report counters for every chunk, and an
        # unqualified "92.44%" over a subset would read as a whole-scan figure.
        _scope = ("" if len(cov_map) == len(batches)
                  else f" over {len(cov_map)}/{len(batches)} measured chunk(s)")
        ctx.echo(f"  nuclei coverage: {_sent}/{_planned} planned request(s) sent "
                 f"({100 * _sent / _planned:.2f}%, {_planned - _sent} skipped{_scope}; -mhe "
                 f"{'off (full depth)' if mhe == 0 else mhe})")
    return RunResult("nuclei", ["nuclei", "-l", "<chunked>"], status, 0,
                     round(time.monotonic() - t0, 2), findings if findings.exists() else None,
                     lines, note=f"{len(batches)} chunk(s), {len(done_map)} execution-complete, "
                                 f"{incomplete} retryable")


def _exposed_urls(ctx, scope) -> list[str]:
    """Exposed-sensitive-file URLs to fetch: nuclei exposure hits + 200 sensitive-path URLs,
    de-duped, in-scope + active-allowed (passive/OOS excluded via active_allowed)."""
    seen: set[str] = set()
    out: list[str] = []
    def consider(u):
        u = (u or "").strip()
        if not u or u in seen:
            return
        if evidence.SENSITIVE_FILE_RX.search(u) and scope.active_allowed(normalize.host_of_url(u)):
            seen.add(u)
            out.append(u)
    for f in ctx.run.read("finding"):                 # nuclei matched-at (exposure templates)
        consider(f.get("matched"))
    for r in ctx.run.read("url"):                      # sensitive paths seen live (crawl/content)
        if r.get("status") in (None, 200, "200"):      # status 200 when known; archive/crawl URLs may have no status
            consider(r.get("url"))
    return out


def _graphql_urls(ctx, scope) -> list[str]:
    """Absolute in-scope GraphQL endpoint URLs to introspect: deep-mine `endpoint` kind=graphql +
    any /graphql|/gql URL. Relative values (no host, e.g. bare '/graphql' from JS) are skipped —
    introspection needs a concrete host, and active_allowed gates scope/OOS/passive."""
    seen: set[str] = set()
    out: list[str] = []
    def consider(u):
        u = (u or "").strip()
        if not u or u in seen or not u.lower().startswith(("http://", "https://")):
            return
        if re.search(r"/(?:graphql|gql)\b", u, re.I) and scope.active_allowed(normalize.host_of_url(u)):
            seen.add(u)
            out.append(u)
    for e in ctx.run.read("endpoint"):
        if e.get("kind") == "graphql":
            consider(e.get("value"))
    for r in ctx.run.read("url"):
        consider(r.get("url"))
    return out


def _actuator_bases(ctx, scope) -> list[str]:
    """In-scope Spring Boot actuator base URLs to interrogate. Two candidate sources:
    (a) any observed URL containing `/actuator`, collapsed to its base; and
    (b) live hosts httpx fingerprints as Spring/Spring-Boot — `/actuator` is almost never linked, so
        the tech fingerprint IS the candidate signal (Test-6: mgmt was Spring but had no /actuator
        URL, so the probe never ran). Still candidate-driven — never blind onto every host."""
    seen: set[str] = set()
    out: list[str] = []
    def add_base(base: str):
        if base and base not in seen and scope.active_allowed(normalize.host_of_url(base)):
            seen.add(base)
            out.append(base)
    def consider_url(u):
        u = (u or "").strip()
        if not u or not u.lower().startswith(("http://", "https://")):
            return
        m = re.match(r"(?i)(https?://[^/]+/(?:[^?#]*?/)?actuator)\b", u)
        if m:
            add_base(m.group(1))
    for r in ctx.run.read("url"):
        consider_url(r.get("url"))
    for e in ctx.run.read("endpoint"):
        consider_url(e.get("value"))
    for f in ctx.run.read("finding"):
        consider_url(f.get("matched"))
    # (b) Spring/Boot-fingerprinted live hosts -> probe <origin>/actuator
    for t in ctx.run.read("tech"):
        if "spring" in str(t.get("tech", "")).lower():
            u = (t.get("url") or "").strip()
            if u.lower().startswith(("http://", "https://")):
                add_base(u.rstrip("/") + "/actuator")
    return out


_OPENAPI_RX = re.compile(
    r"(?i)(openapi\.(?:json|ya?ml)|swagger\.(?:json|ya?ml)|/v[23]/api-docs\b|/api-docs\b|"
    r"/swagger/v\d+/swagger\.json|/swagger\.json)")


def _openapi_urls(ctx, scope) -> list[str]:
    """Absolute in-scope OpenAPI/Swagger doc URLs to fetch+parse (openapi.json/yaml, swagger.json,
    /v2|/v3/api-docs, …), de-duped, active-allowed (passive/OOS excluded)."""
    seen: set[str] = set()
    out: list[str] = []
    def consider(u):
        u = (u or "").strip()
        if not u or u in seen or not u.lower().startswith(("http://", "https://")):
            return
        if _OPENAPI_RX.search(u) and scope.active_allowed(normalize.host_of_url(u)):
            seen.add(u)
            out.append(u)
    for r in ctx.run.read("url"):
        consider(r.get("url"))
    for e in ctx.run.read("endpoint"):
        consider(e.get("value"))
    return out


def _framework_endpoint_candidates(ctx, scope) -> list[dict]:
    """Candidate-driven framework recon endpoints: for each live host, match its httpx tech against
    framework-endpoints.yaml and build the origin+path URLs to GET-probe. Only frameworks actually
    fingerprinted contribute (never blind onto every host), de-duped, active-allowed, bounded.
    Mirrors _actuator_bases — the tech fingerprint IS the candidate signal."""
    fw = evidence._framework_endpoints()
    seen: set[str] = set()
    out: list[dict] = []
    for l in ctx.run.read("live"):
        url = (l.get("url") or "").strip()
        m = re.match(r"(?i)(https?://[^/]+)", url)
        if not m:
            continue
        origin, host = m.group(1), normalize.host_of_url(url)
        if not scope.active_allowed(host):
            continue
        techs = " ".join(str(t) for t in (l.get("tech") or [])).lower()
        if not techs:
            continue
        for name, spec in fw.items():
            if not isinstance(spec, dict) or not any(
                    str(mt).lower() in techs for mt in (spec.get("match") or [])):
                continue
            for ep in (spec.get("endpoints") or []):
                path = ep.get("path") if isinstance(ep, dict) else str(ep)
                if not path:
                    continue
                cu = origin + path
                if cu in seen:
                    continue
                seen.add(cu)
                out.append({"url": cu, "framework": name,
                            "note": ep.get("note") if isinstance(ep, dict) else ""})
    return out[:200]


def _ssti_targets(ctx, scope) -> list[str]:
    """gf ssti candidate URLs that carry a query string, de-duped, active-allowed — the params to
    confirm the SSTI primitive on."""
    seen: set[str] = set()
    out: list[str] = []
    for r in ctx.run.read("review"):
        if r.get("klass") != "ssti":
            continue
        u = (r.get("value") or "").strip()
        if u and u not in seen and "?" in u and scope.active_allowed(normalize.host_of_url(u)):
            seen.add(u)
            out.append(u)
    return out


def _canonicalize_candidates(urls: list[str]) -> tuple[list[str], dict]:
    """Collapse XSS/redirect candidate URLs to unique (host, path, sorted param-NAMES) shapes, keeping
    ONE representative URL per shape. dalfox's reflected-XSS selection depends on the param SHAPE, not
    the specific values, so scanning one URL per shape covers the same surface at a fraction of the cost.
    The real problem was never 'dalfox is slow' — it was feeding it the same shape ~10x (measured on OTC:
    993 raw -> 106 shapes, 89.3% collapsed). Returns (representatives, stats) where stats =
    {raw_candidates, canonical_candidates, reduction_percent, top_collapsed}."""
    from urllib.parse import urlsplit, parse_qsl
    shapes: dict = {}
    for u in urls:
        s = urlsplit(u)
        # ORIGIN-aware key: scheme is part of the identity — http://h/p?x= and https://h/p?x= can be
        # different services / redirect chains, so they must NOT collapse. keep_blank_values: a blank
        # redirect/XSS param (?next= / ?url=) is a REAL distinct sink parse_qs() would silently drop.
        names = tuple(sorted({k for k, _ in parse_qsl(s.query, keep_blank_values=True)}))
        key = (s.scheme.lower(), s.netloc.lower(), s.path, names)
        shapes.setdefault(key, {"url": u, "count": 0})["count"] += 1
    reps = [v["url"] for v in shapes.values()]
    raw, canon = len(urls), len(reps)
    top = sorted(shapes.items(), key=lambda kv: -kv[1]["count"])[:5]
    stats = {
        "raw_candidates": raw,
        "canonical_candidates": canon,
        "reduction_percent": round(100 * (1 - canon / raw), 1) if raw else 0.0,
        "top_collapsed": [{"shape": f"{k[0]}://{k[1]}{k[2]}?{'&'.join(k[3])}", "count": v["count"]}
                          for k, v in top if v["count"] > 1],
    }
    return reps, stats


def _dalfox_cmd(batch_file, out_file, prof) -> list[str]:
    """dalfox v3 (Rust) reflected-XSS scan (v0.3.8). v3 replaced the headless browser with static AST DOM
    analysis, so v2's --skip-headless timekiller is GONE; params are pre-discovered (arjun/gf), so --skip-mining
    stays. Output is structured JSONL to the -o file; -S keeps captured output minimal (status is read from the
    EXIT CODE, not stdout — see the scan loop). Concurrency is 2-DIMENSIONAL in v3: --workers is PER TARGET,
    --max-concurrent-targets is target parallelism — carrying v2's -w 100 forward would explode a 40-target
    chunk's fan-out, so BOTH are governed with CONSERVATIVE defaults (roughly v2's per-host blast radius, more
    hosts sequential) pending OTC measurement, and the global --rate-limit caps the aggregate rps when RoE is set."""
    cmd = ["dalfox", "scan", "-i", "file", str(batch_file), "-o", str(out_file),
           "-f", "jsonl", "-S", "--skip-mining",
           "--workers", str(max(1, settings.workers("dalfox", 30))),          # per-target; v2 -w 100 NOT carried
           "--max-concurrent-targets", str(max(1, settings.concurrency("DALFOX_TARGETS", 4)))]  # OTC-tunable
    bx = secrets.oob().get("blind_xss_url")
    if bx:
        cmd += ["-b", str(bx)]                             # blind/stored XSS OOB beacon (kept; 4.3.D gates)
    if prof.http_rl:
        # v3 has a REAL global rate cap (req/s, shared across workers AND targets) — supersedes v2's per-host
        # --delay math and its per-target-limiter caveat. Bound the aggregate stream directly to the RoE rate.
        cmd += ["--rate-limit", str(prof.http_rl)]
    return cmd


# dalfox v3 finding TYPE -> (store klass, confidence tier, display name). Kept DISTINCT (Lumpy): a Dalfox-verified
# hit (V) is higher-confidence than a reflection (R), and an AST-DOM static finding (A) is its own static-analysis
# evidence — none collapses into another. `confirmed` stays False for all (Quarry-owned impact validation only);
# "Dalfox-verified" (not "DOM-verified") — V is dalfox's own verdict, which doesn't always establish DOM execution.
_DALFOX_TIER = {
    "V": ("xss-verified", "verified", "XSS — Dalfox-verified (Quarry impact validation pending)"),
    "R": ("xss-candidate", "candidate", "reflected parameter — XSS candidate (manual validation required)"),
    "A": ("dom-xss-static", "dom-static", "DOM XSS (static AST, needs runtime confirmation)"),
}
_DALFOX_SRC_SINK = re.compile(r"\(Source:\s*(.*?),\s*Sink:\s*(.*?)\)")
_DALFOX_LINECOL = re.compile(r":(\d+):(\d+)\s*-\s")


def _dalfox_engine_id() -> str:
    """The VERIFIED identity of the dalfox binary that will ACTUALLY run (registry health) — folded into the
    resume work unit so a drifted / shadowed / manually-upgraded binary can't reuse another engine's chunks
    (review-r9#4). An unverified/unknown engine returns a per-run NONCE -> that run is NON-resumable (a re-scan
    is a safe superset; silently skipping chunks we can't prove ran on the same binary is not)."""
    try:
        from ..registry import load_tools, health
        t = next((x for x in load_tools() if x.bin == "dalfox"), None)
        if t is not None:
            h = health(t)
            if h.get("ok") and h.get("identity"):
                return str(h["identity"])
    except Exception:
        pass
    return "unverified-" + os.urandom(8).hex()


def _dstr(v) -> str:
    """A JSON field coerced to a stripped string ONLY if it is a scalar string — a list/dict/number returns ''
    (never str([...])). review-r9#3: essential fields are scalar-string validated, not blindly str()'d."""
    return v.strip() if isinstance(v, str) else ""


def _dalfox_identity(ftype: str, obj: dict) -> "str | None":
    """A canonical identity per finding so DISTINCT routes never collapse (review-r8#2). V/R key on
    scheme://host:port/path + location:param + method — /search?q and /admin?q are DISTINCT. A (AST-DOM) has no
    real param (dalfox writes param '-'), so it keys on its SOURCE/SINK + line:col (two sinks on one URL are
    distinct). Returns None (row rejected, never raises — review-r9#3) when a needed field is missing/non-scalar
    or the PoC URL is unparseable (incl. a bad :port that only raises on attribute access)."""
    poc = _dstr(obj.get("data"))
    if not poc:
        return None
    try:
        u = urlsplit(poc)
        host = (u.hostname or "").lower()
        port = u.port                                          # a bad port raises HERE (not at urlsplit) — guarded
    except ValueError:
        return None
    if not host:
        return None
    h = f"[{host}]" if ":" in host else host                   # review-r10#2: bracket IPv6 so [::1]:80 != [::1:80]
    base = f"{(u.scheme or 'http').lower()}://{h}{f':{port}' if port else ''}{u.path or '/'}"
    method = (_dstr(obj.get("method")) or "GET").upper()
    if ftype == "A":
        ev = _dstr(obj.get("evidence"))
        m, lc = _DALFOX_SRC_SINK.search(ev), _DALFOX_LINECOL.search(ev)
        if m:
            loc = f"{lc.group(1)}:{lc.group(2)}" if lc else ""
            disc = f"{loc}|{m.group(1).strip()}->{m.group(2).strip()}"
        else:
            disc = (ev or _dstr(obj.get("message_str")))[:120]
        return f"{base}|dom|{disc}|{method}" if disc else None
    param = _dstr(obj.get("param"))
    if param in ("", "-"):                                     # '-' is dalfox's no-param placeholder
        return None                                            # a V/R finding with no param is malformed
    return f"{base}|{_dstr(obj.get('location'))}:{param}|{method}"


def _dalfox_finding(obj) -> "dict | None":
    """Validate + build ONE finding record, or None if malformed. `type` must be a scalar string in {V,R,A}
    (unknown/non-scalar REJECTED, never silently reclassified as R); null JSON fields never become the string
    'None'; dalfox's own type/payload/evidence/PoC are preserved. `raw_ref` is added by the caller."""
    if not isinstance(obj, dict):
        return None
    ftype = _dstr(obj.get("type")).upper()
    if ftype not in _DALFOX_TIER:                              # V/R/A only (scalar string)
        return None
    ident = _dalfox_identity(ftype, obj)
    if ident is None:
        return None
    klass, confidence, name = _DALFOX_TIER[ftype]
    param = _dstr(obj.get("param"))
    param = None if param in ("", "-") else param
    poc = _dstr(obj.get("data")) or None
    return {"id": f"{klass}:{ident}", "template": klass, "name": name,
            "severity": (_dstr(obj.get("severity")) or "medium").lower(),
            "matched": _dstr(obj.get("message_str")) or poc or ident,
            "confidence": confidence, "sources": ["dalfox"], "confirmed": False,
            "dalfox_type": ftype, "param": param, "payload": obj.get("payload") if isinstance(obj.get("payload"), str) else None,
            "location": _dstr(obj.get("location")) or _dstr(obj.get("inject_type")) or None,
            "evidence": _dstr(obj.get("evidence")) or None, "poc": poc,
            "cwe": _dstr(obj.get("cwe")) or None}


def _parse_dalfox_jsonl(cf) -> "tuple[list, bool]":
    """FAIL-CLOSED parse of a dalfox v3 JSONL artifact -> (valid_findings, artifact_ok). Keeps every VALID
    finding as evidence, but artifact_ok is False on ANY inconsistency: missing/unreadable file, a decode error,
    a meta row NOT in first position or MORE than one, a non-int/negative/bool findings_count (review-r10#3:
    bool subclasses int, so `type(x) is int`), finding-count != meta count, a torn/non-object line, an unknown
    type, or a row missing its identity fields. The caller ingests the valid findings but marks a not-ok chunk
    PARTIAL/retryable (never 'done'), so incomplete work can't be permanently skipped on resume."""
    if not cf.exists():
        return [], False
    try:
        raw = cf.read_text(encoding="utf-8")                  # strict decode: a bad byte = malformed, not silent
    except (OSError, UnicodeError):
        return [], False
    findings, ok, meta_rows, meta_count, row_idx = [], True, 0, None, 0
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            ok = False; row_idx += 1; continue                # torn line -> not trustworthy
        if not isinstance(obj, dict):
            ok = False; row_idx += 1; continue
        if "meta" in obj:
            meta_rows += 1
            if row_idx != 0:                                  # review-r10#3: meta must be the FIRST row
                ok = False
            m = obj.get("meta")
            c = m.get("findings_count") if isinstance(m, dict) else None
            if type(c) is int and c >= 0:                     # STRICT int (not bool), non-negative
                meta_count = c
            else:
                ok = False
            row_idx += 1
            continue
        try:
            rec = _dalfox_finding(obj)
        except Exception:
            rec = None                                        # defensive: a row can NEVER abort the whole parse
        if rec is None:
            ok = False                                        # malformed/unknown row -> chunk not trustworthy
        else:
            findings.append(rec)
        row_idx += 1
    if meta_rows != 1:                                        # review-r10#3: EXACTLY one meta summary row
        ok = False
    if meta_count is not None and meta_count != len(findings):
        ok = False                                            # count mismatch -> torn/partial artifact
    return findings, ok


def _sha256_file(p) -> str:
    """sha256 of a file, streamed. Used to prove a recorded completion artifact is UNCHANGED before a resume
    trusts it to SKIP its chunk (review-r11#1)."""
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(65536), b""):
            h.update(b)
    return h.hexdigest()


def _dalfox_xss_fast(ctx, cands, prof) -> RunResult:
    """params.dalfox_xss_fast (step 4.3.B): reflected-XSS scan over the CANONICALIZED xss candidates with
    the fast flags, in resumable chunks. Mirrors _nuclei_scan: input-hashed chunk state, mark done ONLY
    on clean completion (failed batch stays retryable), source-level tool_start/tool_progress/tool_finish
    + ledger. dalfox v3 emits structured JSONL (parsed below): findings are tiered by dalfox's own verdict
    (V verified / R reflected / A AST-DOM) into confidence, but stay confirmed:false — the map-don't-exploit
    boundary holds (Quarry-owned impact validation is separate). Findings go straight to the store (deduped by id)."""
    sid = "params.dalfox_xss_fast"
    chunk_n = max(1, settings.concurrency("DALFOX_CHUNK", 40))
    batches = [cands[i:i + chunk_n] for i in range(0, len(cands), chunk_n)]
    state_f = ctx.run.raw_path("params", "dalfox", "chunks.state.json")
    # C07 inc4 + review-r8#4/r9#4: resume validity folds EVERY coverage-affecting knob — the effective v3
    # contract: the VERIFIED EXECUTED engine identity (not just the configured pin — a drifted/shadowed binary
    # must not reuse old chunks; an unverified engine carries a nonce -> non-resumable), workers + target
    # concurrency + rate-limit (fan-out/pacing), a FINGERPRINT of the blind collector (never the raw URL), and
    # chunk size. `mode` v3-fast invalidates any in-progress v2 state.
    bx = secrets.oob().get("blind_xss_url")
    _cfg = {"mode": "v3-fast-reflected", "engine": _dalfox_engine_id(),
            "workers": settings.workers("dalfox", 30),
            "targets": settings.concurrency("DALFOX_TARGETS", 4),
            "rate_limit": prof.http_rl,
            "blind": secrets.fingerprint(bx) if bx else None,
            "chunk": chunk_n}
    scan_wu = events.work_unit(sid, inputs={"cands": cands}, config=_cfg)
    # review-r9#1/r10#1: nuclei's proven resume contract (not just its dir layout). Immutable per-attempt
    # artifacts wu_<scan_wu>/attempt_<id>/findings_<ci>.jsonl; a COMPLETION map (clean chunk -> validated
    # artifact path, controls SKIP) is kept separate from an append-only EVIDENCE map (every attempt's artifact
    # that produced output, controls AGGREGATION). A chunk is skipped ONLY if its recorded artifact still
    # validates (index in range · relative · no `..` · exact filename · resolves INSIDE this work_unit · readable
    # · re-parses); the source verdict + `matched` are derived from the RETAINED EVIDENCE (all attempts, deduped
    # by finding id), so a finding kept in a degraded attempt is never lost when a later retry comes back empty.
    wu_dir = state_f.parent / f"wu_{scan_wu}"
    wu_root = wu_dir.resolve()
    attempt_id = time.strftime('%Y%m%d-%H%M%S') + "-" + os.urandom(4).hex()
    attempt_dir = wu_dir / f"attempt_{attempt_id}"

    def _valid_entry(ci_str, rel) -> bool:
        if not (isinstance(ci_str, str) and ci_str.isdigit() and 0 <= int(ci_str) < len(batches)):
            return False
        if not isinstance(rel, str) or not rel or os.path.isabs(rel) or ".." in Path(rel).parts:
            return False
        if Path(rel).name != f"findings_{int(ci_str)}.jsonl":
            return False
        p = state_f.parent / rel
        try:
            if not p.resolve().is_relative_to(wu_root):      # containment: THIS work-unit's dir only
                return False
            if not p.is_file():
                return False
            with open(p, "rb"):
                pass
        except (OSError, ValueError):
            return False
        return True

    def _prev():
        if not state_f.exists():
            return None
        try:
            prev = json.loads(state_f.read_text())
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(prev, dict):
            return None
        return prev if prev.get("work_unit") == scan_wu else None   # config-inclusive key: mismatch → fresh

    def _valid_completion(ci_str, entry) -> bool:
        # review-r11#1: a completion is trusted to SKIP a chunk only if its artifact is structurally valid AND
        # UNCHANGED (sha256 matches what we recorded) AND still PARSES CLEAN AND still AGREES with the recorded
        # outcome (EMPTY = no findings, SUCCESS = >=1). A completed artifact that later went missing/malformed/
        # tampered is dropped -> the chunk RE-RUNS (never a silent skip on stale evidence).
        if not isinstance(entry, dict):
            return False
        rel, outcome, sha = entry.get("rel"), entry.get("outcome"), entry.get("sha256")
        if outcome not in ("EMPTY", "SUCCESS") or not _valid_entry(ci_str, rel):
            return False
        p = state_f.parent / rel
        try:
            if _sha256_file(p) != sha:                       # unchanged since recorded
                return False
        except OSError:
            return False
        fnds, ok = _parse_dalfox_jsonl(p)                    # re-parses (as the comment promises)
        return ok and ((outcome == "EMPTY" and not fnds) or (outcome == "SUCCESS" and bool(fnds)))

    def _load_completion(prev) -> dict:                      # {ci: {rel, outcome, sha256}} — each FULLY validated
        m = (prev or {}).get("chunks"); out: dict[str, dict] = {}
        if isinstance(m, dict):
            for k, v in m.items():
                if _valid_completion(str(k), v):
                    out[str(k)] = {"rel": str(v["rel"]), "outcome": v["outcome"], "sha256": v["sha256"]}
        return out

    def _valid_evidence(ci_str, entry) -> bool:
        # review-r12: an evidence artifact is aggregated only if structurally valid AND UNCHANGED (its recorded
        # sha256 still matches). A rejected/tampered artifact whose completion failed the digest must not sneak
        # its rows in through the evidence map. Valid rows from an ORIGINALLY malformed/degraded artifact are
        # still retained — as long as its bytes have not changed since we recorded it.
        if not isinstance(entry, dict):
            return False
        rel, sha = entry.get("rel"), entry.get("sha256")
        if not _valid_entry(ci_str, rel):
            return False
        p = state_f.parent / rel
        try:
            return _sha256_file(p) == sha
        except OSError:
            return False

    def _load_evidence(prev) -> dict:                        # {ci: [{rel, sha256}, ...]} — each digest-validated
        m = (prev or {}).get("evidence"); out: dict[str, list[dict]] = {}
        if isinstance(m, dict):
            for k, v in m.items():
                kept = [{"rel": str(e["rel"]), "sha256": e["sha256"]}
                        for e in (v if isinstance(v, list) else [v]) if _valid_evidence(str(k), e)]
                if kept:
                    out[str(k)] = kept
        return out

    _pv = _prev()
    completion: dict[str, dict] = _load_completion(_pv)      # controls SKIP (revalidated each run)
    evidence_map: dict[str, list[dict]] = _load_evidence(_pv)

    def _add_evidence(ci_str, rel, sha):                     # append-only, unique-by-rel, per chunk; digest recorded
        lst = evidence_map.setdefault(ci_str, [])
        if not any(e["rel"] == rel for e in lst):
            lst.append({"rel": rel, "sha256": sha})

    for _ci, _e in completion.items():                       # a clean chunk's artifact is always also evidence
        _add_evidence(_ci, _e["rel"], _e["sha256"])

    def _save():
        state_f.write_text(json.dumps(
            {"work_unit": scan_wu, "chunk_size": chunk_n, "chunks": completion, "evidence": evidence_map}))

    events.tool_start(sid, cmd=["dalfox", "scan", "-i", "file", "<chunk>", "-f", "jsonl", "--skip-mining"],
                      input_total=len(cands), work_unit=scan_wu)
    t0 = time.monotonic()
    degraded = produced = matched = 0                      # defined up-front: the finally ledger must not NameError
    tiers = {"xss-verified": 0, "xss-candidate": 0, "dom-xss-static": 0}   # if the loop raises before the aggregate
    status = Status.FAILED                                 # exception mid-loop must NOT emit scan-level success
    try:
      for ci, batch in enumerate(batches):
        chunk_wu = events.work_unit(sid, inputs={"cands": batch}, config=_cfg)
        seen = min((ci + 1) * chunk_n, len(cands))
        events.tool_progress(sid, chunk_index=ci + 1, chunk_total=len(batches), current_index=seen,
                             work_unit=chunk_wu)
        if str(ci) in completion:                         # resume: CLEAN in a prior attempt (revalidated on load)
            continue
        bf = ctx.write_list(f"dalfox_xss_{ci}.txt", batch)
        attempt_dir.mkdir(parents=True, exist_ok=True)     # created lazily, only if a chunk actually runs
        cf = attempt_dir / f"findings_{ci}.jsonl"          # IMMUTABLE per-attempt artifact (never overwritten)
        rel = f"wu_{scan_wu}/attempt_{attempt_id}/findings_{ci}.jsonl"
        events.tool_start(sid, work_unit=chunk_wu, input_total=len(batch))   # this chunk's own lifecycle
        res = None
        chunk_status = Status.FAILED.value                   # review#1: promoted ONLY after ALL bookkeeping below
        try:                                                 # review#1: chunk terminal ALWAYS fires (finally)
            res = exec_tool("dalfox", _dalfox_cmd(bf, cf, prof), ok_codes=(0, 1),
                            timeout=scaled_timeout(len(batch), ctx.http_timeout, 30))
            # dalfox v3 EXIT CONTRACT (measured): 0 = clean/no-findings, 1 = clean/WITH-findings, >=2 = error.
            # review-r9#2: exit code and parsed artifact must AGREE — CLEAN only for (0 + valid empty) or
            # (1 + valid findings). Any disagreement / hard exit / malformed artifact -> PARTIAL, retryable.
            findings, artifact_ok = _parse_dalfox_jsonl(cf)
            rc = res.exit_code
            clean = artifact_ok and ((rc == 0 and not findings) or (rc == 1 and bool(findings)))
            cf_sha = _sha256_file(cf) if cf.exists() else None
            if clean:
                completion[str(ci)] = {"rel": rel, "outcome": "SUCCESS" if findings else "EMPTY",
                                       "sha256": cf_sha}      # outcome + digest -> revalidated on resume
                _add_evidence(str(ci), rel, cf_sha)          # ...and joins this chunk's evidence history
                _save()
            else:
                degraded += 1
                why = (f"exit {rc}" if rc not in (0, 1) else
                       "artifact malformed/mismatched" if not artifact_ok else
                       f"exit {rc} disagrees with {len(findings)} finding(s)")
                events.coverage_partial(sid, reason=f"chunk {ci + 1}/{len(batches)}: {why}")
                if cf.exists() and cf.stat().st_size > 0:    # a degraded chunk WITH output keeps its evidence
                    _add_evidence(str(ci), rel, cf_sha); _save()   # (PARTIAL(A) then empty retry never erases A)
            chunk_status = (Status.SUCCESS if clean and findings
                            else Status.EMPTY if clean else Status.PARTIAL).value
        finally:
            _chunk_terminal(sid, chunk_wu, res, cf, status=chunk_status)   # FAILED if exec OR bookkeeping raised
      # review-r10#1/r11#2: DERIVE the verdict + telemetry from the RETAINED EVIDENCE (all attempts), not the
      # last per-chunk label. EVERY observation goes through Run.add() so C09 merges raw_refs / reconciles
      # conflicts across attempts (a later clean attempt's provenance must reach the store, not be dropped by a
      # pre-add dedup). A separate GLOBAL id set drives only the `matched` (distinct findings) counter; `produced`
      # counts NEW entities (Run.add True). Falls back to THIS attempt's file for a chunk just run but not yet
      # recorded. Verdict: any degraded this run -> PARTIAL; else any distinct finding -> SUCCESS; else EMPTY.
      produced = matched = 0
      tiers = {"xss-verified": 0, "xss-candidate": 0, "dom-xss-static": 0}
      seen_ids: set[str] = set()                            # GLOBAL — for the matched counter ONLY (not dedup)
      for ci in range(len(batches)):
        entries = list(evidence_map.get(str(ci)) or [])       # each already digest-validated on load
        # fall back to THIS run's just-written attempt file (trusted — we wrote it) for a chunk run but not recorded
        paths = [state_f.parent / e["rel"] for e in entries] or [attempt_dir / f"findings_{ci}.jsonl"]
        for p in paths:
            if not (p.exists() and p.stat().st_size > 0):
                continue
            fnds, _ok = _parse_dalfox_jsonl(p)
            for rec in fnds:
                rec["raw_ref"] = str(p)
                if rec["id"] not in seen_ids:
                    seen_ids.add(rec["id"]); matched += 1    # distinct finding first-seen
                if ctx.run.add("finding", rec):              # ALWAYS add -> provenance merge (raw_refs union)
                    produced += 1
                    tiers[rec["template"]] = tiers.get(rec["template"], 0) + 1
      status = Status.PARTIAL if degraded else (Status.SUCCESS if matched else Status.EMPTY)
    finally:
        # C07 inc4: source terminal ALWAYS fires (even if the loop raised) — one source lifecycle, no dup.
        events.tool_finish(sid, status=status.value, work_unit=scan_wu,
                           reason=(f"{degraded}/{len(batches)} chunk(s) degraded" if degraded else None),
                           duration=round(time.monotonic() - t0, 2), discovery_context="params")
        # ledger: NEW entities by tier (verified/candidate/dom-static kept distinct, review-r8#5) + matched
        # (all valid findings across retained evidence) tracked separately from produced (newly added).
        events.ledger(sid, produced={"xss_verified": tiers["xss-verified"],
                                     "xss_candidate": tiers["xss-candidate"],
                                     "dom_xss_static": tiers["dom-xss-static"], "matched": matched},
                      consumed={"shape": len(cands)})
    return RunResult("dalfox", ["dalfox", "scan", "-i", "file", "<chunked-xss-fast>"], status, 0,
                     round(time.monotonic() - t0, 2), None, produced,
                     note=f"{len(batches)} chunk(s), {produced} new / {matched} matched, {degraded} degraded")


_REDIR_PARAMS = {"url", "redirect", "redirect_url", "redirecturl", "redir", "redirect_uri", "return",
                 "returnto", "return_url", "returnurl", "next", "dest", "destination", "continue",
                 "goto", "target", "to", "out", "view", "u", "r", "link", "go", "checkout_url",
                 "login_url", "image_url", "window", "callback", "redirect_to"}
_REDIR_CANARY = "quarry-redirect-canary.example"   # reserved TLD; never followed/resolved


def _redirect_confirm(ctx, cands, prof) -> RunResult:
    """params.redirect_confirm (step 4.3.C): native open-redirect probe — NO dalfox, NO chromium. For
    each canonical candidate, inject a canary host into the redirect-ish param(s) and read the Location
    header WITHOUT following it (one scoped, rate-paced, non-mutating request each via
    fetch.redirect_location). If the app would send us to the canary HOST, it's an open-redirect
    CANDIDATE (confirmed:false — primitive, not impact). A relative/same-host Location is NOT a finding.
    Emits source-level events; returns a RunResult (stdout_lines = confirmed count) for the caller's
    ledger."""
    from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, urljoin
    sid = "params.redirect_confirm"
    canary_url = f"https://{_REDIR_CANARY}/rc"
    events.tool_start(sid, cmd=["<native redirect probe>", "--no-follow"], input_total=len(cands))
    t0 = time.monotonic()
    confirmed = probed = degraded = 0
    for i, u in enumerate(cands, 1):
        host = normalize.host_of_url(u)
        if not ctx.scope.active_allowed(host):        # scoped: in-scope, not passive, not OOS
            continue
        s = urlsplit(u)
        pairs = parse_qsl(s.query, keep_blank_values=True)
        if not any(k.lower() in _REDIR_PARAMS for k, _ in pairs):
            continue
        newq = [(k, canary_url if k.lower() in _REDIR_PARAMS else v) for k, v in pairs]
        probe = urlunsplit((s.scheme, s.netloc, s.path, urlencode(newq), ""))
        probed += 1
        try:
            loc, status_code = fetch.redirect_location(ctx, probe, host)
        except Exception:
            degraded += 1
            continue
        # A Location header only redirects on a 3xx — a 200/201 that happens to echo one is NOT an open
        # redirect. urljoin resolves relative/protocol-relative Locations against the origin, so a
        # same-host redirect stays on-host (not a finding); only a 3xx whose Location HOST is our canary
        # confirms.
        if loc and 300 <= int(status_code or 0) < 400 \
                and normalize.host_of_url(urljoin(probe, loc)) == _REDIR_CANARY:
            confirmed += 1
            ctx.run.add("finding", {
                "id": f"open-redirect:{u[:90]}", "template": "open-redirect-candidate",
                "name": "open-redirect candidate — param redirects off-host (manual validation required)",
                "severity": "medium", "matched": f"{probe} -> Location: {loc}",
                "sources": ["redirect_confirm"], "confirmed": False})
        events.tool_progress(sid, current_index=i, input_total=len(cands))
    status = Status.PARTIAL if degraded else Status.SUCCESS
    events.tool_finish(sid, status=status.value,
                       reason=(f"{degraded} probe error(s)" if degraded else None),
                       duration=round(time.monotonic() - t0, 2), discovery_context="params")
    return RunResult("redirect_confirm", ["<native redirect probe>"], status, 0,
                     round(time.monotonic() - t0, 2), None, confirmed,
                     note=f"{probed} probed, {confirmed} open-redirect candidate(s)")


_OOB_PARAMS = {"url", "uri", "dest", "destination", "redirect", "redirect_uri", "next", "continue",
               "return", "callback", "webhook", "target", "proxy", "fetch", "load", "site", "host",
               "domain", "feed", "image_url", "imageurl", "link", "out", "to", "u", "path", "file",
               "port", "open", "window", "data", "source", "src", "remote"}


def _oob_probe(ctx, scope, prof):
    """params.oob_probe (P2.3): Quarry-OWNED out-of-band probe. Opens an interactsh session, injects a
    per-(target,param) callback URL into the SSRF-ish params of the gf `ssrf` candidates (SCOPED +
    rate-paced + non-mutating GET via the shared fetch guard), polls the owned session, and records
    CORRELATED oob_interaction rows (source=params.oob_probe, target/param filled). A callback proves the
    SSRF / external-load PRIMITIVE reached out-of-band -> candidate, NOT impact (attack layer's job).
    Skips when passive-only / no interactsh-client / no SSRF-param candidates. Delayed callbacks are
    common — re-poll later with `quarry oob poll` (P2.4). Returns a RunResult or None."""
    from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
    if scope.passive_only:                          # record honest skips — the source is wired/default-on
        ctx.run.record("params", skipped("oob_probe", "passive-only mode"))
        return None
    if not have("interactsh-client"):
        ctx.run.record("params", skipped("oob_probe", "interactsh-client not installed"))
        return None
    raw = [r["value"] for r in ctx.run.read("review")
           if r.get("klass") == "ssrf" and scope.active_allowed(normalize.host_of_url(r.get("value", "")))]
    cands, _canon = _canonicalize_candidates(raw)
    probes = []                                    # (url, split, pairs, ssrf-param) — one token per param
    for u in cands:
        s = urlsplit(u)
        pairs = parse_qsl(s.query, keep_blank_values=True)
        for k, _v in pairs:
            if k.lower() in _OOB_PARAMS:
                probes.append((u, s, pairs, k))
    if not probes:
        ctx.run.record("params", skipped("oob_probe", "no SSRF-param candidates"))
        return None
    opened = oob.open_session(ctx.run, server=secrets.oob().get("interactsh_server"),
                              token=secrets.oob().get("interactsh_token"))
    if opened is None:
        ctx.run.record("params", skipped("oob_probe", "interactsh session did not open"))
        return None
    session, proc = opened
    sid = "params.oob_probe"
    events.tool_start(sid, cmd=["<oob probe>", "interactsh"], input_total=len(probes))
    t0 = time.monotonic()
    issued = added = correlated = 0
    try:
        for i, (u, s, pairs, k) in enumerate(probes, 1):
            # persist the mapping BEFORE the probe leaves (crash-safe: a later callback still correlates)
            token = oob.issue_token(session, sid, u, k, "ssrf-callback", run=ctx.run)
            cb = oob.callback_url(session, token, scheme="http")
            probe_url = urlunsplit((s.scheme, s.netloc, s.path,
                                    urlencode([(kk, cb if kk == k else vv) for kk, vv in pairs]), ""))
            issued += 1
            try:
                # NO-FOLLOW + header-only: if the target 302s to Location: <our-callback>, we must NOT
                # follow it — Quarry would fetch its OWN collector and fake an SSRF hit. The server-side
                # SSRF (if any) still fires from the request itself; we just don't self-trigger.
                fetch.redirect_location(ctx, probe_url, normalize.host_of_url(probe_url), timeout=10)
            except Exception:
                pass                               # a target that doesn't SSRF-fetch is the common case
            events.tool_progress(sid, current_index=i, input_total=len(probes))
        time.sleep(3)                              # brief window for a server-side callback to arrive
        for row in oob.poll_session(ctx.run, session):
            row.setdefault("raw_ref", session.get("log"))
            if ctx.run.add("oob_interaction", row):
                added += 1
                correlated += 1 if row.get("correlation") == "correlated" else 0
    finally:
        oob.close_session(proc)
    events.tool_finish(sid, status=Status.SUCCESS.value, duration=round(time.monotonic() - t0, 2),
                       discovery_context="params")
    events.ledger(sid, produced={"oob_interaction": added, "correlated": correlated},
                  consumed={"probe": issued})
    ctx.echo(f"  oob_probe: {issued} callback probe(s) -> {added} interaction(s) ({correlated} correlated)")
    return RunResult("oob_probe", ["<oob probe>"], Status.SUCCESS, 0, round(time.monotonic() - t0, 2),
                     None, added, note=f"{issued} probe(s), {added} interaction(s), {correlated} correlated")


def run(ctx) -> None:
    prof, scope = ctx.profile, ctx.scope

    # ── OpenAPI/Swagger docs -> endpoint+param corpus (BEFORE the corpus build so gf/nuclei/arjun
    #    see the extracted endpoints). Active fetch; active_allowed self-gates it off in passive. ──
    oa_urls = _openapi_urls(ctx, scope)
    if oa_urls:
        noa = evidence.parse_openapi(ctx, oa_urls)
        ctx.echo(f"  openapi: {len(oa_urls)} doc(s) parsed, +{noa} endpoint(s) into corpus")

    # in-scope URL corpus (always available from crawl, even passive)
    corpus = [u for u in ctx.run.values("url")
              if scope.in_scope(normalize.host_of_url(u)) and not scope.is_oos(normalize.host_of_url(u))]
    corpus_file = ctx.write_list("all_inscope_urls.txt", corpus)

    # ── gf vuln-class buckets -> review candidates ──
    if corpus and have("gf"):
        for pat in GF_PATTERNS:
            raw = ctx.run.raw_path("params", "gf", f"{pat}.txt")
            r = exec_tool("gf", ["gf", pat], input_file=corpus_file, raw_path=raw, timeout=120)
            ctx.run.record("params", r)
            if r.raw_path:
                for line in r.raw_path.read_text().splitlines():
                    u = line.strip()
                    if u:
                        ctx.run.add("review", {"id": f"{pat}:{u}", "klass": pat, "value": u,
                                               "sources": ["gf"]})
        ctx.echo(f"  gf candidates: {ctx.run.count('review')}")
    elif corpus:
        ctx.run.record("params", skipped("gf", "gf not installed / no ~/.gf patterns"))

    if scope.passive_only:
        ctx.run.record("params", skipped("nuclei", "passive-only mode"))
        ctx.run.record("params", skipped("dalfox", "passive-only mode"))
        return

    # ── subdomain takeover (nuclei takeover templates over known subs) ──
    if prof.takeover and have("nuclei"):
        # Union, not "resolved or subdomain": dangling-CNAME hosts (the takeover signal)
        # have no A record and live only in `subdomain` — they must still be checked.
        subs = scope.filter_hosts(sorted(set(ctx.run.values("resolved"))
                                         | set(ctx.run.values("subdomain"))))
        # netguard fresh-resolves these subs: RECORDS private/self leads, WITHHOLDS only scan-box/metadata
        # self-hits (private is scanned), and KEEPS authoritative-NXDOMAIN dangling hosts (allow_dangling) —
        # exactly the takeover signal — while a transient-indeterminate host still passes through.
        subs = netguard.guard_hosts(ctx, subs, phase="params.takeover", allow_dangling=True)
        if subs:
            tk_in = ctx.write_list("takeover_targets.txt", subs)
            tk_out = ctx.run.raw_path("params", "nuclei", "takeover.jsonl")
            tk_cmd = ["nuclei", "-l", str(tk_in), "-tags", "takeover", "-jsonl", "-o", str(tk_out)]
            # NB: nuclei has no connect-time IP deny (-eh excludes INPUT entries, not resolved IPs); the
            # scan-box/metadata protection for these subs is netguard.guard_hosts' fresh-resolve above.
            if prof.http_rl:                       # else native default (empty = fast)
                tk_cmd += ["-rl", str(prof.http_rl)]
            _apply_nuclei_oob(tk_cmd)              # same OOB endpoint as the main scan (no drift)
            r = exec_tool("nuclei", tk_cmd, timeout=nuclei_timeout(len(subs), ctx.http_timeout))
            ctx.run.record("params", r)
            if tk_out.exists():
                import json as _json
                for line in tk_out.read_text().splitlines():
                    try:
                        o = _json.loads(line)
                    except _json.JSONDecodeError:
                        continue
                    ctx.run.add("finding", {"id": f"takeover:{o.get('matched-at', o.get('host'))}",
                                            "template": o.get("template-id", "takeover"),
                                            "severity": "high", "name": "possible subdomain takeover",
                                            "matched": o.get("matched-at", o.get("host", "")),
                                            "sources": ["nuclei-takeover"], "confirmed": False})

    live = [u for u in ctx.run.values("live") if scope.active_allowed(normalize.host_of_url(u))]
    # FRESH self-attack guard right before the scan: `live` was resolved back in the probe phase (possibly
    # hours + a crawl/content phase ago), so re-check current resolution — a host that now points to the scan
    # box / metadata never reaches a nuclei chunk. Private targets stay allowed (recorded as leads).
    live = netguard.guard_urls(ctx, live, phase="params.nuclei_scan")
    if not live:
        ctx.run.record("params", skipped("nuclei", "no active-allowed live hosts"))
        return
    # ── nuclei (non-intrusive, OOB interactsh, severity-scoped) — chunked + resumable (step 4.2 B) ──
    # The long-pole: OTC = 448 hosts / 5.08M req / 7h41 @ 183rps, died at 93%. Work is rate-bound, so we
    # do NOT gate templates or parallelize batches (would blow the RoE) — we chunk hosts for resume,
    # progress and per-batch isolation. See _nuclei_scan.
    findings = ctx.run.raw_path("params", "nuclei", "findings.jsonl")
    log = ctx.run.raw_path("params", "nuclei", "nuclei.run.log")
    ck = max(1, settings.concurrency("NUCLEI_CHUNK_HOSTS", 50))
    _nchunks = (len(live) + ck - 1) // ck
    _budget = nuclei_timeout(min(ck, len(live)), ctx.http_timeout)
    # UX #1: 0 means unbounded (not "0m"). A sub-minute / non-round budget must not truncate to "0m"/whole
    # minutes — render exact m/s so a 45s or 90s ceiling reads honestly.
    if not _budget:
        _budget_txt = "unbounded"
    elif _budget < 60:
        _budget_txt = f"{_budget}s"
    elif _budget % 60:
        _budget_txt = f"{_budget // 60}m{_budget % 60}s"
    else:
        _budget_txt = f"{_budget // 60}m"
    _final = len(live) - (_nchunks - 1) * ck if _nchunks else 0
    ctx.echo(f"  nuclei: {len(live)} host(s) · {_nchunks} sequential chunk(s) of {ck}"
             + (f" (final {_final})" if _nchunks > 1 and _final != ck else "")
             + f" · per-chunk budget {_budget_txt} · checkpointed")   # UX #5: 'checkpointed' (no operator --resume yet)
    r = _nuclei_scan(ctx, live, findings, log, prof)
    ctx.run.record("params", r)
    if findings.exists():
        n = 0
        sev = {"critical": 0, "high": 0, "medium": 0}
        for line in findings.read_text().splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            tid = obj.get("template-id", "?")
            severity = (obj.get("info") or {}).get("severity", "unknown")
            ctx.run.add("finding", {
                "id": f"{tid}|{obj.get('matched-at', obj.get('host',''))}",
                "template": tid, "severity": severity,
                "name": (obj.get("info") or {}).get("name"),
                "matched": obj.get("matched-at", obj.get("host", "")),
                "sources": ["nuclei"], "confirmed": False})
            if severity in sev:
                sev[severity] += 1
            n += 1
        # terser than the old unconfirmed-validation note — the HOTLIST/digest already carry that
        # framing; here a severity breakdown is more useful at a glance.
        ctx.echo(f"  nuclei: {n} candidate findings · "
                 f"crit:{sev['critical']} high:{sev['high']} med:{sev['medium']}")
        events.ledger("params.nuclei_scan",
                      produced={"finding": n, **sev}, consumed={"target": len(live)})

    # ── exposed-resource fetch + secret extraction (recon evidence: unauth, in-scope, GET-only) ──
    # Map-don't-exploit line = "don't accidentally perform impact": an exposed .env/.git/config is
    # fetched and its secret read (redacted). No payloads, no creds used, no state change.
    exp_urls = _exposed_urls(ctx, scope)
    if exp_urls:
        ne = evidence.fetch_exposed(ctx, exp_urls)
        ctx.echo(f"  exposed-fetch: {len(exp_urls)} exposed resource(s), +{ne} secret(s) extracted")

    # ── GraphQL introspection probe (recon evidence: non-mutating read query, in-scope) ──
    gql_urls = _graphql_urls(ctx, scope)
    if gql_urls:
        ng = evidence.probe_graphql(ctx, gql_urls)
        ctx.echo(f"  graphql: {len(gql_urls)} endpoint(s) probed, {ng} with introspection enabled")

    # ── Actuator sensitive sub-path interrogation (recon evidence: GET-only, non-mutating) ──
    act_bases = _actuator_bases(ctx, scope)
    if act_bases:
        na = evidence.probe_actuator(ctx, act_bases)
        ctx.echo(f"  actuator: {len(act_bases)} base(s) probed, {na} with sensitive endpoints exposed")

    # ── framework-conditional recon endpoints (tech-matched debug/admin dashboards; GET-only) ──
    fw_cands = _framework_endpoint_candidates(ctx, scope)
    if fw_cands:
        nf = evidence.probe_framework_endpoints(ctx, fw_cands)
        ctx.echo(f"  framework-endpoints: {len(fw_cands)} candidate(s) probed, {nf} exposed (200)")

    # ── arjun param discovery on param-less API endpoints (throttled) ──
    ARJUN_CAP = 40
    _api_all = sorted({u.split("?")[0] for u in corpus
                       if "?" not in u and any(s in u.lower() for s in
                       ("/api", "/rest", "/account", "/profile", "/search", "/user", "/order"))})
    _api_all = netguard.guard_urls(ctx, _api_all, phase="params.arjun")   # fresh-resolve: withhold scan-box/metadata, contact private
    api_eps = _api_all[:ARJUN_CAP]
    _n_api = len(_api_all)          # emit every run (omitted=0 clears a prior cap gap on rerun)
    events.coverage_partial("params.arjun", kind=events.COVERAGE_CAP, measure="api_endpoints",
                            eligible=_n_api, tested=min(_n_api, ARJUN_CAP), omitted=max(0, _n_api - ARJUN_CAP),
                            reason=f"arjun targets {min(_n_api, ARJUN_CAP)}/{_n_api} API endpoints (cap {ARJUN_CAP})")
    if api_eps:
        aj_in = ctx.write_list("arjun_targets.txt", api_eps)
        aj_out = ctx.run.raw_path("params", "arjun", "arjun.txt")
        aj_out.unlink(missing_ok=True)                     # stale -oT must not fake completion
        # RoE rate. The old `-d 1/rl` was NOT a breach: arjun forces threads=1 whenever a delay is set
        # (verified arjun __main__.py), so it paced correctly but SERIALLY. `--rate-limit` (verified -h)
        # is the better control — a global RPS cap that does NOT collapse threads, so concurrency (`-t`)
        # is preserved under the ceiling. Applied only when the operator sets http_rl. Coverage unchanged.
        aj_cmd = ["arjun", "-i", str(aj_in), "-oT", str(aj_out),
                  "-t", str(settings.workers("arjun", 5))]   # was hard-coded -t 5; I/O-scaled + config-tunable
        if prof.http_rl:
            aj_cmd += ["--rate-limit", str(prof.http_rl)]   # global RPS cap; keeps -t concurrency (unlike -d)
        r = exec_tool("arjun", aj_cmd, timeout=ctx.http_timeout)
        # arjun is a FILE-output tool (-oT); its status must come from the artifact, not its chatty stdout.
        # The OTC false-success: exit 0 + 3954 stdout lines but NO arjun.txt -> classified SUCCESS with 0
        # params. Reclassify from the parsed -oT via the shared adapter (0 params -> EMPTY, absent/unreadable
        # -> PARTIAL/keep-hard). Each -oT line is a param-bearing URL (e.g. ".../v1/search?q=7101").
        urls = _arjun_urls(aj_out)
        reclassify_from_artifact(r, None if urls is None else len(urls), label="arjun")
        ctx.run.record("params", r)
        # Feed arjun's output forward — record provenance AND hand the param-bearing URL to dalfox so a
        # hidden reflected param actually gets XSS-tested (without this it was written to a file + dropped).
        naj = 0
        for u in (urls or []):
            base, qs = u.split("?", 1)
            ctx.run.add("url", {"url": u, "sources": ["arjun"]})
            for pair in qs.split("&"):
                pname = pair.split("=", 1)[0]
                if pname:
                    ctx.run.add("parameter", {"value": f"{base}?{pname}=",
                                              "sources": ["arjun"]})
            ctx.run.add("review", {"id": f"arjun-param:{u[:100]}", "klass": "xss",
                                   "value": u, "host": normalize.host_of_url(u),
                                   "sources": ["arjun"]})
            naj += 1
        if naj:
            ctx.echo(f"  arjun: +{naj} param-bearing URL(s) -> dalfox candidates")
    else:
        ctx.run.record("params", skipped("arjun", "no param-less API endpoints found"))

    # ── vuln-primitive probes over the 4.3.A CANONICALIZED shapes, SPLIT by primitive ──
    # XSS reflection -> params.dalfox_xss_fast (dalfox, 4.3.B). Open-redirect -> params.redirect_confirm
    # (native Location probe, NO dalfox, 4.3.C). dalfox is no longer responsible for redirect at all.
    xss_raw = [r["value"] for r in ctx.run.read("review") if r.get("klass") == "xss"]
    redir_raw = [r["value"] for r in ctx.run.read("review") if r.get("klass") == "redirect"]
    xss_cands, xss_canon = _canonicalize_candidates(xss_raw)
    redir_cands, redir_canon = _canonicalize_candidates(redir_raw)
    # audit #1: dalfox is an external tool that CONTACTS these URLs — drop any whose host resolves internal /
    # can't be resolved. (redir_cands go through fetch.redirect_location, which resolve-guards each origin.)
    xss_cands = netguard.guard_urls(ctx, xss_cands, phase="params.dalfox")
    if not xss_cands and not redir_cands:
        ctx.run.record("params", skipped("dalfox", "no xss/redirect candidates"))
    # XSS reflection — dalfox fast path (needs dalfox)
    if xss_cands:
        if have("dalfox"):
            ctx.echo(f"  dalfox xss: {xss_canon['raw_candidates']} raw -> "
                     f"{xss_canon['canonical_candidates']} shape(s) "
                     f"({xss_canon['reduction_percent']}% collapsed)")
            ctx.run.record("params", _dalfox_xss_fast(ctx, xss_cands, prof))
        else:
            ctx.run.record("params", skipped("dalfox", "dalfox not installed"))
    # open-redirect — native single-request Location probe (4.3.C), no dalfox
    if redir_cands:
        r = _redirect_confirm(ctx, redir_cands, prof)
        ctx.echo(f"  redirect_confirm: {redir_canon['raw_candidates']} raw -> "
                 f"{redir_canon['canonical_candidates']} shape(s) -> {r.stdout_lines} confirmed candidate(s)")
        ctx.run.record("params", r)
        # ledger: raw redirect candidates -> canonical shapes -> confirmed open-redirect candidates
        events.ledger("params.redirect_confirm",
                      produced={"open_redirect_candidate": r.stdout_lines},
                      consumed={"raw_candidates": redir_canon["raw_candidates"],
                                "canonical_candidates": redir_canon["canonical_candidates"]},
                      reduction_percent=redir_canon["reduction_percent"])

    # ── SSTI primitive-confirm probe (benign {{math}} eval; candidate output) ──
    # gf only name-matches ssti params; nothing else probes them. Confirm the PRIMITIVE with a
    # non-mutating math eval. (reflection/open-redirect primitives are already covered by dalfox.)
    ssti_urls = _ssti_targets(ctx, scope)
    if ssti_urls:
        ns = evidence.probe_ssti(ctx, ssti_urls)
        if ns:
            ctx.echo(f"  ssti: +{ns} SSTI primitive candidate(s) confirmed (manual validation required)")

    # ── OOB probe (P2.3): Quarry-owned interactsh callback on SSRF-ish params (correlated evidence) ──
    oob_r = _oob_probe(ctx, scope, prof)
    if oob_r is not None:
        ctx.run.record("params", oob_r)
