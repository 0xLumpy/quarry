"""Tool runner — executes external tools with explicit limits and a status taxonomy.

The core anti-goal of the whole framework is *silent thin output*. The runner makes
every execution explainable: it captures stdout/stderr/exit/duration, stores raw
output before any parsing, and classifies the result so downstream phases never treat
a failure/block/timeout as a genuine "nothing found" (design §3).
"""
from __future__ import annotations

import os
import signal
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

try:
    import resource                              # unix-only; per-tool child CPU via getrusage delta
except ImportError:                              # pragma: no cover — non-unix fallback
    resource = None


def _rss_tree_mb(root_pid: int) -> float:
    """Peak-sample helper: PROPORTIONAL physical RAM (MB) of `root_pid` + all its descendants.

    Uses PSS (Proportional Set Size) from `/proc/<pid>/smaps_rollup` — a shared page is divided among
    its sharers, so summing a tree of copy-on-write processes (chromium's child procs, forked workers)
    gives the TRUE physical footprint. A naive VmRSS *sum* counts shared pages once per process and can
    inflate a tool's RAM manyfold (measured: a v2 dalfox+chromium tree read ~8 GB by VmRSS-sum vs a 664 MB
    true peak). Falls back to VmRSS when smaps_rollup is unavailable. Best-effort; 0.0 on error/non-Linux."""
    try:
        parents: dict[int, int] = {}
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            try:
                with open(f"/proc/{name}/status") as f:
                    for line in f:
                        if line.startswith("PPid:"):
                            parents[int(name)] = int(line.split()[1])
                            break
            except (OSError, ValueError):
                continue
        children: dict[int, list[int]] = {}
        for pid, ppid in parents.items():
            children.setdefault(ppid, []).append(pid)
        total_kb = 0
        stack, seen = [root_pid], set()
        while stack:
            p = stack.pop()
            if p in seen or p not in parents:
                continue
            seen.add(p)
            total_kb += _proc_mem_kb(p)
            stack.extend(children.get(p, []))
        return total_kb / 1024.0
    except Exception:
        return 0.0


def _proc_mem_kb(pid: int) -> int:
    """A process's proportional RAM in kB: PSS from smaps_rollup (shared-aware), else VmRSS."""
    try:
        with open(f"/proc/{pid}/smaps_rollup") as f:
            for line in f:
                if line.startswith("Pss:"):
                    return int(line.split()[1])
    except OSError:
        pass
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return 0

# Some tools write stray files to the current directory (gowitness's sqlite, github-subdomains'
# <domain>.txt, …). Point the working directory at a per-run scratch dir so those land inside the
# run, not wherever the user launched `quarry`. All tool I/O uses absolute paths, so this only
# affects relative/stray output. Set once per run/osint via set_tool_cwd().
_TOOL_CWD: str | None = None


def set_tool_cwd(path) -> None:
    global _TOOL_CWD
    _TOOL_CWD = str(path) if path else None


def fresh_artifact_dir(base) -> "Path":
    """A FRESH per-invocation subdirectory `base/attempt-N` — the first N whose name is free — created
    ATOMICALLY (mkdir exist_ok=False). For file-output tools whose result count is derived by globbing a
    directory (gowitness): a reused / pre-populated directory would let a PRIOR run's artifacts inflate this
    attempt's count (and launder a failed/empty run). Counting existing dirs is unsafe (gaps like attempt-0
    + attempt-2 would reopen the occupied attempt-2), so we probe upward and let the atomic create claim the
    first free slot — this fills gaps, skips any name already taken by a file or dir, and stops two
    concurrent callers sharing an attempt. Prior attempts are PRESERVED as evidence — never deleted."""
    base = Path(base)
    base.mkdir(parents=True, exist_ok=True)
    n = 0
    while True:
        d = base / f"attempt-{n}"
        try:
            d.mkdir(exist_ok=False)                        # atomic: raises if the name is taken -> next slot
            return d
        except FileExistsError:
            n += 1


def reclassify_from_artifact(r: "RunResult", n: "int | None", *, label: str = "tool") -> "RunResult":
    """Shared file-output status matrix (the pattern hardened across reclassify_ffuf / _gitleaks_status /
    the naabu prefilter). A file-output tool leaves an empty stdout, so the generic classifier mislabels it
    from a stderr line; the ARTIFACT is authoritative. `n` = count of VALIDATED results (>=0) when the
    artifact is a trustworthy complete result, or None when there is NO trustworthy artifact (missing /
    unreadable / malformed). The CALLER owns the format-specific FAIL-CLOSED parse and MUST clear the stale
    artifact before running the tool (a stale file must not fake completion). Matrix:
      - SKIPPED                     -> unchanged (never ran)
      - clean (SUCCESS/EMPTY only):  n>0 -> SUCCESS · n==0 -> EMPTY · None -> PARTIAL (completion uncertain)
      - degraded (anything else — FAILED/TIMED_OUT/BLOCKED/PARTIAL): n>0 -> PARTIAL (evidence, incomplete);
        n==0 or None -> KEEP the original status (an empty/absent artifact preserves nothing, so a hard
        run is NEVER laundered into SUCCESS/EMPTY)."""
    if r.status in (Status.SKIPPED, Status.LIMITED):
        # review-B0r4#3: LIMITED must never be re-derived from an artifact. It is a PROVEN provider
        # boundary; folding it into the clean/degraded matrix would either launder it into SUCCESS
        # (losing the limit) or demote it to a degraded PARTIAL (inventing a defect).
        return r
    # enforce the count contract: only a real int >= 0 is a trustworthy count. bool (a truthy int
    # subclass), float, str, or a negative -> None (no trustworthy artifact), so a bad count fails CLOSED
    # instead of laundering (e.g. -1 / True would otherwise be truthy and read as a successful result).
    if n is not None and (isinstance(n, bool) or not isinstance(n, int) or n < 0):
        n = None
    clean = r.status in (Status.SUCCESS, Status.EMPTY)
    if n is not None:
        r.stdout_lines = n
    if n:                                              # n > 0
        r.status = Status.SUCCESS if clean else Status.PARTIAL
        r.note = f"{label}: {n} result(s)" + ("" if clean else " (degraded — scan did not complete)")
    elif clean and n is not None:                      # clean + 0 valid results
        r.status, r.note = Status.EMPTY, f"{label}: 0 results (clean)"
    elif clean:                                        # clean but no trustworthy artifact
        r.status, r.note = Status.PARTIAL, f"{label}: artifact missing/malformed — completion uncertain"
    # else: degraded + empty/absent -> keep the original (hard) status
    return r


def reclassify_from_files(r: "RunResult", produced: int, note_word: str = "item") -> "RunResult":
    """Count-based file-output adapter (gowitness screenshots, …): `produced` = artifact COUNT. Thin
    wrapper over reclassify_from_artifact so a non-empty count on a DEGRADED run is PARTIAL, never
    laundered to SUCCESS (the old behavior turned FAILED+output into SUCCESS)."""
    return reclassify_from_artifact(r, produced, label=note_word)


def ffuf_results(out_file) -> "list | None":
    """Parse an ffuf `-o` JSON artifact into its results list. Returns None when there is NO valid current
    artifact — missing / unreadable / JSON root not an object / `results` not a list — so a caller can
    distinguish "ffuf completed and served this" from "no trustworthy artifact, trust the classifier".
    Central so probe/content and reclassify all validate the root the same way (a bare `[]` root must not
    AttributeError)."""
    import json as _json
    from pathlib import Path as _Path
    try:
        data = _json.loads(_Path(out_file).read_text() or "{}")
    except (OSError, _json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    results = data.get("results")
    if not isinstance(results, list):
        return None
    # review#4 (A1): a structurally malformed ROW means the artifact itself is not trustworthy. Silently
    # filtering `{"results":[null]}` down to `[]` made a corrupt artifact read as a clean EMPTY, which a
    # resumable ledger then journaled as done. ffuf does not emit non-object rows, so any is corruption:
    # fail CLOSED for the whole artifact rather than ingest a subset of a broken file.
    if any(not isinstance(row, dict) for row in results):
        return None
    return list(results)


def ffuf_usable_rows(rows, validate) -> "tuple[list, int]":
    """Split structurally-valid ffuf rows into (USABLE, dropped_count) using a lane's TYPE-CHECKING predicate.

    review#4 (A1): structural validity is not usability — `{"results":[{}]}` is a dict row, so it survived the
    central filter and the run read SUCCESS while yielding no evidence.

    review#1 (A1 r2): a "non-empty field" check is still fail-open. Verified: `url: ["http://h/a"]`,
    `status: true` and `status: "200"` all passed it — the list URL then raised TypeError inside
    host_of_url, and the others would have polluted normalized data. `validate` is a per-lane PREDICATE so
    each lane asserts the actual TYPES it ingests, not merely the presence of a key."""
    usable = [r for r in rows if validate(r)]
    return usable, len(rows) - len(usable)


def ffuf_http_row(row) -> bool:
    """A usable ffuf row for a URL-ingesting lane: a genuinely ABSOLUTE http(s) URL and a real HTTP status.

    `isinstance(x, bool)` is excluded explicitly — bool is an int subclass, so `status: true` would otherwise
    read as a valid status code.

    review#6 (A1 r3): `startswith()` + `int` was still fail-open. Verified passing: `http://` (no authority),
    `http:///path` (empty host), `https://h:99999/` (impossible port), `status: 9999` and `status: 0`. The
    authority is parsed and the status constrained to the real HTTP range instead."""
    from urllib.parse import urlsplit
    u, st = row.get("url"), row.get("status")
    if not isinstance(st, int) or isinstance(st, bool) or not (100 <= st <= 599):
        return False
    if not isinstance(u, str) or len(u) > 8192:
        return False
    try:
        parts = urlsplit(u)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return False
        if parts.port is not None and not (1 <= parts.port <= 65535):
            return False
    except ValueError:                                   # urlsplit raises on a malformed port
        return False
    return True


def reclassify_ffuf(r: "RunResult", out_file, stderr_file=None, maxtime=None) -> "RunResult":
    """ffuf artifact adapter (audit): ffuf writes hits to `-o` JSON while `-s` keeps stdout empty, so the
    generic classifier (stdout + stderr only) can't see the real result and a transport line mislabels the
    run. A VALID artifact (dict root + list `results`) means ffuf reached completion; refine on it:
      - SKIPPED                -> stay SKIPPED (never ran; nothing to refine)
      - FAILED / TIMED_OUT     -> hard stop: findings upgrade to PARTIAL (coverage incomplete), never SUCCESS;
                                  0 findings keeps the hard state
      - BLOCKED + hits         -> PARTIAL (blocked-but-some-served; any exit code — findings are evidence)
      - BLOCKED + 0, exit 0    -> PARTIAL "block observed, 0 candidates (completed)" (clean exit proves ffuf
                                  finished — a block hit some request, not the whole job)
      - BLOCKED + 0, exit != 0 -> stay BLOCKED (block-associated hard stop: nonzero exit + nothing served)
                                  — as does a missing/invalid artifact (real block before write)
      - PARTIAL (transport)    -> hits => stay PARTIAL (degraded coverage); 0 => stay PARTIAL (uncertain)
      - clean                  -> hits => SUCCESS; 0 => EMPTY
    A missing / invalid `-o` (hard error / real block before write) keeps the classifier verdict.
    Callers MUST clear `out_file` before invoking ffuf so a stale prior-run artifact can't fake completion.
    Sets stdout_lines to the result count. Returns the mutated RunResult."""
    if r.status in (Status.SKIPPED, Status.LIMITED):
        # review-B0r4#3: LIMITED must never be re-derived from an artifact. It is a PROVEN provider
        # boundary; folding it into the clean/degraded matrix would either launder it into SUCCESS
        # (losing the limit) or demote it to a degraded PARTIAL (inventing a defect).
        return r                                             # never ran -> no artifact refinement
    # ffuf hit its native -maxtime ceiling: it STOPS mid-wordlist, finalizes the artifact, then exits
    # CLEAN (exit 0) — so the generic classifier reads SUCCESS/EMPTY even though the run was TRUNCATED.
    # Demote to PARTIAL first (a degraded state) so the matrix below never launders it into SUCCESS/EMPTY.
    # review#4 (vhost r1): read the COMPLETE stderr when the caller persisted it. `stderr_tail` is only the
    # LAST 8 LINES, so ffuf output after the cap notice evicted the marker and a TRUNCATED run became
    # SUCCESS — then a resumable ledger journaled it as done. Exactly the mistake just fixed for nuclei.
    _err, _full = r.stderr_tail or "", False
    if stderr_file is not None:
        try:
            if Path(stderr_file).is_file():
                _err, _full = Path(stderr_file).read_text(errors="replace"), True
        except OSError:
            pass
    if r.status in (Status.SUCCESS, Status.EMPTY):
        capped = "maximum running time" in _err.lower()
        if not capped and not _full and maxtime:
            # review#3 (vhost r2): falling back to the 8-line tail RECREATED the original bug whenever the
            # stderr file was missing or unreadable — an evicted marker meant a truncated run read SUCCESS
            # and got journaled as done. Without the full text we cannot see the marker, so DURATION decides:
            # reaching the ceiling means truncated. An early natural finish stays clean.
            capped = r.duration >= maxtime
        if capped:
            r.status = Status.PARTIAL
            r.note = ("ffuf: hit its -maxtime ceiling — run TRUNCATED, coverage incomplete"
                      + ("" if _full else " (inferred from duration; full stderr unavailable)"))
    results = ffuf_results(out_file)
    if results is None:
        # review#4 (A1): FAIL CLOSED on a clean exit. `-o` is ffuf's REQUIRED output, so a missing or
        # malformed artifact after a clean run means completion is UNPROVEN — leaving SUCCESS/EMPTY let a
        # resumable ledger journal it as done and never rerun it. A degraded status keeps its own verdict
        # (a hard stop before write is already honest).
        if r.status in (Status.SUCCESS, Status.EMPTY):
            r.status = Status.PARTIAL
            r.note = "ffuf: -o artifact missing/malformed — completion uncertain"
        return r
    n = len(results)
    r.stdout_lines = n
    # ffuf hard states: ffuf errored / was killed. It may have left a partial artifact, but the run did
    # NOT complete — findings may upgrade to PARTIAL, but NEVER to SUCCESS/EMPTY.
    if r.status in (Status.FAILED, Status.TIMED_OUT):
        # ffuf errored / was killed; a partial artifact can only lift this to PARTIAL, never SUCCESS.
        if n > 0:
            r.status, r.note = Status.PARTIAL, f"ffuf: {n} result(s) ({r.status.value}; coverage incomplete)"
        return r                                             # 0 findings -> keep the hard state
    if r.status == Status.BLOCKED:
        # findings prove ffuf served some paths despite the block -> PARTIAL (evidence, incomplete).
        if n > 0:
            r.status, r.note = Status.PARTIAL, f"ffuf: {n} result(s) (some blocked)"
        # 0 findings: only a CLEAN exit proves the job COMPLETED (block hit some request, not the whole run)
        # -> PARTIAL. A nonzero exit + 0 findings is a block-associated hard stop -> stay fully BLOCKED.
        elif r.exit_code == 0:
            r.status, r.note = Status.PARTIAL, "ffuf: block observed, 0 candidates (completed)"
        return r
    degraded = r.status == Status.PARTIAL                    # transport degradation (not a block)
    if n > 0:
        r.status = Status.PARTIAL if degraded else Status.SUCCESS
        r.note = f"ffuf: {n} result(s)" + (" (degraded coverage)" if degraded else "")
    else:
        r.note = ("ffuf: 0 results, transport-degraded (completion uncertain)" if degraded
                  else "ffuf: 0 results (clean)")
        r.status = Status.PARTIAL if degraded else Status.EMPTY
    return r


def scaled_timeout(n_units: int, floor: int, per_unit: float) -> int:
    """Workload-scaled wall-clock CEILING (not a duration). The tool exits when it finishes, so a
    generous ceiling only lets a big job COMPLETE — it never slows a small one. Budget grows `per_unit`
    seconds per unit of work above `floor`; NO upper cap (scope size must never truncate coverage). Used
    by nuclei (per target), httpx (per host, port-weighted) and ffuf (per wordlist entry) so a large
    scope can't wall out mid-run — a flat 1800s cut a 567-host × 94-port httpx probe at partial coverage.
    `floor <= 0` => fully unbounded (no kill at all)."""
    if floor <= 0:
        return 0
    return max(int(floor), int(per_unit * max(int(n_units), 1)))


def nuclei_timeout(n_targets: int, floor: int, per_target: int = 240) -> int:
    """Scale a nuclei run's timeout by workload. nuclei runtime grows with target count (roughly
    templates × targets / concurrency), so a flat per-tool ceiling kills big scans mid-run and yields
    the "coverage is partial" checkpoint. Here `floor` (the base `--timeout`) is the minimum for small
    scopes, and the budget grows ~`per_target` seconds per target — so a large program (thousands of
    live hosts / endpoints) gets the time it needs. NO upper cap by design: scope size must never
    truncate coverage. The computed (large) ceiling still bounds a genuinely-hung process.

    `per_target` is a CEILING, not a duration: nuclei exits when it finishes, so a generous value only
    lets a slow run complete — it never slows a fast one. Bumped 90→240s after a 34-host range run hit
    the 90s/host ceiling still partial (the always-responsive test range engages far more templates
    per host than a real target; a real host's mostly-404 responses finish well inside this).

    `floor <= 0` (i.e. `--timeout 0`) means FULLY UNBOUNDED — no wall-clock kill at all (reconftw's
    `PARALLEL_JOB_TIMEOUT_SECONDS=0` semantics), for RoE-driven runs where a cut is unacceptable."""
    return scaled_timeout(n_targets, floor, per_target)   # nuclei-specific alias (kept for the rationale)


class Status(str, Enum):
    SUCCESS = "success"     # ran clean, produced output
    EMPTY = "empty"         # ran clean, zero output (genuine nothing-found)
    PARTIAL = "partial"     # produced output but stderr shows trouble
    FAILED = "failed"       # nonzero exit
    TIMED_OUT = "timed_out"
    BLOCKED = "blocked"     # stderr matches WAF/rate-limit/forbidden signatures
    SKIPPED = "skipped"     # not run (scope/mode/missing tool/no input)
    # review-B0r3#1: an EXTERNAL PROVIDER LIMIT (credits spent, plan cannot reach the endpoint) is a
    # CLEAN execution that a third party cut short. It is not FAILED and it is not degraded either — a
    # degraded count says something went wrong here, and nothing did. Distinct outcome, deliberately
    # OUTSIDE store._DEGRADED, so it feeds `complete_with_limits` without inflating any trouble counter.
    LIMITED = "limited"     # ran clean; the PROVIDER stopped us (quota/entitlement) — coverage incomplete


# stderr signatures of a real DENIAL — the target STOPPED us (WAF/rate-limit/forbidden), not "nothing exists".
BLOCK_SIGNATURES = (
    "403 forbidden", "429", "too many requests", "rate limit", "rate-limit",
    "access denied", "captcha", "cloudflare", "akamai", "web application firewall", " waf ",
)
# stderr signatures of TRANSPORT degradation — the connection failed/timed out, the tool kept going. This is
# DEGRADED COVERAGE, not a block: a transport error must NOT read as "WAF blocked" (audit: ffuf autocal
# `context deadline exceeded` was mislabeled BLOCKED). Downgrades a clean run to PARTIAL, never to BLOCKED.
TRANSPORT_SIGNATURES = (
    "connection reset", "i/o timeout", "context deadline exceeded", "deadline exceeded",
    "connection refused", "no such host", "tls handshake", "timeout awaiting", "eof",
)


@dataclass
class RunResult:
    tool: str
    cmd: list[str]
    status: Status
    exit_code: int | None
    duration: float
    raw_path: Path | None
    stdout_lines: int
    stderr_tail: str = ""
    note: str = ""
    cpu_s: float = 0.0                 # child CPU seconds for THIS tool (getrusage delta)
    peak_rss_mb: float = 0.0           # peak RSS of this tool's process tree (/proc sampling)
    meta: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        """Ran acceptably. review-B0r4#3: LIMITED belongs here — the execution was CLEAN and a provider
        cut it short, so excluding it would make an external limit read as 'did not run acceptably'."""
        return self.status in (Status.SUCCESS, Status.PARTIAL, Status.LIMITED)


def have(bin_name: str) -> bool:
    return shutil.which(bin_name) is not None


# ── concurrent-run CPU accounting (review#7, A2) ──────────────────────────────────────────────────────
# getrusage(RUSAGE_CHILDREN) is per-PROCESS, not per-child, so a delta taken around one tool is only that
# tool's CPU while tools run sequentially. Any overlap makes every concurrent delta wrong. Rather than
# silently report a fabricated number we mark each overlapping run unmeasurable: a run is contaminated if
# ANY other run was in flight at any moment of its lifetime — including one that started after it.
_CPU_LOCK = threading.Lock()
_CPU_INFLIGHT: dict[int, bool] = {}
_CPU_NEXT = [0]


def _cpu_start() -> int:
    with _CPU_LOCK:
        token = _CPU_NEXT[0]
        _CPU_NEXT[0] += 1
        overlap = bool(_CPU_INFLIGHT)
        _CPU_INFLIGHT[token] = overlap
        if overlap:
            for k in _CPU_INFLIGHT:                # the runs already in flight are contaminated too
                _CPU_INFLIGHT[k] = True
        return token


def _cpu_finish(token: int) -> bool:
    """True when this run overlapped another and its CPU delta must NOT be reported."""
    with _CPU_LOCK:
        return _CPU_INFLIGHT.pop(token, False)


def cpu_measured(r: "RunResult") -> bool:
    """Whether `r.cpu_s` is a real measurement (-1.0 = unmeasured, concurrent execution)."""
    return r.cpu_s >= 0.0


# ── cooperative cancellation for CONCURRENT lanes (review#2, A2) ──────────────────────────────────────
# Python delivers KeyboardInterrupt to the MAIN thread only, so a tool running inside a worker thread
# never reaches run()'s own interrupt branch: its subprocess keeps going and ThreadPoolExecutor.__exit__
# waits for it — unbounded with `timeout 0`. The main thread therefore needs a way to reach INTO the
# workers and tear their process groups down. `future.cancel()` cannot: it only drops work not yet
# started. A registry of live process groups can.
_LIVE_LOCK = threading.Lock()
_LIVE_PROCS: dict[int, "subprocess.Popen"] = {}
_LIVE_SEQ = [0]
_CANCELLED = threading.Event()


def cancelled() -> bool:
    return _CANCELLED.is_set()


def reset_cancel() -> None:
    """Clear the cancellation latch (a fresh lane, or a test)."""
    _CANCELLED.clear()


def cancel_all(grace: "float | None" = None) -> int:
    """Latch cancellation and terminate EVERY live tool process group. Returns how many were signalled.

    Safe to call from the main thread while workers are blocked in communicate(): the group is killed,
    communicate() then returns promptly, and each worker unwinds through its own finally.

    review#1 (A2 r3): the groups are signalled CONCURRENTLY under ONE SHARED grace deadline. Looping over
    `terminate_group` gave each stubborn child its own full grace, so N children that ignore SIGTERM cost
    N x grace before the first SIGKILL — cancellation that degrades linearly with concurrency is not
    bounded in any useful sense."""
    _CANCELLED.set()
    grace = _TERM_GRACE if grace is None else grace   # resolved at CALL time (defined later in module)
    with _LIVE_LOCK:
        procs = list(_LIVE_PROCS.values())
    if not procs:
        return 0
    if not _POSIX:                                 # no process groups: fall back to per-process handling
        for p in procs:
            try:
                terminate_group(p, grace=grace)
            except Exception:
                pass
        return len(procs)

    def _sig(p, sig):
        try:
            os.killpg(p.pid, sig)                  # start_new_session=True => pid == pgid
        except (ProcessLookupError, OSError):
            pass                                   # group already gone — fine

    for p in procs:
        _sig(p, signal.SIGTERM)                    # ask them ALL first, then wait ONCE
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if all(p.poll() is not None for p in procs):
            break
        time.sleep(0.05)
    for p in procs:
        _sig(p, signal.SIGKILL)                    # hard-kill every survivor after the SHARED deadline
    # review#3 (A2 r4): the REAP deadline must be shared too. A sequential `p.wait(timeout=2)` per process
    # reintroduced exactly the linear blow-up the shared TERM deadline removed — 2s x N whenever a process
    # is slow to reap (or unreapable). SIGKILL is usually instant, which is why a real-child test cannot
    # see this; the bound has to be structural, not incidental.
    reap_deadline = time.monotonic() + _REAP_GRACE
    while time.monotonic() < reap_deadline:
        if all(p.poll() is not None for p in procs):
            break
        time.sleep(0.05)
    for p in procs:
        try:
            p.poll()                               # final non-blocking reap; a survivor is left to the OS
        except (ProcessLookupError, OSError):
            pass
    return len(procs)


def _register(proc) -> int:
    with _LIVE_LOCK:
        token = _LIVE_SEQ[0]
        _LIVE_SEQ[0] += 1
        _LIVE_PROCS[token] = proc
        return token


def _unregister(token: int) -> None:
    with _LIVE_LOCK:
        _LIVE_PROCS.pop(token, None)


def _classify(exit_code: int, out: str, err: str, ok_empty: bool,
              ok_codes: tuple[int, ...] = (0,)) -> tuple[Status, str]:
    low_err = err.lower()
    blocked = any(sig in low_err for sig in BLOCK_SIGNATURES)
    transport = any(sig in low_err for sig in TRANSPORT_SIGNATURES)   # degraded, NOT a block
    has_out = bool(out.strip())
    if exit_code not in ok_codes:
        if blocked:
            return Status.BLOCKED, "nonzero exit + block signature in stderr"
        # some tools exit nonzero with valid partial output
        if has_out:
            return Status.PARTIAL, f"exit {exit_code} but produced output"
        return Status.FAILED, f"exit {exit_code}, no output"
    # A nonzero exit code we *accept* (e.g. gitleaks 1 = leaks found) is only trustworthy
    # if it actually produced output. Nonzero + nothing is more likely a runtime/config
    # error that happens to share the code — surface it, don't mask it as a clean empty.
    if exit_code != 0 and not has_out:
        if blocked:
            return Status.BLOCKED, "nonzero exit + block signature in stderr"
        return Status.FAILED, f"exit {exit_code} accepted but produced no output"
    # CLEAN exit paths: a block signature means the target stopped us; a TRANSPORT error means degraded
    # coverage (the tool ran but some requests failed) -> PARTIAL, never BLOCKED, never a trustworthy EMPTY.
    if not has_out:
        if blocked:
            return Status.BLOCKED, "clean exit, no output, block signature in stderr"
        if transport:
            return Status.PARTIAL, "clean exit, no stdout, transport error — degraded coverage (completion uncertain)"
        return Status.EMPTY, "clean exit, zero output"
    if blocked:
        return Status.PARTIAL, "produced output but block signature in stderr"
    if transport:
        return Status.PARTIAL, "produced output + transport errors — degraded coverage"
    return Status.SUCCESS, ""


_TERM_GRACE = 3.0        # seconds between SIGTERM and the hard SIGKILL of a tool's process group
_REAP_GRACE = 2.0        # SHARED post-SIGKILL reap window in cancel_all (never per-process — see r4#3)
_POSIX = (os.name == "posix")


def terminate_group(proc, grace: float = _TERM_GRACE) -> None:
    """Kill a tool's ENTIRE process group — SIGTERM, bounded grace, then SIGKILL — so a tool that spawned
    children (chromium under katana, subshells) leaves NO orphan behind (the 'tool killed, Quarry
    stuck' class). CALLERS MUST launch with Popen start_new_session=True, which makes the tool a
    session/group leader with pgid == pid. We use `proc.pid` as the PGID DIRECTLY (not os.getpgid, which
    fails once the leader itself has exited — a leader can die while a child still holds the pipe): the
    group id stays valid + signalable as long as any member lives. Reaps after SIGKILL so no zombie is
    left for a caller that doesn't communicate(). Best-effort + race-safe (already-gone == not an error).
    Non-POSIX falls back to single-process terminate→kill. Shared by the runner (timeout / Ctrl-C) and the
    OOB interactsh session."""
    if _POSIX:
        pgid = proc.pid                                # start_new_session=True => pid == pgid; valid even
        def _sig(sig):                                 # after the leader exits, while children remain
            try:
                os.killpg(pgid, sig)
            except (ProcessLookupError, OSError):
                pass                                   # group already gone — fine
        _sig(signal.SIGTERM)
        try:
            proc.wait(timeout=grace)                   # let the group exit gracefully on TERM
        except (subprocess.TimeoutExpired, ProcessLookupError, OSError):
            pass
        _sig(signal.SIGKILL)                           # hard-kill any survivor in the group
        try:
            proc.wait(timeout=grace)                   # reap the leader after the kill (no zombie)
        except (subprocess.TimeoutExpired, ProcessLookupError, OSError):
            pass
        return
    # non-POSIX: no process groups — best-effort single-process TERM -> KILL, reaping after each
    try:
        proc.terminate()
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
            proc.wait(timeout=grace)
        except (subprocess.TimeoutExpired, ProcessLookupError, OSError):
            pass
    except (ProcessLookupError, OSError):
        pass


def run(
    tool: str,
    cmd: list[str],
    *,
    raw_path: Path | None = None,
    timeout: int = 1800,
    stdin_data: str | None = None,
    input_file: Path | None = None,
    ok_empty: bool = True,
    ok_codes: tuple[int, ...] = (0,),
    env: dict | None = None,
    stderr_path: Path | None = None,
) -> RunResult:
    """Run `cmd`, capture everything, persist raw stdout to `raw_path`, classify.

    `input_file`, if given, is read into a BOUNDED string and fed to the tool's stdin over a pipe (see
    the stdin note below — fd-streaming breaks xnLinkFinder; callers cap the file size).
    `ok_codes` lists exit codes that are NOT failures — e.g. gitleaks exits 1 when it
    *finds* leaks, which is success, not error.

    `stderr_path`, if given, persists the COMPLETE stderr (every path, including a timeout kill). Opt-in
    because `stderr_tail` keeps only the last 8 lines — enough for a signature match, but NOT enough for a
    caller that must read a tool's OWN completion/progress report out of its stderr (nuclei prints
    `Scan completed in …` plus periodic `-stats` lines, and a trailing burst of `[INF]` lines can evict
    both from an 8-line tail). A caller parsing tool-reported facts must read this file, never the tail.
    """
    bin_name = cmd[0]
    if not have(bin_name):
        return RunResult(tool, cmd, Status.SKIPPED, None, 0.0, None, 0,
                         note=f"{bin_name} not on PATH")

    # stdin source: input_file or stdin_data is fed over a PIPE via communicate(); otherwise /dev/null.
    # input_file is read into a string here — deliberately, not fd-streamed: a raw file-fd stdin and a
    # chunked writer-thread BOTH break xnLinkFinder (it probes stdin readiness once and needs the pipe
    # primed/complete, so it races an incremental feeder and ignores a regular-file fd). The string is
    # BOUNDED by the caller (gf corpus is tiny; xnLinkFinder caps its blob at XNL_MAX_INPUT), so the load
    # is capped. ProjectDiscovery tools block on an inherited empty stdin, hence DEVNULL when nothing fed.
    if input_file is not None and stdin_data is None:
        stdin_data = Path(input_file).read_text(encoding="utf-8", errors="replace")
    stdin_kw = {"stdin": subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL}

    start = time.monotonic()
    # Popen (not subprocess.run) so we hold the pid + can SAMPLE the process tree's RSS during the
    # run (a daemon thread polling /proc). CPU comes from a getrusage(CHILDREN) delta — tools run
    # sequentially, so the delta cleanly attributes child CPU to THIS tool. communicate(input=,
    # timeout=) is behavior-equivalent to the old run(): same 0/None = no-wall-clock-kill semantics.
    cpu0 = (resource.getrusage(resource.RUSAGE_CHILDREN) if resource else None)
    cpu_base = (cpu0.ru_utime + cpu0.ru_stime) if cpu0 else 0.0
    _cpu_token = _cpu_start()          # marks THIS run, and every overlapping one, as CPU-unmeasurable
    peak_rss = [0.0]
    stop = threading.Event()

    # env is MERGED over the inherited environment (not a replacement): callers pass only overrides, e.g.
    # {"PYTHONHASHSEED": "0"} to make a Python tool's set-ordering reproducible, without dropping PATH etc.
    proc_env = {**os.environ, **env} if env else None

    # start_new_session: the tool becomes its OWN process-group/session leader, so terminate_group can
    # kill the WHOLE tree (tool + any children) on timeout/interrupt — no orphaned chromium/subshell.
    # It also detaches the tool from Quarry's controlling terminal, so a Ctrl-C hits Quarry (not the tool
    # directly) and we do the cleanup deterministically here.
    # review#3 (A2): everything after _cpu_start() must unwind through a finally. Popen itself can raise
    # (ENOENT on a racing uninstall, EMFILE, OOM) and communicate() can raise on a decode error — either
    # left the token in _CPU_INFLIGHT forever, so EVERY later tool looked concurrent and permanently
    # reported its CPU as unmeasured. A telemetry leak that outlives the failure that caused it.
    proc = None
    live_token = None
    group_settled = False                         # True once this run's process group needs no teardown
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                env=proc_env, cwd=_TOOL_CWD, start_new_session=True, **stdin_kw)
        live_token = _register(proc)              # reachable by cancel_all() from the main thread
        if _CANCELLED.is_set():
            # cancellation latched between the check above and the launch: don't leave a new process
            # running after the operator asked to stop.
            terminate_group(proc)

        def _sample():
            while not stop.wait(0.3):
                r = _rss_tree_mb(proc.pid)
                if r > peak_rss[0]:
                    peak_rss[0] = r
        sampler = threading.Thread(target=_sample, daemon=True)
        sampler.start()

        timed_out = False
        try:
            out, err = proc.communicate(input=stdin_data if stdin_data is not None else None,
                                        timeout=timeout or None)
        except subprocess.TimeoutExpired:
            terminate_group(proc)                 # kill the whole group, not just the leader
            out, err = proc.communicate()         # reap + drain whatever the tool buffered
            timed_out = True
        except KeyboardInterrupt:
            # operator cancellation: tear the tool's group down, drain/reap, then RE-RAISE — never report a
            # cancel as a tool FAILED/TIMED_OUT.
            terminate_group(proc)
            try:
                proc.communicate(timeout=5)
            except Exception:
                pass
            group_settled = True                  # already torn down here — the outer guard must not repeat it
            raise
        finally:
            stop.set()                            # sampler shutdown ALWAYS, incl. interrupt/cleanup paths
            sampler.join(timeout=1)
        group_settled = True                      # reached only when nothing propagated out of the block
    finally:
        # review#1 (A2 r4): an UNEXPECTED exception out of communicate() (a decode error, MemoryError, a
        # bug in this function) runs NEITHER the timeout nor the interrupt branch, so nothing had killed
        # the child — and the very next line drops it from the registry, leaving a process alive that
        # cancel_all() can no longer even see. Reproduced with a real `sleep`: child_alive=True, registry=0.
        #
        # review#1 (A2 r5): `poll() is None` is the WRONG gate. It answers only for the process LEADER, and
        # a leader can exit while its children keep the group alive — which is precisely the case
        # terminate_group() exists for (it signals the PGID, valid while any member lives). A leader that
        # spawned `sleep` and exited before communicate() raised left a live, unreachable process GROUP
        # while poll() reported 0. On any EXCEPTIONAL exit, tear the group down regardless of the leader.
        # the ENTIRE probe is guarded, not just the kill: this runs in a finally, so ANY exception raised
        # here (including from poll() itself) would replace the exception actually in flight — a cancelled
        # run reported as an unrelated AttributeError.
        try:
            if proc is not None and (not group_settled or proc.poll() is None):
                terminate_group(proc)
        except Exception:
            pass                                  # best-effort: never mask the original exception
        if live_token is not None:
            _unregister(live_token)
        _cpu_contended = _cpu_finish(_cpu_token)  # ALWAYS reclaim the token, however we leave

    dur = time.monotonic() - start
    cpu1 = (resource.getrusage(resource.RUSAGE_CHILDREN) if resource else None)
    # review#7 (A2): RUSAGE_CHILDREN is PROCESS-GLOBAL, so the delta only attributes cleanly while tools run
    # one at a time. The arjun lane now runs several single-target processes concurrently, and overlapping
    # deltas would each absorb the others' CPU — fabricating per-target numbers that look precise. Report
    # UNMEASURED (-1.0) instead: an honest gap beats an invented measurement.
    cpu_s = -1.0 if _cpu_contended else (
        round((cpu1.ru_utime + cpu1.ru_stime) - cpu_base, 2) if cpu1 else 0.0)
    rss_mb = round(peak_rss[0], 1)
    out, err = out or "", err or ""

    # Persist the COMPLETE stderr BEFORE any return branch — a timed-out chunk's stderr is exactly the
    # evidence that it did NOT reach its own completion marker, so the kill path needs it too. A write
    # failure must never mask the tool's real result: the run is already done, so swallow and carry on
    # (the caller falls back to stderr_tail and, lacking proof of completion, treats the unit as retryable).
    if stderr_path is not None:
        try:
            stderr_path.parent.mkdir(parents=True, exist_ok=True)
            stderr_path.write_text(err)
        except OSError:
            pass

    if timed_out:
        wrote = False
        if raw_path and out:
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            raw_path.write_text(out)
            wrote = True
        return RunResult(tool, cmd, Status.TIMED_OUT, None, dur, raw_path if wrote else None,
                         len(out.splitlines()), note=f"timed out after {timeout}s",
                         cpu_s=cpu_s, peak_rss_mb=rss_mb)

    if raw_path is not None:
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(out)

    status, note = _classify(proc.returncode, out, err, ok_empty, ok_codes)
    err_tail = "\n".join(err.strip().splitlines()[-8:])
    return RunResult(
        tool=tool, cmd=cmd, status=status, exit_code=proc.returncode, duration=dur,
        raw_path=raw_path if out else None, stdout_lines=len(out.splitlines()),
        stderr_tail=err_tail, note=note, cpu_s=cpu_s, peak_rss_mb=rss_mb,
    )


def skipped(tool: str, reason: str) -> RunResult:
    return RunResult(tool, [tool], Status.SKIPPED, None, 0.0, None, 0, note=reason)
