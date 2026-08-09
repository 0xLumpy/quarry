"""Tool runner — executes external tools with explicit limits and a status taxonomy.

Every execution is explainable: stdout/stderr/exit/duration are captured, raw output is stored before
any parsing, and the result is classified so downstream phases never treat a failure/block/timeout as a
genuine "nothing found" (design §3).
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
    """Proportional physical RAM (MB) of `root_pid` and all its descendants: PSS (a shared page divided
    among its sharers) from `/proc/<pid>/smaps_rollup`, else VmRSS. 0.0 on error or non-Linux."""
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
# <domain>.txt, …), so tools run in a per-run scratch dir; all real tool I/O uses absolute paths.
_TOOL_CWD: str | None = None


def set_tool_cwd(path) -> None:
    global _TOOL_CWD
    _TOOL_CWD = str(path) if path else None


def fresh_artifact_dir(base) -> "Path":
    """A fresh per-invocation subdirectory `base/attempt-N` — the first N whose name is free — created
    atomically, so two concurrent callers never share an attempt. For file-output tools whose result count
    is derived by globbing a directory (gowitness): a reused or pre-populated directory would let a prior
    run's artifacts inflate this attempt's count. Prior attempts are preserved as evidence."""
    base = Path(base)
    base.mkdir(parents=True, exist_ok=True)
    n = 0
    while True:
        d = base / f"attempt-{n}"
        try:
            d.mkdir(exist_ok=False)                        # atomic: raises if the name is taken
            return d
        except FileExistsError:
            n += 1


def reclassify_from_artifact(r: "RunResult", n: "int | None", *, label: str = "tool") -> "RunResult":
    """Shared file-output status matrix. A file-output tool leaves an empty stdout, so the generic
    classifier mislabels it from a stderr line; the artifact is authoritative. `n` = count of validated
    results (>=0) when the artifact is a trustworthy complete result, or None when there is no trustworthy
    artifact (missing / unreadable / malformed). The caller owns the format-specific fail-closed parse and
    MUST clear the stale artifact before running the tool. Matrix:
      - SKIPPED / LIMITED           -> unchanged
      - clean (SUCCESS/EMPTY only):  n>0 -> SUCCESS · n==0 -> EMPTY · None -> PARTIAL (completion uncertain)
      - degraded (anything else — FAILED/TIMED_OUT/BLOCKED/PARTIAL): n>0 -> PARTIAL (evidence, incomplete);
        n==0 or None -> keep the original status, so a hard run is never laundered into SUCCESS/EMPTY."""
    if r.status in (Status.SKIPPED, Status.LIMITED):
        # LIMITED is a proven provider boundary and is never re-derived from an artifact: the matrix
        # would either launder it into SUCCESS or demote it to a degraded PARTIAL.
        return r
    # only a real int >= 0 is a trustworthy count: bool (an int subclass), float, str or a negative
    # reads as no trustworthy artifact, so a bad count fails closed instead of laundering the status.
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
    """Count-based file-output adapter (gowitness screenshots, …): `produced` = artifact count. Thin
    wrapper over `reclassify_from_artifact`, so a non-empty count on a degraded run is PARTIAL."""
    return reclassify_from_artifact(r, produced, label=note_word)


def ffuf_results(out_file) -> "list | None":
    """Parse an ffuf `-o` JSON artifact into its results list, or None when there is no valid current
    artifact — missing / unreadable / JSON root not an object / `results` not a list / any non-object row.
    A caller can then distinguish "ffuf completed and served this" from "no trustworthy artifact"."""
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
    # ffuf does not emit non-object rows, so one is corruption: fail closed for the whole artifact
    # rather than ingest a subset of a broken file.
    if any(not isinstance(row, dict) for row in results):
        return None
    return list(results)


def ffuf_usable_rows(rows, validate) -> "tuple[list, int]":
    """Split structurally-valid ffuf rows into (usable, dropped_count). `validate` is a per-lane
    predicate: structural validity is not usability, and a "non-empty field" check is fail-open."""
    usable = [r for r in rows if validate(r)]
    return usable, len(rows) - len(usable)


def ffuf_http_row(row) -> bool:
    """A usable ffuf row for a URL-ingesting lane: an absolute http(s) URL whose authority parses with a
    real host and port, and an HTTP status in 100..599 (`bool` excluded — it is an int subclass)."""
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
    """ffuf artifact adapter: ffuf writes hits to `-o` JSON while `-s` keeps stdout empty, so the generic
    classifier (stdout + stderr only) can't see the real result and a transport line mislabels the run. A
    valid artifact (dict root + list `results`) means ffuf reached completion; refine on it:
      - SKIPPED / LIMITED      -> unchanged
      - FAILED / TIMED_OUT     -> hard stop: findings upgrade to PARTIAL (coverage incomplete), never
                                  SUCCESS; 0 findings keeps the hard state
      - BLOCKED + hits         -> PARTIAL (any exit code — findings are evidence some paths were served)
      - BLOCKED + 0, exit 0    -> PARTIAL: a clean exit proves ffuf finished, so the block hit some
                                  request rather than the whole job
      - BLOCKED + 0, exit != 0 -> stay BLOCKED (nonzero exit + nothing served), as does a missing or
                                  invalid artifact (a real block before the write)
      - PARTIAL (transport)    -> stay PARTIAL, with or without hits
      - clean                  -> hits => SUCCESS; 0 => EMPTY
    A missing / invalid `-o` keeps the classifier verdict. Callers MUST clear `out_file` before invoking
    ffuf so a stale prior-run artifact can't fake completion. Sets `stdout_lines` to the result count and
    returns the mutated RunResult."""
    if r.status in (Status.SKIPPED, Status.LIMITED):
        # LIMITED is a proven provider boundary and is never re-derived from an artifact: the matrix
        # would either launder it into SUCCESS or demote it to a degraded PARTIAL.
        return r
    # ffuf hit its native -maxtime ceiling: it stops mid-wordlist, finalizes the artifact, then exits
    # clean, so demote to PARTIAL first and the matrix below can never launder a truncated run.
    _err, _full = r.stderr_tail or "", False     # the tail is 8 lines; a persisted file has it complete
    if stderr_file is not None:
        try:
            if Path(stderr_file).is_file():
                _err, _full = Path(stderr_file).read_text(errors="replace"), True
        except OSError:
            pass
    if r.status in (Status.SUCCESS, Status.EMPTY):
        capped = "maximum running time" in _err.lower()
        if not capped and not _full and maxtime:
            # without the full text the cap notice may have been evicted from the tail, so duration
            # decides: reaching the ceiling means truncated, an early natural finish stays clean.
            capped = r.duration >= maxtime
        if capped:
            r.status = Status.PARTIAL
            r.note = ("ffuf: hit its -maxtime ceiling — run TRUNCATED, coverage incomplete"
                      + ("" if _full else " (inferred from duration; full stderr unavailable)"))
    results = ffuf_results(out_file)
    if results is None:
        # fail closed on a clean exit: `-o` is ffuf's required output, so a missing or malformed artifact
        # after a clean run means completion is unproven. A degraded status keeps its own verdict.
        if r.status in (Status.SUCCESS, Status.EMPTY):
            r.status = Status.PARTIAL
            r.note = "ffuf: -o artifact missing/malformed — completion uncertain"
        return r
    n = len(results)
    r.stdout_lines = n
    # ffuf errored or was killed: a partial artifact can only lift the run to PARTIAL, never SUCCESS.
    if r.status in (Status.FAILED, Status.TIMED_OUT):
        if n > 0:
            r.status, r.note = Status.PARTIAL, f"ffuf: {n} result(s) ({r.status.value}; coverage incomplete)"
        return r                                             # 0 findings -> keep the hard state
    if r.status == Status.BLOCKED:
        # findings prove ffuf served some paths despite the block -> PARTIAL (evidence, incomplete)
        if n > 0:
            r.status, r.note = Status.PARTIAL, f"ffuf: {n} result(s) (some blocked)"
        # with 0 findings only a clean exit proves the job completed; a nonzero exit stays fully BLOCKED
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
    """Workload-scaled wall-clock ceiling, not a duration: the tool exits when it finishes, so a generous
    ceiling only lets a big job complete and never slows a small one. The budget grows `per_unit` seconds
    per unit of work above `floor`, with no upper cap — scope size must never truncate coverage. Used by
    nuclei (per target), httpx (per host, port-weighted) and ffuf (per wordlist entry). `floor <= 0` means
    fully unbounded, with no kill at all."""
    if floor <= 0:
        return 0
    return max(int(floor), int(per_unit * max(int(n_units), 1)))


def nuclei_timeout(n_targets: int, floor: int, per_target: int = 240) -> int:
    """`scaled_timeout` for nuclei, whose runtime grows with target count (roughly templates × targets /
    concurrency): `floor` (the base `--timeout`) is the ceiling for small scopes and the budget grows
    `per_target` seconds per target. `floor <= 0` (`--timeout 0`) means fully unbounded."""
    return scaled_timeout(n_targets, floor, per_target)


class Status(str, Enum):
    SUCCESS = "success"     # ran clean, produced output
    EMPTY = "empty"         # ran clean, zero output (genuine nothing-found)
    PARTIAL = "partial"     # produced output but stderr shows trouble
    FAILED = "failed"       # nonzero exit
    TIMED_OUT = "timed_out"
    BLOCKED = "blocked"     # stderr matches WAF/rate-limit/forbidden signatures
    SKIPPED = "skipped"     # not run (scope/mode/missing tool/no input)
    # a limit is a clean execution that something cut short: outside `store._DEGRADED`, it feeds
    # `complete_with_limits`, and who bounded us is carried by `error_class` — not by the status.
    LIMITED = "limited"     # ran clean; a provider or operator boundary cut coverage short


# stderr signatures of a real denial — the target stopped us (WAF/rate-limit/forbidden).
BLOCK_SIGNATURES = (
    "403 forbidden", "429", "too many requests", "rate limit", "rate-limit",
    "access denied", "captcha", "cloudflare", "akamai", "web application firewall", " waf ",
)
# stderr signatures of transport degradation — the connection failed or timed out and the tool kept
# going. Degraded coverage, not a block: downgrades a clean run to PARTIAL, never to BLOCKED.
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
    cpu_s: float = 0.0                 # child CPU seconds for this tool (getrusage delta)
    peak_rss_mb: float = 0.0           # peak RSS of this tool's process tree (/proc sampling)
    meta: dict = field(default_factory=dict)

    @property
    def started(self) -> bool:
        """Whether the process demonstrably started — a pid existed. Set only where a pid was obtained,
        so a missing binary, a cancelled launch or a `Popen` that raised never reads as a run."""
        return self.meta.get("started") is True

    @property
    def ok(self) -> bool:
        """Ran acceptably. LIMITED belongs here: the execution was clean and something external cut it
        short."""
        return self.status in (Status.SUCCESS, Status.PARTIAL, Status.LIMITED)


def have(bin_name: str) -> bool:
    return shutil.which(bin_name) is not None


# ── concurrent-run CPU accounting ─────────────────────────────────────────────────────────────────────

# getrusage(RUSAGE_CHILDREN) is per-process, so a delta around one tool is only that tool's CPU while
# tools run sequentially. A run overlapping any other, at any moment of its lifetime, is unmeasurable.
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
    """True when this run overlapped another and its CPU delta must not be reported."""
    with _CPU_LOCK:
        return _CPU_INFLIGHT.pop(token, False)


def cpu_measured(r: "RunResult") -> bool:
    """Whether `r.cpu_s` is a real measurement (-1.0 = unmeasured, concurrent execution)."""
    return r.cpu_s >= 0.0


# ── cooperative cancellation for concurrent lanes ─────────────────────────────────────────────────────

# Python delivers KeyboardInterrupt to the main thread only, so a tool inside a worker thread never
# reaches run()'s interrupt branch. This registry is how the main thread tears those groups down.
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
    """Latch cancellation and terminate every live tool process group. Returns how many were signalled.

    Safe to call from the main thread while workers are blocked in communicate(): the group is killed,
    communicate() then returns promptly, and each worker unwinds through its own finally. The groups are
    signalled concurrently under one shared grace deadline, so the cost does not grow with concurrency."""
    _CANCELLED.set()
    grace = _TERM_GRACE if grace is None else grace   # resolved at call time (defined later in module)
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
        _sig(p, signal.SIGTERM)                    # ask them all first, then wait once
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if all(p.poll() is not None for p in procs):
            break
        time.sleep(0.05)
    for p in procs:
        _sig(p, signal.SIGKILL)                    # hard-kill every survivor after the shared deadline
    # the reap deadline is shared too: a per-process wait would grow linearly with concurrency whenever
    # a process is slow to reap.
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
    transport = any(sig in low_err for sig in TRANSPORT_SIGNATURES)   # degraded, not a block
    has_out = bool(out.strip())
    if exit_code not in ok_codes:
        if blocked:
            return Status.BLOCKED, "nonzero exit + block signature in stderr"
        # some tools exit nonzero with valid partial output
        if has_out:
            return Status.PARTIAL, f"exit {exit_code} but produced output"
        return Status.FAILED, f"exit {exit_code}, no output"
    # a nonzero exit code we *accept* (gitleaks 1 = leaks found) is only trustworthy with output:
    # nonzero + nothing is more likely a runtime/config error that happens to share the code
    if exit_code != 0 and not has_out:
        if blocked:
            return Status.BLOCKED, "nonzero exit + block signature in stderr"
        return Status.FAILED, f"exit {exit_code} accepted but produced no output"
    # clean exit: a block signature means the target stopped us; a transport error means degraded
    # coverage -> PARTIAL, never BLOCKED and never a trustworthy EMPTY
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
_REAP_GRACE = 2.0        # shared post-SIGKILL reap window in cancel_all, never per-process
_POSIX = (os.name == "posix")


def terminate_group(proc, grace: float = _TERM_GRACE) -> None:
    """Kill a tool's entire process group — SIGTERM, bounded grace, then SIGKILL — so a tool that spawned
    children (chromium under katana, subshells) leaves no orphan behind.

    Callers MUST launch with `Popen(start_new_session=True)`, which makes the tool a session/group leader
    with pgid == pid; `proc.pid` is used as the pgid directly, because `os.getpgid` fails once the leader
    itself has exited while a child still holds the group. Reaps after SIGKILL, so no zombie is left for a
    caller that doesn't communicate(). Best-effort and race-safe (already-gone is not an error); non-POSIX
    falls back to single-process terminate→kill. Shared by the runner and the OOB interactsh session."""
    if _POSIX:
        pgid = proc.pid                                # valid while any group member lives
        def _sig(sig):
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

    `input_file`, if given, is read whole into memory and fed to the tool's stdin over a pipe — nothing
    bounds it here, so the caller must keep the source sane. `ok_codes` lists exit codes that are not
    failures — gitleaks exits 1 when it *finds* leaks, which is success, not error.

    `stderr_path`, if given, persists the complete stderr on every path, including a timeout kill. Opt-in
    because `stderr_tail` keeps only the last 8 lines — enough for a signature match, but not for a caller
    that must read a tool's own completion or progress report out of its stderr (nuclei's `Scan completed
    in …` and `-stats` lines are both evictable by a trailing burst of `[INF]` lines). Such a caller must
    read this file, never the tail.
    """
    bin_name = cmd[0]
    if not have(bin_name):
        return RunResult(tool, cmd, Status.SKIPPED, None, 0.0, None, 0,
                         note=f"{bin_name} not on PATH")

    # stdin: `input_file`/`stdin_data` over a pipe via communicate(), else /dev/null (ProjectDiscovery
    # tools block on an empty inherited stdin). The file is read whole: xnLinkFinder needs a primed pipe.
    if input_file is not None and stdin_data is None:
        stdin_data = Path(input_file).read_text(encoding="utf-8", errors="replace")
    stdin_kw = {"stdin": subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL}

    start = time.monotonic()
    # Popen (not subprocess.run) so we hold the pid and can sample the process tree's RSS during the run;
    # CPU comes from a getrusage(CHILDREN) delta. In `communicate(timeout=)`, 0/None means no kill.
    cpu0 = (resource.getrusage(resource.RUSAGE_CHILDREN) if resource else None)
    cpu_base = (cpu0.ru_utime + cpu0.ru_stime) if cpu0 else 0.0
    _cpu_token = _cpu_start()          # marks this run, and every overlapping one, as CPU-unmeasurable
    peak_rss = [0.0]
    stop = threading.Event()

    # env is merged over the inherited environment, not a replacement: callers pass only overrides
    # (e.g. {"PYTHONHASHSEED": "0"}) without dropping PATH.
    proc_env = {**os.environ, **env} if env else None

    # start_new_session: the tool becomes its own process-group/session leader, so terminate_group can
    # kill the whole tree and a Ctrl-C hits Quarry, not the tool. Everything below unwinds via the finally.
    proc = None
    started = False                               # proven by a pid, never inferred
    live_token = None
    group_settled = False                         # True once this run's process group needs no teardown
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                env=proc_env, cwd=_TOOL_CWD, start_new_session=True, **stdin_kw)
        started = True                            # a pid exists: the process really did launch
        live_token = _register(proc)              # reachable by cancel_all() from the main thread
        if _CANCELLED.is_set():
            # cancellation latched between the check above and the launch
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
            # operator cancellation: tear the group down, drain/reap, then re-raise — a cancel is never
            # reported as a tool FAILED/TIMED_OUT
            terminate_group(proc)
            try:
                proc.communicate(timeout=5)
            except Exception:
                pass
            group_settled = True                  # torn down here; the outer guard must not repeat it
            raise
        finally:
            stop.set()                            # sampler shutdown on every path, interrupt included
            sampler.join(timeout=1)
        group_settled = True                      # reached only when nothing propagated out of the block
    finally:
        # on any exceptional exit the group is torn down regardless of the leader, which can exit while
        # its children keep it alive. Guarded throughout, so it never masks the exception in flight.
        try:
            if proc is not None and (not group_settled or proc.poll() is None):
                terminate_group(proc)
        except Exception:
            pass                                  # best-effort: never mask the original exception
        if live_token is not None:
            _unregister(live_token)
        _cpu_contended = _cpu_finish(_cpu_token)  # always reclaim the token, however we leave

    dur = time.monotonic() - start
    cpu1 = (resource.getrusage(resource.RUSAGE_CHILDREN) if resource else None)
    # RUSAGE_CHILDREN is process-global, so the delta only attributes cleanly while tools run one at a
    # time; overlapping deltas would each absorb the others' CPU. Report unmeasured (-1.0) instead.
    cpu_s = -1.0 if _cpu_contended else (
        round((cpu1.ru_utime + cpu1.ru_stime) - cpu_base, 2) if cpu1 else 0.0)
    rss_mb = round(peak_rss[0], 1)
    out, err = out or "", err or ""

    # persist the complete stderr before any return branch — a timed-out chunk's stderr is the evidence
    # that it did not reach its own completion marker. A write failure must not mask the tool's result.
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
                         cpu_s=cpu_s, peak_rss_mb=rss_mb, meta={"started": started})

    if raw_path is not None:
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(out)

    status, note = _classify(proc.returncode, out, err, ok_empty, ok_codes)
    err_tail = "\n".join(err.strip().splitlines()[-8:])
    return RunResult(
        tool=tool, cmd=cmd, status=status, exit_code=proc.returncode, duration=dur,
        raw_path=raw_path if out else None, stdout_lines=len(out.splitlines()),
        stderr_tail=err_tail, note=note, cpu_s=cpu_s, peak_rss_mb=rss_mb,
        meta={"started": started},
    )


def skipped(tool: str, reason: str) -> RunResult:
    return RunResult(tool, [tool], Status.SKIPPED, None, 0.0, None, 0, note=reason)
