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
    inflate a tool's RAM manyfold (measured: a dalfox tree read ~8 GB by VmRSS-sum vs a 664 MB true
    peak). Falls back to VmRSS when smaps_rollup is unavailable. Best-effort; 0.0 on error/non-Linux."""
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
    if r.status == Status.SKIPPED:
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
    # drop malformed rows centrally: a row must be an object, else a caller's `.get()` crashes on it
    # (e.g. `{"results":[null]}`). Filtering here keeps every ingest site (probe/content) row-safe.
    return [row for row in results if isinstance(row, dict)]


def reclassify_ffuf(r: "RunResult", out_file) -> "RunResult":
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
    if r.status == Status.SKIPPED:
        return r                                             # never ran -> no artifact refinement
    # ffuf hit its native -maxtime ceiling: it STOPS mid-wordlist, finalizes the artifact, then exits
    # CLEAN (exit 0) — so the generic classifier reads SUCCESS/EMPTY even though the run was TRUNCATED.
    # Demote to PARTIAL first (a degraded state) so the matrix below never launders it into SUCCESS/EMPTY.
    if r.status in (Status.SUCCESS, Status.EMPTY) and "maximum running time" in (r.stderr_tail or "").lower():
        r.status = Status.PARTIAL
    results = ffuf_results(out_file)
    if results is None:
        return r                                             # no valid artifact -> trust the classifier
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
        return self.status in (Status.SUCCESS, Status.PARTIAL)


def have(bin_name: str) -> bool:
    return shutil.which(bin_name) is not None


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
_POSIX = (os.name == "posix")


def terminate_group(proc, grace: float = _TERM_GRACE) -> None:
    """Kill a tool's ENTIRE process group — SIGTERM, bounded grace, then SIGKILL — so a tool that spawned
    children (chromium under katana/dalfox, subshells) leaves NO orphan behind (the 'tool killed, Quarry
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
) -> RunResult:
    """Run `cmd`, capture everything, persist raw stdout to `raw_path`, classify.

    `input_file`, if given, is read into a BOUNDED string and fed to the tool's stdin over a pipe (see
    the stdin note below — fd-streaming breaks xnLinkFinder; callers cap the file size).
    `ok_codes` lists exit codes that are NOT failures — e.g. gitleaks exits 1 when it
    *finds* leaks, which is success, not error.
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
    peak_rss = [0.0]
    stop = threading.Event()

    # env is MERGED over the inherited environment (not a replacement): callers pass only overrides, e.g.
    # {"PYTHONHASHSEED": "0"} to make a Python tool's set-ordering reproducible, without dropping PATH etc.
    proc_env = {**os.environ, **env} if env else None

    # start_new_session: the tool becomes its OWN process-group/session leader, so terminate_group can
    # kill the WHOLE tree (tool + any children) on timeout/interrupt — no orphaned chromium/subshell.
    # It also detaches the tool from Quarry's controlling terminal, so a Ctrl-C hits Quarry (not the tool
    # directly) and we do the cleanup deterministically here.
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            env=proc_env, cwd=_TOOL_CWD, start_new_session=True, **stdin_kw)

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
        terminate_group(proc)                     # kill the whole group, not just the leader
        out, err = proc.communicate()             # reap + drain whatever the tool buffered
        timed_out = True
    except KeyboardInterrupt:
        # operator cancellation: tear the tool's group down, drain/reap, then RE-RAISE — never report a
        # cancel as a tool FAILED/TIMED_OUT.
        terminate_group(proc)
        try:
            proc.communicate(timeout=5)
        except Exception:
            pass
        raise
    finally:
        stop.set()                                # sampler shutdown ALWAYS, incl. interrupt/cleanup paths
        sampler.join(timeout=1)

    dur = time.monotonic() - start
    cpu1 = (resource.getrusage(resource.RUSAGE_CHILDREN) if resource else None)
    cpu_s = round((cpu1.ru_utime + cpu1.ru_stime) - cpu_base, 2) if cpu1 else 0.0
    rss_mb = round(peak_rss[0], 1)
    out, err = out or "", err or ""

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
