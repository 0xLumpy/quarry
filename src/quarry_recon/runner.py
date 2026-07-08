"""Tool runner — executes external tools with explicit limits and a status taxonomy.

The core anti-goal of the whole framework is *silent thin output*. The runner makes
every execution explainable: it captures stdout/stderr/exit/duration, stores raw
output before any parsing, and classifies the result so downstream phases never treat
a failure/block/timeout as a genuine "nothing found" (design §3).
"""
from __future__ import annotations

import os
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
    """Peak-sample helper: sum RSS (MB) of `root_pid` + all its descendants from /proc (Linux).
    Best-effort — returns 0.0 on any error / non-/proc platform. Uses /proc/<pid>/status (clean
    `VmRSS:` + `PPid:` lines) rather than parsing stat's paren-comm field."""
    try:
        info: dict[int, tuple[int, int]] = {}    # pid -> (ppid, rss_kb)
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            try:
                ppid = rss = 0
                with open(f"/proc/{name}/status") as f:
                    for line in f:
                        if line.startswith("VmRSS:"):
                            rss = int(line.split()[1])
                        elif line.startswith("PPid:"):
                            ppid = int(line.split()[1])
                info[int(name)] = (ppid, rss)
            except (OSError, ValueError):
                continue
        children: dict[int, list[int]] = {}
        for pid, (ppid, _) in info.items():
            children.setdefault(ppid, []).append(pid)
        total = 0
        stack, seen = [root_pid], set()
        while stack:
            p = stack.pop()
            if p in seen or p not in info:
                continue
            seen.add(p)
            total += info[p][1]
            stack.extend(children.get(p, []))
        return total / 1024.0
    except Exception:
        return 0.0

# Some tools write stray files to the current directory (gowitness's sqlite, github-subdomains'
# <domain>.txt, …). Point the working directory at a per-run scratch dir so those land inside the
# run, not wherever the user launched `quarry`. All tool I/O uses absolute paths, so this only
# affects relative/stray output. Set once per run/osint via set_tool_cwd().
_TOOL_CWD: str | None = None


def set_tool_cwd(path) -> None:
    global _TOOL_CWD
    _TOOL_CWD = str(path) if path else None


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
    if floor <= 0:
        return 0                                  # unbounded — exec_tool maps 0 -> no timeout
    return max(int(floor), per_target * max(int(n_targets), 1))


class Status(str, Enum):
    SUCCESS = "success"     # ran clean, produced output
    EMPTY = "empty"         # ran clean, zero output (genuine nothing-found)
    PARTIAL = "partial"     # produced output but stderr shows trouble
    FAILED = "failed"       # nonzero exit
    TIMED_OUT = "timed_out"
    BLOCKED = "blocked"     # stderr matches WAF/rate-limit/forbidden signatures
    SKIPPED = "skipped"     # not run (scope/mode/missing tool/no input)


# stderr signatures that mean "we were stopped", not "nothing exists".
BLOCK_SIGNATURES = (
    "403 forbidden", "429", "too many requests", "rate limit", "rate-limit",
    "access denied", "blocked", "captcha", "cloudflare", "akamai",
    "connection reset", "i/o timeout", "context deadline exceeded",
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
    if not has_out:
        if blocked:
            return Status.BLOCKED, "clean exit, no output, block signature in stderr"
        return Status.EMPTY, "clean exit, zero output"
    if blocked:
        return Status.PARTIAL, "produced output but block signature in stderr"
    return Status.SUCCESS, ""


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

    `input_file`, if given, is streamed to the tool's stdin (used by jsluice/gf/etc).
    `ok_codes` lists exit codes that are NOT failures — e.g. gitleaks exits 1 when it
    *finds* leaks, which is success, not error.
    """
    bin_name = cmd[0]
    if not have(bin_name):
        return RunResult(tool, cmd, Status.SKIPPED, None, 0.0, None, 0,
                         note=f"{bin_name} not on PATH")

    stdin_src = None
    if input_file is not None:
        stdin_data = Path(input_file).read_text(errors="replace")
    if stdin_data is not None:
        stdin_src = subprocess.PIPE

    start = time.monotonic()
    # When we are NOT feeding stdin, hand the tool /dev/null. ProjectDiscovery tools
    # (dnsx/httpx/naabu/katana...) read stdin when it is a non-TTY pipe; an inherited
    # open-but-empty stdin makes them block until EOF (manifests as a full timeout).
    stdin_kw = {"stdin": subprocess.DEVNULL if stdin_data is None else subprocess.PIPE}
    # Popen (not subprocess.run) so we hold the pid + can SAMPLE the process tree's RSS during the
    # run (a daemon thread polling /proc). CPU comes from a getrusage(CHILDREN) delta — tools run
    # sequentially, so the delta cleanly attributes child CPU to THIS tool. communicate(input=,
    # timeout=) is behavior-equivalent to the old run(): same 0/None = no-wall-clock-kill semantics.
    cpu0 = (resource.getrusage(resource.RUSAGE_CHILDREN) if resource else None)
    cpu_base = (cpu0.ru_utime + cpu0.ru_stime) if cpu0 else 0.0
    peak_rss = [0.0]
    stop = threading.Event()

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            env=env, cwd=_TOOL_CWD, **stdin_kw)

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
        proc.kill()
        out, err = proc.communicate()             # reap + drain whatever the tool buffered
        timed_out = True
    finally:
        stop.set()
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
