"""Tool runner — executes external tools with explicit limits and a status taxonomy.

The core anti-goal of the whole framework is *silent thin output*. The runner makes
every execution explainable: it captures stdout/stderr/exit/duration, stores raw
output before any parsing, and classifies the result so downstream phases never treat
a failure/block/timeout as a genuine "nothing found" (design §3).
"""
from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# Some tools write stray files to the current directory (gowitness's sqlite, github-subdomains'
# <domain>.txt, …). Point the working directory at a per-run scratch dir so those land inside the
# run, not wherever the user launched `quarry`. All tool I/O uses absolute paths, so this only
# affects relative/stray output. Set once per run/osint via set_tool_cwd().
_TOOL_CWD: str | None = None


def set_tool_cwd(path) -> None:
    global _TOOL_CWD
    _TOOL_CWD = str(path) if path else None


def nuclei_timeout(n_targets: int, floor: int, per_target: int = 90) -> int:
    """Scale a nuclei run's timeout by workload. nuclei runtime grows with target count (roughly
    templates × targets), so a flat per-tool ceiling kills big scans mid-run and yields the "coverage
    is partial" checkpoint. Here `floor` (the base `--timeout`) is the minimum for small scopes, and
    the budget grows ~`per_target` seconds per target — so a large program (thousands of live hosts /
    endpoints) gets the time it needs. NO upper cap by design: scope size must never truncate coverage.
    The computed (large) ceiling still bounds a genuinely-hung process."""
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
    stdin_kw = {}
    if stdin_data is None:
        stdin_kw["stdin"] = subprocess.DEVNULL
    try:
        proc = subprocess.run(
            cmd,
            input=stdin_data if stdin_data is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            env=env,
            cwd=_TOOL_CWD,
            **stdin_kw,
        )
    except subprocess.TimeoutExpired as e:
        dur = time.monotonic() - start
        out = (e.stdout or "") if isinstance(e.stdout, str) else ""
        wrote = False
        if raw_path and out:
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            raw_path.write_text(out)
            wrote = True
        return RunResult(tool, cmd, Status.TIMED_OUT, None, dur,
                         raw_path if wrote else None,
                         len(out.splitlines()), note=f"timed out after {timeout}s")
    dur = time.monotonic() - start

    out, err = proc.stdout or "", proc.stderr or ""
    if raw_path is not None:
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(out)

    status, note = _classify(proc.returncode, out, err, ok_empty, ok_codes)
    err_tail = "\n".join(err.strip().splitlines()[-8:])
    return RunResult(
        tool=tool, cmd=cmd, status=status, exit_code=proc.returncode, duration=dur,
        raw_path=raw_path if out else None, stdout_lines=len(out.splitlines()),
        stderr_tail=err_tail, note=note,
    )


def skipped(tool: str, reason: str) -> RunResult:
    return RunResult(tool, [tool], Status.SKIPPED, None, 0.0, None, 0, note=reason)
