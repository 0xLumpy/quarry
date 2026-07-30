"""B1.7 — the Shodan host lane's SWEEP PROGRESS under real concurrency.

Its own module because the offline gate hard-denies subprocess spawning, and two real processes is the only
way to observe the project-level lock doing its job rather than merely being present. The single-process
mechanism assertions (lock taken, temp name private, merge max-wins) live in `test_shodan_host.py`.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time

import pytest

from quarry_recon import shodan_host as sh

pytestmark = pytest.mark.integration

#: one child = one run recording one ask and saving. Exactly what two concurrent lanes do.
_CHILD = ("import sys; sys.path.insert(0, 'src');"
          "import quarry_recon.shodan_host as sh;"
          "p = sh.SweepProgress(sys.argv[1]);"
          "p.note(sys.argv[2], float(sys.argv[3]));"
          "raise SystemExit(0 if p.save() else 1)")


def _repo() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent.parent


def _spawn(path, asks):
    procs = [subprocess.Popen([sys.executable, "-c", _CHILD, str(path), ip, when], cwd=str(_repo()))
             for ip, when in asks]
    return [p.wait() for p in procs]


def test_two_REAL_PROCESSES_both_survive_the_merge(tmp_path):
    """review-B1.7r10#1: an unlocked overwrite through one shared temp name let the later save discard the
    earlier run's rotation — so both runs kept asking the same prefix and the tail starved."""
    path = sh.progress_path(tmp_path / "project")
    assert _spawn(path, (("1.1.1.1", "100"), ("2.2.2.2", "200"))) == [0, 0]
    merged = sh.SweepProgress(path)
    assert merged.asked == {"1.1.1.1": 100.0, "2.2.2.2": 200.0}, merged.asked


def test_MANY_concurrent_runs_lose_nothing(tmp_path):
    """Eight at once, each with its own address: every ask has to be in the file afterwards."""
    path = sh.progress_path(tmp_path / "project")
    asks = [(f"10.0.0.{i}", str(100 + i)) for i in range(1, 9)]
    assert _spawn(path, asks) == [0] * len(asks)
    merged = sh.SweepProgress(path)
    assert merged.asked == {ip: float(when) for ip, when in asks}, merged.asked


def test_the_file_is_never_left_TORN(tmp_path):
    """A reader that lands mid-write must still get a usable document — that is what the atomic replace
    under the lock is for."""
    path = sh.progress_path(tmp_path / "project")
    asks = [(f"10.0.1.{i}", str(200 + i)) for i in range(1, 7)]
    assert _spawn(path, asks) == [0] * len(asks)
    assert sh.SweepProgress(path).asked, "the merged document was unreadable"
    leftovers = [q.name for q in path.parent.iterdir() if q.name.endswith(".tmp")]
    assert leftovers == [], leftovers


#: a whole LANE LIFECYCLE in a child process, with a HANDSHAKE so the overlap is not a matter of timing.
#: The holder announces that it owns the sweep and then waits to be told to finish; the contender runs only
#: after that announcement, so it is guaranteed to meet contention. review-B1.7r13#2: without the handshake
#: a late child could start AFTER release, both would sweep the whole live set — correctly, since the lock
#: is per-lifecycle and not per-address — and the "disjoint asked sets" assertion was simply wrong.
_LIFECYCLE = """
import json, pathlib, sys, time
sys.path.insert(0, 'src')
from quarry_recon import budget
import quarry_recon.shodan_host as sh

project = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
ready = pathlib.Path(sys.argv[3]) if sys.argv[3] != '-' else None
go = pathlib.Path(sys.argv[4]) if sys.argv[4] != '-' else None
targets = [sh.IpTarget(f"1.1.{b}.1") for b in range(4)]
asked = []

def fetch(ip):
    asked.append(ip)
    body = json.dumps({"ip_str": ip, "ip": 0, "ports": [443], "hostnames": [], "domains": [],
                       "tags": [], "org": "x", "isp": "x", "asn": "AS1",
                       "last_update": "2026-07-30T04:14:37.743242",
                       "data": [{"port": 443, "transport": "tcp", "_shodan": {},
                                 "timestamp": "2026-07-30T04:14:37.743242"}]}).encode()
    return body, 200, None

d = project / "attempts" / str(out.stem)
d.mkdir(parents=True, exist_ok=True)
led = budget.Ledger(budget.state_path(d, "probe.shodan_host", "fp0"), lane="probe.shodan_host")
result = {"asked": [], "declined": False, "progress_saved": None}
try:
    with sh.sweep_session(sh.progress_path(project)) as progress:
        if ready is not None:
            ready.write_text("held")            # ANNOUNCE: the sweep is ours from here
        if go is not None:
            for _ in range(400):                # ...and wait to be released (bounded, never forever)
                if go.exists():
                    break
                time.sleep(0.02)
        o = sh.run_hosts(targets, fetch=fetch, ingest=lambda t, rec, art, wrote: None, ledger=led,
                         attempt_dir=d, bound=budget.Budget(0), progress=progress)
        result["asked"] = asked
        result["progress_saved"] = o.progress_saved
except sh.SweepBusy:
    result["declined"] = True
    result["asked"] = asked
out.write_text(json.dumps(result))
"""


def _spawn_lifecycle(project, out, ready="-", go="-"):
    return subprocess.Popen([sys.executable, "-c", _LIFECYCLE, str(project), str(out), str(ready), str(go)],
                            cwd=str(_repo()))


def _await(path, what, timeout=20.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if path.exists():
            return
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {what}")


def test_a_CONTENDED_lifecycle_declines_and_asks_NOTHING(tmp_path):
    """The handshake makes the overlap certain: the contender starts only once the holder owns the sweep."""
    project = tmp_path / "project"
    project.mkdir(parents=True, exist_ok=True)
    ready, go = tmp_path / "ready", tmp_path / "go"
    holder_out, other_out = tmp_path / "holder.json", tmp_path / "other.json"

    holder = _spawn_lifecycle(project, holder_out, ready=ready, go=go)
    try:
        _await(ready, "the holder to take the sweep")
        other = _spawn_lifecycle(project, other_out)
        assert other.wait(timeout=30) == 0
    finally:
        go.write_text("release")
        assert holder.wait(timeout=30) == 0

    contender = json.loads(other_out.read_text())
    assert contender["declined"] is True, contender
    assert contender["asked"] == [], f"a contended run still queried: {contender['asked']}"

    swept = json.loads(holder_out.read_text())
    assert swept["declined"] is False and len(swept["asked"]) == 4, swept
    assert swept["progress_saved"] is True, swept


def test_the_sweep_is_RELEASED_for_the_next_lifecycle(tmp_path):
    """The lock is per-LIFECYCLE, so a later run gets it — and correctly refreshes the whole live set."""
    project = tmp_path / "project"
    project.mkdir(parents=True, exist_ok=True)
    first, second = tmp_path / "first.json", tmp_path / "second.json"
    p = _spawn_lifecycle(project, first)
    assert p.wait(timeout=30) == 0
    p = _spawn_lifecycle(project, second)
    assert p.wait(timeout=30) == 0
    a, b = json.loads(first.read_text()), json.loads(second.read_text())
    assert a["declined"] is False and b["declined"] is False, (a, b)
    assert len(a["asked"]) == len(b["asked"]) == 4, (a, b)
    assert sh.SweepProgress(sh.progress_path(project)).asked, "no rotation was recorded"
