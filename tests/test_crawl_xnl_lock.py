"""review-B-audit-6#1 — the xnLinkFinder lane's PROJECT state under real concurrency.

Its own module because the offline gate hard-denies subprocess spawning, and two real processes is the only
way to observe the lock doing its job rather than merely being present: an in-process test can patch
`state_lock` to raise, but it cannot show that two runs of the same project do not both prune the state
directory, mine the same unit, race on the shared `.tmp` and unlink each other's journal.

The single-process assertions (contention is a FAILED terminal with a `lock` gap; the lock is taken before
prune/load and released after save) live in `test_crawl_fetch_lanes.py`.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time

import pytest

from quarry_recon.phases import crawl

pytestmark = pytest.mark.integration

#: one child = one full lane over one input, with a fake tool that RECORDS its invocation and then WAITS
#: for a gate file. The overlap is a handshake, not a sleep: the parent knows the holder is inside the lock
#: because the marker exists, and the holder cannot finish until the parent opens the gate.
_CHILD = r"""
import json, pathlib, sys, time
sys.path.insert(0, "src")
from types import SimpleNamespace
from quarry_recon import events, budget
from quarry_recon.phases import crawl
from quarry_recon.runner import RunResult, Status

project, run_name, indir, gate, marker = sys.argv[1:6]
project, gate = pathlib.Path(project), pathlib.Path(gate)
run_dir = project / run_name
run_dir.mkdir(parents=True, exist_ok=True)
events.reset(); events.configure(run_dir)


def fake_exec(tool, cmd, timeout=None, input_file=None, **k):
    with open(marker, "a") as fh:                      # every real mining attempt leaves one line
        fh.write(run_name + "\n")
    deadline = time.time() + 60
    while str(gate) != "-" and not gate.exists():      # hold the lock until the parent says go
        if time.time() > deadline:
            raise SystemExit("gate never opened")
        time.sleep(0.02)
    pathlib.Path(cmd[cmd.index("-o") + 1]).write_text("https://api.acme.com/x\n")
    pathlib.Path(cmd[cmd.index("-op") + 1]).write_text("id\n")
    if "-os" in cmd:
        pathlib.Path(cmd[cmd.index("-os") + 1]).write_text("[]")   # the MEASURED no-find shapes
    if "-owl" in cmd:
        pathlib.Path(cmd[cmd.index("-owl") + 1]).write_text("")
    return RunResult("xnLinkFinder", cmd, Status.SUCCESS, 0, 0.1, None, 1)


class Run:
    project_dir = project
    dir = run_dir

    def raw_path(self, ph, tl, nm):
        p = run_dir / "raw" / ph / tl / nm
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def add(self, kind, rec):
        return True

    def record(self, *a, **k):
        pass


crawl.exec_tool = fake_exec
crawl.have = lambda t: True
crawl._xnl_engine = lambda: "8.2"
ctx = SimpleNamespace(run=Run(), http_timeout=60,
                      profile=SimpleNamespace(apex_domains=["acme.com"], http_rl=0),
                      scope=SimpleNamespace(in_scope=lambda h: h == "acme.com" or h.endswith(".acme.com"),
                                            is_oos=lambda h: False),
                      echo=lambda m: None)
ctx.write_list = lambda nm, it: (run_dir / nm).write_text("\n".join(map(str, it))) or (run_dir / nm)
crawl._xnl_lane(ctx, [(indir, "js", False)])
fins = [json.loads(l) for l in (run_dir / "events.jsonl").read_text().splitlines()]
fin = [e for e in fins if e.get("event") == "tool_finish"][-1]
print(json.dumps({"status": fin["status"], "reason": fin.get("reason") or ""}))
"""


def _repo() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent.parent


def _start(project, indir, marker, name, gate="-"):
    return subprocess.Popen([sys.executable, "-c", _CHILD, str(project), name, str(indir), str(gate),
                             str(marker)],
                            cwd=str(_repo()), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def _finish(proc):
    so, se = proc.communicate(timeout=120)
    return proc.returncode, so.strip(), se.strip()


def _wait_for(path, proc=None, timeout=60):
    deadline = time.time() + timeout
    while not pathlib.Path(path).exists():
        if proc is not None and proc.poll() is not None:
            raise AssertionError(f"child exited early: {_finish(proc)}")
        assert time.time() < deadline, f"{path} never appeared"
        time.sleep(0.02)


def _fixture(tmp_path):
    d = tmp_path / "in" / "js"
    d.mkdir(parents=True)
    (d / "a.js").write_text("var u = '/api/x?id=1';")
    return d


def test_two_REAL_RUNS_of_one_project_never_mine_the_same_unit_twice(tmp_path):
    """The whole point of the lock: concurrent runs do not duplicate work or corrupt each other's state.

    Deterministic overlap: runA is provably INSIDE the lock (it wrote the marker) and cannot leave until
    the gate opens, so runB's attempt is guaranteed to be concurrent rather than merely likely."""
    indir = _fixture(tmp_path)
    marker, gate = tmp_path / "mined.txt", tmp_path / "gate"
    a = _start(tmp_path, indir, marker, "runA", gate=gate)
    _wait_for(marker, a)                                   # runA holds the lock and is mining
    b_rc, b_out, b_err = _finish(_start(tmp_path, indir, marker, "runB"))
    gate.write_text("go")
    a_rc, a_out, a_err = _finish(a)

    assert (a_rc, b_rc) == (0, 0), (a_out, a_err, b_out, b_err)
    assert marker.read_text().splitlines() == ["runA"], "both runs mined the same unit"
    # the loser reports the contention honestly — never a silent success, and never a chosen skip
    loser = json.loads(b_out)
    assert loser["status"] == "failed" and "another lifecycle" in loser["reason"], b_out
    assert json.loads(a_out)["status"] == "success", a_out

    # the winner's state survives intact and is usable: a THIRD run replays it without mining
    rc, out, err = _finish(_start(tmp_path, indir, marker, "runC"))
    assert rc == 0, (rc, out, err)
    assert marker.read_text().splitlines() == ["runA"], "the surviving state did not replay"
    assert json.loads(out)["status"] == "success", out


def test_a_KILLED_holder_does_not_wedge_the_project(tmp_path):
    """`flock` and not lockfile existence: the kernel releases the lock when the holder dies, however it
    dies. A leftover `.lock` file must never block the next run."""
    indir = _fixture(tmp_path)
    marker, gate = tmp_path / "mined.txt", tmp_path / "gate"
    proc = _start(tmp_path, indir, marker, "runA", gate=gate)     # never opened: it dies holding the lock
    try:
        _wait_for(marker, proc)
    finally:
        proc.kill()
        proc.communicate(timeout=30)
    lock = tmp_path / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}" / ".lock"
    assert lock.exists(), "the lock file should outlive the holder — only the LOCK is released"
    rc, out, err = _finish(_start(tmp_path, indir, marker, "runB"))
    assert rc == 0, (rc, out, err)
    assert json.loads(out)["status"] == "success", out
