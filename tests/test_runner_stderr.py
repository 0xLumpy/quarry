"""runner.run(stderr_path=…) — persist the COMPLETE stderr, not the 8-line tail.

Marked `integration`: these spawn a local `sh` (no network, no target) to exercise the real subprocess
paths — capture, timeout kill, and an unwritable destination. The offline CI gate hard-denies subprocess
spawn for every test it selects, so they must NOT carry the `offline` mark.

WHY the file and not `stderr_tail`: a caller that reads a tool's OWN completion report out of stderr
(params._nuclei_progress) needs every line. In the real OTC run a trailing `[INF]` burst came within one
line of evicting nuclei's `Scan completed in …` terminal from the 8-line tail — which would have made a
finished 54-minute chunk look incomplete and re-run it.
"""
from pathlib import Path

import pytest

from quarry_recon.runner import Status

pytestmark = [
    pytest.mark.integration,
    pytest.mark.requires_tool("seq"),
    pytest.mark.requires_tool("sh"),
    pytest.mark.requires_tool("sleep"),
]


class TestRunnerStderrPath:
    def test_full_stderr_is_persisted_not_just_the_tail(self, tmp_path):
        from quarry_recon import runner
        out = tmp_path / "err.log"
        r = runner.run("sh", ["sh", "-c", "for i in $(seq 1 40); do echo line$i >&2; done"],
                       stderr_path=out, timeout=30)
        assert out.is_file()
        assert out.read_text().count("\n") == 40                  # ALL 40 lines
        assert len(r.stderr_tail.splitlines()) == 8                # the tail is still only 8

    def test_stderr_is_persisted_on_the_timeout_kill_path(self, tmp_path):
        from quarry_recon import runner
        out = tmp_path / "err.log"
        r = runner.run("sh", ["sh", "-c", "echo dying >&2; sleep 30"], stderr_path=out, timeout=1)
        assert r.status == Status.TIMED_OUT
        assert out.is_file() and "dying" in out.read_text()        # the kill path needs its evidence too

    def test_unwritable_stderr_path_does_not_break_the_run(self, tmp_path):
        from quarry_recon import runner
        blocked = tmp_path / "afile"
        blocked.write_text("x")
        r = runner.run("sh", ["sh", "-c", "echo hi"], stderr_path=blocked / "sub" / "err.log", timeout=30)
        assert r.status == Status.SUCCESS                          # the tool's real result is never masked
