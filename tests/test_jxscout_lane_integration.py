"""Real-bwrap namespace checks for the JXScout lane."""
from __future__ import annotations

import pathlib
import shutil
import subprocess
import tempfile

import pytest

import test_jxscout_lane as lane_tests
from quarry_recon import store
from quarry_recon.phases import crawl


pytestmark = [
    pytest.mark.integration,
    pytest.mark.requires_tool("bwrap"),
    pytest.mark.requires_tool("ls"),
    pytest.mark.requires_tool("sh"),
    pytest.mark.skipif(not shutil.which("bwrap"), reason="bwrap not installed"),
]


@pytest.mark.parametrize("path", [".config/quarry/secrets.yaml", ".ssh", "workspace"])
def test_the_operators_own_files_are_NOT_in_the_namespace(tmp_path, monkeypatch, path):
    """Measured through the real sandbox: not merely unwritable — absent."""
    lane_tests._stub_shim(monkeypatch, tmp_path, real_bwrap=True)
    (tmp_path / "b.js").write_text("x")
    cmd = crawl._jxscout_sandbox(
        ["jxscout-chunks", str(tmp_path / "b.js"), "0"],
        tmp_path / "out.txt",
        tmp_path / "err.txt",
    )
    target = str(pathlib.Path.home() / path)
    probe = cmd[:cmd.index("sh")] + ["sh", "-c", f"ls -d {target} 2>&1 || true"]
    got = subprocess.run(probe, capture_output=True, text=True, timeout=60).stdout
    assert target not in got.split("\n")[0] or "No such file" in got, got[:120]


def test_the_evidence_TREE_is_absent_from_the_real_namespace(tmp_path, monkeypatch):
    seen = lane_tests.TestTheWritablePathIsPRIVATEToEachInvocation._recorder(
        monkeypatch,
        tmp_path,
        real_bwrap=True,
    )
    run = store.Run.create(tmp_path, "acme.com")
    (tmp_path / "x.js").write_text("x")
    crawl._jxscout_analyze(type("C", (), {"run": run})(), tmp_path / "x.js", 0)
    published = run.raw_path("crawl", "jxscout", "x.txt")
    assert published.exists() and published.read_text(), "it really is there, on the host"
    dead = seen[0]["binds"][0]
    assert not pathlib.Path(dead).exists(), "the first scratch does not outlive its invocation"
    with tempfile.TemporaryDirectory(prefix="quarry-jxscout-") as later:
        (tmp_path / "y.js").write_text("y")
        cmd = crawl._jxscout_sandbox(
            ["jxscout-chunks", str(tmp_path / "y.js"), "0"],
            pathlib.Path(later) / "out.txt",
            pathlib.Path(later) / "err.txt",
        )
        probe = cmd[:cmd.index("sh")] + [
            "sh",
            "-c",
            f"ls -d {published} {published.parent} {run.dir} {dead}; "
            f"echo rc=$?; : > {published} 2>&1 || echo 'write refused'",
        ]
        done = subprocess.run(probe, capture_output=True, text=True, timeout=60)
        got = done.stdout + done.stderr
    assert str(published) not in got.split("rc=")[0], got[:300]
    assert got.count("No such file") >= 4, got[:300]
    assert dead not in got.split("rc=")[0], "a dead scratch must not reappear either"
    assert published.read_text(), "the earlier artifact is intact after a later bundle ran"
