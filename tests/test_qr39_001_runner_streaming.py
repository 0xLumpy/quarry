"""QR39-001 — the subprocess boundary must not lose or exhaust evidence.

Marked `integration`: these spawn a local `sh`/`cat`/`head` (no network, no target) to drive the REAL
streaming paths — binary capture under a parent-RSS ceiling, one deadline across execute/kill/drain, escaped
pipe holders, exclusive private staging, authoritative stderr, honoured `ok_empty`, and typed
machinery/publication faults. The offline CI gate hard-denies subprocess spawn, so they must NOT carry the
`offline` mark. These are remediation checks for the fixed behaviour, not inversions of the audit
characterization.
"""
import hashlib
import os
import shutil
import threading
import time

import pytest

from quarry_recon.runner import Status

pytestmark = pytest.mark.integration


def _kinds(r):
    return [f["kind"] for f in r.meta.get("faults", [])]


def _vmrss_kb():
    with open("/proc/self/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    return 0


def test_large_stdout_streams_without_a_parent_rss_spike(tmp_path):
    from quarry_recon import runner
    if not os.path.exists("/proc/self/status"):
        pytest.skip("needs /proc for a real RSS measurement")
    raw = tmp_path / "out.bin"
    size = 64 * 1024 * 1024                                             # far larger than any sane buffer
    base = _vmrss_kb()
    peak = [base]
    sampling = threading.Event()
    sampling.set()

    def _sample():                                                     # peak parent RSS DURING the run, not after
        while sampling.is_set():
            peak[0] = max(peak[0], _vmrss_kb())
            time.sleep(0.003)
    th = threading.Thread(target=_sample)
    th.start()
    try:
        r = runner.run("head", ["head", "-c", str(size), "/dev/zero"], raw_path=raw, timeout=60)
    finally:
        sampling.clear()
        th.join()
    assert r.status == Status.SUCCESS
    assert raw.stat().st_size == size and r.meta["stdout_bytes"] == size
    assert peak[0] - base < 24 * 1024, f"parent RSS peaked +{peak[0] - base} KiB for a 64 MiB stream — buffered"


def test_binary_stdout_keeps_exact_bytes_and_digest(tmp_path):
    from quarry_recon import runner
    raw = tmp_path / "out.bin"
    payload = (b"\x00\xff\xfe row\n" * 150_000)
    src = tmp_path / "payload"
    src.write_bytes(payload)
    r = runner.run("cat", ["cat", str(src)], raw_path=raw, timeout=60)
    assert r.status == Status.SUCCESS
    assert raw.read_bytes() == payload
    assert r.meta["stdout_sha256"] == hashlib.sha256(payload).hexdigest()
    assert r.stdout_lines == payload.count(b"\n")


def test_non_utf8_stdout_never_crashes_the_run(tmp_path):
    from quarry_recon import runner
    raw = tmp_path / "out.bin"
    r = runner.run("printf", ["printf", r"\xc3\x28\xff\xfeOK"], raw_path=raw, timeout=30)
    assert r.status == Status.SUCCESS
    assert raw.read_bytes() == b"\xc3\x28\xff\xfeOK"


def test_ok_empty_false_makes_a_clean_empty_run_a_failure(tmp_path):
    from quarry_recon import runner
    assert runner.run("true", ["true"], timeout=10, ok_empty=False).status == Status.FAILED
    assert runner.run("true", ["true"], timeout=10, ok_empty=True).status == Status.EMPTY


def test_output_is_atomically_published_from_private_staging(tmp_path):
    from quarry_recon import runner
    raw = tmp_path / "out.bin"
    r = runner.run("t", ["printf", "%s", "published"], raw_path=raw, timeout=10)
    assert r.raw_path == raw and raw.read_bytes() == b"published"
    assert list(tmp_path.glob("*.partial")) == []                      # staging cleaned up after publish
    assert oct(raw.stat().st_mode & 0o777) == "0o600"                  # published private (mkstemp mode)


def test_staging_ignores_a_planted_symlink_at_the_predictable_name(tmp_path):
    from quarry_recon import runner
    victim = tmp_path / "victim"
    victim.write_text("DO-NOT-CLOBBER")
    final = tmp_path / "out.bin"
    os.symlink(victim, tmp_path / "out.bin.partial")                   # attack the old predictable stage name
    r = runner.run("t", ["printf", "%s", "clean"], raw_path=final, timeout=10)
    assert victim.read_text() == "DO-NOT-CLOBBER"                      # output never followed the symlink
    assert r.raw_path == final and final.read_bytes() == b"clean" and not final.is_symlink()


def test_a_planted_stage_object_is_never_published(tmp_path):
    from quarry_recon import runner
    final = tmp_path / "out.bin"
    (tmp_path / "out.bin.partial").mkdir()                             # a directory where the old stage would be
    r = runner.run("t", ["printf", "x"], raw_path=final, timeout=10)
    assert r.raw_path and os.path.isfile(r.raw_path)                   # a real file, never the planted object
    assert not (final.exists() and final.is_dir())


def test_a_failed_run_never_truncates_existing_evidence(tmp_path):
    from quarry_recon import runner
    evidence = tmp_path / "out.bin"
    evidence.write_text("PAID-EVIDENCE")
    r = runner.run("t", ["sh", "-c", "exit 2"], raw_path=evidence, timeout=10)   # nonzero, no output
    assert r.raw_path is None
    assert evidence.read_text() == "PAID-EVIDENCE"                     # prior evidence intact, not clobbered


def test_large_stdin_is_streamed_from_a_file_and_round_trips(tmp_path):
    from quarry_recon import runner
    src = tmp_path / "in.bin"
    payload = os.urandom(1_500_000)
    src.write_bytes(payload)
    raw = tmp_path / "out.bin"
    r = runner.run("cat", ["cat"], raw_path=raw, input_file=src, timeout=60)
    assert r.status in (Status.SUCCESS, Status.EMPTY)
    assert raw.read_bytes() == payload


def test_a_missing_input_file_is_a_machinery_fault_not_silent(tmp_path):
    from quarry_recon import runner
    r = runner.run("cat", ["cat"], raw_path=tmp_path / "o", timeout=10, input_file=tmp_path / "nope")
    assert "machinery" in _kinds(r)
    assert r.status == Status.PARTIAL                                  # a broken input feed is not a clean EMPTY


def test_an_unopenable_input_source_is_a_machinery_fault(tmp_path):
    from quarry_recon import runner
    srcdir = tmp_path / "srcdir"
    srcdir.mkdir()                                                     # opening a directory as a file fails for ANY uid
    r = runner.run("cat", ["cat"], raw_path=tmp_path / "o", timeout=10, input_file=srcdir)
    assert "machinery" in _kinds(r)


def test_a_child_that_ignores_a_large_stdin_returns_promptly(tmp_path):
    from quarry_recon import runner
    big = tmp_path / "big"
    big.write_bytes(os.urandom(4_000_000))
    t0 = time.monotonic()
    r = runner.run("true", ["true"], timeout=10, input_file=big)       # reads nothing, exits immediately
    assert time.monotonic() - t0 < 5                                   # the blocked writer does not hang the call
    assert r.status in (Status.EMPTY, Status.SUCCESS)


def test_block_signature_early_in_a_large_stderr_is_still_seen(tmp_path):
    from quarry_recon import runner
    cmd = ["sh", "-c", 'echo "429 Too Many Requests" >&2; '
                       'for i in $(seq 1 4000); do echo padding-line-$i >&2; done; echo hello']
    r = runner.run("sh", cmd, timeout=30)
    assert r.status == Status.PARTIAL
    assert "429" not in r.stderr_tail                                   # scanned from the stream, not the tail


def test_stderr_is_authoritative_and_clears_a_stale_prior_file(tmp_path):
    from quarry_recon import runner
    err = tmp_path / "err.log"
    err.write_text("OLD COMPLETION MARKER")                            # a prior run's stderr
    runner.run("true", ["true"], timeout=10, stderr_path=err)          # this run emits nothing on stderr
    assert err.read_text() == ""                                       # never read the stale marker as current


def _flaky_sink(runner, monkeypatch, fail_from=2):
    calls = {"n": 0}
    real = runner._write_all
    def flaky(fp, data):
        calls["n"] += 1
        if calls["n"] >= fail_from:
            raise OSError("ENOSPC: no space left on device")
        real(fp, data)
    monkeypatch.setattr(runner, "_write_all", flaky)


def test_a_publication_write_failure_is_partial_and_owns_a_unique_partial(tmp_path, monkeypatch):
    from quarry_recon import runner
    _flaky_sink(runner, monkeypatch)                                   # fail the sink after the first chunk
    final = tmp_path / "out.bin"
    r = runner.run("t", ["sh", "-c", "head -c 200000 /dev/zero"], raw_path=final, timeout=10)
    assert r.status == Status.PARTIAL                                  # a lost artifact is not a clean SUCCESS
    assert r.raw_path is None and "publication" in _kinds(r)
    pp = r.meta.get("partial_path")
    assert pp and os.path.isfile(pp) and pp.endswith(".partial")
    assert r.meta["partial_bytes"] == os.path.getsize(pp)             # size = RETAINED, not observed


def test_a_later_failed_partial_does_not_overwrite_an_earlier_one(tmp_path, monkeypatch):
    from quarry_recon import runner
    final = tmp_path / "out.bin"
    real = runner._write_all                                          # capture ONCE so the two flakies don't nest

    def make_flaky():
        calls = {"n": 0}
        def flaky(fp, data):
            calls["n"] += 1
            if calls["n"] >= 2:
                raise OSError("ENOSPC")
            real(fp, data)
        return flaky

    monkeypatch.setattr(runner, "_write_all", make_flaky())
    p1 = runner.run("t", ["sh", "-c", "head -c 200000 /dev/zero"], raw_path=final, timeout=10).meta["partial_path"]
    monkeypatch.setattr(runner, "_write_all", make_flaky())          # fresh counter, still wraps the original
    p2 = runner.run("t", ["sh", "-c", "head -c 200000 /dev/zero"], raw_path=final, timeout=10).meta["partial_path"]
    assert p1 != p2 and os.path.isfile(p1) and os.path.isfile(p2)      # each attempt keeps its own bytes


def _last_finish(run_dir):
    import json
    return [e for e in (json.loads(li) for li in (run_dir / "events.jsonl").read_text().splitlines())
            if e.get("event") == "tool_finish"][-1]


def test_a_stdout_fault_and_partial_are_durable_in_the_terminal_event(tmp_path, monkeypatch):
    from quarry_recon import contract, events, runner
    events.configure(tmp_path)
    try:
        _flaky_sink(runner, monkeypatch)                              # stdout writes one chunk, then fails
        contract.run_contract("vertical.subfinder", ["sh", "-c", "head -c 200000 /dev/zero"],
                              raw_path=tmp_path / "out.bin", timeout=10)
        fin = _last_finish(tmp_path)
        assert fin.get("status") == "partial"                        # persisted terminal is NOT clean (stdout lost)
        assert [f for f in (fin.get("faults") or []) if f["kind"] == "publication"]   # completeness-challenging
        assert fin.get("partial_ref", "").endswith(".partial")        # stdout partial: dedicated machine-readable ref
    finally:
        events.reset()


def test_a_stderr_partial_is_durable_in_its_own_terminal_field(tmp_path, monkeypatch):
    from quarry_recon import contract, events, runner
    events.configure(tmp_path)
    try:
        _flaky_sink(runner, monkeypatch)                              # stderr writes one chunk, then fails
        contract.run_contract("vertical.subfinder", ["sh", "-c", "head -c 200000 /dev/zero >&2"],
                              raw_path=tmp_path / "out.bin", stderr_path=tmp_path / "err.log", timeout=10)
        fin = _last_finish(tmp_path)
        assert fin.get("status") == "empty"                          # a diagnostic stderr loss never demotes
        assert [f for f in (fin.get("faults") or []) if f["kind"] == "diagnostic"]     # non-challenging
        assert fin.get("stderr_partial_ref", "").endswith(".partial")  # stderr partial: its OWN structured field
    finally:
        events.reset()


def test_a_diagnostic_stderr_fault_does_not_contradict_a_clean_terminal(tmp_path, monkeypatch):
    from quarry_recon import runner
    monkeypatch.setattr(runner, "_write_all",
                        lambda fp, data: (_ for _ in ()).throw(OSError("ENOSPC")))
    # stdout is empty (clean); only the diagnostic stderr write fails
    r = runner.run("t", ["sh", "-c", "echo onlyerr >&2"], raw_path=tmp_path / "o",
                   stderr_path=tmp_path / "e", timeout=10)
    assert r.status == Status.EMPTY                                   # a lost diagnostic never demotes the verdict
    diag = [f for f in r.meta.get("faults", []) if f["kind"] == "diagnostic"]
    assert diag and diag[0]["challenges_completeness"] is False       # ...and the typed fault agrees (no contradiction)


def test_an_unwritable_destination_yields_exactly_one_publication_fault(tmp_path):
    from quarry_recon import runner
    afile = tmp_path / "afile"
    afile.write_text("x")                                              # a file where a directory is needed
    r = runner.run("sh", ["sh", "-c", "echo hi"], raw_path=afile / "sub" / "out.bin", timeout=30)
    pubs = [f for f in r.meta.get("faults", []) if f["kind"] == "publication"]
    assert r.raw_path is None and len(pubs) == 1                       # recorded once, not twice


def test_stderr_failure_preserves_prior_evidence_and_flags_currency(tmp_path, monkeypatch):
    from quarry_recon import runner
    err = tmp_path / "err.log"
    err.write_text("PRIOR-EVIDENCE")                                  # a prior run's stderr — must NOT be destroyed
    monkeypatch.setattr(runner, "_write_all",
                        lambda fp, data: (_ for _ in ()).throw(OSError("ENOSPC")))
    r = runner.run("t", ["sh", "-c", "echo newerr >&2; echo out"], raw_path=tmp_path / "o",
                   stderr_path=err, timeout=10)
    assert err.read_text() == "PRIOR-EVIDENCE"                        # preserved as evidence, not deleted
    assert r.meta.get("stderr_published") is False                    # ...but flagged as NOT this run's stderr


@pytest.mark.skipif(shutil.which("setsid") is None, reason="needs setsid to detach an escaped child")
def test_an_incomplete_stderr_drain_is_not_authoritative(tmp_path):
    from quarry_recon import runner
    err = tmp_path / "err.log"
    err.write_text("PRIOR")                                           # a prior run's complete stderr
    pidf = tmp_path / "escaped.pid"
    # leader exits after the detached writer emits "partial" to stderr, then keeps the pipe open (never EOFs)
    cmd = ["sh", "-c", f"setsid sh -c 'echo $$ > {pidf}; printf partial >&2; sleep 30' & sleep 0.4; exit 0"]
    try:
        r = runner.run("t", cmd, raw_path=tmp_path / "o", stderr_path=err, timeout=30)
        assert r.meta.get("stderr_published") is False                # a truncated stderr is NOT the complete oracle
        assert err.read_text() == "PRIOR"                             # prior complete stderr preserved
        assert r.meta.get("stderr_partial_path")                      # the truncated bytes retained as a partial
    finally:
        _reap(pidf)


def test_stderr_is_authoritative_and_clears_a_stale_marker_on_success(tmp_path):
    from quarry_recon import runner
    err = tmp_path / "err.log"
    err.write_text("OLD COMPLETION MARKER")
    r = runner.run("true", ["true"], timeout=10, stderr_path=err)     # clean run, empty stderr
    assert err.read_text() == "" and r.meta.get("stderr_published") is True   # replaced with this run's (empty)


def _reap(pidfile):
    """Kill an escaped (new-session) test child recorded in `pidfile`, so it never accumulates across tests."""
    try:
        os.kill(int(pidfile.read_text().strip()), 9)
    except (OSError, ValueError, FileNotFoundError):
        pass


@pytest.mark.skipif(shutil.which("setsid") is None, reason="needs setsid to detach an escaped child")
def test_an_abandoned_stdin_feeder_does_not_leak(tmp_path):
    from quarry_recon import runner
    big = tmp_path / "big"
    big.write_bytes(os.urandom(3_000_000))                            # more than a pipe buffer, so the writer blocks
    pidf = tmp_path / "escaped.pid"
    n0 = threading.active_count()
    # child never reads stdin and leaves an escaped stdout holder, so the feeder must be abandoned on the deadline
    cmd = ["sh", "-c", f"setsid sh -c 'echo $$ > {pidf}; sleep 30' & exec sleep 30"]
    try:
        r = runner.run("t", cmd, raw_path=tmp_path / "o", timeout=1, input_file=big)
        assert r.status == Status.TIMED_OUT
        time.sleep(1.0)                                               # let any lingering thread settle
        assert threading.active_count() <= n0, "the stdin feeder leaked past the bounded return"
    finally:
        _reap(pidf)


@pytest.mark.skipif(shutil.which("setsid") is None, reason="needs setsid to detach an escaped child")
def test_escaped_pipe_holder_is_bounded_flagged_and_digested(tmp_path):
    from quarry_recon import runner
    raw = tmp_path / "out.bin"
    pidf = tmp_path / "escaped.pid"
    cmd = ["sh", "-c", f"head -c 100000 /dev/zero; setsid sh -c 'echo $$ > {pidf}; sleep 30' & sleep 30"]
    try:
        t0 = time.monotonic()
        r = runner.run("sh", cmd, raw_path=raw, timeout=1)
        elapsed = time.monotonic() - t0
        assert r.status == Status.TIMED_OUT
        assert elapsed < 4                                             # one bounded grace, not a fixed 8 s stack
        assert raw.read_bytes() == b"\x00" * 100000                    # partial bytes preserved AND published
        assert r.meta.get("stdout_sha256") == hashlib.sha256(b"\x00" * 100000).hexdigest()   # digest kept for a partial
        assert "machinery" in _kinds(r)                                # abandonment is not silently "complete"
    finally:
        _reap(pidf)


@pytest.mark.skipif(shutil.which("setsid") is None, reason="needs setsid to detach an escaped child")
def test_a_detached_stderr_writer_is_flagged_not_falsely_complete(tmp_path):
    from quarry_recon import runner
    err = tmp_path / "err.log"
    pidf = tmp_path / "escaped.pid"
    # leader exits 0 after the detached writer emitted "e"; "late" is written to stderr after abandonment.
    cmd = ["sh", "-c", f'setsid sh -c "echo \\$\\$ > {pidf}; printf e >&2; sleep 3; printf late >&2" & sleep 0.4; exit 0']
    try:
        r = runner.run("sh", cmd, stderr_path=err, timeout=30)
        assert "machinery" in _kinds(r)                                # the lost stderr tail is recorded
    finally:
        _reap(pidf)
