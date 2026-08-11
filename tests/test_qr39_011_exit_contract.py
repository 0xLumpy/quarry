"""QR39-011 — the process exit status encodes the verdict, and the machine document says the same thing.

Golden coverage of every exit code and every precedence pair, at the `compute_exit` contract and through
the real CLI; plus the stdout discipline `--json` promises — one JSON document, no prose.
"""
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from quarry_recon import state
from quarry_recon.cli import cli
from quarry_recon.runner import RunResult, Status

pytestmark = pytest.mark.offline

#: the document a machine consumer is promised.
DOC_KEYS = {"schema_version", "command", "run_id", "campaign_id", "outcome", "coverage", "faults", "gaps",
            "interrupted", "machinery_after_start", "exit_code", "remediation"}


def _profile(tmp_path: Path, passive=True) -> Path:
    p = tmp_path / "target.yaml"
    p.write_text("TARGET: t\nAPEX_DOMAINS:\n  - example.com\n"
                 + ("MODES:\n  PASSIVE_ONLY: true\n" if passive else ""))
    return p


def _one_phase(monkeypatch, fn, *, label="Horizontal", needs_active=False):
    """Drive `run` through a single controllable phase, so an exit code has one declared cause."""
    from quarry_recon import phases
    monkeypatch.setattr(phases, "REGISTRY", {"horizontal": (fn, label, needs_active)})


def _run(tmp_path, monkeypatch, fn, *args):
    _one_phase(monkeypatch, fn)
    return CliRunner(mix_stderr=False).invoke(
        cli, ["run", "-t", str(_profile(tmp_path)), "--phases", "horizontal", *args])


def _degraded(ctx):
    ctx.run.record("horizontal", RunResult("httpx", ["httpx"], Status.TIMED_OUT, None, 1.0, None, 0,
                                           note="killed at the outer ceiling"))


# ── the contract itself: every code, and every precedence pair ────────────────────────────────────
@pytest.mark.parametrize("kw,code", [
    (dict(outcome="completed", coverage="clean"), 0),
    (dict(outcome="invalid", coverage="clean"), 2),
    (dict(outcome="completed", coverage="intentionally_bounded"), 3),
    (dict(outcome="completed", coverage="gapped"), 4),
    (dict(outcome="failed", coverage="clean"), 5),
    (dict(outcome="refused", coverage="clean"), 6),
    (dict(outcome="completed", coverage="clean", interrupted=True), 130),
])
def test_every_declared_exit_code_is_reachable(kw, code):
    assert state.compute_exit(**kw) == code


@pytest.mark.parametrize("kw,code,beats", [
    # 130 outranks machinery, preflight, gaps and bounds alike
    (dict(outcome="failed", coverage="gapped", interrupted=True, machinery_after_start=True), 130, "5/4"),
    (dict(outcome="invalid", coverage="clean", interrupted=True), 130, "2"),
    (dict(outcome="refused", coverage="clean", interrupted=True), 130, "6"),
    # machinery after start outranks both preflight verdicts and every coverage state
    (dict(outcome="invalid", coverage="clean", machinery_after_start=True), 5, "2"),
    (dict(outcome="refused", coverage="clean", machinery_after_start=True), 5, "6"),
    (dict(outcome="completed", coverage="gapped", machinery_after_start=True), 5, "4"),
    (dict(outcome="completed", coverage="intentionally_bounded", machinery_after_start=True), 5, "3"),
    # a preflight verdict outranks coverage: nothing ran, so coverage is not the answer
    (dict(outcome="invalid", coverage="gapped"), 2, "4"),
    (dict(outcome="refused", coverage="gapped"), 6, "4"),
    (dict(outcome="invalid", coverage="intentionally_bounded"), 2, "3"),
    # a gap outranks a declared bound, and a bound outranks clean
    (dict(outcome="completed", coverage="gapped"), 4, "3"),
    (dict(outcome="completed", coverage="intentionally_bounded"), 3, "0"),
])
def test_precedence_pairs(kw, code, beats):
    assert state.compute_exit(**kw) == code, f"expected {code} to beat {beats}"


def test_a_gap_and_a_bound_together_report_the_gap():
    # a run that both sampled and lost coverage is gapped: the bound never masks the gap
    from quarry_recon.exit_contract import from_summary
    res = from_summary("run", {"verdict": "complete_with_limits",
                               "gaps": [{"tool": "probe.httpx", "kind": "cap", "why": "ceiling"}],
                               "faults": []})
    assert (res.coverage, res.exit_code) == ("gapped", 4)


def test_a_missing_required_dependency_is_a_gap_not_a_machinery_failure():
    # exit 5 is reserved for machinery that broke; an absent tool is coverage we did not get
    from quarry_recon.exit_contract import from_summary
    res = from_summary("run", {"verdict": "complete_with_gaps",
                               "gaps": [{"tool": "params.oob_probe", "kind": "required_tool_missing",
                                         "why": "interactsh-client not installed"}],
                               "faults": [{"kind": "required_tool_missing", "where": "params.oob_probe",
                                           "detail": "interactsh-client not installed",
                                           "challenges_completeness": True}]})
    assert res.exit_code == 4 and not res.faults and res.gaps[0].kind == "required_tool_missing"


# ── the same codes, driven through the real commands ──────────────────────────────────────────────
def test_clean_run_exits_zero(tmp_path, monkeypatch):
    res = _run(tmp_path, monkeypatch, lambda ctx: None)
    assert res.exit_code == 0, res.stderr


def test_invalid_selector_exits_two(tmp_path):
    res = CliRunner(mix_stderr=False).invoke(cli, ["run", "-t", str(_profile(tmp_path)), "--phases", "typo"])
    assert res.exit_code == 2, res.stderr


def test_gapped_run_exits_four(tmp_path, monkeypatch):
    res = _run(tmp_path, monkeypatch, _degraded)
    assert res.exit_code == 4, res.stderr


def test_phase_exception_exits_five(tmp_path, monkeypatch):
    def boom(ctx):
        raise RuntimeError("the runner broke")
    res = _run(tmp_path, monkeypatch, boom)
    assert res.exit_code == 5, res.stderr


def test_refused_before_execution_exits_six(tmp_path, monkeypatch):
    import shutil as _shutil
    from collections import namedtuple
    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(_shutil, "disk_usage", lambda p: usage(0, 0, 1 * 1024 ** 3))
    res = _run(tmp_path, monkeypatch, lambda ctx: None)
    assert res.exit_code == 6, res.stderr
    assert not list((tmp_path / "recon").glob("*/manifest.json")), "a refused run must not execute"


def test_operator_interrupt_exits_130(tmp_path, monkeypatch):
    def stop(ctx):
        raise KeyboardInterrupt
    res = _run(tmp_path, monkeypatch, stop)
    assert res.exit_code == 130, res.stderr


def _doctor_with(monkeypatch, *, installed: bool, verified: bool = True):
    """Doctor over one required tool whose presence and verification we control."""
    from quarry_recon import cli as cli_mod
    from quarry_recon.registry import Tool

    tool = Tool(bin="httpx", phase="probe", role="probe")
    monkeypatch.setattr(Tool, "installed", property(lambda self: installed))
    monkeypatch.setattr(Tool, "version", lambda self: "v1.0.0")
    monkeypatch.setattr(cli_mod, "load_tools", lambda: [tool])
    monkeypatch.setattr(cli_mod, "health", lambda t: {"ok": verified, "drift": "ok" if verified else "DRIFT",
                                                     "identity": "v1.0.0", "capability": True})
    return CliRunner(mix_stderr=False).invoke(cli, ["doctor", "--json"])


@pytest.mark.parametrize("installed,verified,code,kind", [
    (True, True, 0, None),
    (False, True, 4, "required_tool_missing"),      # NOT READY is a missing dependency
    (True, False, 4, "unknown"),                    # DEGRADED: present, but we cannot vouch for it
])
def test_doctor_readiness_verdict_reaches_the_exit_status(monkeypatch, installed, verified, code, kind):
    res = _doctor_with(monkeypatch, installed=installed, verified=verified)
    doc = json.loads(res.stdout)
    assert res.exit_code == code == doc["exit_code"], res.stderr
    assert [g["kind"] for g in doc["gaps"]] == ([kind] if kind else [])
    assert set(doc) == DOC_KEYS


# ── the machine document ──────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("argv,expected", [
    (["run", "--phases", "horizontal", "--json"], 0),
    (["run", "--phases", "typo", "--json"], 2),
    (["status", "--json"], 2),
])
def test_json_stdout_carries_one_document_and_no_prose(tmp_path, monkeypatch, argv, expected):
    _one_phase(monkeypatch, lambda ctx: None)
    argv = [argv[0], "-t", str(_profile(tmp_path))] + argv[1:]
    res = CliRunner(mix_stderr=False).invoke(cli, argv)
    doc = json.loads(res.stdout)                       # the WHOLE stdout parses: no prose fore or aft
    assert res.exit_code == expected, res.stderr
    assert set(doc) == DOC_KEYS
    assert doc["exit_code"] == res.exit_code
    assert doc["schema_version"] == state.SCHEMA_VERSION


def test_prose_goes_to_stderr_under_json(tmp_path, monkeypatch):
    res = _run(tmp_path, monkeypatch, _degraded, "--json")
    assert "══ Quarry run" in res.stderr and "══ Quarry run" not in res.stdout
    doc = json.loads(res.stdout)
    assert doc["command"] == "run" and doc["run_id"] and doc["exit_code"] == 4


def test_human_rendering_is_independent_of_the_process_status(tmp_path, monkeypatch):
    # the same run rendered with and without --json prints the same operator lines; only stdout differs
    plain = _run(tmp_path, monkeypatch, _degraded)
    machine = _run(tmp_path, monkeypatch, _degraded, "--json")
    assert plain.exit_code == machine.exit_code == 4
    for marker in ("══ Quarry run", "complete WITH GAPS"):
        assert marker in plain.stdout and marker in machine.stderr


def test_the_persisted_document_round_trips(tmp_path, monkeypatch):
    res = _run(tmp_path, monkeypatch, _degraded, "--json")
    doc = json.loads(res.stdout)
    assert state.CommandResult.from_dict(doc).exit_code == 4
    state.validate_serialized("CommandResult", doc)


def test_an_escaping_exception_is_a_machinery_failure_with_our_credential_redacted(tmp_path, monkeypatch):
    from quarry_recon import cli as cli_mod, secrets

    token = "shodan-key-abcdef123456"
    monkeypatch.setattr(secrets, "values", lambda: [token])

    def boom(*a, **k):
        raise RuntimeError(f"GET https://api.shodan.io/v1?key={token} failed")
    monkeypatch.setattr(cli_mod, "_run_phases", boom)
    res = CliRunner(mix_stderr=False).invoke(
        cli, ["run", "-t", str(_profile(tmp_path)), "--phases", "horizontal", "--json"])
    doc = json.loads(res.stdout)
    assert res.exit_code == 5 and doc["faults"][0]["kind"] == "machinery"
    assert token not in res.stdout and "***" in doc["faults"][0]["detail"]
