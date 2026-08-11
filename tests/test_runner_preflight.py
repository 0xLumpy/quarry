"""Runner invocation validation that must remain side-effect-free and hermetic."""
from pathlib import Path

import pytest

from quarry_recon.runner import Status

pytestmark = pytest.mark.offline


def _assert_preflight_failure(result):
    assert result.status == Status.FAILED
    assert result.started is False and result.exit_code is None and result.raw_path is None
    faults = result.meta.get("faults", [])
    assert len(faults) == 1 and faults[0]["kind"] == "machinery"
    assert faults[0]["challenges_completeness"] is True
    assert "preflight validation failed" in result.note


def _forbid_boundary_side_effects(monkeypatch, runner):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("invalid invocation crossed the side-effect boundary")
    monkeypatch.setattr(runner, "have", forbidden)
    monkeypatch.setattr(runner, "_open_stage", forbidden)
    monkeypatch.setattr(runner.subprocess, "Popen", forbidden)


class _HostileList(list):
    def __bool__(self):
        raise AssertionError("hostile list method executed")

    def __iter__(self):
        raise AssertionError("hostile list method executed")


class _HostileString(str):
    def __contains__(self, _item):
        raise AssertionError("hostile string method executed")


@pytest.mark.parametrize("argv", [
    [], (), None, "true", ["true", 1], [Path("true")], [""], ["true", "bad\x00arg"],
])
def test_invalid_argv_is_typed_and_has_no_filesystem_or_process_side_effect(tmp_path, monkeypatch, argv):
    from quarry_recon import runner
    _forbid_boundary_side_effects(monkeypatch, runner)
    raw = tmp_path / "uncreated" / "stdout"
    err = tmp_path / "uncreated" / "stderr"
    result = runner.run("test", argv, raw_path=raw, stderr_path=err)
    _assert_preflight_failure(result)
    assert not raw.parent.exists()


@pytest.mark.parametrize("argv", [_HostileList(["true"]), [_HostileString("true")]])
def test_caller_defined_argv_methods_are_never_executed(tmp_path, monkeypatch, argv):
    from quarry_recon import runner
    _forbid_boundary_side_effects(monkeypatch, runner)
    result = runner.run("test", argv, raw_path=tmp_path / "uncreated" / "stdout")
    _assert_preflight_failure(result)
    assert not (tmp_path / "uncreated").exists()


def test_two_stdin_sources_fail_before_any_side_effect(tmp_path, monkeypatch):
    from quarry_recon import runner
    _forbid_boundary_side_effects(monkeypatch, runner)
    result = runner.run("test", ["true"], raw_path=tmp_path / "uncreated" / "stdout",
                        stdin_data="payload", input_file=tmp_path / "input")
    _assert_preflight_failure(result)
    assert "mutually exclusive" in result.note and not (tmp_path / "uncreated").exists()


def test_non_string_stdin_data_fails_before_any_side_effect(tmp_path, monkeypatch):
    from quarry_recon import runner
    _forbid_boundary_side_effects(monkeypatch, runner)
    result = runner.run("test", ["true"], raw_path=tmp_path / "uncreated" / "stdout",
                        stdin_data=b"payload")
    _assert_preflight_failure(result)
    assert "stdin_data" in result.note and not (tmp_path / "uncreated").exists()


@pytest.mark.parametrize("cap", [-1, True, False, 1.0, "1", object()])
def test_invalid_output_cap_fails_preflight_without_side_effect(tmp_path, monkeypatch, cap):
    from quarry_recon import runner
    _forbid_boundary_side_effects(monkeypatch, runner)
    result = runner.run("test", ["true"], raw_path=tmp_path / "uncreated" / "stdout",
                        max_output_bytes=cap)
    _assert_preflight_failure(result)
    assert "max_output_bytes" in result.note and not (tmp_path / "uncreated").exists()


def test_output_cap_without_a_sink_is_refused_not_silently_ignored(monkeypatch):
    from quarry_recon import runner
    _forbid_boundary_side_effects(monkeypatch, runner)
    result = runner.run("test", ["true"], max_output_bytes=1)
    _assert_preflight_failure(result)
    assert "requires raw_path" in result.note
