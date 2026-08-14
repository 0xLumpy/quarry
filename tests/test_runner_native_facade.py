"""Public runner composition for repository-owned native argv outputs."""
from __future__ import annotations

import inspect
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from quarry_recon import (contract, events, runner, runner_native,
                          runner_protocol, runner_repository, runtime_identity, store)
from quarry_recon.runner import RunResult, Status
from quarry_recon.runner_native import RepositoryNativeOutput
from quarry_recon.runner_repository import RepositoryOutput


pytestmark = pytest.mark.offline


def _running_run(project: Path, run_id: str) -> store.Run:
    run = store.Run.create(project, "acme.example", run_id=run_id)
    run.write_state("running")
    return run


def _file_invocation(run: store.Run):
    components = ("raw", "probe", "fixture", "native.txt")
    final = run.dir.joinpath(*components)
    command = [
        sys.executable,
        "-c",
        "from pathlib import Path; import sys; Path(sys.argv[1]).write_text(sys.argv[1])",
        str(final),
    ]
    return final, command, RepositoryNativeOutput.file(3, *components)


def _run_native(run, command, policy, **kwargs):
    return runner.run(
        "native-fixture",
        command,
        repository=run,
        stdout=RepositoryOutput.discard(),
        stderr=RepositoryOutput.discard(),
        native_outputs=(policy,),
        timeout=20,
        **kwargs,
    )


def _attempt_directories(run: store.Run) -> list[Path]:
    root = run.project_dir / "recon" / "state" / "native-stages" / run.run_id
    return [] if not root.exists() else list(root.iterdir())


def _source_line(function, fragment: str) -> int:
    lines, first = inspect.getsourcelines(function)
    matches = [first + index for index, line in enumerate(lines) if fragment in line]
    assert len(matches) == 1
    return matches[0]


def _install_clean_execution(monkeypatch, original_command):
    seen = {}

    def supervise(_run, invocation, **_kwargs):
        seen["child"] = list(invocation.worker.argv)
        Path(invocation.worker.argv[3]).write_text(invocation.worker.argv[3])
        return SimpleNamespace(
            clean=True,
            execution=SimpleNamespace(settlement=SimpleNamespace(
                terminal=runner_protocol.ExecutionTerminal.COMPLETE,
                exit_code=0,
            )),
        )

    def result(tool, cmd, _outcome, **_kwargs):
        assert cmd == original_command
        return RunResult(
            tool, cmd, Status.EMPTY, 0, 0.0, None, 0,
            meta={"started": True, "repository_ownership_settled": True},
        )

    monkeypatch.setattr(
        runner_repository, "supervise_repository_execution", supervise,
    )
    monkeypatch.setattr(runner, "_repository_run_result", result)
    return seen


def test_facade_rewrites_only_child_argv_and_returns_original_command(
    tmp_path, monkeypatch,
):
    run = _running_run(tmp_path, "facade-child-argv")
    final, command, policy = _file_invocation(run)
    seen = _install_clean_execution(monkeypatch, command)

    result = _run_native(run, command, policy)

    assert result.status is Status.EMPTY
    assert result.cmd == command
    assert final.is_file()
    child_path = final.read_text()
    assert child_path != str(final) and "native-stages" in child_path
    assert seen["child"] != command
    assert Path(seen["child"][0]).is_absolute()
    assert seen["child"][0] != command[0]                    # private verified launch authority
    assert seen["child"][1:3] == command[1:3]
    assert result.meta["native_outputs"]["clean"] is True
    assert result.meta["native_outputs"]["policy_count"] == 1
    assert result.meta["native_output_ownership_settled"] is True
    assert runner.native_output_current(result, final) is True
    assert run._live_artifact_claim_count() == 0
    assert _attempt_directories(run) == []


def test_framework_credential_in_native_stage_is_refused_before_publication(
    tmp_path, monkeypatch,
):
    canary = "V310-NATIVE-OUTPUT-CANARY-4933ee"
    run = _running_run(tmp_path, "facade-private-native")
    final, command, policy = _file_invocation(run)
    final.parent.mkdir(parents=True)
    final.write_text("prior-authoritative")

    real_prepare = runtime_identity.prepare_launch

    def prepare(*args, **kwargs):
        admitted = real_prepare(*args, **kwargs)
        return replace(admitted, redactions=(canary,))

    def supervise(_run, invocation, **_kwargs):
        Path(invocation.worker.argv[3]).write_text("prefix:" + canary)
        return SimpleNamespace(
            clean=True,
            execution=SimpleNamespace(settlement=SimpleNamespace(
                terminal=runner_protocol.ExecutionTerminal.COMPLETE,
                exit_code=0,
            )),
        )

    def result(tool, cmd, _outcome, **_kwargs):
        return RunResult(
            tool, cmd, Status.EMPTY, 0, 0.0, None, 0,
            meta={"started": True, "repository_ownership_settled": True},
        )

    monkeypatch.setattr(runtime_identity, "prepare_launch", prepare)
    monkeypatch.setattr(runner_repository, "supervise_repository_execution", supervise)
    monkeypatch.setattr(runner, "_repository_run_result", result)

    observed = _run_native(run, command, policy)

    assert observed.status is Status.FAILED
    assert "framework credential" in observed.note
    assert final.read_text() == "prior-authoritative"
    assert runner.native_output_current(observed, final) is False
    assert canary not in repr(observed.meta)
    assert _attempt_directories(run) == []


def test_invalid_native_policy_refuses_before_have_prepare_or_spawn(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "facade-invalid-policy")
    final, command, _policy = _file_invocation(run)
    wrong = RepositoryNativeOutput.file(3, "raw", "probe", "fixture", "other.txt")
    calls = []
    monkeypatch.setattr(runner, "have", lambda _tool: calls.append("have") or True)
    monkeypatch.setattr(
        runner_native,
        "prepare_native_outputs",
        lambda *args, **kwargs: calls.append("prepare"),
    )

    result = _run_native(run, command, wrong)

    assert result.status is Status.FAILED and result.started is False
    assert calls == []
    assert not final.exists()
    assert result.meta["native_output_ownership_settled"] is True
    assert runner.native_output_current(result, final) is False
    assert run._live_artifact_claim_count() == 0
    assert _attempt_directories(run) == []


def test_missing_binary_refuses_before_native_prepare(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "facade-missing-binary")
    final = run.dir / "raw" / "probe" / "fixture" / "native.txt"
    command = ["definitely-missing-native-tool", "-o", str(final)]
    policy = RepositoryNativeOutput.file(2, "raw", "probe", "fixture", "native.txt")
    calls = []
    monkeypatch.setattr(runner, "have", lambda _tool: False)
    monkeypatch.setattr(
        runner_native,
        "prepare_native_outputs",
        lambda *args, **kwargs: calls.append("prepare"),
    )

    result = _run_native(run, command, policy)

    assert result.status is Status.SKIPPED and result.started is False
    assert calls == [] and not final.exists()
    assert result.meta["native_output_ownership_settled"] is True
    assert runner.native_output_current(result, final) is False
    assert run._live_artifact_claim_count() == 0
    assert _attempt_directories(run) == []


def test_invalid_argv_marks_preserved_native_final_noncurrent(tmp_path):
    run = _running_run(tmp_path, "facade-invalid-argv")
    final = run.dir / "raw" / "probe" / "fixture" / "native.txt"
    final.parent.mkdir(parents=True)
    final.write_text("prior")
    policy = RepositoryNativeOutput.file(
        2, "raw", "probe", "fixture", "native.txt",
    )

    result = _run_native(run, [sys.executable, "bad\0argv", str(final)], policy)

    assert result.status is Status.FAILED and result.started is False
    assert final.read_text() == "prior"
    assert result.meta["native_outputs"]["clean"] is False
    assert result.meta["native_output_ownership_settled"] is True
    assert runner.native_output_current(result, final) is False


@pytest.mark.parametrize("ambient", [False, True])
def test_public_preflight_marks_native_final_noncurrent(
    tmp_path, ambient,
):
    run = _running_run(tmp_path, f"facade-public-preflight-{ambient}")
    final, command, policy = _file_invocation(run)
    final.parent.mkdir(parents=True)
    final.write_text("prior")
    kwargs = {
        "repository": run,
        "stdout": RepositoryOutput.discard(),
        "native_outputs": (policy,),
    }
    if ambient:
        kwargs["stderr"] = RepositoryOutput.discard()
        kwargs["raw_path"] = final

    result = runner.run("native-fixture", command, **kwargs)

    assert result.status is Status.FAILED and result.started is False
    assert final.read_text() == "prior"
    assert result.meta["native_outputs"]["clean"] is False
    assert result.meta["native_output_ownership_settled"] is True
    assert runner.native_output_current(result, final) is False


@pytest.mark.parametrize(
    "exception_type", [RuntimeError, KeyboardInterrupt, SystemExit],
)
def test_facade_fences_real_prepare_return_boundary(
    tmp_path, monkeypatch, exception_type,
):
    run = _running_run(tmp_path, f"facade-adopt-{exception_type.__name__.lower()}")
    final, command, policy = _file_invocation(run)
    primary = exception_type("fixture after native prepare returned")
    real_prepare = runner_native.prepare_native_outputs

    def prepare_then_raise(*args, **kwargs):
        real_prepare(*args, **kwargs)
        raise primary

    monkeypatch.setattr(runner_native, "prepare_native_outputs", prepare_then_raise)
    if isinstance(primary, Exception):
        result = _run_native(run, command, policy)
        assert result.status is Status.FAILED
        assert result.meta["native_output_ownership_settled"] is True
    else:
        with pytest.raises(exception_type) as caught:
            _run_native(run, command, policy)
        assert caught.value is primary

    assert not final.exists()
    assert run._live_artifact_claim_count() == 0
    assert _attempt_directories(run) == []


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_facade_fences_cancellation_after_prepare_assignment(
    tmp_path, monkeypatch, interruption,
):
    run = _running_run(
        tmp_path, f"facade-post-prepare-{interruption.__name__.lower()}",
    )
    final, command, policy = _file_invocation(run)
    cancellation = interruption("fixture after native prepare assignment")
    target = _source_line(runner._run_with_repository, "child_invocation = replace(")
    fired = False

    def trace(frame, event, _arg):
        nonlocal fired
        if (not fired and event == "line"
                and frame.f_code is runner._run_with_repository.__code__
                and frame.f_lineno == target):
            fired = True
            raise cancellation
        return trace

    previous = sys.gettrace()
    try:
        sys.settrace(trace)
        with pytest.raises(interruption) as caught:
            _run_native(run, command, policy)
    finally:
        sys.settrace(previous)

    assert fired and caught.value is cancellation
    assert not final.exists()
    assert run._live_artifact_claim_count() == 0
    assert _attempt_directories(run) == []


@pytest.mark.parametrize(
    "primary_site", ["prepare", "supervisor"],
)
@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_outer_facade_fence_recovers_inner_cleanup_entry_interruption(
    tmp_path, monkeypatch, primary_site, interruption,
):
    run = _running_run(
        tmp_path,
        f"facade-inner-exit-{primary_site}-{interruption.__name__.lower()}",
    )
    final, command, policy = _file_invocation(run)
    ordinary = RuntimeError(f"fixture ordinary {primary_site} primary")
    cancellation = interruption("fixture inner facade cleanup entry")
    if primary_site == "prepare":
        real_prepare = runner_native.prepare_native_outputs

        def prepare_then_fail(*args, **kwargs):
            real_prepare(*args, **kwargs)
            raise ordinary

        monkeypatch.setattr(
            runner_native, "prepare_native_outputs", prepare_then_fail,
        )
    else:
        monkeypatch.setattr(
            runner_repository,
            "supervise_repository_execution",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(ordinary),
        )

    target = _source_line(runner._NativeFacadeFence.__exit__, "cleanup =")
    fired = False

    def trace(frame, event, _arg):
        nonlocal fired
        if (not fired and event == "line"
                and frame.f_code is runner._NativeFacadeFence.__exit__.__code__
                and frame.f_lineno == target):
            fired = True
            raise cancellation
        return trace

    previous = sys.gettrace()
    try:
        sys.settrace(trace)
        with pytest.raises(interruption) as caught:
            _run_native(run, command, policy)
    finally:
        sys.settrace(previous)

    assert fired and caught.value is cancellation
    assert not final.exists()
    assert run._live_artifact_claim_count() == 0
    assert _attempt_directories(run) == []


def test_facade_refuses_native_publication_after_shared_deadline(
    tmp_path, monkeypatch,
):
    run = _running_run(tmp_path, "facade-native-deadline")
    final, command, policy = _file_invocation(run)
    _install_clean_execution(monkeypatch, command)
    samples = iter((100.0, 126.0, 126.0))
    monkeypatch.setattr(runner.time, "monotonic", lambda: next(samples))

    result = _run_native(run, command, policy)

    assert result.status is Status.PARTIAL
    assert not final.exists()
    assert result.meta["native_outputs"]["clean"] is False
    assert result.meta["native_outputs"]["fault_operation"] == "execute"
    assert result.meta["native_output_ownership_settled"] is True
    assert runner.native_output_current(result, final) is False
    assert run._live_artifact_claim_count() == 0
    assert _attempt_directories(run) == []


def test_finish_fault_precedence_keeps_recovery_cancellation():
    ordinary = RuntimeError("ordinary first")
    cancellation = KeyboardInterrupt("cleanup cancellation")
    receipt = object()

    class Transaction:
        def finish(self, *, clean):
            assert clean is True
            raise ordinary

    class Adoption:
        calls = 0

        def fence(self):
            self.calls += 1
            if self.calls == 1:
                raise cancellation
            return receipt

    observed_receipt, fault = runner._finish_native_outputs(
        Transaction(), Adoption(), clean=True,
    )

    assert observed_receipt is receipt
    assert fault is cancellation


def test_run_contract_forwards_the_exact_native_policy_tuple(tmp_path, monkeypatch):
    events.configure(tmp_path)
    captured = {}
    native_outputs = (object(),)

    def fake_run(tool, cmd, **kwargs):
        captured.update(kwargs)
        return RunResult(tool, cmd, Status.EMPTY, 0, 0.0, None, 0)

    monkeypatch.setattr(contract, "_run", fake_run)
    try:
        contract.run_contract(
            "vertical.subfinder", ["subfinder"],
            repository=object(), stdout=object(), stderr=object(),
            native_outputs=native_outputs,
        )
    finally:
        events.reset()

    assert captured["native_outputs"] is native_outputs
