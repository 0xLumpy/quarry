"""Source identity admission at the repository runner boundary."""

import ast
import hashlib
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import ANY

import pytest

from quarry_recon import (contract, events, runner, runner_protocol,
                          runner_repository, runner_supervisor, runtime_identity, store)
import quarry_recon.network_policy as network_policy
from quarry_recon.runner import Status
from quarry_recon.runner_native import RepositoryNativeOutput
from quarry_recon.runner_repository import RepositoryOutput


pytestmark = pytest.mark.offline


_PRODUCTION_DIRECT_ROOTS = (
    Path(__file__).parents[1] / "src" / "quarry_recon" / "osint.py",
    Path(__file__).parents[1] / "src" / "quarry_recon" / "phases",
)


def _direct_exec_calls():
    """Yield managed production facade calls and their enclosing function names."""
    for root in _PRODUCTION_DIRECT_ROOTS:
        paths = (root,) if root.is_file() else sorted(root.glob("*.py"))
        for path in paths:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            parents = {}
            for parent in ast.walk(tree):
                for child in ast.iter_child_nodes(parent):
                    parents[child] = parent
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id == "exec_tool"):
                    continue
                owner = node
                while owner is not None and not isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    owner = parents.get(owner)
                yield path, node, owner.name if owner is not None else None


def test_every_managed_production_direct_call_binds_a_registered_transport_source():
    """A repository-owned direct facade call must not silently lose network authority identity.

    The one parameterized lane (jsluice) is deliberately accepted only through its finite local map;
    arbitrary user input must never become a source id.  For every call, the registered door's
    executable identity is also checked against the literal facade tool name.
    """
    seen = 0
    for path, call, owner in _direct_exec_calls():
        seen += 1
        source_kw = next((kw for kw in call.keywords if kw.arg == "source_id"), None)
        assert source_kw is not None, f"{path}:{call.lineno} omits source_id"
        if isinstance(source_kw.value, ast.Constant):
            source_ids = (source_kw.value.value,)
        else:
            assert path.name == "crawl.py" and owner == "_jsluice_run"
            source_ids = ("crawl.jsluice_urls", "crawl.jsluice_secrets")
        assert all(isinstance(source_id, str) for source_id in source_ids)
        tool = call.args[0] if call.args else None
        assert isinstance(tool, ast.Constant) and isinstance(tool.value, str), \
            f"{path}:{call.lineno} has no literal runner tool name"
        for source_id in source_ids:
            door = network_policy.TRANSPORT_DOORS.get(source_id)
            assert door is not None, (path, call.lineno, source_id)
            assert door.argv0 and Path(tool.value).name in door.argv0, \
                (path, call.lineno, source_id, tool.value, door.argv0)
            probe_argv = (tool.value, *door.required_argv)
            assert network_policy.transport_door(source_id, argv=probe_argv) is not None, \
                (path, call.lineno, source_id, probe_argv)
    assert seen >= 30


def _running_run(tmp_path):
    run = store.Run.create(tmp_path, "acme.example", run_id="source-id-test")
    run.write_state("running")
    return run


def _managed_call(run, command, **kwargs):
    return runner.run(
        "fixture", command,
        repository=run,
        stdout=RepositoryOutput.discard(),
        stderr=RepositoryOutput.discard(),
        timeout=1,
        **kwargs,
    )


def _forbid_launch(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("network admission crossed the launch boundary")

    monkeypatch.setattr(runner, "have", forbidden)
    monkeypatch.setattr(runtime_identity, "prepare_launch", forbidden)
    monkeypatch.setattr(runner.subprocess, "Popen", forbidden)


def _authenticated_outcome(request_id, *, clean=False):
    if clean:
        empty_digest = hashlib.sha256(b"").hexdigest()
        settlement = runner_protocol.WorkerSettlement(
            request_id=request_id,
            terminal=runner_protocol.ExecutionTerminal.COMPLETE,
            launched=True,
            exit_code=1,
            process_group_settled=True,
            process_tree_settled=False,
            streams=(
                runner_protocol.StreamSettlement(
                    role=runner_protocol.StreamRole.STDIN,
                    terminal=runner_protocol.StreamTerminal.COMPLETE,
                    observed_bytes=0,
                    retained_bytes=0,
                    observed_sha256=empty_digest,
                    retained_sha256=None,
                ),
                *(
                    runner_protocol.StreamSettlement(
                        role=role,
                        terminal=runner_protocol.StreamTerminal.EOF,
                        observed_bytes=0,
                        retained_bytes=0,
                        observed_sha256=empty_digest,
                        retained_sha256=None,
                    )
                    for role in (
                        runner_protocol.StreamRole.STDOUT,
                        runner_protocol.StreamRole.STDERR,
                    )
                ),
            ),
            worker_pid=51231,
            tool_pid=51232,
        )
        execution = runner_supervisor.ExecutionOutcome(
            reason=runner_supervisor.ExecutionReason.COMPLETE,
            request_id=request_id,
            worker_pid=51231,
            settlement=settlement,
            validated=runner_protocol.ValidatedSettlement(
                worker=settlement,
                mechanically_settled=True,
                containment_assurance=runner_protocol.ContainmentAssurance.COOPERATIVE_SCOPE,
                escape_protected=False,
                tree_proven=False,
                clean_eligible=True,
                capture_complete=True,
                _authority=runner_protocol._VALIDATION_AUTHORITY,
            ),
            worker_returncode=0,
            worker_spawned=True,
            worker_reaped=True,
            control_eof=True,
            go_command_sent=True,
            parent_pipes_closed=True,
            containment_settled=True,
            stages_settled=True,
            _authority=runner_supervisor._EXECUTION_OUTCOME_AUTHORITY,
        )
    else:
        execution = runner_supervisor.ExecutionOutcome(
            reason=runner_supervisor.ExecutionReason.INCOMPLETE,
            request_id=request_id,
            stages_settled=True,
            _authority=runner_supervisor._EXECUTION_OUTCOME_AUTHORITY,
        )
    return runner_repository.RepositoryExecutionOutcome(
        execution=execution,
        publication=runner_repository.RepositoryPublication.NOT_REQUESTED,
        requested_roles=(),
        discarded_roles=(
            runner_protocol.StreamRole.STDOUT,
            runner_protocol.StreamRole.STDERR,
        ),
    )


class _PreparedLaunch:
    def __init__(self, argv):
        self.argv = tuple(argv)
        self.environment = {"PREPARED": "yes"}
        self.record = {"identity": "prepared"}
        self.redactions = ()
        self.source_argv_indexes = tuple(range(len(argv)))
        self.closed = False

    def close(self):
        self.closed = True


class _PolicyInvocation:
    def __init__(self):
        self.attached = None
        self.settlements = []

    def attach(self, environment):
        self.attached = dict(environment)
        attached = dict(environment)
        attached[network_policy.PRIVATE_POLICY_ENV] = "broker-policy"
        return attached

    def settle(self, **kwargs):
        self.settlements.append(kwargs)


class _PolicyScope:
    def __init__(self):
        self.invocation = _PolicyInvocation()
        self.prepared = None

    def prepare_invocation(self, **kwargs):
        self.prepared = kwargs
        return self.invocation


def _install_bound_policy(monkeypatch, run, scope):
    monkeypatch.setattr(network_policy, "scope_for", lambda repository: scope if repository is run else None)
    monkeypatch.setattr(
        network_policy, "transport_door",
        lambda _source_id, *, argv: SimpleNamespace(supported=True, broker_required=True),
    )
    monkeypatch.setattr(runner, "have", lambda _name: True)
    prepared = _PreparedLaunch(("fixture", "--exact"))
    monkeypatch.setattr(runtime_identity, "prepare_launch", lambda *_args, **_kwargs: prepared)
    monkeypatch.setattr(runtime_identity, "revalidate_launch", lambda _prepared: None)
    monkeypatch.setattr(runtime_identity, "publish_launch_identity", lambda *_args: "identity")
    return prepared


def test_bound_repository_requires_source_id_before_prepare_launch(tmp_path, monkeypatch):
    run = _running_run(tmp_path)
    monkeypatch.setattr(network_policy, "scope_for",
                        lambda repository: object() if repository is run else None)
    _forbid_launch(monkeypatch)

    result = _managed_call(run, ["subfinder", "-duc"])

    assert result.status is Status.FAILED
    assert result.started is False
    assert "source_id" in result.note


def test_bound_repository_refuses_mismatched_transport_door_before_launch(tmp_path, monkeypatch):
    run = _running_run(tmp_path)
    observed = {}
    monkeypatch.setattr(network_policy, "scope_for",
                        lambda repository: object() if repository is run else None)

    def refuse(source_id, *, argv):
        observed.update(source_id=source_id, argv=list(argv))
        return None

    monkeypatch.setattr(network_policy, "transport_door", refuse)
    _forbid_launch(monkeypatch)

    result = _managed_call(run, ["subfinder", "-duc"], source_id="vertical.subfinder")

    assert result.status is Status.FAILED
    assert result.started is False
    assert observed == {"source_id": "vertical.subfinder", "argv": ["subfinder", "-duc"]}


def test_run_contract_passes_literal_source_id(monkeypatch, tmp_path):
    events.configure(tmp_path)
    captured = {}

    def fake_run(tool, cmd, **kwargs):
        captured.update(kwargs)
        return runner.RunResult(tool, cmd, Status.EMPTY, 0, 0.0, None, 0)

    monkeypatch.setattr(contract, "_run", fake_run)
    try:
        contract.run_contract(
            "vertical.subfinder", ["subfinder", "-duc"],
            approved_peers=("8.8.8.8",),
        )
    finally:
        events.reset()

    assert captured["source_id"] == "vertical.subfinder"
    assert captured["approved_peers"] == ("8.8.8.8",)


def test_unbound_repository_keeps_optional_source_id_compatibility(tmp_path, monkeypatch):
    run = _running_run(tmp_path)
    monkeypatch.setattr(network_policy, "scope_for", lambda _repository: None)
    monkeypatch.setattr(runner, "have", lambda _name: False)

    result = _managed_call(run, ["subfinder", "-duc"])

    assert result.status is Status.SKIPPED
    assert result.started is False


def test_bound_policy_payload_is_attached_before_supervise_and_settles_allow(tmp_path, monkeypatch):
    run = _running_run(tmp_path)
    scope = _PolicyScope()
    prepared = _install_bound_policy(monkeypatch, run, scope)
    observed = {}

    def supervise(_repository, invocation, **_kwargs):
        observed["environment"] = invocation.worker.environment
        return _authenticated_outcome(invocation.worker.request_id, clean=True)

    monkeypatch.setattr(runner_repository, "supervise_repository_execution", supervise)

    _managed_call(run, ["fixture", "--exact"], source_id="fixture.source")

    assert scope.prepared == {
        "request_id": ANY,
        "source_id": "fixture.source",
        "tool": "fixture",
        "argv": ["fixture", "--exact"],
        "environment": prepared.environment,
        "runtime_identity": prepared.record,
        "approved_peers": (),
    }
    assert dict(observed["environment"])[network_policy.PRIVATE_POLICY_ENV] == "broker-policy"
    assert scope.invocation.settlements == [{
        "decision": "allow",
        "reason": "repository supervisor returned an authenticated outcome",
        "summary": {"runner": "repository"},
    }]


def test_bound_policy_forwards_caller_owned_approved_peers(tmp_path, monkeypatch):
    run = _running_run(tmp_path)
    scope = _PolicyScope()
    _install_bound_policy(monkeypatch, run, scope)
    monkeypatch.setattr(
        runner_repository, "supervise_repository_execution",
        lambda _repository, invocation, **_kwargs: _authenticated_outcome(
            invocation.worker.request_id, clean=True,
        ),
    )

    _managed_call(
        run, ["fixture", "--exact"], source_id="fixture.source",
        approved_peers=("8.8.8.8", "2001:4860:4860::8888"),
    )

    assert scope.prepared["approved_peers"] == (
        "8.8.8.8", "2001:4860:4860::8888",
    )


@pytest.mark.parametrize("failure", ("normalize", "supervisor"))
def test_bound_policy_settles_deny_on_admission_or_supervisor_failure(tmp_path, monkeypatch, failure):
    run = _running_run(tmp_path)
    scope = _PolicyScope()
    _install_bound_policy(monkeypatch, run, scope)
    if failure == "normalize":
        monkeypatch.setattr(runner_protocol, "normalize_invocation", lambda **_kwargs: (_ for _ in ()).throw(RuntimeError()))
    else:
        monkeypatch.setattr(
            runner_repository, "supervise_repository_execution",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError()),
        )

    result = _managed_call(run, ["fixture", "--exact"], source_id="fixture.source")

    assert result.status is Status.FAILED
    assert [item["decision"] for item in scope.invocation.settlements] == ["deny"]


def test_bound_policy_denies_matching_incomplete_supervisor_outcome(tmp_path, monkeypatch):
    run = _running_run(tmp_path)
    scope = _PolicyScope()
    _install_bound_policy(monkeypatch, run, scope)
    monkeypatch.setattr(
        runner_repository, "supervise_repository_execution",
        lambda _repository, invocation, **_kwargs: _authenticated_outcome(
            invocation.worker.request_id,
        ),
    )

    result = _managed_call(run, ["fixture", "--exact"], source_id="fixture.source")

    assert result.status is Status.FAILED
    assert [item["decision"] for item in scope.invocation.settlements] == ["deny"]


def test_bound_policy_native_cleanup_does_not_settle_twice(tmp_path, monkeypatch):
    run = _running_run(tmp_path)
    scope = _PolicyScope()
    _install_bound_policy(monkeypatch, run, scope)
    final = run.dir / "raw" / "probe" / "fixture" / "native.txt"
    command = [sys.executable, "-c", "pass", str(final)]
    policy = RepositoryNativeOutput.file(3, "raw", "probe", "fixture", "native.txt")
    monkeypatch.setattr(
        runtime_identity, "prepare_launch",
        lambda *_args, **_kwargs: _PreparedLaunch(command),
    )
    monkeypatch.setattr(
        runner_repository, "supervise_repository_execution",
        lambda _repository, invocation, **_kwargs: _authenticated_outcome(
            invocation.worker.request_id,
            clean=True,
        ),
    )
    monkeypatch.setattr(
        runner, "_repository_run_result",
        lambda tool, cmd, *_args, **_kwargs: runner.RunResult(
            tool, cmd, Status.EMPTY, 0, 0.0, None, 0,
            meta={"started": True, "repository_ownership_settled": True},
        ),
    )

    _managed_call(
        run, command, source_id="fixture.source", native_outputs=(policy,),
    )

    assert [item["decision"] for item in scope.invocation.settlements] == ["allow"]
