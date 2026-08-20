"""Source identity admission at the repository runner boundary."""

import ast
from pathlib import Path

import pytest

from quarry_recon import contract, events, runner, runtime_identity, store
import quarry_recon.network_policy as network_policy
from quarry_recon.runner import Status
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
        contract.run_contract("vertical.subfinder", ["subfinder", "-duc"])
    finally:
        events.reset()

    assert captured["source_id"] == "vertical.subfinder"


def test_unbound_repository_keeps_optional_source_id_compatibility(tmp_path, monkeypatch):
    run = _running_run(tmp_path)
    monkeypatch.setattr(network_policy, "scope_for", lambda _repository: None)
    monkeypatch.setattr(runner, "have", lambda _name: False)

    result = _managed_call(run, ["subfinder", "-duc"])

    assert result.status is Status.SKIPPED
    assert result.started is False
