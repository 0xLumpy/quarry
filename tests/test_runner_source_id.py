"""Source identity admission at the repository runner boundary."""

import pytest

from quarry_recon import contract, events, runner, runtime_identity, store
import quarry_recon.network_policy as network_policy
from quarry_recon.runner import Status
from quarry_recon.runner_repository import RepositoryOutput


pytestmark = pytest.mark.offline


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
