from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from quarry_recon import cli, fetch, network_policy, phases, runner, store


pytestmark = pytest.mark.offline


class _Run:
    run_id = "run-scope-test"

    def __init__(self, root: Path):
        self.dir = root / "run"
        self.dir.mkdir()

    def write_state(self, *_args, **_kwargs):
        pass


class _Payload:
    def __init__(self, events):
        self.events = events

    def bind(self, run):
        self.events.append("payload")


class _Scope:
    def __init__(self, events):
        self.events = events

    def bind(self, run):
        self.events.append("network")
        run._network_policy_scope = self


def _setup(monkeypatch, tmp_path, events):
    profile = SimpleNamespace(
        target="example.test", path=tmp_path / "target.yaml", modes={},
        apex_domains=["example.test"], oos=[], cidr=[], passive_only=False,
        block_private_targets=False, ports=[80], ports_are_default=False, http_rl=None,
    )
    profile.path.touch()
    profile.scope = lambda: object()
    run = _Run(tmp_path)
    scope = _Scope(events)
    monkeypatch.setattr(cli.TargetProfile, "load", lambda _path: profile)
    monkeypatch.setattr(cli, "_select_phases", lambda _phases: ["fake"])
    monkeypatch.setattr(cli, "_missing_required", lambda _phases: [])
    monkeypatch.setattr(cli, "_project_dir", lambda _profile: tmp_path)
    monkeypatch.setattr(cli.shutil, "disk_usage", lambda _path: SimpleNamespace(free=10 * 1024**3))
    monkeypatch.setattr(cli.secrets, "apply_env", lambda: None)
    monkeypatch.setattr(cli.events, "configure", lambda _path: None)
    monkeypatch.setattr(cli.events, "emit", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner, "set_tool_cwd", lambda _path: None)
    monkeypatch.setattr(store.Run, "create", lambda *_args, **_kwargs: run)
    monkeypatch.setattr(network_policy.NetworkPolicyScope, "from_profile", classmethod(
        lambda _cls, _profile: scope,
    ))
    monkeypatch.setattr(phases, "REGISTRY", {
        "fake": (lambda ctx: (_ for _ in ()).throw(KeyboardInterrupt()), "fake", False),
    })
    return profile, run, scope


def test_network_scope_is_bound_before_prepare(monkeypatch, tmp_path):
    events = []
    profile, _run, _scope = _setup(monkeypatch, tmp_path, events)
    payload = _Payload(events)

    def prepare(_run):
        events.append("prepare")
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        cli._run_phases_scoped(str(profile.path), None, False, 1, prepare=prepare,
                                _payload_scope=payload)
    assert events == ["payload", "network", "prepare"]


def test_network_scope_bind_failure_stops_before_prepare_or_phase(monkeypatch, tmp_path):
    events = []
    profile, _run, scope = _setup(monkeypatch, tmp_path, events)
    payload = _Payload(events)

    def fail(_run):
        events.append("network")
        raise RuntimeError("bind failed")

    scope.bind = fail
    with pytest.raises(RuntimeError, match="bind failed"):
        cli._run_phases_scoped(str(profile.path), None, False, 1,
                                prepare=lambda _run: events.append("prepare"),
                                _payload_scope=payload)
    assert events == ["payload", "network"]


def test_native_fetch_sees_run_bound_network_scope(monkeypatch, tmp_path):
    events = []
    profile, run, scope = _setup(monkeypatch, tmp_path, events)
    payload = _Payload(events)
    seen = []
    monkeypatch.setattr(network_policy, "scope_for",
                        lambda repository: getattr(repository, "_network_policy_scope", None))

    def phase(ctx):
        seen.append(fetch._network_scope(ctx))
        raise KeyboardInterrupt

    monkeypatch.setattr(phases, "REGISTRY", {
        "fake": (phase, "fake", False),
    })
    with pytest.raises(KeyboardInterrupt):
        cli._run_phases_scoped(str(profile.path), None, False, 1,
                                _payload_scope=payload)
    assert seen == [scope]
    assert fetch._network_scope(SimpleNamespace(run=run)) is scope


def test_real_run_scope_persists_inside_the_raw_network_namespace(tmp_path):
    run = store.Run.create(tmp_path, "example.test")
    scope = network_policy.NetworkPolicyScope(
        block_private_targets=False,
        apex_domains=("example.test",),
        own_ips=("192.0.2.10",),
        resolver_ips=("1.1.1.1",),
    )

    scope.bind(run)

    path = run.dir / "raw" / "network" / "policy.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(rows) == 1
    assert rows[0]["record_type"] == "scope"
    assert rows[0]["policy"]["apex_domains"] == ["example.test"]
    assert network_policy.scope_for(run) is scope
