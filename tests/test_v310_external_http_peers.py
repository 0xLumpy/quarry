"""Exact host handoff for the direct, non-browser HTTP adapters."""
from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

from quarry_recon import events, sweep
from quarry_recon.phases import params, probe, vertical
from quarry_recon.runner import RunResult, Status


pytestmark = pytest.mark.offline


class _Run:
    def __init__(self, root: Path):
        self.dir = root
        self.recorded = []

    def raw_path(self, *parts):
        path = self.dir / "raw" / Path(*parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def record(self, _phase, result):
        self.recorded.append(result)


class _Context:
    def __init__(self, root: Path):
        self.run = _Run(root)
        self.profile = SimpleNamespace(http_rl=0)
        self.http_timeout = 5

    def write_list(self, name, values):
        path = self.run.dir / "work" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(f"{value}\n" for value in values))
        return path


def test_httpx_batches_and_submits_the_same_exact_hosts(tmp_path, monkeypatch):
    ctx = _Context(tmp_path)
    calls = []

    def run_contract(source_id, command, **kwargs):
        submitted = tuple(kwargs["network_hosts"])
        input_path = Path(command[command.index("-l") + 1])
        assert tuple(input_path.read_text().splitlines()) == submitted
        calls.append((source_id, submitted))
        return RunResult("httpx", command, Status.EMPTY, 0, 0.0, None, 0)

    monkeypatch.setattr(probe, "run_contract", run_contract)
    monkeypatch.setattr(probe.events, "work_unit", lambda *_args, **_kwargs: "unit")
    monkeypatch.setattr(probe, "scaled_timeout", lambda *_args, **_kwargs: 5)
    monkeypatch.setattr(probe.settings, "workers", lambda _tool, default: default)

    hosts = [f"h{index:04d}.example.test" for index in range(1025)]
    results = probe._run_httpx(ctx, hosts, [80, 443], "probe", "httpx")

    assert [len(hosts) for _source, hosts in calls] == [1024, 1]
    assert tuple(host for _source, batch in calls for host in batch) == tuple(hosts)
    assert len(results) == len(ctx.run.recorded) == 2


def test_arjun_disables_redirects_and_binds_its_url_host(tmp_path, monkeypatch):
    observed = {}

    def exec_tool(_tool, command, **kwargs):
        observed.update(command=command, kwargs=kwargs)
        return RunResult("arjun", command, Status.EMPTY, 0, 0.0, None, 0)

    monkeypatch.setattr(params, "exec_tool", exec_tool)
    repository = SimpleNamespace(dir=tmp_path)
    output_root = tmp_path / "raw" / "params" / "arjun"
    output_root.mkdir(parents=True)
    paths = tuple(output_root / name for name in ("params.txt", "stdout", "stderr"))
    params._arjun_exec(
        repository, "https://API.Example.Test/search", 0, 2, paths, 5,
    )

    assert "--disable-redirects" in observed["command"]
    assert observed["kwargs"]["network_hosts"] == ("api.example.test",)


def test_wildcard_helper_uses_the_caller_source_and_bounded_scheduler_batches():
    source = inspect.getsource(vertical._wc_differentiate)
    assert "source_id=source_id" in source
    assert "network_hosts=" in source
    assert "max_words_per_invocation=1022" in source


def test_wildcard_batch_outcomes_remain_separate_sweep_invocations(tmp_path):
    events.reset()
    events.configure(tmp_path)
    calls = []
    statuses = iter((Status.SUCCESS, Status.FAILED, Status.EMPTY))

    def execute(_target, _unit, words):
        calls.append(tuple(words))
        return RunResult("httpx", ["httpx"], next(statuses), 0, 0.0, None, 0)

    try:
        result = sweep.run_sweep(
            lane="v310-exact-http", state_dir=tmp_path / "state",
            targets=["example.test"], vocabulary=lambda _target: [f"w{i}" for i in range(2050)],
            execute=execute, budget_s=0, coverage_lane="vertical.wildcard_http",
            max_pairs_per_target=5000, max_words_per_invocation=1022,
        )
    finally:
        events.reset()

    assert len(calls) == 3
    assert all(0 < len(batch) <= 1022 for batch in calls)
    assert sum(map(len, calls)) == 2050
    assert result.invocations == 3
    assert result.invocations_obtained == 2
    assert result.invocation_classes == {Status.FAILED.value: 1}
    assert result.attempted_pairs == 2050


def test_vhost_ffuf_binds_the_base_authority_not_the_fuzzed_host_header():
    source = inspect.getsource(probe._vhost_scan)
    assert "normalize.host_of_url(base)" in source
    assert "network_hosts=(network_host,)" in source
