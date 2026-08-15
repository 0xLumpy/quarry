"""V310-08: an empty Nuclei corpus cannot starve independent Params lanes."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from quarry_recon import events
from quarry_recon.phases import params
from quarry_recon.runner import RunResult, Status


pytestmark = pytest.mark.offline


class _Run:
    def __init__(self, root):
        self.dir = root
        self.records = []

    def values(self, _entity):
        return []

    def read(self, _entity):
        return []

    def record(self, phase, result):
        self.records.append((phase, result))

    def add(self, _entity, _row):
        return True

    def count(self, _entity):
        return 0


class _Scope:
    passive_only = False

    @staticmethod
    def in_scope(_host):
        return True

    @staticmethod
    def is_oos(_host):
        return False

    @staticmethod
    def active_allowed(_host):
        return True

    @staticmethod
    def filter_hosts(hosts):
        return list(hosts)


class _Context:
    def __init__(self, root, *, passive_only=False):
        self.run = _Run(root)
        self.profile = SimpleNamespace(takeover=False, http_rl=0, blind_xss=False)
        self.scope = _Scope()
        self.scope.passive_only = passive_only
        self.http_timeout = 30
        self.messages = []

    def write_list(self, name, items):
        path = self.run.dir / name
        path.write_text("\n".join(items), encoding="utf-8")
        return path

    def echo(self, message):
        self.messages.append(message)


def _result(tool, *, lines=0):
    return RunResult(tool, [tool], Status.SUCCESS, 0, 0.01, None, lines)


def test_empty_nuclei_input_accounts_zero_then_runs_every_independent_lane(tmp_path, monkeypatch):
    ctx = _Context(tmp_path)
    called = []
    coverage = []
    ledgers = []

    monkeypatch.setattr(events, "coverage_partial", lambda *a, **k: coverage.append((a, k)))
    monkeypatch.setattr(events, "ledger", lambda *a, **k: ledgers.append((a, k)))
    monkeypatch.setattr(params, "_openapi_urls", lambda *_a: [])
    monkeypatch.setattr(params, "_nuclei_scan", lambda *_a, **_k: pytest.fail("empty Nuclei lane launched"))
    monkeypatch.setattr(params, "have", lambda tool: tool == "dalfox")
    monkeypatch.setattr(params.netguard, "guard_urls", lambda _ctx, urls, **_k: list(urls))

    monkeypatch.setattr(params, "_exposed_urls", lambda *_a: ["https://app.example/.env"])
    monkeypatch.setattr(params.evidence, "fetch_exposed",
                        lambda *_a: called.append("exposed") or 1)
    monkeypatch.setattr(params, "_graphql_urls", lambda *_a: ["https://app.example/graphql"])
    monkeypatch.setattr(params.evidence, "probe_graphql",
                        lambda *_a: called.append("graphql") or 1)
    monkeypatch.setattr(params, "_actuator_bases", lambda *_a: ["https://app.example/actuator"])
    monkeypatch.setattr(params.evidence, "probe_actuator",
                        lambda *_a: called.append("actuator") or 1)
    monkeypatch.setattr(params, "_framework_endpoint_candidates",
                        lambda *_a: [{"url": "https://app.example/debug"}])
    monkeypatch.setattr(params.evidence, "probe_framework_endpoints",
                        lambda *_a: called.append("framework") or 1)
    monkeypatch.setattr(params, "_arjun_lane", lambda *_a: called.append("arjun"))

    candidates = {
        "xss": ["https://app.example/search?q=x"],
        "redirect": ["https://app.example/next?url=x"],
    }
    monkeypatch.setattr(params, "active_review_values", lambda _ctx, klass: candidates.get(klass, []))
    monkeypatch.setattr(params, "_dalfox_xss_fast",
                        lambda *_a: called.append("dalfox") or _result("dalfox"))
    monkeypatch.setattr(params, "_redirect_confirm",
                        lambda *_a: called.append("redirect") or _result("redirect_confirm", lines=1))
    monkeypatch.setattr(params, "_ssti_targets", lambda *_a: ["https://app.example/tpl?q=x"])
    monkeypatch.setattr(params.evidence, "probe_ssti", lambda *_a: called.append("ssti") or 1)
    monkeypatch.setattr(params, "_oob_probe",
                        lambda *_a: called.append("oob") or _result("oob_probe"))

    params.run(ctx)

    assert called == [
        "exposed", "graphql", "actuator", "framework", "arjun",
        "dalfox", "redirect", "ssti", "oob",
    ]
    assert coverage == [(('params.nuclei_scan',), {
        "kind": events.COVERAGE_CAP,
        "measure": "requests",
        "unit": "requests",
        "eligible": 0,
        "tested": 0,
        "omitted": 0,
        "reason": "no active-allowed live hosts; the Nuclei request corpus is exactly empty",
    })]
    assert ledgers[0] == (("params.nuclei_scan",), {
        "produced": {"finding": 0}, "consumed": {"target": 0},
    })
    nuclei = [r for phase, r in ctx.run.records if phase == "params" and r.tool == "nuclei"]
    assert len(nuclei) == 1
    assert nuclei[0].status is Status.SKIPPED
    assert "no active-allowed live hosts" in nuclei[0].note


def test_passive_only_still_stops_before_every_active_lane(tmp_path, monkeypatch):
    ctx = _Context(tmp_path, passive_only=True)
    monkeypatch.setattr(params, "_openapi_urls", lambda *_a: [])
    monkeypatch.setattr(params, "_main_nuclei_lane",
                        lambda *_a: pytest.fail("passive mode entered the active Nuclei lane"))
    for name in (
        "_exposed_urls", "_graphql_urls", "_actuator_bases",
        "_framework_endpoint_candidates", "_arjun_lane", "_ssti_targets", "_oob_probe",
    ):
        monkeypatch.setattr(params, name,
                            lambda *_a, _name=name: pytest.fail(f"passive mode entered {_name}"))

    params.run(ctx)

    skipped_tools = [(r.tool, r.note) for phase, r in ctx.run.records if phase == "params"]
    assert skipped_tools == [
        ("nuclei", "passive-only mode"),
        ("dalfox", "passive-only mode"),
    ]


def test_nuclei_provider_failure_is_accounted_and_independent_lanes_continue(tmp_path, monkeypatch):
    ctx = _Context(tmp_path)
    called = []
    coverage = []
    monkeypatch.setattr(events, "coverage_partial", lambda *a, **k: coverage.append((a, k)))
    monkeypatch.setattr(events, "ledger", lambda *_a, **_k: None)
    monkeypatch.setattr(params, "_openapi_urls", lambda *_a: [])
    monkeypatch.setattr(params.netguard, "guard_urls", lambda _ctx, urls, **_k: list(urls))
    monkeypatch.setattr(
        params, "_main_nuclei_lane",
        lambda *_a: (_ for _ in ()).throw(ValueError("torn provider JSONL")),
    )
    monkeypatch.setattr(params, "_exposed_urls", lambda *_a: called.append("exposed") or [])
    monkeypatch.setattr(params, "_graphql_urls", lambda *_a: called.append("graphql") or [])
    monkeypatch.setattr(params, "_actuator_bases", lambda *_a: called.append("actuator") or [])
    monkeypatch.setattr(
        params, "_framework_endpoint_candidates", lambda *_a: called.append("framework") or [],
    )
    monkeypatch.setattr(params, "_arjun_lane", lambda *_a: called.append("arjun"))
    monkeypatch.setattr(params, "have", lambda _tool: False)
    monkeypatch.setattr(params, "active_review_values", lambda *_a: [])
    monkeypatch.setattr(params, "_ssti_targets", lambda *_a: called.append("ssti") or [])
    monkeypatch.setattr(params, "_oob_probe", lambda *_a: called.append("oob"))

    params.run(ctx)

    assert called == ["exposed", "graphql", "actuator", "framework", "arjun", "ssti", "oob"]
    failures = [result for phase, result in ctx.run.records
                if phase == "params" and result.tool == "nuclei" and result.status is Status.FAILED]
    assert len(failures) == 1 and "torn provider JSONL" in failures[0].note
    assert any(kwargs.get("kind") == events.COVERAGE_UNKNOWN
               and kwargs.get("measure") == "provider_findings" for _args, kwargs in coverage)


def test_takeover_provider_failure_is_accounted_before_main_and_downstream_lanes_continue(
        tmp_path, monkeypatch,
):
    ctx = _Context(tmp_path)
    ctx.profile.takeover = True
    called = []
    coverage = []
    monkeypatch.setattr(events, "coverage_partial", lambda *a, **k: coverage.append((a, k)))
    monkeypatch.setattr(events, "ledger", lambda *_a, **_k: None)
    monkeypatch.setattr(params, "_openapi_urls", lambda *_a: [])
    monkeypatch.setattr(
        params, "_takeover_nuclei_lane",
        lambda *_a: (_ for _ in ()).throw(ValueError("torn takeover provider JSONL")),
    )
    monkeypatch.setattr(params, "_main_nuclei_lane_isolated",
                        lambda *_a: called.append("main-nuclei"))
    monkeypatch.setattr(params.netguard, "guard_urls", lambda _ctx, urls, **_k: list(urls))
    monkeypatch.setattr(params, "_exposed_urls", lambda *_a: called.append("exposed") or [])
    monkeypatch.setattr(params, "_graphql_urls", lambda *_a: [])
    monkeypatch.setattr(params, "_actuator_bases", lambda *_a: [])
    monkeypatch.setattr(params, "_framework_endpoint_candidates", lambda *_a: [])
    monkeypatch.setattr(params, "_arjun_lane", lambda *_a: None)
    monkeypatch.setattr(params, "have", lambda _tool: False)
    monkeypatch.setattr(params, "active_review_values", lambda *_a: [])
    monkeypatch.setattr(params, "_ssti_targets", lambda *_a: [])
    monkeypatch.setattr(params, "_oob_probe", lambda *_a: None)

    params.run(ctx)

    assert called == ["main-nuclei", "exposed"]
    failure = next(result for phase, result in ctx.run.records
                   if phase == "params" and result.tool == "nuclei-takeover")
    assert failure.status is Status.FAILED and "torn takeover provider JSONL" in failure.note
    assert any(args == ("params.nuclei_takeover",)
               and kwargs.get("kind") == events.COVERAGE_UNKNOWN
               for args, kwargs in coverage)


@pytest.mark.parametrize("signal", [KeyboardInterrupt, SystemExit])
def test_nuclei_isolation_preserves_cancellation_precedence(tmp_path, monkeypatch, signal):
    ctx = _Context(tmp_path)
    monkeypatch.setattr(params, "_main_nuclei_lane",
                        lambda *_a: (_ for _ in ()).throw(signal("stop")))
    with pytest.raises(signal, match="stop"):
        params._main_nuclei_lane_isolated(ctx, [], ctx.profile)
    assert ctx.run.records == []
